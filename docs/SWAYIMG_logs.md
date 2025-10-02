# Анализ heap-buffer-overflow в swayimg

## Обзор

**swayimg** - это image viewer на C для Wayland/X11, который использует libgif для обработки GIF файлов. При тестировании с повреждёнными GIF файлами обнаружен **heap-buffer-overflow** в декодере GIF.

## Методология тестирования

### Сборка с инструментами анализа

Простой запуск:

```bash
swayimg ../poc_copies/poc_1.gif

>>> poc_1.gif: unable to decode gif
>>> image: [0] (null)
>>> malloc(): corrupted top size
>>> Aborted (core dumped)
```

```bash
# после обнаружения странной реакции на крэш-гифки, swayimg запущен с valgrind
G_DEBUG=gc-friendly G_SLICE=always-malloc valgrind --tool=memcheck --leak-check=full --track-origins=yes --num-callers=40 swayimg poc_copies/
```

### Полученный лог
```
==240737== Invalid write of size 4
==240737==
==240737==at 0x117985: decode_frame (gif.c:82)--240737-- VALGRIND INTERNAL ERROR: Valgrind received a signal 11 (SIGSEGV) -
exiting
==240737==by 0x117985: decode_gif (gif.c:134)==240737==by 0x116F95: load_image (loader.c:105)==240737==by 0x111ECE: image_create (image.c:132)==240737==by 0x111FC6: image_from_file (image.c:173)==240737==by 0x112931: image_list_jump (imagelist.c:509)==240737==by 0x11306D: image_list_init (imagelist.c:430)==240737==by 0x10EDA4: main (main.c:241)
==240737==
Address 0xab98820 is 0 bytes after a block of size 55,680 alloc'd
==240737==at 0x48417B4: malloc (vg_replace_malloc.c:381)
==240737==by 0x1121AC: image_frame_allocate (image.c:357)
==240737==by 0x117894: decode_frame (gif.c:52)
==240737==by 0x117894: decode_gif (gif.c:134)
==240737==by 0x116F95: load_image (loader.c:105)
==240737==by 0x111ECE: image_create (image.c:132)
==240737==by 0x111FC6: image_from_file (image.c:173)
==240737==by 0x112931: image_list_jump (imagelist.c:509)
==240737==by 0x11306D: image_list_init (imagelist.c:430)
==240737==by 0x10EDA4: main (main.c:241)
--240737-- si_code=128;
Faulting address: 0x0;
valgrind: the 'impossible' happened:
Killed by fatal signal
```

Далее для полной картины был подключен AddressSanitizer для точного обнаружения heap-ошибок
```bash
meson setup build -Db_sanitize=address,undefined
meson compile -C build
```

### Тестовые файлы
- Повреждённые GIF файлы с некорректными координатами кадра
- `Top`/`Left` + `Width`/`Height` выходят за границы canvas
- Файлы из набора `poc_*.gif`

## Результаты тестирования

### 1. AddressSanitizer: heap-buffer-overflow

**Критическая ошибка в `decode_frame`, `gif.c:81`:**

```
WRITE of size 4 at 0x62f00001bd80 thread T0
    #0 0x55af3e72e556 in decode_frame ../src/formats/gif.c:81
    #1 0x55af3e72ee30 in decode_gif ../src/formats/gif.c:134
    #2 0x55af3e72b5d8 in load_image ../src/formats/loader.c:105
    #3 0x55af3e70754e in image_create ../src/image.c:132
    #4 0x55af3e707a03 in image_from_file ../src/image.c:173
    #5 0x55af3e70ecb5 in image_list_init ../src/imagelist.c:427
    #6 0x55af3e713435 in main ../src/main.c:241

0x62f00001bd80 is located 0 bytes to the right of 55680-byte region
allocated by thread T0 here:
    #0 0x7f1a196b89cf in __interceptor_malloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:69
    #1 0x55af3e709772 in image_frame_allocate ../src/image.c:357
    #2 0x55af3e72d3ac in decode_frame ../src/formats/gif.c:52
```

**Анализ:**
- **Размер буфера:** 55680 bytes
- **Запись за границы:** 0 bytes to the right (прямо за концом буфера)
- **Размер записи:** 4 bytes

### 2. Valgrind: uninitialised value errors

**Valgrind обнаружил проблемы с неинициализированными значениями:**

```
==240737== Conditional jump or move depends on uninitialised value(s)
==240737==    at 0x4A46093: GifErrorString (gif_err.c:22)
==240737==    by 0x117A9C: decode_gif (gif.c:121)
==240737==    by 0x116F95: load_image (loader.c:105)
==240737==    by 0x111ECE: image_create (image.c:132)
==240737==    by 0x111FC6: image_from_file (image.c:173)
==240737==    by 0x11303C: image_list_init (imagelist.c:427)
==240737==    by 0x10EDA4: main (main.c:241)

==240737== Uninitialised value was created by a stack allocation
==240737==    at 0x117770: decode_gif (gif.c:98)
```

**Анализ:**
- **Проблема:** Неинициализированное значение в `GifErrorString`
- **Источник:** Stack allocation в `decode_gif` (gif.c:98)

## Анализ кода

### Проблема в swayimg

**Корневая причина:** swayimg не проверяет размеры изображения перед рендерингом, полагаясь на значения из `GifImageDesc` без валидации.

**Проблемный код**

```c
// giflib честно отдал значения дескриптора, но swayimg не проверил их перед отрисовкой

argb_t* pixel = curr->data
              + gif_desc->Top * curr->width
              + y * curr->width + gif_desc->Left;

for (int x = 0; x < gif_desc->Width; ++x) {
    const GifColorType* rgb = &gif_colors->Colors[color];
    // Возможна запись за пределы буфера,
    // если Top/Left/Width/Height выходят за canvas
    *pixel = ARGB_FROM_A(0xff) |
             ARGB_FROM_R(rgb->Red) |
             ARGB_FROM_G(rgb->Green) |
             ARGB_FROM_B(rgb->Blue);
    ++pixel;
}
```

### Связь с libgif

Это не косяк в libgif, а скорее ошибка в коде swayimg:
- libgif предоставляет данные из `GifImageDesc`
- swayimg должен валидировать эти данные перед использованием
- Отсутствие валидации приводит к heap overflow

