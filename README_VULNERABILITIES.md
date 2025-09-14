# Анализ уязвимостей библиотеки giflib

## Обзор

В ходе фаззинга библиотеки giflib были обнаружены уязвимости, которые могут привести к аварийному завершению программы, переполнению буфера и утечкам памяти. Анализ проводился с использованием AddressSanitizer и AFL++ фаззера.

## Обнаруженные уязвимости

### 1. Heap Buffer Overflow в GifUnionColorMap

**Файл:** `libgif_repo/gifalloc.c:195-197`  
**Функция:** `GifUnionColorMap`  
**Тип:** Heap Buffer Overflow

#### Описание
В функции `GifUnionColorMap` происходит переполнение буфера при записи в массив `ColorUnion->Colors`. Проблема возникает в строках 195-197:

```c
for (j = CrntSlot; j < RoundUpTo; j++) {
    Map[j].Red = Map[j].Green = Map[j].Blue = 0;  // Строка 196
}
```

#### Причина
Функция не проверяет, что `RoundUpTo` не превышает размер выделенного буфера `ColorUnion->Colors`. При определенных входных данных `RoundUpTo` может быть больше, чем `ColorUnion->ColorCount`, что приводит к записи за границы выделенной памяти.

#### Входные данные
Фаззер генерирует специальные цветовые палитры, где:
- `ColorIn1->ColorCount` и `ColorIn2->ColorCount` имеют значения, которые при объединении дают `RoundUpTo > ColorUnion->ColorCount`
- Это происходит в строке 185: `RoundUpTo = (1 << NewGifBitSize)`


### 2. Null Pointer Dereference в GifApplyTranslation

**Файл:** `libgif_repo/gifalloc.c:220-228`  
**Функция:** `GifApplyTranslation`  
**Тип:** Null Pointer Dereference

#### Описание
Функция `GifApplyTranslation` не проверяет входные параметры на NULL перед их использованием:

```c
void GifApplyTranslation(SavedImage *Image, const GifPixelType Translation[]) {
    register int i;
    register int RasterSize = Image->ImageDesc.Height * Image->ImageDesc.Width;  // Строка 222-223
    
    for (i = 0; i < RasterSize; i++) {
        Image->RasterBits[i] = Translation[Image->RasterBits[i]];  // Строка 226
    }
}
```

#### Причина
- Отсутствует проверка `Image != NULL`
- Отсутствует проверка `Image->RasterBits != NULL`
- Отсутствует проверка `Translation != NULL`

#### Входные данные
Фаззер вызывает функцию с NULL указателями:
```c
GifApplyTranslation(NULL, transTable); // Намеренно вызываем с NULL
```


### 3. Memory Leaks в GifAddExtensionBlock

**Файл:** `libgif_repo/gifalloc.c:233-275`  
**Функция:** `GifAddExtensionBlock`  
**Тип:** Memory Leak

#### Описание
В функции `GifAddExtensionBlock` происходит утечка памяти в нескольких местах:

1. **Строки 243-244:** Выделение памяти для `ExtensionBlocks` без освобождения при ошибке
2. **Строки 250-256:** `reallocarray` успешен, но при ошибке выделения `ep->Bytes` память не освобождается
3. **Строки 271-275:** При ошибке выделения `ep->Bytes` память `ExtensionBlocks` не освобождается

#### Код с уязвимостью
```c
if (*ExtensionBlocks == NULL) {
    *ExtensionBlocks = (ExtensionBlock *)malloc(sizeof(ExtensionBlock));  // Строка 243-244
} else {
    ExtensionBlock *ep_new = (ExtensionBlock *)reallocarray(
        *ExtensionBlocks, (*ExtensionBlockCount + 1), sizeof(ExtensionBlock));  // Строки 250-252
    if (ep_new == NULL) {
        return (GIF_ERROR);  // Строка 254 - память не освобождается
    }
    *ExtensionBlocks = ep_new;
}

ep->Bytes = (GifByteType *)malloc(ep->ByteCount);  // Строка 271
if (ep->Bytes == NULL) {
    return (GIF_ERROR);  // Строка 274 - память ExtensionBlocks не освобождается
}
```


### 4. Memory Leaks в GifMakeSavedImage

**Файл:** `libgif_repo/gifalloc.c:345-400`  
**Функция:** `GifMakeSavedImage`  
**Тип:** Memory Leak

#### Описание
В функции `GifMakeSavedImage` происходит утечка памяти при ошибках:

1. **Строки 353-361:** Выделение памяти для `SavedImages` без освобождения при ошибке
2. **Строки 383-389:** При ошибке `GifMakeMapObject` память `SavedImages` не освобождается
3. **Строки 393-400:** При ошибке `reallocarray` для `RasterBits` память не освобождается

#### Код с уязвимостью
```c
if (GifFile->SavedImages == NULL) {
    GifFile->SavedImages = (SavedImage *)malloc(sizeof(SavedImage));  // Строка 353
} else {
    SavedImage *newSavedImages = (SavedImage *)reallocarray(
        GifFile->SavedImages, (GifFile->ImageCount + 1),
        sizeof(SavedImage));  // Строки 355-357
    if (newSavedImages == NULL) {
        return ((SavedImage *)NULL);  // Строка 359 - память не освобождается
    }
    GifFile->SavedImages = newSavedImages;
}

// ... код копирования ...

sp->RasterBits = (unsigned char *)reallocarray(
    NULL,
    (CopyFrom->ImageDesc.Height * CopyFrom->ImageDesc.Width),
    sizeof(GifPixelType));  // Строки 393-397
if (sp->RasterBits == NULL) {
    FreeLastSavedImage(GifFile);  // Строка 399 - частичное освобождение
    return ((SavedImage *)NULL);
}
```

### 5. Memory Leaks в DGifSlurp

**Файл:** `libgif_repo/dgif_lib.c:1189-1290`  
**Функция:** `DGifSlurp`  
**Тип:** Memory Leak

#### Описание
В функции `DGifSlurp` происходит утечка памяти в нескольких местах:

1. **Строки 1189-1195:** При ошибке в `DGifGetImageDesc` выделенная память для `ColorMap` не освобождается
2. **Строки 1274-1283:** При ошибке в `GifAddExtensionBlock` память не освобождается
3. **Строки 1288-1290:** При ошибке в `DGifGetExtensionNext` память не освобождается

#### Код с уязвимостью
```c
case IMAGE_DESC_RECORD_TYPE:
    if (DGifGetImageDesc(GifFile) == GIF_ERROR) {
        /* MEMORY LEAK: Если произошла ошибка в DGifGetImageDesc и внутри этой функции
         * был выделен ColorMap, эта память не будет освобождена при выходе отсюда с ошибкой.
         */
        return (GIF_ERROR);  // Строка 1195
    }

// ... код обработки ...

if (ExtData != NULL) {
    if (GifAddExtensionBlock(
            &GifFile->ExtensionBlockCount,
            &GifFile->ExtensionBlocks, ExtFunction,
            ExtData[0], &ExtData[1]) == GIF_ERROR) {
        return (GIF_ERROR);  // Строка 1282 - память не освобождается
    }
}
for (;;) {
    if (DGifGetExtensionNext(GifFile, &ExtData) == GIF_ERROR) {
        /* MEMORY LEAK: При ошибке здесь, память, выделенная в GifAddExtensionBlock
         * не будет освобождена.
         */
        return (GIF_ERROR);  // Строка 1290
    }
}
```


### 6. Double-Free в GifFreeExtensions

**Файл:** `libgif_repo/gifalloc.c:285-300`  
**Функция:** `GifFreeExtensions`  
**Тип:** Double-Free

#### Описание
В функции `GifFreeExtensions` происходит попытка освободить уже освобожденную память. Проблема возникает при повторном вызове функции или при неправильном управлении жизненным циклом объектов.

#### Код с уязвимостью
```c
void GifFreeExtensions(int *ExtensionBlockCount, ExtensionBlock **ExtensionBlocks) {
    ExtensionBlock *ep;

    if (*ExtensionBlocks == NULL) {
        return;
    }

    for (ep = *ExtensionBlocks; ep < (*ExtensionBlocks + *ExtensionBlockCount); ep++) {
        if (ep->Bytes != NULL) {
            free(ep->Bytes);  // Строка 295 - может быть double-free
        }
    }
    free(*ExtensionBlocks);  // Строка 299 - может быть double-free
    *ExtensionBlocks = NULL;
}
```

### 7. Memory Leaks в GifFreeSavedImages

**Файл:** `libgif_repo/gifalloc.c:310-330`  
**Функция:** `GifFreeSavedImages`  
**Тип:** Memory Leak

#### Описание
В функции `GifFreeSavedImages` происходит утечка памяти при освобождении сохраненных изображений. Некоторые поля структуры `SavedImage` не освобождаются корректно.

## Примеры краш-кейсов

Краш-кейсы, вызывающие обнаруженные уязвимости, находятся в папке `crash_examples/`. Эти файлы были извлечены из результатов фаззинга AFL++ и организованы по типам уязвимостей.


