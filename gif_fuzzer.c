#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "gif_lib.h"
#include <sanitizer/lsan_interface.h>

// Буфер для входных данных
#define MAX_FILE_SIZE 1024 * 1024  // 1MB максимальный размер

// Функция для фаззинга в persistent mode
__AFL_FUZZ_INIT();

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_FILE_SIZE) {
        return 0;
    }

    // Проверка на специальные паттерны, которые могут вызвать проблемы
    if (size >= 6) {
        // Проверка на валидный GIF заголовок
        if (memcmp(data, "GIF87a", 6) != 0 && memcmp(data, "GIF89a", 6) != 0) {
            return 2; // Невалидный GIF заголовок
        }
    } else {
        return 3; // Слишком маленький размер для GIF файла
    }

    // Создаем временный файл для входных данных
    char filename[] = "/tmp/libgif_fuzz_XXXXXX";
    int fd = mkstemp(filename);
    if (fd < 0) {
        return 1; // Ошибка создания файла
    }
    
    write(fd, data, size);
    close(fd);

    // Открываем GIF файл
    int error = 0;
    GifFileType *gif = DGifOpenFileName(filename, &error);
    
    if (!gif) {
        unlink(filename);
        return error; // Возвращаем код ошибки
    }
    
    // Читаем GIF
    if (DGifSlurp(gif) != GIF_OK) {
        error = gif->Error;
        DGifCloseFile(gif, &error);
        unlink(filename);
        return error; // Возвращаем код ошибки
    }
    
    // Проверяем некоторые свойства GIF
    if (gif->ImageCount > 0) {
        SavedImage *image = &gif->SavedImages[0];
        // Доступ к данным изображения для провоцирования возможных ошибок
        if (image->ImageDesc.Width > 0 && image->ImageDesc.Height > 0) {
            GifByteType *raster = image->RasterBits;
            // Просто читаем данные
            if (raster) {
                volatile unsigned char pixel = raster[0];
                (void)pixel;
            }
        }
    }
    
    error = gif->Error;
    DGifCloseFile(gif, &error);
    unlink(filename);
    
    return error; // Возвращаем код ошибки, даже если все в порядке
}

#ifdef __AFL_COMPILER
int main() {
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;
        LLVMFuzzerTestOneInput(buf, len);

        // Проверяем утечки после каждой итерации
        //int leaks_found = __lsan_do_recoverable_leak_check();
        //if (leaks_found > 0) {
            // Если найдены утечки, завершаем процесс с абортом
            //abort();
        //}
    }

    return 0;
}
#else
int main(int argc, char **argv) {
    // Для запуска без AFL
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <gif-file>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    unsigned char *buf = malloc(size);
    fread(buf, 1, size, f);
    fclose(f);
    
    LLVMFuzzerTestOneInput(buf, size);
    free(buf);
    return 0;
}
#endif 