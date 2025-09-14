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

// Тестирование функций работы с цветовой палитрой и ColorMapObject
void test_color_map_functions(const uint8_t *data, size_t size) {
    if (size < 10) return;
    
    // Создаем цветовую палитру
    int colorCount = (data[0] % 256) + 1; // 1-256 цветов
    
    // Тестирование GifMakeMapObject
    ColorMapObject *colorMap = GifMakeMapObject(colorCount, NULL);
    if (!colorMap) return;
    
    // Заполняем цвета из входных данных
    for (int i = 0; i < colorMap->ColorCount && i < size/3; i++) {
        int offset = i * 3;
        if (offset + 2 < size) {
            colorMap->Colors[i].Red = data[offset];
            colorMap->Colors[i].Green = data[offset + 1];
            colorMap->Colors[i].Blue = data[offset + 2];
        }
    }
    
    // Тестирование сортировки и других свойств ColorMapObject
    colorMap->SortFlag = (data[size/2] & 1) ? true : false;
    
    // Тестирование FreeMapObject
    GifFreeMapObject(colorMap);
    
    // Тестирование GifUnionColorMap, если есть достаточно данных
    if (size >= 50) {
        ColorMapObject *map1 = GifMakeMapObject(((data[size/3] % 16) + 1), NULL);
        ColorMapObject *map2 = GifMakeMapObject(((data[size/2] % 16) + 1), NULL);
        
        if (map1 && map2) {
            // Заполнение случайными цветами
            for (int i = 0; i < map1->ColorCount; i++) {
                int idx = (i * 7) % size;
                map1->Colors[i].Red = data[idx % size];
                map1->Colors[i].Green = data[(idx + 1) % size];
                map1->Colors[i].Blue = data[(idx + 2) % size];
            }
            
            for (int i = 0; i < map2->ColorCount; i++) {
                int idx = (i * 11) % size;
                map2->Colors[i].Red = data[idx % size];
                map2->Colors[i].Green = data[(idx + 1) % size];
                map2->Colors[i].Blue = data[(idx + 2) % size];
            }
            
            // Создание таблицы трансляции цветов
            GifPixelType transTable[256];
            memset(transTable, 0, sizeof(transTable));
            
            // Вызов функции для слияния палитр
            ColorMapObject *unionMap = GifUnionColorMap(map1, map2, transTable);
            
            // Если слияние успешно, трансляция пикселей
            if (unionMap) {
                GifPixelType pixelData[10];
                for (int i = 0; i < 10 && i < size; i++) {
                    pixelData[i] = data[i] % map2->ColorCount;
                }
                
                // Тестируем функцию трансляции пикселей
                GifApplyTranslation(NULL, transTable); // Намеренно вызываем с NULL для проверки обработки ошибок
                
                // Создаем SavedImage для правильного тестирования
                SavedImage testImage;
                memset(&testImage, 0, sizeof(SavedImage));
                
                testImage.RasterBits = malloc(10);
                if (testImage.RasterBits) {
                    memcpy(testImage.RasterBits, pixelData, 10);
                    testImage.ImageDesc.Width = 5;
                    testImage.ImageDesc.Height = 2;
                    
                    // Теперь вызываем функцию с валидными данными
                    GifApplyTranslation(&testImage, transTable);
                    
                    free(testImage.RasterBits);
                }
                
                GifFreeMapObject(unionMap);
            }
            
            GifFreeMapObject(map1);
            GifFreeMapObject(map2);
        } else {
            // Очистка в случае частичного успеха
            if (map1) GifFreeMapObject(map1);
            if (map2) GifFreeMapObject(map2);
        }
    }
}

// Тестирование функций работы с ExtensionBlock
void test_extension_functions(const uint8_t *data, size_t size) {
    if (size < 20) return;
    
    // Переменные для работы с блоками расширений
    int extCount = 0;
    ExtensionBlock *extBlocks = NULL;
    
    // Создаем несколько блоков расширений
    for (int i = 0; i < 5 && (i+1)*4 < size; i++) {
        int function = data[i*4] % 256; // Функция расширения
        int len = data[i*4 + 1] % 20;   // Длина данных (ограничиваем для стабильности)
        
        // Убедимся, что у нас достаточно данных
        if (i*4 + 2 + len >= size) len = size - i*4 - 2;
        if (len <= 0) continue;
        
        // Проверяем успешность добавления блока
        if (GifAddExtensionBlock(&extCount, &extBlocks, function, len, &data[i*4 + 2]) == GIF_ERROR) {
            break;
        }
    }
    
    // Освобождаем память блоков расширений
    GifFreeExtensions(&extCount, &extBlocks);
}

// Тестирование функций работы с SavedImage
void test_saved_image_functions(GifFileType *gif, const uint8_t *data, size_t size) {
    if (!gif || size < 20) return;
    
    // Создаем новый GifFileType для тестирования
    GifFileType testGif;
    memset(&testGif, 0, sizeof(GifFileType));
    
    // Копируем базовую информацию
    testGif.SWidth = data[0] % 100 + 10;
    testGif.SHeight = data[1] % 100 + 10;
    
    // Если исходный GIF имеет изображения, тестируем GifMakeSavedImage
    if (gif->ImageCount > 0) {
        SavedImage *sourceSavedImage = &gif->SavedImages[0];
        
        // Копируем первое изображение
        SavedImage *newImage = GifMakeSavedImage(&testGif, sourceSavedImage);
        
        // Проверяем успешность операции
        if (newImage && testGif.ImageCount > 0) {
            // Тестируем FreeLastSavedImage - это не публичная функция, 
            // но она вызывается внутри других функций
            
            // Очищаем все изображения сразу
            GifFreeSavedImages(&testGif);
        }
    } else {
        // Если нет исходных изображений, создаем новое пустое
        SavedImage *newImage = GifMakeSavedImage(&testGif, NULL);
        
        if (newImage) {
            // Заполняем базовую информацию
            newImage->ImageDesc.Left = data[2] % 10;
            newImage->ImageDesc.Top = data[3] % 10;
            newImage->ImageDesc.Width = data[4] % 50 + 5;
            newImage->ImageDesc.Height = data[5] % 50 + 5;
            
            // Создаем цветовую палитру
            int colorCount = data[6] % 16 + 1;
            newImage->ImageDesc.ColorMap = GifMakeMapObject(colorCount, NULL);
            
            // Создаем растровые данные
            size_t rasterSize = newImage->ImageDesc.Width * newImage->ImageDesc.Height;
            newImage->RasterBits = malloc(rasterSize);
            
            if (newImage->RasterBits) {
                // Заполняем растровые данные
                for (size_t i = 0; i < rasterSize && i < size; i++) {
                    newImage->RasterBits[i] = data[i % size] % colorCount;
                }
            }
            
            // Очищаем все изображения
            GifFreeSavedImages(&testGif);
        }
    }
}

// Преобразование GIF в другой формат и обратно для тестирования записи
void test_gif_write_read(GifFileType *gif, const uint8_t *data, size_t size) {
    if (!gif || gif->ImageCount == 0) return;
    
    int error = 0;
    char temp_filename[] = "/tmp/libgif_write_test_XXXXXX";
    int fd = mkstemp(temp_filename);
    if (fd < 0) return;
    close(fd);
    
    // Попытка записи GIF
    GifFileType *writeGif = EGifOpenFileName(temp_filename, false, &error);
    if (!writeGif) {
        unlink(temp_filename);
        return;
    }
    
    // Копируем информацию из исходного GIF в новый
    writeGif->SWidth = gif->SWidth;
    writeGif->SHeight = gif->SHeight;
    writeGif->SColorResolution = gif->SColorResolution;
    writeGif->SBackGroundColor = gif->SBackGroundColor;
    
    // Копируем цветовую палитру, если есть
    if (gif->SColorMap) {
        writeGif->SColorMap = GifMakeMapObject(
            gif->SColorMap->ColorCount,
            gif->SColorMap->Colors);
    }
    
    // Копируем изображения
    for (int i = 0; i < gif->ImageCount; i++) {
        SavedImage *image = &gif->SavedImages[i];
        
        // Сохраняем информацию об изображении
        if (GifAddExtensionBlock(&writeGif->ExtensionBlockCount,
                               &writeGif->ExtensionBlocks,
                               0,
                               0,
                               NULL) == GIF_ERROR) {
            EGifCloseFile(writeGif, &error);
            unlink(temp_filename);
            return;
        }
        
        // Записываем растровые данные
        if (EGifPutImageDesc(writeGif,
                          image->ImageDesc.Left,
                          image->ImageDesc.Top,
                          image->ImageDesc.Width,
                          image->ImageDesc.Height,
                          image->ImageDesc.Interlace,
                          image->ImageDesc.ColorMap) == GIF_ERROR) {
            EGifCloseFile(writeGif, &error);
            unlink(temp_filename);
            return;
        }
        
        // Записываем данные изображения
        for (int y = 0; y < image->ImageDesc.Height; y++) {
            if (EGifPutLine(writeGif,
                          &image->RasterBits[y * image->ImageDesc.Width],
                          image->ImageDesc.Width) == GIF_ERROR) {
                EGifCloseFile(writeGif, &error);
                unlink(temp_filename);
                return;
            }
        }
    }
    
    // Закрываем файл
    EGifCloseFile(writeGif, &error);
    
    // Пробуем прочитать записанный файл
    GifFileType *readGif = DGifOpenFileName(temp_filename, &error);
    if (readGif) {
        DGifSlurp(readGif);
        DGifCloseFile(readGif, &error);
    }
    
    // Удаляем временный файл
    unlink(temp_filename);
}

// Добавляем тестирование LZW декодирования
void test_lzw_decoding(const uint8_t *data, size_t size) {
    if (size < 30) return; // Нужно минимальное количество данных

    // Создаем минимальный валидный GIF-файл в памяти с LZW данными
    unsigned char gif_header[] = "GIF89a";
    unsigned char screen_desc[] = {
        0x0A, 0x00,     // Width (10px)
        0x0A, 0x00,     // Height (10px)
        0x80 | 0x70,    // Global color table, 8 bits per pixel
        0x00,           // Background color
        0x00            // No aspect ratio info
    };
    
    // Создаем цветовую таблицу размером 256 цветов
    unsigned char color_table[768]; // 256 colors * 3 bytes (RGB)
    for (int i = 0; i < 256; i++) {
        // Заполняем таблицу цветов данными из входного буфера или значениями по умолчанию
        color_table[i*3] = (i < size) ? data[i % size] : i;
        color_table[i*3+1] = (i < size) ? data[(i+1) % size] : i;
        color_table[i*3+2] = (i < size) ? data[(i+2) % size] : i;
    }

    // Описание изображения
    unsigned char img_desc[] = {
        0x2C,         // Image separator
        0x00, 0x00,   // Left
        0x00, 0x00,   // Top
        0x0A, 0x00,   // Width (10px)
        0x0A, 0x00,   // Height (10px)
        0x00          // No local color table, not interlaced
    };

    // Начало данных изображения с LZW
    unsigned char lzw_start = 0x08;  // Минимальная длина кода LZW

    // Создаем временный файл для хранения нашего GIF
    char tmpfile[] = "/tmp/lzw_test_XXXXXX";
    int fd = mkstemp(tmpfile);
    if (fd < 0) return;

    // Записываем заголовок и блоки
    write(fd, gif_header, sizeof(gif_header)-1);    // -1 чтобы не учитывать нулевой байт строки
    write(fd, screen_desc, sizeof(screen_desc));
    write(fd, color_table, sizeof(color_table));
    write(fd, img_desc, sizeof(img_desc));
    write(fd, &lzw_start, 1);

    // Записываем сжатые LZW данные из входного буфера 
    // (мы просто берем любые данные и пытаемся их интерпретировать как LZW)
    unsigned char block_size = 0;
    for (size_t i = 0; i < size && i < 200; i += block_size + 1) {
        // Используем данные из входного буфера для создания "блоков данных LZW"
        block_size = (i + 1 < size) ? (data[i] % 64) + 1 : 1; // Размер блока - не более 64 байт
        if (i + block_size >= size) block_size = size - i - 1;
        if (block_size == 0) block_size = 1;

        // Записываем размер блока
        write(fd, &block_size, 1);
        
        // Записываем данные блока
        if (block_size > 0) {
            write(fd, &data[i + 1], block_size);
        }
    }

    // Записываем конец данных изображения
    unsigned char end_block = 0x00;   // Блок нулевой длины для завершения данных
    write(fd, &end_block, 1);

    // Записываем конец файла
    unsigned char trailer = 0x3B;    // Трейлер GIF
    write(fd, &trailer, 1);

    close(fd);

    // Теперь пытаемся открыть и прочитать этот GIF, что заставит библиотеку 
    // декодировать LZW данные
    int error = 0;
    GifFileType *gif = DGifOpenFileName(tmpfile, &error);
    
    if (gif) {
        // Пытаемся выполнить декодирование LZW через DGifSlurp
        if (DGifSlurp(gif) == GIF_OK) {
            // Если все успешно, проверяем результаты декодирования
            if (gif->ImageCount > 0) {
                SavedImage *image = &gif->SavedImages[0];
                
                // Доступ к декодированным пикселям
                if (image->RasterBits) {
                    volatile GifPixelType pixel = image->RasterBits[0];
                    (void)pixel; // Избегаем предупреждения о неиспользуемой переменной
                }
            }
        }
        
        DGifCloseFile(gif, &error);
    }

    // Удаляем временный файл
    unlink(tmpfile);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_FILE_SIZE) {
        return 0;
    }

    // Часть 1: Тестирование функций из gifalloc.c, не требующих GIF файла
    test_color_map_functions(data, size);
    test_extension_functions(data, size);
    test_lzw_decoding(data, size);  // Добавляем тестирование LZW

    // Проверка на специальные паттерны для GIF файлов
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

    // Часть 2: Тестирование с использованием GIF файла
    
    // Открываем GIF файл для чтения
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
    
    // Часть 3: Тестирование функций, требующих загруженного GIF файла
    
    // Проверяем некоторые свойства GIF
    if (gif->ImageCount > 0) {
        SavedImage *image = &gif->SavedImages[0];
        // Доступ к данным изображения
        if (image->ImageDesc.Width > 0 && image->ImageDesc.Height > 0) {
            GifByteType *raster = image->RasterBits;
            if (raster) {
                volatile unsigned char pixel = raster[0];
                (void)pixel;
            }
        }
        
        // Тестируем функции работы с цветовой палитрой
        if (image->ImageDesc.ColorMap) {
            GifColorType *colors = image->ImageDesc.ColorMap->Colors;
            if (colors) {
                volatile unsigned char r = colors[0].Red;
                volatile unsigned char g = colors[0].Green;
                volatile unsigned char b = colors[0].Blue;
                (void)r; (void)g; (void)b;
            }
        }
    }
    
    // Тестируем функции создания SavedImage
    test_saved_image_functions(gif, data, size);
    
    // Тестируем функции записи GIF
    test_gif_write_read(gif, data, size);
    
    // Закрываем GIF файл
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
        int leaks_found = __lsan_do_recoverable_leak_check();
        if (leaks_found > 0) {
            // Если найдены утечки, завершаем процесс с абортом
            abort();
        }
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