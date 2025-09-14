#!/bin/bash

# Настройка переменных окружения
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=fuzzer -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export SOURCE="full_gif_fuzzer.c"
export OBJECT="full_gif_fuzzer"

# Создаем директории если их нет
mkdir -p coverage

# Функция для компиляции фаззера с покрытием
function compile_fuzzer_with_coverage {
    echo "Компиляция libgif и фаззера для покрытия..."
    cd ../libgif_repo
    make clean
    make -j$(nproc)
    cd ../libgif
    
    # Компилируем фаззер с инструментацией для покрытия
    $CC $CFLAGS -o $OBJECT $SOURCE -I../libgif_repo ../libgif_repo/libgif.a -fprofile-instr-generate -fcoverage-mapping
    
    # Проверяем успешность компиляции
    if [ $? -ne 0 ]; then
        echo "Ошибка при компиляции фаззера!"
        exit 1
    fi
}

# Функция для запуска программы с тест-кейсами из одной директории
function collect_coverage_from_dir {
    local OUTPUT_DIR=$1
    local COV_SUBDIR=$(basename $OUTPUT_DIR)
    
    echo "Запуск тест-кейсов из директории: $OUTPUT_DIR"
    
    # Создаем поддиректорию для профилей этой директории
    mkdir -p "coverage/$COV_SUBDIR"
    
    # Устанавливаем путь для профилей
    export LLVM_PROFILE_FILE="coverage/$COV_SUBDIR/profile-%p-%m.profraw"
    
    # Собираем покрытие из всех поддиректорий
    for FUZZER_DIR in "$OUTPUT_DIR"/fuzzer*; do
        if [ -d "$FUZZER_DIR" ]; then
            echo "Обработка фаззера: $FUZZER_DIR"
            
            # Обрабатываем crashes
            if [ -d "$FUZZER_DIR/crashes" ]; then
                for crash in "$FUZZER_DIR/crashes/"*; do
                    if [ -f "$crash" ] && [ "$(basename "$crash")" != "README.txt" ]; then
                        echo "Обработка краш-кейса: $crash"
                        ./$OBJECT < "$crash"
                    fi
                done
            fi
            
            # Обрабатываем hangs
            if [ -d "$FUZZER_DIR/hangs" ]; then
                for hang in "$FUZZER_DIR/hangs/"*; do
                    if [ -f "$hang" ] && [ "$(basename "$hang")" != "README.txt" ]; then
                        echo "Обработка зависшего кейса: $hang"
                        timeout 5s ./$OBJECT < "$hang"
                    fi
                done
            fi
            
            # Обрабатываем queue
            if [ -d "$FUZZER_DIR/queue" ]; then
                for queue_item in "$FUZZER_DIR/queue/"*; do
                    if [ -f "$queue_item" ] && [ "$(basename "$queue_item")" != "README.txt" ]; then
                        echo "Обработка кейса из очереди: $queue_item"
                        ./$OBJECT < "$queue_item"
                    fi
                done
            fi
        fi
    done
    
    echo "Завершен запуск тест-кейсов из директории: $OUTPUT_DIR"
    
    # Слияние профилей
    merge_profiles "coverage/$COV_SUBDIR"
}

# Функция для слияния профилей из одной директории
function merge_profiles {
    local PROFILE_DIR=$1
    echo "Слияние профилей из директории: $PROFILE_DIR"
    
    # Проверяем наличие профилей
    if ls "$PROFILE_DIR"/*.profraw 1> /dev/null 2>&1; then
        echo "Найдены профили для $PROFILE_DIR, объединяем..."
        llvm-profdata-14 merge "$PROFILE_DIR"/*.profraw -o "$PROFILE_DIR/result.profdata"
        echo "Профили объединены в $PROFILE_DIR/result.profdata"
        return 0
    else
        echo "Не найдено профилей для $PROFILE_DIR"
        return 1
    fi
}

# Функция для слияния всех профилей
function merge_all_profiles {
    echo "Слияние всех профилей..."
    local PROFILE_FILES=$(find coverage -name "result.profdata")
    if [ -n "$PROFILE_FILES" ]; then
        llvm-profdata-14 merge $PROFILE_FILES -o coverage/final.profdata
        echo "Профили объединены в coverage/final.profdata"
        return 0
    else
        echo "Нет файлов профилей для слияния"
        return 1
    fi
}

# Функция для экспорта покрытия в формат lcov и генерации HTML отчета
function export_coverage {
    echo "Экспорт покрытия в формат lcov..."
    # Собираем список всех .c файлов в libgif_repo и добавляем full_gif_fuzzer.c
    GIF_SOURCES=$(find ../libgif_repo -name "*.c")
    FUZZER_SOURCE="$PWD/$SOURCE"
    
    # Экспортируем покрытие для фаззера и всех исходников libgif
    llvm-cov-14 export $OBJECT $GIF_SOURCES $FUZZER_SOURCE \
             --instr-profile=coverage/final.profdata \
             --format=lcov > coverage/coverage.info

    # Генерируем HTML отчет
    genhtml coverage/coverage.info --output-directory coverage/html
    echo "HTML отчет сгенерирован в coverage/html"
    
    # Выводим общую информацию о покрытии
    echo "Общая информация о покрытии:"
    llvm-cov-14 report $OBJECT $GIF_SOURCES \
             --instr-profile=coverage/final.profdata
}

# Основной процесс
echo "Начинаем сбор покрытия..."

# Этап 0: Компиляция с покрытием
compile_fuzzer_with_coverage

# Этап 1: Запуск программы со всеми тест-кейсами
echo "Этап 1: Запуск программы со всеми тест-кейсами"
for OUT_DIR in out*; do
    if [ -d "$OUT_DIR" ]; then
        collect_coverage_from_dir "$OUT_DIR"
    fi
done

# Этап 2: Дополнительные тесты для улучшения покрытия
echo "Этап 2: Запуск дополнительных тестов для покрытия"

# Создаем директорию для дополнительных тестов
mkdir -p "coverage/extra_tests"
export LLVM_PROFILE_FILE="coverage/extra_tests/profile-%p-%m.profraw"

# Запускаем фаззер напрямую с различными входными данными
# Примеры случайных данных для тестирования edge cases
echo -n -e "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x00\xff\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00\x3b" > coverage/minimal.gif
echo -n -e "\x47\x49\x46\x38\x39\x61\xff\xff\xff\xff\x00\xff\x00\x2c\x00\x00\x00\x00\xff\xff\xff\xff\x00\x02\x00\x3b" > coverage/edge_case.gif

# Тестируем с валидными GIF файлами
echo "Запуск тестов с валидными GIF файлами..."
./$OBJECT < coverage/minimal.gif
./$OBJECT < coverage/edge_case.gif

# Тестируем с невалидными данными
echo "Запуск тестов с невалидными данными..."
echo -n -e "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09" > coverage/invalid.bin
./$OBJECT < coverage/invalid.bin

# Слияние дополнительных тестов
merge_profiles "coverage/extra_tests"

# Этап 3: Слияние всех профилей и генерация отчета
echo "Этап 3: Слияние всех профилей и генерация отчета"
if merge_all_profiles; then
    # Экспорт покрытия и генерация отчета
    export_coverage
    echo "Обработка завершена успешно"
else
    echo "Ошибка при объединении всех профилей"
    exit 1
fi
