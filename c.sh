#!/bin/bash

# Настройка переменных окружения

# AFL использует CC напрямую
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=fuzzer -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export OUTPUT_DIR=$PWD/out
export SOURCE="gif_fuzzer.c"
export OBJECT="gif_fuzzer"

# Создаем директории если их нет
mkdir -p $OUTPUT_DIR
mkdir -p coverage

# Устанавливаем путь для профилей
export LLVM_PROFILE_FILE="$OUTPUT_DIR/profile-%p-%m.profraw"

function merge_profiles {
    echo "Слияние файлов профилей..."
    if [ -f "$OUTPUT_DIR"/*.profraw ]; then
        llvm-profdata-14 merge "default.profraw" -o coverage/result.profdata
    else
        echo "Нет файлов профилей для слияния"
        exit 1
    fi
}

function export_coverage {
    echo "Экспорт покрытия в формат lcov..."
    # Собираем список всех .c файлов в libgif_repo и добавляем gif_fuzzer.c
    GIF_SOURCES=$(find ../libgif_repo -name "*.c")
    FUZZER_SOURCE="$PWD/$SOURCE"
    
    # Экспортируем покрытие для фаззера и всех исходников libgif
    llvm-cov-14 export $OBJECT $GIF_SOURCES $FUZZER_SOURCE \
             --instr-profile=coverage/result.profdata \
             --format=lcov > coverage/coverage.info

    # Генерируем HTML отчет, игнорируя ошибки unmapped
    genhtml coverage/coverage.info --output-directory coverage/html #--ignore-errors
}

echo "Начинаем сбор покрытия на всех найденных кейсах..."
#collect_crashes_coverage
#collect_hangs_coverage
#collect_queue_coverage
merge_profiles
export_coverage
