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


function collect_crashes_coverage {
    echo "Сбор покрытия на краш-кейсах..."
    if [ -d "$OUTPUT_DIR/default/crashes" ]; then
        for crash in "$OUTPUT_DIR/default/crashes/"*; do
            if [ -f "$crash" ]; then
                echo "Обработка краш-кейса: $crash"
                ./$OBJECT < "$crash"
            fi
        done
    else
        echo "Директория с краш-кейсами не найдена"
    fi
}

function collect_hangs_coverage {
    echo "Сбор покрытия на зависших кейсах..."
    if [ -d "$OUTPUT_DIR/default/hangs" ]; then
        for hang in "$OUTPUT_DIR/default/hangs/"*; do
            if [ -f "$hang" ]; then
                echo "Обработка зависшего кейса: $hang"
                timeout 5s ./$OBJECT < "$hang"
            fi
        done
    else
        echo "Директория с зависшими кейсами не найдена"
    fi
}

function collect_queue_coverage {
    echo "Сбор покрытия на кейсах из очереди..."
    if [ -d "$OUTPUT_DIR/default/queue" ]; then
        for queue_item in "$OUTPUT_DIR/default/queue/"*; do
            if [ -f "$queue_item" ]; then
                echo "Обработка кейса из очереди: $queue_item"
                ./$OBJECT < "$queue_item"
            fi
        done
    else
        echo "Директория с очередью не найдена"
    fi
}

function merge_profiles {
    echo "Слияние файлов профилей..."
    if [ -f "$OUTPUT_DIR"/*.profraw ]; then
        llvm-profdata merge "$OUTPUT_DIR"/*.profraw -o coverage/result.profdata
    else
        echo "Нет файлов профилей для слияния"
        exit 1
    fi
}

function export_coverage {
    echo "Экспорт покрытия в формат lcov..."
    # Собираем список всех .c файлов в libgif_repo
    GIF_SOURCES=$(find ../libgif_repo -name "*.c")
    
    # Экспортируем покрытие для фаззера и всех исходников libgif
    llvm-cov export $OBJECT $GIF_SOURCES \
             --instr-profile=coverage/result.profdata \
             --format=lcov > coverage/coverage.info

    # Генерируем HTML отчет, игнорируя ошибки unmapped
    genhtml coverage/coverage.info --output-directory coverage/html --ignore-errors unmapped
}

echo "Начинаем сбор покрытия на всех найденных кейсах..."
#collect_crashes_coverage
#collect_hangs_coverage
#collect_queue_coverage
merge_profiles
export_coverage
