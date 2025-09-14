#!/bin/bash

# Настройка переменных окружения
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=fuzzer -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export SOURCE="full_gif_fuzzer.c"
export OBJECT="full_gif_fuzzer"

# Функция для запуска программы с тест-кейсами из одной директории
function run_testcases_from_dir {
    local OUTPUT_DIR=$1
    echo "Запуск тест-кейсов из директории: $OUTPUT_DIR"
    
    # Устанавливаем путь для профилей
    export LLVM_PROFILE_FILE="$OUTPUT_DIR/profile-%p-%m.profraw"
    
    # Собираем покрытие из всех поддиректорий
    for FUZZER_DIR in "$OUTPUT_DIR"/fuzzer*; do
        if [ -d "$FUZZER_DIR" ]; then
            echo "Обработка фаззера: $FUZZER_DIR"
            
            # Обрабатываем crashes
            if [ -d "$FUZZER_DIR/crashes" ]; then
                echo "Обработка краш-кейсов из $FUZZER_DIR/crashes"
                for crash in "$FUZZER_DIR/crashes/"*; do
                    if [ -f "$crash" ] && [ "$(basename "$crash")" != "README.txt" ]; then
                        echo "  - Запуск с краш-кейсом: $crash"
                        ./$OBJECT < "$crash"
                    fi
                done
            fi
            
            # Обрабатываем hangs
            if [ -d "$FUZZER_DIR/hangs" ]; then
                echo "Обработка зависших кейсов из $FUZZER_DIR/hangs"
                for hang in "$FUZZER_DIR/hangs/"*; do
                    if [ -f "$hang" ] && [ "$(basename "$hang")" != "README.txt" ]; then
                        echo "  - Запуск с зависшим кейсом: $hang"
                        timeout 5s ./$OBJECT < "$hang"
                    fi
                done
            fi
            
            # Обрабатываем queue
            if [ -d "$FUZZER_DIR/queue" ]; then
                echo "Обработка кейсов из очереди $FUZZER_DIR/queue"
                for queue_item in "$FUZZER_DIR/queue/"*; do
                    if [ -f "$queue_item" ] && [ "$(basename "$queue_item")" != "README.txt" ]; then
                        echo "  - Запуск с кейсом из очереди: $queue_item"
                        ./$OBJECT < "$queue_item"
                    fi
                done
            fi
        fi
    done
    
    echo "Завершен запуск тест-кейсов из директории: $OUTPUT_DIR"
}

# Проверяем, указана ли директория как параметр
if [ $# -eq 1 ]; then
    if [ -d "$1" ]; then
        run_testcases_from_dir "$1"
        exit 0
    else
        echo "Указанная директория не существует: $1"
        exit 1
    fi
fi

# Если директория не указана, обрабатываем все директории out*
echo "=== Запуск программы со всеми тест-кейсами ==="
FOUND=0
for OUT_DIR in out*; do
    if [ -d "$OUT_DIR" ]; then
        FOUND=1
        run_testcases_from_dir "$OUT_DIR"
    fi
done

if [ $FOUND -eq 0 ]; then
    echo "Не найдено директорий, начинающихся с 'out'"
    exit 1
fi

echo "=== Все тест-кейсы обработаны ==="
exit 0 