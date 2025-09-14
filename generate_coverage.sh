#!/bin/bash

# Настройка переменных окружения
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=fuzzer -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export SOURCE="full_gif_fuzzer.c"
export OBJECT="full_gif_fuzzer"

# Создаем директории если их нет
mkdir -p coverage

# Функция для слияния профилей из одной директории
function merge_profiles_from_dir {
    local OUTPUT_DIR=$1
    echo "Слияние профилей из директории: $OUTPUT_DIR"
    
    # Создаем поддиректорию для профилей этой директории
    local PROFILE_DIR="coverage/$(basename $OUTPUT_DIR)"
    mkdir -p "$PROFILE_DIR"
    
    # Проверяем наличие профилей
    if ls "$OUTPUT_DIR"/*.profraw 1> /dev/null 2>&1; then
        echo "Найдены профили для $OUTPUT_DIR, объединяем..."
        llvm-profdata-14 merge "$OUTPUT_DIR"/*.profraw -o "$PROFILE_DIR/result.profdata"
        echo "Профили объединены в $PROFILE_DIR/result.profdata"
        return 0
    else
        echo "Не найдено профилей для $OUTPUT_DIR"
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
    # Собираем список всех .c файлов в libgif_repo и добавляем gif_fuzzer.c
    GIF_SOURCES=$(find ../libgif_repo -name "*.c")
    FUZZER_SOURCE="$PWD/$SOURCE"
    
    # Экспортируем покрытие для фаззера и всех исходников libgif
    llvm-cov-14 export $OBJECT $GIF_SOURCES $FUZZER_SOURCE \
             --instr-profile=coverage/final.profdata \
             --format=lcov > coverage/coverage.info

    # Генерируем HTML отчет
    genhtml coverage/coverage.info --output-directory coverage/html
    echo "HTML отчет сгенерирован в coverage/html"
    
    # Вывод краткой статистики
    echo "=== Статистика покрытия ==="
    llvm-cov-14 report $OBJECT \
             --instr-profile=coverage/final.profdata \
             $GIF_SOURCES $FUZZER_SOURCE | head -n 20
}

# Проверка аргументов
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    echo "Использование: $0 [опции]"
    echo "Опции:"
    echo "  --merge-only   : Только слияние профилей без генерации отчета"
    echo "  --report-only  : Только генерация отчета (предполагает наличие файла coverage/final.profdata)"
    echo "  --dir <dir>    : Обработать только указанную директорию"
    echo "  --help, -h     : Показать эту справку"
    exit 0
fi

# Проверка на режим "только слияние"
if [ "$1" = "--merge-only" ]; then
    echo "=== Только слияние профилей ==="
    
    # Этап 1: Слияние профилей для каждой директории
    echo "Этап 1: Слияние профилей для каждой директории"
    MERGE_SUCCESS=0
    for OUT_DIR in out*; do
        if [ -d "$OUT_DIR" ]; then
            if merge_profiles_from_dir "$OUT_DIR"; then
                MERGE_SUCCESS=1
            fi
        fi
    done
    
    # Этап 2: Слияние всех профилей
    if [ "$MERGE_SUCCESS" -eq 1 ]; then
        echo "Этап 2: Слияние всех профилей"
        if merge_all_profiles; then
            echo "Слияние профилей завершено успешно"
            exit 0
        else
            echo "Ошибка при объединении всех профилей"
            exit 1
        fi
    else
        echo "Не было успешно объединенных профилей для отдельных директорий"
        exit 1
    fi
fi

# Проверка на режим "только отчет"
if [ "$1" = "--report-only" ]; then
    echo "=== Только генерация отчета ==="
    if [ -f "coverage/final.profdata" ]; then
        export_coverage
        echo "Генерация отчета завершена успешно"
        exit 0
    else
        echo "Ошибка: файл coverage/final.profdata не найден"
        echo "Сначала выполните слияние профилей"
        exit 1
    fi
fi

# Проверка на обработку конкретной директории
if [ "$1" = "--dir" ] && [ -n "$2" ]; then
    if [ -d "$2" ]; then
        echo "=== Обработка директории $2 ==="
        if merge_profiles_from_dir "$2"; then
            echo "Профили для директории $2 успешно объединены"
            exit 0
        else
            echo "Ошибка при объединении профилей для директории $2"
            exit 1
        fi
    else
        echo "Ошибка: директория $2 не найдена"
        exit 1
    fi
fi

# Стандартный режим - полный процесс
echo "=== Начинаем генерацию отчета о покрытии ==="

# Этап 1: Слияние профилей для каждой директории
echo "Этап 1: Слияние профилей для каждой директории"
MERGE_SUCCESS=0
for OUT_DIR in out*; do
    if [ -d "$OUT_DIR" ]; then
        if merge_profiles_from_dir "$OUT_DIR"; then
            MERGE_SUCCESS=1
        fi
    fi
done

# Этап 2: Слияние всех профилей и генерация отчета
echo "Этап 2: Слияние всех профилей и генерация отчета"
if [ "$MERGE_SUCCESS" -eq 1 ]; then
    if merge_all_profiles; then
        # Экспорт покрытия и генерация отчета
        export_coverage
        echo "=== Обработка завершена успешно ==="
    else
        echo "Ошибка при объединении всех профилей"
        exit 1
    fi
else
    echo "Не было успешно объединенных профилей для отдельных директорий"
    echo "Возможно, необходимо сначала запустить скрипт run_testcases.sh"
    exit 1
fi 