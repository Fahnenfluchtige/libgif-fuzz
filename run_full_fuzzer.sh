#!/bin/bash

# AFL использует CC напрямую
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=address -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export AFL_USE_ASAN=1
export AFL_USE_LSAN=1

# Настройки ASAN для детектирования утечек
export ASAN_OPTIONS="detect_leaks=1:allocator_may_return_null=1:abort_on_error=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_string_checks=1:detect_invalid_pointer_pairs=2:symbolize=0"

# Настройки LSAN для детектирования утечек
export LSAN_OPTIONS="exitcode=1:symbolize=0:print_suppressions=0:detect_leaks=1"

# Изменяем логику AFL++ для классификации крэшей
export AFL_SKIP_CRASHES=0       # Не пропускать крэши
export AFL_IGNORE_TIMEOUTS=1    # Игнорировать таймауты
export AFL_KEEP_TIMEOUTS=1      # Сохранять тест-кейсы, вызывающие таймауты
export AFL_HANG_TMOUT=1000+     # Таймаут для определения зависаний (1+ секунда)
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  # Игнорировать отсутствие крэшей при проверке
export AFL_CRASH_EXITCODE=1     # Код выхода для крэшей

export OUTPUT_DIR=$PWD/out_full_test
export SOURCE="full_gif_fuzzer.c"
export OBJECT="full_gif_fuzzer"

# Создаем директории заранее
mkdir -p $OUTPUT_DIR
mkdir -p coverage

# Устанавливаем путь для профилей после создания директории
export LLVM_PROFILE_FILE="$OUTPUT_DIR/profile-%p-%m.profraw"

function compile {
    echo "Компиляция libgif и полного фаззера..."
    cd ../libgif_repo
    make clean
    make -j$(nproc)
    cd ../libgif
    $CC $CFLAGS -o $OBJECT $SOURCE -I../libgif_repo ../libgif_repo/libgif.a
    
    echo "Проверка бинарного файла..."
    file $OBJECT
}

function cleanup {
    echo "Остановка фаззеров..."
    pkill -P $$  # Останавливаем все дочерние процессы
    exit 0
}

# Устанавливаем обработчик Ctrl+C
trap cleanup SIGINT SIGTERM

function fuzz {
    echo "Запуск фаззинга с полным фаззером..."
    mkdir -p in
    ls -la
    
    # Подготовка входных данных - копируем пример GIF файла, если есть
    if [ -d "../libgif_repo/pic" ]; then
        find ../libgif_repo/pic -name "*.gif" -exec cp {} in/ \;
    fi
    
    # Если нет входных данных, создаем минимальный валидный GIF файл
    if [ ! "$(ls -A in)" ]; then
        echo "Создание минимального GIF файла..."
        echo -ne "GIF89a\x01\x00\x01\x00\x00\x00\x00;" > in/minimal.gif
    fi
    
    # Запускаем основной фаззер с UI
    AFL_AUTORESUME=1 AFL_ui=1 afl-fuzz -i in -o $OUTPUT_DIR -x dict -M fuzzer01 ./$OBJECT 
    # Запускаем дополнительные фаззеры без UI
    #for i in {2..3}; do
    #    echo "Запуск фаззера $i..."
    #    AFL_AUTORESUME=1 afl-fuzz -i in -o $OUTPUT_DIR -x dict -S fuzzer0$i ./$OBJECT > /dev/null 2>&1 &
    #done
    
    # Ждем завершения основного фаззера
    wait
}

# Основной процесс
compile
fuzz 