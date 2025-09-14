#!/bin/bash

# AFL использует CC напрямую
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=address,leak -fno-inline -fcoverage-mapping -fprofile-instr-generate"
export AFL_USE_ASAN=1
export AFL_USE_LSAN=1

# Настройки ASAN для детектирования утечек
export ASAN_OPTIONS="detect_leaks=1:allocator_may_return_null=1:abort_on_error=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_string_checks=1:detect_invalid_pointer_pairs=2:symbolize=0"

# Настройки LSAN для детектирования утечек
export LSAN_OPTIONS="exitcode=1:symbolize=0:print_suppressions=0:detect_leaks=1:suppressions=lsan.supp"

# Изменяем логику AFL++ для классификации крэшей
export AFL_SKIP_CRASHES=0       # Не пропускать крэши
export AFL_IGNORE_TIMEOUTS=1    # Игнорировать таймауты
export AFL_KEEP_TIMEOUTS=1      # Сохранять тест-кейсы, вызывающие таймауты
export AFL_HANG_TMOUT=1000+     # Таймаут для определения зависаний (1+ секунда)
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1  # Игнорировать отсутствие крэшей при проверке
export AFL_CRASH_EXITCODE=1     # Код выхода для крэшей

export OUTPUT_DIR=$PWD/out
export SOURCE="full_gif_fuzzer.c"
export OBJECT="full_gif_fuzzer"

# Создаем директории заранее
mkdir -p $OUTPUT_DIR
mkdir -p coverage
mkdir -p in

# Генерируем шаблонный GIF для начального корпуса
if [ ! -f in/template.gif ]; then
    echo "Генерируем шаблонный GIF для корпуса..."
    cd ../libgif_repo
    ./gifcolor -v -b -g 2 2 > ../libgif/in/template.gif
    cd ../libgif

    # Проверяем успешность создания
    if [ ! -f in/template.gif ]; then
        echo "Ошибка: Не удалось создать шаблонный GIF"
        exit 1
    fi
fi

# Устанавливаем путь для профилей после создания директории
export LLVM_PROFILE_FILE="$OUTPUT_DIR/profile-%p-%m.profraw"

function compile {
    echo "Компиляция libgif и фаззера..."
    cd ../libgif_repo
    make clean
    make -j$(nproc)
    cd ../libgif
    # Добавляем флаги профилирования для фаззера
    $CC $CFLAGS -o $OBJECT $SOURCE -I../libgif_repo ../libgif_repo/libgif.a -fprofile-instr-generate -fcoverage-mapping
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
    
    # Запускаем основной фаззер с UI
    AFL_AUTORESUME=1 afl-fuzz -i in -o $OUTPUT_DIR -x dict -m none -M fuzzer01 ./$OBJECT &
    
    # Запускаем дополнительные фаззеры без UI
    for i in {2..4}; do
        echo "Запуск фаззера $i..."
        AFL_AUTORESUME=1 afl-fuzz -i in -o $OUTPUT_DIR -x dict -m none -S fuzzer0$i ./$OBJECT > /dev/null 2>&1 &
    done
    
    # Ждем завершения основного фаззера
    wait
}

# Основной процесс
compile
fuzz