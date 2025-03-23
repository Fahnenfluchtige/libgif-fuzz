#!/bin/bash

# AFL использует CC напрямую
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export CFLAGS="-g -O1 -fsanitize=fuzzer -fno-inline -fcoverage-mapping -fprofile-instr-generate"
#export MSAN_OPTIONS="exit_code=86:abort_on_error=1:symbolize=0"

export OUTPUT_DIR=$PWD/out
export SOURCE="gif_fuzzer.c"
export OBJECT="gif_fuzzer"

# Создаем директории заранее
mkdir -p $OUTPUT_DIR
mkdir -p coverage

# Устанавливаем путь для профилей после создания директории
export LLVM_PROFILE_FILE="$OUTPUT_DIR/profile-%p-%m.profraw"

export AFL_SKIP_CRASHES=1
export AFL_IGNORE_TIMEOUTS=1
export AFL_KEEP_TIMEOUTS=1
export AFL_HANG_TMOUT=1000+

function compile {
    echo "Компиляция libgif и фаззера..."
    cd ../libgif_repo
    make clean
    make
    cd ../libgif
    $CC $CFLAGS -o $OBJECT $SOURCE -I../libgif_repo ../libgif_repo/libgif.a
}

function fuzz {
    echo "Запуск фаззинга..."
    mkdir -p in
    # Сохраняем LLVM_PROFILE_FILE перед запуском AFL
    #OLD_PROFILE_FILE=$LLVM_PROFILE_FILE
    AFL_AUTORESUME=1 afl-fuzz -i in -o out -x dict ./$OBJECT
    # Восстанавливаем LLVM_PROFILE_FILE после AFL
    #export LLVM_PROFILE_FILE=$OLD_PROFILE_FILE
}

# Основной процесс
compile
fuzz
