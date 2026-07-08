#!/usr/bin/env bash
# Clipper2/mayhem/build.sh — sanitized fuzz_clipper harness + standalone reproducer, plus the
# GoogleTest suite (normal flags) for mayhem/test.sh.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

INC="-I$SRC/CPP/Clipper2Lib/include"
CXXFLAGS="-std=c++17 $INC"

# 1) Sanitized Clipper2 static library (instrument the fuzzed code, not just the harness)
cmake -S "$SRC/CPP" -B "$SRC/build-fuzz" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCLIPPER2_EXAMPLES=OFF \
  -DCLIPPER2_TESTS=OFF \
  -DCLIPPER2_UTILS=OFF >/dev/null
cmake --build "$SRC/build-fuzz" -j"$MAYHEM_JOBS" --target Clipper2

# 2) libFuzzer target (Mayhem)
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS \
  "$SRC/mayhem/fuzz_clipper.cpp" \
  "$SRC/build-fuzz/libClipper2.a" -lm \
  $LIB_FUZZING_ENGINE \
  -o /mayhem/fuzz_clipper

# 3) Standalone reproducer (C driver keeps extern "C" linkage for the harness)
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/standalone_main.o
# shellcheck disable=SC2086
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $CXXFLAGS \
  "$SRC/mayhem/fuzz_clipper.cpp" /tmp/standalone_main.o \
  "$SRC/build-fuzz/libClipper2.a" -lm \
  -o /mayhem/fuzz_clipper-standalone

# 4) Functional test suite — normal flags, system GoogleTest (air-gapped; no git clone)
cmake -S "$SRC/CPP" -B "$SRC/build-tests" \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DUSE_EXTERNAL_GTEST=ON \
  -DCLIPPER2_EXAMPLES=OFF \
  -DCLIPPER2_UTILS=ON >/dev/null
cmake --build "$SRC/build-tests" -j"$MAYHEM_JOBS" --target ClipperTests
