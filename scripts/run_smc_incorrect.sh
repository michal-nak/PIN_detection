#!/bin/bash
PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./3_smc_incorrect_handling

gcc -z execstack -no-pie -o $BIN ./3_smc_incorrect_handling.c -O0

echo "[TEST 1] Running natively..."
$BIN

echo "------------------------------------------"

echo "[TEST 2] Running under Valgrind..."
valgrind --tool=memcheck $BIN