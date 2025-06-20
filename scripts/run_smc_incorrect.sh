#!/bin/bash
PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./cmodules/bin/3_smc_incorrect_handling
SRC=./cmodules/3_smc_incorrect_handling.c

gcc -z execstack -no-pie -o $BIN $SRC -O0

echo "[TEST 1] Running natively..."
$BIN

echo "------------------------------------------"

echo "[TEST 2] Running under PIN (SMC support disabled)..."
$PIN -smc_strict 0 -t $TOOL -- $BIN