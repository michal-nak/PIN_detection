#!/bin/bash

PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./6_incorrect_assembly_emulation

set -e

echo "Compiling..."
gcc -o $BIN ./6_incorrect_assembly_emulation.c -O0

echo "[INFO] Checking rdfsbase support..."
if ./scripts/check_rdfsbase_support.sh; then
    echo "[INFO] rdfsbase should be supported."
else
    echo "[WARNING] rdfsbase is not supported on this system. The rdfsbase test will be skipped or report as not supported."
fi

echo "[TEST 1] Running natively..."
$BIN

echo "------------------------------------------"

echo "[TEST 2] Running under PIN..."
$PIN -t $TOOL -- $BIN
