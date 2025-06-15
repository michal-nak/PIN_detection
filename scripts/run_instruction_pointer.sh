#!/bin/bash

PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./cmodules/bin/2_ip_unexpected_regions
SRC=./cmodules/2_ip_unexpected_regions.c

VERBOSE=""
if [[ "$1" == "-v" ]]; then
    VERBOSE="-v"
fi

echo "Compiling..."
gcc -o $BIN $SRC -rdynamic -O0

echo "[TEST 1] Running natively..."
$BIN $VERBOSE

echo "------------------------------------------"

echo "[TEST 2] Running under PIN..."
$PIN -t $TOOL -- $BIN $VERBOSE
