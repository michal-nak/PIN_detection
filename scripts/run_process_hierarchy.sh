#!/bin/bash

PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./cmodules/bin/5_process_hierarchy
SRC=./cmodules/5_process_hierarchy.c

set -e

VERBOSE=""
if [[ "$1" == "-v" ]]; then
    VERBOSE="-v"
elif [[ "$1" == "-vv" ]]; then
    VERBOSE="-vv"
fi

echo "Compiling..."
gcc -o $BIN $SRC -O0

echo "[TEST 1] Running natively..."
$BIN $VERBOSE

echo "------------------------------------------"

echo "[TEST 2] Running under PIN..."
$PIN -t $TOOL -- $BIN $VERBOSE
