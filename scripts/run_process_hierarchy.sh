#!/bin/bash

PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./5_process_hierarchy

set -e

VERBOSE=""
if [[ "$1" == "-v" ]]; then
    VERBOSE="-v"
elif [[ "$1" == "-vv" ]]; then
    VERBOSE="-vv"
fi

echo "Compiling..."
gcc -o $BIN ./5_process_hierarchy.c -O0

echo "[TEST 1] Running natively..."
$BIN $VERBOSE

echo "------------------------------------------"

echo "[TEST 2] Running under PIN..."
$PIN -t $TOOL -- $BIN $VERBOSE
