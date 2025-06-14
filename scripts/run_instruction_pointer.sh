#!/bin/bash

PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./2_ip_unexpected_regions

pwd

echo "Compiling..."
gcc -o $BIN ./2_ip_unexpected_regions.c

echo "Running natively..."
$BIN

echo "Running under PIN..."
$PIN -t $TOOL -- $BIN
