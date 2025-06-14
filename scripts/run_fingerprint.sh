#!/bin/bash
PIN=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin
TOOL=~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/source/tools/SimpleExamples/obj-intel64/opcodemix.so
BIN=./code_cache_fingerprint

echo "Running natively..."
$BIN
echo "Running under PIN..."
$PIN -t $TOOL -- $BIN

