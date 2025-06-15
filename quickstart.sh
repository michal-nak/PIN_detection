#!/bin/bash
#
# quickstart.sh - Interactive setup and run for the PIN Detection Suite
#
# Usage:
#   ./quickstart.sh
#
# This script will:
#   1. Check and help configure the Intel PIN path
#   2. Build all techniques
#   3. Run all checks natively and under PIN
#   4. Show summary results

set -e
cd "$(dirname "$0")"

# 1. Check PIN path
if [ -f ./pin.conf ]; then
    source ./pin.conf
fi
PIN=${PIN:-~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin}

if [[ ! -x "$PIN" ]]; then
    echo "[ERROR] Intel PIN not found or not executable at: $PIN"
    echo "Edit pin.conf or set the PIN environment variable."
    read -p "Would you like to edit pin.conf now? [Y/n] " yn
    yn=${yn:-Y}
    if [[ "$yn" =~ ^[Yy]$ ]]; then
        ${EDITOR:-nano} pin.conf
        source ./pin.conf
        PIN=${PIN:-~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin}
        if [[ ! -x "$PIN" ]]; then
            echo "[ERROR] Still cannot find PIN. Exiting."
            exit 1
        fi
    else
        echo "Please configure PIN and re-run this script."
        exit 1
    fi
fi

# 2. Build all
./compile_all.sh

# 3. Run all checks
./run_all_evasions_from_build.sh

# 4. Done
exit 0
