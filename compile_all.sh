#!/bin/bash
#
# compile_all.sh - Compile all DBI evasion technique C modules.
#
# Usage:
#   ./compile_all.sh [-h|--help]
#
# Options:
#   -h, --help   Show this help message and exit
#
# PIN path is read from pin.conf or the PIN environment variable. See README.md for details.
#
# Example:
#   ./compile_all.sh

set -e
cd "$(dirname "$0")"

# Help/usage
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    grep '^#' "$0" | head -20 | sed 's/^# //;s/^#//'
    exit 0
fi

# Load PIN path from environment or pin.conf if available
if [ -f ./pin.conf ]; then
    source ./pin.conf
fi
PIN=${PIN:-~/forensics/pin-external-3.31-98869-gfa6f126a8-gcc-linux/pin}
TOOL=$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so

if [[ ! -x "$PIN" ]]; then
    echo "[ERROR] Intel PIN not found or not executable at: $PIN"
    echo "Edit pin.conf or set the PIN environment variable. See README.md."
    exit 1
fi

BINS=(
    1_code_cache_fingerprint
    2_ip_unexpected_regions
    3_smc_incorrect_handling
    4_memory_permission_mismatch
    5_process_hierarchy
    6_incorrect_assembly_emulation
    7_system_library_hooks
    8_excessive_access_mempage
    9_perf_degradation
)

for BIN in "${BINS[@]}"; do
    SRC="cmodules/$BIN.c"
    OUT="cmodules/bin/$BIN"
    if [[ "$BIN" == "7_system_library_hooks" ]]; then
        gcc -o "$OUT" "$SRC" -ldl -O0
    elif [[ "$BIN" == "3_smc_incorrect_handling" ]]; then
        gcc -z execstack -no-pie -o "$OUT" "$SRC" -O0
    else
        gcc -o "$OUT" "$SRC" -O0
    fi
    chmod +x "$OUT"
done

echo "All binaries compiled to cmodules/bin/ directory."
