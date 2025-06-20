#!/bin/bash
#
# run_all_evasions.sh - Compile and run all DBI evasion techniques natively and under Intel PIN.
#
# Usage:
#   ./run_all_evasions.sh [-v] [-h|--help]
#
# Options:
#   -v         Enable verbose/debug output for all techniques
#   -h, --help Show this help message and exit
#
# PIN path is read from pin.conf or the PIN environment variable. See README.md for details.
#
# Example:
#   ./run_all_evasions.sh -v

set -e
cd "$(dirname "$0")/"

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
TOOL=${TOOL:-$PIN/../source/tools/SimpleExamples/obj-intel64/opcodemix.so}

if [[ ! -x "$PIN" ]]; then
    echo "[ERROR] Intel PIN not found or not executable at: $PIN"
    echo "Edit pin.conf or set the PIN environment variable. See README.md."
    exit 1
fi

if [[ ! -f "$TOOL" ]]; then
    echo "[run_all_evasions_from_build.sh][ERROR] PIN tool not found at: $TOOL"
    echo "[run_all_evasions_from_build.sh] Please build the required PIN tool (e.g., opcodemix.so) or update the TOOL path in this script."
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

# Parse -v option
VERBOSE=""
if [[ "$1" == "-v" ]]; then
    VERBOSE="-v"
fi

# Compile all
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
    if [[ $? -ne 0 ]]; then
        echo "[ERROR] Failed to compile $BIN"
    fi
    chmod +x "$OUT"
done

echo "==============================="
echo "[ALL EVASIONS: Native Execution]"
echo "==============================="

NATIVE_RESULTS=()
PIN_RESULTS=()
PIN_DETECTED_NATIVE=0
PIN_DETECTED_PIN=0

for i in "${!BINS[@]}"; do
    BIN="${BINS[$i]}"
    echo ""
    OUTPUT=$(./cmodules/bin/$BIN $VERBOSE 2>&1)
    echo "$OUTPUT"
    echo "------------------------------------------"
    # Parse for standardized summary marker
    if echo "$OUTPUT" | grep -E "\[$((i+1))/9\] \[DBI Detected\]" > /dev/null; then
        NATIVE_RESULTS+=("DETECTED")
        PIN_DETECTED_NATIVE=$((PIN_DETECTED_NATIVE+1))
    elif echo "$OUTPUT" | grep -E "\[$((i+1))/9\] \[OK\]" > /dev/null; then
        NATIVE_RESULTS+=("OK")
    else
        NATIVE_RESULTS+=("UNKNOWN")
    fi
    sleep 0.1
done

echo "==============================="
echo "[ALL EVASIONS: Under PIN]"
echo "==============================="

for i in "${!BINS[@]}"; do
    BIN="${BINS[$i]}"
    OUTPUT=$($PIN -t $TOOL -- ./cmodules/bin/$BIN $VERBOSE 2>&1)
    EXIT_CODE=$?
    echo "$OUTPUT"
    echo "------------------------------------------"
    if echo "$OUTPUT" | grep -E "\[$((i+1))/9\] \[DBI Detected" > /dev/null; then
        PIN_RESULTS+=("DETECTED")
        PIN_DETECTED_PIN=$((PIN_DETECTED_PIN+1))
    elif echo "$OUTPUT" | grep -E "\[$((i+1))/9\] \[OK\]" > /dev/null; then
        PIN_RESULTS+=("OK")
    else
        PIN_RESULTS+=("UNKNOWN")
    fi
    sleep 0.1
done

echo "==============================="
echo "[SUMMARY TABLE]"
echo "==============================="
printf "%-35s | %-10s | %-10s\n" "Technique" "Native" "PIN"
echo "---------------------------------------------"
for i in "${!BINS[@]}"; do
    printf "%-35s | %-10s | %-10s\n" "${BINS[$i]}" "${NATIVE_RESULTS[$i]}" "${PIN_RESULTS[$i]}"
done
echo "---------------------------------------------"
echo "Total detected natively: $PIN_DETECTED_NATIVE/${#BINS[@]}"
echo "Total detected under PIN: $PIN_DETECTED_PIN/${#BINS[@]}"
echo "---------------------------------------------"
if [[ $PIN_DETECTED_NATIVE -gt 0 ]]; then
    echo "[!] DBI Detected natively in at least one technique."
else
    echo "[OK] No DBI detected natively."
fi
if [[ $PIN_DETECTED_PIN -gt 0 ]]; then
    echo "[!] DBI Detected under PIN in at least one technique."
else
    echo "[OK] No DBI detected under PIN."
fi
