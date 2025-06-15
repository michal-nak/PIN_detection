#!/bin/bash
set -e
cd "$(dirname "$0")"

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
