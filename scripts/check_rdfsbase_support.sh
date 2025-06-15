#!/bin/bash
# Check if rdfsbase is supported by CPU and kernel

if grep -qw rdfsbase /proc/cpuinfo; then
    echo "[INFO] CPU supports rdfsbase."
else
    echo "[INFO] CPU does NOT support rdfsbase."
    exit 1
fi

if [[ -f /proc/cmdline ]] && grep -qw allow_rdfsbase=on /proc/cmdline; then
    echo "[INFO] Kernel booted with allow_rdfsbase=on."
else
    echo "[INFO] Kernel is NOT booted with allow_rdfsbase=on."
    echo "[INFO] To enable user-mode rdfsbase, add allow_rdfsbase=on to your kernel command line and reboot."
    exit 2
fi

# Optionally, check kernel version
KVER=$(uname -r | cut -d. -f1-2)
if [[ $(echo "$KVER >= 4.11" | bc) -eq 1 ]]; then
    echo "[INFO] Kernel version is $KVER (should be >= 4.11 for rdfsbase support)."
else
    echo "[INFO] Kernel version $KVER is too old for rdfsbase user-mode support."
    exit 3
fi

echo "[INFO] System should support rdfsbase in user mode."
exit 0
