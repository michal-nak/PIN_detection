int main() {
    detect_code_cache_fingerprint();
    detect_ip_unexpected_region();
    detect_smc();
    detect_mem_perm_mismatch();
    detect_process_hierarchy();
    detect_bad_syscall_emulation();
    detect_system_hooks();
    detect_excessive_full_access_pages();
    detect_perf_degradation();
    return 0;
}
