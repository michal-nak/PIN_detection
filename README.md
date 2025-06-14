# PIN_detection

## Subject
*PIN Detection. (several groups, 1-3 students each).*

The recent paper "Evasion and Countermeasures Techniques to Detect Dynamic Binary Instrumentation Frameworks" discusses 26 classes of evasion techniques to detect the presence of a dynamic instrumentation framework. Sadly, the authors also notice that PoC are only available for nine of them.The goal of this project is to make a linux binary that test sequentially different techniques to detect the presence of Intel PIN. Start by aggregating the nine existing PoC and then try to implement some of the other techniques described in the paper.

The diffent techniques are as follows:

1. Detect_code_cache_fingerprint
2. detect_ip_unexpected_region();
3. detect_smc();
4. detect_mem_perm_mismatch();
5. detect_process_hierarchy();
6. detect_bad_syscall_emulation();
7. detect_system_hooks();
8. detect_excessive_full_access_pages();
9. detect_perf_degradation()
