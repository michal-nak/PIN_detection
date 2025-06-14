#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <execinfo.h>  // Added for backtrace functions

typedef struct {
    uintptr_t start;
    uintptr_t end;
    bool is_anon;
    bool is_exec;
    char path[256];
} MemoryRegion;

#define MAX_REGIONS 256
MemoryRegion regions[MAX_REGIONS];
int region_count = 0;

void load_memory_regions() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("Failed to open /proc/self/maps");
        return;
    }

    char line[512];
    region_count = 0;

    while (fgets(line, sizeof(line), maps) && region_count < MAX_REGIONS) {
        char perms[5] = {0};
        regions[region_count].path[0] = '\0';

        int res = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", 
                        &regions[region_count].start, 
                        &regions[region_count].end,
                        perms,
                        regions[region_count].path);
        
        if (res < 3) continue;

        regions[region_count].is_anon = (regions[region_count].path[0] == '\0');
        regions[region_count].is_exec = (strchr(perms, 'x') != NULL);
        region_count++;
    }

    fclose(maps);
}

bool is_in_main_executable(uintptr_t addr) {
    static bool main_exe_checked = false;
    static uintptr_t main_exe_start = 0, main_exe_end = 0;
    
    if (!main_exe_checked) {
        // Get our own executable path
        char exe_path[1024];
        ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
        if (len != -1) {
            exe_path[len] = '\0';
            for (int i = 0; i < region_count; i++) {
                if (regions[i].is_exec && strstr(regions[i].path, exe_path)) {
                    main_exe_start = regions[i].start;
                    main_exe_end = regions[i].end;
                    break;
                }
            }
        }
        main_exe_checked = true;
    }
    
    return (addr >= main_exe_start && addr < main_exe_end);
}

bool is_in_known_library(uintptr_t addr) {
    const char *known_libs[] = {
        "libc.so", "ld-linux", "libpthread", "libm.so", "libdl.so",
        "libstdc++", "libgcc_s", "[vdso]", "[vsyscall]", NULL
    };

    for (int i = 0; i < region_count; i++) {
        if (regions[i].is_exec) {
            for (const char **lib = known_libs; *lib; lib++) {
                if (strstr(regions[i].path, *lib)) {
                    if (addr >= regions[i].start && addr < regions[i].end) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

bool is_likely_pin_jit(uintptr_t addr) {
    // Check if we're in any anonymous executable region
    for (int i = 0; i < region_count; i++) {
        if (regions[i].is_exec && regions[i].is_anon) {
            if (addr >= regions[i].start && addr < regions[i].end) {
                // Additional checks for PIN characteristics:
                // 1. Large size (> 1MB)
                // 2. High memory address (> 0x700000000000)
                size_t size = regions[i].end - regions[i].start;
                if (size > 0x100000 && regions[i].start > 0x700000000000) {
                    return true;
                }
                
                // Check for adjacent executable regions
                int adjacent_exec = 0;
                for (int j = 0; j < region_count; j++) {
                    if (regions[j].is_exec && regions[j].is_anon) {
                        if ((regions[j].start == regions[i].end) || 
                            (regions[j].end == regions[i].start)) {
                            adjacent_exec++;
                        }
                    }
                }
                if (adjacent_exec > 1) {
                    return true;
                }
            }
        }
    }
    return false;
}

bool check_call_stack() {
    void *buffer[10];
    int frames = backtrace(buffer, 10);
    if (frames <= 0) return false;

    char **symbols = backtrace_symbols(buffer, frames);
    if (!symbols) return false;

    bool pin_detected = false;
    for (int i = 0; i < frames; i++) {
        if (strstr(symbols[i], "pin") || strstr(symbols[i], "PIN_")) {
            pin_detected = true;
            break;
        }
    }
    free(symbols);
    
    return pin_detected;
}

__attribute__((noinline)) 
void check_for_dbi() {
    load_memory_regions();
    void *retaddr = __builtin_return_address(0);
    uintptr_t ip = (uintptr_t)retaddr;

    printf("Checking IP: 0x%lx\n", ip);
    printf("Memory regions scanned: %d\n", region_count);

    // Debug output for anonymous executable regions
    for (int i = 0; i < region_count; i++) {
        if (regions[i].is_exec && regions[i].is_anon) {
            printf("Anonymous executable region: 0x%lx-0x%lx (size: 0x%lx)\n",
                   regions[i].start, regions[i].end,
                   regions[i].end - regions[i].start);
        }
    }

    if (check_call_stack()) {
        printf("[PIN DETECTED] Found PIN in call stack!\n");
        exit(1);
    }
    else if (is_likely_pin_jit(ip)) {
        printf("[PIN DETECTED] IP 0x%lx is in PIN JIT region!\n", ip);
        exit(1);
    }
    else if (is_in_main_executable(ip)) {
        printf("[OK] IP 0x%lx is in main executable\n", ip);
    }
    else if (is_in_known_library(ip)) {
        printf("[OK] IP 0x%lx is in known library\n", ip);
    }
    else {
        printf("[WARNING] IP 0x%lx is in unexpected region\n", ip);
    }
}

void target_function() {
    printf("This is a normal function\n");
    check_for_dbi();
}

int main() {
    printf("Starting DBI detection test...\n");
    target_function();
    printf("Test completed\n");
    return 0;
}