#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>

// This code detects if the current process is running under Intel PIN by checking the instruction pointer (IP) against known characteristics of PIN's code cache regions.
// It checks if the IP is in the original executable text section or in PIN's code cache regions, which are typically large anonymous executable memory regions.
// I have managed to always catch when the cache is large but it never catches the IP in the cache.


int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

// Get current IP using reliable method
uintptr_t get_ip() {
    uintptr_t ip = (uintptr_t)__builtin_return_address(0);
    VPRINT("[DEBUG] get_ip: return address = 0x%lx\n", ip);
    return ip;
}

// Check if address is in original executable text section
bool is_in_original_text(uintptr_t ip) {
    static uintptr_t text_start = 0, text_end = 0;
    static bool initialized = false;
    
    if (!initialized) {
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[256];
            char exe_path[1024];
            ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
            if (len != -1) {
                exe_path[len] = '\0';
                while (fgets(line, sizeof(line), maps)) {
                    if (strstr(line, exe_path) && strstr(line, "r-xp")) {
                        sscanf(line, "%lx-%lx", &text_start, &text_end);
                        VPRINT("[DEBUG] Found text section: %lx-%lx for %s\n", text_start, text_end, exe_path);
                        break;
                    }
                }
            } else {
                VPRINT("[DEBUG] Could not resolve /proc/self/exe\n");
            }
            fclose(maps);
        } else {
            VPRINT("[DEBUG] Could not open /proc/self/maps\n");
        }
        initialized = true;
    }
    VPRINT("[DEBUG] is_in_original_text: ip=0x%lx, text_start=0x%lx, text_end=0x%lx\n", ip, text_start, text_end);
    return (ip >= text_start && ip < text_end);
}

// Check for PIN's code cache regions
bool is_in_pin_cache(uintptr_t ip) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char line[256];
    bool has_large_anon_exec = false;
    bool ip_in_anon_exec = false;
    int region_idx = 0;
    
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        char path[256] = "";
        int n = sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &start, &end, perms, path);
        if (n < 3) continue;
        VPRINT("[DEBUG] Region %d: %lx-%lx perms=%s path=%s\n", region_idx, start, end, perms, path);
        region_idx++;
        // Check for large anonymous executable regions (PIN characteristic)
        if (strchr(perms, 'x') && path[0] == '\0') {
            if ((end - start) > 0x10000) {
                has_large_anon_exec = true;
                VPRINT("[DEBUG] Found large anonymous executable region: %lx-%lx\n", start, end);
            }
            if (ip >= start && ip < end) {
                VPRINT("[DEBUG] IP 0x%lx in anonymous executable region: %lx-%lx\n", ip, start, end);
                ip_in_anon_exec = true;
            }
        }
    }
    fclose(maps);
    VPRINT("[DEBUG] is_in_pin_cache: has_large_anon_exec=%d, ip_in_anon_exec=%d\n", has_large_anon_exec, ip_in_anon_exec);
    return has_large_anon_exec && ip_in_anon_exec;
}

// Return 1 if PIN detected, 0 otherwise
int detect_pin() {
    uintptr_t ip = get_ip();
    printf("[2/9] Instruction Pointer Unexpected Regions ... \n");
    VPRINT("[DEBUG] Running detect_pin: IP=0x%lx\n", ip);
    bool in_text = is_in_original_text(ip);
    bool in_pin = is_in_pin_cache(ip);
    VPRINT("[DEBUG] detect_pin: in_text=%d, in_pin=%d\n", in_text, in_pin);
    if (!in_text || in_pin) {
        printf("[2/9] [DBI Detected] Execution outside original text (IP: 0x%lx)\n", ip);
        return 1;
    }
    printf("[2/9] [OK] Execution in original text section\n");
    return 0;
}

__attribute__((noinline))
void instrumented_function(int *detected) {
    printf("[2/9] Checking if this function can be instrumented\n");
    int res = detect_pin();
    if (res) *detected = 1;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    printf("[2/9] Starting direct PIN detection test...\n");
    int detected = 0;
    if (detect_pin()) detected = 1;
    instrumented_function(&detected);
    printf("[2/9] Test completed\n");
    return detected;
}