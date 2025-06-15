#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdbool.h>

// Get current IP using reliable method
uintptr_t get_ip() {
    return (uintptr_t)__builtin_return_address(0);
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
                        break;
                    }
                }
            }
            fclose(maps);
        }
        initialized = true;
    }
    
    return (ip >= text_start && ip < text_end);
}

// Check for PIN's code cache regions
bool is_in_pin_cache(uintptr_t ip) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return false;

    char line[256];
    bool has_large_anon_exec = false;
    bool ip_in_anon_exec = false;
    
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        char path[256] = "";
        
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255s", &start, &end, perms, path) < 3)
            continue;
            
        // Check for large anonymous executable regions (PIN characteristic)
        if (strchr(perms, 'x') && path[0] == '\0') {
            if ((end - start) > 0x10000) {
                has_large_anon_exec = true;
                printf("[DEBUG] Found large anonymous executable region: %lx-%lx\n", start, end);
            }
            // if (ip >= start && ip < end) {
            //     printf("[DEBUG] IP 0x%lx in anonymous executable region: %lx-%lx\n", ip, start, end);
            //     ip_in_anon_exec = true;
            // }
        }
    }
    
    fclose(maps);
    
    // PIN detection requires both conditions
    return has_large_anon_exec; //&& ip_in_anon_exec
}

void detect_pin() {
    uintptr_t ip = get_ip();
    printf("Current IP: 0x%lx\n", ip);

    if (!is_in_original_text(ip) || is_in_pin_cache(ip)) {
        printf("[PIN DETECTED] Execution outside original text (IP: 0x%lx)\n", ip);
        exit(1);
    }
    
    printf("[OK] Execution in original text section\n");
}

__attribute__((noinline))
void instrumented_function() {
    printf("Checking if this function can be instrumented\n");
    detect_pin();
}

int main() {
    printf("Starting direct PIN detection test...\n");
    
    // Initial check
    detect_pin();
    
    // Function that might be instrumented
    instrumented_function();
    
    printf("Test completed\n");
    return 0;
}