#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>

// Detect if IP (return address) lies in an unexpected executable memory region
void detect_ip_unexpected_region(void *retaddr) {
    printf("[2/9] IP in Unexpected Memory Regions ... ");

    unsigned long ip = (unsigned long)retaddr;
    printf("[DEBUG] IP (caller address): 0x%lx\n", ip);

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("[!] Failed to open /proc/self/maps");
        return;
    }

    char line[512];
    int found = 0;
    int anon_exec = 0;

    while (fgets(line, sizeof(line), maps)) {
        printf("Parsing line: %s", line);

        if (strchr(line, '-') == NULL) continue;

        unsigned long start = 0, end = 0;
        char perms[5] = {0};

        int res = sscanf(line, "%lx-%lx %4c", &start, &end, perms);
        if (res != 3) {
            printf("sscanf failed\n");
            continue;
        }
        perms[4] = '\0';  // ensure null termination

        if (strchr(perms, 'x')) {
            if (ip >= start && ip < end) {
                found = 1;
                if (!strchr(line, '/')) {
                    anon_exec = 1;
                }
                break;
            }
        }
    }

    fclose(maps);

    if (found) {
        if (anon_exec) {
            printf("[DBI Detected: IP 0x%lx in anonymous executable region]\n", ip);
        } else {
            printf("[OK] IP 0x%lx in expected code region\n", ip);
        }
    } else {
        printf("[DBI Detected: IP 0x%lx outside any mapped executable region]\n", ip);
    }
}

__attribute__((noinline)) 
__attribute__((noreturn))
__attribute__((force_align_arg_pointer))
void trampoline(void *retaddr) {
    // Check stack alignment:
    uintptr_t sp = (uintptr_t)__builtin_frame_address(0);
    printf("[trampoline] stack pointer mod 16 = %lu\n", sp % 16);

    detect_ip_unexpected_region(retaddr);
    printf("Exiting trampoline\n");
    exit(0);
}

__attribute__((force_align_arg_pointer))
void call_generated_code(void (*fn)()) {
    fn();
}

void simulate_code_cache() {
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return;
    }

    unsigned char *p = (unsigned char *)mem;

    // movabs rdi, <ret_addr>
    p[0] = 0x48; p[1] = 0xBF;
    unsigned long ret_addr = (unsigned long)(p + 13); // address after ret
    memcpy(p + 2, &ret_addr, sizeof(ret_addr)); // 8 bytes

    // movabs rax, <trampoline>
    p[10] = 0x48; p[11] = 0xB8;
    unsigned long tramp_addr = (unsigned long)trampoline;
    memcpy(p + 12, &tramp_addr, sizeof(tramp_addr)); // 8 bytes

    // call rax
    p[20] = 0xFF; p[21] = 0xD0;

    // ret (for completeness)
    p[22] = 0xC3;

    printf("Calling trampoline via generated code at %p\n", mem);

    void (*func)() = (void (*)())mem;
    call_generated_code(func);

    munmap(mem, 4096);
}

int main() {
    simulate_code_cache();
    return 0;
}