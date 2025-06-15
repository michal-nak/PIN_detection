#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

int is_running_under_pin() {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;
    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "/pin-")) { found = 1; break; }
    }
    fclose(maps);
    return found;
}

void print_code_bytes(const unsigned char *code, size_t len, const char *label) {
    printf("[3/9] [DEBUG] %s: ", label);
    for (size_t i = 0; i < len; ++i) printf("%02x ", code[i]);
    printf("\n");
}

int main() {
    printf("[3/9] Self-Modifying Code Incorrect Handling ... \n");
    unsigned char *code = mmap(NULL, 4096,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("[3/9] mmap");
        exit(1);
    }

    // original: mov $1, %eax; inc %eax; ret
    code[0] = 0xB8; code[1] = 0x01; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00;
    code[5] = 0xFF; code[6] = 0xC0; // inc eax
    code[7] = 0xC3;

    print_code_bytes(code, 8, "Initial code bytes");

    int (*func)() = (int (*)())code;
    printf("[3/9] Calling original code...\n");
    int val1 = func();
    printf("[3/9] val1 = %d\n", val1);

    // modify: mov $5, %eax; nop; ret
    code[0] = 0xB8; // mov imm32, %eax
    code[1] = 0x05; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; // imm32 = 5
    code[5] = 0x90; code[6] = 0x90; // nops
    code[7] = 0xC3; // ret
    __builtin___clear_cache((char *)code, (char *)code + 8);

    print_code_bytes(code, 8, "Modified code bytes");

    printf("[3/9] Calling modified code...\n");
    int val2 = func();
    printf("[3/9] val2 = %d\n", val2);

    int under_pin = is_running_under_pin();
    if (val1 == 2 && val2 == 5) {
        printf("[3/9] [OK] SMC handled correctly\n");
        if (under_pin) {
            printf("[3/9] [WARNING] SMC handled correctly under PIN (unexpected, check if SMC support is enabled)\n");
        }
    } else {
        printf("[3/9] [DBI DETECTED] SMC not handled properly (got %d, %d)\n", val1, val2);
    }

    munmap(code, 4096);
    printf("[3/9] Test completed\n");
    return 0;
}
