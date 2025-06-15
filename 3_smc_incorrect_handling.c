#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

int main() {
    unsigned char *code = mmap(NULL, 4096,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        perror("mmap");
        exit(1);
    }

    // original: mov $1, %eax; inc %eax; ret
    code[0] = 0xB8; code[1] = 0x01; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00;
    code[5] = 0xFF; code[6] = 0xC0; // inc eax
    code[7] = 0xC3;

    int (*func)() = (int (*)())code;
    int val1 = func();
    printf("[DEBUG] val1 = %d\n", val1);

    
    // modify: mov $5, %eax; nop; ret
    code[1] = 0x05;
    code[5] = 0x90; code[6] = 0x90;
    __builtin___clear_cache((char *)code, (char *)code + 6);

    int val2 = func();
    printf("[DEBUG] val2 = %d\n", val2);

    if (val1 == 2 && val2 == 5) {
        printf("[OK] SMC handled correctly\n");
    } else {
        printf("[DBI DETECTED] SMC not handled properly (got %d, %d)\n", val1, val2);
    }

    munmap(code, 4096);
    return 0;
}
