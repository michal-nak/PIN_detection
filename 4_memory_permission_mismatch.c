#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void detect_mem_perm_mismatch() {
    printf("[4/9] Memory Region Permission Mismatches ... ");

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("[!] Failed to open /proc/self/maps");
        exit(1);
    }
    char line[256];
    int suspicious = 0;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "rwxp")) {
            suspicious = 1;
            break;
        }
    }
    fclose(maps);

    if (suspicious)
        printf("[DBI Detected: RWX page found]\n");
    else
        printf("[OK]\n");
}

int main() {
    detect_mem_perm_mismatch();
    return 0;
}
