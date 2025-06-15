#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

void detect_mem_perm_mismatch() {
    printf("[4/9] Memory Region Permission Mismatches ... \n");

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("[!] Failed to open /proc/self/maps");
        exit(1);
    }
    char line[256];
    int suspicious = 0;
    int region_count = 0;

    while (fgets(line, sizeof(line), maps)) {
        VPRINT("[VERBOSE] Region %d: %s", region_count, line);
        region_count++;
        if (strstr(line, "rwxp")) {
            VPRINT("[VERBOSE] Suspicious RWX region found: %s", line);
            suspicious = 1;
            break;
        }
    }
    fclose(maps);

    if (suspicious)
        printf("[4/9] [DBI Detected: RWX page found]\n");
    else
        printf("[4/9] [OK]\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    detect_mem_perm_mismatch();
    printf("[4/9] Test completed\n");
    return 0;
}
