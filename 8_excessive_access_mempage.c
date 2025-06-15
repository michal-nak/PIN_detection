#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

void detect_excessive_full_access_pages() {
    printf("[8/9] Excessive RWX Pages ... ");

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        printf("[ERROR] Could not open /proc/self/maps\n");
        return;
    }
    char line[512];
    int rwx_count = 0;
    int total = 0;
    while (fgets(line, sizeof(line), maps)) {
        total++;
        if (strstr(line, "rwxp")) {
            rwx_count++;
            if (verbose) VPRINT("[DEBUG] RWX mapping: %s", line);
        }
    }
    fclose(maps);

    if (rwx_count > 1) // Adjust threshold as needed
        printf("[DBI Detected: Excessive RWX pages: %d found]\n", rwx_count);
    else
        printf("[OK]\n");
    if (verbose) VPRINT("[DEBUG] Total mappings: %d, RWX: %d\n", total, rwx_count);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    detect_excessive_full_access_pages();
    return 0;
}
