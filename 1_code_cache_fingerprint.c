#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

int read_mem_region(int mem_fd, unsigned long start, unsigned long end, unsigned char *buffer) {
    if (lseek(mem_fd, start, SEEK_SET) == -1) {
        perror("lseek");
        return -1;
    }
    ssize_t size = end - start;
    if (read(mem_fd, buffer, size) != size) {
        perror("read");
        return -1;
    }
    return 0;
}

void detect_code_cache_fingerprint() {
    printf("[1/9] Code Cache Fingerprint Detection]\n");

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        perror("fopen maps");
        return;
    }

    int mem_fd = open("/proc/self/mem", O_RDONLY);
    if (mem_fd == -1) {
        perror("open mem");
        fclose(maps);
        return;
    }

    char line[512];
    unsigned long regions[100][2];
    char region_lines[100][512];
    int region_count = 0;

    char exe_path[512] = {0};
    ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (exe_len > 0) exe_path[exe_len] = '\0';

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        char *pathname = NULL;
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            pathname = strchr(line, '/');
            if (strchr(perms, 'x')) {
                // Skip region if it matches our own binary
                if (pathname && exe_len > 0 && strncmp(pathname, exe_path, strlen(exe_path)) == 0) {
                    VPRINT("[VERBOSE] Skipping own binary region: %s", line);
                    continue;
                }
                regions[region_count][0] = start;
                regions[region_count][1] = end;
                strncpy(region_lines[region_count], line, sizeof(region_lines[region_count])-1);
                region_lines[region_count][sizeof(region_lines[region_count])-1] = '\0';
                region_count++;
                if (region_count >= 100) break;
            }
        }
    }

    int detected = 0;
    int detected_vdso = 0;
    for (int i = 0; i < region_count; i++) {
        unsigned long start = regions[i][0];
        unsigned long end = regions[i][1];
        size_t size = end - start;
        VPRINT("[VERBOSE] Region %d: %s", i, region_lines[i]);
        VPRINT("[VERBOSE]   Start: 0x%lx, End: 0x%lx, Size: %zu bytes\n", start, end, size);

        unsigned char *buffer = malloc(size);
        if (!buffer) {
            printf("Memory allocation failed\n");
            continue;
        }

        if (read_mem_region(mem_fd, start, end, buffer) == 0) {
            VPRINT("[VERBOSE]   Searching for marker 0xfeedbeaf in region %d...\n", i);
            int found_marker = 0;
            for (size_t j = 0; j < size - 4; j++) {
                uint32_t val = *(uint32_t *)(buffer + j);
                if (val == 0xfeedbeaf) {  // 
                    found_marker = 1;
                    if (strstr(region_lines[i], "[vdso]")) {
                        detected_vdso = 1;
                        VPRINT("[VERBOSE]   Marker found in VDSO at 0x%lx\n", start + j);
                        continue;
                    }
                    printf("Found at 0x%lx in region %s\n", (start + j), region_lines[i]);
                    detected = 1;
                    break;
                }
            }
            if (!found_marker) {
                VPRINT("[VERBOSE]   No marker found in region %d\n", i);
            }
        } else {
            VPRINT("[VERBOSE]   Failed to read region %d\n", i);
        }

        free(buffer);

        if (detected) break;
    }

    if (!detected) {
        if (detected_vdso) {
            printf("[OK] No DBI code cache marker detected, but was found in VDSO region\n");
        }
        else {
            printf("[OK] No DBI code cache marker detected\n");
        }
    }

    close(mem_fd);
    fclose(maps);
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    detect_code_cache_fingerprint();
    return 0;
}
