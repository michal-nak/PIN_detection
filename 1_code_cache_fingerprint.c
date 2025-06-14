#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

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
    int region_count = 0;

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (strchr(perms, 'x')) {
                regions[region_count][0] = start;
                regions[region_count][1] = end;
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

        unsigned char *buffer = malloc(size);
        if (!buffer) {
            printf("Memory allocation failed\n");
            continue;
        }

        if (read_mem_region(mem_fd, start, end, buffer) == 0) {
            for (size_t j = 0; j < size - 4; j++) {
                uint32_t val = *(uint32_t *)(buffer + j);
                if (val == 0xfeedbeaf) {  // 
                    if (strstr(line, "[vdso]")) { // Skip VDSO regions, maybe more  `|| strstr(line, "[vsyscall]") || strstr(line, "[vvar]")`
                            detected_vdso = 1;
                            continue;
                        }
                    printf("Found at 0x%lx in region %s", (start + j), line);
                    detected = 1;
                    break;
                }
            }
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

int main() {
    detect_code_cache_fingerprint();
    return 0;
}
