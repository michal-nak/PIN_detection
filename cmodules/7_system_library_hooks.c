#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <elf.h>
#include <sys/mman.h>

int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define SCAN_BYTE_COUNT 256

void print_bytes(const unsigned char *ptr, size_t n, const char *label) {
    if (!verbose) return;
    VPRINT("[7/9] [DEBUG] %s: ", label);
    for (size_t i = 0; i < n; ++i) VPRINT("%02x ", ptr[i]);
    VPRINT("\n");
}

// Read N bytes from a symbol in the on-disk libc
int read_libc_symbol_bytes(const char *symbol, unsigned char *out, size_t n) {
    char libc_path[512] = {0};
    ssize_t len = readlink("/lib/x86_64-linux-gnu/libc.so.6", libc_path, sizeof(libc_path)-1);
    if (len <= 0) {
        len = readlink("/usr/lib/x86_64-linux-gnu/libc.so.6", libc_path, sizeof(libc_path)-1);
    }
    if (len <= 0) {
        strcpy(libc_path, "/lib/x86_64-linux-gnu/libc.so.6");
    } else {
        libc_path[len] = '\0';
    }
    VPRINT("[7/9] [DEBUG] Using libc path: %s\n", libc_path);
    FILE *f = fopen(libc_path, "rb");
    if (!f) return -1;
    Elf64_Ehdr eh;
    fread(&eh, 1, sizeof(eh), f);
    fseek(f, eh.e_shoff, SEEK_SET);
    Elf64_Shdr shdrs[eh.e_shnum];
    fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f);
    char *shstrtab = malloc(shdrs[eh.e_shstrndx].sh_size);
    fseek(f, shdrs[eh.e_shstrndx].sh_offset, SEEK_SET);
    fread(shstrtab, 1, shdrs[eh.e_shstrndx].sh_size, f);
    Elf64_Shdr *dynsym = NULL, *dynstr = NULL;
    for (int i = 0; i < eh.e_shnum; ++i) {
        if (strcmp(&shstrtab[shdrs[i].sh_name], ".dynsym") == 0) dynsym = &shdrs[i];
        if (strcmp(&shstrtab[shdrs[i].sh_name], ".dynstr") == 0) dynstr = &shdrs[i];
    }
    if (!dynsym || !dynstr) { free(shstrtab); fclose(f); return -1; }
    Elf64_Sym *syms = malloc(dynsym->sh_size);
    fseek(f, dynsym->sh_offset, SEEK_SET);
    fread(syms, 1, dynsym->sh_size, f);
    char *strtab = malloc(dynstr->sh_size);
    fseek(f, dynstr->sh_offset, SEEK_SET);
    fread(strtab, 1, dynstr->sh_size, f);
    int found = 0;
    for (size_t i = 0; i < dynsym->sh_size / sizeof(Elf64_Sym); ++i) {
        if (strcmp(&strtab[syms[i].st_name], symbol) == 0) {
            fseek(f, syms[i].st_value, SEEK_SET);
            fread(out, 1, n, f);
            found = 1;
            break;
        }
    }
    free(shstrtab); free(syms); free(strtab); fclose(f);
    return found ? 0 : -1;
}

void check_mem_protection(void *addr, const char *funcname) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return;
    char line[512];
    uintptr_t ip = (uintptr_t)addr;
    while (fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (ip >= start && ip < end) {
                if (verbose) VPRINT("[7/9] [DEBUG] %s memory region: %lx-%lx perms=%s\n", funcname, start, end, perms);
                if (strstr(perms, "w")) {
                    printf("[7/9] [DBI Detected: %s code region is writable]\n", funcname);
                }
                break;
            }
        }
    }
    fclose(maps);
}

void detect_system_hooks() {
    printf("[7/9] System Library Hooks ... \n");
    int any_detected = 0;
    const char *funcs[] = {"mmap", "mprotect", "__libc_start_main", "dlopen", NULL};
    for (int i = 0; funcs[i]; ++i) {
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if (!handle) { printf("[7/9] [ERROR] Could not open libc.so.6\n"); continue; }
        void *addr = dlsym(handle, funcs[i]);
        dlclose(handle);
        if (!addr) { printf("[7/9] [ERROR] Could not resolve %s\n", funcs[i]); continue; }
        unsigned char *mem_bytes = (unsigned char *)addr;
        print_bytes(mem_bytes, SCAN_BYTE_COUNT, funcs[i]);
        unsigned char disk_bytes[SCAN_BYTE_COUNT];
        int disk_ok = read_libc_symbol_bytes(funcs[i], disk_bytes, SCAN_BYTE_COUNT);
        if (disk_ok == 0) print_bytes(disk_bytes, SCAN_BYTE_COUNT, "on-disk");
        if (disk_ok == 0 && memcmp(mem_bytes, disk_bytes, SCAN_BYTE_COUNT) != 0) {
            printf("[7/9] [DBI Detected: %s in-memory differs from on-disk]\n", funcs[i]);
            any_detected = 1;
        } else if (disk_ok == 0) {
            if (verbose) printf("[7/9] [%s OK]\n", funcs[i]);
        }
        // Check memory protection
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            char line[512];
            uintptr_t ip = (uintptr_t)addr;
            while (fgets(line, sizeof(line), maps)) {
                uintptr_t start, end;
                char perms[5];
                if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                    if (ip >= start && ip < end) {
                        if (verbose) VPRINT("[7/9] [DEBUG] %s memory region: %lx-%lx perms=%s\n", funcs[i], start, end, perms);
                        if (strstr(perms, "w")) {
                            printf("[7/9] [DBI Detected: %s code region is writable]\n", funcs[i]);
                            any_detected = 1;
                        }
                        break;
                    }
                }
            }
            fclose(maps);
        }
    }
    // Shadow libraries
    FILE *maps = fopen("/proc/self/maps", "r");
    int found = 0, suspicious_count = 0;
    if (maps) {
        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            if (strstr(line, "shadow") || strstr(line, "shadowlib") || strstr(line, "pin") || strstr(line, "jit")) {
                suspicious_count++;
                if (verbose) printf("[7/9] [DBI Detected: Suspicious mapping: %s", line);
                found = 1;
            }
        }
        fclose(maps);
    }
    if (suspicious_count > 0) {
        if (!verbose) printf("[7/9] [DBI Detected: %d suspicious mappings found in /proc/self/maps]\n", suspicious_count);
        any_detected = 1;
    }
    // Always print [7/9] [OK] if nothing detected
    if (!any_detected) {
        printf("[7/9] [OK]\n");
    }
    printf("[7/9] Test completed\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    detect_system_hooks();
    return 0;
}
