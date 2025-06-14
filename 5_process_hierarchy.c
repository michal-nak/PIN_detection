#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

void detect_process_hierarchy() {
    printf("[5/9] Process Hierarchy ... ");

    pid_t ppid = getppid();
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", ppid);

    FILE *f = fopen(path, "r");
    if (!f) {
        printf("[!] Could not check parent process\n");
        return;
    }

    char cmdline[256];
    fread(cmdline, 1, sizeof(cmdline), f);
    fclose(f);

    if (strstr(cmdline, "pin")) {
        printf("[DBI Detected: Parent is PIN]\n");
    } else {
        printf("[OK]\n");
    }
}
