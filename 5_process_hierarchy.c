#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>

int verbose = 0;
int very_verbose = 0;
#define DEBUG_PRINT(fmt, ...) \
    do { if (very_verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
#define REASON_PRINT(fmt, ...) \
    do { if (verbose || very_verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)

// Helper: check if cmdline contains '/pin' or '/pin-' as a path component
int cmdline_has_pin(const char *cmdline, size_t n) {
    for (size_t i = 0; i + 4 < n; ++i) {
        if (cmdline[i] == '/' && cmdline[i+1] == 'p' && cmdline[i+2] == 'i' && cmdline[i+3] == 'n' &&
            (cmdline[i+4] == '\0' || cmdline[i+4] == '-' || cmdline[i+4] == '/')) {
            return 1;
        }
    }
    return 0;
}

void detect_process_hierarchy() {
    printf("[5/9] Process Hierarchy ... \n");
    fflush(stdout);

    extern char **environ;
    int found_pin_env = 0;
    const char *reason = NULL;
    char relevant_cmdline[256] = {0};
    size_t relevant_cmdline_len = 0;
    int relevant_pid = 0;

    for (char **env = environ; *env; ++env) {
        if (strncmp(*env, "PIN_", 4) == 0) {
            if (verbose || very_verbose) fprintf(stderr, "[RELEVANT] Detected PIN_ env: %s\n", *env);
            reason = "PIN_ environment variable detected";
            found_pin_env = 1;
            break;
        }
    }
    FILE *selfcmd = fopen("/proc/self/cmdline", "r");
    char selfcmdline[256] = {0};
    size_t nself = 0;
    if (selfcmd) {
        nself = fread(selfcmdline, 1, sizeof(selfcmdline) - 1, selfcmd);
        fclose(selfcmd);
        if (cmdline_has_pin(selfcmdline, nself)) {
            if (very_verbose) fprintf(stderr, "[RELEVANT] Detected '/pin' in /proc/self/cmdline: ");
            if (very_verbose) {
                for (size_t i = 0; i < nself; ++i) fputc(selfcmdline[i] ? selfcmdline[i] : ' ', stderr);
                fputc('\n', stderr);
            }
            reason = "'/pin' found in /proc/self/cmdline";
            found_pin_env = 1;
            strncpy(relevant_cmdline, selfcmdline, sizeof(relevant_cmdline)-1);
            relevant_cmdline_len = nself;
            relevant_pid = getpid();
        }
    }

    pid_t ppid = getppid();
    int found_pin = 0;
    int max_depth = 10;
    int detected_pid = 0;
    char detected_cmdline[256] = {0};
    size_t detected_cmdline_len = 0;
    while (ppid > 1 && max_depth--) {
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/cmdline", ppid);
        FILE *f = fopen(path, "r");
        if (!f) break;
        char cmdline[256] = {0};
        size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        if (cmdline_has_pin(cmdline, n)) {
            found_pin = 1;
            reason = "'/pin' found in parent process cmdline";
            detected_pid = ppid;
            memcpy(detected_cmdline, cmdline, sizeof(detected_cmdline));
            detected_cmdline_len = n;
            break;
        }
        char statpath[256];
        snprintf(statpath, sizeof(statpath), "/proc/%d/stat", ppid);
        FILE *statf = fopen(statpath, "r");
        if (!statf) break;
        int dummy;
        char comm[256];
        char state;
        pid_t next_ppid = 0;
        fscanf(statf, "%d %s %c %d", &dummy, comm, &state, &next_ppid);
        fclose(statf);
        if (next_ppid == ppid || next_ppid <= 1) break;
        ppid = next_ppid;
    }

    if (found_pin || found_pin_env) {
        REASON_PRINT("[REASON] %s\n", reason ? reason : "PIN detected");
        if (very_verbose || verbose) {
            if (found_pin && detected_pid) {
                fprintf(stderr, "[RELEVANT] Detected in process PID %d: ", detected_pid);
                for (size_t i = 0; i < detected_cmdline_len; ++i) fputc(detected_cmdline[i] ? detected_cmdline[i] : ' ', stderr);
                fputc('\n', stderr);
            } else if (found_pin_env && relevant_pid) {
                fprintf(stderr, "[RELEVANT] Detected in process PID %d: ", relevant_pid);
                for (size_t i = 0; i < relevant_cmdline_len; ++i) fputc(relevant_cmdline[i] ? relevant_cmdline[i] : ' ', stderr);
                fputc('\n', stderr);
            }
        }
        printf("[DBI Detected: PIN found in process hierarchy or environment]\n");
    } else {
        if (very_verbose || verbose) {
            // Show concise ancestry if nothing detected
            pid_t show_pid = getpid();
            int show_depth = 0;
            while (show_pid > 1 && show_depth++ < 10) {
                char path[256];
                snprintf(path, sizeof(path), "/proc/%d/cmdline", show_pid);
                FILE *f = fopen(path, "r");
                if (!f) break;
                char cmdline[256] = {0};
                size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, f);
                fclose(f);
                fprintf(stderr, "[ANCESTRY] PID %d: ", show_pid);
                for (size_t i = 0; i < n; ++i) fputc(cmdline[i] ? cmdline[i] : ' ', stderr);
                fputc('\n', stderr);
                char statpath[256];
                snprintf(statpath, sizeof(statpath), "/proc/%d/stat", show_pid);
                FILE *statf = fopen(statpath, "r");
                if (!statf) break;
                int dummy;
                char comm[256];
                char state;
                pid_t next_ppid = 0;
                fscanf(statf, "%d %s %c %d", &dummy, comm, &state, &next_ppid);
                fclose(statf);
                if (next_ppid == show_pid || next_ppid <= 1) break;
                show_pid = next_ppid;
            }
        }
        printf("[OK]\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    if (argc > 1 && strcmp(argv[1], "-vv") == 0) { verbose = 1; very_verbose = 1; }
    detect_process_hierarchy();
    return 0;
}
