#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h> // Ensure sigaction is defined

volatile sig_atomic_t got_sigill = 0;
jmp_buf jmpbuf;
int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, fmt, ##__VA_ARGS__); } while (0)
void sigill_handler(int sig) {
    got_sigill = 1;
    longjmp(jmpbuf, 1);
}

void detect_bad_syscall_emulation() {
    printf("[6/9] Incorrect Emulation of Syscall ... \n");

    long rcx_before, rcx_after;
    asm volatile("mov %%rcx, %0" : "=r" (rcx_before));

    syscall(SYS_getpid);

    asm volatile("mov %%rcx, %0" : "=r" (rcx_after));

    if (verbose)
        printf("[6/9] [DEBUG] RCX before syscall: 0x%lx, after syscall: 0x%lx\n", rcx_before, rcx_after);
    if (rcx_before != rcx_after)
        printf("[6/9] [UNSUPPORTED]\n");
    else
        printf("[6/9] [DBI Detected: RCX unchanged after syscall]\n");
}

void detect_bad_rdfsbase_emulation() {
    printf("[6/9] Incorrect Emulation of rdfsbase ... \n");
    unsigned long fsbase_syscall = 0, fsbase_rdfsbase = 0;
    int supported = 1;
    // Try to get FS base via arch_prctl
    if (syscall(SYS_arch_prctl, 0x1003, &fsbase_syscall) != 0) {
        if (verbose)
            printf("[6/9] [DEBUG] arch_prctl failed: %s\n", strerror(errno));
        supported = 0;
    }
    // Try to get FS base via rdfsbase (may fail if not supported)
    int rdfsbase_ok = 1;
    got_sigill = 0;
    struct sigaction sa, oldsa;
    sa.sa_handler = sigill_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGILL, &sa, &oldsa);
    if (setjmp(jmpbuf) == 0) {
        asm volatile(
            ".byte 0x0f, 0xae, 0xc0" // rdfsbase rax
            : "=a" (fsbase_rdfsbase)
            :
            :
        );
    } else {
        rdfsbase_ok = 0;
    }
    sigaction(SIGILL, &oldsa, NULL);
    if (got_sigill) {
        printf("[6/9] [INFO] rdfsbase not supported on this CPU/OS\n");
        rdfsbase_ok = 0;
    }
    // Compare results if both succeeded
    if (supported && rdfsbase_ok) {
        if (verbose)
            printf("[6/9] [DEBUG] arch_prctl FS base: 0x%lx, rdfsbase: 0x%lx\n", fsbase_syscall, fsbase_rdfsbase);
        if (fsbase_syscall == fsbase_rdfsbase)
            printf("[6/9] [OK]\n");
        else
            printf("[6/9] [DBI Detected: rdfsbase emulation incorrect]\n");
    } else if (!supported) {
        printf("[6/9] [INFO] arch_prctl not supported, skipping rdfsbase test\n");
    } else if (supported && !rdfsbase_ok) {
        printf("[6/9] [INFO] rdfsbase not supported, skipping test\n");
    }
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    detect_bad_syscall_emulation();
    printf("[6/9] ==== Incorrect rdfsbase Emulation Test ====\n");
    detect_bad_rdfsbase_emulation();
    printf("[6/9] Test completed\n");
    return 0;
}
