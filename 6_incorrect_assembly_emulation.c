#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

volatile sig_atomic_t got_sigill = 0;
jmp_buf jmpbuf;
void sigill_handler(int sig) {
    got_sigill = 1;
    longjmp(jmpbuf, 1);
}

void detect_bad_syscall_emulation() {
    printf("[6/9] Incorrect Emulation of Syscall ... ");

    long rcx_before, rcx_after;
    asm volatile("mov %%rcx, %0" : "=r" (rcx_before));

    syscall(SYS_getpid);

    asm volatile("mov %%rcx, %0" : "=r" (rcx_after));

    printf("[DEBUG] RCX before syscall: 0x%lx, after syscall: 0x%lx\n", rcx_before, rcx_after);
    if (rcx_before != rcx_after)
        printf("[OK]\n");
    else
        printf("[DBI Detected: RCX unchanged after syscall]\n");
}

void detect_bad_rdfsbase_emulation() {
    printf("[6/9] Incorrect Emulation of rdfsbase ... ");
    unsigned long fsbase_syscall = 0, fsbase_rdfsbase = 0;
    int supported = 1;
    // Try to get FS base via arch_prctl
    if (syscall(SYS_arch_prctl, 0x1003, &fsbase_syscall) != 0) {
        printf("[DEBUG] arch_prctl failed: %s\n", strerror(errno));
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
        printf("[INFO] rdfsbase not supported on this CPU/OS\n");
        rdfsbase_ok = 0;
    }
    // Compare results if both succeeded
    if (supported && rdfsbase_ok) {
        printf("[DEBUG] arch_prctl FS base: 0x%lx, rdfsbase: 0x%lx\n", fsbase_syscall, fsbase_rdfsbase);
        if (fsbase_syscall == fsbase_rdfsbase)
            printf("[OK]\n");
        else
            printf("[DBI Detected: rdfsbase emulation incorrect]\n");
    } else if (!supported) {
        printf("[INFO] arch_prctl not supported, skipping rdfsbase test\n");
    } else if (supported && !rdfsbase_ok) {
        printf("[INFO] rdfsbase not supported, skipping test\n");
    }
}

int main() {
printf("==== Incorrect Syscall Emulation Test ====\n");
    detect_bad_syscall_emulation();
    printf("==== Incorrect rdfsbase Emulation Test ====\n");
    detect_bad_rdfsbase_emulation();
    printf("==== Test completed ====\n");
    return 0;
}
