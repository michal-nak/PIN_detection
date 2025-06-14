#include <unistd.h>

void detect_bad_syscall_emulation() {
    printf("[6/9] Incorrect Emulation of Syscall ... ");

    long rcx_before, rcx_after;
    asm volatile("mov %%rcx, %0" : "=r" (rcx_before));

    syscall(SYS_getpid);

    asm volatile("mov %%rcx, %0" : "=r" (rcx_after));

    if (rcx_before != rcx_after)
        printf("[OK]\n");
    else
        printf("[DBI Detected: RCX unchanged after syscall]\n");
}
