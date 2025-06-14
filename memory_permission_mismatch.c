void detect_smc() {
    printf("[3/9] Incorrect Handling of SMC ... ");

    unsigned char code[] = { 0xc3 }; // ret instruction
    void (*func)() = (void (*)()) code;

    // Mark memory as executable
    mprotect((void *)((uintptr_t)code & ~0xFFF), 4096, PROT_READ|PROT_WRITE|PROT_EXEC);

    code[0] = 0x90; // nop

    func(); // Should nop and return

    printf("[OK]\n");
}
