void detect_ip_unexpected_region() {
    printf("[2/9] IP in Unexpected Memory Regions ... ");

    void *ip = __builtin_return_address(0);

    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        printf("[!] Failed to open maps\n");
        return;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (strchr(perms, 'x') && (unsigned long)ip >= start && (unsigned long)ip <= end) {
                found = 1;
                break;
            }
        }
    }
    fclose(maps);

    if (found)
        printf("[OK]\n");
    else
        printf("[DBI Detected: IP outside code region]\n");
}
