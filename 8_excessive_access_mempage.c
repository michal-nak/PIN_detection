void detect_excessive_full_access_pages() {
    printf("[8/9] Excessive RWX Pages ... ");

    FILE *maps = fopen("/proc/self/maps", "r");
    char line[256];
    int rwx_count = 0;

    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, "rwxp")) {
            rwx_count++;
        }
    }
    fclose(maps);

    if (rwx_count > 1) // Adjust threshold as needed
        printf("[DBI Detected: Excessive RWX pages]\n");
    else
        printf("[OK]\n");
}
