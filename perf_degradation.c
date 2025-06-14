#include <time.h>

void detect_perf_degradation() {
    printf("[9/9] Performance Degradation ... ");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    for (volatile int i = 0; i < 10000000; i++);

    clock_gettime(CLOCK_MONOTONIC, &end);

    double elapsed = (end.tv_sec - start.tv_sec) + 
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    if (elapsed > 0.1) // Adjust threshold as needed
        printf("[DBI Detected: Slow execution]\n");
    else
        printf("[OK]\n");
}
