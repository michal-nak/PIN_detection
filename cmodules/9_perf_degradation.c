#define _POSIX_C_SOURCE 199309L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int verbose = 0;
#define VPRINT(fmt, ...) do { if (verbose) fprintf(stderr, "[9/9] [DEBUG] " fmt, ##__VA_ARGS__); } while (0)

// Estimate baseline time for the loop based on CPU MHz
// Returns seconds, or -1 on failure
double estimate_baseline_from_cpuinfo() {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return -1.0;
    char line[256];
    double mhz = 0.0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "cpu MHz")) {
            char *colon = strchr(line, ':');
            if (colon) mhz = atof(colon + 1);
            break;
        }
    }
    fclose(f);
    if (mhz <= 0.0) return -1.0;
    // 10,000,000 iterations, assume ~1 cycle per iteration (very rough)
    // 1 MHz = 1,000,000 cycles/sec
    double seconds = 10000000.0 / (mhz * 1e6);
    return seconds > 0.0 ? seconds : -1.0;
}

double run_timing_loop() {
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) return -1.0;
    for (volatile int i = 0; i < 10000000; i++);
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) return -1.0;
    return (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
}

void detect_perf_degradation() {
    // 1. Check for PERF_BASELINE env var
    double baseline = -1.0;
    char *env = getenv("PERF_BASELINE");
    if (env) {
        baseline = atof(env);
        if (verbose) VPRINT("Using PERF_BASELINE from environment: %.6f seconds\n", baseline);
    }
    // 2. Otherwise, estimate from /proc/cpuinfo
    if (baseline <= 0.0) {
        baseline = estimate_baseline_from_cpuinfo();
        if (verbose) VPRINT("Estimated baseline from /proc/cpuinfo: %.6f seconds\n", baseline);
    }
    // 3. Fallback to a default
    if (baseline <= 0.0 || baseline > 1.0) {
        if (verbose) VPRINT("Falling back to default baseline: 0.010000 seconds\n");
        baseline = 0.01;
    }

    // Multiplier for detection
    double factor = 2.5;
    char *envf = getenv("PERF_DEGRADATION_FACTOR");
    if (envf) {
        double f = atof(envf);
        if (f > 1.0 && f < 100.0) factor = f;
    }
    double threshold = baseline * factor;
    if (verbose) VPRINT("Final baseline: %.6f seconds, Threshold: %.6f seconds (Multiplier: %.2f)\n", baseline, threshold, factor);

    // Actual test
    double elapsed = run_timing_loop();
    if (verbose) VPRINT("Test run elapsed time: %.6f seconds\n", elapsed);

    if (elapsed > threshold)
        printf("[9/9] [DBI Detected: Slow execution]\n");
    else
        printf("[9/9] [OK]\n");
    printf("[9/9] Test completed\n");
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "-v") == 0) verbose = 1;
    printf("[9/9] Performance Degradation ... \n");
    detect_perf_degradation();
    return 0;
}
