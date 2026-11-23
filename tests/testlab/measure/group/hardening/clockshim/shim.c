/* TEST ONLY. Gives one process another wall clock, without root: loaded with DYLD_INSERT_LIBRARIES (macOS, see
 * dyld(1)), it adds SG27H_CLOCK_OFFSET_MS milliseconds to CLOCK_REALTIME and gettimeofday. The monotonic clock is
 * untouched. Used by the MVP-27 hardening measurement (scenario 6) and nothing else. */
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

#define DYLD_INTERPOSE(_replacement, _replacee)                                               \
    __attribute__((used)) static struct { const void *replacement; const void *replacee; }    \
        _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {             \
            (const void *)(unsigned long)&_replacement, (const void *)(unsigned long)&_replacee};

static long long offset_ms(void) {
    static int read = 0;
    static long long off = 0;
    if (!read) {
        const char *s = getenv("SG27H_CLOCK_OFFSET_MS");
        off = s ? atoll(s) : 0;
        read = 1;
    }
    return off;
}

static int shim_clock_gettime(clockid_t id, struct timespec *ts) {
    int rc = clock_gettime(id, ts);
    if (rc == 0 && id == CLOCK_REALTIME) {
        long long ns = (long long)ts->tv_sec * 1000000000LL + ts->tv_nsec + offset_ms() * 1000000LL;
        ts->tv_sec = ns / 1000000000LL;
        ts->tv_nsec = ns % 1000000000LL;
    }
    return rc;
}

static int shim_gettimeofday(struct timeval *tv, void *tz) {
    int rc = gettimeofday(tv, tz);
    if (rc == 0 && tv) {
        long long us = (long long)tv->tv_sec * 1000000LL + tv->tv_usec + offset_ms() * 1000LL;
        tv->tv_sec = us / 1000000LL;
        tv->tv_usec = us % 1000000LL;
    }
    return rc;
}

DYLD_INTERPOSE(shim_clock_gettime, clock_gettime)
DYLD_INTERPOSE(shim_gettimeofday, gettimeofday)
