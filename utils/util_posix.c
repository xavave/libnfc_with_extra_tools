//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// utilities requiring Posix library functions
//-----------------------------------------------------------------------------

#if !defined(_WIN32)
#define _POSIX_C_SOURCE 199309L   // need nanosleep()
#else
#include <windows.h>
#include <sys/types.h>
#include <sys/timeb.h>
#endif

#include "util_posix.h"
#include <stdint.h>
#include <time.h>


// Timer functions
#if !defined (_WIN32)
#include <errno.h>

static void nsleep(uint64_t n) {
    struct timespec timeout;
    timeout.tv_sec = n / 1000000000;
    timeout.tv_nsec = n % 1000000000;
    while (nanosleep(&timeout, &timeout) && errno == EINTR);
}

void msleep(uint32_t n) {
    nsleep(1000000 * (uint64_t) n);
}
#endif // _WIN32

#ifdef __APPLE__

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC (1)
#endif
#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME (2)
#endif

#include <sys/time.h>
#include <mach/clock.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

/* clock_gettime is not implemented on OSX prior to 10.12 */
int _civet_clock_gettime(int clk_id, struct timespec *t);

int _civet_clock_gettime(int clk_id, struct timespec *t) {
    memset(t, 0, sizeof (*t));
    if (clk_id == CLOCK_REALTIME) {
        struct timeval now;
        int rv = gettimeofday(&now, NULL);
        if (rv) {
            return rv;
        }
        t->tv_sec = now.tv_sec;
        t->tv_nsec = now.tv_usec * 1000;
        return 0;

    } else if (clk_id == CLOCK_MONOTONIC) {
        static uint64_t clock_start_time = 0;
        static mach_timebase_info_data_t timebase_info = {0, 0};

        uint64_t now = mach_absolute_time();

        if (clock_start_time == 0) {
            mach_timebase_info(&timebase_info);
            clock_start_time = now;
        }

        now = (uint64_t) ((double) (now - clock_start_time)
                * (double) timebase_info.numer
                / (double) timebase_info.denom);

        t->tv_sec = now / 1000000000;
        t->tv_nsec = now % 1000000000;
        return 0;
    }
    return -1; // EINVAL - Clock ID is unknown
}

/* if clock_gettime is declared, then __CLOCK_AVAILABILITY will be defined */
#ifdef __CLOCK_AVAILABILITY
/* If we compiled with Mac OSX 10.12 or later, then clock_gettime will be declared
 * but it may be NULL at runtime. So we need to check before using it. */
int _civet_safe_clock_gettime(int clk_id, struct timespec *t);

int _civet_safe_clock_gettime(int clk_id, struct timespec *t) {
    if (clock_gettime) {
        return clock_gettime(clk_id, t);
    }
    return _civet_clock_gettime(clk_id, t);
}
#define clock_gettime _civet_safe_clock_gettime
#else
#define clock_gettime _civet_clock_gettime
#endif

#endif


// a milliseconds timer for performance measurement
uint64_t msclock() {
#if defined(_WIN32)
    struct _timeb t;
    _ftime(&t);
    return 1000 * (uint64_t) t.time + t.millitm;

#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec * 1000 + t.tv_nsec / 1000000);
#endif
}

