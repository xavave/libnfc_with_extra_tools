//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Parity functions
//-----------------------------------------------------------------------------

// all functions defined in header file by purpose. Allows compiler optimizations. 

#ifndef __PARITY_H
#define __PARITY_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#ifdef _MSC_VER
#  include <intrin.h>
#  define __builtin_popcount __popcnt
#endif
extern const uint8_t OddByteParity[256];

static inline bool oddparity8(const uint8_t x) {
    return OddByteParity[x];
}

static inline bool evenparity8(const uint8_t x) {
    return !OddByteParity[x];
}

static inline bool evenparity32(uint32_t x) {
    x ^= x >> 16;
    x ^= x >> 8;
    x ^= x >> 4;
    x ^= x >> 2;
    x ^= x >> 1;
    return (~x) & 1;
}

#endif /* __PARITY_H */
