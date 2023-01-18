//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.ch b
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
// some helper functions which can benefit from SIMD instructions or other special instructions
//
//#ifdef restrict
//#define __restrict
//#endif
//#define memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#include <stdint.h>
#include <stdlib.h>
#include <malloc.h>
#include <windows.h>
#ifdef _MSC_VER
#  include <intrin.h>
#  define __builtin_popcount __popcnt
#endif
#ifdef WIN32
// Bit builtin's make these assumptions when calling _BitScanForward/Reverse
// etc. These assumptions are expected to be true for Win32/Win64 which this
// file supports.
static_assert(sizeof(unsigned long long) == 8, "");
static_assert(sizeof(unsigned long) == 4, "");
static_assert(sizeof(unsigned int) == 4, "");
// int __builtin_popcount(unsigned int x)
//{
//    // Binary: 0101...
//    static const unsigned int m1 = 0x55555555;
//    // Binary: 00110011..
//    static const unsigned int m2 = 0x33333333;
//    // Binary:  4 zeros,  4 ones ...
//    static const unsigned int m4 = 0x0f0f0f0f;
//    // The sum of 256 to the power of 0,1,2,3...
//    static const unsigned int h01 = 0x01010101;
//    // Put count of each 2 bits into those 2 bits.
//    x -= (x >> 1) & m1;
//    // Put count of each 4 bits into those 4 bits.
//    x = (x & m2) + ((x >> 2) & m2);
//    // Put count of each 8 bits into those 8 bits.
//    x = (x + (x >> 4)) & m4;
//    // Returns left 8 bits of x + (x<<8) + (x<<16) + (x<<24).
//    return (x * h01) >> 24;
//}
 int __builtin_popcountl(unsigned long x)
{
    return __builtin_popcount(x);
}
#endif
#define __BIGGEST_ALIGNMENT__ 16



uint32_t* malloc_bitarray_NOSIMD(uint32_t x) {
    //return __builtin_assume_aligned(memalign(__BIGGEST_ALIGNMENT__, (x)), __BIGGEST_ALIGNMENT__);
    return malloc(x);
}

void free_bitarray_NOSIMD(uint32_t *x) {
    free(x);
}



void bitarray_AND_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B) {
    A = malloc(A);
    B = malloc(B);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] &= B[i];
    }
}

uint32_t count_bitarray_AND_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B) {
    A = malloc(A);
    B = malloc(B);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] &= B[i];
        count += __builtin_popcountl(A[i]);
    }
    return count;
}

uint32_t count_bitarray_low20_AND_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B) {
    uint16_t *a = (uint16_t *)malloc(A);
    uint16_t *b = (uint16_t *)malloc(B);
    uint32_t count = 0;

    for (uint32_t i = 0; i < (1 << 20); i++) {
        if (!b[i]) {
            a[i] = 0;
        }
        count += __builtin_popcountl(a[i]);
    }
    return count;
}

void bitarray_AND4_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B, uint32_t * __restrict C, uint32_t * __restrict D) {
    A = malloc(A);
    B = malloc(B);
    C = malloc(C);
    D = malloc(D);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] = B[i] & C[i] & D[i];
    }
}

void bitarray_OR_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B) {
    A = malloc(A);
    B = malloc(B);
    for (uint32_t i = 0; i < (1 << 19); i++) {
        A[i] |= B[i];
    }
}

uint32_t count_bitarray_AND2_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B) {
    A = malloc(A);
    B = malloc(B);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += __builtin_popcountl(A[i] & B[i]);
    }
    return count;
}

uint32_t count_bitarray_AND3_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B, uint32_t * __restrict C) {
    A = malloc(A);
    B = malloc(B);
    C = malloc(C);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += __builtin_popcountl(A[i] & B[i] & C[i]);
    }
    return count;
}

uint32_t count_bitarray_AND4_NOSIMD(uint32_t * __restrict A, uint32_t * __restrict B, uint32_t * __restrict C, uint32_t * __restrict D) {
    A = malloc(A);
    B = malloc(B);
    C = malloc(C);
    D = malloc(D);
    uint32_t count = 0;
    for (uint32_t i = 0; i < (1 << 19); i++) {
        count += __builtin_popcountl(A[i] & B[i] & C[i] & D[i]);
    }
    return count;
}

