//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
//
// brute forcing is based on @aczids bitsliced brute forcer
// https://github.com/aczid/crypto1_bs with some modifications. Mainly:
// - don't rollback. Start with 2nd byte of nonce instead
// - reuse results of filter subfunctions
// - reuse results of previous nonces if some first bits are identical
// 
//-----------------------------------------------------------------------------
// aczid's Copyright notice:
//
// Bit-sliced Crypto-1 brute-forcing implementation
// Builds on the data structures returned by CraptEV1 craptev1_get_space(nonces, threshold, uid)
/*
Copyright (c) 2015-2016 Aram Verstegen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

#include "hardnested_bruteforce.h"
#include <stdlib.h>
#include <malloc.h>
#include <windows.h> // Inclure windows.h pour les fonctions d'opérations atomiques
#include <intrin.h>  // Inclure intrin.h pour les fonctions d'opérations atomiques
#include "../crapto1.h"
#include "../parity.h"
#include <basetsd.h>
 //#include <hardnested_bf_core_SSE2.c>
 //#include <hardnested_bf_core_AVX512.c>
 //#include <hardnested_bf_core_AVX2.c>
 //#include "./hardnested_bf_core_AVX.c"

#define MAX_BITSLICES 64

#define VECTOR_SIZE (MAX_BITSLICES/8)
//typedef struct __declspec(align(VECTOR_SIZE)) {
//    uint32_t x;
//} bitslice_value_t;

// Chaque bitslice_t représente 64 tranches (bitslices). 
// On utilise un tableau de uint64_t. Ici, MAX_BITSLICES/64 = 1, 
// ce qui donne un tableau de 1 élément si MAX_BITSLICES = 64.
typedef struct {
	uint64_t data[MAX_BITSLICES / 64];
} bitslice_t;


// filter function (f20)
// sourced from ``Wirelessly Pickpocketing a Mifare Classic Card'' by Flavio Garcia, Peter van Rossum, Roel Verdult and Ronny Wichers Schreur
static inline bitslice_t bs_or(const bitslice_t a, const bitslice_t b) {
	bitslice_t r;
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++)
		r.data[i] = a.data[i] | b.data[i];
	return r;
}

static inline bitslice_t bs_and(const bitslice_t a, const bitslice_t b) {
	bitslice_t r;
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++)
		r.data[i] = a.data[i] & b.data[i];
	return r;
}

static inline bitslice_t bs_xor(const bitslice_t a, const bitslice_t b) {
	bitslice_t r;
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++)
		r.data[i] = a.data[i] ^ b.data[i];
	return r;
}

static inline bitslice_t bs_not(const bitslice_t a) {
	bitslice_t r;
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++)
		r.data[i] = ~a.data[i];
	return r;
}
static inline bitslice_t f20a(const bitslice_t a, const bitslice_t b, const bitslice_t c, const bitslice_t d) {
	// ((a|b)^(a&d))^(c&((a^b)|d))
	return bs_xor(
		bs_xor(bs_or(a, b), bs_and(a, d)),
		bs_and(c, bs_or(bs_xor(a, b), d))
	);
}

static inline bitslice_t f20b(const bitslice_t a, const bitslice_t b, const bitslice_t c, const bitslice_t d) {
	// ((a&b)|c)^((a^b)&(c|d))
	return bs_xor(
		bs_or(bs_and(a, b), c),
		bs_and(bs_xor(a, b), bs_or(c, d))
	);
}
#ifdef _WIN32
#include <malloc.h>
#define memalign(ALIGN, SIZE) _aligned_malloc(SIZE, ALIGN)
#define free_bitslice(PTR) _aligned_free(PTR)
#else
#define memalign(ALIGN, SIZE) memalign(ALIGN, SIZE)
#define free_bitslice(PTR) free(PTR)
#endif
static inline bitslice_t f20c(const bitslice_t a, const bitslice_t b, const bitslice_t c, const bitslice_t d, const bitslice_t e) {
	// (a|((b|e)&(d^e)))^( (a^(b&d)) & ((c^d)|(b&e)) )
	return bs_xor(
		bs_or(a, bs_and(bs_or(b, e), bs_xor(d, e))),
		bs_and(bs_xor(a, bs_and(b, d)), bs_or(bs_xor(c, d), bs_and(b, e)))
	);
}
// bit indexing
#define get_bit(n, word) (((word) >> (n)) & 1)
#define get_vector_bit(slice, value) get_bit((slice)&0x3f, value.bytes64[(slice)>>6])

// size of crypto-1 state
#define STATE_SIZE 48
// size of nonce to be decrypted
#define KEYSTREAM_SIZE 24

// endianness conversion
#define rev32(word) ((((word) & 0xff) << 24) | ((((word) >> 8) & 0xff) << 16) | ((((word) >> 16) & 0xff) << 8) | ((((word) >> 24) & 0xff)))
#define malloc_bitslice(x) memalign(MAX_BITSLICES/8, (x))
#define free_bitslice(x) free(x)

// arrays of bitsliced states with identical values in all slices
static bitslice_t bitsliced_encrypted_nonces[256][KEYSTREAM_SIZE];
static bitslice_t bitsliced_encrypted_parity_bits[256][4];
// 1 and 0 vectors
static bitslice_t bs_ones;
static bitslice_t bs_zeroes;

void bitslice_test_nonces_NOSIMD(uint32_t nonces_to_bruteforce, uint32_t* bf_test_nonce, uint8_t* bf_test_nonce_par) {

	// Initialise bs_ones avec tous les bits à 1
// Pour 64 bits : 0xFFFFFFFFFFFFFFFFull
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++) {
		bs_ones.data[i] = 0xFFFFFFFFFFFFFFFFull;
		bs_zeroes.data[i] = 0x0000000000000000ull;
	}
	//// initialize 1 and 0 vectors
	//memset(bs_ones.bytes, 0xff, VECTOR_SIZE);
	//memset(bs_zeroes.bytes, 0x00, VECTOR_SIZE);

	// bitslice nonces' 2nd to 4th byte
	for (uint32_t i = 0; i < nonces_to_bruteforce; i++) {
		for (uint32_t bit_idx = 0; bit_idx < KEYSTREAM_SIZE; bit_idx++) {
			bool bit = get_bit(KEYSTREAM_SIZE - 1 - bit_idx, rev32(bf_test_nonce[i] << 8));
			if (bit) {
				bitsliced_encrypted_nonces[i][bit_idx] = bs_ones;
			}
			else {
				bitsliced_encrypted_nonces[i][bit_idx] = bs_zeroes;
			}
		}
	}
	// bitslice nonces' parity (4 bits)
	for (uint32_t i = 0; i < nonces_to_bruteforce; i++) {
		for (uint32_t bit_idx = 0; bit_idx < 4; bit_idx++) {
			bool bit = get_bit(4 - 1 - bit_idx, bf_test_nonce_par[i]);
			if (bit) {
				bitsliced_encrypted_parity_bits[i][bit_idx] = bs_ones;
			}
			else {
				bitsliced_encrypted_parity_bits[i][bit_idx] = bs_zeroes;
			}
		}
	}

}

uint64_t crack_states_bitsliced_NOSIMD(uint32_t cuid, uint8_t* best_first_bytes, statelist_t* p, uint32_t* keys_found, uint64_t* num_keys_tested, uint32_t nonces_to_bruteforce, uint8_t* bf_test_nonce_2nd_byte, noncelist_t* nonces) {

	// Unlike aczid's implementation this doesn't roll back at all when performing bitsliced bruteforce.
	// We know that the best first byte is already shifted in. Testing with the remaining three bytes of 
	// the nonces is sufficient to eliminate most of them. The small rest is tested with a simple unsliced
	// brute forcing (including roll back).

	bitslice_t states[KEYSTREAM_SIZE + STATE_SIZE];
	bitslice_t* __restrict state_p;
	uint64_t key = -1;
	uint64_t bucket_states_tested = 0;
	uint32_t size_needed = (p->len[EVEN_STATE] - 1) / MAX_BITSLICES + 1;
	uint32_t* bucket_size = (uint32_t*)malloc(size_needed * sizeof(uint32_t));
	if (!bucket_size) {
		perror("malloc failed");
		exit(EXIT_FAILURE);
	}
	uint32_t bitsliced_blocks = 0;
	uint32_t const* __restrict p_even_end = p->states[EVEN_STATE] + p->len[EVEN_STATE];

	// Initialise bs_ones avec tous les bits à 1
 // Pour 64 bits : 0xFFFFFFFFFFFFFFFFull
	for (size_t i = 0; i < (MAX_BITSLICES / 64); i++) {
		bs_ones.data[i] = 0xFFFFFFFFFFFFFFFFull;
		bs_zeroes.data[i] = 0x0000000000000000ull;
	}

	// bitslice all the even states
	bitslice_t** __restrict bitsliced_even_states = (bitslice_t**)malloc(((p->len[EVEN_STATE] - 1) / MAX_BITSLICES + 1) * sizeof(bitslice_t*));
	if (bitsliced_even_states == NULL) {
		printf("Out of memory error in brute_force. Aborting...");
		exit(4);
	}
	bitslice_t* __restrict bitsliced_even_feedback = malloc_bitslice(((p->len[EVEN_STATE] - 1) / MAX_BITSLICES + 1) * sizeof(bitslice_t));

	if (bitsliced_even_feedback == NULL) {
		printf("Out of memory error in brute_force. Aborting...");
		exit(4);
	}
	for (uint32_t* __restrict p_even = p->states[EVEN_STATE]; p_even < p_even_end; p_even += MAX_BITSLICES) {
		bitslice_t* __restrict lstate_p = malloc_bitslice(STATE_SIZE / 2 * sizeof(bitslice_t));
		if (lstate_p == NULL) {
			printf("Out of memory error in brute_force. Aborting... \n");
			exit(4);
		}
		memset(lstate_p, 0x00, STATE_SIZE / 2 * sizeof(bitslice_t)); // zero even bits
		// bitslice even half-states
		const uint32_t max_slices = (p_even_end - p_even) < MAX_BITSLICES ? p_even_end - p_even : MAX_BITSLICES;
		bucket_size[bitsliced_blocks] = max_slices;
		uint32_t slice_idx;
		for (slice_idx = 0; slice_idx < max_slices; ++slice_idx) {
			uint32_t e = *(p_even + slice_idx);
			for (uint32_t bit_idx = 0; bit_idx < STATE_SIZE / 2; bit_idx++, e >>= 1) {
				// set even bits
				if (e & 1) {
					lstate_p[bit_idx].data[slice_idx >> 6] |= 1ull << (slice_idx & 0x3f);
				}
			}
		}
		// padding with last even state
		for (; slice_idx < MAX_BITSLICES; ++slice_idx) {
			uint32_t e = *(p_even_end - 1);
			for (uint32_t bit_idx = 0; bit_idx < STATE_SIZE / 2; bit_idx++, e >>= 1) {
				// set even bits
				if (e & 1) {
					lstate_p[bit_idx].data[slice_idx >> 6] |= 1ull << (slice_idx & 0x3f);
				}
			}
		}
		bitsliced_even_states[bitsliced_blocks] = lstate_p;
		// bitsliced_even_feedback[bitsliced_blocks] = bs_ones;
		for (size_t i = 0; i < (MAX_BITSLICES / 64); i++) {
			bitsliced_even_feedback[bitsliced_blocks].data[i] =
				lstate_p[(47 - 0) / 2].data[i] ^
				lstate_p[(47 - 10) / 2].data[i] ^
				lstate_p[(47 - 12) / 2].data[i] ^
				lstate_p[(47 - 14) / 2].data[i] ^
				lstate_p[(47 - 24) / 2].data[i] ^
				lstate_p[(47 - 42) / 2].data[i];
		}
		bitsliced_blocks++;
	}
	// bitslice every odd state to every block of even states
	for (uint32_t const* __restrict p_odd = p->states[ODD_STATE]; p_odd < p->states[ODD_STATE] + p->len[ODD_STATE]; ++p_odd) {
		// early abort
		if (*keys_found) {
			goto out;
		}

		// set odd state bits and pre-compute first keystream bit vector. This is the same for all blocks of even states

		state_p = &states[KEYSTREAM_SIZE];
		uint32_t o = *p_odd;

		// pre-compute the odd feedback bit
		bool odd_feedback_bit = evenparity32(o & 0x29ce5c);
		const bitslice_t odd_feedback = odd_feedback_bit ? bs_ones : bs_zeroes;

		// set odd state bits
		for (uint32_t state_idx = 0; state_idx < STATE_SIZE; o >>= 1, state_idx += 2) {
			if (o & 1) {
				state_p[state_idx] = bs_ones;
			}
			else {
				state_p[state_idx] = bs_zeroes;
			}
		}

		bitslice_t crypto1_bs_f20b_2[16];
		bitslice_t crypto1_bs_f20b_3[8];

		crypto1_bs_f20b_2[0] = f20b(state_p[(47 - 25)], state_p[(47 - 27)], state_p[(47 - 29)], state_p[(47 - 31)]);
		crypto1_bs_f20b_3[0] = f20b(state_p[47 - 41], state_p[47 - 43], state_p[47 - 45], state_p[47 - 47]);

		bitslice_t ksb[8];
		ksb[0] = f20c(f20a(state_p[47 - 9], state_p[47 - 11], state_p[47 - 13], state_p[47 - 15]),
			f20b(state_p[47 - 17], state_p[47 - 19], state_p[47 - 21], state_p[47 - 23]),
			crypto1_bs_f20b_2[0],
			f20a(state_p[47 - 33], state_p[47 - 35], state_p[47 - 37], state_p[47 - 39]),
			crypto1_bs_f20b_3[0]);

		uint32_t* __restrict p_even = p->states[EVEN_STATE];
		for (uint32_t block_idx = 0; block_idx < bitsliced_blocks; ++block_idx, p_even += MAX_BITSLICES) {
			// add the even state bits
			const bitslice_t* __restrict bitsliced_even_state = bitsliced_even_states[block_idx];
			for (uint32_t state_idx = 1; state_idx < STATE_SIZE; state_idx += 2) {
				state_p[state_idx] = bitsliced_even_state[state_idx / 2];
			}

			// pre-compute first feedback bit vector. This is the same for all nonces
			bitslice_t fbb[8];
			fbb[0] = bs_xor(odd_feedback, bitsliced_even_feedback[block_idx]);

			// vector to contain test results (1 = passed, 0 = failed)
			bitslice_t results;
			results = bs_ones;

			// parity_bits
			bitslice_t par[8];
			par[0] = bs_zeroes;
			uint32_t next_common_bits = 0;

			for (uint32_t tests = 0; tests < nonces_to_bruteforce; ++tests) {
				// common bits with preceding test nonce
				uint32_t common_bits = next_common_bits; //tests ? trailing_zeros(bf_test_nonce_2nd_byte[tests] ^ bf_test_nonce_2nd_byte[tests-1]) : 0;
				next_common_bits = tests < nonces_to_bruteforce - 1 ? trailing_zeros(bf_test_nonce_2nd_byte[tests] ^ bf_test_nonce_2nd_byte[tests + 1]) : 0;
				uint32_t parity_bit_idx = 1; // start checking with the parity of second nonce byte
				bitslice_t fb_bits = fbb[common_bits]; // start with precomputed feedback bits from previous nonce
				bitslice_t ks_bits = ksb[common_bits]; // dito for first keystream bits
				bitslice_t parity_bit_vector = par[common_bits]; // dito for first parity vector
				// bitslice_value_t fb_bits = fbb[0];		// start with precomputed feedback bits from previous nonce
				// bitslice_value_t ks_bits = ksb[0];		// dito for first keystream bits
				// bitslice_value_t parity_bit_vector = par[0]; // dito for first parity vector
				state_p -= common_bits; // and reuse the already calculated state bits
				// highest bit is transmitted/received first. We start with Bit 23 (highest bit of second nonce byte),
				// or the highest bit which differs from the previous nonce
				for (int32_t ks_idx = KEYSTREAM_SIZE - 1 - common_bits; ks_idx >= 0; --ks_idx) {

					// decrypt nonce bits
					const bitslice_t encrypted_nonce_bit_vector = bitsliced_encrypted_nonces[tests][ks_idx];
					const bitslice_t decrypted_nonce_bit_vector = bs_xor(encrypted_nonce_bit_vector, ks_bits);

					// compute real parity bits on the fly
					parity_bit_vector = bs_xor(parity_bit_vector, decrypted_nonce_bit_vector);

					// update state
					state_p--;
					state_p[0] = bs_xor(fb_bits, decrypted_nonce_bit_vector);

					// update crypto1 subfunctions
					bitslice_t f20a_1, f20b_1, f20b_2, f20a_2, f20b_3;
					f20a_2 = f20a(state_p[47 - 33], state_p[47 - 35], state_p[47 - 37], state_p[47 - 39]);
					f20b_3 = f20b(state_p[47 - 41], state_p[47 - 43], state_p[47 - 45], state_p[47 - 47]);
					if (ks_idx > KEYSTREAM_SIZE - 8) {
						f20a_1 = f20a(state_p[47 - 9], state_p[47 - 11], state_p[47 - 13], state_p[47 - 15]);
						f20b_1 = f20b(state_p[47 - 17], state_p[47 - 19], state_p[47 - 21], state_p[47 - 23]);
						f20b_2 = f20b(state_p[47 - 25], state_p[47 - 27], state_p[47 - 29], state_p[47 - 31]);
						crypto1_bs_f20b_2[KEYSTREAM_SIZE - ks_idx] = f20b_2;
						crypto1_bs_f20b_3[KEYSTREAM_SIZE - ks_idx] = f20b_3;
					}
					else if (ks_idx > KEYSTREAM_SIZE - 16) {
						f20a_1 = f20a(state_p[47 - 9], state_p[47 - 11], state_p[47 - 13], state_p[47 - 15]);
						f20b_1 = crypto1_bs_f20b_2[KEYSTREAM_SIZE - ks_idx - 8];
						f20b_2 = f20b(state_p[47 - 25], state_p[47 - 27], state_p[47 - 29], state_p[47 - 31]);
						crypto1_bs_f20b_2[KEYSTREAM_SIZE - ks_idx] = f20b_2;
					}
					else if (ks_idx > KEYSTREAM_SIZE - 24) {
						f20a_1 = f20a(state_p[47 - 9], state_p[47 - 11], state_p[47 - 13], state_p[47 - 15]);
						f20b_1 = crypto1_bs_f20b_2[KEYSTREAM_SIZE - ks_idx - 8];
						f20b_2 = crypto1_bs_f20b_3[KEYSTREAM_SIZE - ks_idx - 16];
					}
					else {
						f20a_1 = f20a(state_p[47 - 9], state_p[47 - 11], state_p[47 - 13], state_p[47 - 15]);
						f20b_1 = f20b(state_p[47 - 17], state_p[47 - 19], state_p[47 - 21], state_p[47 - 23]);
						f20b_2 = f20b(state_p[47 - 25], state_p[47 - 27], state_p[47 - 29], state_p[47 - 31]);
					}
					// update keystream bit
					ks_bits = f20c(f20a_1, f20b_1, f20b_2, f20a_2, f20b_3);

					// for each completed byte:
					if ((ks_idx & 0x07) == 0) {
						// get encrypted parity bits
						const bitslice_t encrypted_parity_bit_vector = bitsliced_encrypted_parity_bits[tests][parity_bit_idx++];

						// decrypt parity bits
						const bitslice_t decrypted_parity_bit_vector = bs_xor(encrypted_parity_bit_vector, ks_bits);

						// compare actual parity bits with decrypted parity bits and take count in results vector
						results = bs_and(results, bs_xor(bs_not(parity_bit_vector), decrypted_parity_bit_vector));


						// make sure we still have a match in our set
						// if(memcmp(&results, &bs_zeroes, sizeof(bitslice_t)) == 0){

						// this is much faster on my gcc, because somehow a memcmp needlessly spills/fills all the xmm registers to/from the stack - ???
						// the short-circuiting also helps
						if (results.data[0] == 0) {
							goto stop_tests;
						}
						// prepare for next nonce byte
						parity_bit_vector = bs_zeroes;
					}
					// update feedback bit vector
					if (ks_idx != 0) {
						fb_bits = state_p[47 - 0];
						fb_bits = bs_xor(fb_bits, state_p[47 - 5]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 9]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 10]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 12]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 14]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 15]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 17]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 19]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 24]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 25]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 27]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 29]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 35]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 39]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 41]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 42]);
						fb_bits = bs_xor(fb_bits, state_p[47 - 43]);
					}
					// remember feedback and keystream vectors for later use
					uint8_t bit = KEYSTREAM_SIZE - ks_idx;
					if (bit <= next_common_bits) {  // if needed and not yet stored
						fbb[bit] = fb_bits;
						ksb[bit] = ks_bits;
						par[bit] = parity_bit_vector;
					}
				}
				// prepare for next nonce. Revert to initial state
				state_p = &states[KEYSTREAM_SIZE];
			}

			// all nonce tests were successful: we've found a possible key in this block!
			uint32_t* p_even_test = p_even;
			for (uint32_t results_word = 0; results_word < MAX_BITSLICES / 64; ++results_word) {
				uint64_t results64 = results.data[results_word];
				for (uint32_t results_bit = 0; results_bit < 64; results_bit++) {
					if (results64 & 0x01) {
						if (verify_key(cuid, nonces, best_first_bytes, *p_odd, *p_even_test)) {
							struct Crypto1State pcs;
							pcs.odd = *p_odd;
							pcs.even = *p_even_test;
							lfsr_rollback_byte(&pcs, (cuid >> 24) ^ best_first_bytes[0], true);
							crypto1_get_lfsr(&pcs, &key);
							bucket_states_tested += 64 * results_word + results_bit;
							goto out;
						}
					}
					results64 >>= 1;
					p_even_test++;
					if (p_even_test == p_even_end) {
						goto stop_tests;
					}
				}
			}
		stop_tests:
			bucket_states_tested += bucket_size[block_idx];
			// prepare to set new states
			state_p = &states[KEYSTREAM_SIZE];
			continue;
		}
	}
out:
	for (uint32_t block_idx = 0; block_idx < bitsliced_blocks; ++block_idx) {
		free_bitslice(bitsliced_even_states[block_idx]);
	}
	free(bitsliced_even_states);
	free_bitslice(bitsliced_even_feedback);
	free(bucket_size);
	InterlockedAdd64((volatile LONG64*)num_keys_tested, (LONG64)bucket_states_tested);
	//__sync_fetch_and_add(num_keys_tested, bucket_states_tested);
	return key;
}
