#ifndef DATUM_POW_V2_H
#define DATUM_POW_V2_H

/*
 * BIP-110 / Blake2b V2 host construction for DATUM Gateway
 * ========================================================
 *
 * Mirrors CBlockHeader::GetHash() and V2 serialization from:
 *   https://github.com/bitcoinknots/bitcoin/pull/359
 *   luke-jr/bitcoin  pow_hf_blake2b
 *
 * COUPLING: Re-diff this module whenever the PR changes GetHash, profiles,
 * header wire layout, time-offset rules, or Blake2b difficulty.
 *
 * Aligned tip (update when re-porting):
 *   0d7a5e74b6  time-offset + ASIC hashPrevBlock.ReversedBytes() + profile vectors
 *
 * Network nBits / retarget: node only (pass-through from GBT).
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** m_flags bit: ASIC grinds time offset; h1 uses GetTimeOnWire() = nTime - offset */
#define DATUM_POW_V2_FLAG_USE_TIME_OFFSET 4u

typedef struct datum_pow_v2_job {
	/* Inputs (template / header) */
	int32_t nVersion; /* without V2 wire flag 0x80000000 */
	uint8_t prev[32];
	uint8_t merkle[32];
	uint32_t nTime; /* host wall / block time (real nTime) */
	uint32_t nBits; /* from node GBT */
	int32_t height;
	uint16_t txcount;
	uint8_t flags; /* low 2 bits = ASIC profile; bit2 = UseTimeOffset */
	uint8_t clear_bits;
	uint8_t xor_key[16];
	uint8_t mm_rhs[32];
	uint8_t extranonce[16];

	/* Grind fields (ASIC-visible) */
	uint32_t nNonce;
	uint32_t nNonce2;
	uint32_t nNonce3; /* u32 after 9228db (was u64) */
	uint32_t time_offset; /* miner-side time rolling; ASIC blind to real nTime */

	/* Outputs */
	uint8_t mid[32];
	uint8_t mask[32];
	uint8_t asic80[80];
	uint8_t raw_blake[32];
	uint8_t final_hash[32];
} datum_pow_v2_job;

/** Effective time in h1: nTime, or nTime - time_offset if UseTimeOffset. */
uint32_t datum_pow_v2_time_on_wire(const datum_pow_v2_job *j);

bool datum_pow_v2_build(datum_pow_v2_job *j);
bool datum_pow_v2_set_nonce(datum_pow_v2_job *j, uint32_t nnonce);

/**
 * Sia-class 80B (profile 0):
 *   prev || nNonce || nNonce2 || time_offset || nNonce3 || mid
 * Maps miner nonce8_le → nNonce|nNonce2, ntime8_le → time_offset|nNonce3.
 */
bool datum_pow_v2_set_sia_nonces(datum_pow_v2_job *j, uint64_t nonce8_le, uint64_t ntime8_le);

int datum_pow_v2_header(const datum_pow_v2_job *j, uint8_t out[164]);

uint64_t datum_pow_v2_parse_hex_le_u64(const char *hex);
void datum_pow_v2_bin_to_hex32(const uint8_t in[32], char out[65]);

#ifdef __cplusplus
}
#endif

#endif /* DATUM_POW_V2_H */
