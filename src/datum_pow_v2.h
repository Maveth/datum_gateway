#ifndef DATUM_POW_V2_H
#define DATUM_POW_V2_H

/*
 * BIP-110 / Blake2b V2 host construction for DATUM Gateway
 * ========================================================
 *
 * Mirrors CBlockHeader::GetHash() and V2 serialization from:
 *   https://github.com/bitcoinknots/bitcoin/pull/359
 *   branch: luke-jr/bitcoin pow_hf_blake2b
 *
 * COUPLING: Any change to GetHash field order, tags, ASIC profiles,
 * mask/XOR rules, or header wire layout in that PR MUST be reflected here.
 * Network nBits / retarget stay on the node (see datum_pow_v2_network_nbits
 * placeholder notes in datum_pow_v2.c).
 *
 * DATUM role (unchanged ethos):
 *   - Build templates / coinbases / Stratum jobs
 *   - Pack miner-facing 80-byte Blake2b work
 *   - Assemble V2 blocks and submitblock to the node
 *
 * Miner role: Blake2b-256 over the 80-byte ASIC region only.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Host + grind fields needed to build mid, ASIC region, final digest, V2 header. */
typedef struct datum_pow_v2_job {
	/* Inputs (template / header) */
	int32_t nVersion; /* without V2 wire flag 0x80000000 */
	uint8_t prev[32]; /* internal header byte order */
	uint8_t merkle[32];
	uint32_t nTime;
	uint32_t nBits; /* compact target from node GBT — authority is the node */
	int32_t height;
	uint16_t txcount;
	uint8_t reserved; /* low 2 bits = ASIC profile (PR multi-profile) */
	uint8_t clear_bits;
	uint8_t xor_key[16];
	uint8_t mm_rhs[32];
	uint8_t extranonce[16];

	/* Grind fields */
	uint32_t nNonce;
	uint32_t nNonce2;
	uint64_t nNonce3;

	/* Outputs of build / set_nonce */
	uint8_t mid[32];
	uint8_t mask[32];
	uint8_t asic80[80];
	uint8_t raw_blake[32];
	uint8_t final_hash[32]; /* uint256 storage order for CheckPoW / compare_hashes */
} datum_pow_v2_job;

/**
 * Compute mid, mask, and current asic/final for nNonce (and nNonce2/3 on job).
 * Returns false on failure (e.g. sodium init).
 */
bool datum_pow_v2_build(datum_pow_v2_job *j);

/** Update grind nonces and recompute asic80 / raw / final (mid must already be set). */
bool datum_pow_v2_set_nonce(datum_pow_v2_job *j, uint32_t nnonce);

/**
 * Sia-class / SC1-style 80B layout (Luke profile 0):
 *   prev32 || nonce8_le || ntime8_le || mid32
 * where nonce8 = nNonce || nNonce2, ntime8 = nNonce3.
 */
bool datum_pow_v2_set_sia_nonces(datum_pow_v2_job *j, uint64_t nonce8_le, uint64_t ntime8_le);

/** Serialize CBlockHeader V2 wire form (164 bytes). Returns 164 or -1. */
int datum_pow_v2_header(const datum_pow_v2_job *j, uint8_t out[164]);

/**
 * Parse up to 16 hex chars as little-endian byte stream into a u64
 * (Sia-class nonce/ntime fields). Shorter hex is treated as big-endian uint
 * (classic Stratum u32 nonce).
 */
uint64_t datum_pow_v2_parse_hex_le_u64(const char *hex);

/** Write 32 bytes as lowercase hex into out[65] (NUL-terminated). */
void datum_pow_v2_bin_to_hex32(const uint8_t in[32], char out[65]);

#ifdef __cplusplus
}
#endif

#endif /* DATUM_POW_V2_H */
