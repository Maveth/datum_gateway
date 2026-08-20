#ifndef DATUM_POW_V2_H
#define DATUM_POW_V2_H

/*
 * BIP-110 / Blake2b V2 host construction for DATUM Gateway
 * ========================================================
 *
 * Mirrors CBlockHeader::GetHash() from luke-jr/bitcoin pow_hf_blake2b.
 *
 * Aligned tip: 5a3f788e84 (GetHash same as ca52286218)
 *   - h1 includes ReversedBytes(prev); reserved time is uint8_t (119B payload)
 *   - prevblock_hidden = TaggedHash("Bitcoin prevblock header, hashed")
 *   - profile 0 ASIC: hidden prev with first 6 bytes cleared
 *   - profile 1 ASIC: ends with h2_hash (not prev)
 *   - h2 pads two zero uint128 before mm_rhs
 *   - time_on_wire: uint32 wrap (== tip WrappingAdd/WrappingSubtract)
 *
 * Why (short):
 *   prev in h1: ASIC cannot brick on future tip; host still commits to prev
 *   prevblock_hidden + 6 zero: grind region hides tip; leading bytes = filter space
 *   h2 zero pads: reserved merge-mine expansion without breaking mid layout yet
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DATUM_POW_V2_FLAG_USE_TIME_OFFSET 4u

/* Sv1 Sia coinb1: 3×0x00 || h2(32) || 4×0x00  (39B). With stratum en12 and
 * hasher prefix 0x00, leaf = u32(0)||h2||(0x00000000||en12) == tip mid stream. */
#define DATUM_POW_V2_SIA_COINB1_LEN 39

typedef struct datum_pow_v2_job {
	int32_t nVersion;
	uint8_t prev[32]; /* header-wire / uint256 internal */
	uint8_t merkle[32];
	uint32_t nTime;
	uint32_t nBits;
	int32_t height;
	uint16_t txcount;
	uint8_t flags;
	uint8_t clear_bits;
	uint8_t xor_key[16];
	uint8_t mm_rhs[32];
	uint8_t extranonce[16];

	uint32_t nNonce;
	uint32_t nNonce2;
	uint32_t nNonce3;
	uint32_t time_offset;

	uint8_t mid[32];
	uint8_t mask[32];
	uint8_t h2[32]; /* exposed for profile 1 ASIC tail / debug */
	uint8_t prev_asic[32]; /* profile-0 grind prefix (hidden+6 cleared) */
	uint8_t asic80[80];
	uint8_t raw_blake[32];
	uint8_t final_hash[32];
} datum_pow_v2_job;

uint32_t datum_pow_v2_time_on_wire(const datum_pow_v2_job *j);

bool datum_pow_v2_build(datum_pow_v2_job *j);
bool datum_pow_v2_set_nonce(datum_pow_v2_job *j, uint32_t nnonce);

/**
 * Sia-class profile 0: header80 = prev_asic || nonce8 || ntime8 || mid
 * (prev_asic is hashed/cleared tip — not wire prev)
 */
bool datum_pow_v2_set_sia_nonces(datum_pow_v2_job *j, uint64_t nonce8_le, uint64_t ntime8_le);

int datum_pow_v2_header(const datum_pow_v2_job *j, uint8_t out[164]);

uint64_t datum_pow_v2_parse_hex_le_u64(const char *hex);
void datum_pow_v2_bin_to_hex32(const uint8_t in[32], char out[65]);

/** Pack Sv1 coinb1 from h2 (Luke tip / stock Sia firmware). */
void datum_pow_v2_sia_coinb1(uint8_t out[DATUM_POW_V2_SIA_COINB1_LEN], const uint8_t h2[32]);

/**
 * Mid from Sia leaf: Blake2b(0x00 || coinb1[39] || en12).
 * Equivalent to tip mid when m_extranonce = 4×0x00 || en12.
 */
bool datum_pow_v2_mid_from_sia_en12(uint8_t mid[32], const uint8_t h2[32], const uint8_t en12[12]);

/** Set m_extranonce = 4×0x00 || en12 (Luke tip ↔ 12-byte Sv1 extranonce). */
void datum_pow_v2_set_extranonce_from_en12(datum_pow_v2_job *j, const uint8_t en12[12]);

#ifdef __cplusplus
}
#endif

#endif /* DATUM_POW_V2_H */
