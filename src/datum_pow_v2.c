/*
 * datum_pow_v2.c — Blake2b V2 host construction (DATUM side)
 *
 * Port of Knots PR #359 GetHash host path for use while DATUM builds templates
 * and packs miner work. Consensus validity remains on the node.
 *
 * Upstream reference (freeze / re-diff when the PR moves):
 *   https://github.com/bitcoinknots/bitcoin/pull/359
 *   CBlockHeader::GetHash, V2 SERIALIZE_METHODS, ASIC profiles (m_reserved&3)
 *
 * -------------------------------------------------------------------------
 * NETWORK DIFFICULTY (placeholder — do not reimplement retarget here)
 * -------------------------------------------------------------------------
 * Compact nBits on jobs come from bitcoind GBT. The node owns:
 *   - GetNextWorkRequired / CalculateNextWorkRequired
 *   - ApplyBlake2bTargetShift on first DEPLOYMENT_BLAKE2B height
 *     (see bitcoin/src/pow.cpp in pow_hf_blake2b)
 *   - CheckPoW against final Blake2b digest
 *
 * DATUM must:
 *   - Pass through template nBits as job nBits / block_target
 *   - Score shares with Blake2b final vs share target and block target
 *   - NOT invent a parallel retarget
 *
 * When the PR changes Blake2bTargetShift, powLimit, or retarget rules,
 * update node first; DATUM only needs re-test (and any share-diff policy).
 * -------------------------------------------------------------------------
 */

#include "datum_pow_v2.h"

#include "datum_utils.h"

#include <sodium.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- little-endian helpers ------------------------------------------------ */

static void write_u32_le(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xff);
	p[1] = (uint8_t)((v >> 8) & 0xff);
	p[2] = (uint8_t)((v >> 16) & 0xff);
	p[3] = (uint8_t)((v >> 24) & 0xff);
}

static void write_u64_le(uint8_t *p, uint64_t v)
{
	for (int i = 0; i < 8; i++) {
		p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
	}
}

static void write_i32_le(uint8_t *p, int32_t v)
{
	write_u32_le(p, (uint32_t)v);
}

/* ---- crypto primitives (match Core TaggedHash + Blake2b-256) -------------- */

static void tagged_sha256(const char *tag, const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
	uint8_t tag_digest[32];
	uint8_t stack_buf[64 + 128];
	uint8_t *buf = stack_buf;
	size_t total = 64 + msg_len;
	int heap = 0;

	my_sha256(tag_digest, (const unsigned char *)tag, strlen(tag));

	if (total > sizeof(stack_buf)) {
		buf = (uint8_t *)malloc(total);
		if (!buf) {
			memset(out, 0, 32);
			return;
		}
		heap = 1;
	}

	memcpy(buf, tag_digest, 32);
	memcpy(buf + 32, tag_digest, 32);
	if (msg_len) {
		memcpy(buf + 64, msg, msg_len);
	}
	my_sha256(out, buf, total);
	if (heap) {
		free(buf);
	}
}

static void blake2b_256(const uint8_t *in, size_t inlen, uint8_t out[32])
{
	crypto_generichash_blake2b(out, 32, in, inlen, NULL, 0);
}

/* ---- public helpers ------------------------------------------------------- */

void datum_pow_v2_bin_to_hex32(const uint8_t in[32], char out[65])
{
	static const char *hexd = "0123456789abcdef";
	for (int i = 0; i < 32; i++) {
		out[i * 2] = hexd[(in[i] >> 4) & 0xf];
		out[i * 2 + 1] = hexd[in[i] & 0xf];
	}
	out[64] = '\0';
}

uint64_t datum_pow_v2_parse_hex_le_u64(const char *hex)
{
	size_t n;
	uint64_t v = 0;
	size_t nbytes;
	size_t i;

	if (!hex) {
		return 0;
	}
	n = strlen(hex);
	if (n == 0) {
		return 0;
	}
	/* 16 hex chars = 8 LE bytes (Sia-class). Else classic Stratum integer hex. */
	if (n == 16) {
		for (i = 0; i < 8; i++) {
			unsigned int b = 0;
			if (sscanf(hex + i * 2, "%02x", &b) != 1) {
				return 0;
			}
			v |= ((uint64_t)b) << (8 * i);
		}
		return v;
	}
	return (uint64_t)strtoull(hex, NULL, 16);
}

/* ---- GetHash host path (PR #359) ------------------------------------------ */

bool datum_pow_v2_build(datum_pow_v2_job *j)
{
	uint8_t xor_key_hash[32];
	uint8_t h1msg[90];
	uint8_t h1[32];
	uint8_t h2msg[64];
	uint8_t h2[32];
	uint8_t mid_ss[52];
	size_t o;
	int xor_null;
	unsigned int i;

	if (!j) {
		return false;
	}
	if (sodium_init() < 0) {
		return false;
	}

	/* xor_key_hash = TaggedHash("…XOR key" || xor_key) */
	tagged_sha256("Bitcoin block hash PoW XOR key", j->xor_key, 16, xor_key_hash);

	/* mask: null key → zeros; else TaggedHash mask tag, then clear_bits */
	memset(j->mask, 0, 32);
	xor_null = 1;
	for (i = 0; i < 16; i++) {
		if (j->xor_key[i]) {
			xor_null = 0;
			break;
		}
	}
	if (!xor_null) {
		unsigned int clear_bytes;
		unsigned int rem;
		tagged_sha256("Bitcoin block hash PoW XOR mask", j->xor_key, 16, j->mask);
		clear_bytes = (unsigned int)j->clear_bits / 8;
		rem = (unsigned int)j->clear_bits % 8;
		if (clear_bytes > 32) {
			clear_bytes = 32;
		}
		memset(j->mask, 0, clear_bytes);
		if (rem && clear_bytes < 32) {
			j->mask[clear_bytes] &= (uint8_t)(0xffu >> rem);
		}
	}

	/*
	 * h1 user payload: 90 bytes (PR assert was fixed 88→90).
	 * version, merkle, height, nTime, 0 (time hi), nBits, txcount u32,
	 * reserved u8, clear_bits u8, xor_key_hash
	 */
	o = 0;
	write_u32_le(h1msg + o, (uint32_t)j->nVersion);
	o += 4;
	memcpy(h1msg + o, j->merkle, 32);
	o += 32;
	write_u32_le(h1msg + o, (uint32_t)j->height);
	o += 4;
	write_u32_le(h1msg + o, j->nTime);
	o += 4;
	write_u32_le(h1msg + o, 0);
	o += 4;
	write_u32_le(h1msg + o, j->nBits);
	o += 4;
	write_u32_le(h1msg + o, (uint32_t)j->txcount);
	o += 4;
	h1msg[o++] = j->reserved;
	h1msg[o++] = j->clear_bits;
	memcpy(h1msg + o, xor_key_hash, 32);
	o += 32;
	if (o != 90) {
		return false;
	}
	tagged_sha256("Bitcoin block header 1", h1msg, 90, h1);

	memcpy(h2msg, h1, 32);
	memcpy(h2msg + 32, j->mm_rhs, 32);
	tagged_sha256("Merge-mining hook", h2msg, 64, h2);

	/* mid = Blake2b-256( u32le(0) || h2 || extranonce16 ) */
	write_u32_le(mid_ss, 0);
	memcpy(mid_ss + 4, h2, 32);
	memcpy(mid_ss + 36, j->extranonce, 16);
	blake2b_256(mid_ss, 52, j->mid);

	return datum_pow_v2_set_nonce(j, j->nNonce);
}

bool datum_pow_v2_set_nonce(datum_pow_v2_job *j, uint32_t nnonce)
{
	int profile;
	uint8_t *a;

	if (!j) {
		return false;
	}
	j->nNonce = nnonce;
	profile = j->reserved & 3;
	a = j->asic80;

	/*
	 * ASIC profiles from PR (m_reserved & 3):
	 *   0: prev || nNonce || nNonce2 || nNonce3 || mid
	 *   1: nNonce || nNonce2 || nNonce3 || mid || prev
	 */
	if (profile == 1) {
		write_u32_le(a + 0, j->nNonce);
		write_u32_le(a + 4, j->nNonce2);
		write_u64_le(a + 8, j->nNonce3);
		memcpy(a + 16, j->mid, 32);
		memcpy(a + 48, j->prev, 32);
	} else {
		memcpy(a + 0, j->prev, 32);
		write_u32_le(a + 32, j->nNonce);
		write_u32_le(a + 36, j->nNonce2);
		write_u64_le(a + 40, j->nNonce3);
		memcpy(a + 48, j->mid, 32);
	}

	blake2b_256(j->asic80, 80, j->raw_blake);

	/* final[31-i] = raw[i] ^ mask[i]  (uint256 storage / CheckPoW order) */
	for (int i = 0; i < 32; i++) {
		j->final_hash[31 - i] = (uint8_t)(j->raw_blake[i] ^ j->mask[i]);
	}
	return true;
}

bool datum_pow_v2_set_sia_nonces(datum_pow_v2_job *j, uint64_t nonce8_le, uint64_t ntime8_le)
{
	/*
	 * Miner-facing Sia-class 80B (profile 0):
	 *   prev32 | nonce8 | ntime8 | mid32
	 * Maps to Luke: nNonce|nNonce2, nNonce3, mid.
	 */
	if (!j) {
		return false;
	}
	j->nNonce = (uint32_t)(nonce8_le & 0xffffffffu);
	j->nNonce2 = (uint32_t)((nonce8_le >> 32) & 0xffffffffu);
	j->nNonce3 = ntime8_le;
	return datum_pow_v2_set_nonce(j, j->nNonce);
}

int datum_pow_v2_header(const datum_pow_v2_job *j, uint8_t out[164])
{
	uint32_t v;
	size_t o = 0;

	if (!j || !out) {
		return -1;
	}

	v = 0x80000000u | ((uint32_t)j->nVersion & 0x7fffffffu);
	write_u32_le(out + o, v);
	o += 4;
	memcpy(out + o, j->prev, 32);
	o += 32;
	memcpy(out + o, j->merkle, 32);
	o += 32;
	write_u32_le(out + o, j->nTime);
	o += 4;
	write_u32_le(out + o, j->nBits);
	o += 4;
	write_u32_le(out + o, j->nNonce);
	o += 4;
	write_u32_le(out + o, j->nNonce2);
	o += 4;
	write_u64_le(out + o, j->nNonce3);
	o += 8;
	memcpy(out + o, j->extranonce, 16);
	o += 16;
	out[o++] = (uint8_t)(j->txcount & 0xff);
	out[o++] = (uint8_t)((j->txcount >> 8) & 0xff);
	out[o++] = j->reserved;
	out[o++] = j->clear_bits;
	memcpy(out + o, j->xor_key, 16);
	o += 16;
	write_i32_le(out + o, j->height);
	o += 4;
	memcpy(out + o, j->mm_rhs, 32);
	o += 32;

	return (o == 164) ? 164 : -1;
}
