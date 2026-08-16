/*
 * Unit tests for Blake2b V2 host construction (datum_pow_v2).
 *
 * Vectors cross-checked against bip110miner Python luke_host (and PR #359 crypto).
 * Re-run / update when pow_hf_blake2b GetHash changes.
 */

#include <stdint.h>
#include <string.h>

#include <sodium.h>

#include "datum_pow_v2.h"
#include "datum_utils.h"

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

static int parse_hex(const char *hex, uint8_t *out, size_t out_len)
{
	size_t n = strlen(hex);
	if (n != out_len * 2) {
		return -1;
	}
	for (size_t i = 0; i < out_len; i++) {
		int hi = hex_nibble(hex[i * 2]);
		int lo = hex_nibble(hex[i * 2 + 1]);
		if (hi < 0 || lo < 0) {
			return -1;
		}
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static void test_blake2b_rfc_vectors(void)
{
	/* Standard BLAKE2b-256 (same as PR crypto tests / Python hashlib) */
	uint8_t out[32];
	uint8_t expect[32];

	datum_test(parse_hex(
	               "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
	               expect, 32) == 0);
	crypto_generichash_blake2b(out, 32, (const unsigned char *)"", 0, NULL, 0);
	datum_test(memcmp(out, expect, 32) == 0);

	datum_test(parse_hex(
	               "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
	               expect, 32) == 0);
	crypto_generichash_blake2b(out, 32, (const unsigned char *)"abc", 3, NULL, 0);
	datum_test(memcmp(out, expect, 32) == 0);
}

/* Fixed job — must match Python bip110miner.pow.luke_host finalize */
static void test_host_job_fixed_vector(void)
{
	datum_pow_v2_job j;
	uint8_t expect_mid[32];
	uint8_t expect_raw[32];
	uint8_t expect_final[32];
	uint8_t expect_asic[80];
	uint8_t hdr[164];
	int n;

	memset(&j, 0, sizeof(j));
	j.nVersion = 0x20000000;
	memset(j.prev, 0, 32);
	j.prev[31] = 0x01;
	memset(j.merkle, 0x11, 32);
	j.nTime = 1700000000;
	j.nBits = 0x207fffff;
	j.height = 1;
	j.txcount = 1;
	j.reserved = 0; /* profile 0 */
	j.clear_bits = 0;
	/* xor_key and mm_rhs and extranonce already zero */

	datum_test(datum_pow_v2_build(&j));

	datum_test(parse_hex(
	               "02ea08234d99b50c51aa2fdc2e3fea3d0fc352046ba2d90ef3d0f4eef0def7ad",
	               expect_mid, 32) == 0);
	datum_test(memcmp(j.mid, expect_mid, 32) == 0);

	/* null xor_key → zero mask */
	for (int i = 0; i < 32; i++) {
		datum_test(j.mask[i] == 0);
	}

	datum_test(parse_hex(
	               "0a8169fb9859778f7b6576a1dfaf7ed58874f3985378d54274124e1473ec1bf3",
	               expect_raw, 32) == 0);
	datum_test(memcmp(j.raw_blake, expect_raw, 32) == 0);

	datum_test(parse_hex(
	               "f31bec73144e127442d5785398f37488d57eafdfa176657b8f775998fb69810a",
	               expect_final, 32) == 0);
	datum_test(memcmp(j.final_hash, expect_final, 32) == 0);

	datum_test(parse_hex(
	               "0000000000000000000000000000000000000000000000000000000000000001"
	               "0000000000000000000000000000000002ea08234d99b50c51aa2fdc2e3fea3d"
	               "0fc352046ba2d90ef3d0f4eef0def7ad",
	               expect_asic, 80) == 0);
	datum_test(memcmp(j.asic80, expect_asic, 80) == 0);

	n = datum_pow_v2_header(&j, hdr);
	datum_test(n == 164);
	/* V2 flag | version 0x20000000 → 0xa0000000 LE */
	datum_test(hdr[0] == 0x00 && hdr[1] == 0x00 && hdr[2] == 0x00 && hdr[3] == 0xa0);
}

static void test_sia_nonce_map_and_profile1(void)
{
	datum_pow_v2_job j;
	uint8_t mid_copy[32];

	memset(&j, 0, sizeof(j));
	j.nVersion = 0x20000000;
	j.prev[31] = 0x01;
	memset(j.merkle, 0x11, 32);
	j.nTime = 1700000000;
	j.nBits = 0x207fffff;
	j.height = 1;
	j.txcount = 1;
	datum_test(datum_pow_v2_build(&j));
	memcpy(mid_copy, j.mid, 32);

	/* nonce8 LE: low u32 = 0x01020304, high u32 = 0x05060708 */
	datum_test(datum_pow_v2_set_sia_nonces(&j, 0x0506070801020304ULL, 0x1122334455667788ULL));
	datum_test(j.nNonce == 0x01020304u);
	datum_test(j.nNonce2 == 0x05060708u);
	datum_test(j.nNonce3 == 0x1122334455667788ULL);
	datum_test(memcmp(j.mid, mid_copy, 32) == 0); /* mid independent of grind nonces */

	/* profile 1: nNonce at start of asic80 */
	j.reserved = 1;
	datum_test(datum_pow_v2_set_nonce(&j, 0xAABBCCDDu));
	datum_test(j.asic80[0] == 0xDD && j.asic80[1] == 0xCC && j.asic80[2] == 0xBB &&
	           j.asic80[3] == 0xAA);
}

static void test_parse_hex_le(void)
{
	/* 8 zero bytes */
	datum_test(datum_pow_v2_parse_hex_le_u64("0000000000000000") == 0);
	/* classic-style integer hex (not 16 chars) */
	datum_test(datum_pow_v2_parse_hex_le_u64("a") == 10);
	datum_test(datum_pow_v2_parse_hex_le_u64("ff") == 255);
}

void datum_pow_v2_tests(void)
{
	test_blake2b_rfc_vectors();
	test_host_job_fixed_vector();
	test_sia_nonce_map_and_profile1();
	test_parse_hex_le();
}
