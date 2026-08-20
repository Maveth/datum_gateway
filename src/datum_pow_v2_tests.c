/*
 * Unit tests for Blake2b V2 host construction (datum_pow_v2).
 * Tip ca52286218 — update when pow_hf_blake2b GetHash changes.
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
	j.flags = 0;
	j.clear_bits = 0;

	datum_test(datum_pow_v2_build(&j));

	datum_test(parse_hex(
	               "0e19be371ae77ae82bfc9244bda8fc3d737d088c76afd3bd9a1a0d7290935753",
	               expect_mid, 32) == 0);
	datum_test(memcmp(j.mid, expect_mid, 32) == 0);

	for (int i = 0; i < 32; i++) {
		datum_test(j.mask[i] == 0);
	}

	datum_test(parse_hex(
	               "f58b8f90f38550d1152e49004ae463c87d506339bc109da65a6433e1d7d5938c",
	               expect_raw, 32) == 0);
	datum_test(memcmp(j.raw_blake, expect_raw, 32) == 0);

	datum_test(parse_hex(
	               "8c93d5d7e133645aa69d10bc3963507dc863e44a00492e15d15085f3908f8bf5",
	               expect_final, 32) == 0);
	datum_test(memcmp(j.final_hash, expect_final, 32) == 0);

	datum_test(j.prev_asic[0] == 0 && j.prev_asic[5] == 0);
	datum_test(parse_hex(
	               "00000000000040d220de03021a7f5602b8bb61c091f12f566c66039554fa856f"
	               "000000000000000000000000000000000e19be371ae77ae82bfc9244bda8fc3d"
	               "737d088c76afd3bd9a1a0d7290935753",
	               expect_asic, 80) == 0);
	datum_test(memcmp(j.asic80, expect_asic, 80) == 0);

	n = datum_pow_v2_header(&j, hdr);
	datum_test(n == 164);
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

	datum_test(datum_pow_v2_set_sia_nonces(&j, 0x0506070801020304ULL, 0x1122334455667788ULL));
	datum_test(j.nNonce == 0x01020304u);
	datum_test(j.nNonce2 == 0x05060708u);
	datum_test(j.time_offset == 0x55667788u);
	datum_test(j.nNonce3 == 0x11223344u);
	datum_test(memcmp(j.mid, mid_copy, 32) == 0);

	j.flags = 1;
	datum_test(datum_pow_v2_set_nonce(&j, 0xAABBCCDDu));
	datum_test(j.asic80[0] == 0xDD && j.asic80[1] == 0xCC && j.asic80[2] == 0xBB &&
	           j.asic80[3] == 0xAA);
	datum_test(memcmp(j.asic80 + 48, j.h2, 32) == 0);
}

static void test_use_time_offset_rebuilds_mid(void)
{
	datum_pow_v2_job j;
	uint8_t mid0[32];

	memset(&j, 0, sizeof(j));
	j.nVersion = 0x20000000;
	j.prev[31] = 0x01;
	memset(j.merkle, 0x11, 32);
	j.nTime = 1700000000;
	j.nBits = 0x207fffff;
	j.height = 1;
	j.txcount = 1;
	j.flags = DATUM_POW_V2_FLAG_USE_TIME_OFFSET;
	datum_test(datum_pow_v2_build(&j));
	memcpy(mid0, j.mid, 32);

	datum_test(datum_pow_v2_set_sia_nonces(&j, 0, 0x0000000000000005ULL));
	datum_test(j.time_offset == 5u);
	datum_test(datum_pow_v2_time_on_wire(&j) == j.nTime - 5u);
	datum_test(memcmp(j.mid, mid0, 32) != 0);
}

static void test_parse_hex_le(void)
{
	datum_test(datum_pow_v2_parse_hex_le_u64("0000000000000000") == 0);
	datum_test(datum_pow_v2_parse_hex_le_u64("a") == 10);
	datum_test(datum_pow_v2_parse_hex_le_u64("ff") == 255);
}

/* Stock Sia leaf (0x00||coinb1||en12) must equal tip mid (u32_0||h2||0x00000000||en12). */
static void test_sia_coinb1_mid_matches_build(void)
{
	datum_pow_v2_job j;
	uint8_t en12[12];
	uint8_t mid_sia[32];
	uint8_t coinb1[DATUM_POW_V2_SIA_COINB1_LEN];
	int i;

	memset(&j, 0, sizeof(j));
	j.nVersion = 0x20000000;
	j.prev[31] = 0x01;
	memset(j.merkle, 0x11, 32);
	j.nTime = 1700000000;
	j.nBits = 0x207fffff;
	j.height = 1;
	j.txcount = 1;
	for (i = 0; i < 12; i++) {
		en12[i] = (uint8_t)(0xa0 + i);
	}
	datum_pow_v2_set_extranonce_from_en12(&j, en12);
	datum_test(datum_pow_v2_build(&j));

	datum_pow_v2_sia_coinb1(coinb1, j.h2);
	datum_test(coinb1[0] == 0 && coinb1[1] == 0 && coinb1[2] == 0);
	datum_test(memcmp(coinb1 + 3, j.h2, 32) == 0);
	datum_test(coinb1[35] == 0 && coinb1[38] == 0);

	datum_test(datum_pow_v2_mid_from_sia_en12(mid_sia, j.h2, en12));
	datum_test(memcmp(mid_sia, j.mid, 32) == 0);
}

void datum_pow_v2_tests(void)
{
	test_blake2b_rfc_vectors();
	test_host_job_fixed_vector();
	test_sia_nonce_map_and_profile1();
	test_use_time_offset_rebuilds_mid();
	test_parse_hex_le();
	test_sia_coinb1_mid_matches_build();
}
