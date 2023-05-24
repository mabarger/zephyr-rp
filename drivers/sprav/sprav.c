/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/sprav.h>
#include <zephyr/logging/log.h>

#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dsa.h>
#include <tinycrypt/constants.h>
#include <tinycrypt/sha256.h>

/* Start and End locations for the prac section */
extern uint8_t *prac_begin;
extern uint8_t *prac_end;

#define ATTESTATION_KEY_SIZE NUM_ECC_BYTES
#define STORE_WORD_IMMEDIATE(dst, word) \
	__asm__ volatile("sw %1, 0(%0)" : : "r" (dst), "r" (word));

#pragma GCC push_options
#pragma GCC optimize ("O0")

/**
 * @brief Load the attestation key into memory using immediates
 *
 * @param[in] sprav_attestation_key destination address
 */
static void sprav_load_attestation_key(uint8_t *sprav_attestation_key)
{
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00, 0xf38389e1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04, 0x312cc644);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08, 0x00f52ebb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0C, 0x105b5ad3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x10, 0x02013857);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x14, 0xa33ce423);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x18, 0x6c150d4f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x1C, 0x24330e58);
}

/**
 * @brief Zeroes out the attestation key in memory
 *
 * @param[in] sprav_attestation_key address to zero out
 */
static void sprav_zero_attestation_key(uint8_t *sprav_attestation_key)
{
	for (size_t i = 0; i < ATTESTATION_KEY_SIZE; i++) {
		sprav_attestation_key[i] = 0x00;
	}
}

#pragma GCC pop_options

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
				  uint8_t *signature)
{
	int ret = 0;
	struct tc_sha256_state_struct ctx;
	uint8_t hash[TC_SHA256_DIGEST_SIZE];
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	uint8_t sprav_attestation_key[ATTESTATION_KEY_SIZE];

	/* Load attestation key */
	sprav_load_attestation_key(sprav_attestation_key);

	/* Compute Hash over requested region */
	tc_sha256_init(&ctx);
	tc_sha256_update(&ctx, (uint8_t *) addr, size);
	tc_sha256_final(hash, &ctx);

	/* Compute Signature over hash & nonce */
	ret = uECC_sign_with_k(sprav_attestation_key, hash,
			       TC_SHA256_DIGEST_SIZE,
			       (uECC_word_t *) &nonce, signature, curve);
	if (ret == 0) {
		return -EFAULT;
	}

	/* Zero out temporary attestation key */
	sprav_zero_attestation_key(sprav_attestation_key);

	return 0;
}
