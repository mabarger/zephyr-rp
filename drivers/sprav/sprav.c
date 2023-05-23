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

/* Private attestation key */
#define ATTESTATION_KEY { \
	0xe1, 0x89, 0x83, 0xf3, 0x44, 0xc6, 0x2c, 0x31, \
	0xbb, 0x2e, 0xf5, 0x00, 0xd3, 0x5a, 0x5b, 0x10, \
	0x57, 0x38, 0x01, 0x02, 0x23, 0xe4, 0x3c, 0xa3, \
	0x4f, 0x0d, 0x15, 0x6c, 0x58, 0x0e, 0x33, 0x24, \
}

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
				  uint8_t *signature)
{
	int ret = 0;
	struct tc_sha256_state_struct ctx;
	uint8_t hash[TC_SHA256_DIGEST_SIZE] = {0};
	const struct uECC_Curve_t *curve = uECC_secp256r1();
	uint8_t secret_key[NUM_ECC_BYTES] = ATTESTATION_KEY;

	/* Compute Hash over requested region */
	tc_sha256_init(&ctx);
	tc_sha256_update(&ctx, (uint8_t *) addr, size);
	tc_sha256_final(hash, &ctx);

	/* Compute Signature over hash & nonce */
	ret = uECC_sign_with_k(secret_key, hash, TC_SHA256_DIGEST_SIZE,
			       (uECC_word_t *) &nonce, signature, curve);
	if (ret == 0) {
		return -EFAULT;
	}

	return 0;
}
