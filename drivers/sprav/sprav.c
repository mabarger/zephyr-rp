/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/drivers/sprav.h>
#include <zephyr/logging/log.h>

#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

/* Start and End locations for the prac section */
extern uint8_t *prac_begin;
extern uint8_t *prac_end;

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
				  uint8_t *signature)
{
	/* Compute Hash over requested region */
	struct tc_sha256_state_struct ctx;

	tc_sha256_init(&ctx);
	tc_sha256_update(&ctx, (uint8_t *) addr, size);
	tc_sha256_final(signature, &ctx);

	return 0;
}
