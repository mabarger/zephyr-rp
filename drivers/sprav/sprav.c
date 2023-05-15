/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/drivers/sprav.h>
#include <zephyr/logging/log.h>

/* Start and End locations for the prac section */
extern uint8_t *prac_begin;
extern uint8_t *prac_end;

int __attribute__((section("prac"))) sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
								   uint8_t *signature)
{
	/* Compute Hash over requested region */

	return 0;
}
