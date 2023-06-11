/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This code is intended to be run directly after the system has booted and
 * will use the first two PMP regions to protect the prover remote attestation
 * code (prac) by applying execute-only permissions and locking the regions.
 */

#include <zephyr/toolchain.h>

/* Set up PMP to mark prac as execute only and lock it */
GTEXT(__sprav_setup_pmp)
SECTION_FUNC(text, __sprav_setup_pmp)
	la t0, prac_begin
	srli t0, t0, 2
	csrw pmpaddr0, t0

	la t0, prac_end
	srli t0, t0, 2
	li t1, 0x8C8F
	csrw pmpaddr1, t0
	csrw pmpcfg0, t1
	ret

/* Test accesses to address outside and inside region, the second will fail */
/* 
la t0, prac_begin
sb t1, -1(t0)
sb t1, 0x20(t0)
*/
