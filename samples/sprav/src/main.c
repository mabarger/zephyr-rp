/* main.c - SPRAV demo */

/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/drivers/sprav.h>

/*
 * This demo makes use of the remote attestation system call interface
 */


int main(void)
{
	uint8_t signature[64] = {0};
	printk("rp_attest_region: %d\n", sprav_attest_region(0x20000000, 0x400, 0x9f6e4ed0, signature));
	for (int i = 0; i < 64; i++) {
		printk("%02x", signature[i]);
	}
	printk("\n");

	return 0;
}
