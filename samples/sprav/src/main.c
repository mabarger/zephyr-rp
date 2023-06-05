/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * SPRAV Remote Attestation Demo
 */

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/drivers/sprav.h>
#if 1
#include <zephyr/drivers/pmp.h>
#endif

#include <string.h>


int main(void)
{
#if 1
	struct pmp_config cfg[PMP_MAX_REGIONS];
	memset(cfg, 0, sizeof(struct pmp_config) * PMP_MAX_REGIONS);

	for (int i = 0; i < 4; i++) {
		pmp_get_config(&cfg[i], i);
	}

	for (int i = 0; i < 4; i++) {
		printk("PMP %2d: @ 0x%08x | Size: 0x%08x B | ", i, cfg[i].base, cfg[i].size);
		printk("Active: %c | Locked: %c | ", cfg[i].active ? 'T' : 'F', cfg[i].locked ? 'T' : 'F');
		printk("Permissions: >%c%c%c<\n", cfg[i].perm & PMP_R ? 'r' : ' ', cfg[i].perm & PMP_W ? 'w' : ' ', cfg[i].perm & PMP_X ? 'x' : ' ');
	}
#endif

	uint8_t signature[SPRAV_SIG_SIZE] = {0};
	printk("[~] sprav_attest_region: %s\n", sprav_attest_region(0x42010020, 0x400, 0x9f6e4ed0, signature) ? "failure" : "success");
	printk("[~] Signature:\n");
	for (size_t i = 0; i < SPRAV_SIG_SIZE; i++) {
		printk("%02x", signature[i]);
	}
	printk("\n");

	return 0;
}
