/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_PMP_H_
#define ZEPHYR_INCLUDE_DRIVERS_PMP_H_

#include <zephyr/arch/riscv/csr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PMP_MAX_REGIONS 16

/**
 * @brief Container for PMP configuration
 */
struct pmp_config {
	size_t base; /* Base address */
	size_t size; /* Size in bytes */
	size_t perm; /* Permissions */
	bool active; /* State */
	bool locked; /* Locked bit */
};

/**
 * @brief Retrieves the current PMP configuration of the system
 *
 * @param[in] pmp_cfg Memory location where results will be stored
 * @param[in] region_id PMP region id; -1 to retrieve all regions
 *
 * @return 0 on success, -EFAULT otherwise.
 */
__syscall int pmp_get_config(struct pmp_config *pmp_cfg, int region_id);

#ifdef __cplusplus
}
#endif

#include <syscalls/pmp.h>

#endif /* ZEPHYR_INCLUDE_DRIVERS_PMP_H_ */
