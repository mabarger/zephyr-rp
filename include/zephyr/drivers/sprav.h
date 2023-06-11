/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_SPRAV_H_
#define ZEPHYR_INCLUDE_DRIVERS_SPRAV_H_

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_SPRAV_ECDSA)
#define SPRAV_SIG_SIZE (64)
#else
#include <oqs/sig_dilithium.h>
#define SPRAV_SIG_SIZE (OQS_SIG_dilithium_2_length_signature)
#endif

/**
 * @brief Attest the specified memory region
 *
 * This function is protected by PMP to prevent leakage of keys.
 *
 * @param[in] addr Start address of memory region.
 * @param[in] size Size of the region to attest in bytes
 * @param[in] nonce Nonce, which will be signed with the memory region.
 * @param[out] signature Memory location where the signature will be stored
 *
 * @return 0 on success, -EFAULT otherwise.
 */
int sprav_attest_region_protected(uintptr_t addr, size_t size, uint32_t nonce,
		     		  uint8_t *signature);

/**
 * @brief Attest the specified memory region
 *
 * @param[in] addr Start address of memory region.
 * @param[in] size Size of the region to attest in bytes
 * @param[in] nonce Nonce, which will be signed with the memory region.
 * @param[out] signature Memory location where the signature will be stored
 *
 * @return 0 on success, -EFAULT otherwise.
 */
__syscall int sprav_attest_region(uintptr_t addr, size_t size, uint32_t nonce,
				  uint8_t *signature);

static inline int z_impl_sprav_attest_region(uintptr_t addr, size_t size,
					     uint32_t nonce,
					     uint8_t *signature)
{
	return sprav_attest_region_protected(addr, size, nonce, signature);
}

#ifdef __cplusplus
}
#endif

#include <syscalls/sprav.h>

#endif /* ZEPHYR_INCLUDE_DRIVERS_SPRAV_H_ */
