/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/drivers/sprav.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/random/rand32.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>

#include <oqs/oqs.h>

#define ATTESTATION_KEY_SIZE OQS_SIG_dilithium_2_length_secret_key

#define SHA_256_DIGEST_SIZE (32)
#define MSG_SIZE (SHA_256_DIGEST_SIZE + sizeof(uint32_t))

/* Main stack */
extern char z_main_stack[];

/* Pointer to the temporary attestation key */
static uint8_t *sprav_attestation_key = NULL;

/* liboqs error tracking & exit wrapping */
int liboqs_errno = 0;
int __errno_location = (int) &liboqs_errno;
static size_t saved_pc = 0;
static size_t saved_sp = 0;
static bool liboqs_exit_flag = false;

/* Wrappers for liboqs library calls */
void *__memcpy_chk(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}

void sprav_csrand(unsigned char *addr, unsigned int size)
{
	sys_csrand_get(addr, size);
}

void sprav_exit(int status)
{
	/* Jump back to recovery point in sprav_attest_region_protected */
	liboqs_exit_flag = true;
	__asm__ volatile("mv sp, %0" :: "r"(saved_sp));
	__asm__ volatile("jr %0" :: "r" (saved_pc));
}

void sprav_perror(const char *s)
{
#if defined(CONFIG_SPRAV_PRAC_ONLY)
	printk("[!] perror(): %s\n", s);
#endif
}

FILE *fopen(const char *pathname, const char *mode)
{
	return NULL;
}

int fclose(FILE *stream)
{
	return 0;
}

int ferror(FILE *stream)
{
	return 0;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	return 0;
}

#pragma GCC push_options
#pragma GCC optimize ("O0")
#define STORE_WORD_IMMEDIATE(dst, word) \
	__asm__ volatile("sw %1, 0(%0)" : : "r" (dst), "r" (word));

/**
 * @brief Load the attestation key into memory using immediate values
 */
static ALWAYS_INLINE void sprav_load_attestation_key()
{

{LOAD_ATTESTATION_KEY_PLACEHOLDER}

}

/**
 * @brief Zeroes out the attestation key in memory
 */
static void sprav_zero_attestation_key()
{
	for (size_t i = 0; i < ATTESTATION_KEY_SIZE; i++) {
		sprav_attestation_key[i] = 0x00;
	}
}

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint32_t nonce,
				  uint8_t *signature)
{
	size_t sig_len = 0;
	uint8_t msg[MSG_SIZE] = {0};
	uint32_t *nonce_ptr = (uint32_t *) (msg + SHA_256_DIGEST_SIZE);
	OQS_STATUS ret = 0;

	uint8_t sprav_attestation_key_local[ATTESTATION_KEY_SIZE];
	sprav_attestation_key = (uint8_t *) &sprav_attestation_key_local;

	/* Configure RNG for liboqs */
	OQS_randombytes_custom_algorithm(sprav_csrand);

	/* Load attestation key temporarily */
	sprav_load_attestation_key(sprav_attestation_key);

	/* Compute Hash over requested region and add nonce */
	OQS_SHA3_sha3_256(msg, (uint8_t *) addr, size);
	*nonce_ptr = nonce;

	/* Save sp and pc to catch exit() from liboqs */
	/* recovery point for exit() */
	liboqs_exit_flag = false;
	__asm__ volatile("mv %0, sp" : "=r"(saved_sp));
	__asm__ volatile("sprav_exit_catch: la %0, sprav_exit_catch" : "=r" (saved_pc));

	if (liboqs_exit_flag) {
		ret = -EFAULT;
		goto cleanup;
	}

	/* Compute Signature over hash & nonce */
	ret = OQS_SIG_dilithium_2_sign(signature, &sig_len, msg, MSG_SIZE,
				       sprav_attestation_key);

cleanup:
	/* Zero out temporary attestation key */
	sprav_zero_attestation_key(sprav_attestation_key);
	sprav_attestation_key = NULL;

	/* Zero out used stack */
	__asm__ volatile("mv %0, sp" : "=r"(saved_sp));
	uint8_t *stack_ptr = (uint8_t *) z_main_stack;
	for (;stack_ptr != (uint8_t *) saved_sp; stack_ptr++) {
		*stack_ptr = 0x00;
	}

	/* Zero out temporary and argument registers */
	__asm__ volatile (
		"mv t0, x0\n"
		"mv t1, x0\n"
		"mv t2, x0\n"
		"mv t3, x0\n"
		"mv t4, x0\n"
		"mv t5, x0\n"
		"mv t6, x0\n"
		"mv a0, x0\n"
		"mv a1, x0\n"
		"mv a2, x0\n"
		"mv a3, x0\n"
		"mv a4, x0\n"
		"mv a5, x0\n"
		"mv a6, x0\n"
		"mv a7, x0\n"
		);

	return ret;
}

#pragma GCC pop_options
