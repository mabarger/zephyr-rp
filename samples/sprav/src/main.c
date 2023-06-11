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

#define SHOW_PMP 0
#define PMP_REGIONS 4

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/device.h>
#include <zephyr/drivers/sprav.h>
#include <zephyr/drivers/uart.h>
#if (SHOW_PMP == 1)
#include <zephyr/drivers/pmp.h>
#endif

#include <string.h>

#if !defined(CONFIG_SPRAV_PRAC_ONLY)
struct __attribute__((packed)) attest_request {
	char     magic[5];
	uint32_t addr;
	uint32_t size;
	uint32_t nonce;
	char     end;
};

struct __attribute__((packed)) attest_response {
	char     magic[5];
	bool     success;
	uint8_t  signature[SPRAV_SIG_SIZE];
};

#define UART_DEVICE_NODE DT_CHOSEN(zephyr_shell_uart)
static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

/* Reads nbytes bytes from uart via polling and stores them in buf */
void uart_recv_bytes(uint8_t *buf, size_t nbytes) {
	size_t buf_pos = 0;
	char curr_char = 0x00;
	int status = -1;

	while(buf_pos != nbytes) {
		status = uart_poll_in(uart_dev, &curr_char);

		if (status == 0) {
			buf[buf_pos] = curr_char;
			buf_pos++;
		}
	}
}

/* Sends nbytes bytes from buf via uart */
void uart_send_bytes(uint8_t *buf, size_t nbytes) {
	size_t buf_pos = 0;

	for(size_t buf_pos = 0; buf_pos < nbytes; buf_pos++) {
		uart_poll_out(uart_dev, buf[buf_pos]);
	}
}
#endif

void attestation_agent() {
	int ret = 0;
#if !defined(CONFIG_SPRAV_PRAC_ONLY)
	struct attest_request req = {0};
	struct attest_response resp = {{'s', 'p', 'r', 'a', 'v'}};

	/* Wait for attestation request */
	while (memcmp(req.magic, "sprav", 5) != 0) {
		uart_recv_bytes((uint8_t *) &req, sizeof(struct attest_request));
	}
#else
	uint8_t signature[SPRAV_SIG_SIZE];
#endif

	/* Attest requested region with requested nonce */
#if !defined(CONFIG_SPRAV_PRAC_ONLY)
	ret = sprav_attest_region(req.addr, req.size, req.nonce, resp.signature);
	resp.success = (ret == 0);
	uart_send_bytes((uint8_t *) &resp, sizeof(struct attest_response));
#else
	ret = sprav_attest_region(0x40380000, 0x2000, 0x12345678, signature);
	printk("[~] sprav_attest_region: %s\n", ret ? "failure" : "success");
	if (ret == 0) {
		printk("[~] Signature:\n");
		for (size_t i = 0; i < SPRAV_SIG_SIZE; i++) {
			printk("%02x", signature[i]);
		}
		printk("\n");
	}
#endif

	return;
}

int main(void)
{
#if (SHOW_PMP == 1)
	struct pmp_config cfg[PMP_MAX_REGIONS];
	memset(cfg, 0, sizeof(struct pmp_config) * PMP_MAX_REGIONS);

	for (int i = 0; i < PMP_REGIONS; i++) {
		pmp_get_config(&cfg[i], i);
	}

	for (int i = 0; i < PMP_REGIONS; i++) {
		printk("PMP %2d: @ 0x%08x | Size: 0x%08x B | ", i, cfg[i].base, cfg[i].size);
		printk("Active: %c | Locked: %c | ", cfg[i].active ? 'T' : 'F', cfg[i].locked ? 'T' : 'F');
		printk("Permissions: >%c%c%c<\n", cfg[i].perm & PMP_R ? 'r' : ' ', cfg[i].perm & PMP_W ? 'w' : ' ', cfg[i].perm & PMP_X ? 'x' : ' ');
	}
#endif

	while (true) {
		attestation_agent();
#if defined(CONFIG_SPRAV_PRAC_ONLY)
		break;
#endif
	}

	return 0;
}
