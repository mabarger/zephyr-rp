/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/pmp.h>
#include <zephyr/logging/log.h>

#include <zephyr/toolchain.h>
#include <stddef.h>
#include <stdarg.h>
#include <inttypes.h>

#ifndef CONFIG_PMP_SLOTS
#define CONFIG_PMP_SLOTS PMP_MAX_REGIONS
#endif

static size_t find_lsb_unset(size_t value)
{
	int res = 0;
	if (value == 0) {
		return res;
	}

	while (value & 1) {
		value >>= 1;
		res++;
	}

	return res;
}

size_t int_pow(size_t base, size_t exp) {
	size_t res = 0;

	while (exp--) {
		res *= base;
	}

	return res;
}

static void read_pmp_register(int region_id, size_t *addr, size_t *conf)
{
	switch (region_id) {
	case 0:
		*addr = csr_read(pmpaddr0);
		*conf = csr_read(pmpcfg0);
		break;
	case 1:
		*addr = csr_read(pmpaddr1);
		*conf = csr_read(pmpcfg0);
		break;
	case 2:
		*addr = csr_read(pmpaddr2);
		*conf = csr_read(pmpcfg0);
		break;
	case 3:
		*addr = csr_read(pmpaddr3);
		*conf = csr_read(pmpcfg0);
		break;
	case 4:
		*addr = csr_read(pmpaddr4);
		*conf = csr_read(pmpcfg1);
		break;
	case 5:
		*addr = csr_read(pmpaddr5);
		*conf = csr_read(pmpcfg1);
		break;
	case 6:
		*addr = csr_read(pmpaddr6);
		*conf = csr_read(pmpcfg1);
		break;
	case 7:
		*addr = csr_read(pmpaddr7);
		*conf = csr_read(pmpcfg1);
		break;
	}
}

static void write_pmp_register(int region_id, size_t addr, size_t conf)
{
	switch (region_id) {
	case 0:
		csr_write(pmpaddr0, addr);
		csr_write(pmpcfg0, conf);
		break;
	case 1:
		csr_write(pmpaddr1, addr);
		csr_write(pmpcfg0, conf);
		break;
	case 2:
		csr_write(pmpaddr2, addr);
		csr_write(pmpcfg0, conf);
		break;
	case 3:
		csr_write(pmpaddr3, addr);
		csr_write(pmpcfg0, conf);
		break;
	case 4:
		csr_write(pmpaddr4, addr);
		csr_write(pmpcfg1, conf);
		break;
	case 5:
		csr_write(pmpaddr5, addr);
		csr_write(pmpcfg1, conf);
		break;
	case 6:
		csr_write(pmpaddr6, addr);
		csr_write(pmpcfg1, conf);
		break;
	case 7:
		csr_write(pmpaddr7, addr);
		csr_write(pmpcfg1, conf);
		break;
	}
}

static void parse_pmp_register(struct pmp_config *pmp_cfg, int region_id)
{
	size_t addr = 0;
	size_t conf = 0;
	size_t prev_addr = 0;
	size_t prev_conf = 0;
	size_t temp = 0;

	/* Read PMP register */
	read_pmp_register(region_id, &addr, &conf);

	/* Parse contents */
	pmp_cfg->active = true;
	conf = (conf >> ((region_id % 4) * 8)) & 0xFF;

	/* Determine address and size of region addrd on A-field */
	switch (conf & PMP_A) {
		case PMP_TOR:
			if (region_id == 0) {
				pmp_cfg->base = 0;
				pmp_cfg->size = addr << 2;
			} else {
				read_pmp_register(region_id - 1, &prev_addr, &prev_conf);
				pmp_cfg->base = prev_addr << 2;
				pmp_cfg->size = (addr << 2) - (prev_addr << 2);
			}
			break;
		case PMP_NA4:
			pmp_cfg->size = 4;
			pmp_cfg->base = addr << 2;
			break;
		case PMP_NAPOT:
			temp = find_lsb_unset(addr);
			pmp_cfg->size = int_pow(2, temp+3);
			pmp_cfg->base = addr & (SIZE_MAX << temp);
			break;
		case 0x00:
			pmp_cfg->base = addr;
			pmp_cfg->size = 0;
			pmp_cfg->active = false;
			break;
	}

	pmp_cfg->perm = conf & (PMP_R | PMP_W | PMP_X);
	pmp_cfg->locked = conf & PMP_L;
}

int z_impl_pmp_get_config(struct pmp_config *pmp_cfg, int region_id)
{
	if (region_id >= CONFIG_PMP_SLOTS && region_id != -1) {
		return -EFAULT;
	}

	if (region_id != -1) {
		parse_pmp_register(&pmp_cfg[0], region_id);
	}

	return 0;
}

int z_impl_pmp_set_config(size_t addr, size_t conf, int region_id)
{
	size_t curr_addr = 0;
	size_t curr_conf = 0;

	if (region_id >= CONFIG_PMP_SLOTS && region_id < 0) {
		return -EFAULT;
	}

	read_pmp_register(region_id, &curr_addr, &curr_conf);
	if ( (curr_conf >> (region_id % 4) * 8) & PMP_L) {
		return -EFAULT;
	}

	curr_conf &= ~(0xf << (region_id % 4) * 8);
	curr_conf |= (conf << (region_id % 4) * 8);

	write_pmp_register(region_id, curr_addr, curr_conf);

	return 0;
}
