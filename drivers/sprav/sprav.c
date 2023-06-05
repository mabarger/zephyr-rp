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

/* TODO: ifdef for ecdsa
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dsa.h>
*/

#include <oqs/oqs.h>

#define SHA3_256_DIGEST_SIZE (32)
#define MSG_SIZE (SHA3_256_DIGEST_SIZE + sizeof(uint64_t))

int liboqs_errno = 0;
int __errno_location = (int)&liboqs_errno;

/* Wrappers for liboqs library calls */
void *__memcpy_chk(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}

void sprav_exit(int status)
{
	/* TODO: Use long jump to return to syscall and return error */
	printk("exit()\n");
	return;
}

void sprav_perror(const char *s)
{
	printk("perror(): %s\n", s);
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

/* Start and End locations for the prac section */
extern uint8_t *prac_begin;
extern uint8_t *prac_end;

// TODO: ifdef for ecdsa
//#define ATTESTATION_KEY_SIZE NUM_ECC_BYTES
#define ATTESTATION_KEY_SIZE OQS_SIG_dilithium_2_length_secret_key

#pragma GCC push_options
#pragma GCC optimize ("O0")
#define STORE_WORD_IMMEDIATE(dst, word) \
	__asm__ volatile("sw %1, 0(%0)" : : "r" (dst), "r" (word));

/**
 * @brief Load the attestation key into memory using immediate values
 *
 * @param[in] sprav_attestation_key destination address
 */
static void sprav_load_attestation_key(uint8_t *sprav_attestation_key)
{
	/* ECDSA
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00, 0xf38389e1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04, 0x312cc644);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08, 0x00f52ebb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0C, 0x105b5ad3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x10, 0x02013857);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x14, 0xa33ce423);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x18, 0x6c150d4f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x1C, 0x24330e58);
	*/

	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0000, 0x16e86ad4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0004, 0x24d4a71d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0008, 0x0f05cbf3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x000c, 0x5b05a154);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0010, 0x7006e025);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0014, 0x730e52ad);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0018, 0xd0d086da);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x001c, 0x64387b6a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0020, 0xb6572069);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0024, 0x747ce2a1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0028, 0xf476df52);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x002c, 0x7c5f6152);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0030, 0xb5132018);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0034, 0x289759f4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0038, 0x5a3a71b2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x003c, 0x7943fea0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0040, 0xa0fd228b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0044, 0x2a3c9444);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0048, 0x5e0d8614);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x004c, 0x7a99674d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0050, 0x3f70c8d1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0054, 0x5059d8f6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0058, 0xe9cccf6f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x005c, 0x3945bc55);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0060, 0x082c14a2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0064, 0xb8e32948);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0068, 0x69b4dc41);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x006c, 0x50822424);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0070, 0x051830c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0074, 0x48928960);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0078, 0x096504d1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x007c, 0x01030ca3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0080, 0x50b64a25);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0084, 0x04401904);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0088, 0x15185131);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x008c, 0x1092e22e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0090, 0x58304444);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0094, 0x329c3116);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0098, 0x42340b04);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x009c, 0x040200e0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a0, 0xb4012825);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a4, 0x8e100085);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a8, 0x2349b90c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00ac, 0x11090927);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b0, 0x20b00b29);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b4, 0x906544a3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b8, 0x96902932);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00bc, 0x84301250);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c0, 0x5a09b909);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c4, 0xc11c8524);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c8, 0x4992a32d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00cc, 0x414c10dc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d0, 0x121b4d10);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d4, 0x29881208);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d8, 0x182986c9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00dc, 0x844c4401);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e0, 0x04865265);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e4, 0x24264413);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e8, 0x242308c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00ec, 0x85370086);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f0, 0x04813490);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f4, 0x20516937);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f8, 0x84345c2c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00fc, 0x5165c44a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0100, 0x421b1036);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0104, 0x6c248980);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0108, 0x10909280);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x010c, 0x94138cc5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0110, 0x92111181);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0114, 0xd82998c1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0118, 0x26236118);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x011c, 0x8246db6e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0120, 0x03491620);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0124, 0x86a26118);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0128, 0x8c000160);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x012c, 0xc0219650);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0130, 0x00c909a0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0134, 0x0a40892a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0138, 0x0c644204);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x013c, 0x83045006);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0140, 0x2d42032c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0144, 0x43211284);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0148, 0x24e30cc4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x014c, 0x1046400d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0150, 0xa1014419);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0154, 0x32da0d80);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0158, 0x04c8082d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x015c, 0x042616c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0160, 0xb05b49b7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0164, 0x0620638d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0168, 0x8c70c4c3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x016c, 0x160a2c24);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0170, 0x71105a85);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0174, 0x09664658);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0178, 0x24030e17);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x017c, 0x20c71345);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0180, 0x2391b902);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0184, 0x20008245);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0188, 0x01c0848e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x018c, 0x40882863);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0190, 0xb10a0910);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0194, 0x84968228);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0198, 0x822d1402);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x019c, 0xa0a460c2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a0, 0x04341044);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a4, 0x8451820b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a8, 0x34e38c82);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01ac, 0x10c30449);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b0, 0x4b909653);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b4, 0x391a40c4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b8, 0x89029b52);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01bc, 0xe128a111);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c0, 0x32e25044);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c4, 0x40300c69);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c8, 0xa348189c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01cc, 0x40c24018);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d0, 0x31b26171);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d4, 0xa268a44a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d8, 0x48180242);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01dc, 0x29b30a06);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e0, 0x19111521);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e4, 0x00a14818);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e8, 0x40a48865);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01ec, 0x882424d0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f0, 0x281888a0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f4, 0x51c44c61);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f8, 0x206a16c8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01fc, 0xb9112845);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0200, 0x2a131c50);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0204, 0x089222c1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0208, 0x32934637);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x020c, 0x91249c80);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0210, 0xa46c151c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0214, 0xc28a0148);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0218, 0x68424329);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x021c, 0x64812103);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0220, 0x485b6e32);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0224, 0x28a65011);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0228, 0xd3694281);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x022c, 0xc1232224);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0230, 0x92030189);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0234, 0x4b4400c8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0238, 0xb6030dc8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x023c, 0x09a45989);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0240, 0xdb6822c9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0244, 0xc0840120);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0248, 0x81441948);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x024c, 0xa312240b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0250, 0x47218a30);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0254, 0x05085085);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0258, 0x1209a881);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x025c, 0xc65251b7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0260, 0x65440349);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0264, 0x63241494);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0268, 0xc61b8622);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x026c, 0x89312471);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0270, 0x122a4083);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0274, 0x47230024);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0278, 0x2014d409);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x027c, 0x1040931a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0280, 0x92c48a41);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0284, 0x2098e280);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0288, 0x5c01c2a3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x028c, 0x22d80c08);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0290, 0x51401012);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0294, 0x6464b511);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0298, 0x15140d82);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x029c, 0x4022188c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a0, 0x60093083);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a4, 0x46580e20);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a8, 0x2584d081);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02ac, 0x1321c684);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b0, 0x02d14231);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b4, 0x50b88a8c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b8, 0x880e3060);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02bc, 0x360c8112);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c0, 0x20411989);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c4, 0x1321c0d1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c8, 0x34cb84c8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02cc, 0x31011a81);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d0, 0x020dc50c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d4, 0x49182998);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d8, 0x60026006);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02dc, 0x010dc254);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e0, 0x945b9244);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e4, 0x2130418d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e8, 0x5b502414);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02ec, 0xc41a4432);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f0, 0x92061a45);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f4, 0x9a104400);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f8, 0x308200c4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02fc, 0x40001220);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0300, 0x48822523);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0304, 0x26c90546);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0308, 0x0028e252);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x030c, 0xc0882249);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0310, 0x832048b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0314, 0x4492086c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0318, 0x102d8724);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x031c, 0x48a16230);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0320, 0x2c20018d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0324, 0x19482709);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0328, 0x15014da4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x032c, 0x0d02db8a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0330, 0xc844930a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0334, 0x13038634);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0338, 0x4222414c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x033c, 0x896c1312);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0340, 0x94446934);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0344, 0x05865911);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0348, 0x4b6e3201);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x034c, 0x13139016);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0350, 0x40930062);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0354, 0xc2684013);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0358, 0x36834908);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x035c, 0x0902e320);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0360, 0x3dd865b1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0364, 0xe2a076a0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0368, 0x5245c721);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x036c, 0x24ecd7ec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0370, 0x1ea3dc12);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0374, 0xb0295ff0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0378, 0x4522545d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x037c, 0xc1036f53);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0380, 0x80d274ff);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0384, 0x1d4c88b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0388, 0x79c06367);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x038c, 0xeba1d4c7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0390, 0x20ff68e5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0394, 0x57726ff8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0398, 0x9e6f6400);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x039c, 0x184dd097);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a0, 0x63cec224);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a4, 0x0c9649f2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a8, 0xc798dbae);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03ac, 0x80ccc50d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b0, 0x90309fe0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b4, 0x4a26171c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b8, 0xcce69c3a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03bc, 0xc702d68f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c0, 0x1a3111df);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c4, 0x1a7d5882);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c8, 0x9cb6fccd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03cc, 0x80e08378);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d0, 0x65666115);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d4, 0xbc69ea84);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d8, 0xcac71b65);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03dc, 0x74836fec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e0, 0x9e89f731);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e4, 0xf21003c7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e8, 0x922378fa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03ec, 0xb4d77ca3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f0, 0x91dca046);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f4, 0x808ac36b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f8, 0x2e269e8c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03fc, 0x63d1ded9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0400, 0x88590674);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0404, 0x70077eee);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0408, 0x7f2e66ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x040c, 0xd86f8b4b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0410, 0x972c783f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0414, 0x4d987ba4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0418, 0xc88033f4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x041c, 0x4d667ea6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0420, 0x19e3270f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0424, 0x30b5445a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0428, 0x17ce2469);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x042c, 0x73367b84);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0430, 0x0b03fb23);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0434, 0x79084db7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0438, 0x892bfacb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x043c, 0x7f6afdc7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0440, 0x8d12b6d5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0444, 0x80dcc3fa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0448, 0x2fc776ff);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x044c, 0x7a0a9bc1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0450, 0x5f989449);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0454, 0xbbf722ef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0458, 0x24603707);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x045c, 0x2ec6c798);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0460, 0x51837c25);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0464, 0x907db6e3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0468, 0x2d0b001a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x046c, 0x1222e19f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0470, 0x7f124880);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0474, 0xa5a0156b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0478, 0x5a3fb929);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x047c, 0x2b3e3311);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0480, 0x56f635aa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0484, 0xe749ddef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0488, 0xa5a0f73f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x048c, 0xfab27feb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0490, 0x686aeb0f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0494, 0xafa7a16b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0498, 0xcb156816);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x049c, 0x90125fd1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a0, 0x5d593edd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a4, 0x12705747);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a8, 0x6614236f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04ac, 0x3418129a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b0, 0xe2e0d2cb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b4, 0x5b88ba4e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b8, 0x0219f0e9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04bc, 0xe01b6b4d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c0, 0x7844ce48);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c4, 0x2b92c28d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c8, 0xbdcea30e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04cc, 0xace39e5d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d0, 0x525e8fd1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d4, 0x9b5cc0bf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d8, 0x0ef42baa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04dc, 0x4880d47d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e0, 0x830a76ca);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e4, 0x9d479f8d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e8, 0xcdb7d699);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04ec, 0x3892d160);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f0, 0xef304d46);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f4, 0x929a23bb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f8, 0xad512426);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04fc, 0xc36ce63d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0500, 0x4e54cc36);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0504, 0x8f65ff50);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0508, 0x63c4c064);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x050c, 0xcaa395f1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0510, 0x3698c7dc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0514, 0x6f0b1b88);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0518, 0x64c452d8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x051c, 0xb20e35f5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0520, 0x50e92919);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0524, 0xf987f663);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0528, 0xb0f39192);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x052c, 0x4c35ab57);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0530, 0xbd648650);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0534, 0xa4aa9134);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0538, 0xeee647d7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x053c, 0x7e3f1bd8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0540, 0xe93a9d15);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0544, 0x65c931c3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0548, 0xdf065542);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x054c, 0x9a8b3538);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0550, 0x8d27e46f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0554, 0xf3119176);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0558, 0xea7492dc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x055c, 0x4cd2c580);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0560, 0x083e5b46);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0564, 0xc7a8fae0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0568, 0xf34e2265);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x056c, 0x2beadcba);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0570, 0x9a7d14f9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0574, 0x08d239d7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0578, 0xa9ac0487);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x057c, 0x9874e8ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0580, 0x525fd647);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0584, 0x2dc4d70b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0588, 0x0db16e8b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x058c, 0x0413afde);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0590, 0x878a97b5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0594, 0x535648f3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0598, 0xb5718395);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x059c, 0x314ddffb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a0, 0x29fc1421);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a4, 0xe77d2fe4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a8, 0x37d57ef4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05ac, 0x870d1a24);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b0, 0x10d9e3e0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b4, 0xd4177de7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b8, 0x675d5ebf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05bc, 0xba88bb03);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c0, 0x3a6edd75);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c4, 0x9ec84569);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c8, 0x70dbf3a1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05cc, 0x719ebc1c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d0, 0xd643c6fa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d4, 0xec5a9475);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d8, 0x8d0c7050);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05dc, 0xecfe64a2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e0, 0x1b280612);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e4, 0x35aa6988);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e8, 0xac6403ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05ec, 0x7a33c250);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f0, 0x54db39a5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f4, 0x3c0d2064);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f8, 0x39025f91);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05fc, 0xfc487b14);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0600, 0xf9d29823);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0604, 0x0c7f1fbe);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0608, 0x5628540b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x060c, 0x80ae075a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0610, 0xd4d2d90a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0614, 0x876f16be);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0618, 0xad3875c2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x061c, 0xcc12b5fd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0620, 0x43d091f6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0624, 0x981cfa61);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0628, 0x5af9d78a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x062c, 0xa60f659f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0630, 0x0ed8f984);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0634, 0xc6b56159);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0638, 0xb35409b3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x063c, 0xd5a8686d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0640, 0xba757ba4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0644, 0xf805cbea);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0648, 0x05f2dac1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x064c, 0x5a414fd6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0650, 0xe6e68065);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0654, 0x4544f390);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0658, 0xde41c12f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x065c, 0xb49969e7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0660, 0x1e0d44c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0664, 0x4188ce4e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0668, 0x79cfc9dc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x066c, 0x1ff97905);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0670, 0x544c5180);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0674, 0xbae28477);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0678, 0x997de769);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x067c, 0x7cedbaa9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0680, 0x8510e560);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0684, 0xde3cc3f3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0688, 0xc2277d8b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x068c, 0x94aca0ef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0690, 0xe679c1db);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0694, 0x1da25419);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0698, 0xf34b5c4a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x069c, 0x53c96bd0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a0, 0x6b3a75f4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a4, 0x12bd8174);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a8, 0x3757b9d9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06ac, 0xacd17dd9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b0, 0xbfed9dda);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b4, 0xd18a0237);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b8, 0xd56062e3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06bc, 0x495f234d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c0, 0xcf5a75b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c4, 0x39defede);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c8, 0x260f3897);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06cc, 0x31ba44a8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d0, 0x05b85b0c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d4, 0x795b4b6b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d8, 0xf2ee077f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06dc, 0x884eb8de);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e0, 0xae668df9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e4, 0xadd35b7f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e8, 0x0d7c5df5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06ec, 0x1cacb217);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f0, 0xdec3c370);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f4, 0xd3269ace);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f8, 0x6a2827aa);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06fc, 0xe3c865bd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0700, 0xe7a442d4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0704, 0x0da6ac91);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0708, 0xa50b8d0f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x070c, 0xbaf6bf15);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0710, 0x259ebf0a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0714, 0xb1726a0e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0718, 0x3c969573);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x071c, 0x2fd0363b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0720, 0x3a690e87);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0724, 0xaf348250);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0728, 0x0f238478);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x072c, 0x0ecf1f8d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0730, 0xcc33955d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0734, 0x21e1a6cf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0738, 0x0ce4dd2b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x073c, 0x531cfb9b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0740, 0xfa9cf12c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0744, 0x03026f59);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0748, 0xdab3df79);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x074c, 0x0661cd7e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0750, 0x07581c02);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0754, 0x5808b4f8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0758, 0x6dd32e23);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x075c, 0xbf719327);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0760, 0x9504551f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0764, 0xcff66e6d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0768, 0x268d9878);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x076c, 0x3cadd7d8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0770, 0x192022db);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0774, 0x456e196e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0778, 0x85f59075);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x077c, 0x7033ae5f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0780, 0x4807a65d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0784, 0x6d24ecfc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0788, 0xdd057eb9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x078c, 0xe6fa0014);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0790, 0x4840fdef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0794, 0x1357c984);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0798, 0x4a22a8b7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x079c, 0xfad51122);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a0, 0xed108780);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a4, 0xd477e939);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a8, 0xadd69972);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07ac, 0xf4213e95);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b0, 0xfa4c4b97);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b4, 0xd2138b28);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b8, 0xc005e236);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07bc, 0x73748456);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c0, 0xb5d593a8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c4, 0xe9bdd9d9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c8, 0x90a0d7e7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07cc, 0x009b60ae);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d0, 0x88c88347);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d4, 0x6711702f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d8, 0xa9e9590c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07dc, 0x7a44f3df);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e0, 0xdf8d0da5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e4, 0x5ecf31ab);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e8, 0x0f4280f6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07ec, 0x2a32e4dd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f0, 0xe0ea76e2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f4, 0xf84c0997);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f8, 0x679c5d84);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07fc, 0xf73052fd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0800, 0x86039385);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0804, 0x77e21a83);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0808, 0x87925a1f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x080c, 0x5c8f4405);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0810, 0xb625c55a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0814, 0xd9e6f757);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0818, 0x47235872);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x081c, 0xb4694b9c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0820, 0x0bb2f631);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0824, 0xa0726714);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0828, 0x95744d52);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x082c, 0x08ba1e97);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0830, 0xc1f40b43);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0834, 0xa85522e0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0838, 0xc3f65d3f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x083c, 0x0d7bf113);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0840, 0xdeec63fd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0844, 0xc4b97b6a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0848, 0x5eceb2eb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x084c, 0x40a632b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0850, 0x17abaa52);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0854, 0x1cb0489d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0858, 0x2f2d882f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x085c, 0x1211e392);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0860, 0x06eb5381);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0864, 0x9cfe8cfc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0868, 0x209d1ff4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x086c, 0x68f26508);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0870, 0xa1323de4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0874, 0x8a8095b6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0878, 0x4651e212);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x087c, 0x22d4f65d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0880, 0xda272749);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0884, 0x82f753d7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0888, 0x7f216ef0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x088c, 0xcbee2fda);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0890, 0x18a4102d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0894, 0x219251b6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0898, 0xc4bba19d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x089c, 0x86f02d59);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a0, 0x1edba770);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a4, 0x1944f581);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a8, 0x721bbd64);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08ac, 0x2413ef77);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b0, 0xd4453b42);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b4, 0xd80ef404);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b8, 0x557e2125);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08bc, 0x0b02490a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c0, 0x1bc53c9b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c4, 0xfb634d78);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c8, 0x97837dab);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08cc, 0xbac1690b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d0, 0x0e573190);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d4, 0x2b6af144);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d8, 0xce8f3903);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08dc, 0x881faa4a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e0, 0x20dad3ab);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e4, 0x2fd2c047);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e8, 0x67d131a6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08ec, 0xb974bb6d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f0, 0x9fc27943);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f4, 0xd83035fc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f8, 0xd5c05322);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08fc, 0xb0815bd8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0900, 0x89e34342);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0904, 0x3df73463);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0908, 0x127064dd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x090c, 0xf7e28153);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0910, 0xd46d3260);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0914, 0x7b2bc447);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0918, 0x549d9608);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x091c, 0xff8ff8c2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0920, 0x01e85d7b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0924, 0x95b660b9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0928, 0xab6ec53b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x092c, 0xe4516167);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0930, 0x603c8097);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0934, 0x96d5b639);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0938, 0x26f5be04);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x093c, 0xc3c52d81);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0940, 0xbff12bc9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0944, 0xb0d2a2b6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0948, 0x072e583e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x094c, 0x36222346);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0950, 0xbda1eff6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0954, 0x165ab218);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0958, 0xcc579bcd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x095c, 0xd7529395);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0960, 0x9f54b733);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0964, 0x75dc2a77);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0968, 0x1cad44e5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x096c, 0x22e38aed);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0970, 0x50e6d6ea);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0974, 0x559e3817);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0978, 0xafbaa53d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x097c, 0x4ffeb283);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0980, 0x60b52657);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0984, 0x20b9bb15);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0988, 0x35f142cd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x098c, 0xad3ebb86);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0990, 0xfa6e5db8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0994, 0x01f49614);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0998, 0xa937f57b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x099c, 0xafdd8c3a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a0, 0x2fda90ed);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a4, 0xafaa0128);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a8, 0xa92870d3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09ac, 0x1e9a986f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b0, 0x479ba405);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b4, 0xe80ab7c6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b8, 0x3b4066d3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09bc, 0x0bc92023);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c0, 0x22b5fb1b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c4, 0x146a60f2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c8, 0x42e637cd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09cc, 0x681657f5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d0, 0x2e2be5b9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d4, 0x47a9aa16);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d8, 0xb309f76e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09dc, 0xf06418c4);
}

/**
 * @brief Zeroes out the attestation key in memory
 *
 * @param[in] sprav_attestation_key address to zero out
 */
static void sprav_zero_attestation_key(uint8_t *sprav_attestation_key)
{
	for (size_t i = 0; i < ATTESTATION_KEY_SIZE; i++) {
		sprav_attestation_key[i] = 0x00;
	}
}

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
				  uint8_t *signature)
{
	OQS_STATUS ret = 0;
	size_t sig_len = 0;
	uint8_t msg[MSG_SIZE] = {0};
	uint64_t *nonce_ptr = (uint64_t *) (msg + SHA3_256_DIGEST_SIZE);
	// TODO: add ifdef for ECDSA
	//const struct uECC_Curve_t *curve = uECC_secp256r1();
	// int ret;
	uint8_t public_key[] = {0xd4, 0x6a, 0xe8, 0x16, 0x1d, 0xa7, 0xd4, 0x24, 0xf3, 0xcb, 0x05, 0x0f, 0x54, 0xa1, 0x05, 0x5b, 0x25, 0xe0, 0x06, 0x70, 0xad, 0x52, 0x0e, 0x73, 0xda, 0x86, 0xd0, 0xd0, 0x6a, 0x7b, 0x38, 0x64, 0x49, 0x86, 0x26, 0xa2, 0xff, 0xd7, 0xd6, 0xcd, 0xcd, 0xc4, 0x36, 0xae, 0x63, 0xa0, 0x27, 0xe1, 0x14, 0x55, 0x81, 0x39, 0x29, 0x10, 0x21, 0xd7, 0xef, 0x43, 0x3d, 0x11, 0xaa, 0x9e, 0xa6, 0x42, 0xee, 0x6a, 0x26, 0xf8, 0x01, 0xf3, 0x82, 0x2c, 0xfa, 0xdf, 0x49, 0x0f, 0xf8, 0x1c, 0xd9, 0xe6, 0xe7, 0xd5, 0xcc, 0x48, 0x20, 0x5f, 0x9e, 0xdf, 0xf2, 0x8d, 0xe9, 0xaa, 0x40, 0x55, 0x31, 0xa6, 0xf4, 0x97, 0x22, 0x51, 0x7b, 0xc9, 0x6b, 0x16, 0x2b, 0x66, 0x13, 0x72, 0x07, 0x61, 0xa7, 0x02, 0x2e, 0x8f, 0x54, 0xa3, 0xba, 0xc8, 0xfb, 0xb2, 0x7a, 0x8a, 0x23, 0x2e, 0xb5, 0x41, 0x12, 0x3a, 0xc6, 0x3f, 0x93, 0x56, 0x7e, 0x3e, 0x29, 0x0c, 0xcd, 0xca, 0x64, 0xbf, 0x57, 0xf4, 0x01, 0xab, 0xdf, 0x2b, 0x37, 0xba, 0x08, 0x9f, 0x0f, 0x60, 0x13, 0x2c, 0x39, 0x94, 0x39, 0xc9, 0xab, 0xa3, 0x31, 0x9a, 0x8a, 0x85, 0x3f, 0xa5, 0x4a, 0x62, 0x5e, 0x75, 0xe6, 0x8a, 0x3d, 0x4a, 0x77, 0x6e, 0x4a, 0x4d, 0x20, 0x0a, 0xab, 0x8b, 0xdb, 0xa8, 0xc1, 0xbc, 0x65, 0xfb, 0xcd, 0xa3, 0x10, 0x10, 0x42, 0x49, 0xb6, 0x71, 0x83, 0xe5, 0xc6, 0x8b, 0x88, 0x26, 0xd7, 0xe0, 0x6a, 0xcf, 0xed, 0xba, 0xd1, 0xee, 0xcd, 0x67, 0x5f, 0x61, 0x48, 0xcc, 0x84, 0xe4, 0xf8, 0xef, 0xef, 0xfb, 0x93, 0x62, 0x07, 0x74, 0xb9, 0xc2, 0xef, 0x6f, 0x08, 0x51, 0x72, 0x8b, 0x53, 0x8d, 0x3e, 0x70, 0x3e, 0x87, 0xac, 0x4d, 0x9f, 0x3a, 0xa4, 0xee, 0x82, 0x55, 0x99, 0xf4, 0x3a, 0x1f, 0x66, 0x22, 0xe6, 0x5c, 0x03, 0x7c, 0xf5, 0x5a, 0x37, 0x8f, 0xf5, 0x1c, 0xa9, 0x52, 0x07, 0x40, 0x62, 0x4b, 0xb2, 0x95, 0x08, 0x5c, 0xbb, 0x06, 0xa6, 0x11, 0xc5, 0x4e, 0x1e, 0xb6, 0x21, 0xdb, 0x27, 0x54, 0xbe, 0x44, 0x41, 0x77, 0xb5, 0x9b, 0x60, 0x8f, 0xbd, 0xb9, 0xe9, 0x94, 0xce, 0x6d, 0x68, 0xf2, 0x43, 0xda, 0xea, 0x4b, 0xc2, 0x15, 0x69, 0x63, 0xe6, 0x48, 0xbe, 0x77, 0xdf, 0xd1, 0x74, 0x22, 0xf2, 0x20, 0xfb, 0xdd, 0x3e, 0x14, 0xcb, 0x96, 0x3f, 0xea, 0x25, 0x08, 0x59, 0x96, 0xe4, 0xb3, 0x22, 0x5f, 0x7c, 0xd1, 0xf4, 0xb9, 0x97, 0x52, 0x65, 0xc2, 0x5d, 0x91, 0x8e, 0xbf, 0x04, 0xe7, 0xab, 0x73, 0x99, 0xa6, 0x2e, 0x9a, 0xa2, 0x21, 0xbf, 0xc6, 0x06, 0x8b, 0x33, 0x22, 0x2b, 0xaf, 0x49, 0xeb, 0x14, 0x41, 0x99, 0x9c, 0x31, 0x95, 0x6a, 0x50, 0x41, 0x9f, 0xc4, 0x99, 0x80, 0x08, 0x32, 0xfb, 0xdb, 0x3d, 0x7a, 0x68, 0x89, 0xbd, 0x96, 0x34, 0x73, 0x7a, 0x67, 0x0b, 0xa7, 0xe8, 0xe9, 0xd8, 0x02, 0xc4, 0xeb, 0x28, 0x74, 0x02, 0xb8, 0x5c, 0xd8, 0x23, 0x23, 0x9d, 0x99, 0x09, 0xb4, 0xae, 0xa9, 0x0f, 0xfe, 0x8d, 0xb4, 0xf3, 0x5a, 0x55, 0x00, 0xcb, 0x31, 0x58, 0x5f, 0x39, 0x5b, 0xf2, 0xbe, 0xbd, 0x7d, 0xd1, 0xd3, 0x64, 0x83, 0xac, 0x09, 0x5c, 0x20, 0x45, 0xd9, 0x79, 0xcc, 0xf6, 0x63, 0x3b, 0x72, 0x45, 0xa8, 0x60, 0x3c, 0x94, 0xc5, 0xd7, 0xbe, 0x2a, 0x25, 0xfd, 0xe9, 0xc2, 0x20, 0xaa, 0xe2, 0xdd, 0xf2, 0xf2, 0xb6, 0xe3, 0x15, 0x14, 0x10, 0x96, 0x21, 0x70, 0x1d, 0x5c, 0x5c, 0x63, 0x77, 0x66, 0x7c, 0x8d, 0xfa, 0xd3, 0x2e, 0x6f, 0x82, 0x78, 0xfb, 0x08, 0x17, 0xe7, 0xbf, 0x3a, 0xd6, 0x65, 0x59, 0xf7, 0x46, 0xdb, 0xa7, 0xff, 0x36, 0x28, 0x05, 0xf9, 0x64, 0x8c, 0x40, 0xe2, 0x6c, 0xe1, 0xc7, 0xaa, 0x32, 0xba, 0x09, 0xb2, 0xa7, 0xea, 0xbd, 0xd4, 0x39, 0x27, 0x99, 0x78, 0xec, 0xbf, 0x8a, 0xfc, 0x7a, 0x08, 0xe9, 0xe4, 0x7f, 0x3b, 0x5c, 0x2c, 0x20, 0x1f, 0xb8, 0x37, 0xd6, 0x04, 0xb0, 0xab, 0xd9, 0x4c, 0x10, 0xd8, 0x9a, 0xf4, 0x32, 0x03, 0x07, 0xe7, 0x3f, 0x4c, 0x80, 0xb7, 0xec, 0x4b, 0xb5, 0xa8, 0x4b, 0xa2, 0xbd, 0x98, 0xc2, 0x6f, 0xdf, 0x69, 0x21, 0xe2, 0x54, 0x00, 0xa7, 0x15, 0xd1, 0x73, 0x41, 0x40, 0xb3, 0xa1, 0x9c, 0x04, 0xa4, 0x1f, 0x8d, 0x40, 0x26, 0x32, 0x2d, 0x10, 0x36, 0x77, 0xa4, 0x06, 0xac, 0x2d, 0x90, 0x23, 0x33, 0x9a, 0xa0, 0xcf, 0x70, 0xf8, 0x6b, 0x63, 0x6c, 0x6d, 0x74, 0x35, 0x22, 0x92, 0x1b, 0x6a, 0x34, 0x7f, 0x36, 0x82, 0xd8, 0x38, 0xcd, 0x78, 0x9a, 0xf8, 0x5e, 0x37, 0xfe, 0xcb, 0xe1, 0xf0, 0xb7, 0x94, 0xcd, 0x6b, 0x45, 0x9f, 0x48, 0xa6, 0x13, 0xa7, 0xbb, 0x57, 0x1d, 0x63, 0x85, 0xde, 0x10, 0x6a, 0x87, 0x98, 0x32, 0x33, 0x4a, 0xf9, 0x1f, 0xbc, 0xb1, 0x3c, 0x7e, 0x16, 0xca, 0xf7, 0x92, 0x8c, 0x23, 0x5e, 0x5e, 0xe8, 0xc4, 0x98, 0x01, 0x59, 0x88, 0x34, 0x19, 0xd1, 0xa4, 0x9a, 0x98, 0x36, 0x46, 0x87, 0x54, 0x71, 0xf8, 0x32, 0x7b, 0x49, 0x66, 0x2a, 0x7b, 0xdf, 0x80, 0xd0, 0x04, 0xe2, 0x6d, 0x56, 0x45, 0x07, 0xc1, 0xdb, 0x58, 0xcb, 0xe1, 0xaa, 0x63, 0x02, 0x61, 0x67, 0x1c, 0x75, 0x7d, 0x9b, 0x68, 0xe4, 0xb3, 0x94, 0x36, 0xdb, 0x76, 0x4b, 0x7f, 0x76, 0x54, 0xbe, 0xa5, 0x92, 0x4e, 0xde, 0xee, 0x6b, 0x03, 0x25, 0xf4, 0x31, 0x72, 0xc1, 0xc8, 0xdc, 0xc6, 0x44, 0x76, 0x40, 0x3c, 0x6a, 0x0c, 0x33, 0x76, 0x0a, 0x66, 0xbe, 0x73, 0x66, 0xa1, 0xd6, 0x6e, 0x21, 0xe2, 0xb8, 0x46, 0x7e, 0xcb, 0xe9, 0x66, 0x30, 0x94, 0x96, 0xd1, 0x7e, 0x54, 0x5d, 0x97, 0x6e, 0xf0, 0x1b, 0xa1, 0x24, 0x2d, 0xbd, 0x20, 0x9e, 0x05, 0x78, 0x41, 0x5c, 0xe1, 0x5f, 0xd0, 0xed, 0xfa, 0xb8, 0x56, 0x18, 0x44, 0x8a, 0x0d, 0x7d, 0x2f, 0x75, 0x62, 0x10, 0x68, 0x43, 0xaa, 0xd7, 0xe9, 0x8c, 0x9f, 0xed, 0x98, 0x78, 0x1b, 0x76, 0xfe, 0xae, 0xc7, 0xaa, 0xcc, 0x5e, 0x26, 0x94, 0xea, 0x96, 0x29, 0x54, 0x9c, 0xcf, 0x69, 0xe7, 0xf6, 0x12, 0xe7, 0xed, 0x6d, 0xb2, 0x27, 0xa9, 0x1a, 0xb0, 0xce, 0x3e, 0x6b, 0x00, 0xa8, 0x38, 0xc1, 0xf4, 0x3c, 0x11, 0x44, 0xfe, 0xec, 0x87, 0xe9, 0x8e, 0x8e, 0xbf, 0x6e, 0xc3, 0xac, 0x24, 0x16, 0x34, 0xbb, 0x81, 0xd5, 0x64, 0xc4, 0x28, 0x09, 0x11, 0x8a, 0x5d, 0x84, 0xc0, 0x2c, 0x62, 0xb1, 0xf8, 0x83, 0x0f, 0xeb, 0x38, 0x59, 0x8e, 0x2f, 0xc5, 0xd9, 0xea, 0x1d, 0xe0, 0x5f, 0xb5, 0xf9, 0x77, 0x34, 0xf7, 0x5c, 0x7f, 0xec, 0x4b, 0x0c, 0x82, 0x1c, 0x14, 0x11, 0x8e, 0x44, 0x8b, 0xcd, 0x01, 0x08, 0xb5, 0xd1, 0xf4, 0x57, 0xae, 0x4f, 0x25, 0x9b, 0xe7, 0x6b, 0x80, 0xd3, 0x7e, 0x04, 0xab, 0x94, 0x1a, 0x97, 0xec, 0xb8, 0x80, 0xf1, 0x54, 0x8f, 0x7d, 0x9c, 0xdc, 0x1e, 0x50, 0xd5, 0x70, 0xa4, 0x76, 0xc5, 0x5f, 0xbc, 0xbe, 0x51, 0xd3, 0xfa, 0x17, 0xf1, 0x62, 0x3b, 0xa2, 0x0c, 0x60, 0x44, 0xfb, 0xc5, 0xfb, 0xcf, 0x0c, 0xa6, 0xce, 0x56, 0x22, 0x92, 0xed, 0x33, 0x8c, 0xd9, 0xe6, 0x0f, 0x3d, 0xd7, 0x9f, 0xc1, 0x36, 0x90, 0x20, 0x3c, 0x7f, 0xf6, 0x6e, 0x0e, 0x14, 0x6c, 0x8b, 0x5e, 0xac, 0x0a, 0x5a, 0x8a, 0x2b, 0xd3, 0x3f, 0x65, 0xa5, 0x22, 0x22, 0x4b, 0x7f, 0x7d, 0x3b, 0x7b, 0xaf, 0x42, 0xfc, 0x37, 0x1c, 0x82, 0x76, 0xa3, 0xb6, 0x95, 0x2c, 0x23, 0x70, 0x20, 0xd7, 0xb0, 0xad, 0xd9, 0x53, 0x5f, 0x4f, 0x7d, 0x9c, 0xe1, 0x7c, 0x3a, 0xfb, 0x1c, 0xb9, 0x49, 0x08, 0x1c, 0x30, 0xec, 0x92, 0x47, 0x86, 0xaa, 0x46, 0xd7, 0x82, 0xd2, 0xec, 0x79, 0x41, 0x8b, 0x4d, 0xe1, 0x4b, 0x68, 0x00, 0xd8, 0xc5, 0x8a, 0x41, 0xdd, 0x82, 0xa1, 0x0d, 0x59, 0x39, 0x3d, 0x8d, 0xd1, 0xde, 0xb4, 0xa4, 0xda, 0x49, 0x5c, 0xc6, 0x04, 0x22, 0xa1, 0x68, 0x89, 0xa1, 0x12, 0x62, 0xe9, 0x80, 0x15, 0x58, 0xd7, 0xd9, 0x47, 0x2c, 0x4c, 0x00, 0xd3, 0x11, 0xe3, 0x2a, 0x51, 0x62, 0x5b, 0x44, 0x91, 0x99, 0xc2, 0x22, 0x05, 0xcb, 0xf1, 0xaa, 0xba, 0x79, 0x6d, 0x5f, 0x01, 0xc2, 0xf7, 0xcd, 0x8a, 0xa6, 0xf1, 0xb4, 0x7f, 0x81, 0x95, 0x76, 0x26, 0x81, 0x70, 0x5a, 0x28, 0xd5, 0xd9, 0xdf, 0x9d, 0x3d, 0x18, 0x39, 0x8d, 0x2f, 0x90, 0xbc, 0xbe, 0x4c, 0x23, 0x26, 0x9e, 0x74, 0xc5, 0xd6, 0x13, 0x61, 0xf2, 0xf9, 0x41, 0xf9, 0xe1, 0xd3, 0x56, 0x8f, 0xab, 0x4b, 0xff, 0x25, 0xbb, 0x55, 0x31, 0xb6, 0x52, 0xe8, 0x08, 0x7c, 0xe0, 0x4a, 0xbe, 0x7c, 0x99, 0xed, 0xa9, 0xbb, 0xca, 0x0c, 0xdc, 0x6b, 0x9e, 0xfb, 0x43, 0x9d, 0x53, 0xde, 0xd9, 0x96, 0x5a, 0xd6, 0x1a, 0xad, 0xda, 0x1e, 0x22, 0xbf, 0xb1, 0xca, 0x76, 0x81, 0x1f, 0x07, 0xd6, 0x70, 0xc0, 0xd5, 0x01, 0x3c, 0x5e, 0xee, 0xa9, 0xf0, 0xb0, 0x29, 0x2e, 0x7f, 0xc9, 0xc9, 0xee, 0x1f, 0x5b, 0xe0, 0x23, 0x00, 0x1b, 0x8c, 0xce, 0x9d, 0x59, 0xbf, 0x9a, 0x3e, 0xf3, 0xbd, 0x1e, 0xd7, 0x98, 0x44, 0x33, 0xd7, 0x45, 0x81, 0x2c, 0xd1, 0x68, 0x3c, 0x4b, 0x4e, 0x2d, 0x6a, 0x0f, 0x97, 0xc3, 0xdc, 0x5b, 0x0b, 0x30, 0x92, 0x01, 0x6c, 0x3a, 0x9f, 0x49, 0xe4, 0xde, 0xaf, 0xf2, 0x6f, 0x84, 0xde, 0xa9, 0x40, 0xac, 0x81, 0x25, 0xcc, 0x40, 0x9a, 0xc4, 0xa8, 0xb3, 0xa9, 0x39, 0x85, 0x4b, 0xe5, 0xe4, 0xae, 0x8b, 0xf0, 0x6b, 0x9b, 0x54, 0xfc, 0xf7, 0xd0};

	uint8_t sprav_attestation_key[ATTESTATION_KEY_SIZE];

	/* Configure RNG for liboqs */
	OQS_randombytes_custom_algorithm(sys_csrand_get);

	/* Load attestation key temporarily */
	sprav_load_attestation_key(sprav_attestation_key);

	/* Compute Hash over requested region and add nonce */
	OQS_SHA3_sha3_256(msg, (uint8_t *) addr, size);
	*nonce_ptr = nonce;

	/* Compute Signature over hash & nonce */
	ret = OQS_SIG_dilithium_2_sign(signature, &sig_len, msg, MSG_SIZE,
				       sprav_attestation_key);
	printk("[~] Signature creation: %s\n", ret == OQS_SUCCESS ? "success" : "failed");

	ret = OQS_SIG_dilithium_2_verify(msg, MSG_SIZE, signature, sig_len,
			                 public_key);
	printk("[~] Signature verification: %s\n", ret == OQS_SUCCESS ? "success" : "failed");

	/* Compute Signature over hash & nonce */
	/* TODO: ifdef for cdsa
	ret = uECC_sign_with_k(sprav_attestation_key, hash,
			       TC_SHA256_DIGEST_SIZE,
			       (uECC_word_t *) &nonce, signature, curve);
	*/

	/* Zero out temporary attestation key */
	sprav_zero_attestation_key(sprav_attestation_key);

	return ret ? -EFAULT : 0;
}

#pragma GCC pop_options
