/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/sys/util.h>
#include <zephyr/kernel.h>
#include <zephyr/drivers/sprav.h>
#include <zephyr/logging/log.h>

#include <zephyr/toolchain.h>

#include <oqs/oqs.h>

void *__memcpy_chk(void *dest, const void *src, size_t n)
{
	return memcpy(dest, src, n);
}

size_t sprav_heap_size = 128 * 1024;
K_HEAP_DEFINE(sprav_heap, 128 * 1024);
void *sprav_malloc(size_t size)
{
	//printk("Requested size malloc(): %d\n", size);
	if ((sprav_heap_size - size) < 0) {
		printk("OOM\n");
	}
	sprav_heap_size -= size;
	return k_heap_alloc(&sprav_heap, size, K_FOREVER);
}

void sprav_free(void *ptr)
{
	//printk("Requested ptr in free(): 0x%08x\n", ptr);
	k_heap_free(&sprav_heap, ptr);
}

void perror(const char *s) {};
int fclose(FILE *stream) {return 0;};
int fopen(const char *pathname, const char *mode)
{
	printk("fopen(): %s\n", pathname);
	return 0;
};
int ferror(FILE *stream) {return 0;};
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	printk("fread()\n"); return 0;
	return nmemb;
};

int liboqs_errno = 0;
int __errno_location = (int)&liboqs_errno;


/*
#include <tinycrypt/ecc.h>
#include <tinycrypt/ecc_dsa.h>
*/
#include <tinycrypt/constants.h>
#include <tinycrypt/sha256.h>

/* Start and End locations for the prac section */
extern uint8_t *prac_begin;
extern uint8_t *prac_end;

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

	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0000, 0xc216f584);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0004, 0xfa46421b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0008, 0x2056a54b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x000c, 0xef68ce69);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0010, 0xcb36aad4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0014, 0x0da09f8a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0018, 0xd42703e5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x001c, 0x1a9e8281);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0020, 0x341a60ca);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0024, 0xbeaabd81);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0028, 0x97a2943a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x002c, 0xecaf05af);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0030, 0x39203087);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0034, 0xa2947be4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0038, 0xfb32949f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x003c, 0x0337d047);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0040, 0x282c395f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0044, 0x3d6f7b75);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0048, 0x10d7f9e1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x004c, 0xb3629af5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0050, 0x04720e30);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0054, 0x2cd840c2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0058, 0x4c9dc7bf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x005c, 0xd0c26ea5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0060, 0xdc28c8d8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0064, 0x92827224);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0068, 0x0534832d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x006c, 0x0349231c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0070, 0xb00a0925);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0074, 0x65044a00);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0078, 0x814c2811);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x007c, 0xa30b01c4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0080, 0x05b0e125);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0084, 0x986cc481);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0088, 0x40c260b4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x008c, 0x01b6d262);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0090, 0xa200240c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0094, 0x24130d12);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0098, 0x85905b85);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x009c, 0xd866268b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a0, 0x02e42da6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a4, 0x11c4e304);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00a8, 0x1a04c2e4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00ac, 0x30480489);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b0, 0x70c89c20);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b4, 0x04050810);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00b8, 0xc2d08217);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00bc, 0x2602a344);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c0, 0x8c848410);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c4, 0x941a2908);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00c8, 0x6e302269);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00cc, 0x08651840);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d0, 0x24d18632);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d4, 0x30c6210e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00d8, 0x4b681664);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00dc, 0x20d485c4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e0, 0x4426d249);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e4, 0xa3652260);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00e8, 0x05248d18);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00ec, 0x49189264);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f0, 0xca11a413);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f4, 0xb0240012);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00f8, 0x42131c30);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x00fc, 0x9984820b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0100, 0x16100d88);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0104, 0x30266191);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0108, 0x1812204b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x010c, 0x26425186);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0110, 0x29481229);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0114, 0xcb88490c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0118, 0x82e37138);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x011c, 0x64805b49);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0120, 0x988da649);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0124, 0x448265a6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0128, 0x6484c181);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x012c, 0x2141a2d8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0130, 0xc84941b8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0134, 0x02149c29);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0138, 0x0a04440b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x013c, 0xb40c25a0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0140, 0x8a16cb8c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0144, 0x64319498);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0148, 0x82544c12);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x014c, 0x09992261);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0150, 0xd288201a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0154, 0x208289b6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0158, 0x0c165a2a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x015c, 0x1b404924);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0160, 0x46816e47);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0164, 0x60388b2e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0168, 0x5c6626da);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x016c, 0x880c4c38);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0170, 0x9080a130);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0174, 0x0c84c108);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0178, 0xc3233008);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x017c, 0x3188d490);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0180, 0xa0489003);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0184, 0xc2dc6c88);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0188, 0x11985841);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x018c, 0x41223023);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0190, 0x42984d92);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0194, 0x20110a48);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0198, 0x1a92089c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x019c, 0x49104d88);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a0, 0x2ca48a00);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a4, 0x182a2310);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01a8, 0x48d28194);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01ac, 0x11371425);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b0, 0xc22d08c4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b4, 0x329b49c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01b8, 0x9215006d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01bc, 0x086cc252);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c0, 0x24c12832);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c4, 0x31a90b05);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01c8, 0x1310929c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01cc, 0xc08205a3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d0, 0x02344380);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d4, 0x4348980b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01d8, 0x08441248);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01dc, 0x8a32cb8e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e0, 0x24440283);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e4, 0xc6cc50c3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01e8, 0x50240b4c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01ec, 0x0c06085b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f0, 0x10e44d39);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f4, 0x60329962);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01f8, 0xc1882504);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x01fc, 0xa3209138);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0200, 0x0c24d289);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0204, 0x5448c089);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0208, 0x128211a8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x020c, 0x86326225);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0210, 0x1c308519);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0214, 0x28206844);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0218, 0x61a31384);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x021c, 0x12480623);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0220, 0xb4540833);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0224, 0x71b0e025);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0228, 0x8c8a1292);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x022c, 0xc4594982);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0230, 0x26412281);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0234, 0x80898601);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0238, 0x44918cc4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x023c, 0x88429152);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0240, 0x49843063);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0244, 0x36612c92);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0248, 0x2894590a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x024c, 0xcc4930d0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0250, 0x161c0586);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0254, 0x12480b88);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0258, 0x5881c842);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x025c, 0x42820522);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0260, 0x60229a0d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0264, 0x00713084);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0268, 0x28c11222);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x026c, 0x0916da41);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0270, 0x4009a853);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0274, 0xa4082904);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0278, 0x8d30ca2c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x027c, 0x04008284);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0280, 0xb9116413);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0284, 0x69b42330);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0288, 0x19263094);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x028c, 0xb3204988);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0290, 0x4182a244);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0294, 0x63440893);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0298, 0xb2db0224);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x029c, 0x3242e425);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a0, 0x1285a484);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a4, 0x30893219);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02a8, 0x64c28b62);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02ac, 0xe14a0518);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b0, 0x32448646);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b4, 0x51201448);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02b8, 0x6382391b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02bc, 0x94d12628);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c0, 0x40941c68);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c4, 0x23688402);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02c8, 0x31038844);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02cc, 0x29844289);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d0, 0x9305a704);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d4, 0x94c15008);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02d8, 0x08c00844);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02dc, 0x026934c8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e0, 0x049850a6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e4, 0x89311b29);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02e8, 0x1185c21c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02ec, 0x469c0db6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f0, 0x85b91225);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f4, 0x0b894213);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02f8, 0x925c0dc5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x02fc, 0x30244010);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0300, 0x494a0253);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0304, 0x86492d82);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0308, 0x01240351);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x030c, 0x23613112);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0310, 0x45146921);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0314, 0x65420100);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0318, 0x130124a1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x031c, 0x19196902);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0320, 0x32420a46);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0324, 0x1080a4d0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0328, 0x92030e12);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x032c, 0x2998006d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0330, 0x90064460);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0334, 0x46a00606);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0338, 0x06050366);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x033c, 0x102c0801);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0340, 0x38832183);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0344, 0x4400da6e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0348, 0x116c8453);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x034c, 0x48225222);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0350, 0x3242a14e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0354, 0x09613324);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0358, 0xc0239245);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x035c, 0x6594c265);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0360, 0x55ba9aea);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0364, 0x16472f7f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0368, 0x534b2e8e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x036c, 0x2740a6c7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0370, 0xe677ce49);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0374, 0xfab369a5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0378, 0xeb7f9813);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x037c, 0x7e26f5e4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0380, 0xca68e200);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0384, 0xeb537fb9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0388, 0x240c6588);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x038c, 0x9d77b400);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0390, 0xda2090d0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0394, 0xe7cdd008);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0398, 0x92baa8a2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x039c, 0x34a09e8b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a0, 0x54a42a7b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a4, 0x5fa8c133);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03a8, 0xf652c84a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03ac, 0x82a8d84b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b0, 0x5ba4c047);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b4, 0xdb5d1c23);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03b8, 0xc71e7376);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03bc, 0x8ee07551);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c0, 0xa8a4d81a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c4, 0xc15ca564);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03c8, 0xd0166a27);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03cc, 0x41bdd9fc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d0, 0xc04a5000);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d4, 0xc46381ab);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03d8, 0x0003f3ae);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03dc, 0x5a2844ca);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e0, 0xf5af191e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e4, 0xc5d231b7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03e8, 0xc5c08411);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03ec, 0x52a96d3b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f0, 0xcfae4799);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f4, 0x3cffae55);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03f8, 0x65972cbc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x03fc, 0xa78fd4e8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0400, 0x27676156);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0404, 0xd49ef547);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0408, 0x149c0603);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x040c, 0x1d38b90c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0410, 0x0d6a53ac);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0414, 0x1b64ea23);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0418, 0x4c4fa119);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x041c, 0x8ea88dc2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0420, 0xe63d2ab0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0424, 0x99fbca89);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0428, 0x46d36dd3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x042c, 0x1b5b3c6d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0430, 0x73766301);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0434, 0xa9ef72f2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0438, 0x7573765f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x043c, 0xfb2634d2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0440, 0x4402e10f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0444, 0xe34502c0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0448, 0xfa7207f1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x044c, 0x7d0178f2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0450, 0x86732d6d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0454, 0x11191a31);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0458, 0x1620c395);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x045c, 0x8c3a2ea5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0460, 0xacdfb05a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0464, 0x5b3cfe68);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0468, 0x9c365c92);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x046c, 0x89cd2db6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0470, 0xe572d5f3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0474, 0x514ce4e6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0478, 0x1a361103);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x047c, 0xe63d46b3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0480, 0xd3e454c1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0484, 0xf25031d3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0488, 0x191cdcb7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x048c, 0x16a0854d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0490, 0x588bb3de);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0494, 0x5bfc7d59);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0498, 0x24a8c961);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x049c, 0xd313a069);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a0, 0xfcfac551);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a4, 0x4fbac838);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04a8, 0xa6d51a08);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04ac, 0x72282b18);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b0, 0x057a5e56);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b4, 0xcfa71b69);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04b8, 0xe9f67beb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04bc, 0x7ca44e44);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c0, 0xba867d80);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c4, 0x3813bbb1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04c8, 0xab2b7109);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04cc, 0x70ea0e9b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d0, 0x681c78e9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d4, 0x54f8b4eb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04d8, 0x6f176431);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04dc, 0x84106316);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e0, 0xc4dd47b1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e4, 0xf7df4427);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04e8, 0x9befbfed);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04ec, 0x9da35f24);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f0, 0xdd26166f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f4, 0xa2cc86b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04f8, 0x53cdef67);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x04fc, 0xdddf897c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0500, 0x24caf08e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0504, 0x37e13dcd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0508, 0xabc506c1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x050c, 0xf9b8a012);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0510, 0x19dc7497);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0514, 0x29e6477b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0518, 0xc14e88a9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x051c, 0xbe6a8557);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0520, 0xe95a0748);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0524, 0x55d3a9fc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0528, 0xc19f3a08);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x052c, 0x37256fc3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0530, 0x415db3fe);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0534, 0x0742d7f2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0538, 0x8628dd00);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x053c, 0x6c54a3d3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0540, 0x5481f350);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0544, 0x20b499d5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0548, 0xa8a930d5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x054c, 0x083b90b9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0550, 0x3519e95c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0554, 0xa0147511);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0558, 0x609d2a35);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x055c, 0x69a89371);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0560, 0xd0c1b84c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0564, 0xd0da97e9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0568, 0xcc22faee);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x056c, 0x1290f6d6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0570, 0x6819abd6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0574, 0x3d584815);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0578, 0xbefa85d4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x057c, 0xd8d230fe);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0580, 0xfe8bf240);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0584, 0x10b12b02);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0588, 0x5b49ea4f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x058c, 0xa69f764f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0590, 0x9b284632);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0594, 0xb123aec0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0598, 0xc2763751);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x059c, 0x435cbac3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a0, 0x3bb9d6a3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a4, 0xcc7a258f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05a8, 0x5d10b277);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05ac, 0x561350b4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b0, 0x8be5d6b7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b4, 0xe866d749);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05b8, 0x991ce598);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05bc, 0x53e8a5e4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c0, 0xc9277c41);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c4, 0xd80b7b5e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05c8, 0x38e8492a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05cc, 0xabb7e449);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d0, 0x07e7d8d3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d4, 0xfde85ee6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05d8, 0xd762d2bc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05dc, 0x3b7ad6e0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e0, 0xb8c11b49);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e4, 0x68c22e5c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05e8, 0x946ace06);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05ec, 0xf6e5d2bd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f0, 0xd35c40fd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f4, 0xe8bc46b0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05f8, 0xb24679ca);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x05fc, 0xfc388455);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0600, 0xe225929f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0604, 0x6892077e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0608, 0xee74a5ff);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x060c, 0x67bfd2ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0610, 0x67f7d395);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0614, 0x3cf5b9f8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0618, 0xe3fce00e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x061c, 0x5942739a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0620, 0xef74d335);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0624, 0x494b017a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0628, 0x4713ad95);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x062c, 0xa2d90f0c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0630, 0xf3982cac);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0634, 0x479a0bcc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0638, 0xfc1848bc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x063c, 0xd8c1ca56);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0640, 0x517aa040);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0644, 0x919fab64);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0648, 0x21aa9ca7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x064c, 0x451e3bf7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0650, 0x65139f61);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0654, 0xb16ca614);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0658, 0x9c0d85e3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x065c, 0x2edd06cc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0660, 0x838cde45);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0664, 0xe2f1f8e1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0668, 0xa547e50d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x066c, 0xcb928fe2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0670, 0x53e62243);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0674, 0x2355a84c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0678, 0xb0dfc63c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x067c, 0x5b6c79eb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0680, 0xd3031793);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0684, 0x51073380);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0688, 0x51c1cfa7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x068c, 0x456db161);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0690, 0x92b1ea00);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0694, 0xa4e0b043);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0698, 0xc55a940a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x069c, 0x50ee3056);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a0, 0xfe5fd60e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a4, 0x7597417d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06a8, 0xb4f58f36);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06ac, 0x4080683c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b0, 0x09488bfc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b4, 0xe85fe3b2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06b8, 0xd35babb8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06bc, 0x75d9d69b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c0, 0x79828cec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c4, 0x43ec9cee);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06c8, 0xdbd79746);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06cc, 0x310f98ab);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d0, 0xc9241f60);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d4, 0xebcd4d62);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06d8, 0x3fa1ec2f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06dc, 0xc0f49bc6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e0, 0x1d5f5306);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e4, 0x269e6e15);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06e8, 0xfa1ebad4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06ec, 0x83d46970);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f0, 0x87c61620);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f4, 0x089cff95);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06f8, 0xb2479264);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x06fc, 0x27181467);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0700, 0xbe026c5f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0704, 0x38ad2920);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0708, 0x88888a9a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x070c, 0xdf15bf0f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0710, 0x8a56e4d9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0714, 0x8686cb43);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0718, 0xcaaf0c36);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x071c, 0xf8d7d378);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0720, 0x4e1de2d2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0724, 0xa9b16ab6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0728, 0xf9ad9256);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x072c, 0x793950ec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0730, 0xda1ec91d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0734, 0xb4f34f27);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0738, 0x4e75f0ad);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x073c, 0x00628e46);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0740, 0x0f320406);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0744, 0x08be13f3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0748, 0xcac0c6c6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x074c, 0x53b58ac6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0750, 0x7f0e8e9d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0754, 0x3fb29568);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0758, 0x036ab815);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x075c, 0x025a1065);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0760, 0xf42a4752);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0764, 0x9734a4e9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0768, 0x89b80cbc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x076c, 0x5b2607f5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0770, 0xea4e109e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0774, 0xfacda147);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0778, 0xb28dc3ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x077c, 0x93da8513);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0780, 0x1fa6d08a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0784, 0x75afa6c5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0788, 0x9e8bae64);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x078c, 0x063395ad);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0790, 0xad2a598c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0794, 0x3d1f4d95);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0798, 0xcc908ca0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x079c, 0xf8801121);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a0, 0x78712bb7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a4, 0xce02219b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07a8, 0x8de61b07);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07ac, 0xfd7cdd2c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b0, 0xdbb82ce8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b4, 0x5375848a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07b8, 0x551cf351);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07bc, 0x64c53282);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c0, 0x1c806bc8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c4, 0xc05e94a0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07c8, 0xff17470e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07cc, 0xbb90520c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d0, 0x532138a2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d4, 0x3480b8b1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07d8, 0xaeeaa7fc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07dc, 0x67442c6b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e0, 0x9f052cb7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e4, 0x477f4fb3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07e8, 0xa493f9d9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07ec, 0xc7730acf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f0, 0xf3a206a9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f4, 0x8f325ba5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07f8, 0xeeb501c6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x07fc, 0xdea7e47a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0800, 0x02a5a82a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0804, 0xfa8ead07);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0808, 0x50b6fbf9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x080c, 0xd30fbd20);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0810, 0x0bc577ea);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0814, 0xf8dd3731);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0818, 0xfaaf1f57);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x081c, 0xd9d229de);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0820, 0x19b2f2e3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0824, 0x669ebc6f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0828, 0xaaf0faec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x082c, 0xc8ccf7e8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0830, 0xa7fa4f9c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0834, 0xa07facdc);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0838, 0xfbdbeaef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x083c, 0x134688f5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0840, 0x2d5fe64e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0844, 0x21eb6751);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0848, 0xbbf03ece);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x084c, 0xee9c73d6);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0850, 0xd5d07b3f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0854, 0x4e431657);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0858, 0xd6d2848c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x085c, 0xcb91a1c2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0860, 0xea450968);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0864, 0x0feccbca);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0868, 0x91a3a69b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x086c, 0x8efcf17e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0870, 0x88ad9035);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0874, 0x68d4b2bf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0878, 0xd40d4d8f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x087c, 0x3f550046);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0880, 0xc3bdee43);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0884, 0x9210b827);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0888, 0x8b1decec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x088c, 0x79ee73fb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0890, 0x3eebbb75);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0894, 0x3d0db0ef);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0898, 0xee2a5e49);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x089c, 0x565d00ec);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a0, 0xd6b3177d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a4, 0xb4c9191e);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08a8, 0x6da5181a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08ac, 0x5b8e2930);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b0, 0x432bbaf4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b4, 0x265f3a24);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08b8, 0xd573c21d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08bc, 0x9075fa02);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c0, 0x240dbfaf);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c4, 0x5ace794c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08c8, 0x68acbcf4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08cc, 0x82201d33);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d0, 0x046f4282);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d4, 0x6f8dcc43);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08d8, 0x77863c49);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08dc, 0xe57092e7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e0, 0xc91f1957);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e4, 0x46f8f340);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08e8, 0xc7f14ac4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08ec, 0xa9eff165);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f0, 0x961a9421);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f4, 0x7ebdad14);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08f8, 0xcb876788);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x08fc, 0xdc175703);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0900, 0x795f85fe);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0904, 0x9dfeb56c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0908, 0x3502a385);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x090c, 0x17cd4d5c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0910, 0x3d41d6e7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0914, 0x19905380);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0918, 0x550349d5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x091c, 0xa037753a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0920, 0x11941fe2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0924, 0x39a95779);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0928, 0xf8da5d8a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x092c, 0x1f937dc1);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0930, 0x71f1fd6b);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0934, 0xa5e2a0ce);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0938, 0x7b7482c5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x093c, 0x0d3b1371);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0940, 0xd67ac596);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0944, 0x02e118cd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0948, 0x336f0a0f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x094c, 0xe2b4e377);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0950, 0x103c69bd);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0954, 0x9031fd02);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0958, 0x375f2914);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x095c, 0xbdd3eae2);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0960, 0x98dd1227);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0964, 0x9939c6a7);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0968, 0x40f61cb4);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x096c, 0x85ad3cc8);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0970, 0x7b68fb45);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0974, 0xf1439dda);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0978, 0xbc29a187);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x097c, 0xb4a4e5cb);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0980, 0x6e9c613c);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0984, 0x496e2bf3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0988, 0x978a4de0);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x098c, 0xc10321ad);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0990, 0x5e2d1223);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0994, 0x14c69288);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x0998, 0x28120900);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x099c, 0x2e92b7b9);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a0, 0xb3a26f73);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a4, 0x0f75b581);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09a8, 0xaaf19fe5);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09ac, 0xcb8ee734);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b0, 0x6b248e24);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b4, 0x4303a83f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09b8, 0x01b80651);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09bc, 0x1a077dd3);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c0, 0xb0aa4bda);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c4, 0x0745051d);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09c8, 0xcd9cba1a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09cc, 0x9c9d8b1f);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d0, 0x9b12d58a);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d4, 0xbff58f73);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09d8, 0x24a46136);
	STORE_WORD_IMMEDIATE(sprav_attestation_key+0x09dc, 0xf1ded81f);
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

#pragma GCC pop_options

int sprav_attest_region_protected(uintptr_t addr, size_t size, uint64_t nonce,
				  uint8_t *signature)
{
	int ret = 0;
	struct tc_sha256_state_struct ctx;
	uint8_t hash[TC_SHA256_DIGEST_SIZE];
	//const struct uECC_Curve_t *curve = uECC_secp256r1();
	uint8_t sprav_attestation_key[ATTESTATION_KEY_SIZE];

	/* Load attestation key temporarily */
	sprav_load_attestation_key(sprav_attestation_key);

	/* Compute Hash over requested region */
	tc_sha256_init(&ctx);
	tc_sha256_update(&ctx, (uint8_t *) addr, size);
	tc_sha256_final(hash, &ctx);

	OQS_STATUS rc;
	size_t sig_len = 0;
	uint8_t pub_key[] = {0x84, 0xf5, 0x16, 0xc2, 0x1b, 0x42, 0x46, 0xfa, 0x4b, 0xa5, 0x56, 0x20, 0x69, 0xce, 0x68, 0xef, 0xd4, 0xaa, 0x36, 0xcb, 0x8a, 0x9f, 0xa0, 0x0d, 0xe5, 0x03, 0x27, 0xd4, 0x81, 0x82, 0x9e, 0x1a, 0xb2, 0x31, 0x5a, 0x64, 0x82, 0x6a, 0x4e, 0xd8, 0x10, 0xb5, 0x32, 0x4e, 0x7a, 0xb5, 0xca, 0x8c, 0xc1, 0x37, 0x8a, 0x1c, 0x70, 0xe0, 0x3c, 0xce, 0x0a, 0xc8, 0xb2, 0xb0, 0x46, 0x4e, 0x18, 0x40, 0x49, 0xde, 0x44, 0xa8, 0xc9, 0xf1, 0x89, 0x78, 0xab, 0x82, 0xb3, 0x00, 0x57, 0x1f, 0x7e, 0x08, 0x94, 0x2c, 0x72, 0xb4, 0x47, 0x91, 0x59, 0x7f, 0x2a, 0x51, 0x65, 0xe4, 0x34, 0x16, 0x76, 0xe8, 0xb5, 0x3e, 0x06, 0xc6, 0xda, 0xae, 0x7d, 0x03, 0x97, 0x29, 0xd2, 0xb6, 0x04, 0xd8, 0xf3, 0xf4, 0xbd, 0x9a, 0xfb, 0xa0, 0x17, 0x5a, 0xa0, 0xf5, 0xbd, 0x28, 0x25, 0xb5, 0x92, 0xee, 0x35, 0xda, 0xe6, 0xfe, 0x67, 0x56, 0xab, 0x12, 0x1f, 0x12, 0xf1, 0xd0, 0x1e, 0xab, 0xa8, 0xa9, 0x41, 0x3d, 0xe0, 0x06, 0xb1, 0xea, 0xae, 0x0f, 0xcc, 0x0c, 0x6d, 0x59, 0xfa, 0xed, 0xe5, 0x09, 0xe7, 0x97, 0x22, 0x50, 0x23, 0xe5, 0xfc, 0xe6, 0xdc, 0x20, 0x42, 0xd3, 0x4b, 0xe3, 0xe0, 0xa4, 0x21, 0x72, 0x1f, 0x3d, 0xb5, 0x20, 0x2c, 0x9b, 0x96, 0xb2, 0x0d, 0xb1, 0x7b, 0x2d, 0xe5, 0x75, 0x49, 0xf5, 0xe2, 0xb3, 0x88, 0xfa, 0xf3, 0x78, 0x69, 0x81, 0x25, 0x25, 0x53, 0x09, 0x82, 0x5f, 0x75, 0xce, 0x95, 0xcb, 0xca, 0x8f, 0x17, 0xcb, 0xe9, 0xb0, 0x38, 0xb9, 0x8a, 0x78, 0xd2, 0x57, 0x8e, 0x01, 0x38, 0x8c, 0x32, 0xaf, 0x28, 0x5c, 0x49, 0x65, 0x0c, 0x39, 0xed, 0x2b, 0xf9, 0xdc, 0x46, 0x8e, 0x55, 0x8b, 0x94, 0xaa, 0x00, 0xd8, 0xa6, 0xf5, 0x75, 0xd6, 0x04, 0x38, 0xf3, 0xf7, 0xd6, 0xb2, 0x81, 0x00, 0xfb, 0x59, 0x66, 0xad, 0x6e, 0x68, 0xda, 0x17, 0x54, 0xa5, 0x33, 0x61, 0x15, 0x7f, 0xcc, 0xa3, 0xba, 0x8c, 0x54, 0x33, 0x6b, 0xe8, 0x35, 0xa4, 0xd5, 0xfb, 0xa6, 0xd1, 0x27, 0x84, 0xe7, 0xd8, 0x1e, 0x36, 0x6e, 0x60, 0x9a, 0x6d, 0x90, 0x7f, 0x95, 0x84, 0x27, 0x10, 0x45, 0xaf, 0xd3, 0x7c, 0x7a, 0xfb, 0x1e, 0x78, 0x40, 0xd4, 0x72, 0x39, 0x6d, 0x1f, 0x5d, 0x74, 0x59, 0x4b, 0x15, 0xf0, 0x32, 0x8d, 0x0f, 0xa8, 0x34, 0x30, 0x4c, 0xe8, 0x59, 0x9c, 0xfd, 0xa7, 0xa5, 0x86, 0xc9, 0xdf, 0x45, 0x70, 0xa3, 0xe2, 0x76, 0x83, 0x4a, 0x95, 0x3f, 0xd8, 0xf3, 0xfa, 0x71, 0x67, 0x01, 0x7d, 0xdd, 0x9f, 0xf9, 0x98, 0x81, 0xa2, 0x51, 0x80, 0x34, 0xf1, 0x92, 0x3a, 0x9e, 0x60, 0x5f, 0xc2, 0xee, 0x2f, 0x9e, 0x24, 0x49, 0xb4, 0x92, 0x3b, 0x81, 0x8c, 0x74, 0x4b, 0xd1, 0x16, 0xef, 0x05, 0x9e, 0xee, 0xef, 0xe8, 0xa9, 0xd9, 0x95, 0x26, 0x29, 0x86, 0xbd, 0x84, 0x75, 0x89, 0x3b, 0x23, 0x84, 0xcb, 0x23, 0x5a, 0x67, 0x48, 0x06, 0xc0, 0x14, 0x70, 0x87, 0x96, 0x6e, 0x50, 0x78, 0x41, 0x02, 0xfd, 0x67, 0xf2, 0xc0, 0x9a, 0x07, 0x62, 0xf6, 0x5a, 0xd6, 0xc2, 0x42, 0x01, 0x34, 0xfd, 0xba, 0x17, 0x17, 0x13, 0x18, 0xc8, 0x3d, 0x70, 0x11, 0xee, 0x15, 0x87, 0x65, 0x64, 0x24, 0xbe, 0xda, 0xf4, 0xf2, 0xc4, 0x38, 0x0a, 0x46, 0xbf, 0xec, 0xbb, 0x80, 0xe3, 0xe6, 0xf7, 0x1e, 0x7a, 0xee, 0xec, 0x6a, 0x6a, 0xff, 0xdf, 0x73, 0xf8, 0x53, 0xdf, 0x69, 0x49, 0x43, 0xb3, 0xf9, 0x42, 0x17, 0xda, 0xb4, 0x03, 0x28, 0xfb, 0xef, 0xee, 0xe5, 0x4f, 0x09, 0x50, 0xd4, 0xcb, 0x93, 0xd5, 0xca, 0xbe, 0xa0, 0x63, 0x76, 0x6f, 0xda, 0x5e, 0xb5, 0x69, 0x98, 0xad, 0xef, 0x23, 0xd5, 0xa8, 0x6b, 0x13, 0xd9, 0xab, 0xb8, 0x3a, 0xfc, 0xca, 0xcb, 0x21, 0xb6, 0x57, 0x06, 0x82, 0x68, 0x95, 0xa6, 0xd7, 0x80, 0xf7, 0xb9, 0x04, 0x70, 0x79, 0xaa, 0x5b, 0xfd, 0x54, 0x94, 0xa7, 0x16, 0xf3, 0x9c, 0xd4, 0x93, 0x1a, 0xe4, 0x7b, 0x5d, 0x7e, 0x8b, 0x70, 0xc9, 0xa3, 0x5f, 0x9c, 0x9a, 0x7d, 0xa1, 0x01, 0x3a, 0x76, 0x73, 0x06, 0x67, 0xea, 0x98, 0xab, 0x5e, 0xfa, 0x0e, 0x2c, 0x0c, 0xa8, 0xb3, 0x6a, 0x5b, 0xb6, 0x08, 0x4c, 0x87, 0x06, 0x38, 0x58, 0x4a, 0xa3, 0x0a, 0xfe, 0x3f, 0x69, 0x42, 0x59, 0x90, 0x74, 0x69, 0x42, 0x6f, 0x36, 0x8f, 0xb3, 0x80, 0x42, 0xb1, 0xec, 0x8b, 0xef, 0x2a, 0x5e, 0x0f, 0xc7, 0x96, 0x76, 0x72, 0x02, 0xdc, 0x59, 0x18, 0xe7, 0x00, 0xc8, 0x06, 0x61, 0x52, 0x96, 0x9a, 0xa6, 0x18, 0x2c, 0x51, 0x38, 0x54, 0x06, 0x70, 0xbc, 0xe9, 0xe4, 0xce, 0x1e, 0x0c, 0xec, 0x91, 0x8e, 0x34, 0x6d, 0xc8, 0xa6, 0xc4, 0x8e, 0x31, 0xba, 0xdf, 0x8c, 0x15, 0x99, 0xc5, 0x26, 0xe4, 0xa7, 0x50, 0x19, 0xec, 0x82, 0x97, 0xc0, 0x82, 0xb2, 0x32, 0xde, 0xcb, 0x49, 0x6d, 0x03, 0xc8, 0x2c, 0xbc, 0x9f, 0x52, 0x13, 0xd6, 0x2e, 0x76, 0xac, 0x53, 0x41, 0x14, 0x5e, 0xf1, 0xc6, 0x7e, 0x5a, 0xda, 0xb5, 0x1f, 0x4e, 0xdc, 0x59, 0xa4, 0xf8, 0x5c, 0x25, 0x72, 0x65, 0x80, 0x25, 0xed, 0x47, 0x9a, 0x34, 0x97, 0x34, 0xc5, 0x97, 0x97, 0x4f, 0x4b, 0x98, 0x94, 0xd2, 0x40, 0x26, 0xb5, 0x10, 0xe5, 0x31, 0xaa, 0xc0, 0xff, 0x65, 0xdf, 0x97, 0xc6, 0x30, 0x62, 0xb7, 0x14, 0xd5, 0x34, 0x8e, 0x93, 0xfc, 0x23, 0xcc, 0x1c, 0xfa, 0x4e, 0x1f, 0x62, 0x32, 0xbb, 0x20, 0x87, 0x34, 0xf1, 0xfa, 0x1a, 0x81, 0x9e, 0xc4, 0x02, 0x59, 0x8f, 0x61, 0xfd, 0x3e, 0x46, 0x4c, 0x7b, 0xf5, 0x80, 0xc4, 0x57, 0xe0, 0x72, 0xd2, 0x92, 0x3b, 0x91, 0x9e, 0xae, 0x32, 0xeb, 0x73, 0x0b, 0x1c, 0xda, 0xac, 0x80, 0x01, 0x58, 0xbb, 0xc3, 0xa5, 0xba, 0xe9, 0x3a, 0x94, 0x30, 0x6d, 0x6c, 0xe6, 0x9f, 0x1c, 0x80, 0x34, 0x02, 0xef, 0xc0, 0xe5, 0x1c, 0x93, 0xaa, 0xcc, 0x52, 0x26, 0x94, 0x62, 0x41, 0x13, 0x88, 0x8c, 0x1c, 0x7d, 0x4b, 0x92, 0x88, 0xc6, 0x8c, 0x09, 0xc9, 0x7c, 0x5c, 0xe5, 0x45, 0x61, 0xfb, 0xa2, 0x25, 0xdc, 0xb7, 0xde, 0x5c, 0x6f, 0x4f, 0xe8, 0x8a, 0x07, 0x2a, 0xba, 0xcd, 0x6e, 0x97, 0x9d, 0x77, 0x5e, 0xa9, 0xd7, 0xaa, 0x25, 0x05, 0x2b, 0x7b, 0x37, 0xb3, 0x96, 0xe1, 0x81, 0xc4, 0xea, 0x99, 0x8b, 0x23, 0xb3, 0xfe, 0x40, 0xa8, 0xda, 0xa2, 0x83, 0xb2, 0x31, 0xd2, 0x23, 0x45, 0x9b, 0xdb, 0xa1, 0x4f, 0x21, 0x2a, 0x63, 0xeb, 0xdc, 0xc5, 0x14, 0x18, 0x48, 0xe2, 0xa1, 0xe4, 0xd0, 0x97, 0xcf, 0xd1, 0x3a, 0x30, 0x85, 0xa6, 0x60, 0x4f, 0xc4, 0x71, 0x7f, 0x04, 0x98, 0x03, 0x4a, 0x43, 0xa9, 0x3e, 0xb2, 0xf4, 0x11, 0xf0, 0x3c, 0xf3, 0x7f, 0x47, 0x86, 0xa9, 0xb1, 0xc1, 0x4d, 0xb2, 0x77, 0x3d, 0x3c, 0xcb, 0x05, 0x5b, 0x5e, 0x28, 0xb3, 0xd7, 0x9f, 0x85, 0x9f, 0x7c, 0x3f, 0x96, 0xd7, 0xc1, 0x2f, 0x75, 0x5a, 0x59, 0xcc, 0x97, 0xeb, 0xdd, 0xcb, 0x3f, 0x0a, 0x5e, 0x30, 0x24, 0x33, 0x8c, 0x67, 0x2f, 0xb2, 0xa6, 0x39, 0xb1, 0xfa, 0xae, 0xf4, 0x33, 0x68, 0x3c, 0xfb, 0xdf, 0xb0, 0x47, 0x53, 0xd7, 0x87, 0x87, 0xe4, 0x6b, 0x13, 0xa3, 0xc0, 0xeb, 0x34, 0x42, 0x98, 0x86, 0x85, 0x9e, 0x85, 0x6c, 0xe5, 0x1e, 0xb6, 0x92, 0x7b, 0x34, 0xf5, 0x1d, 0xb0, 0xcb, 0x04, 0xbb, 0x50, 0xb3, 0x68, 0xf5, 0x90, 0x1f, 0xb4, 0x07, 0x3a, 0x53, 0x50, 0xf4, 0xf4, 0x9c, 0xe8, 0xd9, 0x44, 0x47, 0x04, 0xf4, 0x04, 0x0a, 0xa3, 0xbe, 0x6c, 0x3b, 0xac, 0x59, 0xe6, 0x5c, 0x29, 0x7c, 0xc8, 0xe6, 0x6e, 0x5d, 0xb5, 0x48, 0xc7, 0x20, 0x74, 0x09, 0x05, 0x25, 0x67, 0xa7, 0x7d, 0xcb, 0xd7, 0x29, 0xbb, 0x68, 0x87, 0x49, 0x8a, 0xcf, 0xf4, 0xf7, 0x47, 0x6c, 0x46, 0xd9, 0x48, 0x4b, 0x0e, 0x51, 0x79, 0x6b, 0x66, 0xfb, 0x4b, 0xb1, 0xb2, 0x9e, 0x34, 0xe1, 0x08, 0xcc, 0x8e, 0x99, 0xcd, 0xc2, 0xce, 0xa0, 0xe7, 0x9a, 0xc2, 0x78, 0xaa, 0xb6, 0xc4, 0x9e, 0x82, 0x82, 0xe0, 0x8e, 0x99, 0x7a, 0xd1, 0xfa, 0x5f, 0xac, 0x18, 0xa0, 0x08, 0x84, 0x5e, 0x8e, 0xd2, 0xd9, 0xdd, 0xc5, 0x57, 0xce, 0x23, 0xbb, 0x95, 0x35, 0x71, 0x02, 0xfe, 0x78, 0x2b, 0x2c, 0x48, 0x9a, 0x1d, 0x0e, 0x97, 0x4b, 0x57, 0x29, 0xc7, 0x9d, 0x9c, 0x3c, 0x6e, 0x37, 0xd2, 0x14, 0xf3, 0x36, 0x9a, 0x11, 0x28, 0xba, 0x48, 0x3b, 0x63, 0x16, 0x3c, 0xbd, 0xd1, 0x7b, 0xf8, 0xa7, 0x7d, 0x0b, 0x5d, 0x1a, 0x19, 0x35, 0x65, 0x35, 0xe9, 0x8e, 0x12, 0xb5, 0x9f, 0x62, 0xba, 0xff, 0x59, 0x6f, 0x64, 0xe4, 0x22, 0xd0, 0xfa, 0x31, 0x69, 0x57, 0x57, 0xc5, 0x25, 0xf4, 0x27, 0xdc, 0xab, 0x4c, 0x4f, 0xd6, 0xcd, 0xac, 0x29, 0xee, 0x69, 0x91, 0x22, 0x0e, 0x9f, 0xf3, 0x58, 0xa6, 0xbf, 0x7a, 0xe1, 0x1e, 0xce, 0x75, 0xb0, 0x87, 0x6b, 0x55, 0x41, 0xdc, 0xcd, 0x81, 0x85, 0x37, 0x8e, 0x56, 0x71, 0xbb, 0x24, 0xbd, 0x0c, 0x22, 0xfb, 0xab, 0xd2, 0x37, 0xf3, 0x2c, 0x46, 0x50, 0xc6, 0xb1, 0x51, 0xd1, 0xdf, 0x12, 0x32, 0xae, 0x7e, 0x6a, 0xfd, 0x23, 0x66, 0x28, 0x84, 0x65, 0x90, 0x03, 0x69, 0xa8, 0xa5, 0x5c, 0xeb, 0x08, 0xd8, 0x7b, 0xa7, 0xa4, 0x56, 0x27, 0xef, 0x8d, 0xfb, 0x09, 0x61, 0x1e, 0x85, 0x70, 0x54, 0x50, 0x46, 0x5b, 0xde, 0x10, 0x73, 0x66, 0x1d, 0xfa, 0xf3, 0x63, 0xee, 0xb1, 0xf3, 0x7a, 0x4e, 0xb9, 0xfb, 0x93, 0xe1};

	/* Compute Signature over hash & nonce */
	for (int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
		printk("%02x", hash[i]);
	}
	printk("\n");
	OQS_SIG_dilithium_2_keypair(pub_key, sprav_attestation_key);
	rc = OQS_SIG_dilithium_2_sign(signature, &sig_len, hash, TC_SHA256_DIGEST_SIZE, sprav_attestation_key);
	printk("Return value: %d\n", rc);
	printk("key size: %u\n", ATTESTATION_KEY_SIZE);
	printk("Signature length: %d\n", sig_len);

	for (int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
		printk("%02x", hash[i]);
	}
	printk("\n");
	rc = OQS_SIG_dilithium_2_verify(hash, TC_SHA256_DIGEST_SIZE, signature, sig_len, pub_key);
	printk("Signature verification: %d\n", rc);

	/*
	size_t sig_len = 0;
	crypto_sign(signature, &sig_len, hash, TC_SHA256_DIGEST_SIZE, sprav_attestation_key);
	printk("signature len: %d\n", sig_len);
	*/

	/* Compute Signature over hash & nonce */
	/*
	ret = uECC_sign_with_k(sprav_attestation_key, hash,
			       TC_SHA256_DIGEST_SIZE,
			       (uECC_word_t *) &nonce, signature, curve);
	if (ret == 0) {
		return -EFAULT;
	}

	*/
	/* Zero out temporary attestation key */
	sprav_zero_attestation_key(sprav_attestation_key);

	return 0;
}
