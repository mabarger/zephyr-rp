/*
 * Copyright (c) 2023 Maximilian Barger
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>

#include <zephyr/drivers/sprav.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/toolchain.h>

#define SPRAV_HEAP_MAX_SIZE   (64 * 1024)

/* Node in a linked list of sprav heap allocations */
struct sprav_hn {
	sys_snode_t node;

	void   *ptr;
	size_t size;
};

K_HEAP_DEFINE(sprav_heap, SPRAV_HEAP_MAX_SIZE);
static sys_slist_t sprav_heap_list = SYS_SLIST_STATIC_INIT(&sprav_heap_list);

void *sprav_malloc(size_t size)
{
	/* Allocate memory and store tracking information */
	void *ptr = k_heap_alloc(&sprav_heap, size, K_FOREVER);
	if (ptr != NULL) {
		struct sprav_hn *entry = k_malloc(sizeof(struct sprav_hn));
		entry->ptr = ptr;
		entry->size = size;
		sys_slist_append(&sprav_heap_list, &entry->node);
	}

	return ptr;
}

void sprav_free(void *ptr)
{
	/* Iterate over list to find size and zero out returned memory */
	struct sprav_hn *entry;
	sys_snode_t *node, *safe;
	SYS_SLIST_FOR_EACH_NODE_SAFE(&sprav_heap_list, node, safe) {
		entry = (struct sprav_hn *) node;

		if (entry->ptr == ptr) {
			uint8_t *mem_ptr = entry->ptr;
			for (size_t i = 0; i < entry->size; i++) {
				mem_ptr[i] = 0x00;
			}
			sys_slist_find_and_remove(&sprav_heap_list, node);
			k_free(entry);
			break;
		}
	}

	/* Hand memory back to kernel */
	k_heap_free(&sprav_heap, ptr);
}
