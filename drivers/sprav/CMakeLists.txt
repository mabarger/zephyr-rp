# SPDX-License-Identifier: Apache-2.0

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_SPRAV sprav.c)
zephyr_library_sources_ifdef(CONFIG_SPRAV sprav_heap.c)
zephyr_library_sources_ifdef(CONFIG_SPRAV boot.S)
