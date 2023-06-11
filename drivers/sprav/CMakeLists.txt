# SPDX-License-Identifier: Apache-2.0

zephyr_library()

# Generate key loader
execute_process(
  COMMAND
  ${PYTHON_EXECUTABLE}
  ${CMAKE_CURRENT_LIST_DIR}/gen_attestation_key_loader.py
  ${CMAKE_CURRENT_LIST_DIR}
  )

zephyr_library_sources_ifdef(CONFIG_SPRAV sprav.c)
zephyr_library_sources_ifdef(CONFIG_SPRAV sprav_heap.c)
zephyr_library_sources_ifdef(CONFIG_SPRAV sprav_configure_pmp.S)
