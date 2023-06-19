# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(remote_attestation)

target_sources(app PRIVATE src/main.c)

include(ExternalProject)

set(sprav_wrapper_path "${CMAKE_CURRENT_LIST_DIR}/sprav_wrappers.h")

set(liboqs_root_dir    "${CMAKE_CURRENT_LIST_DIR}/liboqs")
set(liboqs_build_dir   "${liboqs_root_dir}/build")

set(liboqs_lib_dir     "${liboqs_root_dir}/build/lib")
set(liboqs_include_dir "${liboqs_root_dir}/build/include")

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
# https://www.gnu.org/software/make/manual/html_node/MAKE-Variable.html
set(submake "$(MAKE)")
else() # Obviously no MAKEFLAGS. Let's hope a "make" can be found somewhere.
set(submake "make")
endif()

# Create build folder
file(MAKE_DIRECTORY ${liboqs_include_dir})

# Add external project and configure build options
set(CMAKE_VERBOSE_MAKEFILE ON)
ExternalProject_Add(
  liboqs_project
  PREFIX         ${liboqs_root_dir}
  SOURCE_DIR     ${liboqs_root_dir}
  BINARY_DIR     ${liboqs_build_dir}
  CMAKE_ARGS     -DCMAKE_TOOLCHAIN_FILE=../.CMake/toolchain_riscv32.cmake
                 -DOQS_BUILD_ONLY_LIB=ON
		 -DOQS_USE_OPENSSL=OFF
		 -DOQS_PERMIT_UNSUPPORTED_ARCHITECTURE=ON
		 -DOQS_ALGS_ENABLED="STD"
		 -DCMAKE_C_FLAGS:STRING=-fno-stack-protector
		 -DCMAKE_C_FLAGS:STRING=-include${sprav_wrapper_path}
		 ..
  CMAKE_GENERATOR "Ninja"
  INSTALL_COMMAND ""
  TEST_COMMAND ""
  BUILD_BYPRODUCTS ${liboqs_lib_dir}/liboqs.a
  )

add_custom_target(liboqs_build_target ALL DEPENDS liboqs_project)

# Add and configure library
add_library(liboqs_lib STATIC IMPORTED GLOBAL)
add_dependencies(
  liboqs_lib
  liboqs_project
  )

set_target_properties(liboqs_lib PROPERTIES IMPORTED_LOCATION ${liboqs_lib_dir}/liboqs.a)
set_target_properties(liboqs_lib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${liboqs_include_dir})
zephyr_include_directories(${liboqs_include_dir})

target_link_libraries(app PUBLIC liboqs_lib)
