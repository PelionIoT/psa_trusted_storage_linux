###############################################################################
# Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
###############################################################################
#
# <topdir>/test/Makefile
#  Makefile to build the PSA storage x86 test binaries.
#
# This makefile provides support for building the x86 PSA storage tests:
#  - psa-arch-test-ps, a test binary generated from the PSA Compliance project
#    psa-arch-test.
#  - psa_trusted_storage_linux test binaries (derived from the mbed-crypto
#    tests)
#
# (WARNING: Public users will be unable to use this makefile to generate
# psa-arch-test-ps due to repo access restrictions. However, other test
# binaries can be generated. See later for more details.)
#
# In order to run the above, use this makefile in the following way:
#  1. Copy this makefile into a new top level workspace directory TOPDIR.
#  2. cd into TOPDIR and invoke the following commands.
#  3. make ws-create-pinned
#  4. make
#  5. make test
#
# Item 3 above git clones the relevant repositories at compatible pinned versions.
# The projects of interest are:
#  - https://github.com/ARMmbed/psa_trusted_storage_linux.
#  - https://github.com/ARMmbed/mbed-crypto.
#  - A private fork of https://github.com/ARM-software/psa-arch-tests. The private
#    fork contains patches against upstream so that psa-arch-tests-ps can be built.
#    The fork is accessible to ARM stakeholders for internal development. In time,
#    the patches will be upstreamed and become publicly availble.
#    **** WARNING ****
#
# Item 4 above builds test binaries. ARM developers can build all test binaries
# including psa-arch-tests-ps by using the following command:
#  - make all-arm
#
# Item 5 above runs the test binaries and outputs the test trace to the console.
#
# The following tools are required on the host and available on the path:
# - git
# - repo
# - host gcc compiler.
###############################################################################

CFLAGS="-I$(TOPDIR)/$(PSA_STORAGE_DIR)/inc -I$(TOPDIR)/$(PSA_STORAGE_DIR)/configs -DMBEDTLS_CONFIG_FILE='<mbed_crypto_psa_storage_config.h>'"
LD_LIBRARY_PATH=$(TOPDIR)/mbed-crypto/library/:$(TOPDIR)/$(PSA_STORAGE_DIR)/usr/local/lib
LDFLAGS="-L$(TOPDIR)/$(PSA_STORAGE_DIR)/usr/local/lib -lpsastorage"

# MBED_CRYPTO_PATCHXxx are the symbols used to manage patching mbed-crypto
# to leverage mbed-crypto tests for PSA storage testing.
#  - MBED_CRYPTO_PATCHx_NAME are the names of the patch files.
#  - MBED_CRYPTO_PATCHx are the filename paths to the patch files. The patches
#    are stored in the PSA Storage repo.
MBED_CRYPTO_PATCH1_NAME = 0001-Add-psa_trusted_storage_linux-persistent-storage-sup.patch
MBED_CRYPTO_PATCH2_NAME = 0002-PSA-Storage-Fix-tests-to-support-PSA_STORAGE_FLAG_NO.patch
MBED_CRYPTO_PATCH3_NAME = 0003-Fix-test-suite-psa-its-uid-0.patch
MBED_CRYPTO_PATCH4_NAME = 0004-Fix-mbl-crypto-storage-example-app-uid-0.patch
MBED_CRYPTO_PATCH1 = $(TOPDIR)/$(PSA_STORAGE_DIR)/test/$(PSA_CRYPTO_DIR)/$(MBED_CRYPTO_PATCH1_NAME)
MBED_CRYPTO_PATCH2 = $(TOPDIR)/$(PSA_STORAGE_DIR)/test/$(PSA_CRYPTO_DIR)/$(MBED_CRYPTO_PATCH2_NAME)
MBED_CRYPTO_PATCH3 = $(TOPDIR)/$(PSA_STORAGE_DIR)/test/$(PSA_CRYPTO_DIR)/$(MBED_CRYPTO_PATCH3_NAME)
MBED_CRYPTO_PATCH4 = $(TOPDIR)/$(PSA_STORAGE_DIR)/test/$(PSA_CRYPTO_DIR)/$(MBED_CRYPTO_PATCH4_NAME)

# CFLAGS specified for building the PSA Storage library.
# PSA_STORAGE_FILE_C_STORAGE_PREFIX defined to set
# storage location for object files.
PSA_CFLAGS="-DPSA_STORAGE_FILE_C_STORAGE_PREFIX='\"$(TEST_DIR)\"'"

# PSA_ARCH_TESTS_CMAKE_VERBOSE sets the verbosity of output on the
# psa-arch-tests make. Uncomment this symbol to get vebose output
# PSA_ARCH_TESTS_CMAKE_VERBOSE=1

PSA_ARCH_TESTS_DIR=psa-arch-tests
PSA_ARCH_TESTS_MAIN_C_PATH=api-tests/platform/targets/tgt_dev_apis_stdc/nspe/common
PSA_CRYPTO_DIR=mbed-crypto
PSA_STORAGE_DIR=psa_trusted_storage_linux
PSA_STORAGE_MANIFEST_NAME=psa-storage-test-manifest.xml
PSA_STORAGE_PINNED_MANIFEST_NAME=psa-storage-test-pinned-manifest.xml
PSA_STORAGE_REPO_BRANCH=master

# TEST_DIR is the location where PSA storage object files are created/removed
# as part of testing. The path is specified as
# PSA_STORAGE_FILE_C_STORAGE_PREFIX as part of the psa-storage build
# configuration. This directory must be present if the PSA storage
# library runs as part of an test binary, for example
TEST_DIR="$(TOPDIR)/test/"

TOPDIR = $(shell pwd)

###############################################################################
# Standard targets
###############################################################################
.PHONY: all
all: mbed-crypto

.PHONY: all-arm
all-arm: psa-arch-tests-ps

.PHONY: clean
clean: mbed-crypto-clean psa-storage-clean test-clean psa-arch-tests-ps-clean test-clean

.PHONY: install
install: psa-storage-install

.PHONY: test
test: test-mbed-crypto-app test-mbed-crypto-its test-mbed-crypto-key test-psa-storage-app test-psa-arch-tests-ps

.PHONY: test-clean
test-clean:
	rm -fR $(TOPDIR)/test

# Target to create directory for PSA storage file objects
.PHONY: $(TEST_DIR)
$(TEST_DIR):
	-mkdir $(TEST_DIR)

###############################################################################
# mbed-crypto targets
###############################################################################
.PHONY: mbed-crypto
mbed-crypto: psa-storage-install mbed-crypto/$(MBED_CRYPTO_PATCH1_NAME)
	make -C mbed-crypto CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS)

.PHONY: mbed-crypto-for-psa-arch-tests
mbed-crypto-for-psa-arch-tests: psa-storage-install
	# check out a version on development that is know to build psa-arch-tests-crypto
	cd mbed-crypto && git checkout 37b5c831b41cd41456caa979f1444234c51e4c51
	make -C mbed-crypto CFLAGS=$(CFLAGS) LDFLAGS=$(LDFLAGS)

.PHONY: mbed-crypto-clean
mbed-crypto-clean:
	make -C mbed-crypto clean
	rm -fR mbed-crypto/$(MBED_CRYPTO_PATCH1_NAME)

# The mbed-crypto project test framework is used to test the PSA storage lib.
# However, patches must be applied against a specific revision for this to
# work.
mbed-crypto/$(MBED_CRYPTO_PATCH1_NAME):
	# The patch should be applied against the development branch
	# The patch can be created using: git format-patch -1 HEAD
	# where the changes have been checked into the last commit.
	cd mbed-crypto && git checkout aad3dab
	cd mbed-crypto && git am < $(MBED_CRYPTO_PATCH1) && cd ..
	cd mbed-crypto && git am < $(MBED_CRYPTO_PATCH2) && cd ..
	cd mbed-crypto && git am < $(MBED_CRYPTO_PATCH3) && cd ..
	cd mbed-crypto && git am < $(MBED_CRYPTO_PATCH4) && cd ..
	cp $(MBED_CRYPTO_PATCH1) mbed-crypto

# Target to run the mbed-crypto-app test binary
.PHONY: test-mbed-crypto-app
test-mbed-crypto-app: $(TEST_DIR)
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) && cd mbed-crypto/programs/test && ./mbl-crypto-storage-example-app && cd ../..

# Target to run the mbed-crypto-its test binary
.PHONY: test-mbed-crypto-its
test-mbed-crypto-its: $(TEST_DIR)
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) && cd mbed-crypto/tests && ./test_suite_psa_its && cd ../..

# Target to run the mbed-crypto-key test binary
.PHONY: test-mbed-crypto-key
test-mbed-crypto-key: $(TEST_DIR)
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) && cd mbed-crypto/tests && ./test_suite_psa_crypto_persistent_key && cd ../..

###############################################################################
# psa-storage targets
###############################################################################
.PHONY: psa-storage
psa-storage:
	make -C $(PSA_STORAGE_DIR) CFLAGS=$(PSA_CFLAGS)

.PHONY: psa-storage-clean
psa-storage-clean:
	make -C $(PSA_STORAGE_DIR) clean

.PHONY: psa-storage-install
psa-storage-install: psa-storage
	make -C $(PSA_STORAGE_DIR) install prefix=$(TOPDIR)/$(PSA_STORAGE_DIR)/usr/local

.PHONY: test-psa-storage-app
test-psa-storage-app: $(TEST_DIR) psa-storage
	export LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) && cd $(PSA_STORAGE_DIR)/app && ./psa-storage-example-app -v && cd ../..

###############################################################################
# Workspace management targets
###############################################################################

# Target to create a pinned manifest from the workspace
.PHONY: ws-manifest
ws-manifest:
	repo manifest -r -o $(PSA_STORAGE_PINNED_MANIFEST_NAME)

# Target to create a workspace for development (from the unpinned manifest)
.PHONY: ws-create
ws-create:
	repo init -u https://github.com/armmbed/mbl-manifest
	git clone -b $(PSA_STORAGE_REPO_BRANCH) git@github.com:armmbed/psa_trusted_storage_linux psa_trusted_storage_linux_create_clone
	cp $(TOPDIR)/psa_trusted_storage_linux_create_clone/test/$(PSA_STORAGE_MANIFEST_NAME) $(TOPDIR)/.repo/manifests
	repo init -m $(PSA_STORAGE_MANIFEST_NAME)
	repo sync
	rm -fR $(TOPDIR)/psa_trusted_storage_linux_create_clone

# Target to create a workspace for testing latest known good version (pinned manifest)
.PHONY: ws-create-pinned
ws-create-pinned:
	repo init -u https://github.com/armmbed/mbl-manifest
	git clone -b $(PSA_STORAGE_REPO_BRANCH) git@github.com:armmbed/psa_trusted_storage_linux psa_trusted_storage_linux_create_clone
	cp $(TOPDIR)/psa_trusted_storage_linux_create_clone/test/$(PSA_STORAGE_PINNED_MANIFEST_NAME) $(TOPDIR)/.repo/manifests
	repo init -m $(PSA_STORAGE_PINNED_MANIFEST_NAME)
	repo sync
	rm -fR $(TOPDIR)/psa_trusted_storage_linux_create_clone

# Target to delete the workspace.
.PHONY: ws-delete
ws-delete:
	rm -IR $(TOPDIR)/.repo
	rm -IR $(TOPDIR)/Makefile
	rm -IR $(TOPDIR)/mbed-crypto
	rm -IR $(TOPDIR)/$(PSA_STORAGE_DIR)
	rm -IR $(TOPDIR)/$(PSA_ARCH_TESTS)

###############################################################################
# PSA Compliance psa-arch-tests-ps protected storage test binary targets
###############################################################################
# Target to build psa-arch-tests protected storage test binary
.PHONY: psa-arch-tests-ps
psa-arch-tests-ps: mbed-crypto psa-storage-install $(TOPDIR)/psa-arch-tests/api-tests/build-ps $(TOPDIR)/psa-arch-tests/api-tests/build-ps/CMakeFiles main.o
	cd psa-arch-tests/api-tests/build-ps && cmake --build . -- VERBOSE=$(PSA_ARCH_TESTS_CMAKE_VERBOSE)
	cd psa-arch-tests/api-tests/build-ps && gcc -o psa-arch-tests-ps $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.o ./dev_apis/protected_storage/test_combine.a ./val/val_nspe.a ./platform/pal_nspe.a ./dev_apis/protected_storage/test_combine.a $(TOPDIR)/$(PSA_STORAGE_DIR)/usr/local/lib/libpsastorage.so

# Target to create psa-arch-tests protected storage build directory
$(TOPDIR)/psa-arch-tests/api-tests/build-ps:
	mkdir $(TOPDIR)/psa-arch-tests/api-tests/build-ps

# Target to invoke psa-arch-tests protected storage cmake configuration.
$(TOPDIR)/psa-arch-tests/api-tests/build-ps/CMakeFiles:
	cd psa-arch-tests/api-tests/build-ps && cmake ../ -DTOOLCHAIN=HOST_GCC -DTARGET=tgt_dev_apis_stdc -DSUITE=PROTECTED_STORAGE -DPSA_INCLUDE_PATHS=$(TOPDIR)/$(PSA_STORAGE_DIR)/inc -DCPU_ARCH=armv7m

# Target to psa-arch-tests protected storage test binary build
.PHONY: psa-arch-tests-ps-build
psa-arch-tests-ps-build:
	cd $(TOPDIR)/psa-arch-tests/api-tests/build-ps && cmake --build .

# Target to delete the psa-arch-tests-ps build directory and other artifacts
.PHONY: psa-arch-tests-ps-clean
psa-arch-tests-ps-clean:
	rm -fR $(TOPDIR)/psa-arch-tests/api-tests/build-ps
	rm -fR $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.o

# Target to compile boiler-plate main.c for linking with psa-arch-tests libraries.
main.o:
	gcc -Wall -Werror -c -o $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.o $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.c

# Target to run psa-arch-tests protected storage test binary.
.PHONY: test-psa-arch-tests-ps
test-psa-arch-tests-ps: $(TEST_DIR) psa-arch-tests-ps
	-$(TOPDIR)/psa-arch-tests/api-tests/build-ps/psa-arch-tests-ps

###############################################################################
# PSA Compliance psa-arch-tests-crypto crypto test binary targets
# Note the binary has to be generated from a non-patched version of mbed-crypto
###############################################################################
# Target to build psa-arch-tests crypto test binary
.PHONY: psa-arch-tests-crypto
psa-arch-tests-crypto: mbed-crypto-for-psa-arch-tests $(TOPDIR)/psa-arch-tests/api-tests/build-crypto $(TOPDIR)/psa-arch-tests/api-tests/build-crypto/CMakeFiles main.o
	cd psa-arch-tests/api-tests/build-crypto && cmake --build .
	cd psa-arch-tests/api-tests/build-crypto && gcc -o psa-arch-tests-crypto $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.o ./dev_apis/crypto/test_combine.a ./val/val_nspe.a ./platform/pal_nspe.a ./dev_apis/crypto/test_combine.a $(TOPDIR)/mbed-crypto/library/libmbedcrypto.a $(TOPDIR)/$(PSA_STORAGE_DIR)/usr/local/lib/libpsastorage.so

# Target to create psa-arch-tests crypto build directory
$(TOPDIR)/psa-arch-tests/api-tests/build-crypto:
	mkdir $(TOPDIR)/psa-arch-tests/api-tests/build-crypto

# Target to invoke psa-arch-tests crypto cmake configuration.
$(TOPDIR)/psa-arch-tests/api-tests/build-crypto/CMakeFiles:
	cd psa-arch-tests/api-tests/build-crypto && cmake ../ -DTOOLCHAIN=HOST_GCC -DTARGET=tgt_dev_apis_stdc -DSUITE=CRYPTO -DPSA_INCLUDE_PATHS=$(TOPDIR)/mbed-crypto/include -DCPU_ARCH=armv7m

# Target to psa-arch-tests crypto test binary build
.PHONY: psa-arch-tests-crypto-build
psa-arch-tests-crypto-build:
	cd $(TOPDIR)/psa-arch-tests/api-tests/build-crypto && cmake --build .

# Target to delete the psa-arch-tests-crypto build directory and other artifacts
.PHONY: psa-arch-tests-crypto-clean
psa-arch-tests-crypto-clean:
	rm -fR $(TOPDIR)/psa-arch-tests/api-tests/build-crypto
	rm -fR $(TOPDIR)/$(PSA_ARCH_TESTS_DIR)/$(PSA_ARCH_TESTS_MAIN_C_PATH)/main.o

# Target to run psa-arch-tests crypto test binary.
.PHONY: test-psa-arch-tests-crypto
test-psa-arch-tests-crypto: $(TEST_DIR) psa-arch-tests-crypto
	$(TOPDIR)/psa-arch-tests/api-tests/build-crypto/psa-arch-tests-crypto
