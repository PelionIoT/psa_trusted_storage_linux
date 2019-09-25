#
# Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
#
# Based on: Makefile
# In open-source project: https://github.com/ARMmbed/mbed-crypto
#
# Original file: Apache-2.0
# Modifications: Copyright (c) 2019 Arm Limited and Contributors. All 
# rights reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# <topdir>/Makefile
#  Top level Makefile to build the libpsastorage project

prefix_default = usr
prefix ?= /$(prefix_default)/local
bindir ?= $(prefix)/bin
libdir ?= $(prefix)/lib
includedir ?= $(prefix)/include
PSA_INCLUDEDIR = $(includedir)/psa

# tool symbols
INSTALL = install
RM = rm -f
RMR = rm -fR

.PHONY: all
all: lib app

.PHONY: app
app: lib
	$(MAKE) -C app

.PHONY: lib
lib:
	$(MAKE) -C lib

.PHONY: clean
clean: clean_app clean_lib
	${RMR} $(prefix_default)


.PHONY: clean_app
clean_app:
	$(MAKE) -C app clean

.PHONY: clean_lib
clean_lib:
	$(MAKE) -C lib clean

.PHONY: install
install: install_app install_lib
	$(INSTALL) -D inc/psa/protected_storage.h -t $(PSA_INCLUDEDIR)
	$(INSTALL) -D inc/psa/storage_common.h -t $(PSA_INCLUDEDIR)
	$(INSTALL) -D inc/psa/error.h -t $(PSA_INCLUDEDIR)

.PHONY: install_app
install_app:
	$(MAKE) -C app install bindir=$(bindir)

.PHONY: install_lib
install_lib:
	$(MAKE) -C lib install libdir=$(libdir)
