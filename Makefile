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
systemd_system_unitdir ?= "$(libdir)/systemd/system"
includedir ?= $(prefix)/include
PSA_INCLUDEDIR = $(includedir)/psa
major ?= 1
minor ?= 0
rel  ?= 0

# tool symbols
INSTALL = install
RM = rm -f
RMR = rm -fR

.PHONY: all
all: lib app

.PHONY: app
app: install_lib
	$(MAKE) -C app libdir=$(libdir) major=$(major) minor=$(minor) rel=$(rel)

.PHONY: lib
lib:
	$(MAKE) -C lib major=$(major) minor=$(minor) rel=$(rel)

.PHONY: clean
clean: clean_app clean_lib
	${RMR} $(prefix_default)


.PHONY: clean_app
clean_app:
	$(MAKE) -C app clean major=$(major) minor=$(minor) rel=$(rel)

.PHONY: clean_lib
clean_lib:
	$(MAKE) -C lib clean major=$(major) minor=$(minor) rel=$(rel)

.PHONY: install
install: install_app install_lib install_linux
	$(INSTALL) -D inc/psa/protected_storage.h -t $(PSA_INCLUDEDIR)
	$(INSTALL) -D inc/psa/storage_common.h -t $(PSA_INCLUDEDIR)
	$(INSTALL) -D inc/psa/error.h -t $(PSA_INCLUDEDIR)

.PHONY: install_app
install_app:
	$(MAKE) -C app install bindir=$(bindir)

.PHONY: install_lib
install_lib: lib
	$(MAKE) -C lib install libdir=$(libdir) major=$(major) minor=$(minor) rel=$(rel)

.PHONY: install_linux
install_linux:
	$(MAKE) -C linux install bindir=$(bindir) systemd_system_unitdir=$(systemd_system_unitdir)
