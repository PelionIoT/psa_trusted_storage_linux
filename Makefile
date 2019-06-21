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

# PREFIX_DEFAULT is the default installation directory prefix (see Autotools documentation).
PREFIX_DEFAULT?=/usr/local
BINDIR?=$(PREFIX_DEFAULT)/bin
LIBDIR?=$(PREFIX_DEFAULT)/lib
INCLUDEDIR?=$(PREFIX_DEFAULT)/include/psa

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
	if [ -d "usr" ]; then ${RMR} usr; fi


.PHONY: clean_app
clean_app:
	$(MAKE) -C app clean

.PHONY: clean_lib
clean_lib:
	$(MAKE) -C lib clean

.PHONY: install
install: install_app install_lib
	install -D inc/psa/protected_storage.h -t $(INCLUDEDIR)
	install -D inc/psa/storage_common.h -t $(INCLUDEDIR)
	install -D inc/psa/error.h -t $(INCLUDEDIR)

.PHONY: install_app
install_app:
	$(MAKE) -C app install BINDIR=$(BINDIR)

.PHONY: install_lib
install_lib:
	$(MAKE) -C lib install LIBDIR=$(LIBDIR)
