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
# <topdir>/linux/Makefile
#  Makefile to handle Linux systemd integration.

# tools
INSTALL = install

# These are the files that are to be installed.
SYSTEMD_SERVICE = psa-ecryptfs.service
SYSTEMD_INIT = psa-ecryptfs-init.sh

.PHONY: install
install:
	$(INSTALL) -D $(SYSTEMD_SERVICE) -t $(systemd_system_unitdir)
	$(INSTALL) -D $(SYSTEMD_INIT) -t $(bindir)
