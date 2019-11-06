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
#  Makefile to handle Linux project integration.


.PHONY: install
install:
	$(MAKE) -C systemd install bindir=$(bindir) systemd_system_unitdir=$(systemd_system_unitdir)
