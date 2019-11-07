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
# <topdir>/app/Makefile
#  Makefile to build the example application.

# tools
INSTALL = install
RM = rm -f

# symbols
# psa-storage-example-app
TARGET_APP = psa-storage-example-app


CFLAGS ?= -O2 -g
LOCAL_CFLAGS ?= -Wall -W -Wdeclaration-after-statement -I../inc
LOCAL_LDFLAGS = ../lib/libpsastorage.a

SRCS = main.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: $(TARGET_APP)

$(TARGET_APP): $(OBJS)
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) $(OBJS) $(LDFLAGS) $(LOCAL_LDFLAGS) -o $(TARGET_APP)

.c.o:
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	$(RM) *.o $(TARGET_APP)

.PHONY: install
install:
	$(INSTALL) -D $(TARGET_APP) -t $(bindir)
