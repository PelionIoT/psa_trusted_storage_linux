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
# <topdir>/lib/Makefile
#  Makefile to build the library.

# tools
INSTALL = install
RM = rm -f


LOCAL_CFLAGS=-fPIC -Wall -Wextra -O2 -g -I../inc
LOCAL_LDFLAGS=-shared
TARGET_NAME = libpsastorage

TARGET_LIB = $(TARGET_NAME).so

SRCS = \
	protected_storage.c

OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB}

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} $(LOCAL_LDFLAGS) -o $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -MM $< >$@

.c.o:
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	-${RM} ${TARGET_LIB} ${OBJS} $(SRCS:.c=.d)

.PHONY: install
install:
	$(INSTALL) -D $(TARGET_LIB) -t $(LIBDIR)
