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


#CFLAGS ?= -g3 -gstabs+
CFLAGS ?=
LOCAL_CFLAGS ?= -fPIC -Wall -Wextra -I../inc
LOCAL_LDFLAGS ?= -shared -lpthread
LOCAL_ARFLAGS ?= rcs
TARGET_NAME = libpsastorage

SOLINKERNAME = $(TARGET_NAME).so
SONAME = $(TARGET_NAME).so.$(major)
TARGET_LIB = $(SONAME).$(minor).$(rel)
STATIC_LIB = $(TARGET_NAME).a

SRCS = \
	common_storage.c \
	protected_storage.c \
	internal_trusted_storage.c

OBJS = $(SRCS:.c=.o)

.PHONY: all
all: ${TARGET_LIB} $(STATIC_LIB)

$(TARGET_LIB): $(OBJS)
	$(CC) ${LDFLAGS} $(LOCAL_LDFLAGS) -o $@ $^
	ln -sf $(TARGET_LIB) $(SONAME)

$(STATIC_LIB): $(OBJS)
	$(AR) $(LOCAL_ARFLAGS) $@ $^

$(SRCS:.c=.d):%.d:%.c
	$(CC) $(CFLAGS) $(LOCAL_CFLAGS) -MM $< >$@

.c.o:
	$(CC) -g3 -gstabs+ $(CFLAGS) $(LOCAL_CFLAGS) -c $< -o $@

include $(SRCS:.c=.d)

.PHONY: clean
clean:
	$(RM) $(TARGET_LIB) $(STATIC_LIB) $(SONAME) $(SOLINKERNAME) $(OBJS) $(SRCS:.c=.d)

.PHONY: install
install:
	$(INSTALL) -D $(TARGET_LIB) -t $(libdir)
	cd $(libdir) && ln -sf $(TARGET_LIB) $(SONAME)
	cd $(libdir) && ln -sf $(SONAME) $(SOLINKERNAME)
	$(INSTALL) -D $(STATIC_LIB) -t $(libdir)
