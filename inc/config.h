/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * Based on: mbedtls/config.h
 * In open-source project: https://github.com/ARMmbed/mbed-crypto
 *
 * Original file: Apache-2.0
 * Modifications: Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef PSA_STORAGE_CONFIG_H
#define PSA_STORAGE_CONFIG_H

/**
 * \def PSA_STORAGE_USER_CONFIG_FILE
 *
 * Allow a user to override any of the default values defined in this file
 * by provide a use config file with one or more symbol values.
 * The current file (config.h) only defines a symbol value if a value has not
 * been previously defined (i.e. a default is provided).
 */
#if defined(PSA_STORAGE_USER_CONFIG_FILE)
#include PSA_STORAGE_USER_CONFIG_FILE
#endif

/**
 * \def PSA_STORAGE_DEBUG
 *
 * Define this symbol for a debug build to emit trace.
 */
//#define PSA_STORAGE_DEBUG 1

/**
 * \def PSA_STORAGE_FILE_C_STORAGE_PREFIX
 *
 * Define the path to the directory for Internal Trusted Storage
 * (PSA ITS) files representing persisted objects. For example,
 * to store files in "/home/username" define
 * PSA_STORAGE_FILE_C_STORAGE_PREFIX "/home/username/"
 * (note the appended "/").
 */
#if ! defined ( PSA_STORAGE_FILE_C_STORAGE_PREFIX )
#define PSA_STORAGE_FILE_C_STORAGE_PREFIX ""
#endif

/**
 * \def PSA_STORAGE_FILE_MAX
 *
 * Define the maximum number of file objects that can be created.
 * This should be set to an appropriate value to support the application
 * requirements whilst not exhausting available system storage resources.
 * The total number of files is the sum of files allocated for both
 * internal trusted storage and protected storage file objects.
 */
#if ! defined ( PSA_STORAGE_FILE_MAX )
#define PSA_STORAGE_FILE_MAX 1000
#endif

/**
 * \def PSA_STORAGE_MAX_SIZE
 *
 * Define the maximum total number of bytes allocated to objects.
 * This is the sum of all created object sizes (for both internal trusted
 * storage and protected storage file objects), not total file space
 * for store objects. The default value is 16MB.
 */
#if ! defined ( PSA_STORAGE_MAX_SIZE )
#define PSA_STORAGE_MAX_SIZE 0x01000000
#endif

/**
 * \def PSA_STORAGE_TEST
 *
 * Define the this symbol to build a module test code into the library
 * and test apps.
 */
//#define PSA_STORAGE_TEST 1


#endif /* PSA_STORAGE_CONFIG_H */
