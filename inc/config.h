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


/* \} name SECTION: mbed TLS modules */

/* Target and application specific configurations
 *
 * Allow user to override any previous default.
 *
 */

#if defined(PSA_STORAGE_USER_CONFIG_FILE)
#include PSA_STORAGE_USER_CONFIG_FILE
#endif

#endif /* PSA_STORAGE_CONFIG_H */
