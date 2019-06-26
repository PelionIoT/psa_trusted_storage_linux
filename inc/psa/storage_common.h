/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * Based on: include/psa/storage_common.h
 * In open-source project: https://github.com/ARMmbed/psa_trusted_storage_api
 *
 * Original file: Apache-2.0
 * Modifications: Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
/*  Copyright (C) 2019, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file version is at sha 1169353e647be75d52e45715d87ec070c68df100.
 */

/** @file
@brief This file includes common definitions for PSA storage
*/

#ifndef PSA_STORAGE_COMMON_H
#define PSA_STORAGE_COMMON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \brief Flags used when creating a data entry
 */
typedef uint32_t psa_storage_create_flags_t;

/** \brief A type for UIDs used for identifying data
 */
typedef uint64_t psa_storage_uid_t;

#define PSA_STORAGE_FLAG_NONE        0         /**< No flags to pass */
#define PSA_STORAGE_FLAG_WRITE_ONCE (1 << 0) /**< The data associated with the uid will not be able to be modified or deleted. Intended to be used to set bits in `psa_storage_create_flags_t`*/

/**
 * \brief A container for metadata associated with a specific uid
 */
struct psa_storage_info_t {
    uint32_t capacity;                  /**< The allocated capacity of the storage associated with a UID **/
    uint32_t size;                      /**< The size of the data associated with a UID **/
    psa_storage_create_flags_t flags;   /**< The flags set when the UID was created **/
};

/** Flag indicating that `psa_ps_create` and `psa_ps_set_extended` are supported */
#define PSA_STORAGE_SUPPORT_SET_EXTENDED (1 << 0)

/** \brief PSA storage specific error codes
 */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)-149)  /**< The signature on the data is invalid **/
#define PSA_ERROR_DATA_CORRUPT          ((psa_status_t)-152)  /**< The data on the underlying storage is corrupt  **/

#ifdef __cplusplus
}
#endif

#endif // PSA_STORAGE_COMMON_H
