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
 */

/* This file describes the PSA Protected Storage API */

#ifndef PSA_PROTECTED_STORAGE_H
#define PSA_PROTECTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_PS_API_VERSION_MAJOR  1
#define PSA_PS_API_VERSION_MINOR  0 

// This version of the header file is associated with 1.0 final release.


/**
 * Create a new or modify an existing key/value pair
 * 
 */
psa_status_t psa_ps_set(psa_storage_uid_t uid,
                        size_t data_length,
                        const void *p_data,
                        psa_storage_create_flags_t create_flags );

/**
 * Retrieve data associated with a provided UID
 */
psa_status_t psa_ps_get(psa_storage_uid_t uid,
                        size_t data_offset,
                        size_t data_size,
                        void *p_data,
                        size_t *p_data_length );

/**
 * Retrieve the metadata about the provided uid
 */
psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info);

/**
 * Remove the provided uid and its associated data from the storage
 */
psa_status_t psa_ps_remove(psa_storage_uid_t uid);

/**
 * Reserves storage for the specified UID. 
  */
psa_status_t psa_ps_create(psa_storage_uid_t uid,
                           size_t capacity,
                           psa_storage_create_flags_t create_flags );

/**
 * Sets partial data into an asset based on the given identifier, data_offset,
 * data length and p_data.
  */
psa_status_t psa_ps_set_extended(psa_storage_uid_t uid,
                                 size_t data_offset,
                                 size_t data_length,
                                 const void *p_data );

/**
 *  Returns a bitmask with flags set for all of the optional features supported 
 * by the implementation.
 * 
 */
uint32_t psa_ps_get_support(void);

#ifdef __cplusplus
}
#endif


#endif // PSA_PROTECTED_STORAGE_H
