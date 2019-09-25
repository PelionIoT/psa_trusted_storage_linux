/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PSA_COMMON_STORAGE_H
#define PSA_COMMON_STORAGE_H

#include "psa/error.h"
#include "psa/storage_common.h"

typedef enum
{
    PSA_CS_API_ITS = 0,                      /* internal trusted storage api call*/
    PSA_CS_API_PS,                           /* protected storage api call */
    PSA_CS_API_MAX
} psa_cs_api_t;

psa_status_t psa_cs_set(psa_storage_uid_t uid,
                        size_t data_length,
                        const void *p_data,
                        psa_storage_create_flags_t create_flags,
                        psa_cs_api_t api );

/**
 * Retrieve data associated with a provided UID
 */
psa_status_t psa_cs_get(psa_storage_uid_t uid,
                        size_t data_offset,
                        size_t data_size,
                        void *p_data,
                        size_t *p_data_length,
                        psa_cs_api_t api );

/**
 * Retrieve the metadata about the provided uid
 */
psa_status_t psa_cs_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info, psa_cs_api_t api );

/**
 * Remove the provided uid and its associated data from the storage
 */
psa_status_t psa_cs_remove(psa_storage_uid_t uid, psa_cs_api_t api );


#endif /* PSA_COMMON_STORAGE_H */
