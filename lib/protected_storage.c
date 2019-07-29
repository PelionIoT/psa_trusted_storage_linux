/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * Based on: library/psa_its_file.c
 * In open-source project: https://github.com/ARMmbed/mbed-crypto
 *
 * Original file: Apache-2.0
 * Modifications: Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * This file is a modified version of mbed-crypto/library/psa_its_file.c v1.1.0d0. The
 * minimal modifications are as follows:
 * - Modification/removal of conditionally included header files specific to the
 *   mbedtls project.
 * - Search/replace _ITS_-> _STORAGE_, _its_ -> _ps_, etc.
 * - Modification implement protected_storage.h v1.0 e.g. updating get() method.
 */
#include "config.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include "psa/protected_storage.h"
#include "common_storage.h"


psa_status_t psa_ps_get_info( psa_storage_uid_t uid, struct psa_storage_info_t *p_info )
{
	return psa_cs_get_info( uid, p_info, PSA_CS_API_PS );
}

psa_status_t psa_ps_get( psa_storage_uid_t uid,
                         size_t data_offset,
                         size_t data_size,
                         void *p_data,
                         size_t *p_data_length )
{
    return psa_cs_get( uid,data_offset, data_size, p_data, p_data_length, PSA_CS_API_PS );
}

psa_status_t psa_ps_set( psa_storage_uid_t uid,
                          size_t data_length,
                          const void *p_data,
                          psa_storage_create_flags_t create_flags )
{
    return psa_cs_set( uid, data_length, p_data, create_flags, PSA_CS_API_PS );
}

psa_status_t psa_ps_remove( psa_storage_uid_t uid )
{
    return psa_cs_remove( uid, PSA_CS_API_PS );
}
