/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * Based on: include/psa/protected_storage.h
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
 */

/** @file
@brief This file describes the PSA Protected Storage API
*/

#ifndef PSA_PROTECTED_STORAGE_H
#define PSA_PROTECTED_STORAGE_H

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PSA_PS_API_VERSION_MAJOR  1  /**< The major version number of the PSA PS API. It will be incremented on significant updates that may include breaking changes */
#define PSA_PS_API_VERSION_MINOR  0  /**< The minor version number of the PSA PS API. It will be incremented in small updates that are unlikely to include breaking changes */
// This version of the header file is associated with 1.0 final release.


/**
 * \brief create a new or modify an existing key/value pair
 * 
 * The newly created asset has a capacity and size that are equal to \ref`data_length`
 *
 * \param[in] uid           the identifier for the data
 * \param[in] data_length   The size in bytes of the data in `p_data`
 * \param[in] p_data        A buffer containing the data
 * \param[in] create_flags  The flags indicating the properties of the data
 *
 * \return      A status indicating the success/failure of the operation

 * \retval      PSA_SUCCESS                     The operation completed successfully
 * \retval      PSA_ERROR_NOT_PERMITTED         The operation failed because the provided uid value was already created with PSA_STORAGE_WRITE_ONCE_FLAG
 * \retval      PSA_ERROR_INVALID_ARGUMENT      The operation failed because one or more of the given arguments were invalid.
 * \retval      PSA_ERROR_NOT_SUPPORTED         The operation failed because one or more of the flags provided in `create_flags` is not supported or is not valid
 * \retval      PSA_ERROR_INSUFFICIENT_STORAGE  The operation failed because there was insufficient space on the storage medium
 * \retval      PSA_ERROR_STORAGE_FAILURE       The operation failed because the physical storage has failed (Fatal error)
 * \retval      PSA_ERROR_GENERIC_ERROR         The operation failed because of an unspecified internal failure
 */
psa_status_t psa_ps_set(psa_storage_uid_t uid,
                        uint32_t data_length,
                        const void *p_data,
                        psa_storage_create_flags_t create_flags );

/**
 * \brief Retrieve data associated with a provided UID
 * 
 * Retrieves up to `\refdata_size` bytes of the data associated with `uid`, starting at `data_offset` bytes from the beginning of the data.
 * Upon successful completion, the data will be placed in the `p_data buffer`, which must be at least `data_size` bytes in size. The
 * length of the data returned will be in `p_data_length`.
 * If `data_size` is 0, the contents of `p_data_length` will be set to zero.
 *
 * \param[in] uid               The uid value
 * \param[in] data_offset       The starting offset of the data requested
 * \param[in] data_size         The amount of data requested
 * \param[out] p_data           Upon return of PSA_SUCCESS, the buffer where the data will be placed
 * \param[out] p_data_length    Upon return of PSA_SUCCESS, will contain size of the data placed in `p_data`
 * 
 * \return      A status indicating the success/failure of the operation
 *
 * \retval      PSA_SUCCESS                  The operation completed successfully
 * \retval      PSA_ERROR_INVALID_ARGUMENT   The operation failed because one of the provided arguments( `p_data`, `p_data_length`)
 *                                           is invalid, for example is `NULL` or references memory the caller cannot access.
 *                                           In addition, this can also happen if `data_offset` is larger than the size of the
 *                                           data associated with `uid`.
 * \retval      PSA_ERROR_DOES_NOT_EXIST     The operation failed because the provided `uid` value was not found in the storage
 * \retval      PSA_ERROR_STORAGE_FAILURE    The operation failed because the physical storage has failed (Fatal error)
 * \retval      PSA_ERROR_GENERIC_ERROR      The operation failed because of an unspecified internal failure
 * \retval      PSA_ERROR_DATA_CORRUPT       The operation failed because of an authentication failure when attempting to get the key
 * \retval      PSA_ERROR_INVALID_SIGNATURE  The operation failed because the data associated with the UID failed authentication
 */
psa_status_t psa_ps_get(psa_storage_uid_t uid,
                        uint32_t data_offset,
                        uint32_t data_size,
                        void *p_data,
                        uint32_t *p_data_length );

/**
 * \brief Retrieve the metadata about the provided uid
 *
 * \param[in] uid           The identifier for the data
 * \param[out] p_info       A pointer to the `psa_storage_info_t` struct that will be populated with the metadata
 *
 * \return      A status indicating the success/failure of the operation
 *
 * \retval      PSA_SUCCESS                  The operation completed successfully
 * \retval      PSA_ERROR_INVALID_ARGUMENT   The operation failed because one or more of the given arguments were invalid (null pointer, wrong flags etc.)
 * \retval      PSA_ERROR_DOES_NOT_EXIST     The operation failed because the provided uid value was not found in the storage
 * \retval      PSA_ERROR_STORAGE_FAILURE    The operation failed because the physical storage has failed (Fatal error)
 * \retval      PSA_ERROR_GENERIC_ERROR      The operation failed because of an unspecified internal failure
 * \retval      PSA_ERROR_DATA_CORRUPT       The operation failed because of an authentication failure when attempting to get the key
 * \retval      PSA_ERROR_INVALID_SIGNATURE  The operation failed because the data associated with the UID failed authentication
 */
psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t *p_info);

/**
 * \brief Remove the provided uid and its associated data from the storage
 *
 * \param[in] uid   The identifier for the data to be removed
 *
 * \return  A status indicating the success/failure of the operation
 *
 * \retval      PSA_SUCCESS                  The operation completed successfully
 * \retval      PSA_ERROR_INVALID_ARGUMENT   The operation failed because one or more of the given arguments were invalid (null pointer, wrong flags etc.)
 * \retval      PSA_ERROR_DOES_NOT_EXIST     The operation failed because the provided uid value was not found in the storage
 * \retval      PSA_ERROR_NOT_PERMITTED      The operation failed because the provided uid value was created with psa_eps_WRITE_ONCE_FLAG
 * \retval      PSA_ERROR_STORAGE_FAILURE    The operation failed because the physical storage has failed (Fatal error)
 * \retval      PSA_ERROR_GENERIC_ERROR      The operation failed because of an unspecified internal failure
 */
psa_status_t psa_ps_remove(psa_storage_uid_t uid);

/**
 * Reserves storage for the specified UID. Upon success, the capacity
 * of the storage is `capacity`, and the size is 0.
 * 
 * It is only necessary to call this function for assets that will be written
 * with the `psa_ps_set_extended` function. If only the `psa_ps_set` function
 * is needed, calls to this function are redundant.
 * 
 * This function cannot be used to replace an existing asset, and attempting to
 * do so will return `PSA_ERROR_ALREADY_EXISTS`.
 * 
 * If the `PSA_STORAGE_FLAG_WRITE_ONCE` flag is passed, `psa_ps_create` will
 * return `PSA_ERROR_NOT_SUPPORTED`.
 * 
 * This function is optional. Consult the documentation of your chosen
 * platform to determine if it is implemented, or perform a call to
 * `psa_ps_get_support`. This function must be implemented if
 * `psa_ps_get_support` returns `PSA_STORAGE_SUPPORT_SET_EXTENDED`.
 *
 * \param[in] uid           A unique identifier for the asset.
 * \param[in] capacity      The allocated capacity, in bytes, of the UID
 * \param[in] create_flags  Flags indicating properties of the storage
 *
 * \retval PSA_SUCCESS                      The storage was successfully reserved
 * \retval PSA_ERROR_STORAGE_FAILURE        The operation failed because the physical storage has failed (Fatal error)
 * \retval PSA_ERROR_INSUFFICIENT_STORAGE   `capacity` is bigger than the current available space
 * \retval PSA_ERROR_NOT_SUPPORTED          The function is not implemented or one or more `create_flags` are not supported
 * \retval PSA_ERROR_INVALID_ARGUMENT       `uid` was 0 or `create_flags` specified flags that are not defined in the API
 * \retval PSA_ERROR_GENERIC_ERROR          The operation has failed due to an unspecified error
 * \retval PSA_ERROR_ALREADY_EXISTS         Storage for the specified `uid` already exists
 */
psa_status_t psa_ps_create(psa_storage_uid_t uid,
                           uint32_t capacity,
                           psa_storage_create_flags_t create_flags );

/**
 * Sets partial data into an asset based on the given identifier, data_offset,
 * data length and p_data.
 * 
 * Before calling this function, the storage must have been reserved with a
 * call to `psa_ps_create`. It can also be used to overwrite data in an
 * asset that was created with a call to `psa_ps_set`.

 * Calling this function with `data_length` = 0 is permitted. 
 * This makes no change to the stored data. 
 * 
 * This function can overwrite existing data and/or extend it up to the
 * capacity for the UID specified in `psa_ps_create`, but cannot create gaps.
 * That is, it has preconditions:
 *  - `data_offset` <= size
 *  - `data_offset` + `data_length` <= capacity
 * 
 * and postconditions:
 *  - size = max(size, `data_offset` + `data_length`)
 *  - capacity unchanged
 *
 *  This function is optional. Consult the documentation of your chosen
 *  platform to determine if it is implemented, or perform a call to
 * `psa_ps_get_support`. This function must be implemented if
 * `psa_ps_get_support` returns `PSA_STORAGE_SUPPORT_SET_EXTENDED`.
 * 
 * \param[in] uid          The unique identifier for the asset.
 * \param[in] data_offset  Offset within the asset to start the write.
 * \param[in] data_length  The size in bytes of the data in p_data to write.
 * \param[in] p_data       Pointer to a buffer which contains the data to write.
 *
 * \retval PSA_SUCCESS                      The asset exists, the input parameters are correct and the data is correctly written in the physical storage
 * \retval PSA_ERROR_STORAGE_FAILURE        The data was not written correctly in the physical storage
 * \retval PSA_ERROR_INVALID_ARGUMENT       The operation failed because one or more of the precoditions listed above regarding `data_offset`, `size`, or `data_length` was violated
 * \retval PSA_ERROR_DOES_NOT_EXIST         The specified UID was not found
 * \retval PSA_ERROR_NOT_SUPPORTED          The implementation of the API does not support this function
 * \retval PSA_ERROR_GENERIC_ERROR          The operation failed due to an unspecified error
 * \retval PSA_ERROR_DATA_CORRUPT           The operation failed because the existing data has been corrupted
 * \retval PSA_ERROR_INVALID_SIGNATURE      The operation failed because the existing data failed authentication (MAC check failed)
 * \retval PSA_ERROR_NOT_PERMITTED          The operation failed because it was attempted on an asset which was written with the flag `PSA_STORAGE_FLAG_WRITE_ONCE`
 */
psa_status_t psa_ps_set_extended(psa_storage_uid_t uid,
                                 uint32_t data_offset,
                                 uint32_t data_length,
                                 const void *p_data );

/**
 *  Returns a bitmask with flags set for all of the optional features supported 
 * by the implementation.
 * 
 * Currently defined flags are limited to:
 * - `PSA_STORAGE_SUPPORT_SET_EXTENDED`
 */
uint32_t psa_ps_get_support(void);

#ifdef __cplusplus
}
#endif


#endif // PSA_PROTECTED_STORAGE_H
