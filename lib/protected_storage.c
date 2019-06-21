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

#include "psa/psa_storage_types.h"
#include "psa/protected_storage.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PSA_PROTECTED_STORAGE_PREFIX PSA_STORAGE_FILE_C_STORAGE_PREFIX

#define PSA_PROTECTED_STORAGE_FILENAME_PATTERN "%08lx%08lx"
#define PSA_PROTECTED_STORAGE_SUFFIX ".psa_its"
#define PSA_PROTECTED_STORAGE_FILENAME_LENGTH         \
    ( sizeof( PSA_PROTECTED_STORAGE_PREFIX ) - 1 + /*prefix without terminating 0*/ \
      16 + /*UID (64-bit number in hex)*/                               \
      sizeof( PSA_PROTECTED_STORAGE_SUFFIX ) - 1 + /*suffix without terminating 0*/ \
      1 /*terminating null byte*/ )
#define PSA_PROTECTED_STORAGE_TEMP \
    PSA_PROTECTED_STORAGE_PREFIX "tempfile" PSA_PROTECTED_STORAGE_SUFFIX

/* The maximum value of psa_storage_info_t.size */
#define PSA_PROTECTED_STORAGE_MAX_SIZE 0xffffffff

#define PSA_PROTECTED_STORAGE_MAGIC_STRING "PSA\0ITS\0"
#define PSA_PROTECTED_STORAGE_MAGIC_LENGTH 8

/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing( oldpath, newpath ) \
    ( ! MoveFileExA( oldpath, newpath, MOVEFILE_REPLACE_EXISTING ) )
#else
#define rename_replace_existing( oldpath, newpath ) rename( oldpath, newpath )
#endif

typedef struct
{
    uint8_t magic[PSA_PROTECTED_STORAGE_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_file_header_t;

static void psa_its_fill_filename( psa_storage_uid_t uid, char *filename )
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    snprintf( filename, PSA_PROTECTED_STORAGE_FILENAME_LENGTH,
                      "%s" PSA_PROTECTED_STORAGE_FILENAME_PATTERN "%s",
                      PSA_PROTECTED_STORAGE_PREFIX,
                      (unsigned long) ( uid >> 32 ),
                      (unsigned long) ( uid & 0xffffffff ),
                      PSA_PROTECTED_STORAGE_SUFFIX );
}

static psa_status_t psa_its_read_file( psa_storage_uid_t uid,
                                       struct psa_storage_info_t *p_info,
                                       FILE **p_stream )
{
    char filename[PSA_PROTECTED_STORAGE_FILENAME_LENGTH];
    psa_its_file_header_t header;
    size_t n;

    *p_stream = NULL;
    psa_its_fill_filename( uid, filename );
    *p_stream = fopen( filename, "rb" );
    if( *p_stream == NULL )
        return( PSA_ERROR_DOES_NOT_EXIST );

    n = fread( &header, 1, sizeof( header ), *p_stream );
    if( n != sizeof( header ) )
        return( PSA_ERROR_DATA_CORRUPT );
    if( memcmp( header.magic, PSA_PROTECTED_STORAGE_MAGIC_STRING,
                PSA_PROTECTED_STORAGE_MAGIC_LENGTH ) != 0 )
        return( PSA_ERROR_DATA_CORRUPT );

    p_info->size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    p_info->flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );
    return( PSA_SUCCESS );
}

psa_status_t psa_ps_get_info( psa_storage_uid_t uid,
                               struct psa_storage_info_t *p_info )
{
    psa_status_t status;
    FILE *stream = NULL;
    status = psa_its_read_file( uid, p_info, &stream );
    if( stream != NULL )
        fclose( stream );
    return( status );
}

psa_status_t psa_ps_get( psa_storage_uid_t uid,
                          uint32_t data_offset,
                          uint32_t data_length,
                          void *p_data,
                          uint32_t *p_data_length )
{
    psa_status_t status;
    FILE *stream = NULL;
    size_t n;
    struct psa_storage_info_t info;

    status = psa_its_read_file( uid, &info, &stream );
    if( status != PSA_SUCCESS )
        goto exit;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if( data_offset + data_length < data_offset )
        goto exit;
#if SIZE_MAX < 0xffffffff
    if( data_offset + data_length > SIZE_MAX )
        goto exit;
#endif
    if( data_offset + data_length > info.size )
        goto exit;

    status = PSA_ERROR_STORAGE_FAILURE;
#if LONG_MAX < 0xffffffff
    while( data_offset > LONG_MAX )
    {
        if( fseek( stream, LONG_MAX, SEEK_CUR ) != 0 )
            goto exit;
        data_offset -= LONG_MAX;
    }
#endif
    if( fseek( stream, data_offset, SEEK_CUR ) != 0 )
        goto exit;
    n = fread( p_data, 1, data_length, stream );
    if( n != data_length )
        goto exit;
    if( p_data_length )
        *p_data_length = n;
    status = PSA_SUCCESS;

exit:
    if( stream != NULL )
        fclose( stream );
    return( status );
}

psa_status_t psa_ps_set( psa_storage_uid_t uid,
                          uint32_t data_length,
                          const void *p_data,
                          psa_storage_create_flags_t create_flags )
{
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_PROTECTED_STORAGE_FILENAME_LENGTH];
    FILE *stream = NULL;
    psa_its_file_header_t header;
    size_t n;

    memcpy( header.magic, PSA_PROTECTED_STORAGE_MAGIC_STRING, PSA_PROTECTED_STORAGE_MAGIC_LENGTH );
    header.size[0] = data_length & 0xff;
    header.size[1] = ( data_length >> 8 ) & 0xff;
    header.size[2] = ( data_length >> 16 ) & 0xff;
    header.size[3] = ( data_length >> 24 ) & 0xff;
    header.flags[0] = create_flags & 0xff;
    header.flags[1] = ( create_flags >> 8 ) & 0xff;
    header.flags[2] = ( create_flags >> 16 ) & 0xff;
    header.flags[3] = ( create_flags >> 24 ) & 0xff;

    psa_its_fill_filename( uid, filename );
    stream = fopen( PSA_PROTECTED_STORAGE_TEMP, "wb" );
    if( stream == NULL )
        goto exit;

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = fwrite( &header, 1, sizeof( header ), stream );
    if( n != sizeof( header ) )
        goto exit;
    n = fwrite( p_data, 1, data_length, stream );
    if( n != data_length )
        goto exit;
    status = PSA_SUCCESS;

exit:
    if( stream != NULL )
    {
        int ret = fclose( stream );
        if( status == PSA_SUCCESS && ret != 0 )
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
    }
    if( status == PSA_SUCCESS )
    {
        if( rename_replace_existing( PSA_PROTECTED_STORAGE_TEMP, filename ) != 0 )
            status = PSA_ERROR_STORAGE_FAILURE;
    }
    remove( PSA_PROTECTED_STORAGE_TEMP );
    return( status );
}

psa_status_t psa_ps_remove( psa_storage_uid_t uid )
{
    char filename[PSA_PROTECTED_STORAGE_FILENAME_LENGTH];
    FILE *stream;
    psa_its_fill_filename( uid, filename );
    stream = fopen( filename, "rb" );
    if( stream == NULL )
        return( PSA_ERROR_DOES_NOT_EXIST );
    fclose( stream );
    if( remove( filename ) != 0 )
        return( PSA_ERROR_STORAGE_FAILURE );
    return( PSA_SUCCESS );
}
