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
 * This file is a modified version of mbed-crypto/library/psa_its_file.c v1.1.0d0.
 */
#include "config.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include "psa/error.h"
#include "psa/storage_common.h"
#include "common_storage.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#define PSA_CS_PREFIX PSA_STORAGE_FILE_C_STORAGE_PREFIX

#define PSA_CS_FILENAME_PATTERN "%08lx%08lx"
#define PSA_CS_SUFFIX ".psa"

/* File objects created through the ITS API are stored in the
 * of PSA_CS_ITS_SUBPREFIX sub-directory of the
 * PSA_CS_PREFIX directory.
 * and include the "/" at the start. */
#define PSA_CS_ITS_SUBPREFIX "/its/"

/* File objects created through the PS API are stored in the
 * of PSA_CS_PS_SUBPREFIX sub-directory of the
 * PSA_CS_PREFIX directory.  Note this symbol
 * must be the same length as PSA_CS_ITS_SUBPREFIX which is
 * used to compute PSA_CS_FILENAME_LENGTH.*/
#define PSA_CS_PS_SUBPREFIX "/pst/"

#define PSA_CS_FILENAME_LENGTH         \
    ( sizeof( PSA_CS_PREFIX ) - 1 +     /*prefix without terminating 0*/ \
      sizeof( PSA_CS_ITS_SUBPREFIX ) - 1 + /*sub-prefix without terminating 0*/ \
      16 + /*UID (64-bit number in hex)*/                               \
      sizeof( PSA_CS_SUFFIX ) - 1 +     /*suffix without terminating 0*/ \
      1 /*terminating null byte*/ )
#define PSA_CS_TEMP \
    PSA_CS_PREFIX "tempfile" PSA_CS_SUFFIX

/* The maximum value of psa_storage_info_t.size */
#define PSA_CS_MAX_SIZE 0xffffffff

#define PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING "PSA\0ITS\0"
#define PSA_PROTECTED_STORAGE_MAGIC_STRING "PSA\0PST\0"
#define PSA_CS_MAGIC_LENGTH 8


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
    uint8_t magic[PSA_CS_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_file_header_t;

static psa_status_t psa_its_fill_filename( psa_storage_uid_t uid, char *filename, psa_cs_api_t api )
{
    char *subprefix = PSA_CS_ITS_SUBPREFIX;

    /* check api parameter */
    if ( api >= PSA_CS_API_MAX )
        return( PSA_ERROR_GENERIC_ERROR );

    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    subprefix = api == PSA_CS_API_PS ? PSA_CS_PS_SUBPREFIX : subprefix;
    snprintf( filename, PSA_CS_FILENAME_LENGTH,
                      "%s%s" PSA_CS_FILENAME_PATTERN "%s",
                      PSA_CS_PREFIX,
                      subprefix,
                      (unsigned long) ( uid >> 32 ),
                      (unsigned long) ( uid & 0xffffffff ),
                      PSA_CS_SUFFIX );

    return( PSA_SUCCESS );
}

static psa_status_t psa_its_read_file( psa_storage_uid_t uid,
                                       struct psa_storage_info_t *p_info,
                                       FILE **p_stream,
                                       psa_cs_api_t api)
{
    char filename[PSA_CS_FILENAME_LENGTH];
    char *magic_string = PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING;
    psa_its_file_header_t header;
    size_t n;
    psa_status_t status;

    *p_stream = NULL;
    status = psa_its_fill_filename( uid, filename, api );
    if( status != PSA_SUCCESS )
        return( status );

    *p_stream = fopen( filename, "rb" );
    if( *p_stream == NULL )
        return( PSA_ERROR_DOES_NOT_EXIST );

    n = fread( &header, 1, sizeof( header ), *p_stream );
    if( n != sizeof( header ) )
        return( PSA_ERROR_DATA_CORRUPT );
    magic_string = api == PSA_CS_API_PS ? PSA_PROTECTED_STORAGE_MAGIC_STRING : magic_string;
    if( memcmp( header.magic, magic_string, PSA_CS_MAGIC_LENGTH ) != 0 )
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

psa_status_t psa_cs_get_info( psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info,
                              psa_cs_api_t api )
{
    psa_status_t status;
    FILE *stream = NULL;
    status = psa_its_read_file( uid, p_info, &stream, api );
    if( stream != NULL )
        fclose( stream );
    return( status );
}

psa_status_t psa_cs_get( psa_storage_uid_t uid,
                         size_t data_offset,
                         size_t data_size,
                         void *p_data,
                         size_t *p_data_length,
                         psa_cs_api_t api )
{
    psa_status_t status;
    FILE *stream = NULL;
    size_t n = 0;
    struct psa_storage_info_t info;

    status = psa_its_read_file( uid, &info, &stream, api );
    if( status != PSA_SUCCESS )
        goto exit;
    status = PSA_ERROR_INVALID_ARGUMENT;
    if( data_offset + data_size < data_offset )
        goto exit;
#if SIZE_MAX < 0xffffffff
    if( data_offset + data_size > SIZE_MAX )
        goto exit;
#endif
    if( data_offset + data_size > info.size )
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
    n = fread( p_data, 1, data_size, stream );
    if( n != data_size )
        goto exit;
    status = PSA_SUCCESS;

exit:
    /* set the length of data written even if no data was written, as is the
     * case in error scenarios. */
    if( p_data_length )
    {
        *p_data_length = n;
    }
    if( stream != NULL )
        fclose( stream );
    return( status );
}

psa_status_t psa_cs_set( psa_storage_uid_t uid,
                          size_t data_length,
                          const void *p_data,
                          psa_storage_create_flags_t create_flags,
                          psa_cs_api_t api )
{
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_CS_FILENAME_LENGTH];
    char *magic_string = PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING;
    char *subprefix = PSA_CS_ITS_SUBPREFIX;
    FILE *stream = NULL;
    psa_its_file_header_t header;
    size_t n;
    struct psa_storage_info_t info;
    struct stat st = { 0 };
    int ret = 0;

    /* As all files are stored on encrypted file system, a request for no confidentiality
     * is upgraded to confidentiality. Hence if set the PSA_STORAGE_FLAG_NO_CONFIDENTIALITY
     * bit is cleared. */
    if( create_flags & PSA_STORAGE_FLAG_NO_CONFIDENTIALITY )
        create_flags &= ~PSA_STORAGE_FLAG_NO_CONFIDENTIALITY;

    /* Check if sub-prefix directory for storing files has been created and if not
     * create it. */
    subprefix = api == PSA_CS_API_PS ? PSA_CS_PS_SUBPREFIX : subprefix;
    snprintf( filename, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, subprefix );
    if ( stat( filename, &st ) == -1 )
    {
        ret = mkdir( filename, 0700 );
        if ( ret != 0 )
            return( PSA_ERROR_GENERIC_ERROR );
    }

    /* If the file object already exists and PSA_STORAGE_FLAG_WRITE_ONCE is set then do
     * not update the object. */
    status = psa_its_read_file( uid, &info, &stream, api );
    if( status == PSA_SUCCESS )
    {
        fclose( stream );
        if( info.flags & PSA_STORAGE_FLAG_WRITE_ONCE )
            return ( PSA_ERROR_NOT_PERMITTED );
    }

    magic_string = api == PSA_CS_API_PS ? PSA_PROTECTED_STORAGE_MAGIC_STRING : magic_string;
    memcpy( header.magic, magic_string, PSA_CS_MAGIC_LENGTH );
    header.size[0] = data_length & 0xff;
    header.size[1] = ( data_length >> 8 ) & 0xff;
    header.size[2] = ( data_length >> 16 ) & 0xff;
    header.size[3] = ( data_length >> 24 ) & 0xff;
    header.flags[0] = create_flags & 0xff;
    header.flags[1] = ( create_flags >> 8 ) & 0xff;
    header.flags[2] = ( create_flags >> 16 ) & 0xff;
    header.flags[3] = ( create_flags >> 24 ) & 0xff;

    status = psa_its_fill_filename( uid, filename, api );
    if( status != PSA_SUCCESS )
        goto exit;
    stream = fopen( PSA_CS_TEMP, "wb" );
    if( stream == NULL )
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto exit;
    }

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
        if( rename_replace_existing( PSA_CS_TEMP, filename ) != 0 )
            status = PSA_ERROR_STORAGE_FAILURE;
    }
    remove( PSA_CS_TEMP );
    return( status );
}

psa_status_t psa_cs_remove( psa_storage_uid_t uid, psa_cs_api_t api )
{
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_CS_FILENAME_LENGTH];
    FILE *stream;
    struct psa_storage_info_t info;

    status = psa_its_fill_filename( uid, filename, api );
    if( status != PSA_SUCCESS )
        goto exit;
    status = psa_its_read_file( uid, &info, &stream, api );
    if( status != PSA_SUCCESS )
        goto exit;
    if( info.flags & PSA_STORAGE_FLAG_WRITE_ONCE )
    {
        status = PSA_ERROR_NOT_PERMITTED;
        goto exit;
    }
    fclose( stream );
    stream = NULL;
    if( remove( filename ) != 0 )
        status = PSA_ERROR_STORAGE_FAILURE;

exit:
    if( stream != NULL )
        fclose( stream );
    return( status );
}
