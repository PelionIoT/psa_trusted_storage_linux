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
 *
 * See the PSA Trusted Storage Linux Low Level Design docmment in the docs subdirectory
 * for implementation details on the recovery processing, algorithm and test cases.
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
#include <libgen.h>         /* for dirname() */

#define __USE_GNU
#include <dirent.h>
#include <stdlib.h>
#include <inttypes.h>       /* for PRIu64 */
#include <errno.h>          /* for errno */


#define PSA_CS_PREFIX PSA_STORAGE_FILE_C_STORAGE_PREFIX

#define PSA_CS_FILENAME_PATTERN "%08lx%08lx"
#define PSA_CS_BAK_FILENAME_PATTERN "%08lx%08lx_%02x"

/* File extensions. If the first char is "." then for
 * portability there should be at most 3 more characters. */
#define PSA_CS_BAD_FILE_SUFFIX      ".bad"
#define PSA_CS_BAK_FILE_SUFFIX      ".bak"
#define PSA_CS_DATA_FILE_SUFFIX     ".psa"
#define PSA_CS_TEMP_FILE_SUFFIX     ".tmp"
#define PSA_CS_TEMP_FILE_SUFFIX_LEN  (4+1)

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

#define PSA_CS_MAX_UID 0xffffffffffffffff
#define PSA_TRUE 1
#define PSA_FALSE 0
#define PSA_UID_STRING_LENGTH 16

#define PSA_CS_FILENAME_LENGTH                                                              \
    ( sizeof( PSA_CS_PREFIX ) - 1 +             /* prefix without terminating 0*/           \
      sizeof( PSA_CS_ITS_SUBPREFIX ) - 1 +      /* sub-prefix without terminating 0*/       \
      PSA_UID_STRING_LENGTH +                   /* UID (64-bit number in hex)*/             \
      3 +                                       /* "_" and 8-bit sequence number */         \
      sizeof( PSA_CS_DATA_FILE_SUFFIX ) - 1 +   /* suffix without terminating 0*/           \
      1                                         /* terminating null byte*/                  \
     )

/* The maximum value of psa_storage_info_t.size */
#define PSA_CS_MAX_SIZE 0xffffffff

/* Size of general purpose processing buffer held on stack. */
#define PSA_DATA_BUFFER_SIZE 4096

/* The last byte of the magic string used for storing sequence number inside object files. */
#define PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING "PSA\0ITS\0"
#define PSA_PROTECTED_STORAGE_MAGIC_STRING "PSA\0PST\0"
#define PSA_CS_MAGIC_LENGTH 8


/* PSA_CS_MAGIC_F_NONE
 *   All flags not set.
 * PSA_CS_MAGIC_F_BAK_FILE
 *  Meta-data flags in header store in file object data file.
 *  If this bit is set then the linked backup file is named
 *  <uid>.bk1, otherwise *  <uid>.bk0. */
#define PSA_CS_MAGIC_F_NONE                             0
#define PSA_CS_MAGIC_F_BAK_FILE                         (1<<0)

#define PSA_CS_NUM_FILE_OBJECTS_SENTINEL                0xffffffff

#ifdef PSA_STORAGE_DEBUG
#define psa_debug( _format, ... )                                              \
    do                                                                         \
    {                                                                          \
        if( PSA_STORAGE_DEBUG )                                                \
        {                                                                      \
            fprintf( stderr, "%s: " _format, __FUNCTION__, __VA_ARGS__ );      \
        }                                                                      \
    } while ( 0 )
#else
    #define psa_debug( format, ... )
#endif

/* assert() support */
#ifdef PSA_STORAGE_DEBUG
#include <assert.h>
#define psa_assert( _predicate )                                               \
    do                                                                         \
    {                                                                          \
        if( ! ( _predicate ) )                                                 \
        {                                                                      \
            fprintf( stderr, "%s:%d\n", __FUNCTION__, __LINE__ );              \
        }                                                                      \
        assert( ( _predicate ) );                                              \
    } while ( 0 )
#else
    #define psa_assert( _predicate )
#endif


/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing( oldpath, newpath ) \
    ( ! MoveFileExA( oldpath, newpath, MOVEFILE_REPLACE_EXISTING ) )
#else
#define rename_replace_existing( oldpath, newpath ) rename( oldpath, newpath )
#endif

/* magic[PSA_CS_MAGIC_LENGTH-1] is used to store file metadata
 * for managing file object backup files for recovery. This is used
 * for an 8 bit sequence number.
 *
 * PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX
 *  maximum sequence number
 */
#define PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT        0x00
#define PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX         0xff

typedef struct
{
    /* magic[PSA_CS_MAGIC_LENGTH-1] as metadata_flags */
    uint8_t magic[PSA_CS_MAGIC_LENGTH];
    uint8_t size[sizeof( uint32_t )];
    uint8_t flags[sizeof( psa_storage_create_flags_t )];
} psa_its_file_header_t;


/* Recovery parameters for extended _set() behaviour. */
typedef struct _psa_cs_extended_data_t
{
    /* api that is operative*/
    psa_cs_api_t api;
    /* seqnum is used to set the seqnum in xxxx.tmp. The new xxxx.dat file will
     * have seqnum+1. The xxxx.bak(old) has seqnum. */
    uint8_t seqnum;
} psa_cs_extended_data_t;


/* STRUCTURE: psa_cs_recovery_state_t
 *   Data structure used to manage the recovery process
 */
typedef struct _psa_cs_recovery_state_t
{
    int8_t b_min_uid_bka_exists;        // flag indicating first <min_uid>_<seqnum>.bak exists
    int8_t b_min_uid_bkb_exists;        // flag indicating second <min_uid>_<seqnum>.bak exists
    int8_t b_min_uid_dat_exists;        // flag indicating  <min_uid>_<seqnum>.dat exists
    int8_t b_min_uid_tmp_exists;        // flag indicating <min_uid> uid_<seqnum>.tmp exists

    // ref_psa_cs_recovery_state_t_idx
    uint32_t bad_list_idx;              // recovery processing current index into bad_list
    uint32_t bak_list_idx;              // recovery processing current index into bak_list
    uint32_t dat_list_idx;              // recovery processing current index into dat_list
    uint32_t tmp_list_idx;              // recovery processing current index into tmp_list

    // ref_psa_cs_recovery_state_t_lists
    struct dirent **bad_list;           // scandir list of files with PSA_CS_BAD_FILE_SUFFIX extension
    struct dirent **bak_list;           // scandir list of files with PSA_CS_BAK_FILE_SUFFIX extension
    struct dirent **dat_list;           // scandir list of files with PSA_CS_DAT_FILE_SUFFIX extension
    struct dirent **tmp_list;           // scandir list of files with PSA_CS_TMP_FILE_SUFFIX extension

    // ref_psa_cs_recovery_state_t_num_files
    uint32_t num_bak_files;             // number of entries in bak_list
    uint32_t num_bad_files;             // number of entries in bad_list
    uint32_t num_dat_files;             // number of entries in bad_list
    uint32_t num_tmp_files;             // number of entries in tmp_list
    uint32_t num_recovered_files;       // number of recovered files

    char dirname[PSA_CS_FILENAME_LENGTH];       // Name of directory being recovered

    uint8_t bka_seqnum;                 // sequence number of first <min_uid>_<seqnum>.bak file
    uint8_t bkb_seqnum;                 // sequence number of second <min_uid>_<seqnum>.bak file

    char *bka_filename;                 // first <min_uid>_<seqnum>.bak filename not including path.
    char *bkb_filename;                 // second <min_uid>_<seqnum>.bak filename not including path.
    char *dat_filename;                 // <min_uid>_<seqnum>.dat filename not including path.
    char *tmp_filename;                 // <min_uid>_<seqnum>.tmp filename not including path.

    psa_storage_uid_t min_uid;          // lowest uid found in set of <min_uid>_<seqnum>.xxx filenames
    psa_cs_api_t api;                   // whether recovery processing is for ITS or PS files

    /* data to control recover_file */
    char* rec_file_src_filename;        // filename of file being recovered
    psa_cs_extended_data_t ex_data;     // extended data fo recovery process
} psa_cs_recovery_state_t;


/* Global to record the number of file objects created. */
static uint32_t psa_cs_num_file_objects = PSA_CS_NUM_FILE_OBJECTS_SENTINEL;

/* Global to record total space requested. */
static size_t psa_cs_total_size = 0;

/* Global for generating unique temporary file names. */
static uint64_t psa_cs_temp_file_counter = 0;

/* Forward declarations */
static psa_status_t psa_cs_get_core( FILE *p_stream, size_t data_offset, size_t data_size, void *p_data, size_t *p_data_length, struct psa_storage_info_t *file_info );

/* Filter functions e.g. for scandir()
 *   suffix   null terminated suffix string e.g. ".dat"
 */
static int psa_core_file_filter( const struct dirent *dir, const char *suffix )
{
    const char *s = dir->d_name;
    const int cs_suffix_len = strlen( suffix );
    int len = strlen( s ) - cs_suffix_len;

    if( len >= 0 )
    {
        if( strncmp( s + len, suffix, cs_suffix_len ) == 0 )
        {
            return 1;
        }
    }
    return 0;
}

static int psa_cs_bak_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_BAK_FILE_SUFFIX );
}

static int psa_cs_dat_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_DATA_FILE_SUFFIX );
}

static int psa_cs_tmp_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_TEMP_FILE_SUFFIX );
}

static int psa_cs_bad_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_BAD_FILE_SUFFIX );
}


/* FUNCTION: psa_cs_get_mktemp_filename
 *  Generate a temporary filename using using an internal counter.
 * ARGUMENTS:
 *   filename       On input, filename contains the directory path in which to create
 *                  the temporary file. It can be a filename path as dirname(filename)
 *                  is used to extract the directory path.
 *   len            length of buffer at filename.
 */
static psa_status_t psa_cs_get_mktemp_filename( char *filename, uint32_t len )
{
    char *dname = NULL;
    char *dup_fname = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( " %s\n", "Entry" );
    dup_fname = strndup( filename, PSA_CS_FILENAME_LENGTH );
    if (dup_fname == NULL )
    {
        goto err0;
    }
    dname = dirname( dup_fname );
    snprintf( filename, len, "%s/%" PRIu64 "%s", dname, psa_cs_temp_file_counter, PSA_CS_BAD_FILE_SUFFIX );
    free( dup_fname );
    status = PSA_SUCCESS;
err0:
    return ( status );
}


/* FUNCTION: psa_cs_copy_file
 *  Make a copy of a file src_filename to the destination file dst_filename.
 *  This is done by copying the src file to a temporary file and then
 *  renaming the temporary file to the destination filename atomically.
 *  This is so that:
 *  - The destination file either exists or doesn't exist atomically from a
 *    programming perspective. This property is required for the backup
 *    algorithm.
 *  - If the copy is interrupted by a power failure, the incomplete temporary file
 *    can be detected and deleted upon startup.
 * ARGUMENTS:
 *   src_filename       name of file to copy
 *   dst_filename       name of the new file copy
 */
static psa_status_t psa_cs_copy_file( const char *src_filename, const char *dst_filename )
{
    char data[PSA_DATA_BUFFER_SIZE];
    char* mktemp_filename = NULL;
    size_t num_r = 0;
    size_t num_w = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    FILE *p_src_stream = NULL;
    FILE *p_dst_stream = NULL;

    psa_debug( " %s\n", "Entry" );
    p_src_stream = fopen( src_filename, "rb" );
    if( p_src_stream == NULL )
    {
        goto err0;
    }

    mktemp_filename = strndup( dst_filename, PSA_CS_FILENAME_LENGTH );
    if( mktemp_filename == NULL )
    {
        goto err1;
    }
    status = psa_cs_get_mktemp_filename( mktemp_filename, PSA_CS_FILENAME_LENGTH );
    if ( status != PSA_SUCCESS )
    {
        goto err2;
    }

    p_dst_stream = fopen( mktemp_filename, "wb" );
    if( p_dst_stream == NULL )
    {
        goto err2;
    }

    while ( ( num_r = fread( data, sizeof( char ), PSA_DATA_BUFFER_SIZE, p_src_stream ) ) > 0 )
    {
        num_w = fwrite( data, sizeof( char ), num_r, p_dst_stream );
        if ( num_w != num_r )
        {
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
            goto err3;
        }
    }
    if( rename_replace_existing( mktemp_filename, dst_filename ) != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto err3;
    }
    status = PSA_SUCCESS;
err3:
    fclose( p_dst_stream );
err2:
    free( mktemp_filename );
err1:
    fclose( p_src_stream );
err0:
    return ( status );
}


#define PSA_CS_GET_FILENAME_F_NONE                     0
#define PSA_CS_GET_FILENAME_F_API_ITS                  (1<<0)
#define PSA_CS_GET_FILENAME_F_BAK_FILE                 (1<<1)
#define PSA_CS_GET_FILENAME_F_DATA_FILE                (1<<2)
#define PSA_CS_GET_FILENAME_F_TEMP_FILE                (1<<3)

/* FUNCTION: psa_cs_get_filename()
 *  Return a path filename for object of form
 *      PSA_CS_PREFIX / API PREFIX / <uid> <_<seqnum>>. <extension>
 *  where <uid> is PSA_UID_STRING_LENGTH characters for the 64bit uid, and <extension>
 *  is 3 characters indicating the file type e.g. data, temp, etc.
 *  <seqnum> is a sequence number included in backup file names.
 * ARGUMENTS:
 *  flags   flags which control the generation of the filename:
 *
 *    PSA_CS_GET_FILENAME_F_API_ITS
 *      if set, specified to generate ITS path, otherwise PS path
 *    PSA_CS_GET_FILENAME_F_BAK0_FILE
 *      Generate filename for backup file object data file for backup file 0.
 *      e.g. <object-path>/<uid>.bk0
 *    PSA_CS_GET_FILENAME_F_BAK1_FILE
 *    Generate filename for backup file object data file for backup file 1.
 *    e.g. <object-path>/<uid>.bk1
 *    PSA_CS_GET_FILENAME_F_DATA_FILE
 *      Generate filename for file object data file.
 *    PSA_CS_GET_FILENAME_F_MKTEMP_FILE
 *      Generate filename template parameter for mktemp(). This is used
 *      when copying a file. The recovery process will delete any files
 *      found corresponding to the template.
 *    PSA_CS_GET_FILENAME_F_TEMP_FILE
 *      Generate filename for temporary file object data file xxx.tmp.
 *      This tmp file can be used in the recovery process
 */
static psa_status_t psa_cs_get_filename( psa_storage_uid_t uid, char *filename, uint32_t flags, uint8_t seqnum )
{
    char *subprefix = NULL;
    char *ext = PSA_CS_BAD_FILE_SUFFIX;

    psa_debug( " %s\n", "Entry" );

    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    subprefix = flags & PSA_CS_GET_FILENAME_F_API_ITS ? PSA_CS_ITS_SUBPREFIX: PSA_CS_PS_SUBPREFIX;

    if( ! ( flags & PSA_CS_GET_FILENAME_F_BAK_FILE ) )
    {
        ext = flags & PSA_CS_GET_FILENAME_F_DATA_FILE ? PSA_CS_DATA_FILE_SUFFIX: ext;
        ext = flags & PSA_CS_GET_FILENAME_F_TEMP_FILE ? PSA_CS_TEMP_FILE_SUFFIX: ext;
        snprintf( filename, PSA_CS_FILENAME_LENGTH,
                          "%s%s" PSA_CS_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          ext );
    }
    else
    {
        snprintf( filename, PSA_CS_FILENAME_LENGTH,
                          "%s%s" PSA_CS_BAK_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          (unsigned int) seqnum,
                          PSA_CS_BAK_FILE_SUFFIX );
    }
    return( PSA_SUCCESS );
}


/* FUNCTION: psa_cs_read_file_core()
 *  Open and read the file object header given a filename.
 * ARGUMENTS:
 * RETURN:
 *  status      indicating PSA_SUCCESS, PSA_ERROR_DOES_NOT_EXIST, PSA_ERROR_DATA_CORRUPT
 *  p_stream    On success, the open FILE descriptor.
 *  info        On success, the info read from the file object header
 *  seqnum      On success, the sequence number read from the file object header.
 */
static psa_status_t psa_cs_read_file_core( char *filename,
                                           struct psa_storage_info_t *p_info,
                                           FILE **p_stream,
                                           psa_cs_api_t api,
                                           uint8_t *seqnum )
{
    char *magic_string = PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING;
    psa_its_file_header_t header;
    size_t n;
    psa_status_t status;

    psa_debug( " Entry: filename=%s\n", filename );
    *p_stream = fopen( filename, "rb" );
    if( *p_stream == NULL )
    {
        psa_debug( " Error: file doesn't exist (%s).\n", filename );
        status = PSA_ERROR_DOES_NOT_EXIST;
        goto err;
    }
    n = fread( &header, 1, sizeof( header ), *p_stream );
    if( n != sizeof( header ) )
    {
        psa_debug( " Error: file header corrupt (%s).\n", filename );
        status = PSA_ERROR_DATA_CORRUPT;
        goto err;
    }
    magic_string = api == PSA_CS_API_PS ? PSA_PROTECTED_STORAGE_MAGIC_STRING : magic_string;
    if( memcmp( header.magic, magic_string, PSA_CS_MAGIC_LENGTH-1 ) != 0 )
    {
        status = PSA_ERROR_DATA_CORRUPT;
        goto err;
    }
    if( seqnum )
    {
        *seqnum = header.magic[PSA_CS_MAGIC_LENGTH-1];
    }

    p_info->size = ( header.size[0] |
                     header.size[1] << 8 |
                     header.size[2] << 16 |
                     header.size[3] << 24 );
    p_info->flags = ( header.flags[0] |
                      header.flags[1] << 8 |
                      header.flags[2] << 16 |
                      header.flags[3] << 24 );
    status = PSA_SUCCESS;
err:
    return( status );
}


/* FUNCTION: psa_cs_read_file()
 *  Open the file and read the meta-data.
 * ARGUMENTS:
 *   uid         IN, unique file object ID.
 *   p_info      IN, pointer to information structure to take copy of in psa_storage_info_t stored in file.
 *   p_stream    IN, OUT, pointer pointer to opened stream.
 *   api         IN, whether this call in on the ITS or PS API.
 *   seqnum      OUT, sequence number read from the file and returned to caller
 */
static psa_status_t psa_cs_read_file( psa_storage_uid_t uid,
                                       struct psa_storage_info_t *p_info,
                                       FILE **p_stream,
                                       psa_cs_api_t api,
                                       uint8_t *seqnum )
{
    char filename[PSA_CS_FILENAME_LENGTH];
    psa_status_t status;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    uint8_t rf_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;

    psa_debug( " %s\n", "Entry" );
    *p_stream = NULL;
    if( seqnum )
    {
        rf_seqnum = *seqnum;
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, get_filename_flags, rf_seqnum );
    if( status != PSA_SUCCESS )
    {
        return( status );
    }
    return psa_cs_read_file_core( filename, p_info, p_stream, api, seqnum );
}


/* FUNCTION: psa_cs_recover_file()
 * This function is used to recover missing xxxx.dat file, i.e. scenario's 1.x
 *  processing i.e. no <uid>.dat exists, <uid>_<seqnum>.bak and <uid>_<seqnum+1>.bak both exist.
 *  Recover <uid>dat with the xxxx.bak file. The latest backup file xxxx.bak is found from
 *  from (bka, bkb) based on the sequence number.
 * ARGUMENTS:
 *   state          structure containing recovery processing state data.
 *      state->min_uid
 *      state->rec_file_src_filename has to be set to the name of file which contains uid object data.
 *      state->ex_data.seqnum  has to be set. This will be used as the sequence number in the recovered file.
 */
psa_status_t psa_cs_recover_file( psa_cs_recovery_state_t *state )
{
    char fn[PSA_CS_FILENAME_LENGTH];
    void *data = NULL;
    FILE *p_stream = NULL;
    const size_t data_offset = 0;
    size_t data_length;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    struct psa_storage_info_t info;

    psa_debug( " %s\n", "Entry" );
    psa_debug( " state->rec_file_src_filename=%s,state->ex_data.seqnum=%d\n", state->rec_file_src_filename, state->ex_data.seqnum );
    memset( &info, 0, sizeof( info ) );

    psa_assert( strlen( state->rec_file_src_filename ) > 0 );

    /* Read bkx+1 file header info to get size of data. */
    snprintf( fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->rec_file_src_filename );
    status = psa_cs_read_file_core( fn, &info, &p_stream, state->api, NULL );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    data = malloc( info.size );
    if( data == NULL )
    {
        goto err1;
    }
    /* get the data from the bak file */
    status = psa_cs_get_core( p_stream, data_offset, info.size, data, &data_length, &info );
    if( status != PSA_SUCCESS )
    {
        goto err2;
    }
    status = psa_cs_set( state->min_uid, info.size, data, info.flags, state->api, &state->ex_data );
err2:
    if( data ) free( data );
err1:
    if( p_stream != NULL )
    {
        fclose( p_stream );
    }
err0:
    return ( status );
}


/* FUNCTION: psa_cs_proc_scenario_1_1()
 *  Scenario 1.1. No dat exists, bkx and bkx+1 both exist.Recover dat with the latest bkx file.
 *  The latest backup file xxxx.bkx+1 if found from from (bka, bkb) based on the sequence number.
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_1_1( psa_cs_recovery_state_t *state )
{
    char *bkxp1_filename = NULL;
    char *bkx_filename = NULL;
    char fn[PSA_CS_FILENAME_LENGTH];
    uint8_t bkxp1_seqnum = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( " %s\n", "Entry" );
    /* find xxxx.bakx+1
     * If only bka exists then state->bkb_seqnum = 0 and then this doesnt work for
     * bka_seqnum > PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 */
    if( (uint8_t) ( state->bka_seqnum - state->bkb_seqnum ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* bka_seqnum > bkb_seqnum */
        bkxp1_filename = state->bka_filename;
        bkx_filename = state->bkb_filename;
        bkxp1_seqnum = state->bka_seqnum;
    }
    else
    {
        /* bkb_seqnum > bka_seqnum */
        bkxp1_filename = state->bkb_filename;
        bkx_filename = state->bka_filename;
        bkxp1_seqnum = state->bkb_seqnum;
    }
    state->rec_file_src_filename = bkxp1_filename;
    state->ex_data.seqnum = bkxp1_seqnum;
    status = psa_cs_recover_file( state );
    /* The bkx file will not be removed by the _set() operation, so explicitly remove the file */
    if( bkx_filename != NULL )
    {
        snprintf( fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkx_filename );
        remove( fn );
    }
    return ( status );
}


/* FUNCTION: psa_cs_proc_scenario_1_2()
 *  Scenario 1.2. No dat exists. Only bka exists.
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_1_2( psa_cs_recovery_state_t *state )
{
    psa_debug( " %s\n", "Entry" );
    state->rec_file_src_filename = state->bka_filename;
    state->ex_data.seqnum = state->bka_seqnum;
    return psa_cs_recover_file( state );
}



/* FUNCTION: psa_cs_proc_scenario_1()
 *   Scenario 1. No dat exists. Try to recover by using existing xxxx.bkx file(s).
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_1( psa_cs_recovery_state_t *state )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( " %s\n", "Entry" );
    if( state->b_min_uid_bka_exists && state->b_min_uid_bkb_exists )
    {
        /* Scenario 1.1, No dat exists. bkx+1 MUST exist. */
        status = psa_cs_proc_scenario_1_1( state );
    }
    else if( state->b_min_uid_bka_exists )
    {
        /* Scenario 1.2, No dat exists. Only bka exists. */
        status = psa_cs_proc_scenario_1_2( state );
    }
    else
    {
        /* No recovery possible */
        psa_debug( " %s\n", "Error: unable to recover dat file" );
    }
    return status;
}


/* FUNCTION: psa_cs_proc_scenario_2_1()
 *  Scenario 2.1. dat exists. 2 bak files exist.
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_2_1( psa_cs_recovery_state_t *state )
{
    char *bkxp1_filename = NULL;
    char *bkx_filename = NULL;
    char dat_fn[PSA_CS_FILENAME_LENGTH];
    char bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t bkxp1_seqnum = 0;
    uint8_t dat_seqnum = 0;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    struct psa_storage_info_t info;

    psa_debug( " %s\n", "Entry" );
    memset( &info, 0, sizeof( info ) );
    /* get dat_seqnum */
    snprintf( dat_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->dat_filename );
    status = psa_cs_read_file_core( dat_fn, &info, &p_stream, state->api, &dat_seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }

    /* find xxxx.bakx+1 (the latest xxxx.bk file.
     * If only bka exists then state->bkb_seqnum = 0 and then this doesnt work */
    if( (uint8_t) ( state->bka_seqnum - state->bkb_seqnum ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* bka_seqnum > bkb_seqnum */
        bkxp1_filename = state->bka_filename;
        bkx_filename = state->bkb_filename;
        bkxp1_seqnum = state->bka_seqnum;

    }
    else
    {
        /* bkb_seqnum > bka_seqnum */
        bkxp1_filename = state->bkb_filename;
        bkx_filename = state->bka_filename;
        bkxp1_seqnum = state->bkb_seqnum;
    }

    if( bkxp1_seqnum == dat_seqnum )
    {
        /* everything OK, just didnt remove old xxxx.bak(old) file */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkx_filename );
        remove( bak_fn );
    }
    else if( (uint8_t) ( bkxp1_seqnum - dat_seqnum ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* bkxp1_seqnum > dat_seqnum. Use bkxp1 file to recreate xxxx.dat */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkxp1_filename );
        status = psa_cs_copy_file( bak_fn, dat_fn );
        if( status != PSA_SUCCESS )
        {
            goto err1;
        }
        if( strncmp( bkxp1_filename, bkx_filename, PSA_CS_FILENAME_LENGTH ) != 0 )
        {
            snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkx_filename );
            remove( bak_fn );
        }
    }
    else
    {
        /* dat_seqnum > bkxp1_seqnum. recover outdated bak file.
         * xxxx.dat must be later than xxxx.bkx(old) file so
         * recreate correct bak file by copying xxxx.dat. */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkxp1_filename );
        status = psa_cs_copy_file( dat_fn, bak_fn );
        if( status != PSA_SUCCESS )
        {
            goto err1;
        }
        /* Remove stale xxxx.bkx files. */
        if( strncmp( bkxp1_filename, bkx_filename, PSA_CS_FILENAME_LENGTH ) != 0 )
        {
            snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, bkx_filename );
            remove( bak_fn );
        }
    }
err1:
    if( p_stream != NULL )
    {
        fclose( p_stream );
    }
err0:
    return ( status );
}


/* FUNCTION: psa_cs_proc_scenario_2_2()
 *  Scenario 2.2. dat exists. ` bak file1 exist.
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_2_2( psa_cs_recovery_state_t *state )
{
    char dat_fn[PSA_CS_FILENAME_LENGTH];
    char bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t dat_seqnum = 0;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    struct psa_storage_info_t info;

    psa_debug( "Entry: state->dat_filename=%s, state->bka_seqnum=%d\n", state->dat_filename, state->bka_seqnum );
    memset( &info, 0, sizeof( info ) );
    /* get dat_seqnum */
    snprintf( dat_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->dat_filename );
    status = psa_cs_read_file_core( dat_fn, &info, &p_stream, state->api, &dat_seqnum );
    if( status != PSA_SUCCESS )
    {
        psa_debug( " Error: Failed to read file (%s)\n", dat_fn );
        goto err0;
    }
    if( state->bka_seqnum == dat_seqnum )
    {
        /* everything OK */
        goto err1;
    }
    else if( (uint8_t) ( state->bka_seqnum - dat_seqnum ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        psa_debug( " Case: bka_seqnum > dat_seqnum: state->bka_filename=%s\n", state->bka_filename );
        /* bka_seqnum > dat_seqnum. Use bka file to recreate xxxx.dat
         * force the overwrite of xxxx.dat even if _F__WRITE_ONCE set. */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->bka_filename );
        status = psa_cs_copy_file( bak_fn, dat_fn );
        /* The xxxx_<seqnum>.bak is retained and used. */
    }
    else
    {
        psa_debug( " Case: dat_seqnum > bkxp1_seqnum: state->bka_filename=%s\n", state->bka_filename );
        /* dat_seqnum > bkxp1_seqnum. recover outdated bak file.
         * xxxx.dat must be later than xxxx.bkx(old) file so
         * recreate correct bak file by copying xxxx.dat */
        get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
        get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( state->min_uid, bak_fn, get_filename_flags, dat_seqnum );
        if( status != PSA_SUCCESS )
        {
            psa_debug( " Error: unable to get missing bak file from valid uid %" PRIu64 " and seqnum (%d).\n", state->min_uid, dat_seqnum );
            goto err1;
        }
        status = psa_cs_copy_file( dat_fn, bak_fn );
        if( status != PSA_SUCCESS )
        {
            psa_debug( " Error: unable to recreate missing bak file (%s) from valid dat file (%s).\n", bak_fn, dat_fn );
            goto err1;
        }
        /* remove old bak file */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->bka_filename );
        ret = remove( bak_fn );
        if ( ret < 0 )
        {
            psa_debug( " Error: unable to delete old bak file (%s).\n", bak_fn );
            status = PSA_ERROR_DOES_NOT_EXIST;
        }
        state->num_recovered_files++;
    }
err1:
    if( p_stream != NULL )
    {
        fclose( p_stream );
    }
err0:
    return ( status );
}


/* FUNCTION: psa_cs_proc_scenario_2_3()
 *  Scenario 2.3. dat exists. 0 bak files exist.
 * ARGUMENTS:
 */
psa_status_t psa_cs_proc_scenario_2_3( psa_cs_recovery_state_t *state )
{
    char dat_fn[PSA_CS_FILENAME_LENGTH];
    char filename[PSA_CS_FILENAME_LENGTH];
    uint8_t dat_seqnum = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    struct psa_storage_info_t info;

    psa_debug( " %s\n", "Entry" );
    memset( &info, 0, sizeof( info ) );
    /* get dat_seqnum so can regenerate bak filename */
    snprintf( dat_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->dat_filename );
    status = psa_cs_read_file_core( dat_fn, &info, &p_stream, state->api, &dat_seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( state->min_uid, filename, get_filename_flags, dat_seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err1;
    }
    status = psa_cs_copy_file( dat_fn, filename );
    if( status == PSA_SUCCESS )
    {
        state->num_recovered_files++;
    }
err1:
    if( p_stream != NULL )
    {
        fclose( p_stream );
    }
err0:
    return ( status );
}


/* FUNCTION: psa_cs_proc_scenario_2()
 *   Processing the recovery processing scenario 2. See LLD for more details.
 * ARGUMENTS:
 *   state          structure containing recovery processing state data.
 * RETURN:
 *   PSA_SUCCESSS   successful recovery
 *   < 0            otherwise
 */
psa_status_t psa_cs_proc_scenario_2( psa_cs_recovery_state_t *state )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( " %s\n", "Entry" );
    if( state->b_min_uid_bka_exists && state->b_min_uid_bkb_exists )
    {
        /* Scenario 2.1, xxxx.dat exists. bkx+1 MUST exist. */
        status = psa_cs_proc_scenario_2_1( state );
    }
    else if( state->b_min_uid_bka_exists )
    {
        /* Scenario 2.1, xxxx.dat exists. Only bka exists. */
        status = psa_cs_proc_scenario_2_2( state );
    }
    else
    {
        /* Scenario 2.3, xxxx.dat exists. No bkx exists. Recreate xxxx.bkx from xxxx.dat */
        status = psa_cs_proc_scenario_2_3( state );
    }
    return ( status );
}


/* FUNCTION: psa_cs_recover_uid()
 *  Given a state structure containing file data populated by scandir,
 *  processs the lists of files to find missing <uid>.dat and
 *  <uid>_<seqnum>.bak, and recover them. The function requires the following
 *  state members to be initialised:
 *    - min_uid, dirname
 *    - The lists at ref_psa_cs_recovery_state_t_lists (see above).
 *    - The list indices at ref_psa_cs_recovery_state_t_idx (see above).
 *    - The counters at ref_psa_cs_recovery_state_t_num_files (see above)
 * ARGUMENTS:
 *   state          structure containing recovery processing state data.
 * RETURN:
 *   PSA_SUCCESSS   successful recovery
 *   < 0            otherwise
 */
psa_status_t psa_cs_recover_uid( psa_cs_recovery_state_t *state )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    struct dirent *dat_file;
    struct dirent *bka_file;
    struct dirent *bkb_file;
    struct dirent *tmp_file;

    char ext[PSA_CS_TEMP_FILE_SUFFIX_LEN];
    unsigned long dat_uid_hi = 0, dat_uid_lo = 0;
    unsigned long tmp_uid_hi = 0, tmp_uid_lo = 0;
    unsigned long bka_uid_hi = 0, bka_uid_lo = 0;
    unsigned long bkb_uid_hi = 0, bkb_uid_lo = 0;

    psa_storage_uid_t dat_uid = 0, tmp_uid = 0, bka_uid = 0, bkb_uid = 0;

    char min_uid_dat_filename[PSA_CS_FILENAME_LENGTH];

    psa_debug( " Entry: min_uid=%" PRIu64 ", dirname=%s, num_bak_files=%d, num_tmp_files=%d, num_dat_files=%d\n", state->min_uid, state->dirname, state->num_bak_files, state->num_tmp_files, state->num_dat_files );
    psa_assert( strlen( state->dirname ) > 0 );
    psa_assert( state->num_bak_files > 0 || state->num_tmp_files > 0 || state->num_dat_files > 0 );

    /* Using (top entry)->d_name on each list find min uid of (dat_list, bk0_list, bk1_list tmp_list)
     * matching on the uid part of the filename i.e. get the min uid filename without the extension.
     * min_uid = find uid of min file.
     */
    while ( state->dat_list_idx < state->num_dat_files ||
            state->tmp_list_idx < state->num_tmp_files ||
            state->bak_list_idx < state->num_bak_files
          )
    {
        state->min_uid = PSA_CS_MAX_UID;
        state->bka_seqnum = 0;
        state->bkb_seqnum = 0;
        state->bka_filename = NULL;
        state->bkb_filename = NULL;
        state->dat_filename = NULL;
        state->tmp_filename = NULL;
        state->b_min_uid_bka_exists = PSA_FALSE;
        state->b_min_uid_bkb_exists = PSA_FALSE;
        state->b_min_uid_dat_exists = PSA_FALSE;
        state->b_min_uid_tmp_exists = PSA_FALSE;
        dat_uid = 0;
        tmp_uid = 0;
        bka_uid = 0;
        bkb_uid = 0;
        dat_file = NULL;
        bka_file = NULL;
        bkb_file = NULL;
        tmp_file = NULL;

        if( state->dat_list_idx < state->num_dat_files )
        {
            dat_file = state->dat_list[state->dat_list_idx];
            state->dat_filename = dat_file->d_name;
            sscanf( state->dat_filename, PSA_CS_FILENAME_PATTERN "%s", &dat_uid_hi, &dat_uid_lo, ext );
            dat_uid = dat_uid_hi << 32 | dat_uid_lo;
        }
        if( state->bak_list_idx < state->num_bak_files )
        {
            bka_file = state->bak_list[state->bak_list_idx];
            state->bka_filename = bka_file->d_name;
            sscanf( state->bka_filename, PSA_CS_BAK_FILENAME_PATTERN "%s", &bka_uid_hi, &bka_uid_lo, (unsigned int *) &state->bka_seqnum, ext );
            bka_uid = bka_uid_hi << 32 | bka_uid_lo;
        }
        if( state->bak_list_idx+1 < state->num_bak_files )
        {
            bkb_file = state->bak_list[state->bak_list_idx+1];
            state->bkb_filename = bkb_file->d_name;
            sscanf( state->bkb_filename, PSA_CS_BAK_FILENAME_PATTERN "%s", &bkb_uid_hi, &bkb_uid_lo, (unsigned int *) &state->bkb_seqnum, ext );
            bkb_uid = bkb_uid_hi << 32 | bkb_uid_lo;
        }
        if( state->tmp_list_idx < state->num_tmp_files )
        {
            tmp_file = state->tmp_list[state->tmp_list_idx];
            state->tmp_filename = tmp_file->d_name;
            sscanf( state->tmp_filename, PSA_CS_FILENAME_PATTERN "%s", &tmp_uid_hi, &tmp_uid_lo, ext );
            tmp_uid = tmp_uid_hi << 32 | tmp_uid_lo;
        }

        state->min_uid = bka_uid > 0 && bka_uid < state->min_uid ? bka_uid : state->min_uid;
        state->min_uid = bkb_uid > 0 && bkb_uid < state->min_uid ? bkb_uid : state->min_uid;
        state->min_uid = tmp_uid > 0 && tmp_uid < state->min_uid ? tmp_uid : state->min_uid;
        state->min_uid = dat_uid > 0 && dat_uid < state->min_uid ? dat_uid : state->min_uid;
        if ( state->min_uid == PSA_CS_MAX_UID )
        {
            psa_debug( " %s\n", "Error: non-empty uid file lists but unable to find minimum uid value." );
            goto err0;
        }

        /* Now explicitly look for files. */
        snprintf( min_uid_dat_filename, PSA_CS_FILENAME_LENGTH, PSA_CS_FILENAME_PATTERN, (unsigned long) ( state->min_uid >> 32 ), (unsigned long) ( state->min_uid & 0xffffffff ) );

        if( state->dat_filename != NULL ) state->b_min_uid_dat_exists = strncmp( min_uid_dat_filename, state->dat_filename, PSA_UID_STRING_LENGTH ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->tmp_filename != NULL ) state->b_min_uid_tmp_exists = strncmp( min_uid_dat_filename, state->tmp_filename, PSA_UID_STRING_LENGTH ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->bka_filename != NULL ) state->b_min_uid_bka_exists = strncmp( min_uid_dat_filename, state->bka_filename, PSA_UID_STRING_LENGTH ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->bkb_filename != NULL ) state->b_min_uid_bkb_exists = strncmp( min_uid_dat_filename, state->bkb_filename, PSA_UID_STRING_LENGTH ) == 0 ? PSA_TRUE : PSA_FALSE;

        if( ! state->b_min_uid_dat_exists )
        {
            /* Scenario 1. Missing <uid>.dat exists */
            if( ( status = psa_cs_proc_scenario_1( state ) ) != PSA_SUCCESS )
            {
                psa_debug( "Error: Failed recovery operation for uid (%" PRIu64 ").\n", state->min_uid );
                goto err0;
            }
        }
        else
        {
            /* Scenario 1. <uid>.dat exists, possibly missing  <uid>_<seqnum>.bak */
            if( ( status = psa_cs_proc_scenario_2( state ) ) != PSA_SUCCESS )
            {
                psa_debug( "Error: Failed recovery operation for uid (%" PRIu64 ").\n", state->min_uid );
                goto err0;
            }
        }

        /* OK min_uid serviced. Move to next uid in list */
        if ( state->b_min_uid_bka_exists )
        {
            state->bak_list_idx++;
        }
        if ( state->b_min_uid_bkb_exists )
        {
            state->bak_list_idx++;
        }
        if ( state->b_min_uid_dat_exists )
        {
            state->dat_list_idx++;
        }
        if ( state->b_min_uid_tmp_exists )
        {
            state->tmp_list_idx++;
        }
    }
    status = PSA_SUCCESS;
err0:
    return ( status );
}


/* FUNCTION: psa_cs_recover()
 *  Top level file object dat recovery function. This function sets up
 *  the state structure and invokes the recover_uid() as required.
 * ARGUMENTS:
 *   state          structure containing recovery processing state data.
 * RETURN:
 *   PSA_SUCCESSS   successful recovery
 *   < 0            otherwise
 */
psa_status_t psa_cs_recover( psa_cs_recovery_state_t *state )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    char filename[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    int num_files = 0;

    psa_debug( "%s:dirname=%s\n", "Entry", state->dirname );
    psa_assert( strlen( state->dirname ) > 0 );

    ret = scandir( state->dirname, &state->bad_list, psa_cs_bad_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( " Error: scandir for .bad files failed (errno=%d).\n", errno );
        goto err0;
    }
    state->num_bad_files = ret;
    ret = scandir( state->dirname, &state->bak_list, psa_cs_bak_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( "%s:\n", "Error: scandir for .bak files failed." );
        goto err1;
    }
    state->num_bak_files = ret;
    ret = scandir( state->dirname, &state->dat_list, psa_cs_dat_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( "%s:\n", "Error: scandir for .dat files failed." );
        goto err2;
    }
    state->num_dat_files = ret;
    ret = scandir( state->dirname, &state->tmp_list, psa_cs_tmp_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( "%s:\n", "Error: scandir for .tmp files failed." );
        goto err3;
    }
    state->num_tmp_files = ret;

    /* Initialization can invoke recovery, which can call the _set() method
     * to create new versions of xxxx.dat files, which will call psa_cs_init()
     * if cs_num_file_objects == PSA_CS_NUM_FILE_OBJECTS_SENTINEL. Hence
     * prevent this recursion by setting psa_cs_num_file_objects to a first
     * estimate of the number of file objects. This will be updated by the
     * recovery processing */
    psa_cs_num_file_objects = state->num_dat_files;
    if( state->num_bak_files > 0 || state->num_tmp_files > 0 || state->num_dat_files > 0 )
    {
        if( ( status = psa_cs_recover_uid( state ) ) != PSA_SUCCESS )
        {
            psa_debug( "%s:\n", "Error: failed to recover uid." );
            goto err3;
        }
    }
    status = PSA_SUCCESS;
    num_files = state->num_tmp_files;
    while( num_files-- )
    {
        snprintf( filename, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->tmp_list[num_files]->d_name );
        remove( filename );
        free( state->tmp_list[num_files] );
    }
    state->num_tmp_files = 0;
    free( state->tmp_list );

err3:
    num_files = state->num_dat_files;
    while( num_files-- )
    {
        free( state->dat_list[num_files] );
    }
    free( state->dat_list );

err2:
    num_files = state->num_bak_files;
    while( num_files-- )
    {
        free( state->bak_list[num_files] );
    }
    free( state->bak_list );

err1:
    num_files = state->num_bad_files;
    while( num_files-- )
    {
        snprintf( filename, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->bad_list[num_files]->d_name );
        remove( filename );
        free( state->bad_list[num_files] );
    }
    state->num_bad_files = 0;
    free( state->bad_list );

err0:
    return ( status );
}

/* FUNCTION: psa_cs_init()
 *  Start-up initialization function
 */
static psa_status_t psa_cs_init( void )
{
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    int i;
    int ret = 0;
    struct stat st = { 0 };
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_cs_recovery_state_t state;

    /* - Check if sub-prefix directories (its, ps) for storing files have
     *   been created and if not create them.
     * - If the directory exists then count the number of file objects contained. */
    for( i = 0; i < PSA_CS_API_MAX; i++ )
    {
        memset( &state, 0, sizeof( state ) );
        state.api = i;
        snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[i] );
        if( stat( state.dirname, &st ) == -1 )
        {
            /* Directory doesn't exist i.e. no objects have been created yet. */
            ret = mkdir( state.dirname, 0700 );
            if( ret != 0 )
            {
                psa_debug( "Error: failed to create dirname directory (%s)\n", state.dirname );
                goto exit;
            }
        }

        if( ( status = psa_cs_recover( &state ) ) != PSA_SUCCESS )
        {
            psa_debug( "Error: Recovery procedure failure (%d)\n", status );
            goto exit;
        }
    }
    status = PSA_SUCCESS;
    psa_debug( "Exit: status=%d, psa_cs_num_file_objects=%d\n", status, psa_cs_num_file_objects );
    return( status );
exit:
    psa_cs_num_file_objects = PSA_CS_NUM_FILE_OBJECTS_SENTINEL;
    return ( status );
}


/* FUNCTION: psa_cs_get_info()
 *  PSA Storage get_info() implementation for both psa_its_get_info()
 *  and psa_ps_get_info().
 */
psa_status_t psa_cs_get_info( psa_storage_uid_t uid,
                              struct psa_storage_info_t *p_info,
                              psa_cs_api_t api )
{
    psa_status_t status;
    FILE *stream = NULL;

    psa_debug( " %s\n", "Entry" );
    if( psa_cs_num_file_objects == PSA_CS_NUM_FILE_OBJECTS_SENTINEL )
    {
        status = psa_cs_init();
        if( status != PSA_SUCCESS ) {
            return status;
        }
    }
    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORATE_UID_INVALID_VALUE )
    {
        return( PSA_ERROR_INVALID_ARGUMENT );
    }

    status = psa_cs_read_file( uid, p_info, &stream, api, NULL );
    if( stream != NULL )
    {
        fclose( stream );
    }
    return( status );
}


/* FUNCTION: psa_cs_get_core()
 *  Get the data from the open stream and store it in the supplied buffer
 */
psa_status_t psa_cs_get_core( FILE *p_stream,
                              size_t data_offset,
                              size_t data_size,
                              void *p_data,
                              size_t *p_data_length,
                              struct psa_storage_info_t *file_info
                             )
{
    psa_status_t status = PSA_ERROR_INVALID_ARGUMENT;
    size_t n = 0;

    if( data_offset + data_size < data_offset )
        goto exit;
#if SIZE_MAX < 0xffffffff
    if( data_offset + data_size > SIZE_MAX )
        goto exit;
#endif
    if( data_offset + data_size > file_info->size )
        goto exit;

    status = PSA_ERROR_STORAGE_FAILURE;
#if LONG_MAX < 0xffffffff
    while( data_offset > LONG_MAX )
    {
        if( fseek( p_stream, LONG_MAX, SEEK_CUR ) != 0 )
            goto exit;
        data_offset -= LONG_MAX;
    }
#endif
    if( fseek( p_stream, data_offset, SEEK_CUR ) != 0 )
        goto exit;
    n = fread( p_data, 1, data_size, p_stream );
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
    return( status );
}


/* FUNCTION: psa_cs_get_info()
 *  PSA Storage get_info() implementation for both psa_its_get()
 *  and psa_ps_get().
 */
psa_status_t psa_cs_get( psa_storage_uid_t uid,
                         size_t data_offset,
                         size_t data_size,
                         void *p_data,
                         size_t *p_data_length,
                         psa_cs_api_t api )
{
    psa_status_t status;
    FILE *stream = NULL;
    struct psa_storage_info_t info;

    if( psa_cs_num_file_objects == PSA_CS_NUM_FILE_OBJECTS_SENTINEL )
    {
        status = psa_cs_init();
        if( status != PSA_SUCCESS ) {
            return status;
        }
    }
    status = psa_cs_read_file( uid, &info, &stream, api, NULL );
    if( status != PSA_SUCCESS )
        goto exit;

    status = psa_cs_get_core( stream, data_offset, data_size, p_data, p_data_length, &info );
exit:
    if( stream != NULL )
    {
        fclose( stream );
    }
    return( status );
}


/* FUNCTION: psa_cs_set()
 *  PSA Storage set() implementation for both psa_its_set()
 *  and psa_ps_set().
 *
 *  Summary of algorithm for creating file object to assist in recovery of files:
 *   1. file1.dat is copied to a temporary file e.g. file1.tmp.
 *   2. file1.tmp is modified with the set() operation.
 *   3. file1.tmp's pointer (stored in the file metadata inside the file) is
 *      switched to point to a new backup file1.bak.1. Note, this happens
 *      before file1.bak.1 has been created to aid in the recovery procedure.
 *   4. file1.tmp is copied to a create a new backup file file1.bak.1.
 *   5. An atomic rename() operation is used to replace file1.dat with
 *      file1.tmp. The set() operation has been sealed.
 *   6. The old backup file file1.bak.0 is deleted. This is the file with
 *      the earlier modification timestamp.
 *
 *  Note:
 *  - Step 1 is not necessary in the present implementation because each set
 *    operation receives all object data (psa_ps_set_extended() is not
 *    currently implemented, which would require this step).
 */

psa_status_t psa_cs_set( psa_storage_uid_t uid,
                         size_t data_length,
                         const void *p_data,
                         psa_storage_create_flags_t create_flags,
                         psa_cs_api_t api,
                         void *extended_data )
{
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char bak_new_filename[PSA_CS_FILENAME_LENGTH];
    char bak_old_filename[PSA_CS_FILENAME_LENGTH];
    char filename[PSA_CS_FILENAME_LENGTH];
    char tmp_filename[PSA_CS_FILENAME_LENGTH];
    char *magic_string = PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING;
    FILE *stream = NULL;
    psa_its_file_header_t header;
    size_t n;
    struct psa_storage_info_t info;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    uint8_t seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;

    psa_debug( "%s\n", "Entry" );
    if( psa_cs_num_file_objects == PSA_CS_NUM_FILE_OBJECTS_SENTINEL )
    {
        status = psa_cs_init();
        if( status != PSA_SUCCESS ) {
            goto err0;
        }
    }
    /* Check for resource/storage exhaustion */
    if( psa_cs_num_file_objects > PSA_STORAGE_FILE_MAX-1 )
    {
        psa_debug( "Error: num file objects (%d) exceeds max (%d)\n", psa_cs_num_file_objects, PSA_STORAGE_FILE_MAX );
        status = PSA_ERROR_INSUFFICIENT_STORAGE;
        goto err0;
    }
    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORATE_UID_INVALID_VALUE )
    {
        psa_debug( "%s\n", "Error: uid is invalid value (0)" );
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto err0;
    }

    /* As all files are stored on encrypted file system, a request for no confidentiality
     * is upgraded to confidentiality. Hence if set the PSA_STORAGE_FLAG_NO_CONFIDENTIALITY
     * bit is cleared. */
    if( create_flags & PSA_STORAGE_FLAG_NO_CONFIDENTIALITY )
        create_flags &= ~PSA_STORAGE_FLAG_NO_CONFIDENTIALITY;

    /* If the file object already exists and PSA_STORAGE_FLAG_WRITE_ONCE is set then do
     * not update the object. Note that recovery processing scenario 1 uses _set()
     * to recreate the file object, but the file object has been found to be missing
     * and the reading of the file will fail, and _set() processing will continue
     * as required.*/
    status = psa_cs_read_file( uid, &info, &stream, api, &seqnum );
    if( status == PSA_SUCCESS )
    {
        /* Step 1: Copy to pre-existing file to a tmp file.
         * - At present the processing is not required as only whole file
         *   objects are written. When set_extended() is implemented it
         *   will be required.
         * - If/when required Step 1 processing should be located here.
         * - Hence close the stream.
         */
        fclose( stream );
        stream = NULL;
        if( info.flags & PSA_STORAGE_FLAG_WRITE_ONCE )
        {
            status = PSA_ERROR_NOT_PERMITTED;
            goto err0;
        }
    }
    /* check for extended behaviour */
    if( extended_data )
    {
        /* This is a recovery procedure set() operation which uses the supplied seqnum
         * in the recovered xxxx.bkx */
        seqnum  = ( (psa_cs_extended_data_t *) extended_data )->seqnum;
    }
    /* Get xxxx.bak(old) filename while have seqnum value. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, bak_old_filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    /* Begin Step 2 processing. */
    magic_string = api == PSA_CS_API_PS ? PSA_PROTECTED_STORAGE_MAGIC_STRING : magic_string;
    memcpy( header.magic, magic_string, PSA_CS_MAGIC_LENGTH );
    header.magic[PSA_CS_MAGIC_LENGTH-1] = seqnum;
    header.size[0] = data_length & 0xff;
    header.size[1] = ( data_length >> 8 ) & 0xff;
    header.size[2] = ( data_length >> 16 ) & 0xff;
    header.size[3] = ( data_length >> 24 ) & 0xff;
    header.flags[0] = create_flags & 0xff;
    header.flags[1] = ( create_flags >> 8 ) & 0xff;
    header.flags[2] = ( create_flags >> 16 ) & 0xff;
    header.flags[3] = ( create_flags >> 24 ) & 0xff;

    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }

    /* Get the temporary filename and open the stream */
    get_filename_flags = PSA_CS_GET_FILENAME_F_TEMP_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, tmp_filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    stream = fopen( tmp_filename, "wb" );
    if( stream == NULL )
    {
        status = PSA_ERROR_GENERIC_ERROR;
        goto err0;
    }

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = fwrite( &header, 1, sizeof( header ), stream );
    if( n != sizeof( header ) )
    {
        goto err1;
    }
    n = fwrite( p_data, 1, data_length, stream );
    if( n != data_length )
    {
        /* The err1 processing will the close stream. */
        goto err1;
    }

    /* Step 2 is completed by flushing the data to backing store. */
    fflush( stream );

    /* Step 3. Set the xxxx.tmp internal seqnum to point xxxx_x+1.bak
     * file that doesn't exist yet (unless this is part of the recovery processing)*/
    header.magic[PSA_CS_MAGIC_LENGTH-1] = ++seqnum;
    ret = fseek( stream, PSA_CS_MAGIC_LENGTH-1, SEEK_SET );
    if( ret < 0 )
    {
        goto err1;
    }
    n = fwrite( &header.magic[PSA_CS_MAGIC_LENGTH-1], 1, sizeof( uint8_t ), stream );
    if( n != sizeof( uint8_t ) )
    {
        goto err1;
    }
    ret = fclose( stream );
    stream = NULL;
    if( ret != 0 )
    {
        goto err2;
    }

    /* Step 4. Create xxxx_x+1.bak. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, bak_new_filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err2;
    }
    status = psa_cs_copy_file( tmp_filename, bak_new_filename );
    if( status != PSA_SUCCESS )
    {
        goto err2;
    }

    /* Step 5. Rename xxxx.tmp to xxxx.dat */
    ret = rename_replace_existing( tmp_filename, filename );
    if( ret != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
        goto err3;
    }
    /*  Step 6. */
    if( strncmp( bak_new_filename, bak_old_filename, PSA_CS_FILENAME_LENGTH ) != 0 )
    {
        remove( bak_old_filename );
    }
    psa_cs_num_file_objects++;
    psa_cs_total_size += data_length;
    return ( status );

err3:
    remove( bak_new_filename );
err2:
    remove( tmp_filename );
err1:
    if( stream != NULL )
    {
        fclose( stream );
    }
err0:
    return ( status );
}


/* FUNCTION: psa_cs_remove()
 *  PSA Storage remove() implementation for both psa_its_remove()
 *  and psa_ps_remove().
 */
psa_status_t psa_cs_remove( psa_storage_uid_t uid, psa_cs_api_t api )
{
    uint8_t seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    psa_status_t status = PSA_ERROR_STORAGE_FAILURE;
    char filename[PSA_CS_FILENAME_LENGTH];
    char bak_filename[PSA_CS_FILENAME_LENGTH];
    FILE *stream;
    struct psa_storage_info_t info;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;

    psa_debug( " %s\n", "Entry" );
    if( psa_cs_num_file_objects == PSA_CS_NUM_FILE_OBJECTS_SENTINEL )
    {
        status = psa_cs_init();
        if( status != PSA_SUCCESS ) {
            return status;
        }
    }
    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORATE_UID_INVALID_VALUE )
    {
        return ( PSA_ERROR_INVALID_ARGUMENT );
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto exit;
    }
    status = psa_cs_read_file( uid, &info, &stream, api, &seqnum );
    if( status != PSA_SUCCESS )
    {
        goto exit;
    }
    if( info.flags & PSA_STORAGE_FLAG_WRITE_ONCE )
    {
        status = PSA_ERROR_NOT_PERMITTED;
        goto exit;
    }
    fclose( stream );
    stream = NULL;

    /* remove xxxx.bak first */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, bak_filename, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        goto exit;
    }
    remove( bak_filename );
    if( remove( filename ) != 0 )
    {
        status = PSA_ERROR_STORAGE_FAILURE;
    }
    else
    {
        psa_cs_num_file_objects--;
        psa_cs_total_size -= info.size;
    }
exit:
    if( stream != NULL )
    {
        fclose( stream );
    }
    return( status );
}


#ifdef PSA_STORAGE_TEST

/* uid reserved values for testing */
#define PSA_CS_TEST_UID1 0x01234567
#define PSA_CS_TEST_UID2 0x01234568
#define PSA_CS_TEST_UID3 0x01234569
#define PSA_CS_TEST_UID4 0x01234570

/* uid used internally in test routines */
#define PSA_CS_TEST_UID_RESERVED 0xffffffff

/* UID data test vector used for creating both xxxx(seqnum).dat and xxxx_<seqnum>.bak files */
const uint8_t psa_cs_testdata_vec1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
const size_t psa_cs_testdata_vec1_len = sizeof( psa_cs_testdata_vec1 );

/* UID data test vector used for creating both only xxxx_<seqnum>.bak files, intended to be different to
 * psa_cs_testdata_vec1. */
const uint8_t psa_cs_testdata_vec2[] = {0x02, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
const size_t psa_cs_testdata_vec2_len = sizeof( psa_cs_testdata_vec2 );
const uint8_t psa_cs_testdata_vec3[] = {0x03, 0x03, 0x07, 0x0c, 0x12, 0x76, 0x28, 0xf8, 0xe7, 0x6c, 0x51, 0x4a, 0x33, 0x82, 0x41, 0xaa, 0xbb, 0xcc};
const size_t psa_cs_testdata_vec3_len = sizeof( psa_cs_testdata_vec3 );


/* FUNCTION: psa_cs_test_create_bak_file()
 *  Create 1 xxxx.bak files with specific sequence number but without xxxx.dat file.
 *  This is achieved as follows:
 *  - set(uid1)
 * - remove(dat_filename1)
 */
static psa_status_t psa_cs_test_create_bak_file( psa_storage_uid_t uid, psa_storage_create_flags_t create_flags, psa_cs_extended_data_t *data, const void *uid_data, size_t uid_data_length )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid2_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* NB: have to decrement sequence number supplied to _set() because creation of bak files will be
     * with the seqnum+1. This seqnum is used for 1) the filename <uid>_<seqnum>.bak and 2) the seqnum
     * stored inside <uid>_<seqnum>.bak.
     * Create <uid>_<seqnum1>.dat & <uid>_<seqnum1>.bak
     */
    data->seqnum--;
    status = psa_cs_set( PSA_CS_TEST_UID_RESERVED, uid_data_length, uid_data, create_flags, data->api, (psa_cs_extended_data_t *) data );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    /* Delete <uid>_<seqnum1>.dat */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= data->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( PSA_CS_TEST_UID_RESERVED, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    remove( uid_fn );
    /* _set() will have increase file count. Decrement this count as the .dat file has been removed. */
    psa_cs_num_file_objects--;

    /* Rename <uid2>_<seqnum2>.bak to <uid>_<seqnum2>.bak */
    data->seqnum++;
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= data->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, data->seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= data->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( PSA_CS_TEST_UID_RESERVED, uid2_fn, get_filename_flags, data->seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    ret = rename( uid2_fn, uid_fn );
    if( ret < 0 )
    {
        status = PSA_ERROR_GENERIC_ERROR;
    }
err:
    return status;
}


/* FUNCTION: psa_cs_test_create_dat_file()
 *  Create 1 xxxx.dat files with specific sequence number but without xxxx.bak file.
 *  This is achieved as follows:
 *  - set(uid1).
 *  - remove(bak_filename1).
 */
static psa_status_t psa_cs_test_create_dat_file( psa_storage_uid_t uid, psa_storage_create_flags_t create_flags, psa_cs_extended_data_t *data )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* NB: have to decrement sequence number supplied to _set() because creation of bak files will be
     * with the seqnum+1. This seqnum is used for 1) the filename <uid>_<seqnum>.bak and 2) the seqnum
     * stored inside <uid>_<seqnum>.bak.
     * Create <uid>_<seqnum1>.dat & <uid>_<seqnum1>.bak
     */
    data->seqnum--;
    status = psa_cs_set( uid, psa_cs_testdata_vec2_len, (void *) psa_cs_testdata_vec2, create_flags, data->api, (psa_cs_extended_data_t *) data );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    /* Delete <uid>_<seqnum>.bak */
    data->seqnum++;
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= data->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, data->seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    ret = remove( uid_fn );
    if( ret < 0 )
    {
        status = PSA_ERROR_DOES_NOT_EXIST;
    }
err:
    return status;
}


/* FUNCTION: psa_cs_test_create_bak_files()
 *  Create 2 back files with same uid but different sequence numbers.
 *  - create <uid1>_<seqnum1>.bak
 *  - create <uid1>_<seqnum2>.bak
*/
static psa_status_t psa_cs_test_create_bak_files( psa_storage_uid_t uid1, uint8_t seqnum1, uint8_t seqnum2, psa_storage_create_flags_t create_flags )
{
    char uid1_fn[PSA_CS_FILENAME_LENGTH];
    char uid2_fn[PSA_CS_FILENAME_LENGTH];
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_cs_api_t api = PSA_CS_API_PS;
    const psa_storage_uid_t uid2 = PSA_CS_TEST_UID_RESERVED;
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT };

    /* Create <uid1>_<seqnum1>.bak.*/
    ex_data.seqnum = seqnum1;
    status = psa_cs_test_create_bak_file( uid1, create_flags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    /* Create <uid2>_<seqnum2>.bak */
    ex_data.seqnum = seqnum2;
    status = psa_cs_test_create_bak_file( uid2, create_flags, &ex_data, psa_cs_testdata_vec3, psa_cs_testdata_vec3_len );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }

    /* Rename <uid2>_<seqnum2>.bak to <uid1>_<seqnum2>.bak */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid1, uid1_fn, get_filename_flags, seqnum2 );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid2, uid2_fn, get_filename_flags, seqnum2 );
    if( status != PSA_SUCCESS )
    {
        goto err;
    }
    rename( uid2_fn, uid1_fn );
err:
    return status;
}

/* filter */
typedef int ( *psa_scandir_filter )( const struct dirent * );


/* FUNCTION: psa_cs_test_init()
 *  Put the code/system into the state it would have on startup
 * ARGUMENTS:
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_test_init( uint32_t delete_files )
{
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    char filename[PSA_CS_FILENAME_LENGTH];
    int i = 0;
    int j = 0;
    int num_files = 0;
    psa_cs_recovery_state_t state;
    psa_scandir_filter filters[] = {psa_cs_bad_file_filter, psa_cs_bak_file_filter, psa_cs_dat_file_filter, psa_cs_tmp_file_filter };
    struct dirent **list[] = {state.bad_list, state.bak_list, state.dat_list, state.tmp_list };

    psa_cs_num_file_objects = PSA_CS_NUM_FILE_OBJECTS_SENTINEL;

    /* remove any data object remaining */
    if ( delete_files )
    {
        memset( &state, 0 , sizeof( state ) );
        for( i = 0; i < PSA_CS_API_MAX; i++ )
        {
            for( j = 0; j < 4; j++ )
            {
                snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[i] );
                num_files = scandir( state.dirname, &list[j], filters[j], versionsort );
                while( num_files-- )
                {
                    snprintf( filename, PSA_CS_FILENAME_LENGTH, "%s%s", state.dirname, list[j][num_files]->d_name );
                    remove( filename );
                    free( list[j][num_files] );
                }
                free( list[j] );
            }
        }
    }
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_test_case_init()
 *  Create a other uid files so there are present during recovery processing
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_test_case_init( psa_cs_recovery_state_t *state, psa_storage_create_flags_t cflags, psa_cs_extended_data_t *ex_data )
{
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_set( PSA_CS_TEST_UID1, psa_cs_testdata_vec1_len, (void *) psa_cs_testdata_vec1, cflags, state->api, (void *) ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 1 );
    status = psa_cs_set( PSA_CS_TEST_UID3, psa_cs_testdata_vec1_len, (void *) psa_cs_testdata_vec1, cflags, state->api, (void *) ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 2 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_test_case_deinit()
 *  Destroy uid files created in psa_cs_test_case_init().
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_test_case_deinit( psa_cs_recovery_state_t *state, psa_storage_create_flags_t cflags, uint8_t seqnum )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_remove( PSA_CS_TEST_UID1, state->api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force removal */
        get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
        get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( PSA_CS_TEST_UID1, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;

        get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
        get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( PSA_CS_TEST_UID1, uid_fn, get_filename_flags, seqnum );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );

        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 1 );

    status = psa_cs_remove( PSA_CS_TEST_UID3, state->api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force removal */
        get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
        get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( PSA_CS_TEST_UID3, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;

        get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
        get_filename_flags |= state->api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( PSA_CS_TEST_UID3, uid_fn, get_filename_flags, seqnum );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
    }
    /* Check the number of file objects is the same as at the start of testing */
    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1_seqnum()
 *  Helper funtion for recovery test case 1 to do the following:
 *   - init some background uid files.
 *   - create xxxx(seqnum_old).bak and xxxx_<seqnum_new>.bak
 *   - run recovery
 *   - check correct xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 *   seqnum_old     first seqnum
 *   seqnum_new     second seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc1_seqnum( uint8_t seqnum_old, uint8_t seqnum_new, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t uid_data[psa_cs_testdata_vec2_len];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec3_len;
    size_t uid_data_length = psa_cs_testdata_vec3_len;

    psa_debug( " Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d \n", seqnum_old, seqnum_new, cflags );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );
    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    status = psa_cs_test_create_bak_files( uid, seqnum_old, seqnum_new, cflags );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 2 );
    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    /* _init() should have recovered 1 file */
    psa_assert( psa_cs_num_file_objects == 3 );

    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum_new+1,
     * - <uid>_<seqnum_new+1>.bak file
     * - <uid>_<seqnum_old>.bak doesnt exist
     * - <uid>_<seqnum_new>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == (uint8_t) ( seqnum_new + 1 ) );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Check xxxx.dat data is as expected i.e. its the same as that used to create xxxx.bak file. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    ret = memcmp( psa_cs_testdata_vec3, uid_data, psa_cs_testdata_vec3_len );
    psa_assert( ret == 0 );
    psa_assert( uid_data_length == psa_cs_testdata_vec3_len );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_bak_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == (uint8_t) ( seqnum_new + 1 ) );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force remove */
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;
        ret = remove( uid_bak_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_old );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_new );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    /* Check the number of file objects is the same as at the start of testing */
    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1_core()
 *  Module test function for Recover Test Case 1 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc1_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc1a_seqnum_old = 2;
    const uint8_t tc1a_seqnum_new = 3;
    const uint8_t tc1b_seqnum_old = 254;
    const uint8_t tc1b_seqnum_new = 255;
    const uint8_t tc1c_seqnum_old = 255;
    const uint8_t tc1c_seqnum_new = 0;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc1_seqnum( tc1a_seqnum_old, tc1a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc1_seqnum( tc1b_seqnum_old, tc1b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc1_seqnum( tc1c_seqnum_old, tc1c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1()
 *  Module test function for Recover Test Case 1, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - Missing xxxx.dat, 2 xxxx.bak files exists. Test code recovers xxxx.dat file
 *     with latest bak_seqnum.
 *      - tc1a) no xxxx.dat, xxxx_<seqnum=2>.bak, xxxx_<seqnum=3>.bak.
 *      - tc1b) no xxxx.dat, xxxx_<seqnum=254>.bak, xxxx_<seqnum=255>.bak.
 *      - tc1c) no xxxx.dat, xxxx_<seqnum=255>.bak, xxxx_<seqnum=0>.bak.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc1( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc1_core( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc101()
 *  Module test function for Recover Test Case 101, which is as follows:
 *   - Same as tc1 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc101( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc1_core( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc2_seqnum()
 *  Helper funtion for recovery test case 1 to do the following:
 *   - init some background uid files.
 *   - create 1 xxxx_<seqnum>.bak
 *   - run recovery
 *   - check correct xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 *   seqnum     first seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc2_seqnum( uint8_t seqnum, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    uint8_t uid_data[psa_cs_testdata_vec2_len];
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec2_len;
    size_t uid_data_length = psa_cs_testdata_vec2_len;

    psa_debug( " %s\n", "Entry" );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );

    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );
    psa_assert( strlen( state.dirname ) > 0 );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    /* Create <uid1>_<seqnum1>.bak.*/
    status = psa_cs_test_create_bak_file( uid, cflags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 2 );
    /* perform recovery */
    psa_cs_test_init( 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum+1,
     * - <uid>_<seqnum+1>.bak file
     * - <uid>_<seqnum>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == (uint8_t) ( seqnum + 1 ) );

    /* Check xxxx.dat data is as expected i.e. its the same as that used to create xxxx.bak file. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    ret = memcmp( psa_cs_testdata_vec2, uid_data, psa_cs_testdata_vec2_len );
    psa_assert( ret == 0 );
    psa_assert( uid_data_length == psa_cs_testdata_vec2_len );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == (uint8_t) ( seqnum + 1 ) );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Cleanup uid.dat and uid_<seqnum>.bak */
    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force removal */
        get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
        get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;

        get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
        get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
        status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum + 1 );
        psa_assert( status == PSA_SUCCESS );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( r_seqnum == (uint8_t) ( seqnum + 1 ) );
    psa_assert( p_stream == NULL );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}

/* FUNCTION: psa_ps_test_tc2_core()
 *  Module test core function for Recover Test Case 2.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc2_core ( psa_storage_create_flags_t cflags )
{
    const uint8_t tc2a_seqnum_old = 2;
    const uint8_t tc2b_seqnum_old = 254;
    const uint8_t tc2c_seqnum_old = 255;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc2_seqnum( tc2a_seqnum_old, cflags ) == 0 );
    psa_assert( psa_ps_test_tc2_seqnum( tc2b_seqnum_old, cflags ) == 0 );
    psa_assert( psa_ps_test_tc2_seqnum( tc2c_seqnum_old, cflags ) == 0 );
    return PSA_SUCCESS;
}

/* FUNCTION: psa_ps_test_tc2()
 *  Module test function for Recover Test Case 2, which is as follows:
 *   - Missing xxxx.dat, 1 xxxx.bak file exists. Test code recovers xxxx.dat file
 *     with xxxx.bak.
 *      - tc2a) no xxxx.dat, xxxx_<seqnum=2>.bak.
 *      - tc2b) no xxxx.dat, xxxx_<seqnum=254>.bak.
 *      - tc2c) no xxxx.dat, xxxx_<seqnum=255>.bak.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc2( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc2_core ( PSA_STORAGE_FLAG_NONE );
}

/* FUNCTION: psa_ps_test_tc102()
 *  Module test function for Recover Test Case 2, which is as follows:
 *   - Same as tc2 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc102( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc2_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc51_seqnum()
 *  Helper function for recovery test case 51 to do the following:
 *   - init some background uid files.
 *   - create xxxx(seqnum_new).dat and 1 xxxx_<seqnum_old>.bak
 *   - run recovery
 *   - check correct xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 *   seqnum_old     first seqnum
 *   seqnum_new     second seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc51_seqnum( uint8_t seqnum_old, uint8_t seqnum_new, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t uid_data[psa_cs_testdata_vec1_len];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec1_len;
    size_t uid_data_length = psa_cs_testdata_vec1_len;

    psa_debug( " Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d\n", seqnum_old, seqnum_new, cflags );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );

    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    /* Create xxxx(seqnum_new).dat & xxxx_<seqnum_new>.bak */
    ex_data.seqnum = (uint8_t) ( seqnum_new - 1 );
    status = psa_cs_set( uid, psa_cs_testdata_vec1_len, (void *) psa_cs_testdata_vec1, cflags, state.api, (void *) &ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Create <uid4>_<seqnum_old>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_old;
    status = psa_cs_test_create_bak_file( PSA_CS_TEST_UID4, cflags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Rename <uid4>_<seqnum_old>.bak to <uid>_<seqnum_old>.bak */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( PSA_CS_TEST_UID4, uid_fn, get_filename_flags, seqnum_old );
    psa_assert( status == PSA_SUCCESS );
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, seqnum_old );
    psa_assert( status == PSA_SUCCESS );
    ret = rename( uid_fn, uid_bak_fn );
    psa_assert( ret == 0 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum_new,
     * - <uid>_<seqnum_new>.bak file
     * - <uid>_<seqnum_old>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum_new );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Check xxxx.dat data is as expected i.e. it hasn't changed from that used to create it. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    ret = memcmp( psa_cs_testdata_vec1, uid_data, psa_cs_testdata_vec1_len );
    psa_assert( ret == 0 );
    psa_assert( uid_data_length == psa_cs_testdata_vec1_len );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_bak_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum_new );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force remove */
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;
        ret = remove( uid_bak_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );

    /* Check xxxx_<seqnum_old>.bak is not present */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_old );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_new );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc51_core()
 *  Module test function for Recover Test Case 51 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc51_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc51a_seqnum_old = 2;
    const uint8_t tc51a_seqnum_new = 3;
    const uint8_t tc51b_seqnum_old = 254;
    const uint8_t tc51b_seqnum_new = 255;
    const uint8_t tc51c_seqnum_old = 255;
    const uint8_t tc51c_seqnum_new = 0;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc51_seqnum( tc51a_seqnum_old, tc51a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc51_seqnum( tc51b_seqnum_old, tc51b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc51_seqnum( tc51c_seqnum_old, tc51c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc51()
 *  Module test function for Recover Test Case 51, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - 2 xxxx.bak files exists, check the old one is removed
 *     with earliest bak_seqnum, and check xxxx.dat remains the same.
 *      - tc51a) xxxx(seqnum=3).dat, xxxx_<seqnum=2>.bak, xxxx_<seqnum=3>.bak.
 *      - tc51b) xxxx(seqnum=255).dat, xxxx_<seqnum=254>.bak, xxxx_<seqnum=255>.bak.
 *      - tc51c) xxxx(seqnum=0).dat, xxxx_<seqnum=255>.bak, xxxx_<seqnum=0>.bak.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc51( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc51_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc151()
 *  Module test function for Recover Test Case 51, which is as follows:
 *   - Same as tc51 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc151( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc51_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc52_seqnum()
 *  Helper function for recovery test case 52 to do the following:
 *   - init some background uid files.
 *   - create xxxx(seqnum_old).dat and 1 xxxx_<seqnum_new>.bak
 *   - run recovery
 *   - check correct xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 *   seqnum_old     first seqnum
 *   seqnum_new     second seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc52_seqnum( uint8_t seqnum_old, uint8_t seqnum_new, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t uid_data[psa_cs_testdata_vec1_len];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec2_len;
    size_t uid_data_length = psa_cs_testdata_vec2_len;

    psa_debug( " Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d\n", seqnum_old, seqnum_new, cflags );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );

    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    /* Create xxxx(seqnum_new).dat & xxxx_<seqnum_old>.bak */
    ex_data.seqnum = (uint8_t) ( seqnum_old - 1 );
    status = psa_cs_set( uid, psa_cs_testdata_vec1_len, (void *) psa_cs_testdata_vec1, cflags, state.api, (void *) &ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Create <uid4>_<seqnum_new>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_new;
    status = psa_cs_test_create_bak_file( PSA_CS_TEST_UID4, cflags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    psa_assert( status == PSA_SUCCESS );

    /* Rename <uid4>_<seqnum_new>.bak to <uid>_<seqnum_new>.bak */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( PSA_CS_TEST_UID4, uid_fn, get_filename_flags, seqnum_new );
    psa_assert( status == PSA_SUCCESS );
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, seqnum_new );
    psa_assert( status == PSA_SUCCESS );
    ret = rename( uid_fn, uid_bak_fn );
    psa_assert( ret == 0 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Check xxxx(seqnum_new).dat exists */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum_new );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Check xxxx.dat data is as expected i.e. it's the same as uid_<seqnum_new>.bak data. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    ret = memcmp( psa_cs_testdata_vec2, uid_data, psa_cs_testdata_vec2_len );
    psa_assert( ret == 0 );
    psa_assert( uid_data_length == psa_cs_testdata_vec2_len );

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_bak_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum_new );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force remove */
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;
        ret = remove( uid_bak_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );

    /* Check xxxx_<seqnum_old>.bak is not present */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_old );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    /* Check xxxx_<seqnum_new>.bak is not present */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_new );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc52_core()
 *  Module test function for Recover Test Case 52 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc52_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc52a_seqnum_old = 2;
    const uint8_t tc52a_seqnum_new = 3;
    const uint8_t tc52b_seqnum_old = 254;
    const uint8_t tc52b_seqnum_new = 255;
    const uint8_t tc52c_seqnum_old = 255;
    const uint8_t tc52c_seqnum_new = 0;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc52_seqnum( tc52a_seqnum_old, tc52a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc52_seqnum( tc52b_seqnum_old, tc52b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc52_seqnum( tc52c_seqnum_old, tc52c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc52()
 *  Module test function for Recover Test Case 52, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - 2 xxxx.bak files exists, check dat file updated from latest bak file.
 *     with xxx and data xxx
 *     with earliest bak_seqnum, and check xxxx.dat remains the same.
 *      - tc52a) xxxx(seqnum=2).dat, xxxx_<seqnum=2>.bak, xxxx_<seqnum=3>.bak.
 *      - tc52b) xxxx(seqnum=254).dat, xxxx_<seqnum=254>.bak, xxxx_<seqnum=255>.bak.
 *      - tc52c) xxxx(seqnum=255).dat, xxxx_<seqnum=255>.bak, xxxx_<seqnum=0>.bak.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc52( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc52_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc152()
 *  Module test function for Recover Test Case 152, which is as follows:
 *   - Same as tc52 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc152( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc52_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc53_seqnum()
 *  Helper function for recovery test case 53 to do the following:
 *   - init some background uid files.
 *   - create xxxx(seqnum_dat).dat and 1 xxxx_<seqnum_bak>.bak
 *   - run recovery
 *   - check correct xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc53_seqnum( uint8_t seqnum_dat, uint8_t seqnum_bak, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t uid_data[psa_cs_testdata_vec1_len];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_bak };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec2_len;
    size_t uid_data_length = psa_cs_testdata_vec2_len;

    psa_debug( " Entry: seqnum_dat=%d, seqnum_bak=%d, cflags=%d\n", seqnum_dat, seqnum_bak, cflags );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );

    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    /* Create <uid>_<seqnum_dat>.dat file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_dat;
    status = psa_cs_test_create_dat_file( uid, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Create <uid>_<seqnum_bak>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_bak;
    status = psa_cs_test_create_bak_file( uid, cflags, &ex_data, psa_cs_testdata_vec1, psa_cs_testdata_vec1_len );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Check xxxx(seqnum_bak).dat exists */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );

    if( (uint8_t) ( seqnum_dat - seqnum_bak ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* seqnum_dat > seqnum_bak */
        psa_assert( r_seqnum == seqnum_dat );
    }
    else
    {
        /* seqnum_dat < seqnum_bak */
        psa_assert( r_seqnum == seqnum_bak );
    }
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Check xxxx.dat data is as expected i.e. it's the same as uid_<seqnum_bak>.bak data. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    if( (uint8_t) ( seqnum_dat - seqnum_bak ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* seqnum_dat > seqnum_bak */
        ret = memcmp( psa_cs_testdata_vec2, uid_data, psa_cs_testdata_vec2_len );
        psa_assert( uid_data_length == psa_cs_testdata_vec2_len );
        psa_assert( ret == 0 );
    }
    else
    {
        /* seqnum_dat < seqnum_bak */
        ret = memcmp( psa_cs_testdata_vec1, uid_data, psa_cs_testdata_vec1_len );
        psa_assert( uid_data_length == psa_cs_testdata_vec1_len );
        psa_assert( ret == 0 );
    }

    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_bak_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    if((uint8_t) ( seqnum_dat - seqnum_bak ) < PSA_CS_FILE_HEADER_MAGIC_SEQNUM_MAX/2 )
    {
        /* seqnum_dat > seqnum_bak */
        psa_assert( r_seqnum == seqnum_dat );
    }
    else
    {
        /* seqnum_dat < seqnum_bak */
        psa_assert( r_seqnum == seqnum_bak );
    }
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force remove */
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;
        ret = remove( uid_bak_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );
    /* Check xxxx_<seqnum_dat>.bak is not present */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, seqnum_dat );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_ERROR_DOES_NOT_EXIST );
    psa_assert( p_stream == NULL );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_bak + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc53_core()
 *  Module test function for Recover Test Case 53 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc53_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc53a_seqnum_dat = 3;
    const uint8_t tc53a_seqnum_bak = 2;
    const uint8_t tc53b_seqnum_dat = 255;
    const uint8_t tc53b_seqnum_bak = 254;
    const uint8_t tc53c_seqnum_dat = 0;
    const uint8_t tc53c_seqnum_bak = 255;
    const uint8_t tc53d_seqnum_dat = 1;
    const uint8_t tc53d_seqnum_bak = 0;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc53_seqnum( tc53a_seqnum_dat, tc53a_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53b_seqnum_dat, tc53b_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53c_seqnum_dat, tc53c_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53d_seqnum_dat, tc53d_seqnum_bak, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc53()
 *  Module test function for Recover Test Case 53, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - xxxx.dat file exists.
 *   - 1 bak present but files dont have matching sequence number and dat_seq > bak_seqnum. check new xxxx.bak is created
 *      - dat_seqnum=3, bk1_seqnum=2
 *      - dat_seqnum=255, bk1_seqnum=254
 *      - dat_seqnum=0, bk1_seqnum=255
 *      - dat_seqnum=1, bk1_seqnum=0
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc53( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc53_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc153()
 *  Module test function for Recover Test Case 153, which is as follows:
 *   - Same as psa_ps_test_tc153() except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc153( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc53_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc54_core()
 *  Module test function for Recover Test Case 54 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc54_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc54a_seqnum_dat = 3;
    const uint8_t tc54a_seqnum_bak = 4;
    const uint8_t tc54b_seqnum_dat = 254;
    const uint8_t tc54b_seqnum_bak = 255;
    const uint8_t tc54c_seqnum_dat = 255;
    const uint8_t tc54c_seqnum_bak = 0;
    const uint8_t tc54d_seqnum_dat = 0;
    const uint8_t tc54d_seqnum_bak = 1;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc53_seqnum( tc54a_seqnum_dat, tc54a_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54b_seqnum_dat, tc54b_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54c_seqnum_dat, tc54c_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54d_seqnum_dat, tc54d_seqnum_bak, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc54()
 *  Module test function for Recover Test Case 54, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - xxxx.dat file exists.
 *   - 1 bak present but files dont have matching sequence number and dat_seq > bak_seqnum. check new xxxx.bak is created
 *      - dat_seqnum=3, bk1_seqnum=2
 *      - dat_seqnum=255, bk1_seqnum=254
 *      - dat_seqnum=0, bk1_seqnum=255
 *      - dat_seqnum=1, bk1_seqnum=0
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc54( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc54_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc154()
 *  Module test function for Recover Test Case 154, which is as follows:
 *   - Same as psa_ps_test_tc154() except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc154( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc54_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* Global for sharing filter uid value between client code and scandir filter callback function. */
static psa_storage_uid_t psa_cs_g_filter_uid = PSA_STORATE_UID_INVALID_VALUE;

/* NB: this function is not re-entrant (multi-thread safe) */
static int psa_cs_uid_bak_file_filter( const struct dirent *dir )
{
    const char *s = dir->d_name;
    char uid[PSA_CS_FILENAME_LENGTH];
    int len = strlen( s );
    int n = 0;

    if( len >= 0 )
    {
        n = psa_cs_bak_file_filter( dir );
        if ( n == 0 )
        {
            return 0;
        }

        n = snprintf( uid, PSA_CS_FILENAME_LENGTH, PSA_CS_FILENAME_PATTERN, (unsigned long ) ( psa_cs_g_filter_uid >> 32 ), (unsigned long) ( psa_cs_g_filter_uid & 0xffffffff ));
        if (strncmp( s, uid, PSA_UID_STRING_LENGTH ) == 0 )
        {
            return 1;
        }
    }
    return 0;
}


/* FUNCTION: psa_ps_test_tc55_seqnum()
 *  Helper function for recovery test case 55 to do the following:
 *   - init some background uid files.
 *   - create xxxx.dat and remove its xxxx.bak
 *   - run recovery
 *   - check xxxx.dat and xxxx.bak now exist
 *   - deinit some background uid files.
 * ARGUMENTS:
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc55_seqnum( uint8_t seqnum, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    uint8_t uid_data[psa_cs_testdata_vec1_len];
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_NONE;
    FILE *p_stream = NULL;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum };
    const size_t uid_data_offset = 0;
    const size_t uid_data_size = psa_cs_testdata_vec2_len;
    size_t uid_data_length = psa_cs_testdata_vec2_len;

    psa_debug( " Entry: seqnum=%d, cflags=%d\n", seqnum, cflags );
    memset( &info, 0, sizeof( info ) );
    memset( &state, 0, sizeof( state ) );

    psa_cs_test_init( 1 );
    state.api = PSA_CS_API_PS;
    snprintf( state.dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[state.api] );

    /* create uid file objects for uid1 and uid3, before and after the test uid2 file objects.*/
    status = psa_cs_test_case_init( &state, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );

    /* Create <uid1>_<seqnum1>.dat.*/
    status = psa_cs_test_create_dat_file( uid, cflags, &ex_data );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_init();
    psa_assert( status == PSA_SUCCESS );
    psa_assert( psa_cs_num_file_objects == 3 );

    /* Check xxxx(seqnum).dat exists */
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_fn, get_filename_flags, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    /* Check xxxx.dat data is as expected i.e. it hasn't changed. */
    status = psa_cs_get( uid, uid_data_offset, uid_data_size, uid_data, &uid_data_length, state.api );
    psa_assert( status == PSA_SUCCESS );
    ret = memcmp( psa_cs_testdata_vec2, uid_data, psa_cs_testdata_vec2_len );
    psa_assert( ret == 0 );
    psa_assert( uid_data_length == psa_cs_testdata_vec2_len );

    /* Check xxxx_<seqnum>.bak exists */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= state.api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, uid_bak_fn, get_filename_flags, r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    status = psa_cs_read_file_core( uid_bak_fn, &info, &p_stream, state.api, &r_seqnum );
    psa_assert( status == PSA_SUCCESS );
    psa_assert( r_seqnum == seqnum );
    psa_assert( p_stream != NULL );
    fclose( p_stream );

    status = psa_cs_remove( uid, state.api );
    if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
    {
        psa_assert( status == PSA_SUCCESS );
    }
    else
    {
        psa_assert( status == PSA_ERROR_NOT_PERMITTED );
        /* force remove */
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;
        ret = remove( uid_bak_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );
    /* Check other xxxx_<seqnum>.bak not present */
    psa_cs_g_filter_uid = uid;
    ret = scandir( state.dirname, &dirent_list, psa_cs_uid_bak_file_filter, versionsort );
    psa_cs_g_filter_uid = PSA_STORATE_UID_INVALID_VALUE;
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort );
    psa_assert( ret == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc55_core()
 *  Module test function for Recover Test Case 55 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc55_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc55a_seqnum = 0;
    const uint8_t tc55b_seqnum = 254;
    const uint8_t tc55c_seqnum = 255;
    const uint8_t tc55d_seqnum = 128;
    const uint8_t tc55e_seqnum = 1;

    psa_debug( " %s\n", "Entry" );
    psa_assert( psa_ps_test_tc55_seqnum( tc55a_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55b_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55c_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55d_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55e_seqnum, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc55()
 *  Module test function for Recover Test Case 55, which is as follows:
 *   - F_WRITE_ONCE not set.
 *   - 1 xxxx.dat files exists.
 *   - 0 xxxx.bak files exists.
 *   - check xxxx.bak file created
 *      - tc55a) xxxx(seqnum=0).dat
 *      - tc55b) xxxx(seqnum=254).dat.
 *      - tc55c) xxxx(seqnum=255).dat.
 *      - tc55d) xxxx(seqnum=128).dat
 *      - tc55e) xxxx(seqnum=1).dat
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc55( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc55_core ( PSA_STORAGE_FLAG_NONE );
}

/* FUNCTION: psa_ps_test_tc155()
 *  Module test function for Recover Test Case 155, which is as follows:
 *   - Same as tc55 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc155( void )
{
    psa_debug( " %s\n", "Entry" );
    return psa_ps_test_tc55_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


#endif  /* PSA_STORAGE_TEST */
