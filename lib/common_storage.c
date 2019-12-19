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
#define __USE_GNU
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>         /* for dirname() */

#include <dirent.h>
#include <stdlib.h>
#include <inttypes.h>       /* for PRIu64 */
#include <errno.h>          /* for errno */
#include <sys/syscall.h>    /* for gittid() */

#ifdef PSA_STORAGE_TEST
#include <pthread.h>
#endif

/* Terms used in comments and code:
 * - ITS    Internal Trusted Storage.
 * - OFD    fcntl() Open File Description (OFD) locks.
 * - PID    Process ID (PID) returned from getpid().
 * - PS     Protected Storage.
 * - RUID   Real user ID returned from getuid() (32 bit).
 *          RUID is the PSA storage partition identifier.
 * - seqnum Sequence number (8 bit).
 *   TID    Thread ID returned from syscall(SYS_gettid).
 * - UID    PSA storage unique file object ID (64 bit). */

#define PSA_CS_PREFIX PSA_STORAGE_FILE_C_STORAGE_PREFIX

/* PSA_CS_FILENAME_LOCK_OFD
 *   Name of the OFD lock file used to police access to shared
 *   resources. */
#define PSA_CS_FILENAME_LOCK_OFD     "psa_global" PSA_CS_LOCK_FILE_SUFFIX

/* PSA_CS_FILENAME_XUID_PATTERN is the base filename pattern used for RUID, PID and TID patterns. */
#define PSA_CS_FILENAME_XUID_PATTERN "%08lx_"

/* PSA_CS_FILENAME_XUID_PATTERN_LEN is the XUID pattern string length.
 * This is used for defining the RUID, PID and TID patterns. */
#define PSA_CS_FILENAME_XUID_PATTERN_LEN 9

/* PSA_CS_FILENAME_UID_PATTERN is the PSA Storage Unique ID (UID) pattern. */
#define PSA_CS_FILENAME_UID_PATTERN "%08lx%08lx"

/* PSA_CS_FILENAME_UID_PATTERN_LEN is the PSA_CS_FILENAME_UID_PATTERN string length. */
#define PSA_CS_FILENAME_UID_PATTERN_LEN 16

/* PSA_CS_FILENAME_RUID_PATTERN is the RUID filename pattern used in the file
 * object filename <RUID>_<UID>.dat. */
#define PSA_CS_FILENAME_RUID_PATTERN PSA_CS_FILENAME_XUID_PATTERN

/* PSA_CS_FILENAME_RUID_PATTERN_LEN is the PSA_CS_FILENAME_RUID_PATTERN string length. */
#define PSA_CS_FILENAME_RUID_PATTERN_LEN PSA_CS_FILENAME_XUID_PATTERN_LEN

/* PSA_CS_FILENAME_PATTERN is the filename pattern for the file data object used in the
 * filename <RUID>_<UID>.dat. */
#define PSA_CS_FILENAME_PATTERN     PSA_CS_FILENAME_RUID_PATTERN PSA_CS_FILENAME_UID_PATTERN

/* PSA_CS_FILENAME_PATTERN_LEN is the PSA_CS_FILENAME_PATTERN string length. */
#define PSA_CS_FILENAME_PATTERN_LEN (PSA_CS_FILENAME_RUID_PATTERN_LEN + PSA_CS_FILENAME_UID_PATTERN_LEN)

/* PSA_CS_BAK_FILENAME_PATTERN is the filename pattern for the file data object
 * backup filename <RUID>_<UID>_<seqnum>.bak. */
#define PSA_CS_BAK_FILENAME_PATTERN     PSA_CS_FILENAME_RUID_PATTERN PSA_CS_FILENAME_UID_PATTERN "_%02x"

/* PSA_CS_TMP_FILENAME_PATTERN is the file object temporary filename pattern of
 * the form <RUID>_<PID>_<TID>_<UID>.tmp. */
#define PSA_CS_FILENAME_PID_PATTERN                     PSA_CS_FILENAME_XUID_PATTERN
#define PSA_CS_FILENAME_TID_PATTERN                     PSA_CS_FILENAME_XUID_PATTERN
#define PSA_CS_TMP_FILENAME_RUID_PID_TID_PATTERN        PSA_CS_FILENAME_RUID_PATTERN PSA_CS_FILENAME_PID_PATTERN PSA_CS_FILENAME_TID_PATTERN
#define PSA_CS_TMP_FILENAME_PATTERN                     PSA_CS_FILENAME_RUID_PATTERN PSA_CS_FILENAME_PID_PATTERN PSA_CS_FILENAME_TID_PATTERN PSA_CS_FILENAME_UID_PATTERN
#define PSA_CS_LOCK_FILENAME_PATTERN                    PSA_CS_TMP_FILENAME_PATTERN
#define PSA_CS_OFD_LOCK_FILENAME_PATTERN                PSA_CS_FILENAME_RUID_PATTERN

/* PSA_CS_TMP FILENAME_PATTERN_LEN is the PSA_CS_FILENAME_PATTERN string length. */
#define PSA_CS_FILENAME_PID_PATTERN_LEN                 PSA_CS_FILENAME_XUID_PATTERN_LEN
#define PSA_CS_FILENAME_TID_PATTERN_LEN                 PSA_CS_FILENAME_XUID_PATTERN_LEN
#define PSA_CS_FILENAME_RUID_PID_TID_PATTERN_LEN        (PSA_CS_FILENAME_RUID_PATTERN_LEN + PSA_CS_FILENAME_PID_PATTERN_LEN + PSA_CS_FILENAME_TID_PATTERN_LEN )
#define PSA_CS_TMP_FILENAME_PATTERN_LEN                 (PSA_CS_FILENAME_RUID_PATTERN_LEN + PSA_CS_FILENAME_PID_PATTERN_LEN + PSA_CS_FILENAME_TID_PATTERN_LEN + PSA_CS_FILENAME_UID_PATTERN+LEN )
#define PSA_CS_LOCK_FILENAME_PATTERN_LEN                PSA_CS_TMP_FILENAME_PATTERN_LEN
#define PSA_CS_OFD_LOCK_FILENAME_PATTERN_LEN            PSA_CS_FILENAME_RUID_PATTERN_LEN

/* File extensions. If the first char is "." then for
 * portability there should be at most 3 more characters.
 * - BAD files are temporary file names used by psa_cs_copy_file().
 * - BAK files are file object data file backup files.
 * - DATA files contain the file object data.
 * - LOCK files are used to share data between execution contexts without
 *   using mutexes for example.
 * - TEMP files are temporary files used in the set() operation, for example. */
#define PSA_CS_BAD_FILE_SUFFIX      ".bad"
#define PSA_CS_BAK_FILE_SUFFIX      ".bak"
#define PSA_CS_DATA_FILE_SUFFIX     ".psa"
#define PSA_CS_LOCK_FILE_SUFFIX     ".lck"
#define PSA_CS_TEMP_FILE_SUFFIX     ".tmp"
#define PSA_CS_TEMP_FILE_SUFFIX_LEN  (4+1)

/* psa_cs_get_filename() flags
 *   Defines for flags used with psa_cs_get_filename(). */
#define PSA_CS_GET_FILENAME_F_NONE                     0
#define PSA_CS_GET_FILENAME_F_API_ITS                  (1<<0)
#define PSA_CS_GET_FILENAME_F_BAK_FILE                 (1<<1)
#define PSA_CS_GET_FILENAME_F_DATA_FILE                (1<<2)
#define PSA_CS_GET_FILENAME_F_LOCK_FILE                (1<<3)
#define PSA_CS_GET_FILENAME_F_LOCK_OFD_FILE            (1<<4)
#define PSA_CS_GET_FILENAME_F_TEMP_FILE                (1<<5)

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

/* PSA_CS_UID_MAX: The maximum value of a UID.
 * See also PSA_STORAGE_UID_INVALID_VALUE. */
#define PSA_CS_UID_MAX      0xffffffffffffffff

#define PSA_TRUE 1
#define PSA_FALSE 0
#define PSA_SEQNUM_STRING_LENGTH 3

/* File objects created through the PS API are stored in the
 * of PSA_CS_PS_SUBPREFIX sub-directory of the
 * PSA_CS_PREFIX directory.  Note this symbol
 * must be the same length as PSA_CS_ITS_SUBPREFIX which is
 * used to compute PSA_CS_FILENAME_LENGTH.*/
#define PSA_CS_FILENAME_LENGTH                                                              \
    ( sizeof( PSA_CS_PREFIX ) - 1 +             /* Prefix without terminating 0. */         \
      sizeof( PSA_CS_ITS_SUBPREFIX ) - 1 +      /* Sub-prefix without terminating 0. */     \
      PSA_CS_FILENAME_PATTERN_LEN +             /* RUID + "_" + UID. */                     \
      PSA_SEQNUM_STRING_LENGTH +                /* "_" and 8-bit sequence number. */        \
      sizeof( PSA_CS_DATA_FILE_SUFFIX ) - 1 +   /* Suffix without terminating 0. */         \
      1                                         /* Terminating null byte. */                \
     )

#define PSA_CS_TMP_FILENAME_LENGTH                                              \
    ( PSA_CS_FILENAME_LENGTH +                                                  \
      PSA_CS_FILENAME_PID_PATTERN_LEN +       /* PID (32-bit number in hex) */  \
      PSA_CS_FILENAME_TID_PATTERN_LEN         /* TID (32-bit number in hex) */  \
     )

/* The maximum value of psa_storage_info_t.size */
#define PSA_CS_MAX_SIZE 0xffffffff

/* Size of general purpose processing buffer held on stack. */
#define PSA_DATA_BUFFER_SIZE 4096

/* The last byte of the magic string used for storing sequence number inside object files. */
#define PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING "PSA\0ITS\0"
#define PSA_PROTECTED_STORAGE_MAGIC_STRING "PSA\0PST\0"
#define PSA_CS_MAGIC_LENGTH 8

#define PSA_CS_NUM_FILE_OBJECTS_SENTINEL                0xffffffff

#ifdef PSA_STORAGE_DEBUG
#define psa_debug( _format, ... )                                              \
    do                                                                         \
    {                                                                          \
        if( PSA_STORAGE_DEBUG )                                                \
        {                                                                      \
            fprintf( stdout, "%s:"                                             \
                    PSA_CS_FILENAME_RUID_PATTERN                               \
                    PSA_CS_FILENAME_PID_PATTERN                                \
                    PSA_CS_FILENAME_TID_PATTERN _format, __FUNCTION__,         \
                    (unsigned long) getuid(), (unsigned long) getpid(), (unsigned long) syscall(SYS_gettid), __VA_ARGS__ );    \
        }                                                                      \
    } while ( 0 )
#else
    #define psa_debug( format, ... )
#endif

/* assert() support */
#ifdef PSA_STORAGE_TEST
#include <assert.h>
#define psa_assert( _predicate )                                               \
    do                                                                         \
    {                                                                          \
        if( ! ( _predicate ) )                                                 \
        {                                                                      \
            fprintf( stdout, "%s:%d\n", __FUNCTION__, __LINE__ );              \
            assert( 0 );                                                       \
        }                                                                      \
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
    struct dirent **lck_list;           // scandir list of files with PSA_CS_LOCK_FILE_SUFFIX extension
    struct dirent **tmp_list;           // scandir list of files with PSA_CS_TEMP_FILE_SUFFIX extension

    // ref_psa_cs_recovery_state_t_num_files
    uint32_t num_bak_files;             // number of entries in bak_list
    uint32_t num_bad_files;             // number of entries in bad_list
    uint32_t num_dat_files;             // number of entries in dat_list
    uint32_t num_lck_files;             // number of entries in lck_list
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


/* ENUMERATION: psa_cs_init_states_t
 *   State for initialization FSM.
 */
typedef enum _psa_cs_init_states_t
{
    PSA_CS_INIT_STATE_UNINITIALIZED = 0,    /* System starts in uninitialized state. */
    PSA_CS_INIT_STATE_INITIALIZING,         /* System is performing initialization e.g. recovery process. */
    PSA_CS_INIT_STATE_INITIALIZED,          /* System has successfully initialized. */
    PSA_CS_INIT_STATE_FAILED,               /* System failed to initialized. */
    PSA_CS_INIT_STATE_MAX,

} psa_cs_init_states_t;

/* Global to record the number of file objects created. */
static uint32_t psa_cs_num_file_objects = PSA_CS_NUM_FILE_OBJECTS_SENTINEL;

/* Global to record total space requested. */
static size_t psa_cs_total_size = 0;

/* Global to record system initialization state. */
static psa_cs_init_states_t psa_cs_init_fsm_state = PSA_CS_INIT_STATE_UNINITIALIZED;

/* Global to store the initialization execution context thread id. */
static pid_t psa_cs_init_tid = -1;

/* Forward declarations */
static psa_status_t psa_cs_get_core( FILE *p_stream, size_t data_offset, size_t data_size, void *p_data, size_t *p_data_length, struct psa_storage_info_t *file_info );


/* Filter functions e.g. for scandir().
 *   suffix   null terminated suffix string e.g. ".dat"
 */
static int psa_core_file_filter( const struct dirent *dir, const char *suffix )
{
    char ruids[PSA_CS_FILENAME_LENGTH];
    const char *s = dir->d_name;
    const int cs_suffix_len = strlen( suffix );
    int len = strlen( s ) - cs_suffix_len;
    const uid_t ruid = getuid();

    snprintf(ruids, PSA_CS_FILENAME_LENGTH, PSA_CS_FILENAME_RUID_PATTERN, (unsigned long) ruid);

    if( len >= 0 )
    {
        if( strncmp( s, ruids, PSA_CS_FILENAME_RUID_PATTERN_LEN ) == 0 )
        {
            if( strncmp( s + len, suffix, cs_suffix_len ) == 0 )
            {
                return 1;
            }
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

static int psa_cs_tmp_lck_file_filter_core( const struct dirent *dir, const char *suffix )
{
    char tmps_filter[PSA_CS_TMP_FILENAME_LENGTH];
    const char *s = dir->d_name;
    const int cs_suffix_len = strlen( suffix );
    int len = strlen( s ) - cs_suffix_len;
    const uid_t ruid = getuid();
    const pid_t pid = getpid();
    const pid_t tid = syscall(SYS_gettid);

    snprintf( tmps_filter, PSA_CS_TMP_FILENAME_LENGTH, PSA_CS_TMP_FILENAME_RUID_PID_TID_PATTERN, (unsigned long int) ruid, (unsigned long int) pid, (unsigned long int) tid );
    if( len >= 0 )
    {
        if( strncmp( s, tmps_filter, PSA_CS_FILENAME_RUID_PID_TID_PATTERN_LEN ) == 0 )
        {
            if( strncmp( s + len, suffix, cs_suffix_len ) == 0 )
            {
                return 1;
            }
        }
    }
    return 0;
}

static int psa_cs_tmp_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_TEMP_FILE_SUFFIX );
}

static int psa_cs_lck_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_LOCK_FILE_SUFFIX );
}

static int psa_cs_tmp_file_filter_ex( const struct dirent *dir )
{
    return psa_cs_tmp_lck_file_filter_core( dir, PSA_CS_TEMP_FILE_SUFFIX );
}

static int psa_cs_lck_file_filter_ex( const struct dirent *dir )
{
    return psa_cs_tmp_lck_file_filter_core( dir, PSA_CS_LOCK_FILE_SUFFIX );
}

static int psa_cs_bad_file_filter( const struct dirent *dir )
{
    return psa_core_file_filter( dir, PSA_CS_BAD_FILE_SUFFIX );
}


/* FUNCTION: psa_cs_get_mktemp_filename
 *  Generate a process and thread safe temporary filename using getuid(),
 *  getpid() and syscall(SYS_gettid) in the filename.
 *
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
    const uid_t ruid = getuid();
    const pid_t pid = getpid();
    const pid_t tid = syscall(SYS_gettid);

    psa_debug( "%s\n", "Entry");
    dup_fname = strndup( filename, PSA_CS_TMP_FILENAME_LENGTH );
    if (dup_fname == NULL )
    {
        goto err0;
    }
    dname = dirname( dup_fname );
    snprintf( filename, len, "%s/" PSA_CS_TMP_FILENAME_RUID_PID_TID_PATTERN "%s", dname, (unsigned long int) ruid, (unsigned long int) pid, (unsigned long int) tid, PSA_CS_BAD_FILE_SUFFIX );
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
    int ret = -1;
    size_t num_r = 0;
    size_t num_w = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    FILE *p_src_stream = NULL;
    FILE *p_dst_stream = NULL;
    struct stat file_stat;

    psa_debug( "%s\n", "Entry");

    /* Read the src_filename permissions setting, for duplicating permisions on the new file. */
    ret = stat( src_filename, &file_stat );
    if ( ret < 0 )
    {
        psa_debug( "Error: stat() failed with unexpected error (%d)\n", errno );
        goto err0;
    }

    p_src_stream = fopen( src_filename, "rb" );
    if( p_src_stream == NULL )
    {
        psa_debug( "Error: fopen(src_filename) failed with unexpected error (%d)\n", errno );
        goto err0;
    }

    mktemp_filename = strndup( dst_filename, PSA_CS_TMP_FILENAME_LENGTH );
    if( mktemp_filename == NULL )
    {
        psa_debug( "Error: strndup(dst_filename) failed with unexpected error (%d)\n", errno );
        goto err1;
    }
    status = psa_cs_get_mktemp_filename( mktemp_filename, PSA_CS_TMP_FILENAME_LENGTH );
    if ( status != PSA_SUCCESS )
    {
        goto err2;
    }

    p_dst_stream = fopen( mktemp_filename, "wb" );
    if( p_dst_stream == NULL )
    {
        psa_debug( "Error: fopen(mktemp_filename) failed with unexpected error (%d)\n", errno );
        goto err2;
    }

    while ( ( num_r = fread( data, sizeof( char ), PSA_DATA_BUFFER_SIZE, p_src_stream ) ) > 0 )
    {
        num_w = fwrite( data, sizeof( char ), num_r, p_dst_stream );
        if ( num_w != num_r )
        {
            psa_debug( "Error: fwrite(mktemp_filename) failed to write the required data (%d,%d)\n", (int) num_w, (int) num_r );
            status = PSA_ERROR_INSUFFICIENT_STORAGE;
            goto err3;
        }
    }
    if( !( file_stat.st_mode & S_IWUSR ) )
    {
        /* src_filename is a WRITE_ONCE file object.
         * Set permissions to be owner read-only for WRITE_ONCE file object. */
        ret = chmod( mktemp_filename, S_IRUSR );
        if( ret != 0 )
        {
            psa_debug( "Error: failed to read-only permission on WRITE_ONCE file (%d)\n", errno );
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


/* FUNCTION: psa_cs_get_filename()
 *  Return a path filename for object of form
 *      PSA_CS_PREFIX / API PREFIX / <ruid>_<uid> <_<seqnum>>. <extension>
 *  where
 *    <ruid> is PSA_CS_FILENAME_RUID_PATTERN_LEN characters for the 32bit uid returned from getuid(), plus "_".
 *    <uid> is PSA_CS_FILENAME_PATTERN_LEN characters for the 64bit uid.
 *    <seqnum> is a sequence number included in backup file names.
 *    <extension> is 3 characters indicating the file type e.g. data, temp, etc.
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
 *    PSA_CS_GET_FILENAME_F_LOCK_FILE
 *      Generate filename for creating a lock file to share uid between
 *      execution processes. This is used for testing.
 *    PSA_CS_GET_FILENAME_F_LOCK_OFD_FILE
 *      Generate filename for creating a OFD lock file which is used, for example,
 *      to ensure only one thread gets exclusive access to resources e.g. to
 *      perform the recover process. The lock file is generated in PSA_CS_PREFIX
 *      and not in one of the api specific storage directories.
 *    PSA_CS_GET_FILENAME_F_TEMP_FILE
 *      Generate filename for temporary file object data file xxx.tmp.
 *      This tmp file can be used in the recovery process
 */
static psa_status_t psa_cs_get_filename( psa_storage_uid_t uid, char *filename, const size_t len, uint32_t flags, uint8_t seqnum )
{
    char *subprefix = NULL;
    uid_t ruid = 0;
    pid_t pid = 0;
    pid_t tid = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( "%s\n", "Entry");

    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    subprefix = flags & PSA_CS_GET_FILENAME_F_API_ITS ? PSA_CS_ITS_SUBPREFIX: PSA_CS_PS_SUBPREFIX;
    ruid = getuid();

    if( flags & PSA_CS_GET_FILENAME_F_DATA_FILE )
    {
        snprintf( filename, len,
                          "%s%s" PSA_CS_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( ruid ),
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          PSA_CS_DATA_FILE_SUFFIX );
        status = PSA_SUCCESS;
    }
    else if( flags & PSA_CS_GET_FILENAME_F_TEMP_FILE )
    {
        pid = getpid();
        tid = syscall(SYS_gettid);
        snprintf( filename, len,
                          "%s%s" PSA_CS_TMP_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( ruid ),
                          (unsigned long) ( pid ),
                          (unsigned long) ( tid ),
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          PSA_CS_TEMP_FILE_SUFFIX );
        status = PSA_SUCCESS;
    }
    else if( flags & PSA_CS_GET_FILENAME_F_BAK_FILE )
    {
        snprintf( filename, len,
                          "%s%s" PSA_CS_BAK_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( ruid ),
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          (unsigned int) seqnum,
                          PSA_CS_BAK_FILE_SUFFIX );
        status = PSA_SUCCESS;
    }
    else if( flags & PSA_CS_GET_FILENAME_F_LOCK_FILE )
    {
        pid = getpid();
        tid = syscall(SYS_gettid);
        snprintf( filename, len,
                          "%s%s" PSA_CS_LOCK_FILENAME_PATTERN "%s",
                          PSA_CS_PREFIX,
                          subprefix,
                          (unsigned long) ( ruid ),
                          (unsigned long) ( pid ),
                          (unsigned long) ( tid ),
                          (unsigned long) ( uid >> 32 ),
                          (unsigned long) ( uid & 0xffffffff ),
                          PSA_CS_LOCK_FILE_SUFFIX );
        status = PSA_SUCCESS;
    }
    else if( flags & PSA_CS_GET_FILENAME_F_LOCK_OFD_FILE )
    {
        snprintf( filename, len, "%s" PSA_CS_OFD_LOCK_FILENAME_PATTERN "%s", PSA_CS_PREFIX, (unsigned long) ( ruid ), PSA_CS_FILENAME_LOCK_OFD );
        status = PSA_SUCCESS;
    }
    return( status );
}


/* FUNCTION: psa_cs_lock_ofd_take()
 *
 * This function gains ownership of the OFD lock file. The lock is used
 * to police access to resources shared by processes and/or threads. The
 * lock is required because:
 * - Only 1 execution context (either process or thread) can perform
 *   initialization, to the exclusion of all other processes/threads. While
 *   initialization is being performed:
 *   - No other execution context can perform initialization.
 *   - No other execution context can modify file objects (i.e. perform set()
 *     or remove() operations).
 * - There are resources shared by multiple threads (e.g. the
 *   psa_cs_num_file_objects counter) which protect against resource
 *   exhaustion) where a thread must gain exclusive ownership of the
 *   resource before updating it.
 * - Initialization has to be performed exclusively by one execution context
 *   because initialization runs the recovery process, which deletes .tmp
 *   files left in the store as a result of power failures. If a second
 *   execution process was performing a set() operation during this time (a
 *   normal part of which is creating an intermediate .tmp file) then the
 *   recovery process could delete this .tmp file thus causing errors.
 * ARGUMENTS:
 *  fd_lock     pointer to variable to store lock file descriptor.
 * RETURN:
 *  PSA_SUCCESS On success, fd_lock points to a valid file descriptor
 *              holding the lock.
 *  PSA_Xxx     Failed to take the lock
 */
static inline psa_status_t psa_cs_lock_ofd_take( int *fd_lock )
{
    char lock_filename[PSA_CS_FILENAME_LENGTH];
    int ret = -1;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_LOCK_OFD_FILE;
    const uint8_t unused_seqnum = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_storage_uid_t unused_uid = PSA_STORAGE_UID_INVALID_VALUE;
    struct flock lck = {
      .l_whence = SEEK_SET,
      .l_start = 0,
      .l_len = 1,
      .l_type = F_WRLCK,
    };

    psa_debug( "%s\n", "Entry");
    /* By default, make files rw only for the owner. */
    umask ( S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( fd_lock == NULL )
    {
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto out;
    }
    status = psa_cs_get_filename( unused_uid, lock_filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, unused_seqnum );
    if( status != PSA_SUCCESS )
    {
        goto out;
    }
    *fd_lock = open( lock_filename, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR );
    if( *fd_lock < 0 )
    {
        psa_debug( "Error: open() failed with unexpected error (%d)\n", errno );
        status = PSA_ERROR_GENERIC_ERROR;
        goto out;
    }
    /* have successfully created file */
    ret = fcntl (*fd_lock, F_OFD_SETLKW, &lck);
    if( ret < 0 )
    {
        psa_debug( "Error: fcntl(F_OFD_SETLKW,F_WRLCK) failed with unexpected error (%d)\n", errno );
        status = PSA_ERROR_GENERIC_ERROR;
        close( *fd_lock );
        *fd_lock = -1;
        goto out;
    }
    status = PSA_SUCCESS;
out:
    return status;
}


/* FUNCTION: psa_cs_lock_ofd_give()
 *   This function yields the OFD lock file. See psa_cs_lock_ofd_take()
 *   for further details.
 * ARGUMENTS:
 *  fd_lock     pointer to storing the lock file descriptor.
 */
static inline psa_status_t psa_cs_lock_ofd_give( int *fd_lock )
{
    int ret = -1;
    struct flock lck = {
      .l_whence = SEEK_SET,
      .l_start = 0,
      .l_len = 1,
      .l_type = F_UNLCK,
    };

    psa_debug( "%s\n", "Entry");
    if( fd_lock == NULL )
    {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    ret = fcntl ( *fd_lock, F_OFD_SETLKW, &lck );
    if( ret < 0 )
    {
        psa_debug( "Error: fcntl(F_OFD_SETLKW, F_UNLCK) failed with unexpected error (%d)\n", errno );
        close( *fd_lock );
        *fd_lock = -1;
        return PSA_ERROR_GENERIC_ERROR;
    }
    close( *fd_lock );
    *fd_lock = -1;
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_num_file_inc()
 *   Increment global statistics i.e. increment the total count of number of
 *   file objects in the system by 1, and increment total stored data by the
 *   supplied data_length.
 * ARGUMENTS:
 *  data_length         Add data_length to the total count of stored bytes.
 */
static inline psa_status_t psa_cs_num_file_inc( size_t data_length )
{
    int fd_lock = -1;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( "%s\n", "Entry");
    if( psa_cs_init_fsm_state != PSA_CS_INIT_STATE_INITIALIZING )
    {
        /* common case */
        status = psa_cs_lock_ofd_take( &fd_lock );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to take lock (%d)\n", status);
            goto out;
        }
        psa_cs_num_file_objects++;
        psa_cs_total_size += data_length;
        status = psa_cs_lock_ofd_give( &fd_lock );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to give lock (%d)\n", status);
            goto out;
        }

    }
    else
    {
        /* PSA_CS_INIT_STATE_INITIALIZING state implies the initialization
         * process has exclusive access and has already acquired the lock.
         * The counter(s) can be updated without taking the lock again. */
        psa_cs_num_file_objects++;
        psa_cs_total_size += data_length;
        status = PSA_SUCCESS;
    }
out:
    return status;
}

// todo consolidate _dec and _inc into 1 function

/* FUNCTION: psa_cs_num_file_dec()
 *   Decrement global statistics i.e. decrement the total count of number of
 *   file objects in the system by 1, and decrement total stored data by the
 *   supplied data_length.
 * ARGUMENTS:
 *  data_length         Subtract data_length from the total count of stored bytes.
 */
static inline psa_status_t psa_cs_num_file_dec( size_t data_length )
{
    int fd_lock = -1;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    psa_debug( "%s\n", "Entry");
    if( psa_cs_init_fsm_state != PSA_CS_INIT_STATE_INITIALIZING )
    {
        /* common case */
        status = psa_cs_lock_ofd_take( &fd_lock );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to take lock (%d)\n", status);
            goto out;
        }
        psa_cs_num_file_objects--;
        psa_cs_total_size -= data_length;
        status = psa_cs_lock_ofd_give( &fd_lock );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to give lock (%d)\n", status);
            goto out;
        }
    }
    else
    {
        /* PSA_CS_INIT_STATE_INITIALIZING state implies the initialization
         * process has exclusive access and has already acquired the lock.
         * The counter(s) can be updated without taking the lock again. */
        psa_cs_num_file_objects--;
        psa_cs_total_size -= data_length;
        status = PSA_SUCCESS;
    }
out:
    return status;
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

    psa_debug( "Entry: filename=%s\n", filename );
    *p_stream = fopen( filename, "rb" );
    if( *p_stream == NULL )
    {
        psa_debug( "Error: file doesn't exist (%s).\n", filename );
        status = PSA_ERROR_DOES_NOT_EXIST;
        goto err;
    }
    n = fread( &header, 1, sizeof( header ), *p_stream );
    if( n != sizeof( header ) )
    {
        psa_debug( "Error: file header corrupt (%s).\n", filename );
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
 *   uid         IN: unique file object ID.
 *   p_info      IN, OUT: pointer to information structure to receive psa_storage_info_t data read from file.
 *   p_stream    IN, OUT: pointer to pointer to opened stream.
 *   api         IN: whether this call in on the ITS or PS API.
 *   seqnum      OUT: sequence number read from the file and returned to caller
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

    psa_debug( "%s\n", "Entry");
    *p_stream = NULL;
    if( seqnum )
    {
        rf_seqnum = *seqnum;
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, rf_seqnum );
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

    psa_debug( "%s\n", "Entry");
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

    psa_debug( "%s\n", "Entry");
    /* Find <uid>_yyy+1.bak (the latest xxxx.bk file).*/
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
    psa_debug( "%s\n", "Entry");
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

    psa_debug( "%s\n", "Entry");
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

    psa_debug( "%s\n", "Entry");
    memset( &info, 0, sizeof( info ) );
    /* get dat_seqnum */
    snprintf( dat_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->dat_filename );
    status = psa_cs_read_file_core( dat_fn, &info, &p_stream, state->api, &dat_seqnum );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }

    /* Find <uid>_yyy+1.bak (the latest xxxx.bk file).*/
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
        psa_debug( "Error: Failed to read file (%s)\n", dat_fn );
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
        status = psa_cs_get_filename( state->min_uid, bak_fn, PSA_CS_FILENAME_LENGTH, get_filename_flags, dat_seqnum );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to get missing bak file from valid uid %" PRIu64 " and seqnum (%d).\n", state->min_uid, dat_seqnum );
            goto err1;
        }
        status = psa_cs_copy_file( dat_fn, bak_fn );
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: unable to recreate missing bak file (%s) from valid dat file (%s).\n", bak_fn, dat_fn );
            goto err1;
        }
        /* remove old bak file */
        snprintf( bak_fn, PSA_CS_FILENAME_LENGTH, "%s%s", state->dirname, state->bka_filename );
        ret = remove( bak_fn );
        if ( ret < 0 )
        {
            psa_debug( "Error: unable to delete old bak file (%s).\n", bak_fn );
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

    psa_debug( "%s\n", "Entry");
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
    status = psa_cs_get_filename( state->min_uid, filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, dat_seqnum );
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

    psa_debug( "%s\n", "Entry");
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
    const uid_t ruid = getuid();
    uid_t dat_ruid = 0;
    uid_t bka_ruid = 0;
    uid_t bkb_ruid = 0;
    uid_t tmp_ruid = 0;
    pid_t tmp_pid = 0;
    pid_t tmp_tid = 0;

    psa_storage_uid_t dat_uid = 0, tmp_uid = 0, bka_uid = 0, bkb_uid = 0;

    char min_uid_dat_filename[PSA_CS_FILENAME_LENGTH];

    psa_debug( "Entry: min_uid=%" PRIu64 ", dirname=%s, num_bak_files=%d, num_tmp_files=%d, num_dat_files=%d\n", state->min_uid, state->dirname, state->num_bak_files, state->num_tmp_files, state->num_dat_files );
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
        state->min_uid = PSA_CS_UID_MAX;
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
        dat_ruid = 0;
        tmp_ruid = 0;
        bka_ruid = 0;
        bkb_ruid = 0;
        tmp_pid = 0;
        tmp_tid = 0;

        if( state->dat_list_idx < state->num_dat_files )
        {
            dat_file = state->dat_list[state->dat_list_idx];
            state->dat_filename = dat_file->d_name;
            sscanf( state->dat_filename, PSA_CS_FILENAME_PATTERN "%s", (unsigned long *) &dat_ruid, &dat_uid_hi, &dat_uid_lo, ext );
            dat_uid = dat_uid_hi << 32 | dat_uid_lo;
        }
        if( state->bak_list_idx < state->num_bak_files )
        {
            bka_file = state->bak_list[state->bak_list_idx];
            state->bka_filename = bka_file->d_name;
            sscanf( state->bka_filename, PSA_CS_BAK_FILENAME_PATTERN "%s", (unsigned long *) &bka_ruid, &bka_uid_hi, &bka_uid_lo, (unsigned int *) &state->bka_seqnum, ext );
            bka_uid = bka_uid_hi << 32 | bka_uid_lo;
        }
        if( state->bak_list_idx+1 < state->num_bak_files )
        {
            bkb_file = state->bak_list[state->bak_list_idx+1];
            state->bkb_filename = bkb_file->d_name;
            sscanf( state->bkb_filename, PSA_CS_BAK_FILENAME_PATTERN "%s", (unsigned long *) &bkb_ruid, &bkb_uid_hi, &bkb_uid_lo, (unsigned int *) &state->bkb_seqnum, ext );
            bkb_uid = bkb_uid_hi << 32 | bkb_uid_lo;
        }
        if( state->tmp_list_idx < state->num_tmp_files )
        {
            tmp_file = state->tmp_list[state->tmp_list_idx];
            state->tmp_filename = tmp_file->d_name;
            sscanf( state->tmp_filename, PSA_CS_TMP_FILENAME_PATTERN "%s", (unsigned long *) &tmp_ruid, (unsigned long *) &tmp_pid, (unsigned long *) &tmp_tid, (unsigned long *) &tmp_uid_hi, (unsigned long *) &tmp_uid_lo, ext );
            tmp_uid = tmp_uid_hi << 32 | tmp_uid_lo;
        }
        if ( ( dat_ruid > 0 && dat_ruid != ruid ) || ( bka_ruid > 0 && bka_ruid != ruid ) || ( bkb_ruid > 0 && bkb_ruid!= ruid ) || ( tmp_ruid > 0 && tmp_ruid != ruid ) )
        {
            psa_debug( " %s\n", "Error: filename real user ID not equal to getuid()." );
            goto err0;
        }

        state->min_uid = bka_uid > 0 && bka_uid < state->min_uid ? bka_uid : state->min_uid;
        state->min_uid = bkb_uid > 0 && bkb_uid < state->min_uid ? bkb_uid : state->min_uid;
        state->min_uid = tmp_uid > 0 && tmp_uid < state->min_uid ? tmp_uid : state->min_uid;
        state->min_uid = dat_uid > 0 && dat_uid < state->min_uid ? dat_uid : state->min_uid;
        if ( state->min_uid == PSA_CS_UID_MAX )
        {
            psa_debug( " %s\n", "Error: non-empty uid file lists but unable to find minimum uid value." );
            goto err0;
        }

        /* Now explicitly look for files. */
        snprintf( min_uid_dat_filename, PSA_CS_FILENAME_LENGTH, PSA_CS_FILENAME_PATTERN, (unsigned long) ruid, (unsigned long) ( state->min_uid >> 32 ), (unsigned long) ( state->min_uid & 0xffffffff ) );

        if( state->dat_filename != NULL ) state->b_min_uid_dat_exists = strncmp( min_uid_dat_filename, state->dat_filename, PSA_CS_FILENAME_PATTERN_LEN ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->tmp_filename != NULL ) state->b_min_uid_tmp_exists = strncmp( min_uid_dat_filename, state->tmp_filename, PSA_CS_FILENAME_PATTERN_LEN ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->bka_filename != NULL ) state->b_min_uid_bka_exists = strncmp( min_uid_dat_filename, state->bka_filename, PSA_CS_FILENAME_PATTERN_LEN ) == 0 ? PSA_TRUE : PSA_FALSE;
        if( state->bkb_filename != NULL ) state->b_min_uid_bkb_exists = strncmp( min_uid_dat_filename, state->bkb_filename, PSA_CS_FILENAME_PATTERN_LEN ) == 0 ? PSA_TRUE : PSA_FALSE;

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
    char filename[PSA_CS_TMP_FILENAME_LENGTH];
    int ret = 0;
    int num_files = 0;

    psa_debug( "Entry:dirname=%s\n", state->dirname );
    psa_assert( strlen( state->dirname ) > 0 );

    ret = scandir( state->dirname, &state->bad_list, psa_cs_bad_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( "Error: scandir for .bad files failed (errno=%d).\n", errno );
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
    ret = scandir( state->dirname, &state->lck_list, psa_cs_lck_file_filter, versionsort );
    if( ret < 0 )
    {
        psa_debug( "%s:\n", "Error: scandir for .lck files failed." );
        goto err4;
    }
    state->num_lck_files = ret;

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
    num_files = state->num_lck_files;
    while( num_files-- )
    {
        snprintf( filename, PSA_CS_TMP_FILENAME_LENGTH, "%s%s", state->dirname, state->lck_list[num_files]->d_name );
        remove( filename );
        free( state->lck_list[num_files] );
    }
    state->num_lck_files = 0;
    free( state->lck_list );

err4:
    num_files = state->num_tmp_files;
    while( num_files-- )
    {
        snprintf( filename, PSA_CS_TMP_FILENAME_LENGTH, "%s%s", state->dirname, state->tmp_list[num_files]->d_name );
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
 *  Start-up initialization function. This function does not change the system
 *  initialization state, or acquire the OFD lock. The global lock should be
 *  held by the client of this function.
 */
static psa_status_t psa_cs_init( void )
{
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    int i;
    int ret = 0;
    struct stat st = { 0 };
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_cs_recovery_state_t state;

    psa_debug( "%s\n", "Entry");
    /* By default, make files rw only for the owner. */
    umask ( S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );

    /* - Check if sub-prefix directories (ITS, PS) for storing files have
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


/* FUNCTION: psa_cs_do_init()
 *  Start-up initialization function
 */
static psa_status_t psa_cs_do_init( void )
{
    int fd_lock = -1;
    psa_status_t status = PSA_SUCCESS;
    pid_t tid = -1;

    psa_debug( "%s\n", "Entry");
    if( psa_cs_init_fsm_state >= PSA_CS_INIT_STATE_INITIALIZING )
    {
        tid = syscall(SYS_gettid);
        if( tid == psa_cs_init_tid )
        {
            /* Initialization processing has called recursively to this function
             * and process should be alloced to continue (the global lock is already held). */
            psa_debug( "%s\n", "Initializing. Return to avoid recursive calling" );
            return PSA_SUCCESS;
        }
        /* In the case that tcontinue with processing (but system should be initialised) */
    }
    status = psa_cs_lock_ofd_take( &fd_lock );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to acquire global lock (%d)\n", status );
        goto exit;
    }
    /* Global lock has been acquired so can perform initialization. */
    if( psa_cs_init_fsm_state == PSA_CS_INIT_STATE_UNINITIALIZED )
    {
        psa_cs_init_fsm_state = PSA_CS_INIT_STATE_INITIALIZING;
        psa_cs_init_tid = syscall(SYS_gettid);
        status = psa_cs_init();
        if( status != PSA_SUCCESS )
        {
            psa_debug( "Error: initialization failed (%d)\n", status );
            psa_cs_init_fsm_state = PSA_CS_INIT_STATE_FAILED;
            psa_cs_lock_ofd_give( &fd_lock );
            goto exit;
        }
        psa_cs_init_fsm_state = PSA_CS_INIT_STATE_INITIALIZED;
    }
    status = psa_cs_lock_ofd_give( &fd_lock );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to release global lock (%d)\n", status );
    }
exit:
    return status;
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

    psa_debug( "%s\n", "Entry");
    status = psa_cs_do_init();
    if( status != PSA_SUCCESS )
    {
        return status;
    }

    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORAGE_UID_INVALID_VALUE )
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


/* FUNCTION: psa_cs_get()
 *  PSA Storage get() implementation for both psa_its_get()
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

    psa_debug( "%s\n", "Entry");
    status = psa_cs_do_init();
    if( status != PSA_SUCCESS )
    {
        return status;
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
    char tmp_filename[PSA_CS_TMP_FILENAME_LENGTH];
    char *magic_string = PSA_INTERNAL_TRUSTED_STORAGE_MAGIC_STRING;
    FILE *stream = NULL;
    psa_its_file_header_t header;
    size_t n;
    struct psa_storage_info_t info;
    int ret = 0;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    uint8_t seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;

    psa_debug( "%s\n", "Entry");
    status = psa_cs_do_init();
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: initialization call failed (%d)\n", status );
        goto err0;
    }
    /* Check for resource/storage exhaustion */
    if( psa_cs_num_file_objects > PSA_STORAGE_FILE_MAX-1 )
    {
        psa_debug( "Error: num file objects (%d) exceeds max (%d)\n", psa_cs_num_file_objects, PSA_STORAGE_FILE_MAX );
        status = PSA_ERROR_INSUFFICIENT_STORAGE;
        goto err0;
    }
    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORAGE_UID_INVALID_VALUE )
    {
        psa_debug( "%s\n", "Error: uid is invalid value (0)" );
        status = PSA_ERROR_INVALID_ARGUMENT;
        goto err0;
    }

    /* As all files are stored on the encrypted file system, a request for no confidentiality
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
        /* Step 1: Copy pre-existing file to a tmp file.
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
            psa_debug( "%s\n", "Error: not permitted to write WRITE-ONCE object.");
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
    status = psa_cs_get_filename( uid, bak_old_filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to get backup filename (%d)\n", status );
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
    status = psa_cs_get_filename( uid, filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to get data filename (%d)\n", status );
        goto err0;
    }

    /* Get the temporary filename and open the stream */
    get_filename_flags = PSA_CS_GET_FILENAME_F_TEMP_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, tmp_filename, PSA_CS_TMP_FILENAME_LENGTH, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to get temporary filename (%d)\n", status );
        goto err0;
    }
    stream = fopen( tmp_filename, "wb" );
    if( stream == NULL )
    {
        psa_debug( "Error: failed to open temporary file (%d)\n", status );
        status = PSA_ERROR_GENERIC_ERROR;
        goto err0;
    }

    status = PSA_ERROR_INSUFFICIENT_STORAGE;
    n = fwrite( &header, 1, sizeof( header ), stream );
    if( n != sizeof( header ) )
    {
        psa_debug( "Error: failed to write header in temporary file (%d)\n", errno );
        goto err1;
    }
    n = fwrite( p_data, 1, data_length, stream );
    if( n != data_length )
    {
        /* The err1 processing will the close stream. */
        psa_debug( "Error: failed to write all data to temporary file (%d bytes written, %d bytes requested)\n", (int) n, (int) data_length );
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
        psa_debug( "Error: failed to seek temporary file (%d)\n", errno );
        goto err1;
    }
    n = fwrite( &header.magic[PSA_CS_MAGIC_LENGTH-1], 1, sizeof( uint8_t ), stream );
    if( n != sizeof( uint8_t ) )
    {
        psa_debug( "Error: failed to write temporary file sequence number (%d)\n", errno );
        goto err1;
    }
    ret = fclose( stream );
    stream = NULL;
    if( ret != 0 )
    {
        psa_debug( "Error: failed to close temporary file stream (%d)\n", errno );
        goto err2;
    }
    if( create_flags & PSA_STORAGE_FLAG_WRITE_ONCE )
    {
        /* Set permissions to be owner read-only for WRITE_ONCE file object. */
        ret = chmod( tmp_filename, S_IRUSR );
        if( ret != 0 )
        {
            psa_debug( "Error: failed to read-only permission on WRITE_ONCE file (%d)\n", errno );
            goto err2;
        }
    }

    /* Step 4. Create xxxx_x+1.bak. */
    get_filename_flags = PSA_CS_GET_FILENAME_F_BAK_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, bak_new_filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, seqnum );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to get backup filename (%d)\n", status );
        goto err2;
    }
    status = psa_cs_copy_file( tmp_filename, bak_new_filename );
    if( status != PSA_SUCCESS )
    {
        psa_debug( "Error: failed to copy temporary file to backup file (%d)\n", status );
        goto err2;
    }

    /* Step 5. Rename xxxx.tmp to xxxx.dat */
    ret = rename_replace_existing( tmp_filename, filename );
    if( ret != 0 )
    {
        psa_debug( "Error: failed replace existing object file with temporary file (%d)\n", status );
        status = PSA_ERROR_STORAGE_FAILURE;
        goto err3;
    }
    /*  Step 6. */
    if( strncmp( bak_new_filename, bak_old_filename, PSA_CS_FILENAME_LENGTH ) != 0 )
    {
        remove( bak_old_filename );
    }
    psa_cs_num_file_inc( data_length );
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

    psa_debug( "%s\n", "Entry");
    status = psa_cs_do_init();
    if( status != PSA_SUCCESS )
    {
        return status;
    }

    /* Assert the function contract that uid != 0 */
    if( uid == PSA_STORAGE_UID_INVALID_VALUE )
    {
        return ( PSA_ERROR_INVALID_ARGUMENT );
    }
    get_filename_flags = PSA_CS_GET_FILENAME_F_DATA_FILE;
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, seqnum );
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
    status = psa_cs_get_filename( uid, bak_filename, PSA_CS_FILENAME_LENGTH, get_filename_flags, seqnum );
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
        psa_cs_num_file_dec( info.size );
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
#define PSA_CS_TEST_UID4 0x0123456a
#define PSA_CS_TEST_UID5 0x0123456b
#define PSA_CS_TEST_UID6 0x0123456c

/* uid used internally in test routines */
#define PSA_CS_TEST_UID_RESERVED 0xffffffff

/** Macro to check the current number of file objects instantiated. */
#define PSA_CS_CHECK_NUM_FILE_OBJECTS( __num )     psa_assert( psa_cs_num_file_objects == ( __num ) )

/* UID data test vector used for creating both xxxx(seqnum).dat and xxxx_<seqnum>.bak files */
const uint8_t psa_cs_testdata_vec1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
const size_t psa_cs_testdata_vec1_len = sizeof( psa_cs_testdata_vec1 );

/* UID data test vector used for creating both only xxxx_<seqnum>.bak files, intended to be different to
 * psa_cs_testdata_vec1. */
const uint8_t psa_cs_testdata_vec2[] = {0x02, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00};
const size_t psa_cs_testdata_vec2_len = sizeof( psa_cs_testdata_vec2 );
const uint8_t psa_cs_testdata_vec3[] = {0x03, 0x03, 0x07, 0x0c, 0x12, 0x76, 0x28, 0xf8, 0xe7, 0x6c, 0x51, 0x4a, 0x33, 0x82, 0x41, 0xaa, 0xbb, 0xcc};
const size_t psa_cs_testdata_vec3_len = sizeof( psa_cs_testdata_vec3 );


/* FUNCTION: psa_cs_test_case_get_filename()
 *  Test case helper function to check that a object file does not exists.
 * ARGUMENTS:
 *   uid                    Unique identifier of the file object.
 *   get_filename_flags     set to one of the following values:
 *                          - PSA_CS_GET_FILENAME_F_DATA_FILE for <uid>.dat files
 *                          - PSA_CS_GET_FILENAME_F_BAK_FILE for <uid>_yyy.bak files.
 *   api                    PSA_CS_API_ITS for the ITS API or PSA_CS_API_PS for the PS API.
 *   seqnum                 The sequence number is required when generating the <uid>_yyy.bak filename.
 *   filename_buf           Buffer to receive the generated file name for the caller.
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_test_case_get_filename( psa_storage_uid_t uid, uint32_t get_filename_flags, psa_cs_api_t api, uint8_t seqnum, char *filename_buf, const size_t len)
{
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    psa_assert( psa_cs_get_filename( uid, filename_buf, len, get_filename_flags, seqnum ) == PSA_SUCCESS );
    return PSA_SUCCESS;
}


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
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* NB: Decrement the sequence number supplied to _set() because creation the bak files will be
     * created with the sequence number + 1. This seqnum is used for 1) the filename <uid>_<seqnum>.bak and 2) the seqnum
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
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( PSA_CS_TEST_UID_RESERVED, PSA_CS_GET_FILENAME_F_DATA_FILE, data->api, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    remove( uid_fn );
    /* _set() will have increase file count. Decrement this count as the .dat file has been removed. */
    psa_cs_num_file_objects--;

    /* Rename <uid2>_<seqnum2>.bak to <uid>_<seqnum2>.bak */
    data->seqnum++;
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, data->api, data->seqnum, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( PSA_CS_TEST_UID_RESERVED, PSA_CS_GET_FILENAME_F_BAK_FILE, data->api, data->seqnum, uid2_fn, PSA_CS_FILENAME_LENGTH ) );
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
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;

    /* NB: Decrement the sequence number supplied to _set() because creation the bak files will be
     * created with the sequence number + 1. This seqnum is used for 1) the filename <uid>_<seqnum>.bak and 2) the seqnum
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
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, data->api, data->seqnum, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    ret = remove( uid_fn );
    if( ret < 0 )
    {
        psa_debug( "%s", "Error: unable to remove file.\n");
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
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid1, PSA_CS_GET_FILENAME_F_BAK_FILE, api, seqnum2, uid1_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid2, PSA_CS_GET_FILENAME_F_BAK_FILE, api, seqnum2, uid2_fn, PSA_CS_FILENAME_LENGTH ) );
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
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_cs_recovery_state_t state;
    psa_scandir_filter filters[] = {psa_cs_bad_file_filter, psa_cs_bak_file_filter, psa_cs_dat_file_filter, psa_cs_tmp_file_filter_ex };
    struct dirent **list[] = {state.bad_list, state.bak_list, state.dat_list, state.tmp_list };
    psa_cs_num_file_objects = PSA_CS_NUM_FILE_OBJECTS_SENTINEL;
    psa_cs_init_fsm_state = PSA_CS_INIT_STATE_UNINITIALIZED;

    psa_debug( " %s\n", "Entry" );
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
                if( num_files < 0 )
                {
                    psa_debug( "Error: scandir() failed (%d).Check storage directories exist.\n", errno );
                    goto out;
                }
                while( num_files-- > 0 )
                {
                    snprintf( filename, PSA_CS_FILENAME_LENGTH, "%s%s", state.dirname, list[j][num_files]->d_name );
                    remove( filename );
                    free( list[j][num_files] );
                }
                free( list[j] );
            }
        }
    }
    status = PSA_SUCCESS;
out:
    return status;
}


/* FUNCTION: psa_cs_test_case_init()
 *  Create additional uid files in addition to the file objects needed for a test case.
 *  The additional files ensure recovery processing code functions correctly when
 *  multiple files are present.
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
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    int i = 0;

    psa_storage_uid_t uids[] = { PSA_CS_TEST_UID1, PSA_CS_TEST_UID3, 0 };

    /* remove uid file objects for uid1 and uid3.*/
    for( i = 0; uids[i] != 0; i++)
    {
        status = psa_cs_remove( uids[i], state->api );
        if( ! ( cflags & PSA_STORAGE_FLAG_WRITE_ONCE ) )
        {
            psa_assert( status == PSA_SUCCESS );
        }
        else
        {
            psa_assert( status == PSA_ERROR_NOT_PERMITTED );
            /* force removal */
            psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uids[i], PSA_CS_GET_FILENAME_F_DATA_FILE, state->api, seqnum, uid_fn, PSA_CS_FILENAME_LENGTH ) );
            ret = remove( uid_fn );
            psa_assert( ret == 0 );
            /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
            psa_cs_num_file_objects--;
            psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uids[i], PSA_CS_GET_FILENAME_F_BAK_FILE, state->api, seqnum, uid_fn, PSA_CS_FILENAME_LENGTH ) );
            ret = remove( uid_fn );
            psa_assert( ret == 0 );
        }
    }
    /* Check the number of file objects is the same as at the start of testing */
    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_check_file_seqnum()
 *  Test case helper function to check that a object file exists with the
 *  expected sequence number. The file object sequence number is read from
 *  the file metadata and compared with the supplied expected sequence number
 * ARGUMENTS:
 *   uid                    Unique identifier of the file object.
 *   get_filename_flags     set to one of the following values:
 *                          - PSA_CS_GET_FILENAME_F_DATA_FILE for <uid>.dat files
 *                          - PSA_CS_GET_FILENAME_F_BAK_FILE for <uid>_yyy.bak files.
 *   api                    PSA_CS_API_ITS for the ITS API or PSA_CS_API_PS for the PS API.
 *   expected_seqnum        The sequence number expected in the file metadata. For
 *                          <uid>_yyy.bak files the value is also used to generate the file object
 *                          filename.
 *   filename_buf           Buffer to receive the generated file name for the caller.
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_check_file_seqnum( psa_storage_uid_t uid, uint32_t get_filename_flags, psa_cs_api_t api, uint8_t expected_seqnum, char *filename_buf, const size_t len )
{
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    FILE *p_stream = NULL;
    struct psa_storage_info_t info;

    memset( &info, 0, sizeof( info ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, get_filename_flags, api, expected_seqnum, filename_buf, len ) );
    psa_assert( PSA_SUCCESS == psa_cs_read_file_core( filename_buf, &info, &p_stream, api, &r_seqnum ));
    psa_assert( r_seqnum == expected_seqnum );
    psa_assert( p_stream != NULL );
    fclose( p_stream );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_check_no_file()
 *  Test case helper function to check that a object file does not exists.
 * ARGUMENTS:
 *   uid                    Unique identifier of the file object.
 *   get_filename_flags     set to one of the following values:
 *                          - PSA_CS_GET_FILENAME_F_DATA_FILE for <uid>.dat files
 *                          - PSA_CS_GET_FILENAME_F_BAK_FILE for <uid>_yyy.bak files.
 *   api                    PSA_CS_API_ITS for the ITS API or PSA_CS_API_PS for the PS API.
 *   seqnum                 The sequence number is required when generating the <uid>_yyy.bak filename.
 *   filename_buf           Buffer to receive the generated file name for the caller.
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_check_no_file( psa_storage_uid_t uid, uint32_t get_filename_flags, psa_cs_api_t api, uint8_t seqnum, char *filename_buf, const size_t len )
{
    uint8_t r_seqnum = PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT;
    FILE *p_stream = NULL;
    struct psa_storage_info_t info;

    memset( &info, 0, sizeof( info ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, get_filename_flags, api, seqnum, filename_buf, len ) );
    psa_assert( PSA_ERROR_DOES_NOT_EXIST == psa_cs_read_file_core( filename_buf, &info, &p_stream, api, &r_seqnum ));
    psa_assert( p_stream == NULL );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_cs_check_file_data()
 *  Test case helper function to check object file data matches test vector.
 * ARGUMENTS:
 *   uid                    Unique identifier of the file object.
 *   expected_data          Data test vector expected in uid file object.
 *   expected_data_len      Expected data test vector buffer length.
 *   api                    PSA_CS_API_ITS for the ITS API or PSA_CS_API_PS for the PS API.
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_cs_check_file_data( psa_storage_uid_t uid, void *expected_data, size_t expected_data_length, psa_cs_api_t api )
{
    void *uid_data = NULL;
    const size_t uid_data_offset = 0;
    size_t uid_data_length = psa_cs_testdata_vec3_len;
    struct psa_storage_info_t info;

    memset( &info, 0, sizeof( info ) );
    psa_assert( PSA_SUCCESS == psa_cs_get_info( uid, &info, api ) );
    uid_data = malloc( info.size );
    if( uid_data == NULL )
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    psa_assert( PSA_SUCCESS == psa_cs_get( uid, uid_data_offset, info.size, uid_data, &uid_data_length, api ));
    psa_assert( memcmp( expected_data, uid_data, info.size ) == 0 );
    psa_assert( uid_data_length == expected_data_length );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1_seqnum()
 *  Helper function for recovery test case 1 to do the following:
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
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };

    psa_debug( "Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d \n", seqnum_old, seqnum_new, cflags );
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
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    /* _init() should have recovered 1 file */
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );


    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum_new+1,
     * - <uid>_<seqnum_new+1>.bak file
     * - <uid>_<seqnum_old>.bak doesnt exist
     * - <uid>_<seqnum_new>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, seqnum_new + 1, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    /* Check xxxx.dat data is as expected i.e. its the same as that used to create xxxx.bak file. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_data( uid, (void*) psa_cs_testdata_vec3, psa_cs_testdata_vec3_len, state.api ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new + 1, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );

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
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_old, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort ) == 0 );
    free( dirent_list );
    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort ) == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    /* Check the number of file objects is the same as at the start of testing */
    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1_core()
 *  Module test function for Recovery Test Case 1 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc1_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc1a_seqnum_old = 2;
    const uint8_t tc1a_seqnum_new = 3;
    const uint8_t tc1b_seqnum_old = 254;
    const uint8_t tc1b_seqnum_new = 255;
    const uint8_t tc1c_seqnum_old = 255;
    const uint8_t tc1c_seqnum_new = 0;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc1_seqnum( tc1a_seqnum_old, tc1a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc1_seqnum( tc1b_seqnum_old, tc1b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc1_seqnum( tc1c_seqnum_old, tc1c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc1()
 *  This test case can be summarised as follows:
 *  - 0 .dat files exist, 2 .bak files exist, 0 .tmp files exist
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Recover .dat file with sequence number that matches accompanying .bak file.
 *
 *  The sub-cases are as follows:
 *  1. Files <uid>_2.bak and <uid>_3.bak exist. Check that processing recovers <uid>.dat
 *     with sequence number matching that of the recovered .bak file. Check that the
 *     data in the .dat file matches the data in <uid>_3.bak. Check only 1 .bak file
 *     exists.
 *  2. Files <uid>_254.bak and <uid>_255.bak exist. Check that processing recovers
 *     <uid>.dat with sequence number matching that of the recovered .bak file.
 *     Check that the data in the .dat file matches the data in <uid>_255.bak.
 *     Check only 1 .bak file exists.
 *  3. Files <uid>_255.bak and <uid>_0.bak exist. Check that processing recovers
 *     <uid>.dat with sequence number matching that of the recovered .bak file. Check
 *     that the data in the .dat file matches the data in <uid>_0.bak. Check only 1
 *     This test case can be summarised as follows:
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc1( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc1_core( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc101()
 *  Module test function for Recovery Test Case 101, which is as follows:
 *   - Same as tc1 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc101( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc1_core( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc2_seqnum()
 *  This test case can be summarised as follows:
 *  - 0 .dat files exist, 1 .bak file exists, 0 .tmp files exist.
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Create some background uid files.
 *  - Recover .dat file with sequence number that matches accompanying .bak file.
 *  - Delete background uid files.
 *
 *  The sub-cases are as follows:
 *  1. File <uid>_2.bak exists. Check that processing recovers <uid>.dat with
 *     sequence number matching that of the recovered .bak file. Check that
 *     the data in the .dat file matches the data in <uid>_2.bak. Check only
 *     1 .bak file exists.
 *  2. File <uid>_255.bak exists. Check that processing recovers <uid>.dat with
 *     sequence number matching that of the recovered .bak file. Check that the
 *     data in the .dat file matches the data in <uid>_255.bak. Check only 1 .bak
 *     file exists.
 * ARGUMENTS:
 *   seqnum     first seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc2_seqnum( uint8_t seqnum, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum };

    psa_debug( "%s\n", "Entry");
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
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum+1,
     * - <uid>_<seqnum+1>.bak file
     * - <uid>_<seqnum>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, seqnum + 1, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    /* Check xxxx.dat data is as expected i.e. its the same as that used to create xxxx.bak file. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_data( uid, (void*) psa_cs_testdata_vec2, psa_cs_testdata_vec2_len, state.api ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum + 1, uid_fn, PSA_CS_FILENAME_LENGTH ) );

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
        psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT, uid_fn, PSA_CS_FILENAME_LENGTH ) );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
        /* Have forced removed the WRITE_ONCE file so have to manually decrement the uid count. */
        psa_cs_num_file_objects--;

        psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum + 1, uid_fn, PSA_CS_FILENAME_LENGTH ) );
        ret = remove( uid_fn );
        psa_assert( ret == 0 );
    }
    psa_assert( psa_cs_num_file_objects == 2 );
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum + 1, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort ) == 0 );
    free( dirent_list );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort ) == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    psa_assert( PSA_SUCCESS == psa_cs_test_case_deinit( &state, cflags, seqnum + 1 ));

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc2_core()
 *  Module test core function for Recovery Test Case 2.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc2_core ( psa_storage_create_flags_t cflags )
{
    const uint8_t tc2a_seqnum_old = 2;
    const uint8_t tc2b_seqnum_old = 254;
    const uint8_t tc2c_seqnum_old = 255;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc2_seqnum( tc2a_seqnum_old, cflags ) == 0 );
    psa_assert( psa_ps_test_tc2_seqnum( tc2b_seqnum_old, cflags ) == 0 );
    psa_assert( psa_ps_test_tc2_seqnum( tc2c_seqnum_old, cflags ) == 0 );
    return PSA_SUCCESS;
}

/* FUNCTION: psa_ps_test_tc2()
 *  Module test function for Recovery Test Case 2, which is as follows:
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
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc2_core ( PSA_STORAGE_FLAG_NONE );
}

/* FUNCTION: psa_ps_test_tc102()
 *  Module test function for Recovery Test Case 2, which is as follows:
 *   - Same as tc2 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc102( void )
{
    psa_debug( "%s\n", "Entry");
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
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };

    psa_debug( "Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d\n", seqnum_old, seqnum_new, cflags );
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
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Create <uid4>_<seqnum_old>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_old;
    status = psa_cs_test_create_bak_file( PSA_CS_TEST_UID4, cflags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Rename <uid4>_<seqnum_old>.bak to <uid>_<seqnum_old>.bak */
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( PSA_CS_TEST_UID4, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_old, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_old, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );
    ret = rename( uid_fn, uid_bak_fn );
    psa_assert( ret == 0 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* now check have expected files i.e.
     * - <uid>.dat with seqnum = seqnum_new,
     * - <uid>_<seqnum_new>.bak file
     * - <uid>_<seqnum_old>.bak doesnt exist
     * - no other .bak files
     * - no tmp files.
     * - no bad files. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    /* Check xxxx.dat data is as expected i.e. it hasn't changed from that used to create it. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_data( uid, (void*) psa_cs_testdata_vec1, psa_cs_testdata_vec1_len, state.api ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );

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

    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_old, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort ) == 0 );
    free( dirent_list );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort ) == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc51_core()
 *  Module test function for Recovery Test Case 51 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc51_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc51a_seqnum_old = 2;
    const uint8_t tc51a_seqnum_new = 3;
    const uint8_t tc51b_seqnum_old = 254;
    const uint8_t tc51b_seqnum_new = 255;
    const uint8_t tc51c_seqnum_old = 255;
    const uint8_t tc51c_seqnum_new = 0;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc51_seqnum( tc51a_seqnum_old, tc51a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc51_seqnum( tc51b_seqnum_old, tc51b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc51_seqnum( tc51c_seqnum_old, tc51c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc51()
 * This test case can be summarised as follows:
 * - 1 .dat files exist with sequence number yyy,  2 .bak files exist (one with
 *     sequence number yyy and one with yyy-1 i.e. an old file), 0 .tmp file exists.
 * - The F_WRITE_ONCE is not set in the files.
 * - Recover .dat file with sequence number that matches accompanying .bak file.
 * - Check the old .bak file (yyy-1) is removed.
 *
 * The sub-cases are as follows:
 * 1. Files <uid>_2.bak and <uid>_3.bak exist. File .dat exists with sequence number 3.
 * 2. Files <uid>_254.bak and <uid>_255.bak exist. File .dat exists with sequence number 255.
 * 3.    Files <uid>_255.bak and <uid>_0.bak exist. File .dat exists with sequence number 0.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc51( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc51_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc151()
 *  Module test function for Recovery Test Case 51, which is as follows:
 *   - Same as tc51 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc151( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc51_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc52_seqnum()
 *  This test case can be summarised as follows:
 *  - 1 dat files exist with sequence number yyy-1, 2 .bak files exist (one
 *      with sequence number yyy and one with yyy-1 i.e. an old file), 0 .tmp
 *      file exists.
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Create some background uid files.
 *  - Recover .dat file with sequence number that matches accompanying .bak file.
 *  - Check only 1 .bak file exists.
 *   - Delete background uid files.
 *
 *  The sub-cases are as follows:
 *  1. Files <uid>_2.bak and <uid>_3.bak exist. File .dat exists with sequence number 2.
 *  2. Files <uid>_254.bak and <uid>_255.bak exist. File .dat exists with sequence number 254.
 *  3. Files <uid>_255.bak and <uid>_0.bak exist. File .dat exists with sequence number 255.
 * ARGUMENTS:
 *   seqnum_old     first seqnum
 *   seqnum_new     second seqnum
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc52_seqnum( uint8_t seqnum_old, uint8_t seqnum_new, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum_new };

    psa_debug( "Entry: seqnum_old=%d, seqnum_new=%d, cflags=%d\n", seqnum_old, seqnum_new, cflags );
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
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Create <uid4>_<seqnum_new>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_new;
    status = psa_cs_test_create_bak_file( PSA_CS_TEST_UID4, cflags, &ex_data, psa_cs_testdata_vec2, psa_cs_testdata_vec2_len );
    psa_assert( status == PSA_SUCCESS );

    /* Rename <uid4>_<seqnum_new>.bak to <uid>_<seqnum_new>.bak */
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( PSA_CS_TEST_UID4, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );
    ret = rename( uid_fn, uid_bak_fn );
    psa_assert( ret == 0 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Check xxxx(seqnum_new).dat exists */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    /* Check xxxx.dat data is as expected i.e. it's the same as uid_<seqnum_new>.bak data. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_data( uid, (void*) psa_cs_testdata_vec2, psa_cs_testdata_vec2_len, state.api ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );

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

    /* Check xxxx_<seqnum_old>.bak and xxxx_<seqnum_new>.bak are not present */
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_old, uid_fn, PSA_CS_FILENAME_LENGTH ) );
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_new, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort ) == 0 );
    free( dirent_list );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort ) == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_new + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc52_core()
 *  Module test function for Recovery Test Case 52 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc52_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc52a_seqnum_old = 2;
    const uint8_t tc52a_seqnum_new = 3;
    const uint8_t tc52b_seqnum_old = 254;
    const uint8_t tc52b_seqnum_new = 255;
    const uint8_t tc52c_seqnum_old = 255;
    const uint8_t tc52c_seqnum_new = 0;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc52_seqnum( tc52a_seqnum_old, tc52a_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc52_seqnum( tc52b_seqnum_old, tc52b_seqnum_new, cflags ) == 0 );
    psa_assert( psa_ps_test_tc52_seqnum( tc52c_seqnum_old, tc52c_seqnum_new, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc52()
 *  Module test function for Recovery Test Case 52, which is as follows:
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
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc52_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc152()
 *  Module test function for Recovery Test Case 152, which is as follows:
 *   - Same as tc52 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc152( void )
{
    psa_debug( "%s\n", "Entry");
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

    psa_debug( "Entry: seqnum_dat=%d, seqnum_bak=%d, cflags=%d\n", seqnum_dat, seqnum_bak, cflags );
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
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Create <uid>_<seqnum_bak>.bak file (with different uid and data), and then rename to uid filename. */
    ex_data.seqnum = seqnum_bak;
    status = psa_cs_test_create_bak_file( uid, cflags, &ex_data, psa_cs_testdata_vec1, psa_cs_testdata_vec1_len );
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Check xxxx(seqnum_bak).dat exists */
    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, PSA_CS_FILE_HEADER_MAGIC_SEQNUM_INIT, uid_fn, PSA_CS_FILENAME_LENGTH ) );
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

    psa_assert( PSA_SUCCESS == psa_cs_test_case_get_filename( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, r_seqnum, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );
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
    psa_assert( PSA_SUCCESS == psa_cs_check_no_file( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum_dat, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort ) == 0 );
    free( dirent_list );

    psa_assert( scandir( state.dirname, &dirent_list, psa_cs_bad_file_filter, versionsort ) == 0 );
    free( dirent_list );

    /* remove uid file objects for uid1 and uid3.*/
    status = psa_cs_test_case_deinit( &state, cflags, seqnum_bak + 1 );
    psa_assert( status == PSA_SUCCESS );

    psa_assert( psa_cs_num_file_objects == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc53_core()
 *  Module test function for Recovery Test Case 53 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc53_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc53a_seqnum_dat = 3;
    const uint8_t tc53a_seqnum_bak = 2;
    const uint8_t tc53b_seqnum_dat = 255;
    const uint8_t tc53b_seqnum_bak = 254;
    const uint8_t tc53c_seqnum_dat = 0;
    const uint8_t tc53c_seqnum_bak = 255;
    const uint8_t tc53d_seqnum_dat = 1;
    const uint8_t tc53d_seqnum_bak = 0;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc53_seqnum( tc53a_seqnum_dat, tc53a_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53b_seqnum_dat, tc53b_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53c_seqnum_dat, tc53c_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc53d_seqnum_dat, tc53d_seqnum_bak, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc53()
 *  This test case can be summarised as follows:
 *  - 1 .dat files exist with sequence number yyy,  1 .bak files exist with
 *    sequence number xxx where yyy > xxx, 0 .tmp file exists.
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Recover .dat file with sequence number that matches accompanying .bak file.
 *  The sub-cases are as follows:
 *  1. Files <uid>_2.bak and <uid>_3.dat exist.
 *  2. Files <uid>_254.bak and <uid>_255.dat exist.
 *  3. Files <uid>_255.bak and <uid>_0.dat exist.
 *  4. Files <uid>_0.bak and <uid>_1.dat exist.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc53( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc53_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc153()
 *  Module test function for Recovery Test Case 153, which is as follows:
 *   - Same as psa_ps_test_tc153() except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc153( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc53_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* FUNCTION: psa_ps_test_tc54_core()
 *  Module test function for Recovery Test Case 54 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc54_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc54a_seqnum_dat = 3;
    const uint8_t tc54a_seqnum_bak = 4;
    const uint8_t tc54b_seqnum_dat = 254;
    const uint8_t tc54b_seqnum_bak = 255;
    const uint8_t tc54c_seqnum_dat = 255;
    const uint8_t tc54c_seqnum_bak = 0;
    const uint8_t tc54d_seqnum_dat = 0;
    const uint8_t tc54d_seqnum_bak = 1;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc53_seqnum( tc54a_seqnum_dat, tc54a_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54b_seqnum_dat, tc54b_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54c_seqnum_dat, tc54c_seqnum_bak, cflags ) == 0 );
    psa_assert( psa_ps_test_tc53_seqnum( tc54d_seqnum_dat, tc54d_seqnum_bak, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc54()
 *  This test case can be summarised as follows:
 *  - 1 .dat files exist with sequence number yyy, 1 .bak files exist with
 *    sequence number xxx where yyy < xxx, 0 .tmp file exists.
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Recover .dat file with sequence number that matches accompanying .bak file.
 *
 *  The sub-cases are as follows:
 *  1. Files <uid>_4.bak and <uid>_3.dat exist.
 *  2. Files <uid>_255.bak and <uid>_254.dat exist.
 *  3. Files <uid>_0.bak and <uid>_255.dat exist.
 *  4. Files <uid>_1.bak and <uid>_0.dat exist.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc54( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc54_core ( PSA_STORAGE_FLAG_NONE );
}


/* FUNCTION: psa_ps_test_tc154()
 *  Module test function for Recovery Test Case 154, which is as follows:
 *   - Same as psa_ps_test_tc154() except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc154( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc54_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* create a lock file so that the uid can be shared between test code and scandir() callback. */
static int psa_cs_add_lock_file( psa_storage_uid_t uid, psa_cs_api_t api )
{
    char filename[PSA_CS_TMP_FILENAME_LENGTH];
    psa_status_t status;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_LOCK_FILE;
    FILE *p_stream = NULL;

    psa_debug( "%s\n", "Entry");
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, PSA_CS_TMP_FILENAME_LENGTH, get_filename_flags, 0 );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    p_stream = fopen( filename, "wb" );
    if( p_stream == NULL )
    {
        goto err0;
    }
    fclose( p_stream );
err0:
    return status;
}

static int psa_cs_del_lock_file( psa_storage_uid_t uid, psa_cs_api_t api )
{
    char filename[PSA_CS_TMP_FILENAME_LENGTH];
    psa_status_t status;
    uint32_t get_filename_flags = PSA_CS_GET_FILENAME_F_LOCK_FILE;

    psa_debug( "%s\n", "Entry");
    get_filename_flags |= api == PSA_CS_API_ITS ? PSA_CS_GET_FILENAME_F_API_ITS : PSA_CS_GET_FILENAME_F_NONE;
    status = psa_cs_get_filename( uid, filename, PSA_CS_TMP_FILENAME_LENGTH, get_filename_flags, 0 );
    if( status != PSA_SUCCESS )
    {
        goto err0;
    }
    remove( filename );
err0:
    return status;
}

/* recover the uid of the lockfile */
static int psa_cs_get_lock_file_uid( psa_storage_uid_t *uid, psa_cs_api_t api )
{
    char dirname[PSA_CS_FILENAME_LENGTH];
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    int ret = 0;
    struct dirent **dirent_list;
    uid_t lck_ruid = 0;
    pid_t lck_pid = 0;
    pid_t lck_tid = 0;
    unsigned long lck_uid_hi = 0, lck_uid_lo = 0;

    snprintf( dirname, PSA_CS_FILENAME_LENGTH, "%s%s", PSA_CS_PREFIX, api_prefix[api] );
    ret = scandir( dirname, &dirent_list, psa_cs_lck_file_filter_ex, versionsort );
    psa_assert( ret == 1 );

    sscanf( dirent_list[0]->d_name, PSA_CS_LOCK_FILENAME_PATTERN, (unsigned long *) &lck_ruid, (unsigned long *) &lck_pid, (unsigned long *) &lck_tid, (unsigned long *) &lck_uid_hi, (unsigned long *) &lck_uid_lo );
    psa_assert( lck_ruid == getuid() );
    psa_assert( lck_pid == getpid() );
    psa_assert( lck_tid == syscall(SYS_gettid) );
    free( dirent_list );
    if(uid)
    {
        *uid = lck_uid_hi << 32 | lck_uid_lo;

    }
    return ( PSA_SUCCESS );
}


static int psa_cs_uid_bak_file_filter( const struct dirent *dir )
{
    const char *s = dir->d_name;
    char uids[PSA_CS_FILENAME_LENGTH];
    int len = strlen( s );
    int n = 0;
    const uid_t ruid = getuid();
    psa_storage_uid_t uid = PSA_STORAGE_UID_INVALID_VALUE;

    if( len >= 0 )
    {
        n = psa_cs_bak_file_filter( dir );
        if ( n == 0 )
        {
            return 0;
        }

        /* In future, this function will need generalizing to also support PSA_CS_API_ITS. */
        n = psa_cs_get_lock_file_uid( &uid , PSA_CS_API_PS );
        psa_assert( n == 0);
        n = snprintf( uids, PSA_CS_FILENAME_LENGTH, PSA_CS_FILENAME_PATTERN, (unsigned long ) ruid, (unsigned long ) ( uid >> 32 ), (unsigned long) ( uid & 0xffffffff ));
        if (strncmp( s, uids, PSA_CS_FILENAME_PATTERN_LEN ) == 0 )
        {
            return 1;
        }
    }
    return 0;
}


/* FUNCTION: psa_ps_test_tc55_seqnum()
 *  This test case can be summarised as follows:
 *  - 1 .dat files exist with sequence number yyy,  0 .bak files exist, 0 .tmp file exists.
 *  - The F_WRITE_ONCE is not set in the files.
 *  - Create some background uid files.
 *  - Recover .bak file with sequence number that matches accompanying .dat file.
 *  - Delete some background uid files.
 *
 * The sub-cases are as follows:
 * 1. File <uid>_0.dat exist.
 * 2. File <uid>_255.dat exist.
 * 3. File <uid>_254.dat exist.
 * 4. File <uid>_128.dat exist.
 * 5. File <uid>_1.dat exist.
 * ARGUMENTS:
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc55_seqnum( uint8_t seqnum, psa_storage_create_flags_t cflags )
{
    char uid_fn[PSA_CS_FILENAME_LENGTH];
    char uid_bak_fn[PSA_CS_FILENAME_LENGTH];
    int ret = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    const psa_storage_uid_t uid = PSA_CS_TEST_UID2;
    struct psa_storage_info_t info;
    struct dirent **dirent_list;
    psa_cs_recovery_state_t state;
    const char *api_prefix[PSA_CS_API_MAX] = { PSA_CS_ITS_SUBPREFIX, PSA_CS_PS_SUBPREFIX };
    psa_cs_extended_data_t ex_data = { PSA_CS_API_PS, seqnum };

    psa_debug( "Entry: seqnum=%d, cflags=%d\n", seqnum, cflags );
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
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* perform recovery */
    psa_cs_test_init( 0 );
    psa_assert( strlen( state.dirname ) > 0 );
    status = psa_cs_do_init();
    psa_assert( status == PSA_SUCCESS );
    PSA_CS_CHECK_NUM_FILE_OBJECTS( 3 );

    /* Check xxxx(seqnum).dat exists */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_DATA_FILE, state.api, seqnum, uid_fn, PSA_CS_FILENAME_LENGTH ) );

    /* Check xxxx.dat data is as expected i.e. it hasn't changed. */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_data( uid, (void*) psa_cs_testdata_vec2, psa_cs_testdata_vec2_len, state.api ) );

    /* Check xxxx_<seqnum>.bak exists */
    psa_assert( PSA_SUCCESS == psa_cs_check_file_seqnum( uid, PSA_CS_GET_FILENAME_F_BAK_FILE, state.api, seqnum, uid_bak_fn, PSA_CS_FILENAME_LENGTH ) );

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
    ret = psa_cs_add_lock_file( uid, state.api );
    psa_assert( ret == 0 );
    ret = scandir( state.dirname, &dirent_list, psa_cs_uid_bak_file_filter, versionsort );
    psa_assert( ret == 0 );
    ret = psa_cs_del_lock_file( uid, state.api );
    psa_assert( ret == 0 );
    free( dirent_list );

    ret = scandir( state.dirname, &dirent_list, psa_cs_tmp_file_filter_ex, versionsort );
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
 *  Module test function for Recovery Test Case 55 for different create_flags settings.
 * ARGUMENTS:
 *  cflags          _set() create_flags setting for setting/not setting F_WRITE_ONCE flag
 * RETURN: PSA_SUCCESS
 */
static psa_status_t psa_ps_test_tc55_core( psa_storage_create_flags_t cflags )
{
    const uint8_t tc55a_seqnum = 0;
    const uint8_t tc55b_seqnum = 254;
    const uint8_t tc55c_seqnum = 255;
    const uint8_t tc55d_seqnum = 128;
    const uint8_t tc55e_seqnum = 1;

    psa_debug( "%s\n", "Entry");
    psa_assert( psa_ps_test_tc55_seqnum( tc55a_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55b_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55c_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55d_seqnum, cflags ) == 0 );
    psa_assert( psa_ps_test_tc55_seqnum( tc55e_seqnum, cflags ) == 0 );
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc55()
 *  Module test function for Recovery Test Case 55, which is as follows:
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
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc55_core ( PSA_STORAGE_FLAG_NONE );
}

/* FUNCTION: psa_ps_test_tc155()
 *  Module test function for Recovery Test Case 155, which is as follows:
 *   - Same as tc55 except F_WRITE_ONCE is set.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc155( void )
{
    psa_debug( "%s\n", "Entry");
    return psa_ps_test_tc55_core ( PSA_STORAGE_FLAG_WRITE_ONCE );
}


/* PSA_CS_TEST_TC203_NUM_THREADS is the number of threads to create in test
 * case 203, to check for thread safety issues. */
#define PSA_CS_TEST_TC203_NUM_THREADS       2

/* STRUCTURE: psa_cs_test_tc20x_data
 *  This parameterizes a set of UID data for the set()/remove() operations
 *  performed by test functions e.g. psa_cs_test_thread_main(). */
typedef struct _psa_cs_test_tc20x_data
{
    psa_storage_uid_t uid;                      /* UID id to use for operation. */
    size_t len;                                 /* Length of data at test_vec_data. */
    const uint8_t *test_vec_data;               /* Test vector of data to use for operation. */
    psa_storage_create_flags_t flags;           /* Create flags to be specified to set() operations. */
    uint32_t num_file_objects_expected;         /* Number of file objects expected in the system at
                                                   a particular point in time.*/
} psa_cs_test_tc20x_data;


/* STRUCTURE: psa_ps_test_tc201_data_set_1
 *  Set 1 of UID data passed to psa_cs_test_thread_main() for example. UID
 *  values are unique to the set. */
static psa_cs_test_tc20x_data psa_ps_test_tc201_data_set_1[] = {
        { PSA_CS_TEST_UID1, sizeof( psa_cs_testdata_vec1 ), psa_cs_testdata_vec1, PSA_STORAGE_FLAG_NONE, 1 },
        { PSA_CS_TEST_UID2, sizeof( psa_cs_testdata_vec2 ), psa_cs_testdata_vec2, PSA_STORAGE_FLAG_NONE, 2 },
        { PSA_CS_TEST_UID3, sizeof( psa_cs_testdata_vec3 ), psa_cs_testdata_vec3, PSA_STORAGE_FLAG_NONE, 3 },
        { 0, 0, NULL, 0, 0}
};


/* STRUCTURE: psa_ps_test_tc201_data_set_2
 *  Set 2 of UID data passed to psa_cs_test_thread_main() for example. UID
 *  values are unique to the set. */
static psa_cs_test_tc20x_data psa_ps_test_tc201_data_set_2[] = {
        { PSA_CS_TEST_UID4, sizeof( psa_cs_testdata_vec1 ), psa_cs_testdata_vec1, PSA_STORAGE_FLAG_NONE, 1 },
        { PSA_CS_TEST_UID5, sizeof( psa_cs_testdata_vec2 ), psa_cs_testdata_vec2, PSA_STORAGE_FLAG_NONE, 2 },
        { PSA_CS_TEST_UID6, sizeof( psa_cs_testdata_vec3 ), psa_cs_testdata_vec3, PSA_STORAGE_FLAG_NONE, 3 },
        { 0, 0, NULL, 0, 0}
};


/* STRUCTURE: psa_cs_test_thread_ctx_t
 *  Context data structure supplied to psa_cs_test_thread_main(). */
typedef struct _psa_cs_test_thread_ctx_t
{
    psa_cs_test_tc20x_data* data;           /* UID set for set()/remove() operations. */
    unsigned int f_check_num_files;         /* Flag indicating whether to perform num_files checks. */

} psa_cs_test_thread_ctx_t;


/* STRUCTURE: psa_cs_test_process_ctx
 *  This structure defines psa_cs_test_thread_main() context data structures for multi-process testing. */
static psa_cs_test_thread_ctx_t psa_cs_test_process_ctx[] = {
        { psa_ps_test_tc201_data_set_1, 1 },
        { psa_ps_test_tc201_data_set_2, 1 },
        { NULL, 0 },
    };


/* STRUCTURE: psa_cs_test_thread_ctx
 *  This structure defines psa_cs_test_thread_main() context data structures for multi-thread testing. */
static psa_cs_test_thread_ctx_t psa_cs_test_thread_ctx[] = {
        { psa_ps_test_tc201_data_set_1, 0 },
        { psa_ps_test_tc201_data_set_2, 0 },
        { NULL, 0 },
    };


/* FUNCTION: psa_cs_test_thread_main()
 *  This function implements the main processing loop for:
 *  - The multi-processing test case 201.
 *  - The multi-threading test case 203.
 *  The function is pass a pointer to a data structure which specifies the UID
 *  and data to get set(), and subsquently removed.
 * ARGUMENTS:
 *  arg         An instance of a psa_cs_test_thread_ctx_t data structure.
 * RETURN: NULL if successful.
 */
static void* psa_cs_test_thread_main( void *arg )
{
    uint32_t i = 0;
    uint32_t num_file_objects = 0;
    psa_status_t status = PSA_ERROR_GENERIC_ERROR;
    psa_cs_test_thread_ctx_t* ctx = (psa_cs_test_thread_ctx_t*) arg;
    psa_cs_test_tc20x_data *tc_data = ctx->data;

    psa_debug( "%s\n", "Entry");

    for ( i = 0; i < PSA_STORAGE_FILE_MAX; i++ )
    {
        /* add data objects */
        tc_data = ctx->data;
        while ( tc_data->uid != 0 )
        {
            /* Create uid file objects.*/
            status = psa_cs_set( tc_data->uid, tc_data->len, (void *) tc_data->test_vec_data, tc_data->flags, PSA_CS_API_PS, NULL );
            psa_assert( status == PSA_SUCCESS );
            if(ctx->f_check_num_files > 0)
            {
                psa_assert( psa_cs_num_file_objects == tc_data->num_file_objects_expected );
            }
            tc_data++;
        }
        /* Remove data objects */
        tc_data = ctx->data;
        while ( tc_data->uid != 0 )
        {
            /* delete uid file objects. */
            num_file_objects = psa_cs_num_file_objects;
            psa_assert( PSA_SUCCESS == psa_cs_check_file_data( tc_data->uid, (void*) tc_data->test_vec_data, tc_data->len, PSA_CS_API_PS ) );
            status = psa_cs_remove( tc_data->uid, PSA_CS_API_PS );
            psa_assert( status == PSA_SUCCESS );
            if(ctx->f_check_num_files > 0)
            {
                psa_assert( psa_cs_num_file_objects == (num_file_objects - 1) );
            }
            tc_data++;
        }
    }
    psa_debug( "%s\n", "Exiting");
    return NULL;
}


/* FUNCTION: psa_ps_test_tc201()
 *  Module test function for multi-process testing. This function is intended
 *  to be used with the bash script psa_test_case_201.sh which runs muliple
 *  instances of the test binary in parallel. psa_ps_test_tc201() test case
 *  performs _set() and _remove() operations for approximately 100s, to provide
 *  sufficient opportunity for process-safety issues to arise.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc201( void )
{
    void* ret = NULL;

    psa_debug( "%s\n", "Entry");
    psa_cs_test_init( 1 );

    ret = psa_cs_test_thread_main( (void*) &psa_cs_test_process_ctx[0] );
    if( ret != NULL )
    {
        return PSA_ERROR_GENERIC_ERROR;
    }
    return PSA_SUCCESS;
}


/* FUNCTION: psa_ps_test_tc203()
 *  Function for testing multi-thread support. The test case does the
 *  following:
 *  - Starts thread 0 running psa_cs_test_thread_main(), which performs set()
 *    and remove() operations for set_0 UIDs e.g. (UID1, UID2, UID3).
 *  - Starts thread i running psa_cs_test_thread_main(), which performs set()
 *    and remove() operations for set_i UIDs e.g. (UID_i1, UID_i2, UID_i3).
 *    Note the UIDs in set_i dont appear in the any other sets so that 2
 *    different threads dont operate on the same UIDs.
 *  - Starts thread n-1 running psa_cs_test_thread_main(), which performs set()
 *    and remove() operations for set_(n-1) UIDs.
 * - Waits for the threads to complete processing.
 * ARGUMENTS: none
 * RETURN: PSA_SUCCESS
 */
psa_status_t psa_ps_test_tc203( void )
{
    int i = 0;
    int ret = -1;
    pthread_t tid[PSA_CS_TEST_TC203_NUM_THREADS];

    psa_debug( "%s\n", "Entry");
    /* clean up form previous testing */
    psa_cs_test_init( 1 );

    /* Start the threads. */
    while( i < PSA_CS_TEST_TC203_NUM_THREADS )
    {
        ret = pthread_create( &tid[i], NULL, &psa_cs_test_thread_main, &psa_cs_test_thread_ctx[i] );
        psa_assert( ret == 0 );
        i++;
    }
    /* Wait for the threads to complete. */
    i = 0;
    while( i < PSA_CS_TEST_TC203_NUM_THREADS )
    {
        pthread_join( tid[i], NULL );
        i++;
    }
    /* Clean up after test (this is the last test). */
    psa_cs_test_init( 1 );
    return PSA_SUCCESS;
}


#endif  /* PSA_STORAGE_TEST */
