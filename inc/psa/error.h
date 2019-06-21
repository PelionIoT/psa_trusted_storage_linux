/*
 * Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * Based on: psa/crypto_values.h
 * In open-source project: https://github.com/ARMmbed/mbed-crypto
 *
 * Original file: Apache-2.0
 * Modifications: Copyright (c) 2019 Arm Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef PSA_STORAGE_ERROR_H
#define PSA_STORAGE_ERROR_H

/** \defgroup error Error codes
 * @{
 */

/* PSA error codes */

/** The action was completed successfully. */
#define PSA_SUCCESS ((psa_status_t)0)

/** An error occurred that does not correspond to any defined
 * failure cause.
 *
 * Implementations may use this error code if none of the other standard
 * error codes are applicable. */
#define PSA_ERROR_GENERIC_ERROR         ((psa_status_t)-132)

/** The requested operation or a parameter is not supported
 * by this implementation.
 *
 * Implementations should return this error code when an enumeration
 * parameter such as a key type, algorithm, etc. is not recognized.
 * If a combination of parameters is recognized and identified as
 * not valid, return #PSA_ERROR_INVALID_ARGUMENT instead. */
#define PSA_ERROR_NOT_SUPPORTED         ((psa_status_t)-134)

/** The requested action is denied by a policy.
 *
 * Implementations should return this error code when the parameters
 * are recognized as valid and supported, and a policy explicitly
 * denies the requested operation.
 *
 * If a subset of the parameters of a function call identify a
 * forbidden operation, and another subset of the parameters are
 * not valid or not supported, it is unspecified whether the function
 * returns #PSA_ERROR_NOT_PERMITTED, #PSA_ERROR_NOT_SUPPORTED or
 * #PSA_ERROR_INVALID_ARGUMENT. */
#define PSA_ERROR_NOT_PERMITTED         ((psa_status_t)-133)

/** An output buffer is too small.
 *
 * Applications can call the \c PSA_xxx_SIZE macro listed in the function
 * description to determine a sufficient buffer size.
 *
 * Implementations should preferably return this error code only
 * in cases when performing the operation with a larger output
 * buffer would succeed. However implementations may return this
 * error if a function has invalid or unsupported parameters in addition
 * to the parameters that determine the necessary output buffer size. */
#define PSA_ERROR_BUFFER_TOO_SMALL      ((psa_status_t)-138)

/** Asking for an item that already exists
 *
 * Implementations should return this error, when attempting
 * to write an item (like a key) that already exists. */
#define PSA_ERROR_ALREADY_EXISTS        ((psa_status_t)-139)

/** Asking for an item that doesn't exist
 *
 * Implementations should return this error, if a requested item (like
 * a key) does not exist. */
#define PSA_ERROR_DOES_NOT_EXIST        ((psa_status_t)-140)

/** The requested action cannot be performed in the current state.
 *
 * Multipart operations return this error when one of the
 * functions is called out of sequence. Refer to the function
 * descriptions for permitted sequencing of functions.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_ALREADY_EXISTS or #PSA_ERROR_DOES_NOT_EXIST
 * as applicable. */
#define PSA_ERROR_BAD_STATE             ((psa_status_t)-137)

/** The parameters passed to the function are invalid.
 *
 * Implementations may return this error any time a parameter or
 * combination of parameters are recognized as invalid.
 *
 * Implementations shall not return this error code to indicate
 * that a key slot is occupied when it needs to be free or vice versa,
 * but shall return #PSA_ERROR_ALREADY_EXISTS or #PSA_ERROR_DOES_NOT_EXIST
 * as applicable.
 *
 * Implementation shall not return this error code to indicate that a
 * key handle is invalid, but shall return #PSA_ERROR_INVALID_HANDLE
 * instead.
 */
#define PSA_ERROR_INVALID_ARGUMENT      ((psa_status_t)-135)

/** There is not enough runtime memory.
 *
 * If the action is carried out across multiple security realms, this
 * error can refer to available memory in any of the security realms. */
#define PSA_ERROR_INSUFFICIENT_MEMORY   ((psa_status_t)-141)

/** There is not enough persistent storage.
 *
 * Functions that modify the key storage return this error code if
 * there is insufficient storage space on the host media. In addition,
 * many functions that do not otherwise access storage may return this
 * error code if the implementation requires a mandatory log entry for
 * the requested action and the log storage space is full. */
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)-142)

/** There was a communication failure inside the implementation.
 *
 * This can indicate a communication failure between the application
 * and an external cryptoprocessor or between the cryptoprocessor and
 * an external volatile or persistent memory. A communication failure
 * may be transient or permanent depending on the cause.
 *
 * \warning If a function returns this error, it is undetermined
 * whether the requested action has completed or not. Implementations
 * should return #PSA_SUCCESS on successful completion whenver
 * possible, however functions may return #PSA_ERROR_COMMUNICATION_FAILURE
 * if the requested action was completed successfully in an external
 * cryptoprocessor but there was a breakdown of communication before
 * the cryptoprocessor could report the status to the application.
 */
#define PSA_ERROR_COMMUNICATION_FAILURE ((psa_status_t)-145)

/** There was a storage failure that may have led to data loss.
 *
 * This error indicates that some persistent storage is corrupted.
 * It should not be used for a corruption of volatile memory
 * (use #PSA_ERROR_TAMPERING_DETECTED), for a communication error
 * between the cryptoprocessor and its external storage (use
 * #PSA_ERROR_COMMUNICATION_FAILURE), or when the storage is
 * in a valid state but is full (use #PSA_ERROR_INSUFFICIENT_STORAGE).
 *
 * Note that a storage failure does not indicate that any data that was
 * previously read is invalid. However this previously read data may no
 * longer be readable from storage.
 *
 * When a storage failure occurs, it is no longer possible to ensure
 * the global integrity of the keystore. Depending on the global
 * integrity guarantees offered by the implementation, access to other
 * data may or may not fail even if the data is still readable but
 * its integrity canont be guaranteed.
 *
 * Implementations should only use this error code to report a
 * permanent storage corruption. However application writers should
 * keep in mind that transient errors while reading the storage may be
 * reported using this error code. */
#define PSA_ERROR_STORAGE_FAILURE       ((psa_status_t)-146)

/** A hardware failure was detected.
 *
 * A hardware failure may be transient or permanent depending on the
 * cause. */
#define PSA_ERROR_HARDWARE_FAILURE      ((psa_status_t)-147)

/** A tampering attempt was detected.
 *
 * If an application receives this error code, there is no guarantee
 * that previously accessed or computed data was correct and remains
 * confidential. Applications should not perform any security function
 * and should enter a safe failure state.
 *
 * Implementations may return this error code if they detect an invalid
 * state that cannot happen during normal operation and that indicates
 * that the implementation's security guarantees no longer hold. Depending
 * on the implementation architecture and on its security and safety goals,
 * the implementation may forcibly terminate the application.
 *
 * This error code is intended as a last resort when a security breach
 * is detected and it is unsure whether the keystore data is still
 * protected. Implementations shall only return this error code
 * to report an alarm from a tampering detector, to indicate that
 * the confidentiality of stored data can no longer be guaranteed,
 * or to indicate that the integrity of previously returned data is now
 * considered compromised. Implementations shall not use this error code
 * to indicate a hardware failure that merely makes it impossible to
 * perform the requested operation (use #PSA_ERROR_COMMUNICATION_FAILURE,
 * #PSA_ERROR_STORAGE_FAILURE, #PSA_ERROR_HARDWARE_FAILURE,
 * #PSA_ERROR_INSUFFICIENT_ENTROPY or other applicable error code
 * instead).
 *
 * This error indicates an attack against the application. Implementations
 * shall not return this error code as a consequence of the behavior of
 * the application itself. */
#define PSA_ERROR_TAMPERING_DETECTED    ((psa_status_t)-151)

/** There is not enough entropy to generate random data needed
 * for the requested action.
 *
 * This error indicates a failure of a hardware random generator.
 * Application writers should note that this error can be returned not
 * only by functions whose purpose is to generate random data, such
 * as key, IV or nonce generation, but also by functions that execute
 * an algorithm with a randomized result, as well as functions that
 * use randomization of intermediate computations as a countermeasure
 * to certain attacks.
 *
 * Implementations should avoid returning this error after psa_crypto_init()
 * has succeeded. Implementations should generate sufficient
 * entropy during initialization and subsequently use a cryptographically
 * secure pseudorandom generator (PRNG). However implementations may return
 * this error at any time if a policy requires the PRNG to be reseeded
 * during normal operation. */
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)-148)

/** The signature, MAC or hash is incorrect.
 *
 * Verification functions return this error if the verification
 * calculations completed successfully, and the value to be verified
 * was determined to be incorrect.
 *
 * If the value to verify has an invalid size, implementations may return
 * either #PSA_ERROR_INVALID_ARGUMENT or #PSA_ERROR_INVALID_SIGNATURE. */
#define PSA_ERROR_INVALID_SIGNATURE     ((psa_status_t)-149)

/** The decrypted padding is incorrect.
 *
 * \warning In some protocols, when decrypting data, it is essential that
 * the behavior of the application does not depend on whether the padding
 * is correct, down to precise timing. Applications should prefer
 * protocols that use authenticated encryption rather than plain
 * encryption. If the application must perform a decryption of
 * unauthenticated data, the application writer should take care not
 * to reveal whether the padding is invalid.
 *
 * Implementations should strive to make valid and invalid padding
 * as close as possible to indistinguishable to an external observer.
 * In particular, the timing of a decryption operation should not
 * depend on the validity of the padding. */
#define PSA_ERROR_INVALID_PADDING       ((psa_status_t)-150)

/** Return this error when there's insufficient data when attempting
 * to read from a resource. */
#define PSA_ERROR_INSUFFICIENT_DATA     ((psa_status_t)-143)

/** The key handle is not valid.
 */
#define PSA_ERROR_INVALID_HANDLE        ((psa_status_t)-136)

/**@}*/

#endif /* PSA_STORAGE_ERROR_H */
