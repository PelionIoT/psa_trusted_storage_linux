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

#ifndef PSA_STORAGE_TEST_H
#define PSA_STORAGE_TEST_H

#ifdef PSA_STORAGE_TEST

#include <stddef.h>
#include <stdint.h>

#include "psa/error.h"
#include "psa/storage_common.h"

#ifdef __cplusplus
extern "C" {
#endif

psa_status_t psa_ps_test_tc1( void );
psa_status_t psa_ps_test_tc2( void );
psa_status_t psa_ps_test_tc51( void );
psa_status_t psa_ps_test_tc52( void );
psa_status_t psa_ps_test_tc53( void );
psa_status_t psa_ps_test_tc54( void );
psa_status_t psa_ps_test_tc55( void );
psa_status_t psa_ps_test_tc101( void );
psa_status_t psa_ps_test_tc102( void );
psa_status_t psa_ps_test_tc151( void );
psa_status_t psa_ps_test_tc152( void );
psa_status_t psa_ps_test_tc153( void );
psa_status_t psa_ps_test_tc154( void );
psa_status_t psa_ps_test_tc155( void );

#ifdef __cplusplus
}
#endif

#endif /* PSA_STORAGE_TEST */

#endif // PSA_STORAGE_TEST_H

