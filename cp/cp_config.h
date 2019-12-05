/*
* Copyright 2019-present Open Networking Foundation
*
* SPDX-License-Identifier: Apache-2.0
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*  http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/
#ifndef __CP_CONFIG_H__
#define __CP_CONFIG_H__

#define DP_SITE_NAME_MAX 128
#include <stdint.h>
#include <sys/queue.h>

extern struct app_config *appl_config; 

struct mcc_mnc_key 
{
	uint8_t mcc_digit_1 :4;
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t mnc_digit_2 :4;
};


struct dp_key
{
    struct mcc_mnc_key mcc_mnc;
    struct in_addr enb_addrs[2];
    uint16_t tac;
};

struct dp_info
{
    struct dp_key  key;
	char dpName[DP_SITE_NAME_MAX];
	uint32_t dpId;
	LIST_ENTRY(dp_info) dpentries;
};

struct app_config 
{
    /* Dataplane selection rules. */
    LIST_HEAD(dplisthead, dp_info) dpList;

	/* add any other dynamic config for spgw control app 
     * Common : various interfaces timeout intervals,  admin state etc.., logging enable/disable 
     * SGW : DDN profile, APN (optional) etc..
     * PGW : APN, IP Pool etc..
     */
};

void init_spgwc_dynamic_config(struct app_config *cfg);

uint64_t select_dp_for_key(struct dp_key *); 

#endif
