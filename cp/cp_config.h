/*
* Copyright 2019-present Open Networking Foundation
*
* SPDX-License-Identifier: Apache-2.0
*
*/
#ifndef __CP_CONFIG_H__
#define __CP_CONFIG_H__

#define DP_SITE_NAME_MAX		256
#include <stdint.h>
#include <sys/queue.h>

#define CP_CONFIG_ETC_PATH		"../config/app_config.cfg"
#define CP_CONFIG_OPT_PATH		"/tmp/app_config.cfg"

extern struct app_config *appl_config;
struct upf_context;

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
	uint16_t tac;
};

struct dp_info
{
	struct dp_key key;
	char dpName[DP_SITE_NAME_MAX];
	uint32_t dpId;
	struct in_addr s1u_sgw_ip;
	struct upf_context *upf;
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

/* Application can pass the dp_key and get back one of the selected DP in return.
 * Over the period of time dp_key will have multiple keys and this API will
 * go through all the config to return one of the first matching DP ID.
*/
uint32_t select_dp_for_key(struct dp_key *);

/**
 * Whenever a upf registers with a CP, the entry is scanned through
 * a list of appl_config list of dp's. If the DP exists in the appl_config
 * list, it returns 1, otherwise it returns 0
 */
uint8_t resolve_upf_context_to_dpInfo(struct upf_context *upf, char *hostname, struct in_addr s1u_sgw_ip);

/**
 * Given dpId, what is the s1u's IP address of dp (as stored in the apl_config list)
 */
struct in_addr fetch_s1u_sgw_ip(uint32_t dpId);

/**
 * Given dpId, what is upf's context (as stored in the apl_config list)
 */
struct upf_context *fetch_upf_context(uint32_t dpId);
#endif
