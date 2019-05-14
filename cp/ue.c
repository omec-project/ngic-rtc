/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ue.h"
#include "interface.h"
#include "cp.h"

#include <rte_debug.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

struct rte_hash *ue_context_by_imsi_hash;
struct rte_hash *ue_context_by_fteid_hash;

static struct in_addr ip_pool_ip;
static struct in_addr ip_pool_mask;

extern struct pfcp_config_t pfcp_config;

apn apn_list[MAX_NB_DPN];

const uint32_t s11_sgw_gtpc_base_teid = 0xC0FFEE;
static uint32_t s11_sgw_gtpc_teid_offset;
const uint32_t s5s8_pgw_gtpc_base_teid = 0xD0FFEE;
static uint32_t s5s8_pgw_gtpc_teid_offset;

uint32_t base_s1u_sgw_gtpu_teid = 0xf0000000;

void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	bearer->s1u_sgw_gtpu_teid = (context->s11_sgw_gtpc_teid & 0x00ffffff)
	    | ((0xf0 + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
	 * Computation same as s1u_sgw_gtpu_teid
	 */
	bearer->s5s8_sgw_gtpu_teid = (context->s11_sgw_gtpc_teid & 0x00ffffff)
	    | ((0xf0 + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_pgw_gtpc_teid(pdn_connection *pdn)
{
	pdn->s5s8_pgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
		+ s5s8_pgw_gtpc_teid_offset;
	++s5s8_pgw_gtpc_teid_offset;
}

void
create_ue_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "bearer_by_imsi_hash",
	    .entries = LDB_ENTRIES_DEFAULT,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	ue_context_by_imsi_hash = rte_hash_create(&rte_hash_params);
	if (!ue_context_by_imsi_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
	rte_hash_params.name = "bearer_by_fteid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	ue_context_by_fteid_hash = rte_hash_create(&rte_hash_params);
	if (!ue_context_by_fteid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}


void
set_ip_pool_ip(const char *ip_str)
{
	if (!inet_aton(ip_str, &ip_pool_ip))
		rte_panic("Invalid argument - %s - Exiting.", ip_str);
	printf("ip_pool_ip:  %s\n", inet_ntoa(ip_pool_ip));
}


void
set_ip_pool_mask(const char *ip_str)
{
	if (!inet_aton(ip_str, &ip_pool_mask))
		rte_panic("Invalid argument - %s - Exiting.", ip_str);
	printf("ip_pool_mask: %s\n", inet_ntoa(ip_pool_mask));
}


void
set_apn_name(apn *an_apn, char *argstr)
{
	if (argstr == NULL)
		rte_panic("APN Name argument not set\n");
	an_apn->apn_name_length = strlen(argstr) + 1;
	an_apn->apn_name_label = rte_zmalloc_socket(NULL, an_apn->apn_name_length,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (an_apn->apn_name_label == NULL)
		rte_panic("Failure to allocate apn_name_label buffer: "
				"%s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
	/* Don't copy NULL termination */
	strncpy(an_apn->apn_name_label + 1, argstr, strlen(argstr));
	char *ptr, *size;
	size = an_apn->apn_name_label;
	*size = 1;
	ptr = an_apn->apn_name_label + strlen(argstr) - 1;
	do {
		if (ptr == size)
			break;
		if (*ptr == '.') {
			*ptr = *size;
			*size = 0;
		} else {
			(*size)++;
		}
		--ptr;
	} while (ptr != an_apn->apn_name_label);
}


void
print_ue_context_by(struct rte_hash *h, ue_context *context)
{
	uint64_t *key;
	int32_t ret;
	uint32_t next = 0;
	int i;
	printf(" %16s %1s %16s %16s %8s %8s %11s\n", "imsi", "u", "mei",
			"msisdn", "s11-teid", "s11-ipv4", "56789012345");
	if (context) {
		printf("*%16lx %1lx %16lx %16lx %8x %15s ", context->imsi,
		    (uint64_t) context->unathenticated_imsi, context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		     inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			printf("%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		printf("\t0x%04x\n", context->bearer_bitmap);
	}
	if (h == NULL)
		return;
	while (1) {
		ret = rte_hash_iterate(h, (const void **) &key,
				(void **) &context, &next);
		if (ret < 0)
			break;
		printf(" %16lx %1lx %16lx %16lx %8x %15s ",
			context->imsi,
			(uint64_t) context->unathenticated_imsi,
			context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		    inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			printf("%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		printf("\t0x%4x", context->bearer_bitmap);
		puts("");
	}
}


int
create_ue_context(uint8_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context)
{
	int ret;
	int i;
	uint8_t ebi_index;
	uint64_t imsi = UINT64_MAX;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	memcpy(&imsi, imsi_val, imsi_len);

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
	    (void **) &(*context));

	if (ret == -ENOENT) {
		(*context) = rte_zmalloc_socket(NULL, sizeof(ue_context),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (*context == NULL) {
			fprintf(stderr, "Failure to allocate ue context "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->imsi = imsi;
		ret = rte_hash_add_key_data(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi, (void *) (*context));
		if (ret < 0) {
			fprintf(stderr,
				"%s - Error on rte_hash_add_key_data add\n",
				strerror(ret));
			rte_free((*context));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
		(*context)->s11_sgw_gtpc_teid = s11_sgw_gtpc_base_teid
		    + s11_sgw_gtpc_teid_offset;
		++s11_sgw_gtpc_teid_offset;

	} else if (spgw_cfg == PGWC){
		(*context)->s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
			+ s5s8_pgw_gtpc_teid_offset;
	}

	ret = rte_hash_add_key_data(ue_context_by_fteid_hash,
	    (const void *) &(*context)->s11_sgw_gtpc_teid,
	    (void *) (*context));

	if (ret < 0) {
		fprintf(stderr,
			"%s - Error on ue_context_by_fteid_hash add\n",
			strerror(ret));
		rte_hash_del_key(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi);
		if (ret < 0) {
			/* If we get here something bad happened. The
			 * context that was added to
			 * ue_context_by_imsi_hash above was not able
			 * to be removed.
			 */
			rte_panic("%s - Error on "
				"ue_context_by_imsi_hash del\n",
				strerror(ret));
		}
		rte_free((*context));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	ebi_index = ebi - 5;
	pdn = (*context)->pdns[ebi_index];
	bearer = (*context)->eps_bearers[ebi_index];

	if (bearer) {
		if (pdn) {
			/* created session is overwriting old session... */
			/*  ...clean up old session's dedicated bearers */
			for (i = 0; i < MAX_BEARERS; ++i) {
				if (!pdn->eps_bearers[i])
					continue;
				if (i == ebi_index) {
					bzero(bearer, sizeof(*bearer));
					continue;
				}
				rte_free(pdn->eps_bearers[i]);
				pdn->eps_bearers[i] = NULL;
				(*context)->eps_bearers[i] = NULL;
				(*context)->bearer_bitmap &= ~(1 << ebi_index);
			}
		} else {
			/* created session is creating a default bearer in place */
			/* of a different pdn connection's dedicated bearer */
			bearer->pdn->eps_bearers[ebi_index] = NULL;
			bzero(bearer, sizeof(*bearer));
			pdn = rte_zmalloc_socket(NULL,
				sizeof(struct pdn_connection_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (pdn == NULL) {
				fprintf(stderr, "Failure to allocate PDN "
						"structure: %s (%s:%d)\n",
						rte_strerror(rte_errno),
						__FILE__,
						__LINE__);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			(*context)->pdns[ebi_index] = pdn;
			(*context)->num_pdns++;
			pdn->eps_bearers[ebi_index] = bearer;
			pdn->default_bearer_id = ebi;
		}
	} else {
		bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			fprintf(stderr, "Failure to allocate bearer "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		bearer->eps_bearer_id = ebi;
		pdn = rte_zmalloc_socket(NULL, sizeof(struct pdn_connection_t),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (pdn == NULL) {
			fprintf(stderr, "Failure to allocate PDN "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->eps_bearers[ebi_index] = bearer;
		(*context)->pdns[ebi_index] = pdn;
		(*context)->bearer_bitmap |= (1 << ebi_index);
		pdn->eps_bearers[ebi_index] = bearer;
		pdn->default_bearer_id = ebi;
	}

	for (i = 0; i < MAX_FILTERS_PER_UE; ++i)
		bearer->packet_filter_map[i] = -ENOENT;


	bearer->pdn = pdn;
	bearer->eps_bearer_id = ebi;
	return 0;
}


apn *
get_apn(char *apn_label, uint16_t apn_length)
{
	int i;

	for (i = 0; i < MAX_NB_DPN; i++)   {
		if ((apn_length == apn_list[i].apn_name_length)
			&& !memcmp(apn_label, apn_list[i].apn_name_label,
			apn_length)) {
			break;
	        }
	}
	if(i >= MAX_NB_DPN)     {
		fprintf(stderr,
		"Received create session"
		"request with incorrect"
		"apn_label :%s", apn_label);
		return NULL;
	}

	apn_list[i].apn_idx = i;
	return apn_list+i;
}


uint32_t
acquire_ip(struct in_addr *ipv4)
{
	static uint32_t next_ip_index;
	if (unlikely(next_ip_index == LDB_ENTRIES_DEFAULT)) {
		fprintf(stderr, "IP Pool depleted\n");
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	}
	ipv4->s_addr = GET_UE_IP(next_ip_index++);
	return 0;
}

