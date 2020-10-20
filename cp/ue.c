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
#include "cp.h"
#include "interface.h"
#include "gw_adapter.h"
#include "sm_struct.h"
#include "teid.h"

extern pfcp_config_t config;
extern int clSystemLog;
struct rte_hash *ue_context_by_imsi_hash;
struct rte_hash *ue_context_by_fteid_hash;
struct rte_hash *bearer_by_fteid_hash;
struct rte_hash *li_info_by_id_hash;
struct rte_hash *li_id_by_imsi_hash;
struct rte_hash *ue_context_by_sender_teid_hash;
struct rte_hash *timer_by_teid_hash;
struct rte_hash *ddn_by_seid_hash;
struct rte_hash *dl_timer_by_teid_hash;
struct rte_hash *pfcp_rep_by_seid_hash;
struct rte_hash *thrtl_timer_by_nodeip_hash;
struct rte_hash *thrtl_ddn_count_hash;

apn apn_list[MAX_NB_DPN];
int total_apn_cnt;

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

	rte_hash_params.name = "bearer_by_teid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	bearer_by_fteid_hash = rte_hash_create(&rte_hash_params);
	if (!bearer_by_fteid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "ue_context_by_sender_teid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	ue_context_by_sender_teid_hash = rte_hash_create(&rte_hash_params);
	if (!ue_context_by_sender_teid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "timer_by_teid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	timer_by_teid_hash = rte_hash_create(&rte_hash_params);
	if (!timer_by_teid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "ddn_request_by_session_id_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	ddn_by_seid_hash = rte_hash_create(&rte_hash_params);
	if (!ddn_by_seid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "dl_timer_by_teid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	dl_timer_by_teid_hash = rte_hash_create(&rte_hash_params);
	if (!dl_timer_by_teid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "pfcp_rep_by_session_id_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	pfcp_rep_by_seid_hash = rte_hash_create(&rte_hash_params);
	if (!pfcp_rep_by_seid_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "thrtl_timer_by_nodeip_hash";
	rte_hash_params.key_len = sizeof(uint64_t);
	thrtl_timer_by_nodeip_hash = rte_hash_create(&rte_hash_params);
	if (!thrtl_timer_by_nodeip_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "thrtl_ddn_count_hash";
	rte_hash_params.key_len = sizeof(uint64_t);
	thrtl_ddn_count_hash = rte_hash_create(&rte_hash_params);
	if (!thrtl_ddn_count_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}
}

void
create_li_info_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "li_info_by_id_hash",
	    .entries = LI_LDB_ENTRIES_DEFAULT,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	li_info_by_id_hash = rte_hash_create(&rte_hash_params);
	if (!li_info_by_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
			rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}

	rte_hash_params.name = "li_id_by_imsi_hash";
	li_id_by_imsi_hash = rte_hash_create(&rte_hash_params);
	if (!li_id_by_imsi_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
			rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

void
set_apn_name(apn *an_apn, char *argstr)
{
	if (argstr == NULL)
		rte_panic("APN Name argument not set\n");
	an_apn->apn_name_length = strnlen(argstr,MAX_NB_DPN) + 1;
	an_apn->apn_name_label = rte_zmalloc_socket(NULL, an_apn->apn_name_length,
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (an_apn->apn_name_label == NULL)
		rte_panic("Failure to allocate apn_name_label buffer: "
				"%s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
	/* Don't copy NULL termination */
	strncpy(an_apn->apn_name_label + 1, argstr, strnlen(argstr,MAX_NB_DPN));
	char *ptr, *size;
	size = an_apn->apn_name_label;
	*size = 1;
	ptr = an_apn->apn_name_label + strnlen(argstr,MAX_NB_DPN) - 1;
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
	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT" %16s %1s %16s %16s %8s %8s %11s\n", LOG_VALUE, "imsi", "u", "mei",
			"msisdn", "s11-teid", "s11-ipv4", "56789012345");
	if (context) {
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"*%16lx %1lx %16lx %16lx %8x %15s ", LOG_VALUE, context->imsi,
		    (uint64_t) context->unathenticated_imsi, context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		     inet_ntoa(*((struct in_addr *)&context->s11_sgw_gtpc_ip.ipv4_addr)));
		for (i = 0; i < MAX_BEARERS; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "Bearer bitmap %c",
				LOG_VALUE, (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"\t0x%04x\n", LOG_VALUE, context->bearer_bitmap);
	}
	if (h == NULL)
		return;
	while (1) {
		ret = rte_hash_iterate(h, (const void **) &key,
				(void **) &context, &next);
		if (ret < 0)
			break;
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT" %16lx %1lx %16lx %16lx %8x %15s ", LOG_VALUE,
			context->imsi,
			(uint64_t) context->unathenticated_imsi,
			context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		    inet_ntoa(*((struct in_addr *)&context->s11_sgw_gtpc_ip.ipv4_addr)));
		for (i = 0; i < MAX_BEARERS; ++i) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "Bearer bitmap %c",
				LOG_VALUE, (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "\t0x%4x", LOG_VALUE, context->bearer_bitmap);
		puts("");
	}
}

int
add_bearer_entry_by_sgw_s5s8_tied(uint32_t fteid_key, struct eps_bearer_t **bearer)
{
	int8_t ret = 0;
	ret = rte_hash_add_key_data(bearer_by_fteid_hash,
	    (const void *) &fteid_key, (void *) (*bearer));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			"%s - Error on rte_hash_add_key_data add\n",
			strerror(ret));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Added bearer entry by sgw_s5s8_teid:%u\n", LOG_VALUE, fteid_key);
	return 0;
}

int
create_ue_context(uint64_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, apn *apn_requested,
		uint32_t sequence, uint8_t *check_if_ue_hash_exist,
		uint8_t cp_type)
{
	int ret;
	int ebi_index;
	uint64_t imsi = UINT64_MAX;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;

	memcpy(&imsi, imsi_val, imsi_len);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
	    (void **) &(*context));

	if (ret == -ENOENT) {
		(*context) = rte_zmalloc_socket(NULL, sizeof(ue_context),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (*context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for Context, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->imsi = imsi;
		(*context)->imsi_len = imsi_len;
		ret = rte_hash_add_key_data(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi, (void *) (*context));
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
				"%s - Error on rte_hash_add_key_data add\n", LOG_VALUE,
				strerror(ret));
			rte_free((*context));
			*context = NULL;
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	} else {
		/* VS: TODO: Need to think on this, flush entry when received DSR*/
		RTE_SET_USED(apn_requested);
		*check_if_ue_hash_exist = 1;
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return -1;
		}

		if((*context)->eps_bearers[ebi_index] != NULL ) {
			pdn = (*context)->eps_bearers[ebi_index]->pdn;
			if(pdn != NULL ) {
				if(pdn->csr_sequence == sequence )
				{
					/* Discarding re-transmitted csr */
					return GTPC_RE_TRANSMITTED_REQ;
				}
			}
		}
	}

	(*context)->s11_sgw_gtpc_teid =
		get_s11_sgw_gtpc_teid(check_if_ue_hash_exist, cp_type, (*context)->s11_sgw_gtpc_teid);

	ret = rte_hash_add_key_data(ue_context_by_fteid_hash,
	    (const void *) &(*context)->s11_sgw_gtpc_teid,
	    (void *) (*context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
			"%s - Error on ue_context_by_fteid_hash add\n", LOG_VALUE,
			strerror(ret));
		ret = rte_hash_del_key(ue_context_by_imsi_hash,
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
		if (*context != NULL) {
			rte_free((*context));
			*context = NULL;
		}
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	bearer = (*context)->eps_bearers[ebi_index];

	if (bearer) {
		if (pdn) {
			/* created session is overwriting old session... */
			/*  ...clean up old session's dedicated bearers */
			for (int i = 0; i < MAX_BEARERS; ++i) {
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
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for PDN, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			pdn->num_bearer++;
			(*context)->pdns[ebi_index] = pdn;
			(*context)->num_pdns++;
			pdn->eps_bearers[ebi_index] = bearer;
		}
	} else {
		/*
		 * Allocate default bearer
		 */
		bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for Bearer, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		bearer->eps_bearer_id = ebi;

		int ret = get_pdn(&(*context), apn_requested, &pdn);
		/* NOTE : APN comparison has been done to handle
		 * the  case of multiple PDN;
		 * In mutiple PDN, each PDN will have a unique apn*/
		if(ret < 0) {

			pdn = rte_zmalloc_socket(NULL, sizeof(struct pdn_connection_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
					"Memory for PDN, Error: %s \n", LOG_VALUE,
						rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			pdn->num_bearer++;
			(*context)->eps_bearers[ebi_index] = bearer;
			(*context)->pdns[ebi_index] = pdn;
			(*context)->num_pdns++;
			(*context)->bearer_bitmap |= (1 << ebi_index);
			pdn->eps_bearers[ebi_index] = bearer;
			pdn->default_bearer_id = ebi;
		} else {
			pdn->num_bearer++;
			(*context)->eps_bearers[ebi_index] = bearer;
			pdn->eps_bearers[ebi_index] = bearer;
		}
	}

	for (int i = 0; i < MAX_FILTERS_PER_UE; ++i)
		bearer->packet_filter_map[i] = -ENOENT;


	bearer->pdn = pdn;
	bearer->eps_bearer_id = ebi;
	pdn->apn_in_use = apn_requested;
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
	if(i >= MAX_NB_DPN) {
		/* when apn name of csr are not found in cp.cfg file */
		/* TODO : free apn_reruested and apn_name_label memory */
		apn *apn_requested = rte_zmalloc_socket(NULL, sizeof(apn),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (apn_requested == NULL) {
			rte_panic("Failure to allocate apn_requested buffer: "
					"%s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return NULL;
		}

		apn_requested->apn_name_label = rte_zmalloc_socket(NULL, apn_length,
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (apn_requested->apn_name_label == NULL) {
			rte_panic("Failure to allocate apn_name_label buffer: "
					"%s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return NULL;
		}
		strncpy(apn_requested->apn_name_label, apn_label, apn_length);
		apn_requested->apn_name_length = apn_length;
		/*TODO: need to discuss with himanshu */
		apn_requested->apn_idx = -1;
		/*Using default value*/
		apn_requested->trigger_type = config.trigger_type;
		apn_requested->uplink_volume_th = config.uplink_volume_th;
		apn_requested->downlink_volume_th = config.downlink_volume_th;
		apn_requested->time_th = config.time_th;
		/*Using default IP pool if no configured APN is used.*/
		apn_requested->ip_pool_ip = config.ip_pool_ip;
		apn_requested->ip_pool_mask = config.ip_pool_mask;
		memcpy(apn_requested->ipv6_network_id.s6_addr,
				config.ipv6_network_id.s6_addr,
									IPV6_ADDRESS_LEN);
		apn_requested->ipv6_prefix_len = config.ipv6_prefix_len;

		return apn_requested;
	}

	apn_list[i].apn_idx = i;
	return apn_list+i;
}

apn *set_default_apn(void)
{

	apn *apn_requested = rte_zmalloc_socket(NULL, sizeof(apn),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if (apn_requested == NULL) {

		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Failure to allocate apn_requested buffer", LOG_VALUE);

		//return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/*Using default value*/
	apn_requested->apn_name_label = NULL;
	apn_requested->trigger_type = config.trigger_type;
	apn_requested->uplink_volume_th = config.uplink_volume_th;
	apn_requested->downlink_volume_th = config.downlink_volume_th;
	apn_requested->time_th = config.time_th;

	return apn_requested;

}

uint32_t
acquire_ip(struct in_addr ip_pool,
			struct in_addr ip_pool_mask,
					struct in_addr *ipv4) {
	static uint32_t next_ip_index;
	if (unlikely(next_ip_index == LDB_ENTRIES_DEFAULT)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "IP Pool depleted\n", LOG_VALUE);
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	}
	ipv4->s_addr = GET_UE_IP(ip_pool, ip_pool_mask, next_ip_index++);
	RTE_SET_USED(ip_pool);
	return 0;
}


static int
fill_ipv6(uint8_t *ipv6, uint64_t prefix_len){

	static uint8_t next_ipv6_index;
	static uint8_t pos;
	if(next_ipv6_index == MAX_UINT8_T_VAL){
		pos++;
		next_ipv6_index = 0;
		if(pos + prefix_len >= IPV6_ADDRESS_LEN)
			return -1;
	}

	int i = 0;
	for(i = 0; i < pos; i++){
		*(ipv6 + i) = MAX_UINT8_T_VAL;
	}
	*(ipv6 + i) = ++next_ipv6_index;

	return 0;
}

uint32_t
acquire_ipv6(struct in6_addr ipv6_network_id, uint8_t prefix_len,
								struct in6_addr *ipv6) {
	int ret = 0;
	memcpy(ipv6->s6_addr, ipv6_network_id.s6_addr, IPV6_ADDRESS_LEN);
	ret = fill_ipv6(ipv6->s6_addr + prefix_len, prefix_len);
	if(ret){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "IPv6 Pool depleted\n", LOG_VALUE);
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	}
	return 0;
}
