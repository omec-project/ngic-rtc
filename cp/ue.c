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
#include "clogger.h"

extern pfcp_config_t pfcp_config;
struct rte_hash *ue_context_by_imsi_hash;
struct rte_hash *ue_context_by_fteid_hash;
struct rte_hash *pdn_by_fteid_hash;
struct rte_hash *bearer_by_fteid_hash;

static struct in_addr ip_pool_ip;
static struct in_addr ip_pool_mask;

apn apn_list[MAX_NB_DPN];

/* base value and offset for seid generation */
const uint32_t s11_sgw_gtpc_base_teid = 0xC0FFEE;
static uint32_t s11_sgw_gtpc_teid_offset;
const uint32_t s5s8_sgw_gtpc_base_teid = 0xE0FFEE;
const uint32_t s5s8_pgw_gtpc_base_teid = 0xD0FFEE;
static uint32_t s5s8_pgw_gtpc_teid_offset;

/* base value and offset for teid generation */
static uint32_t sgw_gtpc_base_teid = 0xC0FFEE;
static uint32_t sgw_gtpc_teid_offset;
static uint32_t pgw_gtpc_base_teid = 0xD0FFEE;
static uint32_t pgw_gtpc_teid_offset;
static uint8_t teid_range = 0xf0;
static uint32_t sgw_gtpu_base_teid = 0xf0000001;
static uint32_t pgw_gtpu_base_teid = 0x00000001;
/*TODO : Decide how to diffrentiate between sgw and pgw teids*/

uint32_t base_s1u_sgw_gtpu_teid = 0xf0000000;

void
set_base_teid(uint8_t val){

	/* set cp teid_range value */
	teid_range = val;

	/* set base teid value */
	/* teid will start from index 1 instead of index 0*/
	if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC){
		sgw_gtpc_base_teid = (teid_range << 24);
		sgw_gtpc_base_teid++;
	}else if(pfcp_config.cp_type == PGWC){
		pgw_gtpc_base_teid = (teid_range << 24);
		pgw_gtpc_base_teid++;
	}
	return;
}

void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
		sgw_gtpu_base_teid = sgw_gtpc_base_teid + sgw_gtpc_teid_offset;
		++sgw_gtpc_teid_offset;
	}

	bearer->s1u_sgw_gtpu_teid = (sgw_gtpu_base_teid & 0x00ffffff)
		| ((teid_range + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context)
{
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
	 * Computation same as s1u_sgw_gtpu_teid
	 */
	bearer->s5s8_sgw_gtpu_teid = (sgw_gtpu_base_teid & 0x00ffffff)
	    | ((teid_range + index) << 24);
	context->teid_bitmap |= (0x01 << index);
}

void
set_s5s8_pgw_gtpu_teid(eps_bearer *bearer, ue_context *context){
	uint8_t index = __builtin_ffs(~(context->teid_bitmap)) - 1;
	if (spgw_cfg == PGWC){
		pgw_gtpu_base_teid = pgw_gtpc_base_teid + pgw_gtpc_teid_offset;
		++pgw_gtpc_teid_offset;
	}
	bearer->s5s8_pgw_gtpu_teid = (pgw_gtpu_base_teid & 0x00ffffff)
		| ((teid_range + index) << 24);
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
set_s5s8_pgw_gtpu_teid_using_pdn(eps_bearer *bearer, pdn_connection *pdn)
{
	uint8_t index = __builtin_ffs(~(pdn->context->teid_bitmap)) - 1;
	/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
	 * Computation same as s1u_sgw_gtpu_teid
	 */
	bearer->s5s8_pgw_gtpu_teid = (pdn->s5s8_pgw_gtpc_teid & 0x00ffffff)
	    | ((0xf0 + index) << 24);
	pdn->context->teid_bitmap |= (0x01 << index);
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

	rte_hash_params.name = "pdn_by_fteid_hash";
	rte_hash_params.key_len = sizeof(uint32_t);
	pdn_by_fteid_hash = rte_hash_create(&rte_hash_params);
	if (!pdn_by_fteid_hash) {
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
}


void
set_ip_pool_ip(const char *ip_str)
{
	if (!inet_aton(ip_str, &ip_pool_ip))
		rte_panic("Invalid argument - %s - Exiting.", ip_str);
	clLog(clSystemLog, eCLSeverityDebug,"ip_pool_ip:  %s\n", inet_ntoa(ip_pool_ip));
}


void
set_ip_pool_mask(const char *ip_str)
{
	if (!inet_aton(ip_str, &ip_pool_mask))
		rte_panic("Invalid argument - %s - Exiting.", ip_str);
	clLog(clSystemLog, eCLSeverityDebug,"ip_pool_mask: %s\n", inet_ntoa(ip_pool_mask));
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
	clLog(clSystemLog, eCLSeverityDebug," %16s %1s %16s %16s %8s %8s %11s\n", "imsi", "u", "mei",
			"msisdn", "s11-teid", "s11-ipv4", "56789012345");
	if (context) {
		clLog(clSystemLog, eCLSeverityDebug,"*%16lx %1lx %16lx %16lx %8x %15s ", context->imsi,
		    (uint64_t) context->unathenticated_imsi, context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		     inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		clLog(clSystemLog, eCLSeverityDebug,"\t0x%04x\n", context->bearer_bitmap);
	}
	if (h == NULL)
		return;
	while (1) {
		ret = rte_hash_iterate(h, (const void **) &key,
				(void **) &context, &next);
		if (ret < 0)
			break;
		clLog(clSystemLog, eCLSeverityDebug," %16lx %1lx %16lx %16lx %8x %15s ",
			context->imsi,
			(uint64_t) context->unathenticated_imsi,
			context->mei,
		    context->msisdn, context->s11_sgw_gtpc_teid,
		    inet_ntoa(context->s11_sgw_gtpc_ipv4));
		for (i = 0; i < MAX_BEARERS; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"%c", (context->bearer_bitmap & (1 << i))
					? '1' : '0');
		}
		clLog(clSystemLog, eCLSeverityDebug,"\t0x%4x", context->bearer_bitmap);
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
	return 0;
}

int
create_ue_context(uint64_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, apn *apn_requested,
	  	uint32_t sequence)
{
	int ret;
	int i;
	uint8_t ebi_index;
	uint64_t imsi = UINT64_MAX;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int if_ue_present = 0;

	memcpy(&imsi, imsi_val, imsi_len);

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi,
	    (void **) &(*context));

	if (ret == -ENOENT) {
		(*context) = rte_zmalloc_socket(NULL, sizeof(ue_context),
		    RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (*context == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate ue context "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		(*context)->imsi = imsi;
		(*context)->imsi_len = imsi_len;
		ret = rte_hash_add_key_data(ue_context_by_imsi_hash,
		    (const void *) &(*context)->imsi, (void *) (*context));
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				"%s - Error on rte_hash_add_key_data add\n",
				strerror(ret));
			rte_free((*context));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	} else {
		/* VS: TODO: Need to think on this, flush entry when received DSR*/
		RTE_SET_USED(apn_requested);
		if_ue_present = 1;
		if((*context)->eps_bearers[ebi - 5] != NULL ) {
			pdn = (*context)->eps_bearers[ebi - 5]->pdn;
			if(pdn != NULL ) {
				if(pdn->csr_sequence == sequence ) 
				{
					/* -2 : Discarding re-transmitted csr */
					return -2;
				}
			}
		}
		/*if ((strncmp(apn_requested->apn_name_label,
					(((*context)->pdns[ebi - 5])->apn_in_use)->apn_name_label,
					sizeof(apn_requested->apn_name_length))) == 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				"%s- Discarding re-transmitted csr received for IMSI:%lu \n",
				__func__, imsi);
			return -1;
		}*/
	}
	if (if_ue_present == 0){
		if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
			(*context)->s11_sgw_gtpc_teid = s11_sgw_gtpc_base_teid
			    + s11_sgw_gtpc_teid_offset;
			++s11_sgw_gtpc_teid_offset;

		} else if (spgw_cfg == PGWC){
			(*context)->s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
				+ s5s8_pgw_gtpc_teid_offset;
		}
	}else if (spgw_cfg == PGWC){
		(*context)->s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
			+ s5s8_pgw_gtpc_teid_offset;
	}

	ret = rte_hash_add_key_data(ue_context_by_fteid_hash,
	    (const void *) &(*context)->s11_sgw_gtpc_teid,
	    (void *) (*context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
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
				clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate PDN "
						"structure: %s (%s:%d)\n",
						rte_strerror(rte_errno),
						__FILE__,
						__LINE__);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
			pdn->num_bearer++;
			(*context)->pdns[ebi_index] = pdn;
			(*context)->num_pdns++;
			pdn->eps_bearers[ebi_index] = bearer;
			pdn->default_bearer_id = ebi;
		}
	} else {
		/*
		 * Allocate default bearer
		 */
		bearer = rte_zmalloc_socket(NULL, sizeof(eps_bearer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (bearer == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate bearer "
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
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate PDN "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		pdn->num_bearer++;
		(*context)->eps_bearers[ebi_index] = bearer;
		(*context)->pdns[ebi_index] = pdn;
		(*context)->num_pdns++;
		(*context)->bearer_bitmap |= (1 << ebi_index);
		pdn->eps_bearers[ebi_index] = bearer;
		pdn->default_bearer_id = ebi;
	}

	for (i = 0; i < MAX_FILTERS_PER_UE; ++i)
		bearer->packet_filter_map[i] = -ENOENT;


	bearer->pdn = pdn;
	bearer->eps_bearer_id = ebi;

	pdn = (*context)->pdns[ebi_index];
	bearer = (*context)->eps_bearers[ebi_index];

	ret = rte_hash_add_key_data(pdn_by_fteid_hash,
	    (const void *) &(*context)->s11_sgw_gtpc_teid,
	    (void *) pdn);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			"%s - Error on pdn_by_fteid_hash add\n",
			strerror(ret));
		rte_hash_del_key(pdn_by_fteid_hash,
		    (const void *) &(*context)->s11_sgw_gtpc_teid);
		if (ret < 0) {
			/* If we get here something bad happened. The
			 * context that was added to
			 * ue_context_by_imsi_hash above was not able
			 * to be removed.
			 */
			rte_panic("%s - Error on "
				"pdn_by_fteid_hash del\n",
				strerror(ret));
		}
		rte_free((*context));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

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
		/* BP : TODO : free apn_reruested and apn_name_label memory */
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
		return apn_requested;
	}

	apn_list[i].apn_idx = i;
	return apn_list+i;
}

uint32_t
acquire_ip(struct in_addr *ipv4)
{
	static uint32_t next_ip_index;
	if (unlikely(next_ip_index == LDB_ENTRIES_DEFAULT)) {
		clLog(clSystemLog, eCLSeverityCritical, "IP Pool depleted\n");
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	}
	ipv4->s_addr = GET_UE_IP(next_ip_index++);
	return 0;
}

