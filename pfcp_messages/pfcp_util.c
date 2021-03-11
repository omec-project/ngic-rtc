/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#include <sys/time.h>
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_hash_crc.h>

#include "li_interface.h"
#include "gw_adapter.h"
#include "pfcp_enum.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages.h"
#include "../cp_dp_api/tcp_client.h"
#include "pfcp_messages_decoder.h"

#ifdef CP_BUILD
#include "cp_config.h"
#include "sm_pcnd.h"
#include "cp_timer.h"
#include "cp_stats.h"
#include "li_config.h"
#include "pfcp_session.h"
#include "gtpv2c_error_rsp.h"
#include "cdnshelper.h"
#endif /* CP_BUILD */

extern int pfcp_fd;
extern int pfcp_fd_v6;
extern void *ddf2_fd;

struct rte_hash *heartbeat_recovery_hash;
struct rte_hash *associated_upf_hash;
extern int clSystemLog;

#ifdef CP_BUILD
extern pfcp_config_t config;

/**
 * @brief  : free canonical result list
 * @param  : result , result list
 * @param  : res_count , total entries in result
 * @return : Returns nothing
 */
static void
free_canonical_result_list(canonical_result_t *result, uint8_t res_count) {
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Free DNS canonical result list :: SART \n", LOG_VALUE);
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"DNS result count: %d \n", LOG_VALUE,
			res_count);
	for (uint8_t itr = 0; itr < res_count; itr++) {

		if (result[itr].host1_info.ipv4_hosts != NULL) {
			for (uint8_t itr1 = 0; itr1 < result[itr].host1_info.ipv4host_count; itr1++) {
				if (result[itr].host1_info.ipv4_hosts[itr1] != NULL) {
					free(result[itr].host1_info.ipv4_hosts[itr1]);
					result[itr].host1_info.ipv4_hosts[itr1] = NULL;
				}
			}
			free(result[itr].host1_info.ipv4_hosts);
			result[itr].host1_info.ipv4_hosts = NULL;
		}

		if (result[itr].host1_info.ipv6_hosts != NULL) {
			for (uint8_t itr2 = 0; itr2 < result[itr].host1_info.ipv6host_count; itr2++) {
				if (result[itr].host1_info.ipv6_hosts[itr2] != NULL) {
					free(result[itr].host1_info.ipv6_hosts[itr2]);
					result[itr].host1_info.ipv6_hosts[itr2] = NULL;
				}
			}
			free(result[itr].host1_info.ipv6_hosts);
			result[itr].host1_info.ipv6_hosts = NULL;
		}

		if (result[itr].host2_info.ipv4_hosts != NULL) {
			for (uint8_t itr3 = 0; itr3 < result[itr].host2_info.ipv4host_count; itr3++) {
				if (result[itr].host2_info.ipv4_hosts[itr3] != NULL) {
					free(result[itr].host2_info.ipv4_hosts[itr3]);
					result[itr].host2_info.ipv4_hosts[itr3] = NULL;
				}
			}
			free(result[itr].host2_info.ipv4_hosts);
			result[itr].host2_info.ipv4_hosts = NULL;
		}

		if (result[itr].host2_info.ipv6_hosts != NULL) {
			for (uint8_t itr4 = 0; itr4 < result[itr].host2_info.ipv6host_count; itr4++) {
				if (result[itr].host2_info.ipv6_hosts[itr4] != NULL) {
					free(result[itr].host2_info.ipv6_hosts[itr4]);
					result[itr].host2_info.ipv6_hosts[itr4] = NULL;
				}
			}
			free(result[itr].host2_info.ipv6_hosts);
			result[itr].host2_info.ipv6_hosts = NULL;
		}
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Free DNS canonical result list :: END \n", LOG_VALUE);

}

/**
 * @brief  : free DNS result list
 * @param  : result , result list
 * @param  : res_count , total entries in result
 * @return : Returns nothing
 */
static void
free_dns_result_list(dns_query_result_t *res, uint8_t res_count) {

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Free DNS result list :: SART \n", LOG_VALUE);
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"DNS result count: %d \n", LOG_VALUE,
			res_count);
	for (uint8_t itr = 0; itr < res_count; itr++) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPV4 DNS result count: %d \n", LOG_VALUE,
				res[itr].ipv4host_count);

		if (res[itr].ipv4_hosts != NULL) {
			for (uint8_t itr1 = 0; itr1 < res[itr].ipv4host_count; itr1++) {
				if (res[itr].ipv4_hosts[itr1] != NULL) {
					free(res[itr].ipv4_hosts[itr1]);
					res[itr].ipv4_hosts[itr1] = NULL;
				}
			}
			free(res[itr].ipv4_hosts);
			res[itr].ipv4_hosts = NULL;
		}

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPV6 DNS result count: %d \n", LOG_VALUE,
				res[itr].ipv6host_count);
		if (res[itr].ipv6_hosts != NULL) {
			for (uint8_t itr2 = 0; itr2 < res[itr].ipv6host_count; itr2++) {
				if (res[itr].ipv6_hosts[itr2] != NULL) {
					free(res[itr].ipv6_hosts[itr2]);
					res[itr].ipv6_hosts[itr2] = NULL;
				}
			}
			free(res[itr].ipv6_hosts);
			res[itr].ipv6_hosts = NULL;
		}
	}
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Free DNS result list :: END \n", LOG_VALUE);
}

static void
add_dns_result_v6(dns_query_result_t *res, upfs_dnsres_t *upf_list,
					uint8_t i, uint8_t *upf_v6_cnt)
{

	for (int j = 0; j < res[i].ipv6host_count; j++) {
		int flag_added = false;
		/* TODO:: duplicate entries should not be present in result itself */
		if(upf_list->upf_count == 0){
			inet_pton(AF_INET6, res[i].ipv6_hosts[j], &(upf_list->upf_ip[upf_list->upf_count].ipv6));
			memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].hostname,
					strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
			flag_added = TRUE;

		}else{
			int match_found = false;
			for (int k = 0; k < upf_list->upf_count ; k++) {
				struct in6_addr temp_ip6;

				inet_pton(AF_INET6, res[i].ipv6_hosts[j], temp_ip6.s6_addr);

				uint8_t ret = memcmp(temp_ip6.s6_addr, upf_list->upf_ip[k].ipv6.s6_addr, IPV6_ADDRESS_LEN);
				if (!ret) {
					break;
				}
			}

			if(match_found == false){
				inet_pton(AF_INET6, res[i].ipv6_hosts[j], &upf_list->upf_ip[upf_list->upf_count].ipv6);

				memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].hostname,
						strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;
			}
		}
		if(flag_added == TRUE){
			*upf_v6_cnt += 1;
		}
	}
	upf_list->upf_ip_type = PDN_TYPE_IPV6;
}


static void
add_dns_result_v4(dns_query_result_t *res, upfs_dnsres_t *upf_list,
						uint8_t i, uint8_t *upf_v4_cnt)
{
	for (int j = 0; j < res[i].ipv4host_count; j++) {
		int flag_added = false;
		/* TODO:: duplicate entries should not be present in result itself */
		if(upf_list->upf_count == 0) {
			inet_aton(res[i].ipv4_hosts[j],
					&upf_list->upf_ip[upf_list->upf_count].ipv4);
			memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].hostname,
					strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
			flag_added = TRUE;

		} else {
			int match_found = false;
			for (int k = 0; k < upf_list->upf_count ; k++) {
				struct in_addr temp_ip;
				inet_aton(res[i].ipv4_hosts[j],
						&temp_ip);
				if( temp_ip.s_addr == upf_list->upf_ip[k].ipv4.s_addr){
					break;
				}
			}

			if(match_found == false){
				inet_aton(res[i].ipv4_hosts[j],
						&upf_list->upf_ip[upf_list->upf_count].ipv4);
				memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].hostname,
						strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;
			}
		}

		if(flag_added == TRUE){
			*upf_v4_cnt += 1;
		}
	}
	upf_list->upf_ip_type = PDN_TYPE_IPV4;
}

static void
add_canonical_result_v4(canonical_result_t *res, upfs_dnsres_t *upf_list,
						uint8_t i, uint8_t *upf_v4_cnt)
{
	for (int j = 0; j < res[i].host2_info.ipv4host_count; j++) {
		int flag_added = false;
		/* TODO:: duplicate entries should not be present in result itself */
		if(upf_list->upf_count == 0){
			inet_aton(res[i].host2_info.ipv4_hosts[j],
					&upf_list->upf_ip[upf_list->upf_count].ipv4);
			memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].cano_name2,
					strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
			flag_added = TRUE;

		} else {
			int match_found = false;
			for (int k = 0; k < upf_list->upf_count ; k++) {
				struct in_addr temp_ip;
				inet_aton(res[i].host2_info.ipv4_hosts[j],
						&temp_ip);
				if( temp_ip.s_addr == upf_list->upf_ip[k].ipv4.s_addr){
					match_found = true;
					break;
				}
			}
			if(match_found == false){

				inet_aton(res[i].host2_info.ipv4_hosts[j],
						&upf_list->upf_ip[upf_list->upf_count].ipv4);
				memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].cano_name2,
						strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;
			}
		}

		if(flag_added == TRUE){
			*upf_v4_cnt += 1;
		}
	}

	upf_list->upf_ip_type = PDN_TYPE_IPV4;
}

static void
add_canonical_result_v6(canonical_result_t *res, upfs_dnsres_t *upf_list,
								uint8_t i, uint8_t *upf_v6_cnt)
{

	for (int j = 0; j < res[i].host2_info.ipv6host_count; j++) {
		int flag_added = false;
		/* TODO:: duplicate entries should not be present in result itself */
		if(upf_list->upf_count == 0){

			inet_pton(AF_INET6, res[i].host2_info.ipv6_hosts[j],
							&(upf_list->upf_ip[upf_list->upf_count].ipv6));
			memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].cano_name2,
					strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
			flag_added = TRUE;

		}else{
			int match_found = false;
			for (int k = 0; k < upf_list->upf_count; k++) {

				char ipv6[IPV6_STR_LEN];
				inet_ntop(AF_INET6, upf_list->upf_ip[k].ipv6.s6_addr, ipv6, IPV6_ADDRESS_LEN);

				uint8_t ret = strncmp(res[i].host2_info.ipv6_hosts[j], ipv6 , IPV6_ADDRESS_LEN);
				if (!ret) {
					match_found = true;
					break;
				}
			}
			if(match_found == false){

				inet_pton(AF_INET6, res[i].host2_info.ipv6_hosts[j],
							&upf_list->upf_ip[upf_list->upf_count].ipv6);
				memcpy(upf_list->upf_fqdn[upf_list->upf_count], res[i].cano_name2,
						strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;
			}
		}

		if(flag_added == TRUE){
			*upf_v6_cnt += 1;
		}
	}

	upf_list->upf_ip_type = PDN_TYPE_IPV6;
}

/**
 * @brief  : Add canonical result entry in upflist hash
 * @param  : res , result
 * @param  : res_count , total entries in result
 * @param  : imsi_val , imsi value
 * @param  : imsi_len , imsi length
 * @return : Returns upf count in case of success , 0 if could not get list , -1 otherwise
 */
static int
add_canonical_result_upflist_entry(canonical_result_t *res,
		uint8_t res_count, uint64_t *imsi_val, uint16_t imsi_len)
{
	uint8_t count = 0;;
	upfs_dnsres_t *upf_list = rte_zmalloc_socket(NULL,
			sizeof(upfs_dnsres_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (NULL == upf_list) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory for UPF list, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
		free_canonical_result_list(res, res_count);
		return -1;
	}

	for (int i = 0; (upf_list->upf_count < res_count) && (i < QUERY_RESULT_COUNT); i++) {
		uint8_t upf_v4_cnt = 0, upf_v6_cnt = 0;

		if (res[i].host2_info.ipv6host_count == 0
				&& res[i].host2_info.ipv4host_count == 0) {
			count += 1;
			continue;
		}

		if (res[i].host2_info.ipv6host_count) {

			add_canonical_result_v6(res, upf_list, count, &upf_v6_cnt);
		}

		if (res[i].host2_info.ipv4host_count) {

			add_canonical_result_v4(res, upf_list, count, &upf_v4_cnt);

		}
		count += 1;

		if (upf_v4_cnt != 0 || upf_v6_cnt != 0)
			upf_list->upf_count += 1;
	}

	if (upf_list->upf_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Could not get collocated "
			"candidate list.\n", LOG_VALUE);
		return 0;
	}

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	free_canonical_result_list(res, res_count);

	return upf_list->upf_count;
}

/**
 * @brief  : Add dns result in upflist hash
 * @param  : res , dns result
 * @param  : res_count , total entries in result
 * @param  : imsi_val , imsi value
 * @param  : imsi_len , imsi length
 * @return : Returns upf count in case of success , 0 if could not get list , -1 otherwise
*/
static int
add_dns_result_upflist_entry(dns_query_result_t *res,
		uint8_t res_count, uint64_t *imsi_val, uint16_t imsi_len)
{
	uint8_t count = 0;
	upfs_dnsres_t *upf_list = NULL;
	int ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi_val,
		(void**)&upf_list);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "Failed to search entry in upflist_by_ue_hash"
				"hash table", LOG_VALUE);

		upf_list = rte_zmalloc_socket(NULL,
				sizeof(upfs_dnsres_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (NULL == upf_list) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for UPF list, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			free_dns_result_list(res, res_count);
			return -1;
		}
	}

	for (int i = 0; (upf_list->upf_count < res_count) && (i < QUERY_RESULT_COUNT); i++) {

		uint8_t upf_v4_cnt = 0, upf_v6_cnt = 0;
		if (res[i].ipv6host_count == 0
				&& res[i].ipv4host_count == 0) {
			count += 1;
			continue;
		}

		if (res[i].ipv6host_count) {

			add_dns_result_v6(res, upf_list, count, &upf_v6_cnt);
		}

		if (res[i].ipv4host_count) {

			add_dns_result_v4(res, upf_list, count, &upf_v4_cnt);

		}

		count += 1;

		if (upf_v4_cnt != 0 || upf_v6_cnt != 0)
			upf_list->upf_count += 1;
	}

	if (upf_list->upf_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Could not get SGW-U "
			"list using DNS query \n", LOG_VALUE);
		return 0;
	}

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	return upf_list->upf_count;
}

/**
 * @brief  : Record entries for failed enodeb
 * @param  : endid , enodeb id
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
record_failed_enbid(char *enbid)
{
	FILE *fp = fopen(FAILED_ENB_FILE, "a");

	if (fp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Could not open %s for writing failed "
				"eNodeB query entry.\n", LOG_VALUE, FAILED_ENB_FILE);
		return 1;
	}

	fwrite(enbid, sizeof(char), strnlen(enbid,MAX_ENODEB_LEN), fp);
	fwrite("\n", sizeof(char), 1, fp);
	fclose(fp);

	return 0;
}

/**
 * @brief  : get mnc mcc into string.
 * @param  : pdn, structure to store retrived pdn.
 * @param  : mnc, pointer var. to store mnc string.
 * @param  : mcc, pointer var. to store mcc string.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static void
get_mnc_mcc(pdn_connection *pdn, char *mnc, char *mcc) {

	ue_context *ctxt = NULL;

	ctxt = pdn->context;

	if (ctxt->uli.ecgi2.ecgi_mnc_digit_3 == 15)
		snprintf(mnc, MCC_MNC_LEN, "%u%u", ctxt->uli.ecgi2.ecgi_mnc_digit_1,
				ctxt->uli.ecgi2.ecgi_mnc_digit_2);
	else
		snprintf(mnc, MCC_MNC_LEN, "%u%u%u", ctxt->uli.ecgi2.ecgi_mnc_digit_1,
				ctxt->uli.ecgi2.ecgi_mnc_digit_2,
				ctxt->uli.ecgi2.ecgi_mnc_digit_3);

	snprintf(mcc, MCC_MNC_LEN,"%u%u%u", ctxt->uli.ecgi2.ecgi_mcc_digit_1,
			ctxt->uli.ecgi2.ecgi_mcc_digit_2,
			ctxt->uli.ecgi2.ecgi_mcc_digit_3);
}

/**
 * @brief  : set ue cap. and uses type.
 * @param  : node_sel, node selector.
 * @param  : pdn, structure to store retrived pdn.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static void
set_ue_cap_ue_uses(void *node_sel, pdn_connection *pdn) {

	if(strnlen(pdn->apn_in_use->apn_net_cap,MAX_NETCAP_LEN) > 0) {
		set_nwcapability(node_sel, pdn->apn_in_use->apn_net_cap);
	}

	if (pdn->apn_in_use->apn_usage_type != -1) {
		set_ueusage_type(node_sel,
				pdn->apn_in_use->apn_usage_type);
	}
}

/**
 * @brief  : get mnc mcc into string
 * @param  : pdn, structure to store retrived pdn.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
send_tac_dns_query(pdn_connection *pdn) {

	/* Query DNS based on lb and hb of tac */
	char lb[LB_HB_LEN] = {0};
	char hb[LB_HB_LEN] = {0};
	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};
	char enodeb[MAX_ENODEB_LEN] = {0};
	uint32_t enbid = 0;
	dns_cb_userdata_t *cb_user_data = NULL;
	ue_context *ctxt = NULL;

	ctxt = pdn->context;

	enbid = ctxt->uli.ecgi2.eci >> 8;
	snprintf(enodeb, ENODE_LEN,"%u", enbid);

	record_failed_enbid(enodeb);

	if (ctxt->uli.tai != 1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
			" Could not get SGW-U list using DNS "
			"query. TAC missing in CSR.\n", LOG_VALUE);
		return -1;
	}

	get_mnc_mcc(pdn, mnc, mcc);

	snprintf(lb, LB_HB_LEN,  "%u", ctxt->uli.tai2.tai_tac & 0xFF);
	snprintf(hb, LB_HB_LEN, "%u", (ctxt->uli.tai2.tai_tac >> 8) & 0xFF);
	cb_user_data = rte_zmalloc_socket(NULL, sizeof(dns_cb_userdata_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (cb_user_data == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory for DNS user data, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	void *sgwupf_node_sel = init_sgwupf_node_selector(lb, hb, mnc, mcc);
	set_desired_proto(sgwupf_node_sel, UPF_X_SXA);

	set_ue_cap_ue_uses(sgwupf_node_sel, pdn);

	cb_user_data->cb = dns_callback;
	cb_user_data->data = pdn;
	cb_user_data->obj_type = SGWUPFNODESELECTOR;

	process_dnsreq_async(sgwupf_node_sel, cb_user_data);

	return 0;
}

/**
 * @brief  : get UPF address list.
 * @param  : node_sel, node selector info.
 * @param  : pdn, structure to store retrived pdn.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
get_upf_list(void *node_sel, pdn_connection *pdn)
{
	int upf_count = 0;
	int res_count = 0;
	ue_context *ctxt = NULL;
	canonical_result_t result[QUERY_RESULT_COUNT] = {0};

	ctxt = pdn->context;

	/* Get collocated candidate list */
	if (!strnlen((char *)pdn->fqdn,MAX_HOSTNAME_LENGTH)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
			"SGW-U node name missing in Create Session Request. \n", LOG_VALUE);
		deinit_node_selector(node_sel);
		return 0;
	}

	res_count = get_colocated_candlist_fqdn(
			(char *)pdn->fqdn, node_sel, result);

	if (res_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
			"Could not get collocated candidate list. \n", LOG_VALUE);
		deinit_node_selector(node_sel);
		return 0;
	}

	upf_count = add_canonical_result_upflist_entry(result, res_count,
			&ctxt->imsi, sizeof(ctxt->imsi));
	return upf_count;
}

static void
set_dns_resp_status(pdn_connection *pdn, void *node_sel)
{
	uint8_t node_sel_type = 0;
	node_sel_type = get_node_selector_type(node_sel);
	switch(node_sel_type) {
		case PGWUPFNODESELECTOR:
			{
				/*apn base query response received */
				pdn->dns_query_domain |= APN_BASE_QUERY;
				break;
			}
		case ENBUPFNODESELECTOR:
			{
				/* enB base query response received */
				pdn->dns_query_domain |= ENODEB_BASE_QUERY;
				pdn->enb_query_flag = ENODEB_BASE_QUERY;
				break;
			}
		case SGWUPFNODESELECTOR:
			{
				/* Tac base query response received */
				pdn->dns_query_domain |= TAC_BASE_QUERY;
				break;
			}
	}
}


int dns_callback(void *node_sel, void *data, void *user_data)
{
	uint16_t res_count = 0,canonical_res_count = 0;
	int ret = 0;
	pdn_connection *pdn = NULL;
	ue_context *ctxt = NULL;

	if (user_data != NULL) {
		rte_free(user_data);
		user_data = NULL;
	}
	pdn = (pdn_connection *) data;

	if (pdn == NULL)
		return 0;

	ctxt = pdn->context;

	dns_query_result_t res_list[QUERY_RESULT_COUNT] = {0};

	set_dns_resp_status(pdn, node_sel);

	get_dns_query_res(node_sel, res_list, &res_count);
	if ((res_count == 0) &&
			((pdn->enb_query_flag & ENODEB_BASE_QUERY) == ENODEB_BASE_QUERY)) {
		/*
		 * If in Enode base DNS query response doesn't find any UPF address
		 * then we sent tac base DNS query
		 */
		/* reseting enB base query bit */
		pdn->dns_query_domain &= (1 << ENODEB_BASE_QUERY);
		pdn->enb_query_flag &= (1 << ENODEB_BASE_QUERY);
		deinit_node_selector(node_sel);
		if (send_tac_dns_query(pdn) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"ERROR : while sending TAC base DNS query \n", LOG_VALUE);
			if (ctxt->s11_sgw_gtpc_teid != 0) {
				send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);
			}
			return 0;
		}
		return 0;
	}

	if (res_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Could not get UPF list using DNS query \n", LOG_VALUE);
		deinit_node_selector(node_sel);

		if (pdn != NULL && pdn->node_sel != NULL )
			deinit_node_selector(pdn->node_sel);

		if (ctxt->s11_sgw_gtpc_teid != 0)
			send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);

		return 0;
	}
	if (ctxt->cp_mode == PGWC) {
		if (get_upf_list(node_sel, pdn) <= 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Could not get UPF list using DNS query \n", LOG_VALUE);
			send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);
			return 0;
		}
	} else if (ctxt->cp_mode == SAEGWC) {

		if ((pdn->node_sel != NULL)
				&& (((pdn->dns_query_domain & TAC_BASE_QUERY) == TAC_BASE_QUERY)
				|| ((pdn->dns_query_domain & ENODEB_BASE_QUERY) == ENODEB_BASE_QUERY))
				&& ((pdn->dns_query_domain & APN_BASE_QUERY) == APN_BASE_QUERY)) {

			canonical_result_t result[QUERY_RESULT_COUNT] = {0};
			canonical_res_count = get_colocated_candlist(pdn->node_sel, node_sel, result);
			if (canonical_res_count == 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Could not get collocated candidate list. \n", LOG_VALUE);
				deinit_node_selector(node_sel);
				deinit_node_selector(pdn->node_sel);
				send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);
				return 0;
			}
			ret = add_canonical_result_upflist_entry(result, canonical_res_count,
					&ctxt->imsi, sizeof(ctxt->imsi));
			if (ret <= 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Failed to add collocated candidate list. \n", LOG_VALUE);
				deinit_node_selector(node_sel);
				deinit_node_selector(pdn->node_sel);
				send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);
				return 0;
			}

			deinit_node_selector(pdn->node_sel);
			pdn->node_sel = NULL;
		} else if (pdn != NULL && pdn->node_sel == NULL) {
			pdn->node_sel = node_sel;
			/* Reset eNB query flag, if eNB query resp received */
			if(pdn->enb_query_flag == ENODEB_BASE_QUERY) {
				pdn->enb_query_flag &= (1 << ENODEB_BASE_QUERY);
			}

			if (res_count != 0) {
				free_dns_result_list(res_list, res_count);
			}
			return 0;
		}
	} else {
		ret = add_dns_result_upflist_entry(res_list, res_count,
				&ctxt->imsi, sizeof(ctxt->imsi));
		if (ret <= 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Failed to add UFP list entry. \n", LOG_VALUE);
			deinit_node_selector(node_sel);
			send_error_resp(pdn, GTPV2C_CAUSE_REQUEST_REJECTED);
			return 0;
		}
	}

	/*Check If UPF IP is already set or not*/
	if (pdn->upf_ip.ip_type == 0) {

		uint8_t ret = get_upf_ip(pdn->context, pdn);
		if (!ret)
			process_pfcp_sess_setup(pdn);
		else {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to extract UPF IP\n", LOG_VALUE);
			send_error_resp(pdn, ret);
		}
	}

	if (res_count != 0) {
		free_dns_result_list(res_list, res_count);
	}
	pdn->dns_query_domain = NO_DNS_QUERY;
	deinit_node_selector(node_sel);

	return 0;
}

int
push_dns_query(pdn_connection *pdn) {

	char apn_name[MAX_APN_LEN] = {0};
	char enodeb[MAX_ENODEB_LEN] = {0};
	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};
	uint32_t enbid = 0;
	ue_context *ctxt = NULL;
	if(config.use_dns) {
		dns_cb_userdata_t *cb_user_data = NULL;

		/* Retrive the UE context */
		ctxt = pdn->context;

		/* Get enodeb id, mnc, mcc from Create Session Request */
		enbid = ctxt->uli.ecgi2.eci >> 8;

		snprintf(enodeb, ENODE_LEN,"%u", enbid);

		get_mnc_mcc(pdn, mnc, mcc);

		/* reseting dns query domain */
		pdn->dns_query_domain = NO_DNS_QUERY;

		if (pdn->context->cp_mode == SGWC || pdn->context->cp_mode == SAEGWC) {

			cb_user_data = rte_zmalloc_socket(NULL, sizeof(dns_cb_userdata_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (cb_user_data == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
					"allocate ue context structure: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			void *sgwupf_node_sel = init_enbupf_node_selector(enodeb, mnc, mcc);
			set_desired_proto(sgwupf_node_sel, UPF_X_SXA);
			set_ue_cap_ue_uses(sgwupf_node_sel, pdn);

			cb_user_data->cb = dns_callback;
			cb_user_data->data = pdn;
			cb_user_data->obj_type = ENBUPFNODESELECTOR;

			process_dnsreq_async(sgwupf_node_sel, cb_user_data);
		}
		if ((pdn->context->cp_mode == PGWC) || (pdn->context->cp_mode == SAEGWC)) {
			if (!pdn->apn_in_use) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" APN context not found \n",
						LOG_VALUE);
				return 0;
			}
			cb_user_data = rte_zmalloc_socket(NULL, sizeof(dns_cb_userdata_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (cb_user_data == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
					"allocate ue context structure: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			memcpy(apn_name, (pdn->apn_in_use)->apn_name_label + 1,
					(pdn->apn_in_use)->apn_name_length -1);

			void *pgwupf_node_sel = init_pgwupf_node_selector(apn_name, mnc, mcc);

			set_desired_proto(pgwupf_node_sel, UPF_X_SXB);
			set_ue_cap_ue_uses(pgwupf_node_sel, pdn);

			cb_user_data->cb = dns_callback;
			cb_user_data->data = pdn;
			cb_user_data->obj_type = PGWUPFNODESELECTOR;

			process_dnsreq_async(pgwupf_node_sel, cb_user_data);

		}

	}
	return 0;
}

int
pfcp_recv(void *msg_payload, uint32_t size, peer_addr_t *peer_addr, bool is_ipv6)
{
	socklen_t v4_addr_len = sizeof(peer_addr->ipv4);
	socklen_t v6_addr_len = sizeof(peer_addr->ipv6);
	int bytes = 0;

	if (!is_ipv6 ) {

		bytes = recvfrom(pfcp_fd, msg_payload, size,
					MSG_DONTWAIT, (struct sockaddr *) &peer_addr->ipv4,
					&v4_addr_len);

		peer_addr->type |= PDN_TYPE_IPV4;
		clLog(clSystemLog, eCLSeverityDebug, "pfcp received %d bytes "
				"with IPv4 Address", bytes);

	} else {

		bytes = recvfrom(pfcp_fd_v6, msg_payload, size,
						MSG_DONTWAIT, (struct sockaddr *) &peer_addr->ipv6,
						&v6_addr_len);

		peer_addr->type |= PDN_TYPE_IPV6;
		clLog(clSystemLog, eCLSeverityDebug, "pfcp received %d bytes "
				"with IPv6 Address", bytes);

	}

	if(bytes == 0){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error Receving on PFCP Sock ",LOG_VALUE);
	}

	return bytes;
}
#endif /* CP_BUILD */

/**
 * @brief  : Retrive SEID from encoded message
 * @param  : msg_payload, encoded message
 * @return : Returns seid for PFCP
 */
static uint64_t get_seid(void *msg_payload){

	pfcp_header_t header = {0};
	decode_pfcp_header_t((uint8_t *)msg_payload, &header);

	/*To get CP fseid as in Case of PFCP_SESS_ESTAB_REQ
	 * We send 0 to establish connection with new DP in pfcp header seid*/
	if(header.s && !header.seid_seqno.has_seid.seid &&
			header.message_type == PFCP_SESS_ESTAB_REQ){
		pfcp_sess_estab_req_t pfcp_session_request = {0};
		decode_pfcp_sess_estab_req_t(msg_payload, &pfcp_session_request);
		return pfcp_session_request.cp_fseid.seid;
	}

	if(header.s)
		return header.seid_seqno.has_seid.seid;
	else
		return 0;
}

int
pfcp_send(int fd_v4, int fd_v6, void *msg_payload, uint32_t size,
								peer_addr_t peer_addr, Dir dir)
{

	pfcp_header_t *head = (pfcp_header_t *)msg_payload;
	int bytes = 0;

	if (peer_addr.type == PDN_TYPE_IPV4) {

		if(fd_v4 <= 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"PFCP send is "
				"not possible due to incompatiable IP Type at "
				"Source and Destination\n", LOG_VALUE);
			return 0;
		}

		bytes = sendto(fd_v4, (uint8_t *) msg_payload, size, MSG_DONTWAIT,
		(struct sockaddr *) &peer_addr.ipv4, sizeof(peer_addr.ipv4));

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::pfcp_send()"
			"\n\tpfcp_fd_v4= %d, payload_length= %d ,Direction= %d, tx bytes= %d\n",
			LOG_VALUE, fd_v4, size, dir, bytes);

	} else if (peer_addr.type == PDN_TYPE_IPV6) {

		if(fd_v6 <= 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"PFCP send is "
				"not possible due to incompatiable IP Type at "
				"Source and Destination\n", LOG_VALUE);
			return 0;
		}

		bytes = sendto(fd_v6, (uint8_t *) msg_payload, size, MSG_DONTWAIT,
		(struct sockaddr *) &peer_addr.ipv6, sizeof(peer_addr.ipv6));

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::pfcp_send()"
			"\n\tpfcp_fd_v6= %d, payload_length= %d ,Direction= %d, tx bytes= %d\n",
			LOG_VALUE, fd_v6, size, dir, bytes);

	} else {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Socket Type "
				"is not set for sending message over PFCP interface ",
				LOG_VALUE);
	}

	update_cli_stats((peer_address_t *) &peer_addr, head->message_type, dir, SX);

	#ifdef CP_BUILD
	uint64_t sess_id = get_seid(msg_payload);
	process_cp_li_msg(sess_id, SX_INTFC_OUT, msg_payload, size,
			fill_ip_info(peer_addr.type, config.pfcp_ip.s_addr, config.pfcp_ip_v6.s6_addr),
			fill_ip_info(peer_addr.type, peer_addr.ipv4.sin_addr.s_addr, peer_addr.ipv6.sin6_addr.s6_addr),
			config.pfcp_port, ntohs(peer_addr.ipv4.sin_port));
	#endif

	return bytes;
}

long
uptime(void)
{
	struct sysinfo s_info;
	int error = sysinfo(&s_info);
	if(error != 0) {
#ifdef CP_BUILD
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Error in uptime\n", LOG_VALUE);
#endif /* CP_BUILD */
	}
	return s_info.uptime;
}

void
create_heartbeat_hash_table(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "RECOVERY_TIME_HASH",
		.entries = HEARTBEAT_ASSOCIATION_ENTRIES_DEFAULT,
		.key_len = sizeof(node_address_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id()
	};

	heartbeat_recovery_hash = rte_hash_create(&rte_hash_params);
	if (!heartbeat_recovery_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void
create_associated_upf_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "associated_upf_hash",
		.entries = 50,
		.key_len = UINT32_SIZE,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	associated_upf_hash = rte_hash_create(&rte_hash_params);
	if (!associated_upf_hash) {
		rte_panic("%s Associated UPF hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

uint32_t
current_ntp_timestamp(void) {

	struct timeval tim;
	uint8_t ntp_time[8] = {0};
	uint32_t timestamp = 0;

	gettimeofday(&tim, NULL);
	time_to_ntp(&tim, ntp_time);

	timestamp |= ntp_time[0] << 24 | ntp_time[1] << 16
								| ntp_time[2] << 8 | ntp_time[3];

	return timestamp;
}

void
time_to_ntp(struct timeval *tv, uint8_t *ntp)
{
	uint64_t ntp_tim = 0;
	uint8_t len = (uint8_t)sizeof(ntp)/sizeof(ntp[0]);
	uint8_t *p = ntp + len;

	int i = 0;

	ntp_tim = tv->tv_usec;
	ntp_tim <<= 32;
	ntp_tim /= 1000000;

	/* Setting the ntp in network byte order */

	for (i = 0; i < len/2; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

	ntp_tim = tv->tv_sec;
	ntp_tim += OFFSET;

	/* Settting  the fraction of second */

	for (; i < len; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

}

void ntp_to_unix_time(uint32_t *ntp, struct timeval *unix_tm)
{
	if (*ntp == 0) {
		unix_tm->tv_sec = 0;
	} else {
		/* the seconds from Jan 1, 1900 to Jan 1, 1970*/
		if(unix_tm != NULL)
			unix_tm->tv_sec = (*ntp) - 0x83AA7E80;
	}
}

/* TODO: Convert this func into inline func */
/* VS: Validate the IP Address is in the subnet or not */
int
validate_Subnet(uint32_t addr, uint32_t net_init, uint32_t net_end)
{
	if ((addr >= net_init) && (addr <= net_end)) {
		/* IP Address is in the subnet range */
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPv4 Addr "IPV4_ADDR" is in the subnet\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(addr));
		return 1;
	}

	/* IP Address is not in the subnet range */
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv4 Addr "IPV4_ADDR" is NOT in the subnet\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(addr));
	return 0;
}

/* TODO: Convert this func into inline func */
/* VS: Validate the IPv6 Address is in the subnet or not */
int
validate_ipv6_network(struct in6_addr addr,
		struct in6_addr local_addr, uint8_t local_prefix)
{
	uint8_t match = 0;
	for (uint8_t inx = 0; inx < local_prefix/8; inx++) {
		/* Compare IPv6 Address Hexstat by Hexstat */
		if (!memcmp(&addr.s6_addr[inx], &local_addr.s6_addr[inx],
					sizeof(addr.s6_addr[inx]))) {
			/* If Hexstat match */
			match = 1;
		} else {
			/* If Hexstat is NOT match */
			match = 0;
			break;
		}
	}

	if (match) {
		/* IPv6 Address is in the same network range */
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPv6 Addr "IPv6_FMT" is in the network\n",
				LOG_VALUE, IPv6_PRINT(addr));
		return 1;
	}

	/* IPv6 Address is not in the network range */
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv6 Addr "IPv6_FMT" is NOT in the network\n",
			LOG_VALUE, IPv6_PRINT(addr));
	return 0;
}

/**
 * @brief  : Retrieve the IPv6 Network Prefix Address
 * @param  : local_addr, Compare Network ID
 * @param  : local_prefix, Network bits
 * @return : Returns Prefix
 * */
struct in6_addr
retrieve_ipv6_prefix(struct in6_addr addr, uint8_t local_prefix)
{
	struct in6_addr tmp = {0};
	for (uint8_t inx = 0; inx < local_prefix/8; inx++) {
		tmp.s6_addr[inx] = addr.s6_addr[inx];
	}

	/* IPv6 Address is not in the network range */
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"IPv6 Network Prefix "IPv6_FMT" and Prefix len:%u\n",
			LOG_VALUE, IPv6_PRINT(tmp), local_prefix);

	return tmp;
}

#ifdef CP_BUILD
uint8_t
is_li_enabled(li_data_t *li_data, uint8_t intfc_name, uint8_t cp_type) {

	uint8_t doCopy = NOT_PRESENT;

	switch (intfc_name) {
		case S11_INTFC_IN:
		case S11_INTFC_OUT:
				if (PRESENT == li_data->s11) {
					doCopy = PRESENT;
				}

				break;

		case S5S8_C_INTFC_IN:
		case S5S8_C_INTFC_OUT:
				if (((SGWC == cp_type) && (PRESENT == li_data->sgw_s5s8c)) ||
						((PGWC == cp_type) && (PRESENT == li_data->pgw_s5s8c))) {
					doCopy = PRESENT;
				}

				break;

		case SX_INTFC_IN:
		case SX_INTFC_OUT:
				if (((SGWC == cp_type) && (PRESENT == li_data->sxa)) ||
						((PGWC == cp_type) && (PRESENT == li_data->sxb)) ||
						((SAEGWC == cp_type) && (PRESENT == li_data->sxa_sxb))) {
					doCopy = PRESENT;
				}

				break;

		default:
				/* Do nothing. Default value is already set 0 */
				break;
	}

	return doCopy;
}

uint8_t
is_li_enabled_using_imsi(uint64_t uiImsi, uint8_t intfc_name, uint8_t cp_type) {
	int ret = 0;
	uint8_t doCopy = NOT_PRESENT;
	struct li_df_config_t *li_config = NULL;

	ret = get_li_config(uiImsi, &li_config);
	if (!ret) {
		switch (intfc_name) {
			case S11_INTFC_IN:
			case S11_INTFC_OUT:
					if (COPY_SIG_MSG_ON == li_config->uiS11) {
						doCopy = PRESENT;
					}

					break;

			case S5S8_C_INTFC_IN:
			case S5S8_C_INTFC_OUT:
					if (
							((SGWC == cp_type) &&
							 (COPY_SIG_MSG_ON == li_config->uiSgwS5s8C)) ||
							((PGWC == cp_type) &&
							 (COPY_SIG_MSG_ON == li_config->uiPgwS5s8C))) {
						doCopy = PRESENT;
					}

					break;

			case SX_INTFC_IN:
			case SX_INTFC_OUT:
					if (
							((SGWC == cp_type) &&
							 ((SX_COPY_CP_MSG == li_config->uiSxa) ||
							  (SX_COPY_CP_DP_MSG == li_config->uiSxa))) ||
							((PGWC == cp_type) &&
							 ((SX_COPY_CP_MSG == li_config->uiSxb) ||
							  (SX_COPY_CP_DP_MSG == li_config->uiSxb))) ||
							((SAEGWC == cp_type) &&
							 ((SX_COPY_CP_MSG == li_config->uiSxaSxb) ||
							  (SX_COPY_CP_DP_MSG == li_config->uiSxaSxb)))) {
						doCopy = PRESENT;
					}

					break;

			default:
					/* Do nothing. Default value is already set 0 */
					break;
		}
	}

	return doCopy;
}

int
process_pkt_for_li(ue_context *context, uint8_t intfc_name, uint8_t *buf_tx,
		int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort,
		uint16_t uiDstPort) {

	int8_t ret = 0;
	int retval = 0;
	uint8_t *pkt = NULL;
	int pkt_length = 0;
	uint8_t doCopy = NOT_PRESENT;

	for (uint8_t cnt = 0; cnt < context->li_data_cntr; cnt++) {

		doCopy = is_li_enabled(&(context->li_data[cnt]), intfc_name, context->cp_mode);
		if (PRESENT == doCopy) {

			pkt_length = buf_tx_size;
			pkt = (uint8_t *)malloc(pkt_length + sizeof(li_header_t));
			if (NULL == pkt) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to allocate memory for"
						" li packet\n", LOG_VALUE);

				return -1;
			}

			memcpy(pkt, buf_tx, pkt_length);

			ret = create_li_header(pkt, &pkt_length, EVENT_BASED,
					context->li_data[cnt].id, context->imsi, srcIp, dstIp,
					uiSrcPort, uiDstPort, context->li_data[cnt].forward);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to create li header\n",
					LOG_VALUE);

				return -1;
			}

			retval = send_li_data_pkt(ddf2_fd, pkt, pkt_length);
			if (retval < 0) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to send CP message on TCP"
						" sock with error %d\n", LOG_VALUE, retval);

				return -1;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": Send to LI success.\n", LOG_VALUE);

			free(pkt);
			pkt = NULL;
		}
	}
	return 0;
}

int
process_cp_li_msg(uint64_t sess_id, uint8_t intfc_name, uint8_t *buf_tx,
		int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort,
		uint16_t uiDstPort) {

	int8_t ret = 0;
	uint32_t teid = 0;
	ue_context *context = NULL;

	if (!sess_id) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT " Seid Recived is: %u\n",
			LOG_VALUE, sess_id);
		return -1;
	}

	teid = UE_SESS_ID(sess_id);
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"Context for teid: %u\n", LOG_VALUE, teid);
		return -1;
	}

	if (NULL == context) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UE context is NULL.\n" ,
				LOG_VALUE);
		return -1;
	}

	if (PRESENT == context->dupl) {
		process_pkt_for_li(context, intfc_name, buf_tx, buf_tx_size, srcIp,
				dstIp, uiSrcPort, uiDstPort);
	}

	return 0;
}

int
process_msg_for_li(ue_context *context, uint8_t intfc_name, msg_info *msg,
		struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort, uint16_t uiDstPort) {

	int buf_tx_size = 0;
	gtpv2c_header_t *header;
	uint8_t buf_tx[MAX_GTPV2C_UDP_LEN] = {0};

	if (NULL == context) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "UE context is NULL or LI"
				"for this UE is not enabled \n", LOG_VALUE);
		return -1;
	}

	/* Handling for CSR. If want to handle other msgs then add if condition
	 * on msg_type basis */
	buf_tx_size = encode_create_sess_req(&msg->gtpc_msg.csr,(uint8_t*)buf_tx);

	header = (gtpv2c_header_t*) buf_tx;
	header->gtpc.message_len = htons(buf_tx_size);

	if (PRESENT == context->dupl) {
		process_pkt_for_li(context, intfc_name, buf_tx, buf_tx_size, srcIp,
				dstIp, uiSrcPort, uiDstPort);
	}

	return 0;
}

int
process_cp_li_msg_for_cleanup(li_data_t *li_data, uint8_t uiLiDataCntr, uint8_t intfc_name,
		uint8_t *buf_tx, int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort,
		uint16_t uiDstPort, uint8_t uiCpMode, uint64_t uiImsi) {

	int8_t ret = 0;
	int retval = 0;
	uint8_t *pkt = NULL;
	int pkt_length = 0;
	uint8_t doCopy = NOT_PRESENT;

	if (0 == uiLiDataCntr) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No li entry found.\n", LOG_VALUE);
		return -1;
	}

	for (uint8_t cnt = 0; cnt < uiLiDataCntr; cnt++) {

		doCopy = is_li_enabled(&li_data[cnt], intfc_name, uiCpMode);
		if (PRESENT == doCopy) {

			pkt_length = buf_tx_size;
			pkt = (uint8_t *)malloc(pkt_length + sizeof(li_header_t));
			if (NULL == pkt) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to allocate memory for"
						" li packet\n", LOG_VALUE);

				return -1;
			}

			memcpy(pkt, buf_tx, pkt_length);

			ret = create_li_header(pkt, &pkt_length, EVENT_BASED,
					li_data[cnt].id, uiImsi, srcIp, dstIp,
					uiSrcPort, uiDstPort, li_data[cnt].forward);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to create li header\n",
					LOG_VALUE);

				return -1;
			}

			retval = send_li_data_pkt(ddf2_fd, pkt, pkt_length);
			if (retval < 0) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to send CP message on TCP"
						" sock with error %d\n", LOG_VALUE, retval);

				return -1;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": Send to LI success.\n", LOG_VALUE);

			free(pkt);
			pkt = NULL;
		}
	}

	return 0;
}

#endif /* CP_BUILD */
