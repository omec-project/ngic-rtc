/*
 * Copyright (c) 2019 Sprint
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

#include "pfcp_enum.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages.h"
#include "gw_adapter.h"
#include "clogger.h"
#include "../cp_dp_api/tcp_client.h"
#include "pfcp_messages_decoder.h"

#ifdef CP_BUILD
#include "cp_config.h"
#include "sm_pcnd.h"
#include "cp_timer.h"
#include "cp_stats.h"
#include "li_config.h"
#else
#define LDB_ENTRIES_DEFAULT (1024 * 1024 * 4)
#endif /* CP_BUILD */

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "cdnshelper.h"

#define FAILED_ENB_FILE "logs/failed_enb_queries.log"
#endif

#define QUERY_RESULT_COUNT 16
#define MAX_ENODEB_LEN     16
extern int pfcp_fd;

struct rte_hash *node_id_hash;
struct rte_hash *heartbeat_recovery_hash;
struct rte_hash *associated_upf_hash;

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
extern pfcp_config_t pfcp_config;

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
	upfs_dnsres_t *upf_list = rte_zmalloc_socket(NULL,
			sizeof(upfs_dnsres_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (NULL == upf_list) {
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate memory for upf list "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	uint8_t upf_count = 0;

	for (int i = 0; (upf_count < res_count) && (i < QUERY_RESULT_COUNT);i++) {
		for (int j = 0; j < res[i].host2_info.ipv4host_count; j++) {
			int flag_added = false;
			/* TODO:: duplicate entries should not be present in result itself */
			if(upf_count == 0){
				inet_aton(res[i].host2_info.ipv4_hosts[j],
						&upf_list->upf_ip[upf_count]);
				memcpy(upf_list->upf_fqdn[upf_count], res[i].cano_name2,
						strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;

			}else{
				for (int k = 0; k < upf_count ; k++) {
					struct in_addr temp_ip;
					inet_aton(res[i].host2_info.ipv4_hosts[j],
							&temp_ip);
					if( temp_ip.s_addr == upf_list->upf_ip[k].s_addr){
						break;
					}else{
						inet_aton(res[i].host2_info.ipv4_hosts[j],
								&upf_list->upf_ip[upf_count]);
						memcpy(upf_list->upf_fqdn[upf_count], res[i].cano_name2,
								strnlen((char *)res[i].cano_name2,MAX_HOSTNAME_LENGTH));
						flag_added = TRUE;
					}
				}
			}
			if(flag_added == TRUE){
				upf_count++;
			}
		}
	}

	if (upf_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Could not get collocated candidate list. \n");
		return 0;
	}

	upf_list->upf_count = upf_count;

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	return upf_count;
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
	upfs_dnsres_t *upf_list = NULL;
	int ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi_val,
		(void**)&upf_list);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "Failed to search entry in upflist_by_ue_hash"
				"hash table");

		upf_list = rte_zmalloc_socket(NULL,
				sizeof(upfs_dnsres_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (NULL == upf_list) {
			clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate memeory for upf list "
					"structure: %s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);
			return -1;
		}
	}

	uint8_t upf_count = 0;

	for (int i = 0; (upf_count < res_count) && (i < QUERY_RESULT_COUNT); i++) {
		for (int j = 0; j < res[i].ipv4host_count; j++) {
			int flag_added = false;
			/* TODO:: duplicate entries should not be present in result itself */
			if(upf_count == 0){
				inet_aton(res[i].ipv4_hosts[j],
						&upf_list->upf_ip[upf_count]);
				memcpy(upf_list->upf_fqdn[upf_count], res[i].hostname,
						strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
				flag_added = TRUE;

			}else{
				for (int k = 0; k < upf_count ; k++) {
					struct in_addr temp_ip;
					inet_aton(res[i].ipv4_hosts[j],
							&temp_ip);
					if( temp_ip.s_addr == upf_list->upf_ip[k].s_addr){
						break;
					}else{
						inet_aton(res[i].ipv4_hosts[j],
								&upf_list->upf_ip[upf_count]);
						memcpy(upf_list->upf_fqdn[upf_count], res[i].hostname,
								strnlen((char *)res[i].hostname,MAX_HOSTNAME_LENGTH));
						flag_added = TRUE;
					}
				}
			}
			if(flag_added == TRUE){
				upf_count++;
			}
		}
	}

	if (upf_count == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Could not get SGW-U list using DNS query \n");
		return 0;
	}

	upf_list->upf_count = upf_count;

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	return upf_count;
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
		clLog(clSystemLog, eCLSeverityCritical, "Could not open %s for writing failed "
				"eNodeB query entry.\n", FAILED_ENB_FILE);
		return 1;
	}

	fwrite(enbid, sizeof(char), strnlen(enbid,MAX_ENODEB_LEN), fp);
	fwrite("\n", sizeof(char), 1, fp);
	fclose(fp);

	return 0;
}

int
get_upf_list(pdn_connection *pdn)
{
	int upf_count = 0;
	ue_context *ctxt = NULL;
	char apn_name[MAX_APN_LEN] = {0};

	/* VS: Retrive the UE context */
	ctxt = pdn->context;

	/* Get enodeb id, mnc, mcc from Create Session Request */
	uint32_t enbid = ctxt->uli.ecgi2.eci >> 8;
	char enodeb[MAX_ENODEB_LEN] = {0};
	char mnc[MCC_MNC_LEN] = {0};
	char mcc[MCC_MNC_LEN] = {0};

	snprintf(enodeb, ENODE_LEN,"%u", enbid);

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

	if (!pdn->apn_in_use) {
		return 0;
	}

	/* Get network capabilities from apn configuration file */
	apn *apn_requested = pdn->apn_in_use;

	//memcpy(apn_name,(char *)ctxt->apn.apn + 1, apn_requested->apn_name_length -1);
	/* VS: Need to revist this */
	memcpy(apn_name, (pdn->apn_in_use)->apn_name_label + 1, (pdn->apn_in_use)->apn_name_length -1);

	if (pfcp_config.cp_type == SAEGWC || pfcp_config.cp_type == SGWC) {

		void *sgwupf_node_sel = init_enbupf_node_selector(enodeb, mnc, mcc);

		set_desired_proto(sgwupf_node_sel, ENBUPFNODESELECTOR, UPF_X_SXA);
		if(strnlen(apn_requested->apn_net_cap,MAX_NETCAP_LEN) > 0) {
			set_nwcapability(sgwupf_node_sel, apn_requested->apn_net_cap);
		}

		if (apn_requested->apn_usage_type != -1) {
			set_ueusage_type(sgwupf_node_sel,
				apn_requested->apn_usage_type);
		}

		uint16_t sgwu_count = 0;
		dns_query_result_t sgwu_list[QUERY_RESULT_COUNT] = {0};
		process_dnsreq(sgwupf_node_sel, sgwu_list, &sgwu_count);

		if (!sgwu_count) {

			record_failed_enbid(enodeb);
			deinit_node_selector(sgwupf_node_sel);

			/* Query DNS based on lb and hb of tac */
			char lb[LB_HB_LEN] = {0};
			char hb[LB_HB_LEN] = {0};

			if (ctxt->uli.tai != 1) {
				clLog(clSystemLog, eCLSeverityCritical, "Could not get SGW-U list using DNS"
								"query. TAC missing in CSR.\n");
				return 0;
			}

			snprintf(lb, LB_HB_LEN,  "%u", ctxt->uli.tai2.tai_tac & 0xFF);
			snprintf(hb, LB_HB_LEN, "%u", (ctxt->uli.tai2.tai_tac >> 8) & 0xFF);

			sgwupf_node_sel = init_sgwupf_node_selector(lb, hb, mnc, mcc);

			set_desired_proto(sgwupf_node_sel, SGWUPFNODESELECTOR, UPF_X_SXA);

			if(strnlen(apn_requested->apn_net_cap,MAX_NETCAP_LEN) > 0) {
				set_nwcapability(sgwupf_node_sel, apn_requested->apn_net_cap);
			}

			if (apn_requested->apn_usage_type != -1) {
				set_ueusage_type(sgwupf_node_sel,
					apn_requested->apn_usage_type);
			}

			process_dnsreq(sgwupf_node_sel, sgwu_list, &sgwu_count);

			if (!sgwu_count) {
				clLog(clSystemLog, eCLSeverityCritical, "Could not get SGW-U list using DNS"
					"query \n");
				return 0;
			}
		}

		/* SAEGW-C */
		if (pdn->s5s8_pgw_gtpc_ipv4.s_addr == 0) {

			uint16_t pgwu_count = 0;
			dns_query_result_t pgwu_list[QUERY_RESULT_COUNT] = {0};

			void *pwupf_node_sel = init_pgwupf_node_selector(apn_name,
					mnc, mcc);

			set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);

			if(strnlen(apn_requested->apn_net_cap,MAX_NETCAP_LEN) > 0) {
				set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);
			}

			if (apn_requested->apn_usage_type != -1) {
				set_ueusage_type(pwupf_node_sel,
					apn_requested->apn_usage_type);
			}

			process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

			/* Get colocated candidate list */
			canonical_result_t result[QUERY_RESULT_COUNT] = {0};
			int res_count = get_colocated_candlist(sgwupf_node_sel,
						pwupf_node_sel, result);

			if (!res_count) {
				deinit_node_selector(pwupf_node_sel);
				return 0;
			}

			/* VS: Need to check this */
			upf_count = add_canonical_result_upflist_entry(result, res_count,
							&ctxt->imsi, sizeof(ctxt->imsi));

			deinit_node_selector(pwupf_node_sel);

		} else { /* SGW-C */

			upf_count = add_dns_result_upflist_entry(sgwu_list, sgwu_count,
							&ctxt->imsi, sizeof(ctxt->imsi));
		}

		deinit_node_selector(sgwupf_node_sel);

	} else if (pfcp_config.cp_type == PGWC) {

		uint16_t pgwu_count = 0;
		dns_query_result_t pgwu_list[QUERY_RESULT_COUNT] = {0};

		void *pwupf_node_sel = init_pgwupf_node_selector(apn_name, mnc, mcc);

		set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);
		if(strnlen(apn_requested->apn_net_cap,MAX_NETCAP_LEN) > 0) {
			set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);
		}

		if (apn_requested->apn_usage_type != -1) {
			set_ueusage_type(pwupf_node_sel,
				apn_requested->apn_usage_type);
		}

		process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

		/* VS: Need to check this */
		/* Get collocated candidate list */
		if (!strnlen((char *)pdn->fqdn,MAX_HOSTNAME_LENGTH)) {
			clLog(clSystemLog, eCLSeverityCritical, "SGW-U node name missing in CSR. \n");
			deinit_node_selector(pwupf_node_sel);
			return 0;
		}

		canonical_result_t result[QUERY_RESULT_COUNT] = {0};
		int res_count = get_colocated_candlist_fqdn(
				(char *)pdn->fqdn, pwupf_node_sel, result);

		if (!res_count) {
			clLog(clSystemLog, eCLSeverityCritical, "Could not get collocated candidate list. \n");
			deinit_node_selector(pwupf_node_sel);
			return 0;
		}

		upf_count = add_canonical_result_upflist_entry(result, res_count,
							&ctxt->imsi, sizeof(ctxt->imsi));

		deinit_node_selector(pwupf_node_sel);
	}

	return upf_count;
}

int
dns_query_lookup(pdn_connection *pdn, uint32_t **upf_ip)
{
	upfs_dnsres_t *entry = NULL;

	if (get_upf_list(pdn) == 0){
		 clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error:\n",
			    __func__, __LINE__);
		return GTPV2C_CAUSE_REQUEST_REJECTED;
	}

	/* Fill msg->upf_ipv4 address */
	if ((get_upf_ip(pdn->context, &entry, upf_ip)) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Failed to get upf ip address\n");
		return GTPV2C_CAUSE_REQUEST_REJECTED;
	}
	memcpy(pdn->fqdn, entry->upf_fqdn[entry->current_upf],
					sizeof(entry->upf_fqdn[entry->current_upf]));
	return 0;
}

#endif /* CP_BUILD && USE_DNS_QUERY */

#ifdef CP_BUILD
int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes;
	bytes = recvfrom(pfcp_fd, msg_payload, size, 0,
			(struct sockaddr *)peer_addr, &addr_len);
	//if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC)
	//	bytes = recvfrom(pfcp_sgwc_fd_arr[0], msg_payload, size, 0,
	//			(struct sockaddr *)peer_addr, &addr_len);
	//else
	//	bytes = recvfrom(pfcp_pgwc_fd_arr[0], msg_payload, size, 0,
	//			(struct sockaddr *)peer_addr, &addr_len);
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
		decode_pfcp_sess_estab_req_t(msg_payload, &pfcp_session_request, INTERFACE);
		return pfcp_session_request.cp_fseid.seid;
	}

	if(header.s)
		return header.seid_seqno.has_seid.seid;
	else
		return 0;
}

int
pfcp_send(int fd, void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr,Dir dir)
{

	struct sockaddr_in *sin = (struct sockaddr_in *) peer_addr;
	pfcp_header_t *head = (pfcp_header_t *)msg_payload;

	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes = sendto(fd,
			(uint8_t *) msg_payload,
			size,
			MSG_DONTWAIT,
			(struct sockaddr *)peer_addr,
			addr_len);

	update_cli_stats(sin->sin_addr.s_addr, head->message_type, dir,SX);

	#ifdef CP_BUILD
	uint64_t sess_id = get_seid(msg_payload);
	process_cp_li_msg(sess_id, msg_payload, size,
			pfcp_config.pfcp_ip.s_addr, peer_addr->sin_addr.s_addr,
			pfcp_config.pfcp_port, peer_addr->sin_port);
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
		clLog(clSystemLog, eCLSeverityDebug, "Error in uptime\n");
#endif /* CP_BUILD */
	}
	return s_info.uptime;
}

void
create_node_id_hash(void)
{

	struct rte_hash_parameters rte_hash_params = {
		.name = "node_id_hash",
		.entries = LDB_ENTRIES_DEFAULT,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id()
	};

	node_id_hash = rte_hash_create(&rte_hash_params);
	if (!node_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void
create_heartbeat_hash_table(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "RECOVERY_TIME_HASH",
		.entries = HEARTBEAT_ASSOCIATION_ENTRIES_DEFAULT,
		.key_len = sizeof(uint32_t),
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
		unix_tm->tv_sec = (*ntp) - 0x83AA7E80; // the seconds from Jan 1, 1900 to Jan 1, 1970
	}
}

#ifdef CP_BUILD
int
process_cp_li_msg(uint64_t sess_id, uint8_t *buf_tx, int buf_tx_size,
		uint32_t uiSrcIp, uint32_t uiDstIp, uint16_t uiSrcPort, uint16_t uiDstPort) {

	if(!sess_id){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Seid Recived is: %u\n",
					__func__, __LINE__, sess_id);
		return -1;
	}

	ue_context *context = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);
	int8_t ret = 0;
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		return -1;
	}
	if(context == NULL || context->li_sock_fd <= 0){
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%dUE context is NULL or LI for this UE is not enabled \n"
			,__func__, __LINE__);
		return -1;
	}

	ret = create_li_header(buf_tx, &buf_tx_size, EVENT_BASED,
			context->imsi, uiSrcIp, uiDstIp, uiSrcPort, uiDstPort, 0, 0);

	//VK : Sending data to LI server
	int ret1 = send_li_data_pkt(context->li_sock_fd, buf_tx, buf_tx_size);
	if(context->li_sock_fd != 0 && ret1 < 0){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to send CP message on TCP sock with error %d\n",
																						__func__, __LINE__, ret1);
		close(context->li_sock_fd);
		context->li_sock_fd = 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Send to LI success.\n", __func__);

	return 0;
}

int
process_cp_li_msg_using_context(ue_context *context, uint8_t *buf_tx, int buf_tx_size,
		uint32_t uiSrcIp, uint32_t uiDstIp, uint16_t uiSrcPort, uint16_t uiDstPort) {

	int8_t ret = 0;

	if(context == NULL || context->li_sock_fd <= 0){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%dUE context is NULL or LI for this UE is not enabled \n"
																					,__func__, __LINE__);
		return -1;
	}

	ret = create_li_header(buf_tx, &buf_tx_size, EVENT_BASED,
			context->imsi, uiSrcIp, uiDstIp, uiSrcPort, uiDstPort, 0, 0);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to create li header\n",
					__func__, __LINE__);
		return -1;
	}

	//VK : Sending data to LI server
	int ret1 = send_li_data_pkt(context->li_sock_fd, buf_tx, buf_tx_size);
	if(context->li_sock_fd != 0 && ret1 < 0){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to send CP message on TCP sock with error %d\n",
																					__func__, __LINE__, ret1);
		close(context->li_sock_fd);
		context->li_sock_fd = 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Send to LI success.\n", __func__);

	return 0;
}

int
process_msg_for_li(ue_context *context, msg_info *msg, uint32_t uiSrcIp,
		uint32_t uiDstIp, uint16_t uiSrcPort, uint16_t uiDstPort) {

	int8_t ret = 0;
	int buf_tx_size = 0;
	gtpv2c_header_t *header;
	uint8_t buf_tx[MAX_GTPV2C_UDP_LEN] = {0};

	if(context == NULL || context->li_sock_fd <= 0) {
		clLog(clSystemLog, eCLSeverityDebug, "%s:%dUE context is NULL or LI for this UE is not enabled \n"
																					,__func__, __LINE__);
		return -1;
	}

	/* Handling for CSR. If want to handle other msgs then add if condition
	 * on msg_type basis */
	buf_tx_size = encode_create_sess_req(&msg->gtpc_msg.csr,(uint8_t*)buf_tx);
	//buf_tx_size -= 4;
	header = (gtpv2c_header_t*) buf_tx;
	header->gtpc.message_len = htons(buf_tx_size);

	ret = create_li_header(buf_tx, &buf_tx_size, EVENT_BASED,
			context->imsi, uiSrcIp, uiDstIp, uiSrcPort, uiDstPort, 0, 0);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to create li header\n",
					__func__, __LINE__);
		return -1;
	}

	if(0 >= context->li_sock_fd) {
		struct li_df_config_t *li_config = NULL;
		int ret = get_li_config(context->imsi, &li_config);
		if(!ret){
			if((EVENT_BASED == li_config->uiAction) ||
					(CC_EVENT_BASED == li_config->uiAction)){
				context->li_sock_fd = get_tcp_tunnel(li_config->ddf2_ip.s_addr,
						li_config->uiDDf2Port,
						TCP_CREATE);
				context->dupl = PRESENT;
			}
		} else {
			clLog(clSystemLog, eCLSeverityDebug, "%s:%d Li configuration not found\n",
					__func__, __LINE__);

			return -1;
		}
	}

	int ret1 = send_li_data_pkt(context->li_sock_fd, buf_tx, buf_tx_size);
	if (context->li_sock_fd != 0 && ret1 < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to send li packet\n",
					__func__, __LINE__);
		close(context->li_sock_fd);
		context->li_sock_fd = 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Send to LI success.\n", __func__);

	return 0;
}

int
process_cp_li_msg_for_cleanup(uint64_t uiImsi, int li_sock_fd, uint8_t *buf_tx, int buf_tx_size,
		uint32_t uiSrcIp, uint32_t uiDstIp, uint16_t uiSrcPort, uint16_t uiDstPort) {

	int8_t ret = 0;

	if ((li_sock_fd <= 0) || (0 == uiImsi)){
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:%dUE li socket fd or imsi is NULL or LI for this UE is not enabled \n"
				,__func__, __LINE__);
		return -1;
	}

	ret = create_li_header(buf_tx, &buf_tx_size, EVENT_BASED,
			uiImsi, uiSrcIp, uiDstIp, uiSrcPort, uiDstPort, 0, 0);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to create li header\n",
					__func__, __LINE__);
		return -1;
	}

	//VK : Sending data to LI server
	int ret1 = send_li_data_pkt(li_sock_fd, buf_tx, buf_tx_size);
	if(li_sock_fd != 0 && ret1 < 0){
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d Failed to send CP message on TCP sock with error %d\n",
																					__func__, __LINE__, ret1);
		close(li_sock_fd);
		li_sock_fd = 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Send to LI success.\n", __func__);

	return 0;
}

#endif /* CP_BUILD */
