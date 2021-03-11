/*
 * Copyright (c) 2017 Intel Corporation
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

#include "gtpv2c.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "rte_common.h"
#include "cp_timer.h"
#include "gtpv2c_error_rsp.h"
#include "gw_adapter.h"
#include "debug_str.h"
#include "teid.h"
#include "cp.h"
#include "pfcp_session.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_messages_encoder.h"

#define DIAMETER_PCC_RULE_EVENT (5142)

extern int s11_fd;
extern int s11_fd_v6;
extern int s5s8_fd;
extern int s5s8_fd_v6;
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;
extern int clSystemLog;
extern pfcp_config_t config;

void start_throttle_timer(node_address_t *node_ip, int thrtlng_delay_val, uint8_t thrtl_fact)
{
	int ret = 0;
	throttle_timer *timer_data = NULL;
	/* Fill timer entry */

	timer_data = rte_zmalloc_socket(NULL, sizeof(throttle_timer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_data == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"Memory for throttling timer, Error: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
		return;
	}

	timer_data->node_ip = node_ip;
	timer_data->throttle_factor = thrtl_fact;

	TIMER_GET_CURRENT_TP(timer_data->start_time);

	/* Add entry into a hash */
	ret = rte_hash_add_key_data(thrtl_timer_by_nodeip_hash,
			(const void *)node_ip, timer_data);
	if (ret < 0) {

			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry into throttling timer hash for MME node "
					" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
					"\n\tError= %d\n", LOG_VALUE, ip_type_str(node_ip->ip_type),
					IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr),ret);
		rte_free(timer_data);
		timer_data = NULL;
		return;
	}

	/*Register timer callback*/
	if(!(gst_timer_init(&timer_data->pt, ttInterval, thrtle_timer_callback,
					thrtlng_delay_val, timer_data))){

		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Faild to initialize timer entry for throttling timer\n",
				LOG_VALUE);

		ret = rte_hash_del_key(thrtl_timer_by_nodeip_hash, (const void *)node_ip);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not found for node "
					" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
					"\n\tError= %d\n", LOG_VALUE, ip_type_str(node_ip->ip_type),
					IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr),ret);
		}
		rte_free(timer_data);
		timer_data = NULL;
		return;
	}

	if (starttimer(&timer_data->pt) != true) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Periodic Timer "
				"failed to start timer for throttling  \n", LOG_VALUE);

		ret = rte_hash_del_key(thrtl_timer_by_nodeip_hash, (const void *)node_ip);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not found for node "
					" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
					"\n\tError= %d\n", LOG_VALUE, ip_type_str(node_ip->ip_type),
					IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr),ret);
		}
		rte_free(timer_data);
		timer_data = NULL;
		return;
	}else{
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Throttling Timer Entry Started Successfully"
			" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT "\n",
			LOG_VALUE, ip_type_str(node_ip->ip_type),
			IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr));
		}
}

uint8_t
delete_thrtle_timer(node_address_t *node_ip)
{
	int ret = 0;
	uint8_t extend_timer_value = 0;
	thrtle_count *thrtl_cnt = NULL;
	throttle_timer *timer_data = NULL;

	ret = rte_hash_lookup_data(thrtl_timer_by_nodeip_hash,
					(const void *)node_ip, (void **)&timer_data);

	if(ret >= 0){
		if(timer_data->pt.ti_id != 0) {
			extend_timer_value = TIMER_GET_ELAPSED_NS(timer_data->start_time) / 1000000000;
			stoptimer(&timer_data->pt.ti_id);
			deinittimer(&timer_data->pt.ti_id);

			ret = rte_hash_lookup_data(thrtl_ddn_count_hash,
					(const void *)timer_data->node_ip, (void **)&thrtl_cnt);
			if(ret >= 0){
				delete_from_sess_info_list(thrtl_cnt->sess_ptr);
			}
			ret = rte_hash_del_key(thrtl_ddn_count_hash, (const void *)node_ip);
	        if ( ret < 0) {
	           clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Throttling Count Entry not found for"
					" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t  and IPv6 : "IPv6_FMT "\n",
					LOG_VALUE, ip_type_str(node_ip->ip_type),
					IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr));
	           }

			ret = rte_hash_del_key(thrtl_timer_by_nodeip_hash, (const void *)node_ip);
			if ( ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not found for node "
						" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT""
						"\n\tError= %d\n", LOG_VALUE, ip_type_str(node_ip->ip_type),
						IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr),ret);
			}

			if (timer_data != NULL) {
				rte_free(timer_data);
				timer_data = NULL;
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Throttling Timer Entry Deleted Successfully"
					" of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT "\n",
					LOG_VALUE, ip_type_str(node_ip->ip_type),
					IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr), PRINT_IPV6_ADDR(node_ip->ipv6_addr));
			}
		}

	} else {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Timer Entry not found for node"
				"of IP Type : %s\n with IP IPv4 : "IPV4_ADDR "\t and IPv6 : "IPv6_FMT""
				"\n", LOG_VALUE, ip_type_str(node_ip->ip_type),
				IPV4_ADDR_HOST_FORMAT(node_ip->ipv4_addr),
				PRINT_IPV6_ADDR(node_ip->ipv6_addr));
	}

	return extend_timer_value;
}

void
delete_sess_in_thrtl_timer(ue_context *context, uint64_t sess_id)
{
	throttle_timer *thrtle_timer_data = NULL;
	thrtle_count *thrtl_cnt = NULL;
	sess_info *traverse = NULL;
	sess_info *prev = NULL;
	sess_info *head = NULL;
	int ret = 0;

	if((rte_hash_lookup_data(thrtl_timer_by_nodeip_hash,
					(const void *)&context->s11_mme_gtpc_ip, (void **)&thrtle_timer_data)) >= 0 ){

		ret = rte_hash_lookup_data(thrtl_ddn_count_hash,
				(const void*)thrtle_timer_data->node_ip, (void **)&thrtl_cnt);
		if (ret >= 0){
			if (thrtl_cnt->sess_ptr != NULL){
				head = thrtl_cnt->sess_ptr;
				for(traverse = head; traverse != NULL; traverse = traverse->next){
					if(traverse->sess_id == sess_id){
						if(traverse == head){
							head = head->next;
						}else{
							for(prev = head; prev->next != traverse; prev= prev->next);
							prev->next = traverse->next;
						}
						rte_free(traverse);
						traverse = NULL;
					}
				}
			}
		}
	}
}

void start_ddn_timer_entry(struct rte_hash *hash, uint64_t seid,
		int delay_value, gstimercallback cb)
{
	int ret = 0;
	uint32_t teid = 0;
	ue_level_timer *timer_data = NULL;

	/* Fill timer entry */
	timer_data = fill_timer_entry(seid);
	if(timer_data != NULL){

		/* Add timer entry into hash */
		teid = UE_SESS_ID(seid);
		ret = rte_hash_add_key_data(hash, &teid, timer_data);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add into ddn timer entry hash for teid = %u"
					"\n\tError= %d\n", LOG_VALUE, teid, ret);

			rte_free(timer_data);
			timer_data = NULL;
			return;
		}

		/*Register timer callback*/
		if(!gst_timer_init(&timer_data->pt, ttInterval, cb, delay_value, timer_data)){
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Faild to initialize timer entry for downlink data notification\n",
					LOG_VALUE);

			ret = rte_hash_del_key(hash, &teid);
			if ( ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not "
						"found for teid:%u\n", LOG_VALUE, teid);
			}

			rte_free(timer_data);
			timer_data = NULL;
			return;
		}

		TIMER_GET_CURRENT_TP(timer_data->start_time);
		if(delay_value != 0){
			if (starttimer(&timer_data->pt) != true) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Periodic Timer "
						"failed to start timer for downlink data notification \n", LOG_VALUE);

				ret = rte_hash_del_key(hash, &teid);
				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not "
							"found for teid:%u\n", LOG_VALUE, teid);
				}

				rte_free(timer_data);
				timer_data = NULL;
				return;
			} else {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DDN Timer Entry Started Successfully"
							"for teid:%u\n", LOG_VALUE, teid);
			}
		}
	}
}


void delete_entry_from_sess_hash(uint64_t seid, struct rte_hash *sess_hash)
{
	int ret = 0;
	pdr_ids *pfcp_pdr_id = NULL;

	ret = rte_hash_lookup_data(sess_hash, &seid, (void **)&pfcp_pdr_id);
	if(ret >= 0){
		ret = rte_hash_del_key(sess_hash, &seid);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session "
					"found for session id:%u\n", LOG_VALUE, seid);
		}
		if(pfcp_pdr_id != NULL){
			rte_free(pfcp_pdr_id);
			pfcp_pdr_id = NULL;

		}
	}

}
uint8_t
delete_ddn_timer_entry(struct rte_hash *hash, uint32_t teid, struct rte_hash *sess_hash)
{
	int ret = 0;
	ue_context *context = NULL;
	uint8_t extend_timer_value = 0;
	ue_level_timer *timer_data = NULL;

	ret = rte_hash_lookup_data(hash, &teid, (void **)&timer_data);

	if(ret >= 0){
		if(timer_data->pt.ti_id != 0) {
			/*lookup and delete the entry  if present*/
			ret = get_ue_context(teid, &context);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
						"context for teid: %u\n", LOG_VALUE, teid);
				if(timer_data != NULL){
					stoptimer(&timer_data->pt.ti_id);
					deinittimer(&timer_data->pt.ti_id);
					rte_free(timer_data);
					timer_data = NULL;
				}
				return 0;
			}

			/* Cleanup the maintain PDR IDs to Seids */
			for(uint8_t itr = 0; itr < MAX_BEARERS; itr++){
				if(context->pdns[itr] != NULL){
					delete_entry_from_sess_hash(context->pdns[itr]->seid, sess_hash);
				}
			}

			/* Delete the timer entry from hash with key teid */
			ret = rte_hash_del_key(hash, &teid);
			if ( ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry not "
						"found for teid:%u\n", LOG_VALUE, teid);
			}

			if (timer_data != NULL) {
				extend_timer_value = TIMER_GET_ELAPSED_NS(timer_data->start_time) / 1000000000;
				/* Stop Running timer and delete the timer obj */
				stoptimer(&timer_data->pt.ti_id);
				deinittimer(&timer_data->pt.ti_id);
				rte_free(timer_data);
				timer_data = NULL;
			}
		}
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DDN Timer Entry successfully"
				" Deleted for teid:%u\n", LOG_VALUE, teid);

	} else {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Timer Entry not "
				"found for teid:%u\n", LOG_VALUE, teid);
	}

	return extend_timer_value;
}


/* Callback called after throttled timer get expired */
void thrtle_timer_callback(gstimerinfo_t *ti, const void *data_t )
{
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	throttle_timer *timer_entry = (throttle_timer*)data_t;
#pragma GCC diagnostic pop
	int ret = 0;
	pdr_ids pfcp_pdr_id = {0};
	ue_context *context = NULL;
	thrtle_count *thrtl_cnt = NULL;
	sess_info *traverse = NULL;

	thrtl_cnt = get_throtle_count(timer_entry->node_ip, DELETE_ENTRY);
	if (thrtl_cnt == NULL){
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"FAILED: To get throtlling count"
				"of IP Type : %s\n with IP IPv4 : "IPV4_ADDR "\t and IPv6 : "IPv6_FMT""
				"\n", LOG_VALUE, ip_type_str(timer_entry->node_ip->ip_type),
				IPV4_ADDR_HOST_FORMAT(timer_entry->node_ip->ipv4_addr),
				PRINT_IPV6_ADDR(timer_entry->node_ip->ipv6_addr));

		delete_thrtle_timer(timer_entry->node_ip);
		return;
	}
	if (thrtl_cnt->sess_ptr == NULL){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT "FAILED: To get buffered session entry"
				" for throttling \n\n", LOG_VALUE);
		delete_thrtle_timer(timer_entry->node_ip);
		return;
	}
	for(traverse = thrtl_cnt->sess_ptr; traverse != NULL; traverse = traverse->next){
		uint32_t teid = UE_SESS_ID(traverse->sess_id);

		ret = get_ue_context(teid, &context);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
					"context for teid: %u\n", LOG_VALUE, teid);
		}
		for(uint8_t itr = 0; itr < MAX_BEARERS; itr++){
			if(context->pdns[itr] != NULL){
				if(context->pdns[itr]->seid == traverse->sess_id){
					memcpy(pfcp_pdr_id.pdr_id, traverse->pdr_id, sizeof(uint16_t));
					pfcp_pdr_id.pdr_count = traverse->pdr_count;
					pfcp_pdr_id.ddn_buffered_count = 0;
					ret = ddn_by_session_id(traverse->sess_id, &pfcp_pdr_id);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
					}
					context->pfcp_rept_resp_sent_flag = 0;
				}
			}
		}
	}
	delete_thrtle_timer(timer_entry->node_ip);

	RTE_SET_USED(ti);
}

void
send_pfcp_sess_mod_req_for_ddn(pdn_connection *pdn)
{
	uint32_t seq = 0;
	int ret = 0;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	node_address_t node_value = {0};

	set_pfcpsmreqflags(&(pfcp_sess_mod_req.pfcpsmreq_flags));
	pfcp_sess_mod_req.pfcpsmreq_flags.drobu = 1;

	/*Filling Node ID for F-SEID*/
	if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV4) {
		uint8_t temp[IPV6_ADDRESS_LEN] = {0};

		ret = fill_ip_addr(config.pfcp_ip.s_addr, temp, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

	} else if (pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV6) {

		ret = fill_ip_addr(0, config.pfcp_ip_v6.s6_addr, &node_value);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

	}
	set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn->seid, node_value);

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
				HAS_SEID, seq, pdn->context->cp_mode);
	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if(pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded,
							upf_pfcp_sockaddr, SENT) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to send"
				"PFCP Session Modification Request %i\n", LOG_VALUE, errno);
	}
}

/* PFCP: Callback calls while expired UE Level timer for buffering rpt req msg*/
void dl_buffer_timer_callback(gstimerinfo_t *ti, const void *data_t )
{
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	ue_level_timer *timer_entry = (ue_level_timer *)data_t;
#pragma GCC diagnostic pop
	int ret = 0;
	bool match_found = FALSE;
	pdr_ids *pfcp_pdr_id = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint32_t teid = UE_SESS_ID(timer_entry->sess_id);

	/* Send Pfcp Session Modification Request with apply action DROP */
	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
				"context for teid: %u\n", LOG_VALUE, teid);
		delete_ddn_timer_entry(dl_timer_by_teid_hash, teid, pfcp_rep_by_seid_hash);
		return;
	}
	for(uint8_t itr_pdn = 0; itr_pdn < MAX_BEARERS; itr_pdn++){
		if(context->pdns[itr_pdn]!=NULL){
			pdn = context->pdns[itr_pdn];

			ret = rte_hash_lookup_data(pfcp_rep_by_seid_hash,
					&pdn->seid, (void **)&pfcp_pdr_id);
			if(ret >= 0 && pfcp_pdr_id != NULL){
				match_found = TRUE;
			}
		}
	}
	if(match_found == TRUE){
		send_pfcp_sess_mod_req_for_ddn(pdn);
	}

	delete_ddn_timer_entry(dl_timer_by_teid_hash, teid, pfcp_rep_by_seid_hash);
	RTE_SET_USED(ti);
}

/* GTPv2C: UE Level timer */
void ddn_timer_callback(gstimerinfo_t *ti, const void *data_t )
{
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	ue_level_timer *timer_entry = (ue_level_timer *)data_t;
#pragma GCC diagnostic pop
	int ret = 0;
	uint8_t cp_thrtl_fact = 0;
	pfcp_pdr_id_ie_t pdr[MAX_LIST_SIZE] = {0};
	pdr_ids *pfcp_pdr_id = NULL;
	ue_context *context = NULL;
	throttle_timer *thrtle_timer_data = NULL;

	uint32_t teid = UE_SESS_ID(timer_entry->sess_id);

	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
				"context for teid: %u\n", LOG_VALUE, teid);
		delete_ddn_timer_entry(timer_by_teid_hash, teid, ddn_by_seid_hash);
		return;
	}
	for(uint8_t i = 0; i < MAX_BEARERS; i++){
		if(context->pdns[i] != NULL){
			ret = rte_hash_lookup_data(ddn_by_seid_hash,
					&context->pdns[i]->seid, (void **)&pfcp_pdr_id);
			if(ret >= 0){
				if((rte_hash_lookup_data(thrtl_timer_by_nodeip_hash,
								(const void *)&context->s11_mme_gtpc_ip, (void **)&thrtle_timer_data)) >= 0){

					thrtle_count *thrtl_cnt = NULL;
					thrtl_cnt = get_throtle_count(&context->s11_mme_gtpc_ip, ADD_ENTRY);
					if(thrtl_cnt != NULL){
							if(thrtl_cnt->prev_ddn_eval != 0){
								cp_thrtl_fact = (thrtl_cnt->prev_ddn_discard/thrtl_cnt->prev_ddn_eval) * 100;
								if(cp_thrtl_fact >  thrtle_timer_data->throttle_factor){
									pfcp_pdr_id->ddn_buffered_count = 0;
									ret = ddn_by_session_id(context->pdns[i]->seid, pfcp_pdr_id);
									if (ret) {
										clLog(clSystemLog, eCLSeverityCritical,
												LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
									}
									thrtl_cnt->prev_ddn_eval = thrtl_cnt->prev_ddn_eval + 1;
									context->pfcp_rept_resp_sent_flag = 1;
								}else{
									for(uint8_t i = 0; i < MAX_LIST_SIZE; i++){
										pdr[i].rule_id = pfcp_pdr_id->pdr_id[i];
									}
									thrtl_cnt->prev_ddn_eval = thrtl_cnt->prev_ddn_eval + 1;
									thrtl_cnt->prev_ddn_discard = thrtl_cnt->prev_ddn_discard + 1;
									fill_sess_info_id(thrtl_cnt, context->pdns[i]->seid,
											pfcp_pdr_id->pdr_count, pdr);
									context->pfcp_rept_resp_sent_flag = 1;
								}

							} else {
								pfcp_pdr_id->ddn_buffered_count = 0;
								ret = ddn_by_session_id(context->pdns[i]->seid, pfcp_pdr_id);
								if (ret) {
									clLog(clSystemLog, eCLSeverityCritical,
											LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
								}
								thrtl_cnt->prev_ddn_eval = thrtl_cnt->prev_ddn_eval + 1;
								context->pfcp_rept_resp_sent_flag = 1;
							}

						delete_ddn_timer_entry(timer_by_teid_hash, teid, ddn_by_seid_hash);
						return;
					}
				} else {
					pfcp_pdr_id->ddn_buffered_count = 0;
					ret = ddn_by_session_id(context->pdns[i]->seid, pfcp_pdr_id);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT "Failed to process DDN request \n", LOG_VALUE);
					}
					context->pfcp_rept_resp_sent_flag = 1;
				}
			}
		}
	}

	delete_ddn_timer_entry(timer_by_teid_hash, teid, ddn_by_seid_hash);
	RTE_SET_USED(ti);
}


ue_level_timer *
fill_timer_entry(uint64_t seid)
{
	ue_level_timer *timer_entry = NULL;

	timer_entry = rte_zmalloc_socket(NULL, sizeof(ue_level_timer),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"Memory for ue_level_timer, Error: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
		return NULL;
	}

	timer_entry->sess_id = seid;
	return(timer_entry);
}

bool
add_timer_entry(peerData *conn_data, uint32_t timeout_ms,
		gstimercallback cb)
{

	if (!init_timer(conn_data, timeout_ms, cb))
	{
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT" =>%s - initialization of %s failed erro no %d\n",
				LOG_VALUE,
				getPrintableTime(), conn_data->name, errno);
		return false;
	}

	return true;
}

void
timer_callback(gstimerinfo_t *ti, const void *data_t )
{
	int ret = 0;
	msg_info msg = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	RTE_SET_USED(ti);

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *data =  (peerData *) data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	data->itr = config.request_tries;
	if (data->itr_cnt >= data->itr - 1) {
		ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get Ue context for teid: %d\n",
					LOG_VALUE, data->teid);
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			if(data != NULL){
				rte_free(data);
				data = NULL;
			}
			return;
		}

		if(context != NULL && context->eps_bearers[data->ebi_index] != NULL
				&& context->eps_bearers[data->ebi_index]->pdn != NULL ) {
			pdn = context->eps_bearers[data->ebi_index]->pdn;
			if(get_sess_entry(pdn->seid, &resp) == 0){
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session entry "
					"found for session id: %s",LOG_VALUE,
						gtp_type_str(resp->msg_type));
				if(resp->state == ERROR_OCCURED_STATE){
					reset_resp_info_structure(resp);
					cleanup_ue_and_bearer(data->teid, data->ebi_index);

				} else if (GTP_MODIFY_BEARER_REQ == resp->msg_type) {
					msg.gtpc_msg.mbr = resp->gtpc_msg.mbr;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					mbr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
							CAUSE_SOURCE_SET_TO_0,
							context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					if(context->piggyback == TRUE) {
						msg.msg_type = GTP_CREATE_BEARER_RSP;
						msg.gtpc_msg.cb_rsp.header.teid.has_teid.seq = resp->cb_rsp_attach.seq;
						msg.gtpc_msg.cb_rsp.cause.cause_value =  resp->cb_rsp_attach.cause_value;
						msg.gtpc_msg.cb_rsp.cause.header.len = PRESENT;

						resp->bearer_count = resp->cb_rsp_attach.bearer_cnt;
						for(int idx =0 ; idx < resp->bearer_count ; idx ++) {
							msg.gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.header.len = PRESENT;
							msg.gtpc_msg.cb_rsp.bearer_contexts[idx].cause.header.len = PRESENT;
							msg.gtpc_msg.cb_rsp.bearer_contexts[idx].cause.cause_value =
								resp->cb_rsp_attach.bearer_cause_value[idx];
							msg.gtpc_msg.cb_rsp.bearer_contexts[idx].eps_bearer_id.ebi_ebi =
								resp->cb_rsp_attach.ebi_ebi[idx];
							resp->eps_bearer_ids[idx] = resp->cb_rsp_attach.ebi_ebi[idx];
						}
						cbr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
									CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
						context->piggyback = FALSE;
					}
				} else if (GTP_BEARER_RESOURCE_CMD == resp->msg_type) {
					msg.gtpc_msg.bearer_rsrc_cmd = resp->gtpc_msg.bearer_rsrc_cmd;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					send_bearer_resource_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				} else if (GTP_MODIFY_BEARER_CMD == resp->msg_type) {
					msg.gtpc_msg.mod_bearer_cmd = resp->gtpc_msg.mod_bearer_cmd;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					modify_bearer_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
										CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				} else if ((GTP_CREATE_SESSION_REQ == resp->msg_type)
						|| (GTP_CREATE_SESSION_RSP == resp->msg_type)) {
					msg.gtpc_msg.csr = resp->gtpc_msg.csr;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					msg.teid = data->teid;
					msg.state = resp->state;
					if (!context->piggyback || context->cp_mode != SGWC) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Peer not responding, hence sending an error response\n",
								LOG_VALUE);
						cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0,
								context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
					} else {
						clean_up_while_error(context->pdns[data->ebi_index]->default_bearer_id, context, data->teid,
								&context->imsi, 0, &msg);
					}
				} else if (GTP_DELETE_SESSION_REQ == resp->msg_type) {
					if(resp->state == PFCP_SESS_MOD_REQ_SNT_STATE)
					{
						/* when timer retry end on sxa interface in case of sgwc
						* then send delete session requent on s5s8 interface
						* after recieving DSR response scenerio will execute
						* similar to initial attach dettach
						*/
						send_delete_session_request_after_timer_retry(context, data->ebi_index);
						return;
					}
					msg.gtpc_msg.dsr = resp->gtpc_msg.dsr;
					msg.msg_type = resp->msg_type;
					msg.teid = resp->teid;
					ds_error_response(&msg, GTPV2C_CAUSE_REQUEST_ACCEPTED,
							CAUSE_SOURCE_SET_TO_0,
							context->cp_mode != PGWC ? S11_IFACE :S5S8_IFACE);
				} else if ((context->cp_mode == PGWC ||  context->cp_mode ==  SAEGWC )
						&& ((resp->msg_type == GX_RAR_MSG) || (resp->state == CREATE_BER_REQ_SNT_STATE))) {

					if (resp->msg_type == GX_RAR_MSG){
						msg.gx_msg.rar.session_id.len = strnlen(resp->gx_sess_id, GX_SESS_ID_LEN);
						memcpy(msg.gx_msg.rar.session_id.val, resp->gx_sess_id,
								msg.gx_msg.rar.session_id.len);
					}

					if (pdn->policy.num_charg_rule_install) {
						cbr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
									CAUSE_SOURCE_SET_TO_0, GX_IFACE);
					} else if (pdn->policy.num_charg_rule_delete) {
						delete_bearer_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
							CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
					}

					pdn->state = CONNECTED_STATE;

				} else if (((resp->msg_type == GTP_CREATE_BEARER_REQ) || (resp->msg_type == GTP_CREATE_BEARER_RSP))
									&& (context->cp_mode == SGWC)) {
					msg.msg_type = resp->msg_type;
					msg.gtpc_msg.cb_req =  resp->gtpc_msg.cb_req;
					if(pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
						send_bearer_resource_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0,
								context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
						provision_ack_ccr(pdn, pdn->eps_bearers[data->ebi_index],
								RULE_ACTION_ADD, RESOURCE_ALLOCATION_FAILURE);
					} else {
						cbr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
					}
				} else if (((resp->msg_type == GTP_DELETE_BEARER_REQ) || (resp->msg_type == GTP_DELETE_BEARER_RSP))) {
					msg.gtpc_msg.db_req = resp->gtpc_msg.db_req;
					msg.msg_type = resp->msg_type;
					if(pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
						send_bearer_resource_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0,
								context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
						provision_ack_ccr(pdn, pdn->eps_bearers[data->ebi_index],
								RULE_ACTION_DELETE, RESOURCE_ALLOCATION_FAILURE);
					} else {
						delete_bearer_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0, S5S8_IFACE);
					}
				}  else if ((context->cp_mode == PGWC ||  context->cp_mode ==  SAEGWC ) &&
					((resp->state == DELETE_BER_REQ_SNT_STATE) || (resp->state == UPDATE_BEARER_REQ_SNT_STATE)
					|| (resp->msg_type == GTP_UPDATE_BEARER_RSP))) {
					if (pdn->proc == UE_REQ_BER_RSRC_MOD_PROC) {
						/* TODO: Timer Flow not handled properly, added temp solution */
						if (resp->state == UPDATE_BEARER_REQ_SNT_STATE) {
							resp->msg_type = GTP_UPDATE_BEARER_REQ;
							msg.gtpc_msg.ub_req = resp->gtpc_msg.ub_req;
						}

						/* TODO: Timer Flow not handled properly, added temp solution */
						if (resp->msg_type == GTP_UPDATE_BEARER_RSP) {
							msg.gtpc_msg.ub_rsp = resp->gtpc_msg.ub_rsp;
						}

						/* TODO: Timer Flow not handled properly, added temp solution */
						if (resp->state == DELETE_BER_REQ_SNT_STATE) {
							resp->msg_type = GTP_DELETE_BEARER_REQ;
							msg.gtpc_msg.db_req = resp->gtpc_msg.db_req;
						}

						msg.msg_type = resp->msg_type;
						msg.teid = resp->teid;
						send_bearer_resource_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0,
								context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
						provision_ack_ccr(pdn, pdn->eps_bearers[data->ebi_index],
								RULE_ACTION_MODIFY, RESOURCE_ALLOCATION_FAILURE);
					} else {
						gen_reauth_error_response(pdn, DIAMETER_UNABLE_TO_COMPLY);
					}
				} else if (resp->msg_type == GTP_UPDATE_BEARER_REQ) {
					msg.gtpc_msg.ub_req = resp->gtpc_msg.ub_req;
					msg.msg_type = resp->msg_type;
					ubr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
							CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);

				} else if (resp->msg_type == GTP_RELEASE_ACCESS_BEARERS_REQ) {
					msg.gtpc_msg.rel_acc_ber_req =  resp->gtpc_msg.rel_acc_ber_req;
					msg.msg_type = resp->msg_type;
					release_access_bearer_error_response(&msg,
						GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING, CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);

				} else if(resp->state == DDN_REQ_SNT_STATE){
					send_pfcp_sess_mod_req_for_ddn(pdn);

					/* Remove session Entry from buffered ddn request hash */
					pdr_ids *pfcp_pdr_id = delete_buff_ddn_req(pdn->seid);
					if(pfcp_pdr_id != NULL) {
						rte_free(pfcp_pdr_id);
						pfcp_pdr_id = NULL;
					}
				} else{

					/* Need to handle for other request */
				}
			}
		}
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			if(data != NULL){
				rte_free(data);
				data = NULL;
			}
			/*if this line is uncommented timer is not getting deleted*/
			//pdn->timer_entry =  NULL;
		}
		return;
	}

	/* timer retry handler */
	switch(data->portId) {
		case GX_IFACE:
			break;
		case S11_IFACE:
			timer_retry_send(s11_fd, s11_fd_v6, data, context);
			break;
		case S5S8_IFACE:
			timer_retry_send(s5s8_fd, s5s8_fd_v6, data, context);
			break;
		case PFCP_IFACE:
			timer_retry_send(pfcp_fd, pfcp_fd_v6, data, context);
			break;
		default:
			break;
	}
	data->itr_cnt++;
	return;
}

void
delete_association_timer(peerData *data)
{
	stoptimer(&data->pt.ti_id);
	deinittimer(&data->pt.ti_id);
	/* free peer data when timer is de int */
	if(data != NULL){
		rte_free(data);
		data = NULL;
	}

}

void association_fill_error_response(peerData *data)
{
	int ret = 0;
	msg_info msg = {0};
	ue_context *context = NULL;
	upf_context_t *upf_context = NULL;
	context_key *key = NULL;
	uint8_t index = 0;

		ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get Ue context for teid: %d\n",
					LOG_VALUE, data->teid);
			delete_association_timer(data);
			return;
		}
		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
				(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ip),
				(void **) &(upf_context));

		if (upf_context != NULL &&  ret >= 0) {
			for(uint8_t idx = 0; idx < upf_context->csr_cnt; idx++) {

				msg.msg_type = GTP_CREATE_SESSION_REQ;
				key = (context_key *) upf_context->pending_csr_teid[idx];
				msg.gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = key->sender_teid;
				msg.gtpc_msg.csr.header.teid.has_teid.seq = key->sequence;
				for (uint8_t itr = 0; itr < MAX_BEARERS; ++itr) {
					if(key->bearer_ids[itr] != 0){
						msg.gtpc_msg.csr.bearer_contexts_to_be_created[index].header.len =
							sizeof(uint8_t) + IE_HEADER_SIZE;
						msg.gtpc_msg.csr.bearer_contexts_to_be_created[index].eps_bearer_id.ebi_ebi =
							key->bearer_ids[itr];
						index++;
					}
				}
				msg.gtpc_msg.csr.bearer_count = index;
				msg.gtpc_msg.csr.header.teid.has_teid.teid = key->teid;
				msg.cp_mode = context->cp_mode;
				cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
						CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			}
		}


		if(data->pt.ti_id != 0) {
			delete_association_timer(data);
		}
		return;
}

void
association_timer_callback(gstimerinfo_t *ti, const void *data_t )
{
	ue_context *context = NULL;
	upf_context_t *upf_context = NULL;
	int ret = 0;
	upfs_dnsres_t *entry = NULL;
	RTE_SET_USED(ti);
	pdn_connection *pdn = NULL;
	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};
	int decoded = 0;
	node_address_t cp_node_value = {0};

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *data =  (peerData *) data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	if(config.use_dns){
		ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					" get Ue context for teid: %d\n",
					LOG_VALUE, data->teid);
			delete_association_timer(data);
			return;
		}
		if(rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ip),
					(void **) &(upf_context)) < 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Upf Context "
				"not found of IP Type : %s\n with IP IPv4 : "IPV4_ADDR"\t"
				" and IPv6 : "IPv6_FMT"", LOG_VALUE,
				ip_type_str(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ip_type),
				IPV4_ADDR_HOST_FORMAT(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ipv4_addr),
				PRINT_IPV6_ADDR(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ipv6_addr));

			delete_association_timer(data);
			return;
		}
		if (upflist_by_ue_hash_entry_lookup(&data->imsi,
					sizeof(data->imsi), &entry) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT" Failure in upflist_by_ue_hash_entry_lookup\n",LOG_VALUE);
			delete_association_timer(data);
			return;
		}
	}

	if(config.use_dns){
		if ((entry->current_upf) == (entry->upf_count - 1)){
			association_fill_error_response(data);
			return;
		}
	}else{
		association_fill_error_response(data);
		return;
	}

	if (entry->current_upf < (entry->upf_count - 1)) {

			upf_context_t *tmp_upf_context = upf_context;

			/* Delete entry from teid info list for given upf*/
			delete_entry_from_teid_list(context->eps_bearers[data->ebi_index]->pdn->upf_ip,
					&upf_teid_info_head);

			/* Delete old upf_ip entry from hash */
			rte_hash_del_key(upf_context_by_ip_hash, (const void *)
					&context->eps_bearers[data->ebi_index]->pdn->upf_ip);

			if (entry->upf_ip_type == PDN_TYPE_IPV4
					&& *entry->upf_ip[entry->current_upf].ipv6.s6_addr
					&& (config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
							|| config.pfcp_ip_type == PDN_TYPE_IPV6)) {

					ret = fill_ip_addr(0, entry->upf_ip[entry->current_upf].ipv6.s6_addr, &data->dstIP);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					ret = fill_ip_addr(0, entry->upf_ip[entry->current_upf].ipv6.s6_addr,
								&context->eps_bearers[data->ebi_index]->pdn->upf_ip);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					entry->upf_ip_type |= PDN_TYPE_IPV6;

			} else if (entry->upf_ip_type == PDN_TYPE_IPV6
					&& entry->upf_ip[entry->current_upf].ipv4.s_addr != 0
					&& (config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
							|| config.pfcp_ip_type == PDN_TYPE_IPV4)) {

					uint8_t temp[IPV6_ADDRESS_LEN] = {0};

					ret = fill_ip_addr(entry->upf_ip[entry->current_upf].ipv4.s_addr, temp,
								&data->dstIP);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					ret = fill_ip_addr(entry->upf_ip[entry->current_upf].ipv4.s_addr, temp,
								&context->eps_bearers[data->ebi_index]->pdn->upf_ip);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					entry->upf_ip_type |= PDN_TYPE_IPV4;

			} else {

				entry->current_upf++;
				/*store new upf_ip entry */
				memcpy(context->eps_bearers[data->ebi_index]->pdn->fqdn, entry->upf_fqdn[entry->current_upf],
						strnlen(entry->upf_fqdn[entry->current_upf], MAX_HOSTNAME_LENGTH));

				if ((config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
							|| config.pfcp_ip_type == PDN_TYPE_IPV6)
								&& (*entry->upf_ip[entry->current_upf].ipv6.s6_addr)) {

					ret = fill_ip_addr(0, entry->upf_ip[entry->current_upf].ipv6.s6_addr, &data->dstIP);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					ret = fill_ip_addr(0, entry->upf_ip[entry->current_upf].ipv6.s6_addr,
								&context->eps_bearers[data->ebi_index]->pdn->upf_ip);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					entry->upf_ip_type = PDN_TYPE_IPV6;

				} else if ((config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6
							|| config.pfcp_ip_type == PDN_TYPE_IPV4)
								&& (entry->upf_ip[entry->current_upf].ipv4.s_addr != 0)) {

					uint8_t temp[IPV6_ADDRESS_LEN] = {0};

					ret = fill_ip_addr(entry->upf_ip[entry->current_upf].ipv4.s_addr, temp,
								&data->dstIP);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					ret = fill_ip_addr(entry->upf_ip[entry->current_upf].ipv4.s_addr, temp,
								&context->eps_bearers[data->ebi_index]->pdn->upf_ip);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}

					entry->upf_ip_type = PDN_TYPE_IPV4;

				} else {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT "Requested type and DNS supported type are not same\n", LOG_VALUE);
				}
			}

			decoded = decode_pfcp_assn_setup_req_t(data->buf,
								&pfcp_ass_setup_req);

			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "decoded Association "
				"Request while retrying with %d ", LOG_VALUE, decoded);

			/*Filling CP Node ID*/
			if (context->eps_bearers[data->ebi_index]->pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV4) {
				uint8_t temp[IPV6_ADDRESS_LEN] = {0};
				ret = fill_ip_addr(config.pfcp_ip.s_addr, temp, &cp_node_value);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}
			} else if (context->eps_bearers[data->ebi_index]->pdn->upf_ip.ip_type == PDN_IP_TYPE_IPV6) {

				ret = fill_ip_addr(0, config.pfcp_ip_v6.s6_addr, &cp_node_value);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}

			}

			set_node_id(&pfcp_ass_setup_req.node_id, cp_node_value);

			int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, data->buf);

			data->buf_len = encoded;

			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "encoded Association "
				"Request while retrying with %d ", LOG_VALUE, encoded);
			/* Assign new upf_ip entry to global variable  holding upf_ip */
			ret = set_dest_address(context->eps_bearers[data->ebi_index]->pdn->upf_ip,
								&upf_pfcp_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}

			/*Searching UPF Context for New DNS IP*/
			ret = 0;
			ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ip),
					(void **) &(upf_context));

			if (ret == -ENOENT) {
				/* Add entry of new upf_ip in hash */
				ret = upf_context_entry_add(&(context->eps_bearers[data->ebi_index]->pdn->upf_ip),
																						upf_context);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"failed to add entry  %d \n", LOG_VALUE, ret);
					return ;
				} else {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Added entry "
						"UPF Context for IP Type : %s "
						"with IPv4 : "IPV4_ADDR"\t and IPv6 : "IPv6_FMT"",
						LOG_VALUE, ip_type_str(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ip_type),
						IPV4_ADDR_HOST_FORMAT(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ipv4_addr),
						PRINT_IPV6_ADDR(context->eps_bearers[data->ebi_index]->pdn->upf_ip.ipv6_addr));
				}
				/* Send the Association Request to next UPF */
				if (data->portId == PFCP_IFACE) {
					timer_retry_send(pfcp_fd, pfcp_fd_v6, data, context);
				}
			} else if (ret == -EINVAL ) {

				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Invalid key In RTE HASH Look UP DATA: %d \n",
						LOG_VALUE, ret);

				delete_association_timer(data);
				return ;

			} else {

				if(upf_context->state == PFCP_ASSOC_RESP_RCVD_STATE
						|| upf_context->assoc_status == ASSOC_ESTABLISHED) {


					ret = get_ue_context(data->teid, &context);
					if(ret < 0)  {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"UE context not found ", LOG_VALUE);
					}
					pdn = GET_PDN(context, data->ebi_index);
					if(pdn == NULL){
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
								"pdn for ebi_index %d\n", LOG_VALUE, data->ebi_index);
					}

					pdn->upf_ip.ipv4_addr = upf_pfcp_sockaddr.ipv4.sin_addr.s_addr;
					memcpy(pdn->upf_ip.ipv6_addr,
							upf_pfcp_sockaddr.ipv6.sin6_addr.s6_addr,
							IPV6_ADDRESS_LEN);
					pdn->upf_ip.ip_type = upf_pfcp_sockaddr.type;

					int count = 0;
					upf_context->csr_cnt = tmp_upf_context->csr_cnt;

					for (uint8_t i = 0; i < tmp_upf_context->csr_cnt; i++) {

						context_key *key = (context_key *)tmp_upf_context->pending_csr_teid[i];

						if (get_ue_context(key->teid, &context) != 0) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"UE context not found "
									"for teid: %d\n", LOG_VALUE, key->teid);
							continue;
						}

						pdn = GET_PDN(context, key->ebi_index);
						if(pdn == NULL){
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
									"pdn for ebi_index %d\n", LOG_VALUE, key->ebi_index);
							continue;
						}

						// pdn->upf_ipv4.s_addr = upf_pfcp_sockaddr.ipv4.sin_addr.s_addr;
						ret = process_pfcp_sess_est_request(key->teid, pdn, upf_context);
						if (ret) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process PFCP "
									"session eshtablishment request %d \n", LOG_VALUE, ret);

							fill_response(pdn->seid, key);

						}
						fill_response(pdn->seid, key);
						rte_free(tmp_upf_context->pending_csr_teid[i]);
						count++;

					} /*for*/

					upf_context->csr_cnt = upf_context->csr_cnt - count;
					tmp_upf_context->csr_cnt = tmp_upf_context->csr_cnt - count;
					delete_association_timer(data);
				}
			}
	}
	return;
}

peerData *
fill_timer_entry_data(enum source_interface iface, peer_addr_t *peer_addr,
		uint8_t *buf, uint16_t buf_len, uint8_t itr, uint32_t teid,  int ebi_index )
{
	peerData *timer_entry = NULL;

	timer_entry = rte_zmalloc_socket(NULL, sizeof(peerData),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"Memory for timer entry, Error: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
		return NULL;
	}

	timer_entry->dstIP.ip_type = peer_addr->type;

	if (peer_addr->type == PDN_TYPE_IPV4) {

		timer_entry->dstPort = peer_addr->ipv4.sin_port;
		timer_entry->dstIP.ipv4_addr = peer_addr->ipv4.sin_addr.s_addr;
	} else {

		timer_entry->dstPort = peer_addr->ipv6.sin6_port;
		memcpy(&timer_entry->dstIP.ipv6_addr, peer_addr->ipv6.sin6_addr.s6_addr, IPV6_ADDRESS_LEN);
	}

	timer_entry->portId = (uint8_t)iface;
	timer_entry->itr = itr;
	timer_entry->teid = teid;
	timer_entry->ebi_index = ebi_index;
	timer_entry->buf_len = buf_len;
	memcpy(&timer_entry->buf,(uint8_t *)buf, buf_len);

	return(timer_entry);
}

void
delete_pfcp_if_timer_entry(uint32_t teid, int ebi_index )
{
	int ret = 0;
	peerData *data = NULL;
	ue_context *context = NULL;

	ret = get_ue_context(teid, &context);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Ue context for teid: %d\n", LOG_VALUE, teid);
		return;
	}
	if(context != NULL && context->eps_bearers[ebi_index] != NULL
			&& context->eps_bearers[ebi_index]->pdn != NULL
			&& context->eps_bearers[ebi_index]->pdn->timer_entry != NULL) {
		data = context->eps_bearers[ebi_index]->pdn->timer_entry;
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			if(data != NULL){
				rte_free(data);
				data = NULL;
			}
			context->eps_bearers[ebi_index]->pdn->timer_entry = NULL;
		}
	}
	return;
}

void
delete_gtpv2c_if_timer_entry(uint32_t teid, int ebi_index)
{
	int ret = 0;
	peerData *data = NULL;
	ue_context *context = NULL;

	ret = get_ue_context(teid, &context);
	if(ret < 0 || context == NULL ){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Context found "
			"for teid: %x\n", LOG_VALUE, teid);
		return;
	}
	if(context != NULL && context->eps_bearers[ebi_index] != NULL
			&& context->eps_bearers[ebi_index]->pdn != NULL
			&& context->eps_bearers[ebi_index]->pdn->timer_entry != NULL){
		data = context->eps_bearers[ebi_index]->pdn->timer_entry;
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			if(data != NULL){
				rte_free(data);
				data = NULL;
			}
		}
	}
	return;
}

void
delete_timer_entry(uint32_t teid)
{
	int ret = 0;
	peerData *data = NULL;
	eps_bearer *bearer = NULL;

	ret = get_bearer_by_teid(teid, &bearer);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Bearer found "
				"for teid: %x\n", LOG_VALUE, teid);
		return;
	}

	if(bearer != NULL && bearer->pdn != NULL &&
			bearer->pdn->timer_entry != NULL ) {
		data = bearer->pdn->timer_entry;
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			if(data != NULL){
				rte_free(data);
				data = NULL;
			}
			bearer->pdn->timer_entry = NULL;
		}
	}
	return;
}

void
add_pfcp_if_timer_entry(uint32_t teid, peer_addr_t *peer_addr,
		uint8_t *buf, uint16_t buf_len, int ebi_index )
{
	int ret = 0;
	peerData *timer_entry = NULL;
	ue_context *context = NULL;

	ret = get_ue_context(teid, &context);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Failed to get Ue context for teid: %x \n", LOG_VALUE, teid);
		return;
	}
	/* fill and add timer entry */
	timer_entry = fill_timer_entry_data(PFCP_IFACE, peer_addr,
			buf, buf_len, config.request_tries, teid, ebi_index);
	if (timer_entry == NULL ) {
		 clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				 "Failed to Add timer entry for teid: %x\n",
				 LOG_VALUE, teid);
		return;
	}

	if(!(add_timer_entry(timer_entry, config.request_timeout, timer_callback))) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add timer entry...\n",
				LOG_VALUE);
	}
	if(context != NULL && context->eps_bearers[ebi_index] != NULL
			&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
		context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;

		if (starttimer(&timer_entry->pt) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Periodic Timer failed to start...\n",
					LOG_VALUE);
		} else {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Periodic Timer is started for TEID:%u\n",
					LOG_VALUE, teid);
		}
	}
}

void
add_gtpv2c_if_timer_entry(uint32_t teid, peer_addr_t *peer_addr,
	uint8_t *buf, uint16_t buf_len, int ebi_index , enum source_interface iface,
	uint8_t cp_mode)
{
	int ret = 0;
	peerData *timer_entry = NULL;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;

	/* fill and add timer entry */
	timer_entry = fill_timer_entry_data(iface, peer_addr,
			buf, buf_len, config.request_tries, teid, ebi_index);

	if (timer_entry == NULL ) {
		 clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				 "Failed to Add timer entry for teid: %x\n",
				 LOG_VALUE, teid);
		return;
	}

	if(!(add_timer_entry(timer_entry, config.request_timeout, timer_callback))) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Faild to add timer entry...\n",
				LOG_VALUE);
	}

	if(SGWC == cp_mode) {
			/* if we get s5s8 fteid we will retrive bearer , if we get sgw s11 fteid we will retrive ue contex */
		ret = get_bearer_by_teid(teid, &bearer);
		if ( ret < 0) {
			/*The teid might be of S11*/
			ret = get_ue_context(teid, &context);
			if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Ue context for teid: %d\n", LOG_VALUE, teid);
					return;
			}

			if(context != NULL && context->eps_bearers[ebi_index] != NULL
				&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
					context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;
			} else {
				return;
			}
		}else {
			bearer->pdn->timer_entry = timer_entry;
		}
	} else {
		ret = get_ue_context(teid, &context);
			if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Ue context for teid: %d\n", LOG_VALUE, teid);
					return;
			}

		if(context != NULL && context->eps_bearers[ebi_index] != NULL
			&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
					context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;
		} else {
			return;
		}
	}
	if (starttimer(&timer_entry->pt) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Periodic Timer failed to start...\n",
				LOG_VALUE);
	}
}

sess_info *
insert_into_sess_info_list(sess_info *head, sess_info *new_node)
{

	sess_info *traverse = NULL;
	if(new_node == NULL)
		return head;

	if(head == NULL){
		head = new_node;
	} else{
		for(traverse = head; traverse->next != NULL; traverse = traverse->next);
			traverse->next = new_node;
	}
	return head;
}

void
delete_from_sess_info_list(sess_info *head)
{
	sess_info *traverse = NULL;
	if(head == NULL)
		return;
	for(traverse = head; traverse != NULL;){
		head = head->next;
		rte_free(traverse);
		traverse = NULL;
		traverse = head;
	}
}

sess_info *
search_into_sess_info_list(sess_info * head, uint64_t sess_id)
{
	sess_info *traverse = NULL;
	if(head == NULL)
		return NULL;
	for(traverse = head; traverse != NULL; traverse = traverse->next){
		if(traverse->sess_id == sess_id){
			return traverse;
		}
	}
	return NULL;
}
