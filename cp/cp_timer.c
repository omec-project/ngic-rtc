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

#include "gtpv2c.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "rte_common.h"
#include "cp_timer.h"
#include "gtpv2c_error_rsp.h"
#include "clogger.h"
#include "gw_adapter.h"
#include "debug_str.h"
#include "teid.h"
#include "cp.h"
#include "pfcp_session.h"

#define DIAMETER_PCC_RULE_EVENT (5142)

extern int s11_fd;
extern int s5s8_fd;
extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;

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
	data->itr = number_of_request_tries;
	if (data->itr_cnt >= data->itr - 1) {
		ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Ue context for teid: %d\n", LOG_VALUE, data->teid);
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
				} else if (GTP_BEARER_RESOURCE_CMD == resp->msg_type) {
					msg.gtpc_msg.bearer_rsrc_cmd = resp->gtpc_msg.bearer_rsrc_cmd;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					send_bearer_resource_failure_indication(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
								CAUSE_SOURCE_SET_TO_0, S11_IFACE);
				} else if ((GTP_CREATE_SESSION_REQ == resp->msg_type)
						|| (GTP_CREATE_SESSION_RSP == resp->msg_type)) {
					msg.gtpc_msg.csr = resp->gtpc_msg.csr;
					msg.msg_type = resp->msg_type;
					msg.cp_mode = context->cp_mode;
					msg.teid = data->teid;
					cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
							CAUSE_SOURCE_SET_TO_0,
							context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
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

					if (resp->msg_type == GX_RAR_MSG)
						msg.gx_msg.rar = resp->gx_msg.rar;

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
								RULE_ACTION_ADD, RESOURCE_ALLOCATION_FAILURE, &pro_ack_rule_array);
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
								RULE_ACTION_DELETE, RESOURCE_ALLOCATION_FAILURE, &pro_ack_rule_array);
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
								RULE_ACTION_MODIFY, RESOURCE_ALLOCATION_FAILURE, &pro_ack_rule_array);
					} else {
						gen_reauth_error_response(pdn, DIAMETER_UNABLE_TO_COMPLY);
					}
				} else if (resp->msg_type == GTP_UPDATE_BEARER_REQ) {
					msg.gtpc_msg.ub_req =  resp->gtpc_msg.ub_req;
					msg.msg_type = resp->msg_type;
					ubr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
							CAUSE_SOURCE_SET_TO_0, context->cp_mode == SGWC ? S5S8_IFACE : GX_IFACE);
				} else if (resp->msg_type == GTP_RELEASE_ACCESS_BEARERS_REQ) {
					msg.gtpc_msg.rel_acc_ber_req =  resp->gtpc_msg.rel_acc_ber_req;
					msg.msg_type = resp->msg_type;
					release_access_bearer_error_response(&msg,
						GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING, CAUSE_SOURCE_SET_TO_0,
						context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
				}else{

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
			timer_retry_send(s11_fd, data, context);
			break;
		case S5S8_IFACE:
			timer_retry_send(s5s8_fd, data, context);
			break;
		case PFCP_IFACE:
			timer_retry_send(pfcp_fd, data, context);
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
				(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr),
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

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *data =  (peerData *) data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	if(pfcp_config.use_dns){
		ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to"
					" get Ue context for teid: %d\n",
					LOG_VALUE, data->teid);
			delete_association_timer(data);
			return;
		}
		if(rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr),
					(void **) &(upf_context)) < 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"upf_context "
					"not found :%u\n", LOG_VALUE,
					context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr);

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

	if(pfcp_config.use_dns){
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

			entry->current_upf++;

			/* Delete entry from teid info list for given upf*/
			delete_entry_from_teid_list(context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr,
					&upf_teid_info_head);

			/* Delete old upf_ip entry from hash */
			rte_hash_del_key(upf_context_by_ip_hash, (const void *)
					&context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr);

			/*store new upf_ip entry */
			data->dstIP =  entry->upf_ip[entry->current_upf].s_addr;
			memcpy(context->eps_bearers[data->ebi_index]->pdn->fqdn, entry->upf_fqdn[entry->current_upf],
					strnlen(entry->upf_fqdn[entry->current_upf], MAX_HOSTNAME_LENGTH));

			context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr =
				entry->upf_ip[entry->current_upf].s_addr;


			/* Assign new upf_ip entry to global variable  holding upf_ip */
			upf_pfcp_sockaddr.sin_addr.s_addr = entry->upf_ip[entry->current_upf].s_addr;


			/*Searching UPF Context for New DNS IP*/
			int ret = 0;
			ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr),
					(void **) &(upf_context));

			if (ret == -ENOENT) {
				/* Add entry of new upf_ip in hash */
				ret = upf_context_entry_add(&entry->upf_ip[entry->current_upf].s_addr, upf_context);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"failed to add entry  %d \n", LOG_VALUE, ret);
					return ;
				}
				/* Send the Association Request to next UPF */
				if (data->portId == PFCP_IFACE) {
					timer_retry_send(pfcp_fd, data, context);
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

					pdn->upf_ipv4.s_addr = upf_pfcp_sockaddr.sin_addr.s_addr;
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

						pdn->upf_ipv4.s_addr = upf_pfcp_sockaddr.sin_addr.s_addr;
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
fill_timer_entry_data(enum source_interface iface, struct sockaddr_in *peer_addr,
		uint8_t *buf, uint16_t buf_len, uint8_t itr, uint32_t teid,  int ebi_index )
{
	peerData *timer_entry = NULL;

	timer_entry = rte_zmalloc_socket(NULL, sizeof(peerData),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"Memory for li_df_config, Error: %s \n", LOG_VALUE,
				rte_strerror(rte_errno));
	}

	timer_entry->portId = (uint8_t)iface;
	timer_entry->dstIP = peer_addr->sin_addr.s_addr;
	timer_entry->dstPort = peer_addr->sin_port;
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
delete_gtpv2c_if_timer_entry(uint32_t teid)
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
add_pfcp_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
		uint8_t *buf, uint16_t buf_len, int ebi_index )
{
	int ret = 0;
	peerData *timer_entry = NULL;
	ue_context *context = NULL;

	ret = get_ue_context(teid, &context);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Ue context for teid: \n", LOG_VALUE, teid);
		return;
	}
	/* fill and add timer entry */
	timer_entry = fill_timer_entry_data(PFCP_IFACE, peer_addr,
			buf, buf_len, pfcp_config.request_tries, teid, ebi_index);

	if(!(add_timer_entry(timer_entry, pfcp_config.request_timeout, timer_callback))) {
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
add_gtpv2c_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
	uint8_t *buf, uint16_t buf_len, int ebi_index , enum source_interface iface,
	uint8_t cp_mode)
{
	int ret = 0;
	peerData *timer_entry = NULL;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;

	/* fill and add timer entry */
	timer_entry = fill_timer_entry_data(iface, peer_addr,
			buf, buf_len, pfcp_config.request_tries, teid, ebi_index);

	if(!(add_timer_entry(timer_entry, pfcp_config.request_timeout, timer_callback))) {
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
