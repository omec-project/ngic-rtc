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

#include "cp.h"
#include "teid.h"
#include "pfcp.h"
#include "li_config.h"
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "debug_str.h"
#include "seid_llist.h"
#include "gw_adapter.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "cp/gtpc_session.h"
#include "pfcp_messages_encoder.h"
#include "cp_timer.h"

#include "cp_app.h"
#include "sm_enum.h"
#include "ipc_api.h"
#include "cp_timer.h"
#include "pfcp_session.h"
#include "csid_struct.h"

extern int gx_app_sock;

#define UPD_PARAM_HEADER_SIZE (4)

extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;
extern socklen_t s11_mme_sockaddr_len;
extern int clSystemLog;
extern int s5s8_fd;
extern int s5s8_fd_v6;
peer_addr_t s5s8_recv_sockaddr;
extern socklen_t s5s8_sockaddr_len;

extern pfcp_config_t config;
extern int clSystemLog;
static uint16_t sequence = 0;

/**
 * @brief  : Fills ip address
 * @param  : ip_addr,
 * @param  : node_addr,
 * @param  : instance,
 * @return : Returns 0 in case of success, -1 otherwise
 */
static void
fill_pgw_rstrt_notif_addr(gtp_ip_address_ie_t *ip_addr,
		node_address_t *node_addr, uint8_t instance) {
	uint8_t header_len = 0;

	if ((node_addr->ip_type == PDN_TYPE_IPV4)
			|| (node_addr->ip_type == IPV4_GLOBAL_UNICAST)) {
		header_len = IPV4_SIZE;
		memcpy(ip_addr->ipv4_ipv6_addr,
				&node_addr->ipv4_addr, IPV4_SIZE);
	} else {
		header_len = IPV6_ADDRESS_LEN;
		memcpy(ip_addr->ipv4_ipv6_addr,
				&node_addr->ipv6_addr, IPV6_ADDRESS_LEN);
	}

	/* Fill the PGW S5/S8 IP Address */
	set_ie_header(&ip_addr->header,
			GTP_IE_IP_ADDRESS, instance, header_len);
}

int8_t
fill_pgw_restart_notification(gtpv2c_header_t *gtpv2c_tx,
		node_address_t *s11_sgw, node_address_t *s5s8_pgw)
{
	/* Encode the PGW Restart Notification request*/
	pgw_rstrt_notif_t pgw_rstrt_notif = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&pgw_rstrt_notif.header,
			GTP_PGW_RESTART_NOTIFICATION, 0, ++sequence, 0);

	fill_pgw_rstrt_notif_addr(&pgw_rstrt_notif.sgw_s11s4_ip_addr_ctl_plane,
			s11_sgw, IE_INSTANCE_ONE);

	if(!(is_present(s5s8_pgw))) {
		fill_pgw_rstrt_notif_addr(
				&pgw_rstrt_notif.pgw_s5s8_ip_addr_ctl_plane_or_pmip,
				s11_sgw, IE_INSTANCE_ZERO);
	} else {
		fill_pgw_rstrt_notif_addr(
				&pgw_rstrt_notif.pgw_s5s8_ip_addr_ctl_plane_or_pmip,
				s5s8_pgw, IE_INSTANCE_ZERO);
	}

	/* Set Cause value */
	set_ie_header(&pgw_rstrt_notif.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			sizeof(struct cause_ie_hdr_t));
	pgw_rstrt_notif.cause.cause_value = GTPV2C_CAUSE_PGW_NOT_RESPONDING;


	encode_pgw_rstrt_notif(&pgw_rstrt_notif, (uint8_t *)gtpv2c_tx);

	return 0;
}

/**
 * @brief  : Fills delete set pdn connection request
 * @param  : gtpv2c_tx, buffer to be filled
 * @param  : local_csids, local csids list
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
fill_gtpc_del_set_pdn_conn_req_t(gtpv2c_header_t *gtpv2c_tx, fqcsid_t *local_csids)
{
	del_pdn_conn_set_req_t del_pdn_conn_req = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&del_pdn_conn_req.header,
			GTP_DELETE_PDN_CONNECTION_SET_REQ, 0, ++sequence, 0);

	if (local_csids->instance == 0) {
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req.mme_fqcsid, IE_INSTANCE_ZERO,
					local_csids);
		}
	} else if (local_csids->instance == 1){
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req.sgw_fqcsid, IE_INSTANCE_ONE,
					local_csids);
		}
	} else if (local_csids->instance == 2) {
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req.pgw_fqcsid, IE_INSTANCE_TWO,
					local_csids);
		}
	}

	/* Encode the del pdn conn set request*/
	encode_del_pdn_conn_set_req(&del_pdn_conn_req, (uint8_t *)gtpv2c_tx);

	return 0;
}

/**
 * @brief  : Match peer node address
 * @param  : num_node_addr, node addr count.
 * @param  : peer_node_addr,
 * @param  : peer_node_addrs,
 * @return : Returns 0 in case of match not found, 1 otherwise
 */
static int
match_node_addr(uint8_t num_node_addr, node_address_t *peer_node_addr,
				node_address_t *peer_node_addrs) {
	int match = 0;
	node_address_t ip_addr = {0}, ip_addrs = {0};

	memcpy(&ip_addr, peer_node_addr, sizeof(node_address_t));

	for (uint8_t itr = 0; itr < num_node_addr; itr++) {
		memcpy(&ip_addrs, &peer_node_addrs[itr], sizeof(node_address_t));
		if ((COMPARE_IP_ADDRESS(ip_addr, ip_addrs)) == 0) {
			match = 1;
			break;
		}
	}

	return match;
}

/**
 * @brief  : Fills delete set pdn connection request
 * @param  : del_pdn_conn_req, buffer to be filled
 * @param  : local_csids, local csids list
 * @param  : cp_ip,
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
fill_gtpc_del_set_pdn_conn_req(del_pdn_conn_set_req_t *del_pdn_conn_req, fqcsid_t *local_csids,
		node_address_t *cp_ip)
{

	set_gtpv2c_teid_header((gtpv2c_header_t *)&del_pdn_conn_req->header,
			GTP_DELETE_PDN_CONNECTION_SET_REQ, 0, ++sequence, 0);

	int cnd = ((cp_ip->ip_type == PDN_TYPE_IPV4) ?
			memcmp(&cp_ip->ipv4_addr, &config.s5s8_ip.s_addr, IPV4_SIZE) :
			memcmp(&cp_ip->ipv6_addr, &config.s5s8_ip_v6.s6_addr, IPV6_SIZE));

	/* Set the SGW FQ-CSID */
	if ((is_present(cp_ip) == 0) || (cnd != 0)) {
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req->sgw_fqcsid, IE_INSTANCE_ONE,
					local_csids);
		}
	} else {
		/* Set the PGW FQ-CSID */
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req->pgw_fqcsid, IE_INSTANCE_TWO,
					local_csids);
		}
	}

	return 0;
}

uint32_t s5s8_node_addr = 0;

/**
 * @brief  : Fill ccr request
 * @param  : pdc, pdn connection details
 * @param  : ebi_index
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
fill_ccr_t_request(pdn_connection *pdn, uint8_t ebi_index)
{
	int ret = 0;
	uint16_t msglen = 0;
	uint8_t *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN Gx "
			"HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
		return -1;
	}

	/* Set the Msg header type for CCR-T */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = TERMINATION_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = TERMINATION ;

	/* Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context, ebi_index, pdn->gx_sess_id,0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed CCR request filling process\n", LOG_VALUE);
		return -1;
	}
	/* Update UE State */
	pdn->state = CCR_SNT_STATE;

	/* Set the Gx State for events */
	gx_context->state = CCR_SNT_STATE;
	gx_context->proc = pdn->proc;

	/* Calculate the max size of CCR msg to allocate the buffer */
	msglen = gx_ccr_calc_length(&ccr_request.data.ccr);
	ccr_request.msg_len = msglen + GX_HEADER_LEN;

	buffer = rte_zmalloc_socket(NULL, msglen + GX_HEADER_LEN,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Failure to allocate CCR-T Buffer memory"
				"structure, Error : %s\n", LOG_VALUE, rte_strerror(rte_errno));
		return -1;
	}

	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
	memcpy(buffer + sizeof(ccr_request.msg_type),
							&ccr_request.msg_len,
					sizeof(ccr_request.msg_len));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + GX_HEADER_LEN), msglen) == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"ERROR in Packing CCR Buffer\n", LOG_VALUE);
		rte_free(buffer);
		return -1;
	}

	/* Write or Send CCR -T msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer, msglen + GX_HEADER_LEN);
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Sent CCR-T to PCRF \n", LOG_VALUE);

	free_dynamically_alloc_memory(&ccr_request);

	update_cli_stats((peer_address_t *) &config.gx_ip, OSS_CCR_TERMINATE, SENT, GX);

	rte_free(buffer);

	return 0;
}


/**
 * @brief  : Delete pdr entries
 * @param  : bearer, bearer information
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
flush_pdr_entries(eps_bearer *bearer)
{
	for (uint8_t itr = 0; itr < bearer->pdr_count; itr++) {
		if (NULL == bearer->pdrs[itr])
			continue;

		if (del_pdr_entry((bearer->pdrs[itr])->rule_id)) {
			return -1;
		}
	}

	for (uint8_t itr1 = 0; itr1 < bearer->qer_count; itr1++) {
		if (del_qer_entry(bearer->qer_id[itr1].qer_id)) {
			return -1;
		}
	}
	return 0;
}

/**
 * @brief  : Delete session entry using csid
 * @param  : pdn, Structure to store PDN context
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
del_sess_by_csid_entry(pdn_connection *pdn)
{
	int ret = 0;
	int8_t ebi_index = GET_EBI_INDEX(pdn->default_bearer_id);
	if ((config.use_gx) && ((pdn->context)->cp_mode != SGWC)) {
		fill_ccr_t_request(pdn, ebi_index);

		gx_context_t *gx_context = NULL;

		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
				(const void*)(pdn->gx_sess_id), (void **)&gx_context);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NO ENTRY FOUND IN "
					"Gx HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
		} else {
			/* Deleting PDN hash map with GX call id */
			rte_hash_del_key(pdn_conn_hash, (const void *) &pdn->call_id);
			/* Delete UE context entry from IMSI Hash */
			if (rte_hash_del_key(gx_context_by_sess_id_hash, &pdn->gx_sess_id) < 0) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error on "
						"Deleting GX context Key entry from Hash\n",
						LOG_VALUE);
			}

			if (gx_context != NULL) {
				rte_free(gx_context);
				gx_context = NULL;
			}
		}
	}

	for (uint8_t ebi_index = 0; ebi_index < MAX_BEARERS; ebi_index++) {

		eps_bearer *bearer = pdn->eps_bearers[ebi_index];
		if (bearer == NULL)
			continue;

		if (flush_pdr_entries(bearer)) {
			/* TODO: Error Handling */
			return -1;
		}
		rte_free(pdn->eps_bearers[ebi_index]);
		pdn->eps_bearers[ebi_index] = NULL;
	}

	rte_free(pdn);
	pdn = NULL;

	return 0;
}

/**
 * @brief  : Delete csid using csid entry
 * @param  : peer_fqcsid
 * @param  : local_fqcsid
 * @param  : iface
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_csid_by_csid_entry(sess_fqcsid_t *peer_fqcsid, fqcsid_t *local_fqcsid, uint8_t iface)
{

	for (uint8_t itr = 0; itr < peer_fqcsid->num_csid; itr++) {
		csid_t *local_csids = NULL;
		csid_key_t key_t = {0};

		key_t.local_csid = peer_fqcsid->local_csid[itr];
		memcpy(&key_t.node_addr, &peer_fqcsid->node_addr[itr],
					sizeof(node_address_t));

		local_csids = get_peer_csid_entry(&key_t, iface, REMOVE_NODE);
		if (local_csids == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
				"entry while cleanup CSID by CSID entry, Error : %s \n", LOG_VALUE,
				strerror(errno));
			return -1;
		}

		for (uint8_t itr1 = 0; itr1 < local_csids->num_csid; itr1++) {
			for (uint8_t itr2 = 0; itr2 < local_fqcsid->num_csid; itr2++) {
				if (local_fqcsid->local_csid[itr2] == local_csids->local_csid[itr1]) {
					for(uint8_t pos = itr1; pos < (local_csids->num_csid - 1); pos++ ) {
						local_csids->local_csid[pos] = local_csids->local_csid[pos + 1];
					}
					if (local_csids->num_csid)
						local_csids->num_csid--;
				}
			}
		}

		if (!local_csids->num_csid) {
			if (del_peer_csid_entry(&key_t, iface)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete CSID "
					"entry while cleanup CSID by CSID entry, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
		}
	}

	return 0;
}

/**
 * @brief  : Send gtpc pgw restart notification.
 * @param  : csids, Conten list of local csid.
 * @param  : iface,
 * @return : void
 */
static void
send_gtpc_pgw_restart_notification(fqcsid_t *csids, uint8_t iface)
{
	uint8_t num_mme_node_addr = 0;
	uint8_t num_pgw_node_addr = 0;
	uint8_t tmp_cnt = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	int ret = 0;
	uint16_t payload_length = 0;
	uint32_t teid_key = 0;
	node_address_t mme_node_addrs[MAX_CSID] = {0};
	node_address_t pgw_node_addrs[MAX_CSID] = {0};
	node_address_t local_node_addr = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_csid *tmp = NULL;
	sess_csid *current = NULL;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));

	for (uint8_t itr = 0; itr < csids->num_csid; itr++) {
		tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					csids->local_csid[itr]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL) {
			teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get UE context for teid : %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get PDN context for seid : %u \n",
						LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			if (is_present(&pdn->mme_csid.node_addr)) {
				if ((match_node_addr(num_mme_node_addr,
								&pdn->mme_csid.node_addr, mme_node_addrs)) == 0) {
					fill_peer_info(&mme_node_addrs[num_mme_node_addr++],
							&pdn->mme_csid.node_addr);
				}
			}

			if ((context->cp_mode != SAEGWC) && (is_present(&pdn->s5s8_pgw_gtpc_ip))) {
					if ((match_node_addr(num_pgw_node_addr,
									&pdn->s5s8_pgw_gtpc_ip, pgw_node_addrs)) == 0) {
						fill_peer_info(&pgw_node_addrs[num_pgw_node_addr++],
									&pdn->s5s8_pgw_gtpc_ip);
					}
			}
			/* Assign Next node address */
			tmp = current->next;

			current = tmp;
			break;
		}
	}

	/* If SGWU failure detect, SGWC should not send PGW restart notfication to MME
	 * If SX failure detect and PGW node addr found, i.e peer node is SGWU */
	if(iface == SX_PORT_ID) {
		if((num_pgw_node_addr != 0)
				&& (is_present(&pgw_node_addrs[num_pgw_node_addr - 1])))
			return;
	}

	for (uint8_t itr1 = 0; itr1 < num_mme_node_addr; itr1++) {
		/* one pgw/sgw/saewc might be connected with more than one mme */
		if (mme_node_addrs[itr1].ip_type == PDN_TYPE_IPV4) {
				local_node_addr.ip_type = PDN_TYPE_IPV4;
				local_node_addr.ipv4_addr = config.s11_ip.s_addr;
		} else {
				local_node_addr.ip_type = PDN_TYPE_IPV6;
				memcpy(local_node_addr.ipv6_addr,
						config.s11_ip_v6.s6_addr, IPV6_ADDRESS_LEN);
		}

		/* Fill the PGW restart notification request */
		fill_pgw_restart_notification(gtpv2c_tx, &local_node_addr,
				&pgw_node_addrs[tmp_cnt]);

		ret = set_dest_address(mme_node_addrs[itr1], &s11_mme_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		/* Send the Delete PDN Request to peer node */
		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);
		gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
				s11_mme_sockaddr, SENT);

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Send PGW Restart notification to MME \n",
				LOG_VALUE);
		memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
	}
}

/**
 * @brief  : Cleanup fqcsid entry from UE context
 * @param  : pdn, Structure for store PDN Connection context
 * @return : Returns void
 */
static void
cleanup_sess_csid_entry(pdn_connection *pdn)
{
	ue_context *context = NULL;

	context = pdn->context;

	if (context->mme_fqcsid != NULL) {
		if ((context->mme_fqcsid)->num_csid) {

			remove_csid_from_cntx(context->mme_fqcsid, &pdn->mme_csid);

			if ((context->mme_fqcsid)->num_csid == 0)
			{
				if ((context->mme_fqcsid != NULL) && ((context->mme_fqcsid)->num_csid)) {
					rte_free(context->mme_fqcsid);
				}
				context->mme_fqcsid = NULL;
			}
		}
	}

	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {

			remove_csid_from_cntx(context->sgw_fqcsid, &pdn->sgw_csid);

			if ((context->sgw_fqcsid)->num_csid == 0)
			{
				if ((context->sgw_fqcsid != NULL) && ((context->sgw_fqcsid)->num_csid)) {
					rte_free(context->sgw_fqcsid);
				}
				context->sgw_fqcsid = NULL;
			}
		}
	}

	if (context->pgw_fqcsid != NULL) {
		if ((context->pgw_fqcsid)->num_csid) {

			remove_csid_from_cntx(context->pgw_fqcsid, &pdn->pgw_csid);

			if ((context->pgw_fqcsid)->num_csid == 0)
			{
				if ((context->pgw_fqcsid != NULL) && ((context->pgw_fqcsid)->num_csid)) {
					rte_free(context->pgw_fqcsid);
				}
				context->pgw_fqcsid = NULL;
			}
		}
	}

	if (context->up_fqcsid != NULL) {
		if ((context->up_fqcsid)->num_csid) {

			remove_csid_from_cntx(context->up_fqcsid, &pdn->up_csid);

			if ((context->up_fqcsid)->num_csid == 0)
			{
				if ((context->up_fqcsid != NULL) && ((context->up_fqcsid)->num_csid)) {
					rte_free(context->up_fqcsid);
				}
				context->up_fqcsid = NULL;
			}
		}
	}
	return;
}

/**
 * @brief  : Match sess. fqcsid and add.
 * @param  : fqcsids, conten list of peer node csid and address's.
 * @param  : fqcsid, conten list of csid and address.
 * @return : Returns void.
 */
static void
match_and_add_sess_fqcsid_t(sess_fqcsid_t *fqcsids, fqcsid_t *fqcsid)
{
	uint8_t match = 0;
	for (uint8_t itr = 0; itr < fqcsid->num_csid; itr++) {
		for (uint8_t itr1 = 0; itr1 < fqcsids->num_csid; itr1++) {
			if((fqcsids->local_csid[itr1] == fqcsid->local_csid[itr])
					&& (COMPARE_IP_ADDRESS(fqcsids->node_addr[itr1], fqcsid->node_addr)) == 0){
				match = 1;
				break;
			}
		}
		if (match == 0) {
			if ((fqcsid->node_addr.ip_type == IPV4_GLOBAL_UNICAST)
					|| (fqcsid->node_addr.ip_type == PDN_TYPE_IPV4)) {
				fqcsids->node_addr[(fqcsids->num_csid)].ip_type =
					PDN_TYPE_IPV4;
				fqcsids->node_addr[(fqcsids->num_csid)].ipv4_addr =
					fqcsid->node_addr.ipv4_addr;
			} else {
				fqcsids->node_addr[(fqcsids->num_csid)].ip_type =
					PDN_TYPE_IPV6;
				memcpy(fqcsids->node_addr[(fqcsids->num_csid)].ipv6_addr,
						fqcsid->node_addr.ipv6_addr, IPV6_ADDRESS_LEN);
			}
			fqcsids->local_csid[(fqcsids->num_csid++)] = fqcsid->local_csid[itr];
		}
	}
}

/**
 * @brief  : Match peer node address's and add.
 * @param  : peer_node_addr, node address.
 * @param  : peer_node_addrs, conten list of peer node address.
 * @return : Returns void.
 */
static void
match_and_add_peer_node_addr(node_address_t *peer_node_addr,
			node_addr_t *peer_node_addrs)
{
	uint8_t match = 0;
	node_address_t peer_ip = {0};

	memcpy(&peer_ip, peer_node_addr, sizeof(node_address_t));

	for (uint8_t itr = 0; itr < peer_node_addrs->num_addr; itr++) {
		if((COMPARE_IP_ADDRESS(peer_node_addrs->node_addr[itr], peer_ip)) == 0){
			match = 1;
			break;
		}
	}
	if (match == 0) {
		if ((peer_ip.ip_type == IPV4_GLOBAL_UNICAST)
				|| (peer_ip.ip_type == PDN_TYPE_IPV4)) {
			peer_node_addrs->node_addr[peer_node_addrs->num_addr].ip_type =
					PDN_TYPE_IPV4;
			peer_node_addrs->node_addr[peer_node_addrs->num_addr++].ipv4_addr =
					peer_ip.ipv4_addr;
		} else {
			peer_node_addrs->node_addr[peer_node_addrs->num_addr].ip_type =
					PDN_TYPE_IPV6;
			memcpy(&peer_node_addrs->node_addr[peer_node_addrs->num_addr++].ipv6_addr,
					&peer_ip.ipv6_addr, IPV6_ADDRESS_LEN);
		}
	}
}

/**
 * @brief  : Cleanup peer node address entry for fqcsid IE address.
 * @param  : key, key of the hash.
 * @param  : iface, .
 * @return : In success return 0, otherwise -1.
 */
static int
cleanup_peer_node_addr_entry(peer_node_addr_key_t *key, uint8_t iface) {

	fqcsid_ie_node_addr_t *tmp;
	fqcsid_t *peer_csids = NULL;

	tmp = get_peer_node_addr_entry(key, REMOVE_NODE);
	if (tmp == NULL) {
		(key->peer_node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Entry not found for Peer Node IPv6 Addr : "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(key->peer_node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Entry not found for Peer Node Addr : "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(key->peer_node_addr.ipv4_addr));
		return -1;
	}
	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(&tmp->fqcsid_node_addr, UPDATE_NODE);
	if (peer_csids == NULL) {
		(tmp->fqcsid_node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(tmp->fqcsid_node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(tmp->fqcsid_node_addr.ipv4_addr));
		del_peer_node_addr_entry(key);
		return 0;
	}
	/* Get the mapped Session */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		peer_csid_key_t key_t = {0};
		sess_csid *tmp = NULL;

		key_t.iface = iface;
		key_t.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key_t.peer_node_addr, &peer_csids->node_addr,
					sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key_t, REMOVE_NODE);
		if (tmp == NULL) {
				del_peer_node_addr_entry(key);
				return 0;
		}
	}

	return 0;
}

/**
 * @brief  : Cleanup session using csid entry
 * @param  : csids
 * @param  : iface
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_sess_by_csid_entry(fqcsid_t *csids, uint8_t iface)
{
	int ret = 0;
	uint8_t cp_mode = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	uint32_t teid_key = 0;
	node_addr_t mme_node_addr = {0};
	node_addr_t sgw_node_addr = {0};
	node_addr_t pgw_node_addr = {0};
	node_addr_t up_node_addr = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_fqcsid_t mme_csids = {0};
	sess_fqcsid_t up_csids = {0};
	sess_fqcsid_t tmp1 = {0};

	/* Get the session ID by csid */
	for (uint8_t itr1 = 0; itr1 < csids->num_csid; itr1++) {
		sess_csid *tmp_t = NULL;
		sess_csid *current = NULL;

		tmp_t = get_sess_csid_entry(csids->local_csid[itr1], REMOVE_NODE);
		if (tmp_t == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					csids->local_csid[itr1]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp_t->cp_seid == 0) && (tmp_t->next == 0)) {
			continue;
		}

		current = tmp_t;
		while (current != NULL ) {
			sess_csid *tmp = NULL;
			teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			    (const void *) &teid_key,
			    (void **) &context);

			if ((ret < 0) || (context == NULL)) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get UE context for teid : %u, Error: %s \n", LOG_VALUE,
					teid_key, strerror(errno));
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			delete_ddn_timer_entry(timer_by_teid_hash, teid_key, ddn_by_seid_hash);
			delete_ddn_timer_entry(dl_timer_by_teid_hash, teid_key, pfcp_rep_by_seid_hash);

			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get PDn Connection context for EBI index: %d, Error: %s \n",
					LOG_VALUE, ebi_index, strerror(errno));
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			/*Copying CP mode type */
			 cp_mode = context->cp_mode;

			 /* MME FQ-CSID */
			 if(pdn->mme_csid.num_csid != 0) {
				match_and_add_sess_fqcsid_t(&mme_csids, &pdn->mme_csid);
			 }

			 /* SGWC FQ-CSID */
			 if(PGWC == context->cp_mode && (pdn->sgw_csid.num_csid)) {
				 match_and_add_sess_fqcsid_t(&tmp1, &pdn->sgw_csid);
			 }

			 /* PGWC FQ-CSID */
			 if(SGWC == context->cp_mode && (pdn->pgw_csid.num_csid)) {
				 match_and_add_sess_fqcsid_t(&tmp1, &pdn->pgw_csid);
			 }

			 if (SX_PORT_ID != iface) {
				 /* UP FQ-CSID */
				 if(pdn->up_csid.num_csid) {
					 match_and_add_sess_fqcsid_t(&up_csids, &pdn->up_csid);
				 }
			 }

			cleanup_sess_csid_entry(pdn);

			/* peer mode address */
			if (context->cp_mode != PGWC) {
				/* MME S11 IP */
				match_and_add_peer_node_addr(&context->s11_mme_gtpc_ip,
						&mme_node_addr);
				/* UP SX IP */
				match_and_add_peer_node_addr(&pdn->upf_ip,
						 &up_node_addr);

				/* PGWC S5S8 IP */
				if (is_present(&pdn->s5s8_pgw_gtpc_ip)) {
					match_and_add_peer_node_addr(&pdn->s5s8_pgw_gtpc_ip,
							&pgw_node_addr);
				}
			} else {
				/* SGWC S5S8 IP */
				match_and_add_peer_node_addr(&pdn->s5s8_pgw_gtpc_ip,
						&sgw_node_addr);
				/* UP SX IP */
				match_and_add_peer_node_addr(&pdn->upf_ip,
						 &up_node_addr);
			}
			/* Delete UE session entry from UE Hash */
			if (del_sess_by_csid_entry(pdn)) {
				/* TODO Handle Error */
			}

			context->num_pdns--;
			if (context->num_pdns == 0) {
				/* Delete UE context entry from IMSI Hash */
				if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
							"Deleting UE context entry from IMSI Hash\n",
							LOG_VALUE);
				}

				if (context != NULL) {
					rte_free(context);
					context = NULL;
				}

				/* Delete UE context entry from UE Hash */
				if (rte_hash_del_key(ue_context_by_fteid_hash, &teid_key) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
							"Deleting UE context entry from UE Hash\n", LOG_VALUE);
				}

			}

			update_sys_stat(number_of_users, DECREMENT);
			update_sys_stat(number_of_active_session, DECREMENT);

			/* Assign Next node address */
			tmp = current->next;

			/* free csid linked list node */
			if(current != NULL) {
				rte_free(current);
				current = NULL;
			}

			current = tmp;
		}
		/* Update CSID Entry in table */
	   ret = rte_hash_add_key_data(seids_by_csid_hash,
				&csids->local_csid[itr1], current);
		if (ret) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to update Session IDs entry for CSID = %u"
					"\n\tError= %s\n",
					LOG_VALUE, csids->local_csid[itr1],
					rte_strerror(abs(ret)));
		}
	}

	/* Cleanup MME FQ-CSID */
	if(mme_csids.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&mme_csids, csids,
					((cp_mode == PGWC)? S5S8_PGWC_PORT_ID : S11_SGW_PORT_ID)) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
				"Deleting MME FQ-CSID entry\n", LOG_VALUE);
			return -1;
		}
	}

	/* Cleanup SGWC or PGWC FQ-CSID */
	if(tmp1.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&tmp1, csids,
					((cp_mode == SGWC) ? S5S8_SGWC_PORT_ID : S5S8_PGWC_PORT_ID)) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
				"Deleting FQ-CSID entry\n", LOG_VALUE);
			return -1;
		}
	}

	/* Cleanup UP FQ-CSID */
	if (SX_PORT_ID != iface) {
		if(up_csids.num_csid != 0) {
			if(cleanup_csid_by_csid_entry(&up_csids, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
				"Deleting UP FQ-CSID entry\n", LOG_VALUE);
				return -1;
			}
		}
	}

	peer_node_addr_key_t key = {0};
	/* MME */
	for (uint8_t itr = 0; itr < mme_node_addr.num_addr; itr++) {
		key.iface = S11_SGW_PORT_ID;
		memcpy(&key.peer_node_addr,
				&mme_node_addr.node_addr[itr], sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key, S11_SGW_PORT_ID);
	}
	/* UP */
	for (uint8_t itr = 0; itr < up_node_addr.num_addr; itr++) {
		key.iface = SX_PORT_ID;
		memcpy(&key.peer_node_addr, &up_node_addr.node_addr[itr],
				sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key, SX_PORT_ID);
	}
	/* PGWC */
	for (uint8_t itr = 0; itr < pgw_node_addr.num_addr; itr++) {
		key.iface = S5S8_SGWC_PORT_ID;
		memcpy(&key.peer_node_addr,
				&pgw_node_addr.node_addr[itr], sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key, S5S8_SGWC_PORT_ID);
	}
	/* SGWC */
	for (uint8_t itr = 0; itr < sgw_node_addr.num_addr; itr++) {
		key.iface = S5S8_SGWC_PORT_ID;
		memcpy(&key.peer_node_addr,
				&sgw_node_addr.node_addr[itr], sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key, S5S8_SGWC_PORT_ID);
	}
	return 0;
}


/**
 * @brief  : Cleanup session using Peer csid entry
 * @param  :  Peer csids
 * @param  : iface
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_sess_by_peer_csid_entry(fqcsid_t *peer_csids, uint8_t iface)
{
	int ret = 0;
	int8_t ebi = 0;
	uint8_t num_csid = 0;
	int8_t ebi_index = 0;
	uint32_t teid_key = 0;
	fqcsid_t csid = {0};
	peer_csid_key_t key = {0};
	peer_node_addr_key_t key_t = {0};
	node_addr_t mme_node_addr = {0};
	node_addr_t sgw_node_addr = {0};
	node_addr_t pgw_node_addr = {0};
	node_addr_t up_node_addr = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;

	/* Get the session ID by csid */
	for (uint8_t itr1 = 0; itr1 < peer_csids->num_csid; itr1++) {
		sess_csid *tmp = NULL;
		sess_csid *current = NULL;

		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr1];
		memcpy(&key.peer_node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					peer_csids->local_csid[itr1]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			teid_key = UE_SESS_ID(current->cp_seid);
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"Initiate Cleanup for teid : 0x%x \n",
				LOG_VALUE, teid_key);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			    (const void *) &teid_key,
			    (void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"ERROR : Failed to get UE context for teid : %u \n",
					LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			delete_ddn_timer_entry(timer_by_teid_hash, teid_key, ddn_by_seid_hash);
			delete_ddn_timer_entry(dl_timer_by_teid_hash, teid_key, pfcp_rep_by_seid_hash);

			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"ERROR : Failed to get PDN context for seid : %u \n",
					LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				/* free csid linked list node */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}
			sess_csid *head = NULL;
			/* Delete Session for peer CSID hash */
			if ((pdn->mme_csid.num_csid) &&
					(COMPARE_IP_ADDRESS(peer_csids->node_addr, pdn->mme_csid.node_addr) != 0)) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from MME CSID Link List \n", LOG_VALUE);
				/* Remove the session link from MME CSID */
				key.iface = ((context->cp_mode != PGWC) ? S11_SGW_PORT_ID : S5S8_PGWC_PORT_ID);
				key.peer_local_csid = pdn->mme_csid.local_csid[num_csid];
				memcpy(&key.peer_node_addr, &pdn->mme_csid.node_addr, sizeof(node_address_t));

				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, pdn->seid, &key);
			}

			if ((pdn->up_csid.num_csid) &&
					(COMPARE_IP_ADDRESS(peer_csids->node_addr, pdn->up_csid.node_addr) != 0)) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from DP CSID Link List \n", LOG_VALUE);
				/* Remove the session link from UP CSID */
				key.iface = SX_PORT_ID;
				key.peer_local_csid = pdn->up_csid.local_csid[num_csid];
				memcpy(&key.peer_node_addr, &pdn->up_csid.node_addr, sizeof(node_address_t));
				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, pdn->seid, &key);
			}

			if ((pdn->pgw_csid.num_csid) && (context->cp_mode == SGWC)
					&& (COMPARE_IP_ADDRESS(peer_csids->node_addr, pdn->pgw_csid.node_addr) != 0)) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from PGWC CSID Link List \n", LOG_VALUE);
				/* Remove the session link from UP CSID */
				key.iface = S5S8_SGWC_PORT_ID;
				key.peer_local_csid = pdn->pgw_csid.local_csid[num_csid];
				memcpy(&key.peer_node_addr, &pdn->pgw_csid.node_addr, sizeof(node_address_t));
				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, pdn->seid, &key);
			}
			if ((pdn->sgw_csid.num_csid) && (context->cp_mode == PGWC)
					&& (COMPARE_IP_ADDRESS(peer_csids->node_addr, pdn->sgw_csid.node_addr) != 0)) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from SGWC CSID Link List \n", LOG_VALUE);
				/* Remove the session link from UP CSID */
				key.iface = S5S8_PGWC_PORT_ID;
				key.peer_local_csid = pdn->sgw_csid.local_csid[num_csid];
				memcpy(&key.peer_node_addr, &pdn->sgw_csid.node_addr, sizeof(node_address_t));
				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, pdn->seid, &key);
			}
			/* Retriving local csid from pdn */
			if (context->cp_mode != PGWC) {
				csid.local_csid[num_csid] = pdn->sgw_csid.local_csid[num_csid];
				memcpy(&csid.node_addr, &pdn->sgw_csid.node_addr, sizeof(node_address_t));
				csid.num_csid = pdn->sgw_csid.num_csid;
			} else {
				csid.local_csid[num_csid] = pdn->pgw_csid.local_csid[num_csid];
				memcpy(&csid.node_addr, &pdn->pgw_csid.node_addr, sizeof(node_address_t));
				csid.num_csid = pdn->pgw_csid.num_csid;
			}
			 /* Remove session link from local CSID */
			 for (uint8_t itr = 0; itr < csid.num_csid; ++itr) {
				 sess_csid *tmp1 = NULL;
				 tmp1 = get_sess_csid_entry(csid.local_csid[itr], REMOVE_NODE);

				 if (tmp1 != NULL) {
					 /* Remove node from csid linked list */
					 tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

					 int8_t ret = 0;
					 /* Update CSID Entry in table */
					 ret = rte_hash_add_key_data(seids_by_csid_hash,
							 &csid.local_csid[itr], tmp1);
					 if (ret) {
						 clLog(clSystemLog, eCLSeverityCritical,
								 LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
								 "\n\tError= %s\n",
								 LOG_VALUE, csid.local_csid[itr]);
					 }
					 if (tmp1 == NULL) {
						 /* MME FQ-CSID */
						 if(pdn->mme_csid.num_csid != 0) {
							 del_csid_entry_hash(&pdn->mme_csid, &csid,
									 ((context->cp_mode == PGWC)? S5S8_PGWC_PORT_ID : S11_SGW_PORT_ID));
						 }

						 /* SGWC FQ-CSID */
						 if(PGWC == context->cp_mode && (pdn->sgw_csid.num_csid)) {
							 del_csid_entry_hash(&pdn->sgw_csid, &csid, S5S8_PGWC_PORT_ID);
						 }

						 /* PGWC FQ-CSID */
						 if(SGWC == context->cp_mode && (pdn->pgw_csid.num_csid)) {
							 del_csid_entry_hash(&pdn->pgw_csid, &csid,  S5S8_SGWC_PORT_ID);
						 }

						 if (SX_PORT_ID != iface) {
							 /* UP FQ-CSID */
							 if(pdn->up_csid.num_csid) {
								 del_csid_entry_hash(&pdn->up_csid, &csid, SX_PORT_ID);
							 }
						 }
						 del_sess_csid_entry(csid.local_csid[itr]);
					 }
				 }
			 }
			cleanup_sess_csid_entry(pdn);
			/* peer mode address */
			if (context->cp_mode != PGWC) {
				/* MME S11 IP */
				match_and_add_peer_node_addr(&context->s11_mme_gtpc_ip,
						&mme_node_addr);
				/* UP SX IP */
				match_and_add_peer_node_addr(&pdn->upf_ip,
						 &up_node_addr);

				/* PGWC S5S8 IP */
				if (is_present(&pdn->s5s8_pgw_gtpc_ip)) {
					match_and_add_peer_node_addr(&pdn->s5s8_pgw_gtpc_ip,
							&pgw_node_addr);
				}
			} else {
				/* SGWC S5S8 IP */
				match_and_add_peer_node_addr(&pdn->s5s8_pgw_gtpc_ip,
						&sgw_node_addr);
				/* UP SX IP */
				match_and_add_peer_node_addr(&pdn->upf_ip,
						 &up_node_addr);
			}

			/* Delete UE session entry from UE Hash */
			if (del_sess_by_csid_entry(pdn)) {
				/* TODO Handle Error */
			}

			context->num_pdns--;
			if (context->num_pdns == 0) {
				/* Delete UE context entry from IMSI Hash */
				if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
							"Deleting UE context entry from IMSI Hash\n",
							LOG_VALUE);
				}

				if (context != NULL) {
					rte_free(context);
					context = NULL;
				}

				/* Delete UE context entry from UE Hash */
				if (rte_hash_del_key(ue_context_by_fteid_hash, &teid_key) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
							"Deleting UE context entry from UE Hash\n", LOG_VALUE);
				}
			}

			update_sys_stat(number_of_users, DECREMENT);
			update_sys_stat(number_of_active_session, DECREMENT);

			/* Assign Next node address */
			tmp = current->next;

			/* free csid linked list node */
			if(current != NULL) {
				rte_free(current);
				current = NULL;
			}

			current = tmp;
		}
		/* Adding the null entry in the hash */
		rte_hash_add_key_data(seid_by_peer_csid_hash, &key, tmp);
	}

	/* Delete Peer CSID entry */
	for (uint8_t itr = 0; itr < peer_csids->num_csid; ++itr) {
		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key.peer_node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		if (del_sess_peer_csid_entry(&key) < 0) {
			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error on "
				"Deleting peer CSID entry\n", LOG_VALUE);
		}
	}

	/* MME */
	for (uint8_t itr = 0; itr < mme_node_addr.num_addr; itr++) {
		key_t.iface = S11_SGW_PORT_ID;
		memcpy(&key_t.peer_node_addr, &mme_node_addr.node_addr[itr],
				sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key_t, S11_SGW_PORT_ID);
	}
	/* UP */
	for (uint8_t itr = 0; itr < up_node_addr.num_addr; itr++) {
		key_t.iface = SX_PORT_ID;
		memcpy(&key_t.peer_node_addr, &up_node_addr.node_addr[itr],
				sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key_t, SX_PORT_ID);
	}
	/* PGWC */
	for (uint8_t itr = 0; itr < pgw_node_addr.num_addr; itr++) {
		key_t.iface = S5S8_SGWC_PORT_ID;
		memcpy(&key_t.peer_node_addr, &pgw_node_addr.node_addr[itr],
				sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key_t, S5S8_SGWC_PORT_ID);
	}
	/* SGWC */
	for (uint8_t itr = 0; itr < sgw_node_addr.num_addr; itr++) {
		key_t.iface = S5S8_SGWC_PORT_ID;
		memcpy(&key_t.peer_node_addr, &sgw_node_addr.node_addr[itr],
				sizeof(node_address_t));
		/* cleanup Peer node address entry */
		cleanup_peer_node_addr_entry(&key_t, S5S8_SGWC_PORT_ID);
	}

	return 0;
}

/**
 * @brief  : Send del PDN con. set req. to peer node's
 * @param  : csids, Cotent local csid list.
 * @param  : ifacce,
 * @return : Returns 0 in case of success,
 */
static int8_t
send_delete_pdn_con_set_req(fqcsid_t *csids, uint8_t iface)
{
	uint8_t num_mme_node_addr = 0;
	uint8_t num_sgw_node_addr = 0;
	uint8_t num_pgw_node_addr = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	uint8_t tmp_cnt = 0;
	int ret = 0;
	uint16_t payload_length = 0;
	uint32_t teid_key = 0;
	node_address_t mme_node_addrs[MAX_CSID] = {0};
	node_address_t pgw_node_addrs[MAX_CSID] = {0};
	node_address_t sgw_node_addrs[MAX_CSID] = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_csid *tmp = NULL;
	sess_csid *current = NULL;

	del_pdn_conn_set_req_t del_pdn_conn_req = {0};

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));

	for (uint8_t itr = 0; itr < csids->num_csid; itr++) {
		tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					csids->local_csid[itr]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get UE context for teid : %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get PDN context for seid : %u \n",
						LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			if (is_present(&pdn->mme_csid.node_addr)) {
				if ((match_node_addr(num_mme_node_addr, &pdn->mme_csid.node_addr,
								mme_node_addrs)) == 0)
				{
					fill_peer_info(&mme_node_addrs[num_mme_node_addr++],
									&pdn->mme_csid.node_addr);
				}
			}

			if (context->cp_mode != PGWC) {
				if (is_present(&pdn->sgw_csid.node_addr)) {
					if ((match_node_addr(num_sgw_node_addr, &pdn->sgw_csid.node_addr,
									sgw_node_addrs)) == 0)
					{
						fill_peer_info(&sgw_node_addrs[num_sgw_node_addr++],
									&pdn->sgw_csid.node_addr);
					}
				}

			} else {
				if (is_present(&pdn->sgw_csid.node_addr)) {
					if ((match_node_addr(num_sgw_node_addr, &pdn->s5s8_sgw_gtpc_ip,
									sgw_node_addrs)) == 0)
					{
						fill_peer_info(&sgw_node_addrs[num_sgw_node_addr++],
									&pdn->s5s8_sgw_gtpc_ip);
					}
				}
			}

			if (is_present(&pdn->pgw_csid.node_addr)) {
				if ((match_node_addr(num_pgw_node_addr, &pdn->pgw_csid.node_addr,
								pgw_node_addrs)) == 0) {
					fill_peer_info(&pgw_node_addrs[num_pgw_node_addr++],
								&pdn->pgw_csid.node_addr);
				}
			}
			/* Assign Next node address */
			tmp = current->next;

			current = tmp;
			break;
		}
	}
	/* if pgw_node_addr is not match with config s5s8 ip,  i.e cp type is SGWC
	 * if pgw_node_addr is set to zero , i.e cp type is SAEGWC */
	/* Fill the Delete PDN Request */
	fill_gtpc_del_set_pdn_conn_req(&del_pdn_conn_req, csids, &pgw_node_addrs[tmp_cnt]);

	int cnd = (((pgw_node_addrs[tmp_cnt].ip_type == PDN_TYPE_IPV4)
						|| (pgw_node_addrs[tmp_cnt].ip_type == IPV4_GLOBAL_UNICAST))?
			memcmp(&pgw_node_addrs[tmp_cnt].ipv4_addr, &config.s5s8_ip.s_addr, IPV4_SIZE) :
			memcmp(&pgw_node_addrs[tmp_cnt].ipv6_addr, &config.s5s8_ip_v6.s6_addr, IPV6_SIZE));
	/* PGWC */
	if ((num_pgw_node_addr != 0) && (cnd == 0)) {
		if (iface != S5S8_PGWC_PORT_ID) {
			/* Encode the del pdn conn set request*/
			uint16_t msg_len = 0;
			memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
			msg_len = encode_del_pdn_conn_set_req(&del_pdn_conn_req, (uint8_t *)gtpv2c_tx);
			gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

			/* Send the Delete PDN Request to peer node */
			payload_length = 0;
			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			for (uint8_t itr2 = 0; itr2 < num_sgw_node_addr; itr2++) {
				ret = set_dest_address(sgw_node_addrs[itr2], &s5s8_recv_sockaddr);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}
				gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
						s5s8_recv_sockaddr, SENT);
				(s5s8_recv_sockaddr.type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Send Delete PDN Connection Set Request to SGW, Node IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(IPv6_CAST(s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr))):
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Send Delete PDN Connection Set Request to SGW, Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(s5s8_recv_sockaddr.ipv4.sin_addr.s_addr));
			}
			num_sgw_node_addr = 0;
		}
	} else {
		/* SGWC / SAEGWC */
		if (iface != S11_SGW_PORT_ID) {
			/* Encode the del pdn conn set request*/
			uint16_t msg_len = 0;
			memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
			msg_len = encode_del_pdn_conn_set_req(&del_pdn_conn_req, (uint8_t *)gtpv2c_tx);
			gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

			/* Send the Delete PDN Request to peer node */
			payload_length = 0;
			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			for (uint8_t itr3 = 0; itr3 < num_mme_node_addr; itr3++) {
				ret = set_dest_address(mme_node_addrs[itr3], &s11_mme_sockaddr);
				if (ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
						"IP address", LOG_VALUE);
				}
				gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
						s11_mme_sockaddr, SENT);

				(s11_mme_sockaddr.type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Send Delete PDN Connection Set Request to MME, Node IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(IPv6_CAST(s11_mme_sockaddr.ipv6.sin6_addr.s6_addr))):
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Send Delete PDN Connection Set Request to MME, Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(s11_mme_sockaddr.ipv4.sin_addr.s_addr ));

			}
			num_mme_node_addr = 0;
		}
		/* SGWC */
		cnd = (((sgw_node_addrs[tmp_cnt].ip_type == PDN_TYPE_IPV4)
					|| (sgw_node_addrs[tmp_cnt].ip_type == IPV4_GLOBAL_UNICAST)) ?
			memcmp(&sgw_node_addrs[tmp_cnt].ipv4_addr, &config.s11_ip.s_addr, IPV4_SIZE) :
			memcmp(&sgw_node_addrs[tmp_cnt].ipv6_addr, &config.s11_ip_v6.s6_addr, IPV6_SIZE));

		if ((num_pgw_node_addr != 0) && (cnd == 0)) {
			if (iface != S5S8_SGWC_PORT_ID) {
				/* Encode the del pdn conn set request*/
				uint16_t msg_len = 0;
				memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
				msg_len = encode_del_pdn_conn_set_req(&del_pdn_conn_req, (uint8_t *)gtpv2c_tx);
				gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

				/* Send the Delete PDN Request to peer node */
				payload_length = 0;
				payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
					+ sizeof(gtpv2c_tx->gtpc);

				for (uint8_t itr4 = 0; itr4 < num_pgw_node_addr; itr4++) {
					ret = set_dest_address(pgw_node_addrs[itr4], &s5s8_recv_sockaddr);
					if (ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
							"IP address", LOG_VALUE);
					}
					gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
							s5s8_recv_sockaddr, SENT);

					(s5s8_recv_sockaddr.type == IPV6_TYPE) ?
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Send Delete PDN Connection Set Request to PGW, Node IPv6 Addr:"IPv6_FMT"\n",
								LOG_VALUE, IPv6_PRINT(IPv6_CAST(s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr))):
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"Send Delete PDN Connection Set Request to PGW, Node IPv4 Addr:"IPV4_ADDR"\n",
								LOG_VALUE, IPV4_ADDR_HOST_FORMAT(s5s8_recv_sockaddr.ipv4.sin_addr.s_addr));
				}
				num_pgw_node_addr = 0;
			}
		}
	}
	return 0;
}

/* Cleanup Session information by local csid*/
int8_t
del_peer_node_sess(node_address_t *node_addr, uint8_t iface)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":START\n", LOG_VALUE);
	int ret = 0;
	fqcsid_t csids = {0};
	peer_node_addr_key_t key_t = {0};
	fqcsid_ie_node_addr_t *tmp = {0};
	fqcsid_t *peer_csids = NULL;

	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(node_addr,
			UPDATE_NODE);

	if (peer_csids == NULL) {
		key_t.iface = iface;
		memcpy(&key_t.peer_node_addr, node_addr, sizeof(node_address_t));

		tmp = get_peer_node_addr_entry(&key_t, UPDATE_NODE);
		if (tmp != NULL)
			peer_csids = get_peer_addr_csids_entry(&tmp->fqcsid_node_addr, UPDATE_NODE);

		/* Delete UPF hash entry */
		if (peer_csids == NULL) {

			if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Error in Deleting UPF hash entry\n", LOG_VALUE);
			}
			if (iface == SX_PORT_ID) {
				/* Delete entry from teid info list for given upf*/
				delete_entry_from_teid_list(*node_addr, &upf_teid_info_head);

				if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT" Error in Deleting UPF hash entry\n", LOG_VALUE);
				}
			}
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return 0;
		}
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_csids->local_csid[itr];
		memcpy(&key.node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_peer_csid_entry(&key, iface, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get CSID "
				"Entry while cleanup session  \n", LOG_VALUE);
			return -1;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		memcpy(&csids.node_addr, &tmp->node_addr, sizeof(node_address_t));
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CSIDs are already cleanup \n", LOG_VALUE);
		return 0;
	}

	send_delete_pdn_con_set_req(&csids, iface);

	if ((iface != S11_SGW_PORT_ID) && (iface != S5S8_PGWC_PORT_ID)) {
		send_gtpc_pgw_restart_notification(&csids, iface);
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get CSID "
			"Entry while cleanup session  \n", LOG_VALUE);
		return -1;
	}
	if (is_present(&key_t.peer_node_addr)) {
		ret = del_peer_node_addr_entry(&key_t);
		if (ret) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to delete CSID "
					"Entry from hash while cleanup session  \n", LOG_VALUE);
			return -1;
		}
	}

	/* Cleanup Internal data structures */
	ret = del_csid_entry_hash(peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to delete CSID "
			"Entry from hash while cleanup session  \n", LOG_VALUE);
		return -1;
	}

	/* Delete UPF hash entry */
	if (iface == SX_PORT_ID) {
		/* Delete entry from teid info list for given upf*/
		delete_entry_from_teid_list(*node_addr, &upf_teid_info_head);

		if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr) < 0) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Failed to delete UPF "
				"hash entry \n", LOG_VALUE);
		}
	}

	/* Delete local csid */
	for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
		ret = del_sess_csid_entry(csids.local_csid[itr]);
		if (ret) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Failed to delete CSID Entry from hash "
					"while cleanup session\n", LOG_VALUE);
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":END\n", LOG_VALUE);
	return 0;
}

/**
 * @brief  : Send del PDN con. set req. to peer node's
 * @param  : peer_csids, Content peer csid list.
 * @param  : ifacce,
 * @return : Returns 0 in case of success,
 */
static int8_t
send_del_pdn_con_set_req(fqcsid_t *peer_csids, uint8_t  iface)
{
	uint8_t num_mme_node_addr = 0;
	uint8_t num_pgw_node_addr = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	int ret = 0;
	uint16_t payload_length = 0;
	uint32_t teid_key = 0;
	node_address_t mme_node_addrs[MAX_CSID] = {0};
	node_address_t pgw_node_addrs[MAX_CSID] = {0};
	peer_csid_key_t key = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_csid *tmp = NULL;
	sess_csid *current = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	for (uint8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key.peer_node_addr, &peer_csids->node_addr,
					sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					peer_csids->local_csid[itr]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get UE context for teid : %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get PDN context for seid : %u \n",
						LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			if(is_present(&pdn->mme_csid.node_addr)) {
				if ((match_node_addr(num_mme_node_addr, &pdn->mme_csid.node_addr,
								mme_node_addrs)) == 0)
				{
					fill_peer_info(&mme_node_addrs[num_mme_node_addr++],
							&pdn->mme_csid.node_addr);
				}
			}
			if(is_present(&pdn->pgw_csid.node_addr)) {
				if ((match_node_addr(num_pgw_node_addr, &pdn->pgw_csid.node_addr,
								pgw_node_addrs)) == 0)
				{
					fill_peer_info(&pgw_node_addrs[num_pgw_node_addr++],
							&pdn->pgw_csid.node_addr);
				}
			}
			/* Assign Next node address */
			tmp = current->next;

			current = tmp;
		}
	}
	if (iface == S11_SGW_PORT_ID) {
		for (uint8_t itr2; itr2 < num_pgw_node_addr; itr2++) {
			ret = set_dest_address(pgw_node_addrs[itr2], &s5s8_recv_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			fill_gtpc_del_set_pdn_conn_req_t(gtpv2c_tx, peer_csids);

			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);
			/* Send the delete PDN set request to PGW */
			gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
					s5s8_recv_sockaddr, SENT);

			memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
		}
	} else if (iface == S5S8_SGWC_PORT_ID) {
		for (uint8_t itr2; itr2 < num_mme_node_addr; itr2++) {
			ret = set_dest_address(mme_node_addrs[itr2], &s11_mme_sockaddr);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
			fill_gtpc_del_set_pdn_conn_req_t(gtpv2c_tx, peer_csids);

			payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
				+ sizeof(gtpv2c_tx->gtpc);

			/* Send the delete PDN set request to MME */
			gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
					s11_mme_sockaddr, SENT);

			memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
		}
	}
	return 0;
}

/**
 * @brief  : Send pfcp sess. del. ser req. to peer node's
 * @param  : peer_csids, Conten list of peer csid.
 * @return : Returns 0 in case of success,
 */
static int8_t
send_pfcp_sess_del_set_req(fqcsid_t *peer_csids, uint8_t iface)
{
	uint8_t num_node_addr = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	int ret = 0;
	uint32_t teid_key = 0;
	node_address_t node_addrs[MAX_CSID] = {0};
	peer_csid_key_t key = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_csid *tmp = NULL;
	sess_csid *current = NULL;
	for (uint8_t itr = 0; itr < peer_csids->num_csid; itr++)
	{
		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key.peer_node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					peer_csids->local_csid[itr]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			teid_key = UE_SESS_ID(current->cp_seid);
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Found TEID : 0x%x\n", LOG_VALUE, teid_key);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get UE context for teid : %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get PDN context for seid : %u \n",
						LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			if(is_present(&pdn->up_csid.node_addr)) {
				if ((match_node_addr(num_node_addr, &pdn->up_csid.node_addr,
								node_addrs)) == 0)
				{
					fill_peer_info(&node_addrs[num_node_addr++],
									&pdn->up_csid.node_addr);
				}
			}
			/* Assign Next node address */
			tmp = current->next;

			current = tmp;
		}
	}

	/* Send the PFCP deletion session set request to PGW */
	pfcp_sess_set_del_req_t del_set_req_t = {0};

	/* Fill the PFCP session set deletion request */
	cp_fill_pfcp_sess_set_del_req_t(&del_set_req_t, peer_csids);

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	for (uint8_t itr2 = 0; itr2 < num_node_addr; itr2++) {
		ret = set_dest_address(node_addrs[itr2], &upf_pfcp_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
		if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0 ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to send "
					"Delete PDN set Connection Request, Error: %s \n", LOG_VALUE, strerror(errno));
			continue;
		}
	}
	num_node_addr = 0;
	return 0;
}

int8_t
process_del_pdn_conn_set_req_t(del_pdn_conn_set_req_t *del_pdn_req)
{
	int ret = 0;
	uint8_t iface = 0;
	fqcsid_t csids = {0};
	fqcsid_t peer_csids = {0};

	/* MME FQ-CSID */
	if (del_pdn_req->mme_fqcsid.header.len) {
		for (uint8_t itr = 0; itr < del_pdn_req->mme_fqcsid.number_of_csids; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = del_pdn_req->mme_fqcsid.pdn_csid[itr];
			if (del_pdn_req->mme_fqcsid.node_id_type == IPV4_GLOBAL_UNICAST) {
				key.node_addr.ip_type = PDN_TYPE_IPV4;
				memcpy(&key.node_addr.ipv4_addr,
						del_pdn_req->mme_fqcsid.node_address, IPV4_SIZE);
			} else {
				key.node_addr.ip_type = PDN_TYPE_IPV6;
				memcpy(&key.node_addr.ipv6_addr,
						del_pdn_req->mme_fqcsid.node_address, IPV6_ADDRESS_LEN);
			}

			tmp = get_peer_csid_entry(&key, S11_SGW_PORT_ID, REMOVE_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get "
					"MME FQ-CSID entry while processing Delete PDN set Connection "
					"Request, Error: %s \n", LOG_VALUE, strerror(errno));
				continue;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
			}

			memcpy(&csids.node_addr, &tmp->node_addr, sizeof(node_address_t));
			peer_csids.local_csid[peer_csids.num_csid++] =
					del_pdn_req->mme_fqcsid.pdn_csid[itr];
			memcpy(&peer_csids.node_addr, &key.node_addr, sizeof(node_address_t));
		}
		peer_csids.instance = del_pdn_req->mme_fqcsid.header.instance;
		iface = S11_SGW_PORT_ID;
		if (csids.num_csid) {
			send_del_pdn_con_set_req(&peer_csids, iface);
		}
	}

	/* SGW FQ-CSID */
	if (del_pdn_req->sgw_fqcsid.header.len) {
		for (uint8_t itr = 0; itr < del_pdn_req->sgw_fqcsid.number_of_csids; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = del_pdn_req->sgw_fqcsid.pdn_csid[itr];
			if (del_pdn_req->sgw_fqcsid.node_id_type == IPV4_GLOBAL_UNICAST) {
				key.node_addr.ip_type = PDN_TYPE_IPV4;
				memcpy(&key.node_addr.ipv4_addr,
						del_pdn_req->sgw_fqcsid.node_address, IPV4_SIZE);
			} else {
				key.node_addr.ip_type = PDN_TYPE_IPV6;
				memcpy(&key.node_addr.ipv6_addr,
						del_pdn_req->sgw_fqcsid.node_address, IPV6_ADDRESS_LEN);
			}

			tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID, REMOVE_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get "
					"SGW FQ-CSID entry while processing Delete PDN set Connection "
					"Request\n", LOG_VALUE);
				continue;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
			}

			memcpy(&csids.node_addr, &tmp->node_addr, sizeof(node_address_t));
			peer_csids.local_csid[peer_csids.num_csid++] =
					del_pdn_req->sgw_fqcsid.pdn_csid[itr];
			memcpy(&peer_csids.node_addr, &key.node_addr, sizeof(node_address_t));
		}
		peer_csids.instance = del_pdn_req->sgw_fqcsid.header.instance;
		iface = S5S8_PGWC_PORT_ID;
	}

	/* PGW FQ-CSID */
	if (del_pdn_req->pgw_fqcsid.header.len) {
		for (uint8_t itr = 0; itr < del_pdn_req->pgw_fqcsid.number_of_csids; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = del_pdn_req->pgw_fqcsid.pdn_csid[itr];
			if (del_pdn_req->pgw_fqcsid.node_id_type == IPV4_GLOBAL_UNICAST) {
				key.node_addr.ip_type = PDN_TYPE_IPV4;
				memcpy(&key.node_addr.ipv4_addr,
						del_pdn_req->pgw_fqcsid.node_address, IPV4_SIZE);
			} else {
				key.node_addr.ip_type = PDN_TYPE_IPV6;
				memcpy(&key.node_addr.ipv6_addr,
						del_pdn_req->pgw_fqcsid.node_address, IPV6_ADDRESS_LEN);
			}

			tmp = get_peer_csid_entry(&key, S5S8_SGWC_PORT_ID, REMOVE_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"PGW FQ-CSID entry while processing Delete PDN set Connection "
					"Request\n", LOG_VALUE);
				continue;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
			}

			memcpy(&csids.node_addr, &tmp->node_addr, sizeof(node_address_t));
			peer_csids.local_csid[peer_csids.num_csid++] =
				del_pdn_req->pgw_fqcsid.pdn_csid[itr];
			memcpy(&peer_csids.node_addr, &key.node_addr, sizeof(node_address_t));
		}
		peer_csids.instance = del_pdn_req->pgw_fqcsid.header.instance;
		iface = S5S8_SGWC_PORT_ID;
		if (csids.num_csid) {
			send_del_pdn_con_set_req(&peer_csids, iface);
		}
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Not found peer associated CSIDs, CSIDs already cleanup  \n",
				LOG_VALUE);
		return 0;
	}
	/* send pfcp session del. set req. to DP */
	send_pfcp_sess_del_set_req(&peer_csids, iface);
	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_peer_csid_entry(&peer_csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to cleanup "
			"Session by CSID entry\n", LOG_VALUE);
		return -1;
	}

	/* TODO: UPDATE THE NODE ADDRESS */
	//csids.node_addr = config.pfcp_ip.s_addr;

	/* Cleanup Internal data structures */
	ret = del_csid_entry_hash(&peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to cleanup "
			"Session by CSID entry\n", LOG_VALUE);
		return -1;
	}

	return 0;
}

int8_t
fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_header_t *gtpv2c_tx, uint8_t seq_t,
		uint8_t casue_value)
{
	del_pdn_conn_set_rsp_t del_pdn_conn_rsp = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&del_pdn_conn_rsp.header,
			GTP_DELETE_PDN_CONNECTION_SET_RSP, 0, seq_t, 0);

	/* Set Cause value */
	set_ie_header(&del_pdn_conn_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			sizeof(struct cause_ie_hdr_t));
	del_pdn_conn_rsp.cause.cause_value = casue_value;

	encode_del_pdn_conn_set_rsp(&del_pdn_conn_rsp, (uint8_t *)gtpv2c_tx);
	return 0;
}

int8_t
process_del_pdn_conn_set_rsp_t(del_pdn_conn_set_rsp_t *del_pdn_rsp)
{
	if (del_pdn_rsp->cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to process"
			"Delete PDN Connection Set Response with cause : %s \n",
			LOG_VALUE, cause_str(del_pdn_rsp->cause.cause_value));
		return -1;
	}
	return 0;
}

int8_t
process_upd_pdn_conn_set_req_t(upd_pdn_conn_set_req_t *upd_pdn_req)
{
	RTE_SET_USED(upd_pdn_req);
	return 0;
}

int8_t
process_upd_pdn_conn_set_rsp_t(upd_pdn_conn_set_rsp_t *upd_pdn_rsp)
{
	RTE_SET_USED(upd_pdn_rsp);
	return 0;
}

/* Function */
int
process_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *del_set_req, peer_addr_t *peer_addr)
{
	int ret = 0;
	int offend_id = 0;
	uint8_t cause_id = 0;
	peer_addr_t peer_ip = {0};
	node_address_t upf_ip = {0};
	fqcsid_t csids = {0};
	fqcsid_t peer_csids = {0};
	pfcp_sess_set_del_rsp_t pfcp_del_resp = {0};
	upf_context_t *upf_context = NULL;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"PFCP Session Set Deletion Request :: START \n", LOG_VALUE);

	if (peer_addr->type == PDN_TYPE_IPV4) {
		upf_ip.ip_type = PDN_TYPE_IPV4;
		upf_ip.ipv4_addr = peer_addr->ipv4.sin_addr.s_addr;
	} else {
		upf_ip.ip_type = peer_addr->type;
		memcpy(&upf_ip.ipv6_addr,
				&(peer_addr->ipv6.sin6_addr.s6_addr), IPV6_ADDRESS_LEN);
	}
	/* Lookup upf context of peer node */
	/* need to revisite here */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ip), (void **) &(upf_context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN "
				"UPF HASH [%u]\n", LOG_VALUE, del_set_req->node_id.node_id_value_ipv4_address);
		return -1;
	}


	/* UP FQ-CSID */
	if (del_set_req->up_fqcsid.header.len) {
		if (del_set_req->up_fqcsid.number_of_csids) {
			for (uint8_t itr = 0; itr < del_set_req->up_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = del_set_req->up_fqcsid.pdn_conn_set_ident[itr];
				if (del_set_req->up_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
					key.node_addr.ip_type = PDN_TYPE_IPV4;
					memcpy(&key.node_addr.ipv4_addr,
							&(del_set_req->up_fqcsid.node_address), IPV4_SIZE);
				} else {
					key.node_addr.ip_type = PDN_TYPE_IPV6;
					memcpy(&key.node_addr.ipv6_addr,
							del_set_req->up_fqcsid.node_address, IPV6_ADDRESS_LEN);
				}

				tmp = get_peer_csid_entry(&key, SX_PORT_ID, REMOVE_NODE);
				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get "
						"SGW/PGW/SAEGW-U FQ-CSID entry while processing PFCP Session Set Deletion "
						"Request, Error: %s \n", LOG_VALUE, strerror(errno));
					continue;
				}

				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				csids.node_addr = tmp->node_addr;
				peer_csids.local_csid[peer_csids.num_csid++] =
						del_set_req->up_fqcsid.pdn_conn_set_ident[itr];
				memcpy(&peer_csids.node_addr, &(key.node_addr), sizeof(node_address_t));
			}
		}
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Local CSIDs Found \n", LOG_VALUE);
		return 0;
	}

	send_delete_pdn_con_set_req(&csids, SX_PORT_ID);

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids, SX_PORT_ID);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to local cleanup "
			"Session by CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	ret = del_csid_entry_hash(&peer_csids, &csids, SX_PORT_ID);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
			"CSID entry from hash, Error: %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	/* fill pfcp set del resp */
	cause_id = REQUESTACCEPTED;
	fill_pfcp_sess_set_del_resp(&pfcp_del_resp, cause_id, offend_id);

	if (del_set_req->header.s) {
		pfcp_del_resp.header.seid_seqno.no_seid.seq_no =
			 del_set_req->header.seid_seqno.has_seid.seq_no;
	} else {
		pfcp_del_resp.header.seid_seqno.no_seid.seq_no =
			del_set_req->header.seid_seqno.no_seid.seq_no;
	}

	uint8_t pfcp_msg[PFCP_MSG_LEN]= {0};
	int encoded = encode_pfcp_sess_set_del_rsp_t(&pfcp_del_resp, pfcp_msg);

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Sending response for PFCP "
		"Session Set Deletion Response\n", LOG_VALUE);
	memcpy(&peer_ip, peer_addr, sizeof(peer_addr_t));
	/* send pfcp set del resp on sx interface */
	if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, peer_ip, ACC) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to send "
			"PFCP Session Set Deletion Request, Error: %s \n", LOG_VALUE, strerror(errno));
	}
	/* Delete local csid */
	for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
		ret = del_sess_csid_entry(csids.local_csid[itr]);
		if (ret) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Failed to delete CSID Entry from hash "
					"while cleanup session\n", LOG_VALUE);
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Set Deletion Request :: END \n", LOG_VALUE);

	return 0;
}

/* Function */
int
process_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *del_set_rsp)
{
	if(del_set_rsp->cause.cause_value != REQUESTACCEPTED){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"ERROR:Cause received Session Set deletion response is %d\n",
				LOG_VALUE, del_set_rsp->cause.cause_value);

		/* TODO: Add handling to send association to next upf
		 * for each buffered CSR */
		return -1;
	}
	return 0;
}

int
remove_peer_temp_csid(fqcsid_t *peer_fqcsid, uint16_t tmp_csid, uint8_t iface)
{

	csid_t *local_csids = NULL;
	csid_key_t key_t = {0};
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Removing Temporary local CSID "
			"linked with peer node CSID :: START  %d\n", LOG_VALUE, tmp_csid);

	if (peer_fqcsid != NULL) {

		for (uint8_t itr = 0; itr < (peer_fqcsid)->num_csid; itr++) {
			key_t.local_csid = (peer_fqcsid)->local_csid[itr];
			fill_node_addr_info(&key_t.node_addr, &(peer_fqcsid)->node_addr);

			local_csids = get_peer_csid_entry(&key_t, iface, REMOVE_NODE);
			if (local_csids == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"CSID entry while removing temp local CSID, Error : %s \n",
					LOG_VALUE, strerror(errno));
				return -1;
			}
			for (uint8_t itr1 = 0; itr1 < local_csids->num_csid; itr1++) {
				if (local_csids->local_csid[itr1] == tmp_csid ) {
					for (uint8_t pos = itr1; pos < local_csids->num_csid; pos++) {
						local_csids->local_csid[pos] = local_csids->local_csid[(pos + 1)];
					}
					local_csids->num_csid--;
				}
			}
			if (local_csids->num_csid == 0) {
				if (del_peer_csid_entry(&key_t, iface)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Error : Failed to delete CSID "
							"entry while cleanup CSID by CSID entry,\n", LOG_VALUE);
					return -1;
				}
			}
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Remove Temp Local CSID : Number of CSID %d \n",
					LOG_VALUE, local_csids->num_csid);
			}

		return 0;
	}

	return -1;
}

/**
* @brief  : Delete peer address node entry
* @param  : pdn,
* @return : Returns nothing
*/
static void
del_peer_addr_node_entry(pdn_connection *pdn) {

	peer_node_addr_key_t key = {0};
	fqcsid_ie_node_addr_t *node_addr = NULL;
	fqcsid_t *tmp = NULL;

	if (((pdn->context)->cp_mode != PGWC)
			&& (COMPARE_IP_ADDRESS(pdn->mme_csid.node_addr,
					(pdn->context)->s11_mme_gtpc_ip) != 0)) {
		key.iface = S11_SGW_PORT_ID;
		memcpy(&key.peer_node_addr,
				&(pdn->context)->s11_mme_gtpc_ip, sizeof(node_address_t));
		node_addr = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (node_addr != NULL) {
			tmp = get_peer_addr_csids_entry(&node_addr->fqcsid_node_addr, UPDATE_NODE);
			if (tmp == NULL) {
				del_peer_node_addr_entry(&key);
			}
		} else {
			del_peer_node_addr_entry(&key);
		}
	}

	if ((pdn->context)->cp_mode == PGWC
			&& (COMPARE_IP_ADDRESS(pdn->sgw_csid.node_addr,
					pdn->s5s8_sgw_gtpc_ip) != 0))  {
		key.iface = S5S8_PGWC_PORT_ID;
		memcpy(&key.peer_node_addr,
				&pdn->s5s8_sgw_gtpc_ip, sizeof(node_address_t));
		node_addr = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (node_addr != NULL) {
			tmp = get_peer_addr_csids_entry(&node_addr->fqcsid_node_addr, UPDATE_NODE);
			if (tmp == NULL) {
				del_peer_node_addr_entry(&key);
			}
		} else {
			del_peer_node_addr_entry(&key);
		}
	}

	if ((pdn->context)->cp_mode == SGWC
			&& (COMPARE_IP_ADDRESS(pdn->pgw_csid.node_addr,
					pdn->s5s8_pgw_gtpc_ip) != 0))  {
		key.iface = S5S8_SGWC_PORT_ID;
		memcpy(&key.peer_node_addr,
				&pdn->s5s8_pgw_gtpc_ip, sizeof(node_address_t));
		node_addr = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (node_addr != NULL) {
			tmp = get_peer_addr_csids_entry(&node_addr->fqcsid_node_addr, UPDATE_NODE);
			if (tmp == NULL) {
				del_peer_node_addr_entry(&key);
			}
		} else {
			del_peer_node_addr_entry(&key);
		}
	}

	if (COMPARE_IP_ADDRESS(pdn->up_csid.node_addr, pdn->upf_ip) != 0) {
		key.iface = SX_PORT_ID;
		memcpy(&key.peer_node_addr, &pdn->upf_ip, sizeof(node_address_t));
		node_addr = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (node_addr != NULL) {
			tmp = get_peer_addr_csids_entry(&node_addr->fqcsid_node_addr, UPDATE_NODE);
			if (tmp == NULL) {
				del_peer_node_addr_entry(&key);
			}
		} else {
			del_peer_node_addr_entry(&key);
		}
	}
}

int
cleanup_csid_entry(uint64_t seid,
		fqcsid_t *fqcsid, pdn_connection *pdn) {

	uint8_t ret = 0;
	uint16_t csid = 0;
	sess_csid *sess_list = NULL;

	if (fqcsid != NULL) {

		for (uint8_t itr = 0; itr < fqcsid->num_csid; itr++) {

			csid = fqcsid->local_csid[itr];
			/* Remove the session link from CSID */
			sess_list = get_sess_csid_entry(csid, REMOVE_NODE);

			if (sess_list == NULL)
				continue;


			/* Remove node from csid linked list */
			sess_list = remove_sess_csid_data_node(sess_list, seid);

			/* Update CSID Entry in table */
			ret = rte_hash_add_key_data(seids_by_csid_hash,
					&csid, sess_list);

			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to remove Session IDs entry for CSID = %u"
						"\n\tError= %s\n",
						LOG_VALUE, csid,
						rte_strerror(abs(ret)));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			if (sess_list == NULL) {
				ret = del_sess_csid_entry(csid);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Error : While Delete Session CSID entry \n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				ret = cleanup_session_entries(csid, pdn);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Error : While Cleanup session entries \n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}

				del_peer_addr_node_entry(pdn);
			} else {
				/* Remove session csid from UE context */
				cleanup_sess_csid_entry(pdn);
			}
			/*Delete Session Link with Peer CSID */
			del_session_csid_entry(pdn);
		}
		return 0;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"fqcsid not found while Cleanup CSID entry \n", LOG_VALUE);
	return -1;
}

/* Cleanup Service GW context after demotion happen from SAEGWC to PGWC */
int8_t
cleanup_sgw_context(del_sess_req_t *ds_req, ue_context *context)
{
	int ret = 0;
	uint16_t payload_length = 0;
	uint32_t dstIp = context->s11_mme_gtpc_ip.ipv4_addr;
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Peer Node MME IP Addr:"IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp));

	/*Get the ebi index*/
	int ebi_index = GET_EBI_INDEX(ds_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	/* Select the PDN based on the ebi_index*/
	pdn_connection *pdn = GET_PDN(context, ebi_index);
	if (!pdn) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* TODO: Need to think on Multiple Session Scenario */
	/* Delete the MME PATH managment timer Entry*/
	//peerData *conn_data = NULL;

	//ret = rte_hash_lookup_data(conn_hash_handle,
	//		&dstIp, (void **)&conn_data);
	//if ( ret < 0) {
	//	clLog(clSystemLog, eCLSeverityDebug,
	//			LOG_FORMAT" Entry not found for NODE: "IPV4_ADDR"\n",
	//			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp));
	//} else {
	//	/* Stop transmit timer for specific peer node */
	//	stopTimer(&conn_data->tt);
	//	/* Stop periodic timer for specific peer node */
	//	stopTimer(&conn_data->pt);
	//	/* Deinit transmit timer for specific Peer Node */
	//	deinitTimer(&conn_data->tt);
	//	/* Deinit periodic timer for specific Peer Node */
	//	deinitTimer(&conn_data->pt);

	//	/* Update the CLI Peer Status */
	//	update_peer_status(dstIp, FALSE);
	//	/* Delete CLI Peer Entry */
	//	delete_cli_peer(dstIp);

	//	/* Delete entry from connection hash table */
	//	ret = rte_hash_del_key(conn_hash_handle,
	//			&dstIp);
	//	if (ret < 0) {
	//		clLog(clSystemLog, eCLSeverityDebug,
	//				LOG_FORMAT"Failed to del entry from hash table, Key IP:"IPV4_ADDR"\n",
	//				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(dstIp));
	//	}
	//	conn_cnt--;

	//}

	/* TODO: */
	/* Cleanup Peer Node CSIDs Entry */
#ifdef USE_CSID
	/*
	 * De-link entry of the session from the CSID list
	 * for only default bearer id
	 * */
	/* Remove session entry from the SGWC or SAEGWC CSID */
	//cleanup_csid_entry(pdn->seid, (context)->sgw_fqcsid, context);
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Cleanup CSID for SEID:%lu\n",
			LOG_VALUE, pdn->seid);
#endif /* USE_CSID */

	/* TODO: */
	//uint32_t teid = ds_req->header.teid.has_teid.teid;
	///* Delete S11 SGW GTPC TEID entry from the hash table */
	//ret = rte_hash_del_key(ue_context_by_fteid_hash,
	//		&teid);
	//if (ret < 0) {
	//	clLog(clSystemLog, eCLSeverityDebug,
	//			LOG_FORMAT"Failed to del entry from hash table, Key TEID:%u\n",
	//			LOG_VALUE, teid);
	//}
	//clLog(clSystemLog, eCLSeverityDebug,
	//		LOG_FORMAT"Entry deleted from ue_context_by_fteid_hash for TEID:%u\n",
	//		LOG_VALUE, teid);

	/* DSR Response */
	del_sess_rsp_t del_resp = {0};
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	/* Retrieve the Sequence number from Request header */
	uint8_t seq = ds_req->header.teid.has_teid.seq;

	/* Fill the Response and send to MME */
	fill_del_sess_rsp(&del_resp, seq, context->s11_mme_gtpc_teid);

	/*Encode the S11 delete session response message. */
	payload_length = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	ret = set_dest_address(context->s11_mme_gtpc_ip, &s11_mme_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	gtpv2c_send(s11_fd, s11_fd_v6, tx_buf, payload_length,
			s11_mme_sockaddr,ACC);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S11_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s11_mme_sockaddr.type,
						config.s11_ip.s_addr,
						config.s11_ip_v6.s6_addr),
				fill_ip_info(s11_mme_sockaddr.type,
						s11_mme_sockaddr.ipv4.sin_addr.s_addr,
						s11_mme_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s11_port,
				((s11_mme_sockaddr.type == IPTYPE_IPV4_LI) ?
						ntohs(s11_mme_sockaddr.ipv4.sin_port) :
						ntohs(s11_mme_sockaddr.ipv6.sin6_port)));
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"SGW/SAEGW Sent the DSRsp back to MME\n", LOG_VALUE);
	/* Cleanup SGW UE Context */
	context->s11_mme_gtpc_teid = 0;
	//context->s11_sgw_gtpc_teid = 0;
	return 0;
}

/* TODO: Remove it, Never expected behaviour i*/
/* Cleanup Service GW context after demotion happen from SAEGWC to PGWC */
int8_t
cleanup_pgw_context(del_sess_req_t *ds_req, ue_context *context)
{
	int ret = 0;
	uint16_t payload_length = 0;
	/*Get the ebi index*/
	int ebi_index = GET_EBI_INDEX(ds_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	/* Select the PDN based on the ebi_index*/
	pdn_connection *pdn = GET_PDN(context, ebi_index);
	if (!pdn) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* DSR Response */
	del_sess_rsp_t del_resp = {0};
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	/* Retrieve the Sequence number from Request header */
	uint8_t seq = ds_req->header.teid.has_teid.seq;

	/* Fill the Response and send to MME */
	fill_del_sess_rsp(&del_resp, seq, context->s11_mme_gtpc_teid);

	/*Encode the S11 delete session response message. */
	payload_length = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);
	ret = set_dest_address(pdn->old_sgw_addr, &s5s8_recv_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
	gtpv2c_send(s5s8_fd, s5s8_fd_v6, tx_buf, payload_length,
			s5s8_recv_sockaddr, ACC);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				fill_ip_info(s5s8_recv_sockaddr.type,
						config.s5s8_ip.s_addr,
						config.s5s8_ip_v6.s6_addr),
				fill_ip_info(s5s8_recv_sockaddr.type,
						s5s8_recv_sockaddr.ipv4.sin_addr.s_addr,
						s5s8_recv_sockaddr.ipv6.sin6_addr.s6_addr),
				config.s5s8_port,
				((s5s8_recv_sockaddr.type == IPTYPE_IPV4_LI) ?
					ntohs(s5s8_recv_sockaddr.ipv4.sin_port) :
					ntohs(s5s8_recv_sockaddr.ipv6.sin6_port)));
	}

	clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"PGW Sent the DSRsp back to SGW\n", LOG_VALUE);
	return 0;
}

/* Send the PFCP Session Modification Request after promotion */
int8_t
send_pfcp_modification_req(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, create_sess_req_t *csr, uint8_t ebi_index)
{
	int ret = 0;
	uint32_t seq = 0;
	uint8_t num_csid = 0;
	uint8_t far_count = 0;
	uint8_t mme_csid_changed_flag = 0;
	struct resp_info *resp = NULL;
	pdr_t *pdr_ctxt = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	node_address_t node_value = {0};

#ifdef USE_CSID
	/* Parse and stored MME and SGW FQ-CSID in the context */
	fqcsid_t *tmp = NULL;

	/* Allocate the memory for each session */
	if (context != NULL) {
		if (context->mme_fqcsid == NULL) {
			context->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(sess_fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
		}
		if (context->sgw_fqcsid == NULL) {
			context->sgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(sess_fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
		}

		if ((context->mme_fqcsid == NULL) || (context->sgw_fqcsid == NULL)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
					"memory for fqcsids entry\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found "
				"while processing Create Session Request \n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Cleanup PGW Associated CSIDs */
	/* PGW FQ-CSID */
	if (context->pgw_fqcsid) {
		if ((context->pgw_fqcsid)->num_csid) {
			for (uint8_t inx = 0; (context->pgw_fqcsid != NULL) && (inx < (context->pgw_fqcsid)->num_csid); inx++) {
				/* Remove the session link from old CSID */
				uint16_t tmp_csid = (context->pgw_fqcsid)->local_csid[inx];
				sess_csid *tmp1 = NULL;
				tmp1 = get_sess_csid_entry(tmp_csid, REMOVE_NODE);

				if (tmp1 != NULL) {
					/* Remove node from csid linked list */
					tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);
					int8_t ret = 0;
					/* Update CSID Entry in table */
					ret = rte_hash_add_key_data(seids_by_csid_hash,
									&tmp_csid, tmp1);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
								"\n\tError= %s\n",
								LOG_VALUE, tmp_csid,
								rte_strerror(abs(ret)));
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}
					if (tmp1 == NULL) {
						/* Removing temporary local CSID associated with MME */
						remove_peer_temp_csid(&pdn->mme_csid, tmp_csid,
								S5S8_PGWC_PORT_ID);

						/* Removing temporary local CSID assocoated with PGWC */
						remove_peer_temp_csid(&pdn->sgw_csid, tmp_csid,
								S5S8_PGWC_PORT_ID);

						/* Remove Session link from peer csid */
						sess_csid *tmp1 = NULL;
						peer_csid_key_t key = {0};

						key.iface = S5S8_PGWC_PORT_ID;
						key.peer_local_csid = pdn->sgw_csid.local_csid[num_csid];
						memcpy(&(key.peer_node_addr),
								&(pdn->sgw_csid.node_addr), sizeof(node_address_t));

						tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);

						remove_sess_entry(tmp1, pdn->seid, &key);
						/* Delete Local CSID entry */
						del_sess_csid_entry(tmp_csid);
					}
					/* Delete CSID from the context */
					for (uint8_t itr1 = 0; itr1 < (context->pgw_fqcsid)->num_csid; itr1++) {
						if ((context->pgw_fqcsid)->local_csid[itr1] == tmp_csid) {
							for(uint8_t pos = itr1; pos < ((context->pgw_fqcsid)->num_csid - 1); pos++ ) {
								(context->pgw_fqcsid)->local_csid[pos] = (context->pgw_fqcsid)->local_csid[pos + 1];
							}
							(context->pgw_fqcsid)->num_csid--;
						}
					}
				}
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Remove PGWC CSID: %u\n",
						LOG_VALUE, tmp_csid);
			}

			if ((context->pgw_fqcsid)->num_csid == 0)
			{
				memset(&(pdn->pgw_csid), 0, sizeof(fqcsid_t));
				if (context->pgw_fqcsid != NULL) {
					rte_free(context->pgw_fqcsid);
					context->pgw_fqcsid = NULL;
				}
			}
		}
	}

	/* MME FQ-CSID */
	if (csr->mme_fqcsid.header.len) {
		if (csr->mme_fqcsid.number_of_csids) {
			for (uint8_t inx = 0; inx < pdn->mme_csid.num_csid; inx++) {
				if (csr->mme_fqcsid.pdn_csid[csr->mme_fqcsid.number_of_csids - 1] !=
						pdn->mme_csid.local_csid[inx]) {
					mme_csid_changed_flag = TRUE;
				}
			}
			if (mme_csid_changed_flag) {
				fqcsid_t *tmp = NULL;
				tmp = get_peer_addr_csids_entry(&pdn->mme_csid.node_addr, UPDATE_NODE);
				if (tmp != NULL) {
					for (uint8_t itr3 = 0; itr3 < tmp->num_csid; itr3++) {
						if (tmp->local_csid[itr3] ==
								pdn->mme_csid.local_csid[(pdn->mme_csid.num_csid - 1)]) {
							for(uint8_t pos = itr3; pos < (tmp->num_csid - 1); pos++ ) {
								tmp->local_csid[pos] = tmp->local_csid[pos + 1];
							}
							tmp->num_csid--;
						}
					}

					if (tmp->num_csid == 0) {
						if (del_peer_addr_csids_entry(&pdn->mme_csid.node_addr)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in deleting "
									"peer CSID entry, Error : %i\n", LOG_VALUE, errno);
							/* TODO ERROR HANDLING */
							return -1;
						}
					}
				}
				/* Remove Session link from peer csid */
				sess_csid *tmp1 = NULL;
				peer_csid_key_t key = {0};

				key.iface = S5S8_PGWC_PORT_ID;
				key.peer_local_csid = pdn->mme_csid.local_csid[num_csid];
				memcpy(&(key.peer_node_addr),
						&(pdn->mme_csid.node_addr), sizeof(node_address_t));
				tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(tmp1, pdn->seid, &key);

				/* Remove CSID from context */
				remove_csid_from_cntx(context->mme_fqcsid, &pdn->mme_csid);

				ret = add_peer_addr_entry_for_fqcsid_ie_node_addr(
						&context->s11_mme_gtpc_ip, &csr->mme_fqcsid,
						S11_SGW_PORT_ID);
				if (ret)
					return ret;

				ret = add_fqcsid_entry(&csr->mme_fqcsid, context->mme_fqcsid);
				if(ret)
					return ret;

				fill_pdn_fqcsid_info(&pdn->mme_csid, context->mme_fqcsid);
				if (pdn->mme_csid.num_csid) {
					link_sess_with_peer_csid(&pdn->mme_csid, pdn, S11_SGW_PORT_ID);
				}
			}
		}
	} else {
		/* Stored the MME CSID by MME Node address */
		tmp = get_peer_addr_csids_entry(&context->s11_mme_gtpc_ip,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
					"Add the MME CSID by MME Node address, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		memcpy(&tmp->node_addr, &context->s11_mme_gtpc_ip, sizeof(node_address_t));
		memcpy(&(context->mme_fqcsid)->node_addr[(context->mme_fqcsid)->num_csid],
								&context->s11_mme_gtpc_ip, sizeof(node_address_t));
	}

	/* SGW FQ-CSID */
	if (!(context->sgw_fqcsid)->num_csid) {
		tmp = get_peer_addr_csids_entry(&context->s11_sgw_gtpc_ip,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed "
					"to Add the SGW CSID by SGW Node address, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		memcpy(&tmp->node_addr, &context->s11_sgw_gtpc_ip, sizeof(node_address_t));
		memcpy(&(context->sgw_fqcsid)->node_addr[(context->sgw_fqcsid)->num_csid],
								&context->s11_sgw_gtpc_ip, sizeof(node_address_t));
	}

	/* Get the copy of existing SGW CSID */
	fqcsid_t tmp_csid_t = {0};
	if (pdn->sgw_csid.num_csid) {
		if ((context->sgw_fqcsid)->num_csid) {
			memcpy(&tmp_csid_t, &pdn->sgw_csid, sizeof(fqcsid_t));
		}
	}

	/* Update the entry for peer nodes */
	if (fill_peer_node_info(pdn, bearer)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to fill peer node info and assignment of the "
			"CSID Error: %s\n", LOG_VALUE, strerror(errno));
		return  GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	if(pdn->flag_fqcsid_modified == TRUE) {
		uint8_t tmp_csid = 0;
		/* Validate the exsiting CSID or allocated new one */
		for (uint8_t inx1 = 0; inx1 < tmp_csid_t.num_csid; inx1++) {
			if ((context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1] ==
					tmp_csid_t.local_csid[inx1]) {
				tmp_csid = tmp_csid_t.local_csid[inx1];
				break;
			}
		}

		if (!tmp_csid) {
			for (uint8_t inx = 0; inx < tmp_csid_t.num_csid; inx++) {
				/* Remove the session link from old CSID */
				sess_csid *tmp1 = NULL;
				tmp1 = get_sess_csid_entry(tmp_csid_t.local_csid[inx], REMOVE_NODE);

				if (tmp1 != NULL) {
					/* Remove node from csid linked list */
					tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

					int8_t ret = 0;
					/* Update CSID Entry in table */
					ret = rte_hash_add_key_data(seids_by_csid_hash,
									&tmp_csid_t.local_csid[inx], tmp1);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
								"\n\tError= %s\n",
								LOG_VALUE, tmp_csid_t.local_csid[inx],
								rte_strerror(abs(ret)));
						return GTPV2C_CAUSE_SYSTEM_FAILURE;
					}
					if (tmp1 == NULL) {
						/* Removing temporary local CSID associated with MME */
						remove_peer_temp_csid(&pdn->mme_csid, tmp_csid_t.local_csid[inx],
								S11_SGW_PORT_ID);

						/* Removing temporary local CSID assocoated with PGWC */
						remove_peer_temp_csid(&pdn->pgw_csid, tmp_csid_t.local_csid[inx],
								S5S8_SGWC_PORT_ID);
						del_sess_csid_entry(tmp_csid_t.local_csid[inx]);
					}
					/* Delete CSID from the context */
					remove_csid_from_cntx(context->sgw_fqcsid, &tmp_csid_t);
				}

				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Remove session link from Old CSID:%u\n",
						LOG_VALUE, tmp_csid_t.local_csid[inx]);
			}
		}

		/* update entry for cp session id with link local csid */
		sess_csid *tmp = NULL;
		tmp = get_sess_csid_entry(
				pdn->sgw_csid.local_csid[pdn->sgw_csid.num_csid - 1],
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to get session of CSID entry %s \n",
					LOG_VALUE, strerror(errno));
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		/* Link local csid with session id */
		/* Check head node created ot not */
		if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
			sess_csid *new_node = NULL;
			/* Add new node into csid linked list */
			new_node = add_sess_csid_data_node(tmp);
			if(new_node == NULL ) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
					"ADD new node into CSID linked list : %s\n", LOG_VALUE);
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			} else {
				new_node->cp_seid = pdn->seid;
				new_node->up_seid = pdn->dp_seid;
			}

		} else {
			tmp->cp_seid = pdn->seid;
			tmp->up_seid = pdn->dp_seid;
		}
		/* Fill the fqcsid into the session est request */
		if (fill_fqcsid_sess_mod_req(&pfcp_sess_mod_req, pdn)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to fill "
				"FQ-CSID in Session Modification Request, "
				"Error: %s\n", LOG_VALUE, strerror(errno));
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if (mme_csid_changed_flag) {
			/* set MME FQ-CSID */
			set_fq_csid_t(&pfcp_sess_mod_req.mme_fqcsid, &pdn->mme_csid);
		}
	}
#endif /* USE_CSID */

	if(pdn) {
		for(int bearer_inx = 0; bearer_inx < MAX_BEARERS; bearer_inx++) {
			bearer = pdn->eps_bearers[bearer_inx];
			if(bearer) {
				/* Get the PDR Context */
				for(uint8_t pdr = 0; pdr < bearer->pdr_count; pdr++) {
					if (bearer->pdrs[pdr] == NULL) {
						continue;
					}

					if(bearer->pdrs[pdr]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) {
						pdr_ctxt = bearer->pdrs[pdr];
						break;
					} else if ((bearer->pdrs[pdr])->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
						/* Update the local source IP Address and teid */
						ret = set_node_address(&(bearer->pdrs[pdr])->pdi.local_fteid.ipv4_address,
							(bearer->pdrs[pdr])->pdi.local_fteid.ipv6_address,
							bearer->s1u_sgw_gtpu_ip);
						if (ret < 0) {
							clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
								"IP address", LOG_VALUE);
						}
						/* Update the PDR info */
						set_update_pdr(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count]),
							bearer->pdrs[pdr], (pdn->context)->cp_mode);
						/* Reset Precedance, No need to forward */
						memset(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].precedence), 0, sizeof(pfcp_precedence_ie_t));
						/* Reset FAR ID, No need to forward */
						memset(&(pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].far_id), 0,
							sizeof(pfcp_far_id_ie_t));
						/* Update the PDR header length*/
						pfcp_sess_mod_req.update_pdr[pfcp_sess_mod_req.update_pdr_count].header.len -=
							(sizeof(pfcp_far_id_ie_t) + sizeof(pfcp_precedence_ie_t));
						pfcp_sess_mod_req.update_pdr_count++;
					}
				}
				/* Set the Appropriate Actions */
				if(pdr_ctxt) {
					pdr_ctxt->far.actions.buff = FALSE;
					pdr_ctxt->far.actions.nocp = FALSE;
					pdr_ctxt->far.actions.forw = TRUE;
					pdr_ctxt->far.actions.drop = FALSE;
					pdr_ctxt->far.actions.dupl = GET_DUP_STATUS(pdn->context);
				}

				/* Add the Update FAR in the message */
				if (pdr_ctxt->far.actions.forw) {
					set_update_far(
							&(pfcp_sess_mod_req.update_far[far_count]),
							&pdr_ctxt->far);

					/* Set the Update Forwarding Parameter IE*/
					uint16_t len = 0;
					len += set_upd_forwarding_param(&(pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms),
						bearer->s1u_enb_gtpu_ip);

					len += UPD_PARAM_HEADER_SIZE;
					pfcp_sess_mod_req.update_far[far_count].header.len += len;

					/* Fill the eNB F-TEID Information */
					pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms.outer_hdr_creation.teid =
						bearer->s1u_enb_gtpu_teid;

					pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms.dst_intfc.interface_value =
						GTPV2C_IFTYPE_S1U_ENODEB_GTPU;

					/* Set the endmarker flag */
					set_pfcpsmreqflags(&(pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms.pfcpsmreq_flags));
					pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms.pfcpsmreq_flags.sndem = PRESENT;
					pfcp_sess_mod_req.update_far[far_count].header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);
					pfcp_sess_mod_req.update_far[far_count].upd_frwdng_parms.header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);

					far_count++;
					pfcp_sess_mod_req.update_far_count = far_count;
				}


			}
		}
		/* Set the procedure */
		//pdn->proc = MODIFY_BEARER_PROCEDURE;

		/* Set CP Seid and Node Address */
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

		/* Get the Sequence Number for Request */
		seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);
		/* Fill the Sequence Number inside the header */
		set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header), PFCP_SESSION_MODIFICATION_REQUEST,
				HAS_SEID, seq, context->cp_mode);
		/* Set the UP Seid inside the header */
		pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

		/* Encode the PFCP Session Modification Request */
		uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
		int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

		/* Set the UPF IP Address */
		//upf_pfcp_sockaddr = pdn->upf_ip.ipv4_addr;

		/* Sent the PFCP messages */
		if(pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to send"
			"PFCP Session Modification Request %i\n", LOG_VALUE, errno);
		} else {

			/* Add the timer for PFCP Session Modification Request  */
#ifdef CP_BUILD
			add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
				&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
			/* Stored the Resp Struct with CP Seid */
			if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
				"for seid: %lu", LOG_VALUE, pdn->seid);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
			/* Reset the resp structure */
			reset_resp_info_structure(resp);

			/* Stored info to send resp back to s11 intfc */
			resp->gtpc_msg.csr = *csr;
			resp->msg_type = GTP_CREATE_SESSION_REQ;
			resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
			resp->proc = pdn->proc;
			resp->cp_mode = context->cp_mode;
			pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent Request to UP, msg_type:%u, State:%s\n", LOG_VALUE, resp->msg_type,
					"PFCP_SESS_MOD_REQ_SNT_STATE");
		}
	}
	return 0;
}

/* Promotion: Parse the handover CSR and modify existing session info */
/**
 * @brief  : Parse handover CSR request on Combined GW
 * @param  : csr holds data in csr
 * @param  : COntext, pointer to UE context structure
 * @param  : CP_TYPE: changed gateway type, promotion PGWC --> SAEGWC
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
promotion_parse_cs_req(create_sess_req_t *csr, ue_context *context,
		uint8_t cp_type)
{
	int ret = 0;
	int ebi_index = 0;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	for(uint8_t i = 0; i < csr->bearer_count; i++) {

		if (!csr->bearer_contexts_to_be_created[i].header.len) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Bearer Context IE Missing in the CSR\n", LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		ebi_index = GET_EBI_INDEX(csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n",
				LOG_VALUE);
			return -1;
		}

		/* set s11_sgw_gtpc_teid = key->ue_context_by_fteid_hash */
		if (context->s11_sgw_gtpc_teid !=
				csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key) {
			/* Promotion Scenario S11 SGW and S5S8 PGW TEIDs are same */
			context->s11_sgw_gtpc_teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
		}

		if (cp_type != 0) {
			context->cp_mode = cp_type;
		} else {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to select appropriate cp type\n",
				LOG_VALUE);
			return -1;
		}

		/* Retrive procedure of CSR */
		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
				"get pdn for ebi_index %d \n", LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		bearer = context->eps_bearers[ebi_index];
		if (csr->linked_eps_bearer_id.ebi_ebi) {
			if (pdn->default_bearer_id != csr->linked_eps_bearer_id.ebi_ebi) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Exsiting default ebi:'%u' not match with received ebi: %u\n",
						LOG_VALUE, pdn->default_bearer_id, csr->linked_eps_bearer_id.ebi_ebi);
				/* TODO */
			}
		}

		if (pdn->default_bearer_id == csr->bearer_contexts_to_be_created[i].eps_bearer_id.ebi_ebi) {
			if(fill_context_info(csr, context, pdn) != 0) {
				return -1;
			}

			pdn->proc = get_csr_proc(csr);

			if (fill_pdn_info(csr, pdn, context, bearer) != 0) {
				return -1;
			}

		} /*Check UE Exist*/


		imsi_id_hash_t *imsi_id_config = NULL;

		/* To minimize lookup of hash for LI */
		if ((NULL == imsi_id_config) && (NULL != context)) {

			if (NULL == imsi_id_config) {

				/* Get User Level Packet Copying Token or Id Using Imsi */
				ret = get_id_using_imsi(context->imsi, &imsi_id_config);
				if (ret < 0) {

					clLog(clSystemLog, eCLSeverityDebug, "[%s]:[%s]:[%d] Not applicable for li\n",
							__file__, __func__, __LINE__);
				}
			}

			if (NULL != imsi_id_config) {

				/* Fillup context from li hash */
				fill_li_config_in_context(context, imsi_id_config);
			}
		}


		/* Fill the Bearer Information */
		bearer->s1u_enb_gtpu_teid = csr->bearer_contexts_to_be_created[i].s1u_enb_fteid.teid_gre_key;

		ret = fill_ip_addr(csr->bearer_contexts_to_be_created[i].s1u_enb_fteid.ipv4_address,
			csr->bearer_contexts_to_be_created[i].s1u_enb_fteid.ipv6_address,
			&bearer->s1u_enb_gtpu_ip);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
		/* Assign the S1U SAEGWU TEID */
		bearer->s1u_sgw_gtpu_teid = bearer->s5s8_pgw_gtpu_teid;

	} /*for loop*/


	/* Store the context of ue in pdn */
	context->bearer_count = csr->bearer_count;
	pdn->context = context;

	if (config.use_gx) {
		if(((context->uli_flag != FALSE) && (((context->event_trigger & (1 << ULI_EVENT_TRIGGER))) != 0))
			|| ((context->ue_time_zone_flag != FALSE) && (((context->event_trigger) & (1 << UE_TIMEZONE_EVT_TRIGGER)) != 0))
			|| ((context->rat_type_flag != FALSE) &&  ((context->event_trigger & (1 << RAT_EVENT_TRIGGER))) != 0)) {

			ret = gen_ccru_request(context, bearer, NULL, NULL);

			struct resp_info *resp = NULL;
			/*Retrive the session information based on session id. */
			if (get_sess_entry(pdn->seid, &resp) != 0){
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Session Entry "
					"Found for session ID:%lu\n", LOG_VALUE, pdn->seid);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
			reset_resp_info_structure(resp);
			resp->gtpc_msg.csr = *csr;
			resp->cp_mode = context->cp_mode;
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Sent the CCRU Request to PCRF\n", LOG_VALUE);

			return ret;
		}
	}

	if ((ret = send_pfcp_modification_req(context, pdn, bearer, csr, ebi_index)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Sent PFCP MOD Req\n",
				LOG_VALUE);
		return ret;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Sent the PFCP modification Request to UP\n", LOG_VALUE);
	return 0;
}
