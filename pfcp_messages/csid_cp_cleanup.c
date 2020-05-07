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

#include "cp.h"
#include "pfcp.h"
#include "clogger.h"
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "gw_adapter.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "clogger.h"

#ifdef GX_BUILD
#include "cp_app.h"
#include "sm_enum.h"
#include "ipc_api.h"

extern int gx_app_sock;
#endif /* GX_BUILD */

extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;
extern socklen_t s11_mme_sockaddr_len;

extern int s5s8_fd;
struct sockaddr_in s5s8_recv_sockaddr;
extern socklen_t s5s8_sockaddr_len;

extern pfcp_config_t pfcp_config;

static uint16_t sequence = 0;

int8_t
fill_pgw_restart_notification(gtpv2c_header_t *gtpv2c_tx,
		uint32_t s11_sgw, uint32_t s5s8_pgw)
{
	/* Encode the PGW Restart Notification request*/
	pgw_rstrt_notif_t pgw_rstrt_notif = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&pgw_rstrt_notif.header,
			GTP_PGW_RESTART_NOTIFICATION, 0, ++sequence);

	/* Fill the SGW S11 IP Address */
	set_ie_header(&pgw_rstrt_notif.sgw_s11s4_ip_addr_ctl_plane.header,
			GTP_IE_IP_ADDRESS, IE_INSTANCE_ONE,
			sizeof(uint32_t));

	pgw_rstrt_notif.sgw_s11s4_ip_addr_ctl_plane.ipv4_ipv6_addr = s11_sgw;

	/* Fill the PGW S5/S8 IP Address */
	set_ie_header(&pgw_rstrt_notif.pgw_s5s8_ip_addr_ctl_plane_or_pmip.header,
			GTP_IE_IP_ADDRESS, IE_INSTANCE_ZERO,
			sizeof(uint32_t));

	if (pfcp_config.cp_type == SAEGWC) {
		pgw_rstrt_notif.pgw_s5s8_ip_addr_ctl_plane_or_pmip.ipv4_ipv6_addr = s11_sgw;
	} else {
		pgw_rstrt_notif.pgw_s5s8_ip_addr_ctl_plane_or_pmip.ipv4_ipv6_addr = s5s8_pgw;
	}

	/* Set Cause value */
	set_ie_header(&pgw_rstrt_notif.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			sizeof(struct cause_ie_hdr_t));
	pgw_rstrt_notif.cause.cause_value = GTPV2C_CAUSE_PGW_NOT_RESPONDING;


	uint16_t msg_len = 0;
	msg_len = encode_pgw_rstrt_notif(&pgw_rstrt_notif, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	return 0;
}

static int8_t
fill_gtpc_del_set_pdn_conn_req(gtpv2c_header_t *gtpv2c_tx, fqcsid_t *local_csids,
		uint8_t iface)
{
	del_pdn_conn_set_req_t del_pdn_conn_req = {0};

	set_gtpv2c_teid_header((gtpv2c_header_t *)&del_pdn_conn_req.header,
			GTP_DELETE_PDN_CONNECTION_SET_REQ, 0, ++sequence);

	if ((iface == S11_SGW_PORT_ID) ||
			(iface == SX_PORT_ID) ||
			(iface == S5S8_SGWC_PORT_ID)) {
			/* Set the SGW FQ-CSID */
			if (pfcp_config.cp_type != PGWC) {
				if (local_csids->num_csid) {
					set_gtpc_fqcsid_t(&del_pdn_conn_req.sgw_fqcsid, IE_INSTANCE_ONE,
							local_csids);
				}
			} else {
				/* Set the PGW FQ-CSID */
				if (local_csids->num_csid) {
					set_gtpc_fqcsid_t(&del_pdn_conn_req.pgw_fqcsid, IE_INSTANCE_TWO,
							local_csids);
				}
			}
	} else if (iface == S5S8_PGWC_PORT_ID) {
		/* Set the PGW FQ-CSID */
		if (local_csids->num_csid) {
			set_gtpc_fqcsid_t(&del_pdn_conn_req.pgw_fqcsid, IE_INSTANCE_TWO,
					local_csids);
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Select Invalid iface type..\n", ERR_MSG);
		return -1;
	}

	/* Encode the del pdn conn set request*/
	uint16_t msg_len = 0;
	msg_len = encode_del_pdn_conn_set_req(&del_pdn_conn_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	return 0;
}

uint32_t s5s8_node_addr = 0;

#ifdef GX_BUILD
static int8_t
fill_ccr_t_request(pdn_connection *pdn, uint8_t ebi_index)
{
	int ret = 0;
	uint16_t msglen = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	/* Retrive Gx_context based on Sess ID. */
	ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*)(pdn->gx_sess_id),
			(void **)&gx_context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
				pdn->gx_sess_id);
		return -1;
	}

	/* VS: Set the Msg header type for CCR-T */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = TERMINATION_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = TERMINATION ;

	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, pdn->context, ebi_index, pdn->gx_sess_id) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}
	/* Update UE State */
	pdn->state = CCR_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = CCR_SNT_STATE;
	gx_context->proc = pdn->proc;

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msglen = gx_ccr_calc_length(&ccr_request.data.ccr);

	buffer = rte_zmalloc_socket(NULL, msglen + sizeof(ccr_request.msg_type),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		clLog(sxlogger, eCLSeverityCritical, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msglen) == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
		return -1;
	}

	/* VS: Write or Send CCR -T msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer, msglen + sizeof(ccr_request.msg_type));
	clLog(clSystemLog, eCLSeverityDebug, FORMAT"Send CCR-T to PCRF \n", ERR_MSG);

	struct sockaddr_in saddr_in;
	saddr_in.sin_family = AF_INET;
	inet_aton("127.0.0.1", &(saddr_in.sin_addr));
	update_cli_stats(saddr_in.sin_addr.s_addr, OSS_CCR_TERMINATE, SENT, GX);

	return 0;
}
#endif /* GX_BUILD */

static int8_t
flush_pdr_entries(eps_bearer *bearer)
{
	for (uint8_t itr = 0; itr < bearer->pdr_count; itr++) {
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

static int8_t
del_sess_by_csid_entry(uint32_t teid, uint8_t iface)
{
	int i = 0;
	int ret = 0;
	ue_context *context = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	for (uint8_t ebi_index = 0; ebi_index < MAX_BEARERS; ebi_index++) {

		eps_bearer *bearer = context->eps_bearers[ebi_index];
		if (bearer == NULL)
			continue;

		pdn_connection *pdn = bearer->pdn;
		if (pdn == NULL)
			continue;

		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == PGWC))
			s5s8_node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;

#ifdef GX_BUILD
		if ( pfcp_config.cp_type != SGWC) {
			/* TODO: Need to remove in real enviorment*/
			if (iface != S11_SGW_PORT_ID) {
				fill_ccr_t_request(pdn, ebi_index);
			}
		}
#else
	RTE_SET_USED(iface);
#endif /* GX_BUILD */

		for (i = 0; i < MAX_BEARERS; ++i) {
			if (pdn->eps_bearers[i] == NULL)
				continue;

			if (context->eps_bearers[i] == pdn->eps_bearers[i]) {
				if (flush_pdr_entries(pdn->eps_bearers[i])) {
					/* TODO: Error Handling */
					return -1;
				}
				rte_free(context->eps_bearers[i]);
			}
		}

		rte_free(pdn);
		pdn = NULL;
	}

	/* Delete UE context entry from IMSI Hash */
	if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s %s - Error on ue_context_by_imsi_hash del\n",__file__,
				strerror(ret));
	}
	rte_free(context);
	context = NULL;

	update_sys_stat(number_of_users, DECREMENT);
	update_sys_stat(number_of_active_session, DECREMENT);


	return 0;
}

static int8_t
cleanup_sess_by_csid_entry(fqcsid_t *csids, uint8_t iface)
{
	/* Get the session ID by csid */
	for (uint8_t itr1 = 0; itr1 < csids->num_csid; itr1++) {
		sess_csid *tmp = NULL;
		tmp = get_sess_csid_entry(csids->local_csid[itr1]);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		for (uint8_t itr2 = 0; itr2 < tmp->seid_cnt; itr2++) {
			uint32_t teid_key = UE_SESS_ID(tmp->cp_seid[itr2]);
			if (del_sess_by_csid_entry(teid_key, iface)) {
				/* TODO Handle Error */
			}

			/* Delete UE context entry from UE Hash */
			if (rte_hash_del_key(ue_context_by_fteid_hash, &teid_key) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						"%s - Error on ue_context_by_fteid_hash del\n", __file__);
			}
		}
	}
	return 0;
}

/* Cleanup Session information by local csid*/
int8_t
del_peer_node_sess(uint32_t node_addr, uint8_t iface)
{
	clLog(apilogger, eCLSeverityDebug, "%s:START\n", __func__);
	int ret = 0;
	uint16_t payload_length = 0;
	fqcsid_t csids = {0};
	fqcsid_t *peer_csids = NULL;
	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
	memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));

	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(ntohl(node_addr),
			MOD);

	if (peer_csids == NULL) {
		/* Delete UPF hash entry */
		if (iface == SX_PORT_ID) {
			if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						FORMAT" Error on upf_context_by_ip_hash del\n", ERR_MSG);
			}
		}
		clLog(clSystemLog, eCLSeverityDebug, FORMAT" Entry not found \n", ERR_MSG);
		return -1;
	}

	/* Get the mapped local CSID */
	csids.num_csid = peer_csids->num_csid;
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		tmp = get_peer_csid_entry(&peer_csids->local_csid[itr],
				iface);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug, FORMAT" Entry not found \n", ERR_MSG);
			return -1;
		}
		csids.local_csid[itr] = tmp->local_csid;
		csids.node_addr = tmp->node_addr;
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug, FORMAT"Csids are empty \n", ERR_MSG);
		return 0;
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		//return -1;
	}

	if (pfcp_config.cp_type != PGWC) {
		if (iface != S11_SGW_PORT_ID) {
			//fqcsid_t *csid_t = NULL;
			//csid_t = get_peer_addr_csids_entry(s11_mme_sockaddr.sin_addr.s_addr,
			//		MOD);
			//if (csid_t != NULL) {
				/* Fill the PGW restart notification request */
				fill_pgw_restart_notification(gtpv2c_tx, ntohl(pfcp_config.s11_ip.s_addr),
						s5s8_node_addr);
				/* Send the Delete PDN Request to peer node */
				payload_length = 0;
				payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
					+ sizeof(gtpv2c_tx->gtpc);

				/* TODO: NEED TO HANDLE THIS */
				/* Send the PGW Restart notification */
				if (pfcp_config.cp_type == SAEGWC) {
					gtpv2c_send(s11_fd, tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);

					clLog(clSystemLog, eCLSeverityDebug, FORMAT"Send PGW Restart notification to MME \n",
							ERR_MSG);

				}

				if ((pfcp_config.cp_type == SGWC) && (iface == S5S8_SGWC_PORT_ID)) {
					gtpv2c_send(s11_fd, tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);

					clLog(clSystemLog, eCLSeverityDebug, FORMAT"Send PGW Restart notification to MME \n",
							ERR_MSG);
				}

				memset(gtpv2c_tx, 0, sizeof(gtpv2c_header_t));
			//}
		}
	}


	/* Fill the Delete PDN Request */
	fill_gtpc_del_set_pdn_conn_req(gtpv2c_tx, &csids, iface);

	/* Send the Delete PDN Request to peer node */
	payload_length = 0;
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	//fqcsid_t *csid = NULL;
	if (pfcp_config.cp_type == PGWC) {
		if (iface != S5S8_PGWC_PORT_ID) {
			/* Get peer CSID associated with node */
			//csid = get_peer_addr_csids_entry(s5s8_recv_sockaddr.sin_addr.s_addr,
			//		MOD);
			//if ((csid != NULL) && (csid->num_csid)) {
				gtpv2c_send(s5s8_fd, tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len);
			//}
		}
	} else {
		if (iface != S11_SGW_PORT_ID) {
			/* Get peer CSID associated with node */
			//csid = get_peer_addr_csids_entry(s11_mme_sockaddr.sin_addr.s_addr,
			//		MOD);
			//if ((csid != NULL) && (csid->num_csid)) {
				gtpv2c_send(s11_fd, tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
			//}
		}
		if (pfcp_config.cp_type == SGWC) {
			/* Get peer CSID associated with node */
			//csid = get_peer_addr_csids_entry(s5s8_recv_sockaddr.sin_addr.s_addr,
			//		MOD);
			//if ((csid != NULL) && (csid->num_csid)) {
			if (iface != S5S8_SGWC_PORT_ID) {
				gtpv2c_send(s5s8_fd, tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len);
			}
		}
	}

	/* TODO: Temp work around */
	if (iface == S5S8_SGWC_PORT_ID) {
		peer_csids->node_addr = ntohl(peer_csids->node_addr);
	}

	/* Cleanup Internal data structures */
	ret = del_csid_entry_hash(peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
		return -1;
	}

	/* Delete UPF hash entry */
	if (iface == SX_PORT_ID) {
		if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					FORMAT" Error on upf_context_by_ip_hash del\n", ERR_MSG);
		}
	}
	clLog(apilogger, eCLSeverityDebug, "%s:END\n", __func__);
	return 0;
}

int8_t
process_del_pdn_conn_set_req_t(del_pdn_conn_set_req_t *del_pdn_req,
		gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t iface = 0;
	fqcsid_t csids = {0};
	fqcsid_t peer_csids = {0};

	/* MME FQ-CSID */
	if (del_pdn_req->mme_fqcsid.header.len) {
		csids.num_csid = del_pdn_req->mme_fqcsid.number_of_csids;
		peer_csids.num_csid = csids.num_csid;
		for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(&del_pdn_req->mme_fqcsid.pdn_csid[itr],
					S11_SGW_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			csids.local_csid[itr] = tmp->local_csid;
			csids.node_addr = tmp->node_addr;
			peer_csids.local_csid[itr] = del_pdn_req->mme_fqcsid.pdn_csid[itr];
			peer_csids.node_addr = del_pdn_req->mme_fqcsid.node_address;
		}

		/* Send the delete PDN set request to PGW */
		if (pfcp_config.cp_type == SGWC ) {
			/* TODO: UPDATE THE NODE ADDRESS */
			csids.node_addr = pfcp_config.s5s8_ip.s_addr;

			fill_gtpc_del_set_pdn_conn_req(gtpv2c_tx, &csids,
					S5S8_SGWC_PORT_ID);
		}
		/* Set the interface */
		iface = S11_SGW_PORT_ID;
	}

	/* SGW FQ-CSID */
	if (del_pdn_req->sgw_fqcsid.header.len) {
		csids.num_csid = del_pdn_req->sgw_fqcsid.number_of_csids;
		peer_csids.num_csid = csids.num_csid;
		for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(&del_pdn_req->sgw_fqcsid.pdn_csid[itr],
					S5S8_PGWC_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			csids.local_csid[itr] = tmp->local_csid;
			csids.node_addr = tmp->node_addr;
			peer_csids.local_csid[itr] = del_pdn_req->sgw_fqcsid.pdn_csid[itr];
			peer_csids.node_addr = del_pdn_req->sgw_fqcsid.node_address;
		}
		/* Set the interface */
		iface = S5S8_PGWC_PORT_ID;
	}

	/* PGW FQ-CSID */
	if (del_pdn_req->pgw_fqcsid.header.len) {
		csids.num_csid = del_pdn_req->pgw_fqcsid.number_of_csids;
		peer_csids.num_csid = csids.num_csid;
		for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(&del_pdn_req->pgw_fqcsid.pdn_csid[itr],
					S5S8_SGWC_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			csids.local_csid[itr] = tmp->local_csid;
			csids.node_addr = tmp->node_addr;
			peer_csids.local_csid[itr] = del_pdn_req->pgw_fqcsid.pdn_csid[itr];
			peer_csids.node_addr = del_pdn_req->pgw_fqcsid.node_address;
		}

		/* Set the interface */
		iface = S5S8_SGWC_PORT_ID;
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Not received any CSID from peer node \n", ERR_MSG);
		return -1;
	}

	/* PGW FQ-CSID */
	if (del_pdn_req->pgw_fqcsid.header.len) {
		/* Send the delete PDN set request to MME */
		if (pfcp_config.cp_type == SGWC ) {
			csids.node_addr = ntohl(pfcp_config.s11_ip.s_addr);

			fill_gtpc_del_set_pdn_conn_req(gtpv2c_tx, &csids,
					S11_SGW_PORT_ID);
		}
		if (pfcp_config.cp_type == SGWC) {
			bzero(&s11_tx_buf, sizeof(s11_tx_buf));
			gtpv2c_header_t *gtpv2c_tx_t = (gtpv2c_header_t *)s11_tx_buf;
			//fqcsid_t *csid_t = NULL;
			//csid_t = get_peer_addr_csids_entry(s11_mme_sockaddr.sin_addr.s_addr,
			//		MOD);
			//if (csid_t != NULL) {
				/* Fill the PGW restart notification request */
				fill_pgw_restart_notification(gtpv2c_tx_t, ntohl(pfcp_config.s11_ip.s_addr),
						peer_csids.node_addr);
				/* Send the Delete PDN Request to peer node */
				int payload_length = 0;
				payload_length = ntohs(gtpv2c_tx_t->gtpc.message_len)
					+ sizeof(gtpv2c_tx_t->gtpc);

				/* TODO: NEED TO HANDLE THIS */
				/* Send the PGW Restart notification */
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);

				clLog(clSystemLog, eCLSeverityDebug, FORMAT"Send PGW Restart notification to MME \n",
						ERR_MSG);
			//}
			}
	}

	/* MME FQ-CSID */
	if (del_pdn_req->mme_fqcsid.header.len) {
		/* Send the delete PDN set request to PGW */
		if (pfcp_config.cp_type == SGWC ) {
			csids.node_addr = ntohl(pfcp_config.s5s8_ip.s_addr);

			fill_gtpc_del_set_pdn_conn_req(gtpv2c_tx, &csids,
					S5S8_SGWC_PORT_ID);
		}
	}

	/* Send the PFCP deletion session set request to PGW */
	/* TODO: UPDATE THE NODE ADDRESS */
	csids.node_addr = pfcp_config.pfcp_ip.s_addr;

	pfcp_sess_set_del_req_t del_set_req_t = {0};

	/* TODO: Need To think on it iface*/
	if (pfcp_config.cp_type == PGWC) {
		fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, S5S8_PGWC_PORT_ID);
	} else {
		fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, S11_SGW_PORT_ID);
	}

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error sending: %i\n",
				ERR_MSG, errno);
		return -1;
	}


	/* Cleanup Internal data structures */
	ret = del_csid_entry_hash(&peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
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
			GTP_DELETE_PDN_CONNECTION_SET_RSP, 0, seq_t);

	/* Set Cause value */
	set_ie_header(&del_pdn_conn_rsp.cause.header, GTP_IE_CAUSE, IE_INSTANCE_ZERO,
			sizeof(struct cause_ie_hdr_t));
	del_pdn_conn_rsp.cause.cause_value = casue_value;

	uint16_t msg_len = 0;
	msg_len =  encode_del_pdn_conn_set_rsp(&del_pdn_conn_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
	return 0;
}

int8_t
process_del_pdn_conn_set_rsp_t(del_pdn_conn_set_rsp_t *del_pdn_rsp)
{
	if (del_pdn_rsp->cause.cause_value != GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
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
process_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *del_set_req,
		gtpv2c_header_t *gtpv2c_tx)
{
	RTE_SET_USED(del_set_req);
	RTE_SET_USED(gtpv2c_tx);
	return 0;
}

/* Function */
int
process_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *del_set_rsp)
{
	if(del_set_rsp->cause.cause_value != REQUESTACCEPTED){
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"ERROR:Cause received Session Set deletion response is %d\n",
				ERR_MSG, del_set_rsp->cause.cause_value);

		/* TODO: Add handling to send association to next upf
		 * for each buffered CSR */
		return -1;
	}
	return 0;
}

