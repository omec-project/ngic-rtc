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

#include "up_acl.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_llist.h"
#include "pfcp_association.h"
#include "clogger.h"
#include "gw_adapter.h"

extern struct in_addr dp_comm_ip;
extern struct in_addr cp_comm_ip;
extern struct rte_hash *node_id_hash;

#ifdef USE_CSID
/* TEMP fill the FQ-CSID form here */
/* PFCP: Create and Fill the FQ-CSIDs */
static void
est_set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids)
{
	fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;

	fq_csid->number_of_csids = 1;

	fq_csid->node_address = csids->node_addr;
	fq_csid->pdn_conn_set_ident[0] = csids->local_csid[csids->num_csid - 1];

	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID, (2 * (fq_csid->number_of_csids)) + 5);

}

int8_t
fill_fqcsid_sess_est_rsp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, pfcp_session_t *sess)
{

	/* Set SGW FQ-CSID */
	if (sess->sgwu_fqcsid) {
		if ((sess->sgwu_fqcsid)->num_csid) {
			est_set_fq_csid_t(&pfcp_sess_est_rsp->sgw_u_fqcsid, sess->sgwu_fqcsid);
			(pfcp_sess_est_rsp->sgw_u_fqcsid).node_address = dp_comm_ip.s_addr;
		}
	}

	/* Set PGW FQ-CSID */
	if (app.spgw_cfg == PGWU) {
		if (sess->pgwu_fqcsid) {
			if ((sess->pgwu_fqcsid)->num_csid) {
				est_set_fq_csid_t(&pfcp_sess_est_rsp->pgw_u_fqcsid, sess->pgwu_fqcsid);
				(pfcp_sess_est_rsp->pgw_u_fqcsid).node_address = dp_comm_ip.s_addr;
			}
		}
	}

	return 0;
}

int
fill_peer_node_info_t(pfcp_session_t *sess)
{
	int16_t csid = 0;
	csid_key peer_info_t = {0};

	/* MME FQ-CSID */
	if (sess->mme_fqcsid) {
		if ((sess->mme_fqcsid)->num_csid) {
			peer_info_t.mme_ip = (sess->mme_fqcsid)->node_addr;
		}
	}

	/* SGWC FQ-CSID */
	if (sess->sgw_fqcsid) {
		if ((sess->sgw_fqcsid)->num_csid) {
			peer_info_t.sgwc_ip = (sess->sgw_fqcsid)->node_addr;
		}
	} else {
		/* IF SGWC not support partial failure */
		if (app.spgw_cfg != PGWU) {
			peer_info_t.sgwc_ip = (sess->sgw_fqcsid)->node_addr;
		}
	}

	/* PGWC FQ-CSID */
	if (sess->pgw_fqcsid) {
		if ((sess->pgw_fqcsid)->num_csid) {
			peer_info_t.pgwc_ip = (sess->pgw_fqcsid)->node_addr;
		}
	} else {
		/* IF PGWC not support partial failure */
		if (app.spgw_cfg == PGWU) {
			peer_info_t.pgwc_ip = (sess->pgw_fqcsid)->node_addr;
		}
	}

	/* Fill the enodeb ID */
	peer_info_t.enodeb_ip = 0;

	/* SGW and PGW peer node info */
	if (app.spgw_cfg == SGWU) {
		peer_info_t.pgwc_ip = 0;
		peer_info_t.peer_csid =
			(sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid - 1];
	} else if (app.spgw_cfg == PGWU) {
		peer_info_t.sgwc_ip = 0;
		peer_info_t.peer_csid =
			(sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid - 1];
	}

	/* SGWU and PGWU peer node info */
	if (app.spgw_cfg != PGWU) {
		peer_info_t.sgwu_ip = dp_comm_ip.s_addr;
		peer_info_t.pgwu_ip = 0;
	} else {
		peer_info_t.sgwu_ip = 0;
		peer_info_t.pgwu_ip = dp_comm_ip.s_addr;
	}

	/* Get local csid for set of peer node */
	csid = get_csid_entry(&peer_info_t);
	if (csid < 0) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Failed to assinged CSID..\n", ERR_MSG);
		return -1;
	}

	/* Update the local csid into the UE context */
	uint8_t match = 0;
	if ((app.spgw_cfg == SGWU) || (app.spgw_cfg == SAEGWU)) {
		for(uint8_t itr = 0; itr < (sess->sgwu_fqcsid)->num_csid; itr++) {
			if ((sess->sgwu_fqcsid)->local_csid[itr] == csid)
				match = 1;
		}

		if (!match) {
			(sess->sgwu_fqcsid)->local_csid[(sess->sgwu_fqcsid)->num_csid++] =
				csid;
			match = 0;
		}
	} else {
		for(uint8_t itr = 0; itr < (sess->pgwu_fqcsid)->num_csid; itr++) {
			if ((sess->pgwu_fqcsid)->local_csid[itr] == csid)
				match = 1;
		}

		if (!match) {
			(sess->pgwu_fqcsid)->local_csid[(sess->pgwu_fqcsid)->num_csid++] =
				csid;
			match = 0;
		}
	}

	/* LINK SGW or PGW CSID with local CSID */
	if (sess->sgw_fqcsid) {
		if ((sess->sgw_fqcsid)->num_csid) {
			csid_t *tmp1 = NULL;
			if (app.spgw_cfg != PGWU) {
				tmp1 = get_peer_csid_entry(
						&(sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid - 1],
						SX_PORT_ID);
			} else {
				tmp1 = get_peer_csid_entry(
						&(sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid - 1],
						SX_PORT_ID);
			}
			if (tmp1 == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			/* Link local csid with SGW and PGW CSID */
			if (tmp1->local_csid == 0) {
				/* Update csid by mme csid */
				tmp1->local_csid = csid;
			} else if (tmp1->local_csid != csid) {
				/* TODO: handle condition like single MME CSID link with multiple local CSID  */
			}
		}
	}

	/* LINK SGW or PGW CSID with local CSID */
	if (sess->pgw_fqcsid) {
		if ((sess->pgw_fqcsid)->num_csid) {
			csid_t *tmp1 = NULL;
			if (app.spgw_cfg != PGWU) {
				tmp1 = get_peer_csid_entry(
						&(sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid - 1],
						SX_PORT_ID);
			} else {
				tmp1 = get_peer_csid_entry(
						&(sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid - 1],
						SX_PORT_ID);
			}
			if (tmp1 == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			/* Link local csid with SGW and PGW CSID */
			if (tmp1->local_csid == 0) {
				/* Update csid by mme csid */
				tmp1->local_csid = csid;
			} else if (tmp1->local_csid != csid) {
				/* TODO: handle condition like single MME CSID link with multiple local CSID  */
			}
		}
	}
	return 0;
}
#endif /* USE_CSID */

int8_t
process_up_assoc_req(pfcp_assn_setup_req_t *ass_setup_req,
			pfcp_assn_setup_rsp_t *ass_setup_resp)
{
	int offend_id = 0;
	uint8_t cause_id = 0;
	cause_check_association(ass_setup_req, &cause_id, &offend_id);

	// TODO: /handle hash error handling
	if (cause_id == REQUESTACCEPTED)
	{
		/* Adding NODE ID into nodeid hash in DP */
		int ret = 0;
		uint32_t value = 0;
		uint64_t *data = rte_zmalloc_socket(NULL, sizeof(uint8_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());

		if (data == NULL)
			rte_panic("Failure to allocate node id hash: "
					"%s (%s:%d)\n",
					rte_strerror(rte_errno),
					__FILE__,
					__LINE__);

		*data = NODE_ID_TYPE_TYPE_IPV4ADDRESS;
		memcpy(&value, ass_setup_req->node_id.node_id_value, IPV4_SIZE);

		uint32_t nodeid = (ntohl(value));
		clLog(clSystemLog, eCLSeverityDebug, "NODEID in INTERRFACE [%u]\n", nodeid);
		clLog(clSystemLog, eCLSeverityDebug, "DATA[%lu]\n", *data);

		ret = rte_hash_lookup_data(node_id_hash, (const void*) &(nodeid),
				(void **) &(data));
		if (ret == -ENOENT) {
			ret = add_node_id_hash(&nodeid, data);
		}

	}

	fill_pfcp_association_setup_resp(ass_setup_resp, cause_id);

	ass_setup_resp->header.seid_seqno.no_seid.seq_no =
		ass_setup_req->header.seid_seqno.no_seid.seq_no;
	return 0;
}

/**
 * @brief  : Process sdf filters
 * @param  : sdf_fltr_t , holds sdf filter data
 * @param  : sdf_fltr , update this strucutre using sdf filter data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_sdf_filters(pfcp_sdf_filter_ie_t *sdf_fltr_t, sdf_filter_t *sdf_fltr)
{
	if (sdf_fltr_t->fd) {
		/* len of flow description */
		sdf_fltr->len_of_flow_desc = sdf_fltr_t->len_of_flow_desc;

		sdf_fltr->fd = sdf_fltr_t->fd;
		/* flow description */
		memcpy(&sdf_fltr->flow_desc, sdf_fltr_t->flow_desc,
				sdf_fltr->len_of_flow_desc);
	}

	if (sdf_fltr_t->bid) {
		/* TODO:*/
	}

	if (sdf_fltr_t->fl) {
		/* TODO:*/
	}

	return 0;
}

/**
 * @brief  : Process ueip information
 * @param  : ue_addr, holds ue ip information
 * @param  : ue_addr_t, update this structure with ue ip info
 * @param  : ue_ip, copy ue ip address to this variable
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_ueip_info(pfcp_ue_ip_address_ie_t *ue_addr, ue_ip_addr_t *ue_addr_t,
				uint32_t *ue_ip)
{
	/* Check ipv4 address */
	if (ue_addr->v4) {
		/* UE IP Address */
		ue_addr_t->ipv4_address = ue_addr->ipv4_address;
		*ue_ip = ue_addr_t->ipv4_address;
	}

	/* Check the IPv6 Flag */
	if (ue_addr->v6) {
		/* TODO: IPv6 not Supported */
	}
	return 0;
}

/**
 * @brief  : Process pdi local teid info
 * @param  : lo_tied, hold information about local teid
 * @param  : f_teid, update this structure using local teid info
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_local_teid_info(pfcp_fteid_ie_t *lo_teid, fteid_ie_t *f_teid)
{
	/* Check the IPv4 Flag */
	if (lo_teid->v4) {
		/* TEID */
		f_teid->teid = lo_teid->teid;
		/* Local Interface IP address */
		f_teid->ipv4_address = lo_teid->ipv4_address;
	}

	/* Check the IPv6 Flag */
	if (lo_teid->v6) {
		/* TODO: IPv6 not Supported */

	}

	/* Check the chid Flag */
	if (lo_teid->chid) {
		/* TODO: Not Supported */
	}

	/* Check the CHOOSE Flag */
	if (lo_teid->ch) {
		/* TODO: Not supported */
	}

	return 0;
}

/**
 * @brief  : Process pdi info
 * @param  : pdi_ie_t, holds pdi information
 * @param  : pdi, structure to be updated
 * @param  : session, session information
 * @param  : prcdnc_val , precondition value
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdr_pdi_info(pfcp_pdi_ie_t *pdi_ie_t, pdi_t *pdi,
			pfcp_session_datat_t **session, uint32_t prcdnc_val)
{
	/* M: Source Interface */
	if (pdi_ie_t->src_intfc.header.len) {
		pdi->src_intfc.interface_value = pdi_ie_t->src_intfc.interface_value;
	}

	/* Local F-TEID */
	if (pdi_ie_t->local_fteid.header.len) {
		if (process_pdi_local_teid_info(&pdi_ie_t->local_fteid,
					&pdi->local_fteid)) {
			/* TODO:Error handling  */
		}
	}

	/* Network Instance */
	if (pdi_ie_t->ntwk_inst.header.len) {
		memcpy(pdi->ntwk_inst.ntwk_inst, pdi_ie_t->ntwk_inst.ntwk_inst,
				sizeof(ntwk_inst_t));
	}

	/* UE IP Address */
	if (pdi_ie_t->ue_ip_address.header.len) {
		if (process_pdi_ueip_info(&pdi_ie_t->ue_ip_address, &pdi->ue_addr,
						&((*session)->ue_ip_addr))) {
			/* TODO:Error handling  */
		}
	}

	/* SDF Filters */
	if (pdi_ie_t->sdf_filter_count > 0) {

		clLog(clSystemLog, eCLSeverityDebug, "Number of SDF Rule Rcv:%u\n",
				pdi_ie_t->sdf_filter_count);

		for (int itr = 0; itr < pdi_ie_t->sdf_filter_count; itr++) {
			if (pdi_ie_t->sdf_filter[itr].header.len) {
				/* Add SDF rule entry in the ACL TABLE */
				struct sdf_pkt_filter pkt_filter = {0};
				pkt_filter.precedence = prcdnc_val;


				if (process_pdi_sdf_filters(&pdi_ie_t->sdf_filter[itr],
							&pdi->sdf_filter[pdi->sdf_filter_cnt++])) {
					/* TODO:Error handling  */
				}

				/* Reset the rule string */
				memset(pkt_filter.u.rule_str, 0, MAX_LEN);

				/* flow description */
				if (pdi_ie_t->sdf_filter[itr].fd) {
					memcpy(&pkt_filter.u.rule_str, &pdi_ie_t->sdf_filter[itr].flow_desc,
							pdi_ie_t->sdf_filter[itr].len_of_flow_desc);

					if (!pdi_ie_t->src_intfc.interface_value) {
						/* swap the src and dst address for UL traffic.*/
						swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
					}

					if (!(*session)->acl_table_indx) {
						(*session)->acl_table_indx = get_acl_table_indx(&pkt_filter);
					} else {
						if (up_sdf_filter_entry_add((*session)->acl_table_indx, &pkt_filter)) {
							/* TODO: ERROR handling */
						}
					}
					if ((*session)->acl_table_indx <= 0) {
						/* TODO: ERROR Handling */
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"ACL table creation failed\n", ERR_MSG);
						(*session)->acl_table_indx = 0;
					}
				}
			}
		}
#ifdef DEFAULT_ACL_RULE_ADD
		uint8_t dir = 0;
		if (pdi_ie_t->src_intfc.interface_value) {
			dir = DOWNLINK;
		} else {
			dir = UPLINK;
		}

		if (up_sdf_default_entry_add((*session)->acl_table_indx, prcdnc_val, dir)) {
			/* TODO: ERROR Handling */
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add default rule \n", ERR_MSG);
		}
		pdi->sdf_filter_cnt++;
#endif /* DEFAULT_ACL_RULE_ADD */

		/* Update the SDF RULE COUNTER */
		//Commenting As this is incresing count by sdf_filter_count(No need)
		//pdi->sdf_filter_cnt += pdi_ie_t->sdf_filter_count;
	} else {

#ifdef DEFAULT_ACL_TABLE
		uint8_t dir = 0;
		if (pdi_ie_t->src_intfc.interface_value) {
			dir = DOWNLINK;
		} else {
			dir = UPLINK;
		}

		if (app.spgw_cfg != SGWU) {
			(*session)->acl_table_indx = default_up_filter_entry_add(prcdnc_val, dir);

			if (!(*session)->acl_table_indx) {
				/* TODO: ERROR Handling */
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"ACL table creation failed indx:%u\n", ERR_MSG,
					(*session)->acl_table_indx);
			}
			pdi->sdf_filter_cnt++;
		}
#endif  /* DEFAULT_ACL_TABLE */
	}
	return 0;
}

/**
 * @brief  : Process create urr info
 * @param  : urr, hold create urr info
 * @param  : urr_t, structure to be updated
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_urr_info(pfcp_create_urr_ie_t *urr, urr_info_t *urr_t)
{
	/* M : URR ID */
	/* M : Measurement Method */
	/* M : Reporting Triggers */
	/* TODO: Implement Handling */
	return 0;
}

/**
 * @brief  : Process create bar info
 * @param  : bar, hold create bar info
 * @param  : bar_t, structure to be updated
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_bar_info(pfcp_create_bar_ie_t *bar, bar_info_t *bar_t)
{
	/* M: BAR ID */
	/* Downlink Data Notification Delay */
	/* Suggested Buffering Packet Count */

	/* TODO: Implement Handling */
	return 0;
}

/**
 * @brief  : Process create qer info
 * @param  : qer, hold create qer info
 * @param  : quer_t, structure to be updated
 * @param  : session, session information
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_qer_info(pfcp_create_qer_ie_t *qer, qer_info_t **quer_t,
		pfcp_session_datat_t **session)
{
	qer_info_t *qer_t = NULL;
	/* M: QER ID */
	if (qer->qer_id.header.len) {
		/* Get allocated memory location */
		qer_t = get_qer_info_entry(qer->qer_id.qer_id_value, quer_t);
		if (qer_t == NULL)
			return -1;
	}

	/* M: Gate Status */
	if (qer->gate_status.header.len) {
		/* Uplink Action Allow/Drop */
		qer_t->gate_status.ul_gate = qer->gate_status.ul_gate;
		/* Downlink Action Allow/Drop */
		qer_t->gate_status.dl_gate = qer->gate_status.dl_gate;
	}

	/* QER Correlation ID */
	if (qer->qer_corr_id.header.len) {
		qer_t->qer_corr_id_val = qer->qer_corr_id.qer_corr_id_val;
	}

	/* MBR: Maximum Bitrate */
	if (qer->maximum_bitrate.header.len) {
		/* Maximum Bitrare allow on Uplink */
		qer_t->max_bitrate.ul_mbr = qer->maximum_bitrate.ul_mbr;
		/* Maximum Bitrare allow on Downlink */
		qer_t->max_bitrate.dl_mbr = qer->maximum_bitrate.dl_mbr;
	}

	/* GBR: Guaranteed Bitrate */
	if (qer->guaranteed_bitrate.header.len) {
		/* Guaranteed Bitrare allow on Uplink */
		qer_t->guaranteed_bitrate.ul_gbr = qer->guaranteed_bitrate.ul_gbr;
		/* Guaranteed Bitrare allow on Downlink */
		qer_t->guaranteed_bitrate.dl_gbr = qer->guaranteed_bitrate.dl_gbr;
	}

	/* Packet Rate */
	if (qer->packet_rate.header.len) {
		/* Check Uplink Packet Rate Flag */
		if (qer->packet_rate.ulpr) {
			/* Maximum Uplink Packet Rate */
			qer_t->packet_rate.max_uplnk_pckt_rate =
				qer->packet_rate.max_uplnk_pckt_rate;
			/* Uplink Time Unit */
			/* TODO: Need to think on it */
			qer_t->packet_rate.uplnk_time_unit =
				qer->packet_rate.uplnk_time_unit;
		}
		/* Check Downlink Packet Rate Flag */
		if (qer->packet_rate.dlpr) {
			/* Maximum Downlink Packet Rate */
			qer_t->packet_rate.max_dnlnk_pckt_rate =
				qer->packet_rate.max_dnlnk_pckt_rate;
			/* Downlink Time Unit */
			/* TODO: Need to think on it */
			qer_t->packet_rate.dnlnk_time_unit =
				qer->packet_rate.dnlnk_time_unit;
		}
	}

	/* Downlink Flow Level Marking */
	if (qer->dl_flow_lvl_marking.header.len) {
		/* Check ToS/Traffic Class Flag */
		if (qer->dl_flow_lvl_marking.ttc) {
			qer_t->dl_flow_lvl_marking.ttc =
				qer->dl_flow_lvl_marking.ttc;
			/* ToS/Traffic Class */
			qer_t->dl_flow_lvl_marking.tostraffic_cls =
				qer->dl_flow_lvl_marking.tostraffic_cls;
		}

		/* Check Service Class Indicator Flag */
		if (qer->dl_flow_lvl_marking.sci) {
			qer_t->dl_flow_lvl_marking.sci =
				qer->dl_flow_lvl_marking.sci;
			/* Service Class Indicator */
			qer_t->dl_flow_lvl_marking.svc_cls_indctr =
				qer->dl_flow_lvl_marking.svc_cls_indctr;
		}
	}

	/* QOS Flow Ident */
	if (qer->qos_flow_ident.header.len) {
		qer_t->qos_flow_ident.qfi_value = qer->qos_flow_ident.qfi_value;
	}

	/* RQI: Reflective QoS */
	if (qer->reflective_qos.header.len) {
		qer_t->reflective_qos.rqi = qer->reflective_qos.rqi;
	}

	/* Paging policy */
	if (qer->paging_plcy_indctr.header.len) {
		qer_t->paging_plcy_indctr.ppi_value = qer->paging_plcy_indctr.ppi_value;
	}

	/* Averaging Window */
	if (qer->avgng_wnd.header.len) {
		qer_t->avgng_wnd.avgng_wnd = qer->avgng_wnd.avgng_wnd;
	}

	/* Pointer to Sessions */
	qer_t->session = *session;

	return 0;
}

/**
 * @brief  : update far apply action
 * @param  : far, hold create far apply action info
 * @param  : far_t, structure to be updated
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
far_apply_action(pfcp_apply_action_ie_t *far, apply_action *far_t)
{
	/* M: Apply Action */
	if (far->header.len) {
		/* Duplicate the packets */
		far_t->dupl = far->dupl;
		/* Buffer the packets */
		far_t->buff = far->buff;
		/* Forward the packets */
		far_t->forw = far->forw;
		/* Drop the packets */
		far_t->drop = far->drop;
		/* Notify the CP function about arrival of a
		 * first downlink packet being buffered */
		far_t->nocp = far->nocp;
	}
	return 0;
}

/**
 * @brief  : Process create far info
 * @param  : far, hold create far info
 * @param  : session, session information
 * @param  : up_seid , session id
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_far_info(pfcp_create_far_ie_t *far,
		pfcp_session_datat_t **session, uint64_t up_seid)
{
	far_info_t *far_t = NULL;
	/* M: FAR ID */
	if (far->far_id.header.len) {
		/* Get allocated memory location */
		far_t = get_far_info_entry(far->far_id.far_id_value);

		if (far_t == NULL)
			return -1;
	}

	/* M: Apply Action */
	if (far->apply_action.header.len) {
		if (far_apply_action(&far->apply_action, &far_t->actions)) {
			/* TODO: Error Handling */
		}
	}

	/* Forwarding Parameters */
	if (far->frwdng_parms.header.len) {
		/* M: Destination Interface */
		if (far->frwdng_parms.dst_intfc.header.len) {
			/* Destination Interface */
			far_t->frwdng_parms.dst_intfc.interface_value =
				far->frwdng_parms.dst_intfc.interface_value;
		}

		/* Outer Header Creation */
		if (far->frwdng_parms.outer_hdr_creation.header.len) {
			/* TEID */
			far_t->frwdng_parms.outer_hdr_creation.teid =
				far->frwdng_parms.outer_hdr_creation.teid;
			clLog(clSystemLog, eCLSeverityDebug, "FAR Teid : %u\n",
					far_t->frwdng_parms.outer_hdr_creation.teid);

			/* Customer-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.ctag =
				far->frwdng_parms.outer_hdr_creation.ctag;

			/* Service-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.stag =
				far->frwdng_parms.outer_hdr_creation.stag;

			/* Port Number */
			far_t->frwdng_parms.outer_hdr_creation.port_number =
				far->frwdng_parms.outer_hdr_creation.port_number;

			/* IPv4 Address */
			far_t->frwdng_parms.outer_hdr_creation.ipv4_address =
				far->frwdng_parms.outer_hdr_creation.ipv4_address;

			clLog(clSystemLog, eCLSeverityDebug, "FAR dst Ipv4 Address :"IPV4_ADDR"\n",
					IPV4_ADDR_HOST_FORMAT(far_t->frwdng_parms.outer_hdr_creation.ipv4_address));

			/* Outer Header Creation Description */
			far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc =
				far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc;
		}
		if (far->frwdng_parms.dst_intfc.interface_value == ACCESS ) {
			/* VS: Add eNB peer node information in connection table */
			if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
				if ((add_node_conn_entry(ntohl(far->frwdng_parms.outer_hdr_creation.ipv4_address),
						up_seid, S1U_PORT_ID)) < 0) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT":Failed to add connection entry for eNB\n",
							ERR_MSG);
				}
#endif /* USE_REST */

				/* Update the Session state */
				if (far->frwdng_parms.outer_hdr_creation.teid != 0) {
					(*session)->sess_state = CONNECTED;
					clLog(clSystemLog, eCLSeverityDebug, "Session State Change : "
								"IN_PROGRESS --> CONNECTED\n");
				}
			}
		} else {
			/* VS: Add S5S8 peer node information in connection table */
			if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
				if ((add_node_conn_entry(ntohl(far->frwdng_parms.outer_hdr_creation.ipv4_address),
						up_seid, SGI_PORT_ID)) < 0) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT":Failed to add connection entry for S5S8\n",
							ERR_MSG);
				}
#endif /* USE_REST */

				/* Update the Session state */
				if (far->frwdng_parms.outer_hdr_creation.teid != 0) {
					(*session)->sess_state = CONNECTED;
					clLog(clSystemLog, eCLSeverityDebug, "Session State Change : "
								"IN_PROGRESS --> CONNECTED\n");
				}
			}
		}
	}

	/* Buffering Action Rule Identifier */
	if (far->bar_id.header.len) {
		/* TODO: Implement Handling */
	}

	/* Duplicating Parameters */
	if (far->dupng_parms_count > 0) {
		for (int itr = 0; itr < far->dupng_parms_count; itr++) {
			/* TODO: Implement Handling */
		}
	}

	/* Pointer to Session */
	far_t->session = *session;
	return 0;
}

static int8_t
process_update_pdr_info(pfcp_update_pdr_ie_t *pdr, pfcp_session_t *sess)
{
	int ret = 0;
	pfcp_session_datat_t *session = NULL;
	pdr_info_t *pdr_t = NULL;
	struct sdf_pkt_filter pkt_filter = {0};

	if (pdr->pdi.local_fteid.teid) {
		session = get_sess_by_teid_entry(pdr->pdi.local_fteid.teid,
										&sess->sessions, SESS_MODIFY);
		if (session == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for TEID:%u",
														pdr->pdi.local_fteid.teid);
			return -1;
		}
	} else if (pdr->pdi.ue_ip_address.ipv4_address){
		if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
			session = get_sess_by_ueip_entry(pdr->pdi.ue_ip_address.ipv4_address,
													&sess->sessions, SESS_MODIFY);

			if (session == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for UE_IP:"IPV4_ADDR"",
					IPV4_ADDR_HOST_FORMAT(pdr->pdi.ue_ip_address.ipv4_address));
				return -1;
			}
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical, "%s: TIED and UE_IP_addr both are NULL \n",
					__func__);
		return -1;
	}

	/* M: PDR ID */
	if (pdr->pdr_id.header.len) {
		ret = rte_hash_lookup_data(pdr_by_id_hash,
				&pdr->pdr_id.rule_id, (void **)&pdr_t);

		if ( ret < 0) {
			return -1;
		}
		if(pdr_t->rule_id != pdr->pdr_id.rule_id)
			return -1;
	}

	/*First remove older sdf context from acl rules*/
	for(int itr = 0; itr < pdr_t->pdi.sdf_filter_cnt; itr++){

		pkt_filter.precedence = pdr_t->prcdnc_val;
		/* Reset the rule string */
		memset(pkt_filter.u.rule_str, 0, MAX_LEN);

		/* flow description */
		if (pdr_t->pdi.sdf_filter[itr].fd) {
			memcpy(&pkt_filter.u.rule_str, &pdr_t->pdi.sdf_filter[itr].flow_desc,
					pdr_t->pdi.sdf_filter[itr].len_of_flow_desc);

			if (!pdr_t->pdi.src_intfc.interface_value) {
				/* swap the src and dst address for UL traffic.*/
				swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
			}

			if (!session->acl_table_indx) {
				return -1;
			} else {
				if (up_sdf_filter_entry_delete(session->acl_table_indx, &pkt_filter)) {
					/* TODO: ERROR handling */
				}
			}
		}
	}

	if (pdr->precedence.header.len) {
		pdr_t->prcdnc_val = pdr->precedence.prcdnc_val;
	}

	/* M: Packet Detection Information */
	if (pdr->pdi.header.len) {
		if (process_pdr_pdi_info(&pdr->pdi, &pdr_t->pdi, &session,
				pdr_t->prcdnc_val)) {
			/* TODO:Error handling  */
		}
	}
	return 0;
}

/**
 * @brief  : Process create pdr info
 * @param  : pdr, hold create pdr info
 * @param  : session, pfcp session data related info
 * @param  : sess , pfcp session info
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_pdr_info(pfcp_create_pdr_ie_t *pdr, pfcp_session_datat_t **session,
			pfcp_session_t *sess)
{
	pdr_info_t *pdr_t = NULL;

	/* M: PDR ID */
	if (pdr->pdr_id.header.len) {
		pdr_t = get_pdr_info_entry(pdr->pdr_id.rule_id, &(*session)->pdrs);
		if (pdr_t == NULL)
			return -1;
		pdr_t->rule_id = pdr->pdr_id.rule_id;
	}

	/* M: Precedance */
	if (pdr->precedence.header.len) {
		pdr_t->prcdnc_val = pdr->precedence.prcdnc_val;
	}

	/* M: Packet Detection Information */
	if (pdr->pdi.header.len) {
		if (process_pdr_pdi_info(&pdr->pdi, &pdr_t->pdi, session,
				pdr_t->prcdnc_val)) {
			/* TODO:Error handling  */
		}
	}

	/* Forwarding Action Rule (FAR ID) Identifer */
	if (pdr->far_id.header.len) {
		/* Add FAR ID entry in the hash table */
		if (add_far_info_entry(pdr->far_id.far_id_value, &pdr_t->far)) {
			/* TODO: Error handling */
		}
		(pdr_t->far)->far_id_value = pdr->far_id.far_id_value;
	}

	/* QoS Enforcement Rule (QER ID) Identifiers */
	if (pdr->qer_id_count > 0) {
		pdr_t->qer_count = pdr->qer_id_count;
		for (int itr = 0; itr < pdr_t->qer_count; itr++) {
			/* Add QER ID entry in the hash table */
			if (add_qer_info_entry(pdr->qer_id[itr].qer_id_value, &pdr_t->quer)) {
				/* TODO: Error handling */
			}
			(pdr_t->quer[itr]).qer_id = pdr->qer_id[itr].qer_id_value;
		}
	}

	/* Usage Reporting Rule (URR ID) Identifiers */
	if (pdr->urr_id_count > 0) {
		pdr_t->urr_count = pdr->urr_id_count;
		for (int itr = 0; itr < pdr_t->urr_count; itr++) {
			/* Add URR ID entry in the hash table */
			if (add_urr_info_entry(pdr->urr_id[itr].urr_id_value, &pdr_t->urr)) {
				/* TODO: Error handling */
			}
			(pdr_t->urr[itr]).urr_id = pdr->urr_id[itr].urr_id_value;
		}
	}

	/* Predefine Rules */
	if (pdr->actvt_predef_rules_count > 0) {
		pdr_t->predef_rules_count = pdr->actvt_predef_rules_count;
		for (int itr = 0; itr < pdr_t->predef_rules_count; itr++) {
			/* Add predefine rule entry in the table */
				/* TODO: Implement handling */
		}

	}

	clLog(clSystemLog, eCLSeverityInfo, "Entry Add PDR_ID:%u, precedence:%u, ACL_TABLE_INDX:%u\n",
			pdr->pdr_id.rule_id, pdr->precedence.prcdnc_val,
			(*session)->acl_table_indx);

	/* pointer to the session */
	pdr_t->session = sess;
	return 0;
}

//static int8_t
//process_pdr_info()

int8_t
process_up_session_estab_req(pfcp_sess_estab_req_t *sess_req,
				pfcp_sess_estab_rsp_t *sess_rsp)
{
	pfcp_session_t *sess = NULL;

	if (sess_req == NULL)
		return -1;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Establishment Request :: START \n");
	/* Check Session ID is present or not in header */
	if (sess_req->header.s) {
		/* Check SEID is not ZERO */
		if (sess_req->header.seid_seqno.has_seid.seid != 0) {
			sess = get_sess_info_entry(sess_req->header.seid_seqno.has_seid.seid,
					SESS_CREATE);
		} else {
			/* Generate the Session ID for UP */
			sess = get_sess_info_entry(
					gen_up_sess_id(sess_req->cp_fseid.seid),
					SESS_CREATE);
		}
	} else {
		/* Generate the Session ID for UP */
		sess = get_sess_info_entry(gen_up_sess_id(0),
				SESS_CREATE);
	}

	if (sess == NULL)
		return -1;

	/* Get the Bearer Id  */
	//uint8_t bearer_id = UE_BEAR_ID(sess_req->cp_fseid.seid);

	/* Get the CP Session Id  */
	//sess->cp_seid = UE_SESS_ID(sess_req->cp_fseid.seid);
	sess->cp_seid = sess_req->cp_fseid.seid;

	clLog(clSystemLog, eCLSeverityDebug, "%s: CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			__func__, sess->cp_seid, sess->up_seid);

	/* TODO: Export this function to make it generic across the establishment and modify request */
	/* Fill the info from PDR */
	for (int itr = 0; itr < sess_req->create_pdr_count; itr++) {
		pfcp_session_datat_t *session = NULL;

		if (sess_req->create_pdr[itr].pdi.local_fteid.teid) {
			session = get_sess_by_teid_entry(sess_req->create_pdr[itr].pdi.local_fteid.teid,
					&sess->sessions, SESS_CREATE);
			if (session == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for TEID:%u",
						sess_req->create_pdr[itr].pdi.local_fteid.teid);
				continue;
			}
		} else if (sess_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address){
			if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
				session = get_sess_by_ueip_entry(sess_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address,
						&sess->sessions, SESS_CREATE);

				if (session == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for UE_IP:"IPV4_ADDR"",
						IPV4_ADDR_HOST_FORMAT(sess_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address));
					continue;
				}
			}
		} else {
			clLog(clSystemLog, eCLSeverityCritical, "%s: TIED and UE_IP_addr both are NULL \n",
					__func__);
			return -1;
		}


		/* VS: Update the Session state */
		session->sess_state = IN_PROGRESS;

		/* Process the Create PDR info */
		if (process_create_pdr_info(&sess_req->create_pdr[itr],
					&session, sess)) {
			/* TODO: Error Handling */
		}

		for (int itr1 = 0; itr1 < sess_req->create_far_count; itr1++) {
			if (sess_req->create_pdr[itr].far_id.far_id_value ==
					sess_req->create_far[itr1].far_id.far_id_value) {
				/* Process the Create FAR info */
				if (process_create_far_info(&sess_req->create_far[itr1],
						&session, sess->up_seid)) {
					/* TODO: Error Handling */

				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr2 = 0; itr2 < sess_req->create_pdr[itr].qer_id_count; itr2++) {
			for (int itr3 = 0; itr3 < sess_req->create_qer_count; itr3++) {
				if (sess_req->create_pdr[itr].qer_id[itr2].qer_id_value ==
						sess_req->create_qer[itr3].qer_id.qer_id_value) {

					if (process_create_qer_info(&sess_req->create_qer[itr3],
								&(session->pdrs[itr]).quer, &session)) {
						/* TODO: Error Handling */
					}
				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr3 = 0; itr3 < sess_req->create_pdr[itr].urr_id_count; itr3++) {
			for (int itr4 = 0; itr4 < sess_req->create_urr_count; itr4++) {
				if (sess_req->create_pdr[itr].urr_id[itr3].urr_id_value ==
						sess_req->create_urr[itr4].urr_id.urr_id_value) {

					urr_info_t urr = {0};
					/* VS: Process the Create URR info */
					if (process_create_urr_info(&sess_req->create_urr[itr3],
								&urr)) {
						/* TODO: Error Handling */
					}
					/* VS: Function to add a node in URR Linked List. */
					if (insert_urr_node((session->pdrs[itr]).urr, &urr)) {
						/* TODO: Error Handling */
					}
				}
			}
		}

		/* Maintain the teids in session level  */
		if (sess_req->create_pdr[itr].pdi.local_fteid.teid) {
			sess->teids[sess->ber_cnt] = sess_req->create_pdr[itr].pdi.local_fteid.teid;
			sess->ber_cnt++;
		}
	}

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	if (app.spgw_cfg != PGWU) {
		sess->sgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (sess->sgw_fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
					ERR_MSG);
			return -1;
		}
	}

	if (app.spgw_cfg != SAEGWU) {
		sess->pgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (sess->pgw_fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
					ERR_MSG);
			return -1;
		}
	}

	/* MME FQ-CSID */
	if (sess_req->mme_fqcsid.header.len) {
		sess->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (sess->mme_fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
					ERR_MSG);
			return -1;
		}

		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(sess_req->mme_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = sess_req->mme_fqcsid.node_address;

		for(uint8_t itr = 0; itr < sess_req->mme_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == sess_req->mme_fqcsid.pdn_conn_set_ident[itr])
					match = 1;
			}

			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					sess_req->mme_fqcsid.pdn_conn_set_ident[itr];
			}
		}
		memcpy(sess->mme_fqcsid, tmp, sizeof(fqcsid_t));
	}

	/* SGW FQ-CSID */
	if (sess_req->sgw_c_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(sess_req->sgw_c_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		tmp->node_addr = sess_req->sgw_c_fqcsid.node_address;

		for(uint8_t itr = 0; itr < sess_req->sgw_c_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == sess_req->sgw_c_fqcsid.pdn_conn_set_ident[itr])
					match = 1;
			}

			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					sess_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
		}
		memcpy(sess->sgw_fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		if ((app.spgw_cfg == SGWU) || (app.spgw_cfg == SAEGWU)) {
			sess->sgw_fqcsid = get_peer_addr_csids_entry(cp_comm_ip.s_addr,
					ADD);
			if (sess->sgw_fqcsid == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			tmp->node_addr = cp_comm_ip.s_addr;
			memcpy(sess->sgw_fqcsid, tmp, sizeof(fqcsid_t));
		}
	}

	/* PGW FQ-CSID */
	if (sess_req->pgw_c_fqcsid.header.len) {
		/* Stored the PGW CSID by SGW Node address */
		tmp = get_peer_addr_csids_entry(sess_req->pgw_c_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		tmp->node_addr = sess_req->pgw_c_fqcsid.node_address;

		for(uint8_t itr = 0; itr < sess_req->pgw_c_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == sess_req->pgw_c_fqcsid.pdn_conn_set_ident[itr])
					match = 1;
			}

			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					sess_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
		}
		memcpy(sess->pgw_fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		if (app.spgw_cfg == PGWU)  {
			sess->pgw_fqcsid = get_peer_addr_csids_entry(cp_comm_ip.s_addr,
					ADD);
			if (sess->pgw_fqcsid == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			tmp->node_addr = cp_comm_ip.s_addr;
			memcpy(sess->pgw_fqcsid, tmp, sizeof(fqcsid_t));
		}
	}

	if (app.spgw_cfg != PGWU) {
		sess->sgwu_fqcsid = get_peer_addr_csids_entry(dp_comm_ip.s_addr,
				ADD);
		if (sess->sgwu_fqcsid == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		(sess->sgwu_fqcsid)->node_addr = dp_comm_ip.s_addr;

	} else {
		sess->pgwu_fqcsid = get_peer_addr_csids_entry(dp_comm_ip.s_addr,
				ADD);
		if (sess->pgwu_fqcsid == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		(sess->pgwu_fqcsid)->node_addr = dp_comm_ip.s_addr;
	}

	/* Add the entry for peer nodes */
	if (fill_peer_node_info_t(sess)) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
				ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp1 = NULL;
	if ((app.spgw_cfg == SGWU) || (app.spgw_cfg == SAEGWU)) {
		tmp1 = get_sess_csid_entry(
				(sess->sgwu_fqcsid)->local_csid[(sess->sgwu_fqcsid)->num_csid - 1]);
	} else {
		/* PGWC */
		tmp1 = get_sess_csid_entry(
				(sess->pgwu_fqcsid)->local_csid[(sess->pgwu_fqcsid)->num_csid - 1]);
	}

	if (tmp1 == NULL) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Link local csid with session id */
	tmp1->cp_seid[tmp1->seid_cnt++] = sess->cp_seid;
	tmp1->up_seid[tmp1->seid_cnt - 1] = sess->up_seid;

	/* Fill the fqcsid into the session est request */
	if (fill_fqcsid_sess_est_rsp(sess_rsp, sess)) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Failed to fill FQ-CSID in Sess EST Resp ERROR: %s\n",
				ERR_MSG,
				strerror(errno));
		return -1;
	}
#endif /* USE_CSID */

	/* Update the UP session id in the response */
	sess_rsp->up_fseid.seid = sess->up_seid;
	/* TODO: Need to be remove */
	sess_req->header.seid_seqno.has_seid.seid = sess->up_seid;

	/* Update the CP seid in the response packet */
	sess_rsp->header.seid_seqno.has_seid.seid = sess->cp_seid;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Establishment Request :: END \n\n");
	return 0;
}

/**
 * @brief  : Process update far info
 * @param  : far, hold create far info
 * @param  : up_seid, session id
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_update_far_info(pfcp_update_far_ie_t *far, uint64_t up_seid)
{
	far_info_t *far_t = NULL;

	/* M: FAR ID */
	if (far->far_id.header.len) {
		/* Get allocated memory location */
		far_t = get_far_info_entry(far->far_id.far_id_value);
	}

	/* Check far entry found or not */
	if (far_t == NULL)
		return -1;

	/* M: Apply Action */
	if (far->apply_action.header.len) {
		if (far_apply_action(&far->apply_action, &far_t->actions)) {
			/* TODO: Error Handling */
		}
	}

	/* Update Forwarding Parameters */
	if (far->upd_frwdng_parms.header.len) {
		/* pfcpsmreq_flags: */
		if (far->upd_frwdng_parms.pfcpsmreq_flags.header.len) {

			/* X2 Handover: Send the endmarker packet to old eNB*/
			if (far->upd_frwdng_parms.pfcpsmreq_flags.sndem) {
				if (sess_modify_with_endmarker(far_t)) {
					/* TODO: ERROR Handling */
				}
			}
		}

		/* M: Destination Interface */
		if (far->upd_frwdng_parms.dst_intfc.header.len) {
			/* Destination Interface */
			far_t->frwdng_parms.dst_intfc.interface_value =
				far->upd_frwdng_parms.dst_intfc.interface_value;
		}

		/* Outer Header Creation */
		if (far->upd_frwdng_parms.outer_hdr_creation.header.len) {
			/* TEID */
			far_t->frwdng_parms.outer_hdr_creation.teid =
				far->upd_frwdng_parms.outer_hdr_creation.teid;
			clLog(clSystemLog, eCLSeverityDebug, "FAR Teid : %u\n",
					far->upd_frwdng_parms.outer_hdr_creation.teid);

			/* Customer-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.ctag =
				far->upd_frwdng_parms.outer_hdr_creation.ctag;

			/* Service-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.stag =
				far->upd_frwdng_parms.outer_hdr_creation.stag;

			/* Port Number */
			far_t->frwdng_parms.outer_hdr_creation.port_number =
				far->upd_frwdng_parms.outer_hdr_creation.port_number;

			/* IPv4 Address */
			far_t->frwdng_parms.outer_hdr_creation.ipv4_address =
				far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;
			clLog(clSystemLog, eCLSeverityDebug, "FAR dst Ipv4 Address :"IPV4_ADDR"\n",
					IPV4_ADDR_HOST_FORMAT(far->upd_frwdng_parms.outer_hdr_creation.ipv4_address));

			/* Outer Header Creation Description */
			far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc =
				far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc;
		}

		if (far->upd_frwdng_parms.dst_intfc.interface_value == ACCESS ) {
			/* VS: Add eNB peer node information in connection table */
			if (far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
				if ((add_node_conn_entry(ntohl(far->upd_frwdng_parms.outer_hdr_creation.ipv4_address),
						up_seid, S1U_PORT_ID)) < 0) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT":Failed to add connection entry for eNB\n",
							ERR_MSG);
				}
#endif /* USE_REST */

				/* Update the Session state */
				if (!far->upd_frwdng_parms.outer_hdr_creation.teid) {
					if ((far_t->session)->sess_state == CONNECTED) {
						(far_t->session)->sess_state = IDLE;
						clLog(clSystemLog, eCLSeverityDebug, "Session State Change : "
									"CONNECTED --> IDLE\n");
					}
				} else {
					switch((far_t->session)->sess_state) {
					case IDLE:
						{
							(far_t->session)->sess_state = CONNECTED;
							clLog(clSystemLog, eCLSeverityDebug, "Session State Change : "
										"IDLE --> CONNECTED\n");
						}
						break;
					case IN_PROGRESS:
						{
						/**VS: Resolved queued pkts by dl core and enqueue pkts into notification ring */
							struct rte_mbuf *buf_pkt =
								rte_ctrlmbuf_alloc(notify_msg_pool);
							uint32_t *key =
								rte_pktmbuf_mtod(buf_pkt, uint32_t *);

							if (app.spgw_cfg == SGWU) {
								if ((far_t->session)->pdrs) {
									*key = (far_t->session)->pdrs->pdi.local_fteid.teid;
								} else {
									clLog(clSystemLog, eCLSeverityDebug, FORMAT"ERROR: PDRs value is NULL\n", ERR_MSG);
									break;
								}
							} else {
								if ((far_t->session)->ue_ip_addr) {
									*key = (far_t->session)->ue_ip_addr;
								} else {
									clLog(clSystemLog, eCLSeverityDebug, FORMAT"ERROR: UE_IP value is NULL\n", ERR_MSG);
									break;
								}
							}

							rte_ring_enqueue(notify_ring,
							        buf_pkt);

							(far_t->session)->sess_state = CONNECTED;
							clLog(clSystemLog, eCLSeverityDebug, "Session State Change : "
										"IN_PROGRESS --> CONNECTED\n");
						}
						break;
					default:
						clLog(clSystemLog, eCLSeverityDebug, "No state change\n");
					}
				}
			}
		} else {
			/* VS: Add S5S8 peer node information in connection table */
			if (far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
				if ((add_node_conn_entry(ntohl(far->upd_frwdng_parms.outer_hdr_creation.ipv4_address),
						up_seid, SGI_PORT_ID)) < 0) {
					clLog(clSystemLog, eCLSeverityCritical, "%s:%d:Failed to add connection entry for S5S8\n",
							 __func__, __LINE__);
				}
#endif /* USE_REST */

				/* Update the Session state */
				if (far->upd_frwdng_parms.outer_hdr_creation.teid != 0) {
					(far_t->session)->sess_state = CONNECTED;
				}
			}

		}
	}

	/* Buffering Action Rule Identifier */
	if (far->bar_id.header.len) {
		/* TODO: Implement Handling */
	}

	/* Duplicating Parameters */
	if (far->upd_dupng_parms_count > 0) {
		for (int itr = 0; itr < far->upd_dupng_parms_count; itr++) {
			/* TODO: Implement Handling */
		}
	}

	return 0;
}


int8_t
process_remove_pdr_sess(pfcp_remove_pdr_ie_t *remove_pdr, uint64_t up_seid)
{
	int ret = 0;
	uint8_t uiFlag = 0;
	pfcp_session_t *sess = NULL;
	struct sdf_pkt_filter pkt_filter = {0};

	/* Get the session information from session table based on UP_SESSION_ID*/
	sess = get_sess_info_entry(up_seid, SESS_MODIFY);

	if (sess == NULL)
		return -1;

	/* Flush the Session data info from the hash tables based on teid*/
	pfcp_session_datat_t *session = sess->sessions;
	/* Cleanup the session data form hash table and delete the node from linked list */
	while (NULL != session) {
		/* Cleanup PDRs info from the linked list */
		pdr_info_t *pdr = session->pdrs;
		while (NULL != pdr) {
			if (remove_pdr->pdr_id.rule_id == pdr->rule_id) {
				pdr = get_pdr_info_entry(
					remove_pdr->pdr_id.rule_id,
					NULL);
				if (pdr == NULL)
					return -1;

				//Remove Entry from ACL Table
				for(int itr = 0; itr < pdr->pdi.sdf_filter_cnt; itr++){

					pkt_filter.precedence = pdr->prcdnc_val;
					/* Reset the rule string */
					memset(pkt_filter.u.rule_str, 0, MAX_LEN);

					/* flow description */
					if (pdr->pdi.sdf_filter[itr].fd) {
						memcpy(&pkt_filter.u.rule_str, &pdr->pdi.sdf_filter[itr].flow_desc,
										pdr->pdi.sdf_filter[itr].len_of_flow_desc);

						if (!pdr->pdi.src_intfc.interface_value) {
							/* swap the src and dst address for UL traffic.*/
							swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
						}

						if (session->acl_table_indx)
							remove_rule_entry_acl(session->acl_table_indx, &pkt_filter);
					}
				}


				far_info_t *far = pdr->far;
				/* Cleanup the FAR information */
				if (far != NULL) {
#ifdef USE_REST
					if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0)
						dp_flush_session(
							ntohl(far->frwdng_parms.outer_hdr_creation.ipv4_address),
							sess->up_seid);
#endif /* USE_REST */

					/* Flush the far info from the hash table */
					ret = rte_hash_del_key(far_by_id_hash, &far->far_id_value);
					if ( ret < 0) {
						clLog(clSystemLog, eCLSeverityDebug,
							"DP:"FORMAT"Entry not found for FAR_ID:%u...\n",
							ERR_MSG, far->far_id_value);
						return -1;
					}
				}

				/* Cleanup QERs info from the linked list */
				qer_info_t *qer = pdr->quer;
				while (qer != NULL) {
					/* Get QER ID */
					uint32_t qer_id = qer->qer_id;

					/* Delete the QER info node from the linked list */
					pdr->quer = remove_qer_node(pdr->quer, qer);
					qer = pdr->quer;

					/* Flush the QER info from the hash table */
					ret = rte_hash_del_key(qer_by_id_hash, &qer_id);
					if ( ret < 0) {
						clLog(clSystemLog, eCLSeverityDebug,
							FORMAT"Entry not found for QER_ID:%u...\n",
									ERR_MSG, qer_id);
						return -1;
					}
				}

				/* Cleanup URRs info from the linked list */
				urr_info_t *urr = pdr->urr;
				while (urr != NULL) {
					/* Get URR ID */
					uint32_t urr_id = urr->urr_id;

					/* Delete the URR info node from the linked list */
					pdr->urr = remove_urr_node(pdr->urr, urr);
					urr = pdr->urr;

					/* Flush the URR info from the hash table */
					if (del_urr_info_entry(urr_id)) {
						/* TODO : ERROR Handling */
					}
				}

				if (pdr->pdi.local_fteid.teid) {
					if (del_sess_by_teid_entry(pdr->pdi.local_fteid.teid)) {
						/* TODO : ERROR Handling */
					}else{
						for (int itr1 = 0; itr1 < sess->ber_cnt; itr1++) {
							if (pdr->pdi.local_fteid.teid == sess->teids[itr1]) {
								sess->teids[itr1] = 0;
							}
						}

					}
				}

				/* Cleanup PDRs info from the linked list */
				/* Get PDR ID */
				uint32_t pdr_id = pdr->rule_id;

				/* Delete the PDR info node from the linked list */
				session->pdrs = remove_pdr_node(session->pdrs, pdr);

				/* Flush the PDR info from the hash table */
				ret = rte_hash_del_key(pdr_by_id_hash, &pdr_id);
				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityDebug,
						FORMAT"Entry not found for PDR_ID:%u...\n",
								ERR_MSG, pdr_id);
					return -1;
				}

				uiFlag = 1;
				pdr = session->pdrs;
				continue;
			}

			pdr = pdr->next;
		}

		if ((1 == uiFlag) && (NULL == session->pdrs)) {
			/* Delete the Session data info node from the linked list */
			sess->sessions = remove_sess_data_node(sess->sessions, session);
			if (sess->sessions != NULL) {
				session = sess->sessions;
			}
			uiFlag = 0;
		} else {
			session = session->next;
		}
	}

	return 0;
}

int8_t
process_up_session_modification_req(pfcp_sess_mod_req_t *sess_mod_req,
					pfcp_sess_mod_rsp_t *sess_mod_rsp)
{
	pfcp_session_t *sess = NULL;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Modification Request :: START \n");
	/* Get the session information from session table based on UP_SESSION_ID*/
	if (sess_mod_req->header.s) {
		/* Check SEID is not ZERO */
		sess = get_sess_info_entry(sess_mod_req->header.seid_seqno.has_seid.seid,
				SESS_MODIFY);
	}

	if (sess == NULL)
		return -1;

	/* pfcpsmreq_flags: Dropped the bufferd packets  */
	if (sess_mod_req->pfcpsmreq_flags.drobu) {
		/* Free the downlink data rings */
		//rte_free();

	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			__func__, sess->cp_seid, sess->up_seid);

	/* TODO: Export this function to make it generic across the establishment and modify request */
	/* Fill the info from PDR */
	for (int itr = 0; itr < sess_mod_req->create_pdr_count; itr++) {
		pfcp_session_datat_t *session = NULL;

		if (sess_mod_req->create_pdr[itr].pdi.local_fteid.teid) {
			session = get_sess_by_teid_entry(sess_mod_req->create_pdr[itr].pdi.local_fteid.teid,
					&sess->sessions, SESS_CREATE);
			if (session == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for TEID:%u",
						sess_mod_req->create_pdr[itr].pdi.local_fteid.teid);
				continue;
			}
		} else if (sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address){
			if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
				session = get_sess_by_ueip_entry(sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address,
						&sess->sessions, SESS_CREATE);

				if (session == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, "Failed to create the session for UE_IP:"IPV4_ADDR"",
						IPV4_ADDR_HOST_FORMAT(sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address));
					continue;
				}
			}
		} else {
			clLog(clSystemLog, eCLSeverityCritical, "%s: TIED and UE_IP_addr both are NULL \n",
					__func__);
			return -1;
		}


		/* VS: Update the Session state */
		session->sess_state = IN_PROGRESS;

		/* Process the Create PDR info */
		if (process_create_pdr_info(&sess_mod_req->create_pdr[itr],
					&session, sess)) {
			/* TODO: Error Handling */
		}

		/* TODO: Remove the loops */
		for (int itr1 = 0; itr1 < sess_mod_req->create_far_count; itr1++) {
			if (sess_mod_req->create_pdr[itr].far_id.far_id_value ==
					sess_mod_req->create_far[itr1].far_id.far_id_value) {
				/* Process the Create FAR info */
				if (process_create_far_info(&sess_mod_req->create_far[itr1],
						&session, sess->up_seid)) {
					/* TODO: Error Handling */

				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr2 = 0; itr2 < sess_mod_req->create_pdr[itr].qer_id_count; itr2++) {
			for (int itr3 = 0; itr3 < sess_mod_req->create_qer_count; itr3++) {
				if (sess_mod_req->create_pdr[itr].qer_id[itr2].qer_id_value ==
						sess_mod_req->create_qer[itr3].qer_id.qer_id_value) {

					if (process_create_qer_info(&sess_mod_req->create_qer[itr3],
								&(session->pdrs[itr]).quer, &session)) {
						/* TODO: Error Handling */
					}
				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr3 = 0; itr3 < sess_mod_req->create_pdr[itr].urr_id_count; itr3++) {
			for (int itr4 = 0; itr4 < sess_mod_req->create_urr_count; itr4++) {
				if (sess_mod_req->create_pdr[itr].urr_id[itr3].urr_id_value ==
						sess_mod_req->create_urr[itr4].urr_id.urr_id_value) {

					urr_info_t urr = {0};
					/* VS: Process the Create URR info */
					if (process_create_urr_info(&sess_mod_req->create_urr[itr3],
								&urr)) {
						/* TODO: Error Handling */
					}
					/* VS: Function to add a node in URR Linked List. */
					if (insert_urr_node((session->pdrs[itr]).urr, &urr)) {
						/* TODO: Error Handling */
					}
				}
			}
		}

		/* Maintain the teids in session level  */
		if (sess_mod_req->create_pdr[itr].pdi.local_fteid.teid) {
			sess->teids[sess->ber_cnt] = sess_mod_req->create_pdr[itr].pdi.local_fteid.teid;
			sess->ber_cnt++;
		}
	}


	/* TODO::::: */
	/* Process the Update FAR information */
	for (int itr = 0; itr < sess_mod_req->update_far_count; itr++) {
		if (process_update_far_info(&sess_mod_req->update_far[itr],
					sess->up_seid)) {
			/* TODO: Error Handling */
			return -1;
		}
	}

	for(int itr = 0; itr < sess_mod_req->update_pdr_count; itr++ ){
		/* VK : Process the Update PDR info */
		if(process_update_pdr_info(&sess_mod_req->update_pdr[itr], sess)){
				/* TODO: Error Handling */
		}
	}

	/* Process the Remove PDR information */
	for (int itr = 0; itr < sess_mod_req->remove_pdr_count; itr++) {
		if (process_remove_pdr_sess(&sess_mod_req->remove_pdr[itr], sess->up_seid)) {
			/* TODO: Error Handling */
			return -1;
		}
	}

#ifdef USE_CSID
	/* SGW FQ-CSID */
	if (sess_mod_req->sgw_c_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		sess->sgw_fqcsid = get_peer_addr_csids_entry(sess_mod_req->sgw_c_fqcsid.node_address,
				ADD);

		if (sess->sgw_fqcsid == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		(sess->sgw_fqcsid)->node_addr = sess_mod_req->sgw_c_fqcsid.node_address;

		for(uint8_t itr = 0; itr < sess_mod_req->sgw_c_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < (sess->sgw_fqcsid)->num_csid; itr1++) {
				if ((sess->sgw_fqcsid)->local_csid[itr1] == sess_mod_req->sgw_c_fqcsid.pdn_conn_set_ident[itr])
					match = 1;
			}

			if (!match) {
				(sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid++] =
					sess_mod_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
		}
	}

	/* PGW FQ-CSID */
	if (sess_mod_req->pgw_c_fqcsid.header.len) {
		/* Stored the SGW CSID by SGW Node address */
		sess->pgw_fqcsid = get_peer_addr_csids_entry(sess_mod_req->pgw_c_fqcsid.node_address,
				ADD);

		if (sess->pgw_fqcsid == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		(sess->pgw_fqcsid)->node_addr = sess_mod_req->pgw_c_fqcsid.node_address;

		for(uint8_t itr = 0; itr < sess_mod_req->pgw_c_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < (sess->pgw_fqcsid)->num_csid; itr1++) {
				if ((sess->pgw_fqcsid)->local_csid[itr1] == sess_mod_req->pgw_c_fqcsid.pdn_conn_set_ident[itr])
					match = 1;
			}

			if (!match) {
				(sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid++] =
					sess_mod_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
		}
	}
#endif /* USE_CSID */
	/* Update the CP seid in the response packet */
	sess_mod_rsp->header.seid_seqno.has_seid.seid =	sess->cp_seid;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Modification Request :: END \n\n");
	return 0;
}

int8_t
up_delete_session_entry(pfcp_session_t *sess)
{
	int ret = 0;
	int8_t inx = 0;
	uint32_t ue_ip[MAX_BEARERS] = {0};

	clLog(clSystemLog, eCLSeverityDebug, "%s: CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			__func__, sess->cp_seid, sess->up_seid);
	/* Flush the Session data info from the hash tables based on teid*/
	pfcp_session_datat_t *session = sess->sessions;

	/* Cleanup the session data form hash table and delete the node from linked list */
	while (session != NULL) {
			if (session->dl_ring != NULL) {
			struct rte_ring *ring = session->dl_ring;

			session->dl_ring = NULL;
			/* This is going to be nasty. We could potentially have a race
			 * condition if modify bearer occurs directly before a delete
			 * session, causing scan_notify_ring_func to work on the same
			 * ring as this function. For our current tests, we *should* be
			 * okay. For now.
			 */

			int i = 0;
			int ret = 0;
			int count = 0;
			struct rte_mbuf *m[MAX_BURST_SZ];

			do {

		 /* VS: Adding handling for support dpdk-18.02 and dpdk-16.11.04 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
				ret = rte_ring_sc_dequeue_burst(ring,
				        (void **)m, MAX_BURST_SZ);
#elif (RTE_VER_YEAR >= 18) && (RTE_VER_MONTH >= 02)
				unsigned int *ring_entry = NULL;

				/* VS: Adding handling for support dpdk-18.02 */
				ret = rte_ring_sc_dequeue_burst(ring,
				        (void **)m, MAX_BURST_SZ, ring_entry);
#endif

				for (i = 0; i < ret; ++i)
				    rte_pktmbuf_free(m[i]);
				count += ret;
			} while (ret);

			if (rte_ring_enqueue(dl_ring_container, ring) ==
			        ENOBUFS) {
			    clLog(clSystemLog, eCLSeverityCritical, "Can't put ring back, so free it - "
			            "dropped %d pkts\n", count);
			    rte_ring_free(ring);
			}
		}

		/* Cleanup PDRs info from the linked list */
		pdr_info_t *pdr = session->pdrs;

		while (pdr != NULL) {
			far_info_t *far = pdr->far;
			/* Cleanup the FAR information */
			if (far != NULL) {
#ifdef USE_REST
				if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0)
					dp_flush_session(
						ntohl(far->frwdng_parms.outer_hdr_creation.ipv4_address),
						sess->up_seid);
#endif /* USE_REST */
				/* Flush the far info from the hash table */
				ret = rte_hash_del_key(far_by_id_hash, &far->far_id_value);
				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, "DP:"FORMAT"Entry not found for FAR_ID:%u...\n",
								ERR_MSG, far->far_id_value);
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, "%s: FAR_ID:%u\n",
						__func__, far->far_id_value);
			}

			/* Cleanup QERs info from the linked list */
			qer_info_t *qer = pdr->quer;
			while (qer != NULL) {
				/* Get QER ID */
				uint32_t qer_id = qer->qer_id;

				/* Delete the QER info node from the linked list */
				pdr->quer = remove_qer_node(pdr->quer, qer);
				qer = pdr->quer;

				/* Flush the QER info from the hash table */
				ret = rte_hash_del_key(qer_by_id_hash, &qer_id);
				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Entry not found for QER_ID:%u...\n",
								ERR_MSG, qer_id);
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, "%s: QER_ID:%u\n",
						__func__, qer_id);
			}

			/* Cleanup URRs info from the linked list */
			urr_info_t *urr = pdr->urr;
			while (urr != NULL) {
				/* Get URR ID */
				uint32_t urr_id = urr->urr_id;

				/* Delete the URR info node from the linked list */
				pdr->urr = remove_urr_node(pdr->urr, urr);
				urr = pdr->urr;

				/* Flush the URR info from the hash table */
				if (del_urr_info_entry(urr_id)) {
					/* TODO : ERROR Handling */
				}
			}

			/* Cleanup PDRs info from the linked list */
			/* Get PDR ID */
			uint32_t pdr_id = pdr->rule_id;

			/* Delete the PDR info node from the linked list */
			session->pdrs = remove_pdr_node(session->pdrs, pdr);
			pdr = session->pdrs;

			/* Flush the PDR info from the hash table */
			ret = rte_hash_del_key(pdr_by_id_hash, &pdr_id);
			if ( ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Entry not found for PDR_ID:%u...\n",
							ERR_MSG, pdr_id);
				return -1;
			}
			clLog(clSystemLog, eCLSeverityDebug, "%s: PDR_ID:%u\n",
					__func__, pdr_id);
		}

		/* Delete the ACL table */
		//if (session->acl_table_indx != 0) {
		//	if (up_sdf_filter_table_delete(session->acl_table_indx)) {
		//		/* TODO : ERROR Handling */
		//	}
		//}

		if (session->ue_ip_addr != 0)
			ue_ip[inx++] = session->ue_ip_addr;

		/* Delete the Session data info node from the linked list */
		sess->sessions = remove_sess_data_node(sess->sessions, session);
		if (sess->sessions == NULL)
			break;

		session = sess->sessions;
	}

	/* Flush the Session data info from the hash tables based on ue_ip */
	if ((app.spgw_cfg == PGWU) || (app.spgw_cfg == SAEGWU)) {
		for (int itr = 0; itr < inx; itr++) {
			if (ue_ip[inx] != 0) {
				/* Session Entry is present. Delete Session Entry */
				ret = rte_hash_del_key(sess_by_ueip_hash, &ue_ip[inx]);
				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Entry not found for UE_IP:"IPV4_ADDR"...\n",
								ERR_MSG, IPV4_ADDR_HOST_FORMAT(ue_ip[inx]));
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, "%s: UE_IP:"IPV4_ADDR"\n",
						__func__, IPV4_ADDR_HOST_FORMAT(ue_ip[inx]));
			}
		}
	}


	for (int itr1 = 0; itr1 < sess->ber_cnt; itr1++) {
		if(sess->teids[itr1] == 0)
			continue;
		else if (del_sess_by_teid_entry(sess->teids[itr1])) {
			/* TODO : ERROR Handling */
		}
	}

	/* Session Entry is present. Delete Session Entry */
	ret = rte_hash_del_key(sess_ctx_by_sessid_hash, &sess->up_seid);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Entry not found for UP_SESS_ID:%lu...\n",
					ERR_MSG, sess->up_seid);
		return -1;
	}

	/*CLI:decrement active session count*/
	update_sys_stat(number_of_active_session, DECREMENT);

	return 0;
}

int8_t
process_up_session_deletion_req(pfcp_sess_del_req_t *sess_del_req,
				pfcp_sess_del_rsp_t *sess_del_rsp)
{
	pfcp_session_t *sess = NULL;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Deletion Request :: START \n");
	/* Get the session information from session table based on UP_SESSION_ID*/
	if (sess_del_req->header.s) {
		/* Check SEID is not ZERO */
		sess = get_sess_info_entry(sess_del_req->header.seid_seqno.has_seid.seid,
				SESS_DEL);
	}

	if (sess == NULL)
		return -1;

	if (up_delete_session_entry(sess))
		return -1;

	/* Update the CP seid in the response packet */
	sess_del_rsp->header.seid_seqno.has_seid.seid =	sess->cp_seid;

#ifdef USE_CSID
	if (app.spgw_cfg != PGWU) {
		if (del_sess_by_csid_entry(sess->sgw_fqcsid, sess->sgwu_fqcsid,
			sess_del_req->header.seid_seqno.has_seid.seid)) {
			return -1;
		}
	} else {
		if (del_sess_by_csid_entry(sess->pgw_fqcsid, sess->pgwu_fqcsid,
			sess_del_req->header.seid_seqno.has_seid.seid)) {
			return -1;
		}
	}
#endif /* USE_CSID */

	/* Cleanup the session */
	rte_free(sess);
	sess = NULL;

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Deletion Request :: END \n\n");
	return 0;
}

