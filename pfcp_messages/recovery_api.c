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
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "gw_adapter.h"
#include "pfcp.h"
#include "csid_struct.h"
#include "teid.h"


#ifdef CP_BUILD
#include "cp_config.h"
#include "cp.h"

static pthread_t recov_thread;
node_address_t recov_peer_addr;
extern uint8_t recovery_flag;
extern pfcp_config_t config;
extern int clSystemLog;
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;

/*
 * num_sess : Contain Number of session est.
 * req sent to the peer node while Recover affected session's
 */
uint64_t num_sess ;

#endif /* CP_BUILD */

/**
 * @brief  : Fill create pdr ie
 * @param  : create_pdr, buffer to be filled
 * @param  : pdr, pdr information
 * @param  : bearer, bearer information
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_create_pdr(pfcp_create_pdr_ie_t *create_pdr, pdr_t *pdr, eps_bearer *bearer)
{

	int pdr_header_len = 0;

	/* Filling pdr ID */
	pfcp_set_ie_header(&((create_pdr)->pdr_id.header), PFCP_IE_PDR_ID,
			(sizeof(pfcp_pdr_id_ie_t) - sizeof(pfcp_ie_header_t)));

	pdr_header_len += sizeof(pfcp_pdr_id_ie_t);

	create_pdr->pdr_id.rule_id = pdr->rule_id;

	/* Filling Precedance */
	pfcp_set_ie_header(&((create_pdr)->precedence.header), PFCP_IE_PRECEDENCE,
			(sizeof(pfcp_precedence_ie_t) - sizeof(pfcp_ie_header_t)));

	pdr_header_len += sizeof(pfcp_precedence_ie_t);

	create_pdr->precedence.prcdnc_val = pdr->prcdnc_val;

	/* Filling PDI */
	int pdi_header_len = 0;
	/* -> source Interface */
	pfcp_set_ie_header(&(create_pdr->pdi.src_intfc.header), PFCP_IE_SRC_INTFC,
			(sizeof(pfcp_src_intfc_ie_t) - sizeof(pfcp_ie_header_t)));
	pdi_header_len += sizeof(pfcp_src_intfc_ie_t);

	create_pdr->pdi.src_intfc.src_intfc_spare = 0;
	create_pdr->pdi.src_intfc.interface_value = pdr->pdi.src_intfc.interface_value;

	/* -> F-TEID */
	if ((bearer->pdn->context->cp_mode == SGWC) ||
			(pdr->pdi.src_intfc.interface_value != SOURCE_INTERFACE_VALUE_CORE)) {
		int len = 0;
		if (pdr->pdi.local_fteid.v4) {
			len = sizeof(pfcp_fteid_ie_t) -
				( sizeof(create_pdr->pdi.local_fteid.ipv6_address)
				  + sizeof(create_pdr->pdi.local_fteid.choose_id));
		} else if (pdr->pdi.local_fteid.v6){
			len = sizeof(pfcp_fteid_ie_t) -
				(sizeof(create_pdr->pdi.local_fteid.ipv4_address)
				 + sizeof(create_pdr->pdi.local_fteid.choose_id));
		}

		pfcp_set_ie_header(&(create_pdr->pdi.local_fteid.header), PFCP_IE_FTEID,
				(len - sizeof(pfcp_ie_header_t)));

		if (pdr->pdi.local_fteid.v4) {
			create_pdr->pdi.local_fteid.v4 = PRESENT;
			create_pdr->pdi.local_fteid.teid = pdr->pdi.local_fteid.teid;
			create_pdr->pdi.local_fteid.ipv4_address = pdr->pdi.local_fteid.ipv4_address;
		} else if (pdr->pdi.local_fteid.v6) {
			create_pdr->pdi.local_fteid.v6 = PRESENT;
			create_pdr->pdi.local_fteid.teid = pdr->pdi.local_fteid.teid;
			memcpy(&create_pdr->pdi.local_fteid.ipv6_address,
					&pdr->pdi.local_fteid.ipv6_address, IPV6_ADDR_LEN);
		}

		pdi_header_len += len;
	}

	if ((bearer->pdn->context->cp_mode != SGWC) &&
			(pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE)) {
		/* ->  netework Instance */
		pfcp_set_ie_header(&(create_pdr->pdi.ntwk_inst.header), PFCP_IE_NTWK_INST,
				(sizeof(pfcp_ntwk_inst_ie_t) - sizeof(pfcp_ie_header_t)));

		pdi_header_len += sizeof(pfcp_ntwk_inst_ie_t);

		strncpy((char *)create_pdr->pdi.ntwk_inst.ntwk_inst,
				(char *)&pdr->pdi.ntwk_inst.ntwk_inst, PFCP_NTWK_INST_LEN);

		int len = 0;
		/* -> UE IP address */
		if (pdr->pdi.ue_addr.v4) {
			len = sizeof(pfcp_ue_ip_address_ie_t)
				-(sizeof(create_pdr->pdi.ue_ip_address.ipv6_address)
						+ sizeof(create_pdr->pdi.ue_ip_address.ipv6_pfx_dlgtn_bits));
		} else if (pdr->pdi.ue_addr.v6) {
			len = sizeof(pfcp_ue_ip_address_ie_t)
				- (sizeof(create_pdr->pdi.ue_ip_address.ipv4_address)
						+ sizeof(create_pdr->pdi.ue_ip_address.ipv6_pfx_dlgtn_bits));
		}

		pfcp_set_ie_header(&((create_pdr)->pdi.ue_ip_address.header), PFCP_IE_UE_IP_ADDRESS,
				(len - sizeof(pfcp_ie_header_t)));

		if (pdr->pdi.ue_addr.v4) {
			create_pdr->pdi.ue_ip_address.v4 = PRESENT;
			create_pdr->pdi.ue_ip_address.ipv4_address = pdr->pdi.ue_addr.ipv4_address;
		} else if (pdr->pdi.ue_addr.v6) {
			create_pdr->pdi.ue_ip_address.v6 = PRESENT;
			memcpy(&create_pdr->pdi.ue_ip_address.ipv6_address,
					&pdr->pdi.ue_addr.ipv6_address, IPV6_ADDR_LEN);
		}

		pdi_header_len += len;
	}
	/* --> UE IPv6 address */
	if (((bearer->pdn->context->cp_mode != SGWC) &&
				(pdr->pdi.src_intfc.interface_value  == SOURCE_INTERFACE_VALUE_ACCESS)
				&& (pdr->pdi.ue_addr.v6))) {
		uint8_t len = 0;

		create_pdr->pdi.ue_ip_address.v6 = PRESENT;
		create_pdr->pdi.ue_ip_address.ipv6d = PRESENT;
		create_pdr->pdi.ue_ip_address.ipv6_pfx_dlgtn_bits =
				pdr->pdi.ue_addr.ipv6_pfx_dlgtn_bits;
		memcpy(&create_pdr->pdi.ue_ip_address.ipv6_address,
				&pdr->pdi.ue_addr.ipv6_address, IPV6_ADDR_LEN);

		len = sizeof(pfcp_ue_ip_address_ie_t)
			- (sizeof(create_pdr->pdi.ue_ip_address.ipv4_address));

		pfcp_set_ie_header(&((create_pdr)->pdi.ue_ip_address.header), PFCP_IE_UE_IP_ADDRESS,
				(len - sizeof(pfcp_ie_header_t)));
		pdi_header_len += len;
	}

	pdr_header_len += pdi_header_len + sizeof(pfcp_ie_header_t);
	pfcp_set_ie_header(&(create_pdr->pdi.header), IE_PDI, pdi_header_len);

	/* Outer header removal */
	if((bearer->pdn->context->cp_mode != SGWC) &&
			pdr->pdi.src_intfc.interface_value  == SOURCE_INTERFACE_VALUE_ACCESS) {
		pfcp_set_ie_header(&(create_pdr->outer_hdr_removal.header),
				PFCP_IE_OUTER_HDR_REMOVAL, UINT8_SIZE);

		pdr_header_len += (sizeof(pfcp_outer_hdr_removal_ie_t)
				- sizeof(create_pdr->outer_hdr_removal.gtpu_ext_hdr_del));

		create_pdr->outer_hdr_removal.outer_hdr_removal_desc = 0;
	}

	/* FAR ID */
	pfcp_set_ie_header(&(create_pdr->far_id.header), PFCP_IE_FAR_ID,
			(sizeof(pfcp_far_id_ie_t) - sizeof(pfcp_ie_header_t)));

	pdr_header_len += sizeof(pfcp_far_id_ie_t);

	create_pdr->far_id.far_id_value = pdr->far.far_id_value;

	/* URR ID */
	if (bearer->pdn->generate_cdr) {
		create_pdr->urr_id_count = pdr->urr_id_count;
		for (uint8_t itr = 0; itr < pdr->urr_id_count; itr++) {
			pfcp_set_ie_header(&(create_pdr->urr_id[itr].header),
					PFCP_IE_URR_ID, UINT32_SIZE);

			create_pdr->urr_id[itr].urr_id_value = pdr->urr.urr_id_value;

			/* If Multiple urr id in one pdr */
			if (pdr->urr_id_count > 1 ) {
				create_pdr->urr_id[itr].urr_id_value = pdr->urr_id[itr].urr_id;
			}

			pdr_header_len += sizeof(pfcp_urr_id_ie_t);
		}
	}

	/* QER ID */
	if((config.use_gx) && bearer->pdn->context->cp_mode != SGWC) {

		create_pdr->qer_id_count = pdr->qer_id_count;
		for(int itr1 = 0; itr1 < pdr->qer_id_count; itr1++) {
			pfcp_set_ie_header(&(create_pdr->qer_id[itr1].header), PFCP_IE_QER_ID,
					(sizeof(pfcp_qer_id_ie_t) - sizeof(pfcp_ie_header_t)));
			pdr_header_len += sizeof(pfcp_qer_id_ie_t);

			create_pdr->qer_id[itr1].qer_id_value = pdr->qer_id[itr1].qer_id;
		}
	}

	pfcp_set_ie_header(&(create_pdr->header), IE_CREATE_PDR, pdr_header_len);

	return (pdr_header_len + sizeof(pfcp_ie_header_t));
}

/**
 * @brief  : Fill create far ie
 * @param  : create_far, buffer to be filled
 * @param  : pdr, pdr information
 * @param  : bearer, bearer information
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_create_far(pfcp_create_far_ie_t *create_far, pdr_t *pdr, eps_bearer *bearer)
{
	/* Filling create FAR */
	int far_hdr_len = 0, ret = 0;
	/* -> FAR ID */
	pfcp_set_ie_header(&(create_far->far_id.header), PFCP_IE_FAR_ID,
			(sizeof(pfcp_far_id_ie_t) - sizeof(pfcp_ie_header_t)));

	far_hdr_len += sizeof(pfcp_far_id_ie_t);

	create_far->far_id.far_id_value = pdr->far.far_id_value;

	/* -> Apply Action */
	pfcp_set_ie_header(&(create_far->apply_action.header), IE_APPLY_ACTION_ID, UINT8_SIZE);
	create_far->apply_action.forw = pdr->far.actions.forw;
	create_far->apply_action.dupl= GET_DUP_STATUS(bearer->pdn->context);
	create_far->apply_action.nocp = pdr->far.actions.nocp;
	create_far->apply_action.buff = pdr->far.actions.buff;
	create_far->apply_action.drop = pdr->far.actions.drop;
	far_hdr_len += UINT8_SIZE + sizeof(pfcp_ie_header_t);
	/* -> Forwarding Parameters */
	int frw_hdr_len = 0;
	/* --> Destination Interface */
	pfcp_set_ie_header(&(create_far->frwdng_parms.dst_intfc.header),
			IE_DEST_INTRFACE_ID, UINT8_SIZE);

	frw_hdr_len += sizeof(pfcp_dst_intfc_ie_t);

	create_far->frwdng_parms.dst_intfc.interface_value =
		pdr->far.dst_intfc.interface_value;

	if((bearer->pdn->context->cp_mode == SGWC) ||
			(pdr->far.dst_intfc.interface_value == DESTINATION_INTERFACE_VALUE_ACCESS)) {
		/* --> outer header creation */
		int len = sizeof(create_far->frwdng_parms.outer_hdr_creation.teid)
			+ sizeof(create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);

		pfcp_set_ie_header(&(create_far->frwdng_parms.outer_hdr_creation.header),
				PFCP_IE_OUTER_HDR_CREATION, len);

		/* SGWC --> access --> ENB S1U */
		/* SAEGWC --> access --> ENB S1U */
		if (((bearer->pdn->context->cp_mode == SGWC) || (bearer->pdn->context->cp_mode ==  SAEGWC)) &&
				(pdr->far.dst_intfc.interface_value == DESTINATION_INTERFACE_VALUE_ACCESS)) {
			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s1u_enb_gtpu_teid;

			if (bearer->s1u_enb_gtpu_ip.ip_type == IPV4_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv4_address);
			} else if (bearer->s1u_enb_gtpu_ip.ip_type == IPV6_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv6_address);
			}

			ret = set_node_address(&create_far->frwdng_parms.outer_hdr_creation.ipv4_address,
					create_far->frwdng_parms.outer_hdr_creation.ipv6_address,
					bearer->s1u_enb_gtpu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		}

		/* In far not found destinatiion instarface value, it's by default 0  pdr->far.dst_intfc.interface_value
		 * so insted of far we use pdi */
		/* SGWC --> core --> PGW S5S8  */
		if ((bearer->pdn->context->cp_mode == SGWC) &&
				(pdr->far.dst_intfc.interface_value ==  DESTINATION_INTERFACE_VALUE_CORE)) {

			if (bearer->s5s8_pgw_gtpu_ip.ip_type == IPV4_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv4_address);
			} else if (bearer->s5s8_pgw_gtpu_ip.ip_type == IPV6_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv6_address);
			}

			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s5s8_pgw_gtpu_teid;
			ret = set_node_address(&create_far->frwdng_parms.outer_hdr_creation.ipv4_address,
					create_far->frwdng_parms.outer_hdr_creation.ipv6_address,
					bearer->s5s8_pgw_gtpu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		}

		/* PGWC --> access --> SGW S5S8 */
		if ((bearer->pdn->context->cp_mode == PGWC) &&
				pdr->far.dst_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {

			if (bearer->s5s8_sgw_gtpu_ip.ip_type == IPV4_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv4_address);
			} else if (bearer->s5s8_sgw_gtpu_ip.ip_type == IPV6_TYPE) {
				create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6 = PRESENT;
				len += sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv6_address);
			}

			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s5s8_sgw_gtpu_teid;
			ret = set_node_address(&create_far->frwdng_parms.outer_hdr_creation.ipv4_address,
					create_far->frwdng_parms.outer_hdr_creation.ipv6_address,
					bearer->s5s8_sgw_gtpu_ip);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
					"IP address", LOG_VALUE);
			}
		}
		create_far->frwdng_parms.outer_hdr_creation.header.len = len;
		frw_hdr_len += len + sizeof(pfcp_ie_header_t);
	}
	pfcp_set_ie_header(&(create_far->frwdng_parms.header), IE_FRWDNG_PARMS, frw_hdr_len);

	far_hdr_len += (frw_hdr_len + sizeof(pfcp_ie_header_t));

	if (((create_far->apply_action.buff == PRESENT)
				&& ((bearer->pdn->context->cp_mode != PGWC)
				&& (bearer->pdn->context->indication_flag.oi == NOT_PRESENT)
				&& (bearer->pdn->context->indication_flag.daf == NOT_PRESENT)))) {
		/* BAR ID */
		uint16_t bar_hdr_len = 0;
		bar_hdr_len = set_bar_id(&(create_far->bar_id), pdr->far.bar_id_value);
		far_hdr_len += bar_hdr_len;
	}

	pfcp_set_ie_header(&(create_far->header), IE_CREATE_FAR, far_hdr_len);

	return (far_hdr_len + sizeof(pfcp_ie_header_t));
}

/**
 * @brief  : Fill create qer ie
 * @param  : pfcp_sess_est_req, buffer to be filled
 * @param  : bearer, bearer information
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_create_qer(pfcp_sess_estab_req_t *pfcp_sess_est_req, eps_bearer *bearer)
{

	/* Filling create qer */
	int ret = 0;
	int qer_hdr_len = 0;
	int qer_itr = pfcp_sess_est_req->create_qer_count;
	pfcp_create_qer_ie_t *create_qer;

	for (uint8_t itr = 0; itr < bearer->qer_count; itr++) {
		qer_hdr_len = 0;
		create_qer = &pfcp_sess_est_req->create_qer[qer_itr];
		/* QER ID */
		pfcp_set_ie_header(&(create_qer->qer_id.header), PFCP_IE_QER_ID,
				(sizeof(pfcp_qer_id_ie_t) - sizeof(pfcp_ie_header_t)));

		create_qer->qer_id.qer_id_value  = bearer->qer_id[itr].qer_id;

		qer_hdr_len += sizeof(pfcp_qer_id_ie_t);
		/* Gate Status */
		pfcp_set_ie_header(&(create_qer->gate_status.header), PFCP_IE_GATE_STATUS,
				(sizeof(pfcp_gate_status_ie_t) - sizeof(pfcp_ie_header_t)));

		create_qer->gate_status.gate_status_spare = 0;
		create_qer->gate_status.ul_gate = UL_GATE_OPEN;
		create_qer->gate_status.ul_gate = DL_GATE_OPEN;

		qer_hdr_len += sizeof(pfcp_gate_status_ie_t);

		/* get_qer_entry */
		qer_t *qer_context = NULL;
		qer_context = get_qer_entry(create_qer->qer_id.qer_id_value);
		if (qer_context  != NULL) {
			/* MAX Bit Rate */
			pfcp_set_ie_header(&(create_qer->maximum_bitrate.header), PFCP_IE_MBR,
					(sizeof(pfcp_mbr_ie_t) - sizeof(pfcp_ie_header_t)));

			create_qer->maximum_bitrate.ul_mbr  =
				qer_context->max_bitrate.ul_mbr;
			create_qer->maximum_bitrate.dl_mbr  =
				qer_context->max_bitrate.dl_mbr;
			qer_hdr_len += sizeof(pfcp_mbr_ie_t);
			/* Garented Bit Rate */
			pfcp_set_ie_header(&(create_qer->guaranteed_bitrate.header), PFCP_IE_GBR,
					(sizeof(pfcp_gbr_ie_t) - sizeof(pfcp_ie_header_t)));

			create_qer->guaranteed_bitrate.ul_gbr  =
				qer_context->guaranteed_bitrate.ul_gbr;
			create_qer->guaranteed_bitrate.dl_gbr  =
				qer_context->guaranteed_bitrate.dl_gbr;
			qer_hdr_len += sizeof(pfcp_gbr_ie_t);
		}
		/* QER header */
		pfcp_set_ie_header(&(create_qer->header), IE_CREATE_QER, qer_hdr_len);
		ret += qer_hdr_len;
		qer_itr++;
	}

	/* Total header lenght of qer */
	return ret;
}

/**
 * @brief  : Fill create urr ie
 * @param  : pfcp_create_urr_ie_t, structure to be filled
 * @param  : pdr, pdr information
 * @return : Returns header length of create urr.
 */

static int
fill_create_urr(pfcp_create_urr_ie_t *create_urr, pdr_t *pdr)
{
	int ret = 0;
	int urr_hdr_len = 0;
	int vol_th_hdr_len = 0;

	/* UUR ID */
	pfcp_set_ie_header(&(create_urr->urr_id.header), PFCP_IE_URR_ID, UINT32_SIZE);

	create_urr->urr_id.urr_id_value = pdr->urr.urr_id_value;

	urr_hdr_len += sizeof(pfcp_urr_id_ie_t);

	/* Measurement Method */
	pfcp_set_ie_header(&(create_urr->meas_mthd.header), PFCP_IE_MEAS_MTHD, UINT8_SIZE);

	create_urr->meas_mthd.volum = pdr->urr.mea_mt.volum;

	create_urr->meas_mthd.durat = pdr->urr.mea_mt.durat;

	urr_hdr_len += sizeof(pfcp_meas_mthd_ie_t);

	/* Reporting Triggers */
	pfcp_set_ie_header(&(create_urr->rptng_triggers.header), PFCP_IE_RPTNG_TRIGGERS, UINT16_SIZE);

	urr_hdr_len += sizeof(pfcp_rptng_triggers_ie_t);

	/* If Volume and Time threshold Both are Present */
	if ((pdr->urr.rept_trigg.volth == PRESENT) && (pdr->urr.rept_trigg.timth == PRESENT)) {

		create_urr->rptng_triggers.timth = pdr->urr.rept_trigg.timth;

		create_urr->rptng_triggers.volth = pdr->urr.rept_trigg.volth;

		/* Time Threshold */
		pfcp_set_ie_header(&(create_urr->time_threshold.header), PFCP_IE_TIME_THRESHOLD,
				sizeof(pfcp_time_threshold_ie_t) - sizeof(pfcp_ie_header_t));

		create_urr->time_threshold.time_threshold = pdr->urr.time_th.time_threshold;

		urr_hdr_len += sizeof(pfcp_time_threshold_ie_t);

		/* Volume Threshold */
		vol_th_hdr_len = (sizeof(pfcp_vol_thresh_ie_t)
				- (sizeof(pfcp_ie_header_t) + (2 * sizeof(uint64_t))));
		pfcp_set_ie_header(&(create_urr->vol_thresh.header), PFCP_IE_VOL_THRESH, vol_th_hdr_len);

		urr_hdr_len += (vol_th_hdr_len + sizeof(pfcp_ie_header_t));

		if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS)
		{
			create_urr->vol_thresh.ulvol = PRESENT;
			create_urr->vol_thresh.uplink_volume = pdr->urr.vol_th.uplink_volume;

		} else
		{
			create_urr->vol_thresh.dlvol = PRESENT;
			create_urr->vol_thresh.downlink_volume = pdr->urr.vol_th.downlink_volume;
		}

		/* If only Volume Threshold are Present */
	} else if (pdr->urr.rept_trigg.volth == PRESENT) {

		/* Reporting Triggers */
		create_urr->rptng_triggers.volth = pdr->urr.rept_trigg.volth;

		/* Volume Threshold */
		vol_th_hdr_len = (sizeof(pfcp_vol_thresh_ie_t)
				- (sizeof(pfcp_ie_header_t) + (2 * sizeof(uint64_t))));
		pfcp_set_ie_header(&(create_urr->vol_thresh.header), PFCP_IE_VOL_THRESH, vol_th_hdr_len);

		urr_hdr_len += (vol_th_hdr_len + sizeof(pfcp_ie_header_t));

		if (pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS)
		{
			create_urr->vol_thresh.ulvol = PRESENT;
			create_urr->vol_thresh.uplink_volume = pdr->urr.vol_th.uplink_volume;
		} else
		{
			create_urr->vol_thresh.dlvol = PRESENT;
			create_urr->vol_thresh.downlink_volume = pdr->urr.vol_th.downlink_volume;
		}
	} else {
		create_urr->rptng_triggers.timth = pdr->urr.rept_trigg.timth;

		/* Time Threshold */
		pfcp_set_ie_header(&(create_urr->time_threshold.header), PFCP_IE_TIME_THRESHOLD,
				sizeof(pfcp_time_threshold_ie_t) - sizeof(pfcp_ie_header_t));

		create_urr->time_threshold.time_threshold = pdr->urr.time_th.time_threshold;

		urr_hdr_len += sizeof(pfcp_time_threshold_ie_t);
	}
	pfcp_set_ie_header(&(create_urr->header), IE_CREATE_URR, urr_hdr_len);
	ret = (urr_hdr_len + sizeof(pfcp_ie_header_t));
	return ret;
}
/**
 * @brief  : Function to fille pfcp session establishment request
 * @param  : context, ue context information
 * @param  : node_addr, node address
 * @return : Returns 0 on success, -1 otherwise
 */
static int
process_pfcp_sess_est_req(pdn_connection *pdn, node_address_t *node_addr)
{
	uint32_t seq = 0;
	int ret = 0;
	eps_bearer *bearer = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};
	ue_context *context = NULL;
	node_address_t node_value = {0};

	context = pdn->context;

	/* need to think anout it */
	seq = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, seq);

	/* Filling header */
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req.header),
			PFCP_SESSION_ESTABLISHMENT_REQUEST, HAS_SEID, seq, pdn->context->cp_mode);

	/* Assing DP SEID */
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" : DP SEID %u\n",
			LOG_VALUE, pdn->dp_seid);

	pfcp_sess_est_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

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
	set_node_id(&(pfcp_sess_est_req.node_id), node_value);

	set_fseid(&(pfcp_sess_est_req.cp_fseid), pdn->seid, node_value);

	/* Filling PDN structure*/
	pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
	pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
	pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
	pfcp_sess_est_req.pdn_type.pdn_type =  1;

	/* Filling Create BAR IE */
	if ((pdn->context->cp_mode != PGWC) && (pdn->bar.bar_id))
		set_create_bar(&(pfcp_sess_est_req.create_bar), &pdn->bar);

	set_pdn_type(&(pfcp_sess_est_req.pdn_type), &(pdn->pdn_type));

	/* Filling USER ID structure */
	set_user_id(&(pfcp_sess_est_req.user_id), context->imsi);

	uint8_t pdr_idx =0;
	for(uint8_t itr1 = 0; itr1 < MAX_BEARERS; itr1++) {
		bearer = pdn->eps_bearers[itr1];
		if(bearer == NULL)
			continue;

		pfcp_sess_est_req.create_pdr_count += bearer->pdr_count;
		pfcp_sess_est_req.create_far_count += bearer->pdr_count;
		pfcp_sess_est_req.create_urr_count += bearer->pdr_count;

		for(uint8_t itr2 = 0; itr2 < bearer->pdr_count; itr2++) {
			fill_create_pdr(&(pfcp_sess_est_req.create_pdr[pdr_idx]),
					bearer->pdrs[itr2], bearer);
			fill_create_far(&(pfcp_sess_est_req.create_far[pdr_idx]),
					bearer->pdrs[itr2], bearer);
			if (pdn->generate_cdr) {
				fill_create_urr(&(pfcp_sess_est_req.create_urr[pdr_idx]),
						bearer->pdrs[itr2]);
			}

			if ((config.use_gx) && pdn->context->cp_mode != SGWC) {
				for(int sdf_itr1 = 0;
						sdf_itr1 < bearer->pdrs[itr2]->pdi.sdf_filter_cnt; sdf_itr1++) {
					enum flow_status f_status =
						pdn->policy.pcc_rule[sdf_itr1].dyn_rule.flow_status;

					fill_create_pdr_sdf_rules(pfcp_sess_est_req.create_pdr,
							bearer->dynamic_rules[sdf_itr1], pdr_idx);
					fill_gate_status(&pfcp_sess_est_req, pdr_idx, f_status);
				}
				//pdr_idx++;
			}

			pdr_idx++;
		}

		if((config.use_gx) && pdn->context->cp_mode != SGWC) {

			fill_create_qer(&(pfcp_sess_est_req), bearer);
			pfcp_sess_est_req.create_qer_count += bearer->qer_count;

		}

	} /* for loop  */

	/* Fill the fqcsid into the session est request */
	if (context->cp_mode != PGWC) {
		/* Set SGW FQ-CSID */
		if (pdn->sgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req.sgw_c_fqcsid, &pdn->sgw_csid);
		}
		/* Set MME FQ-CSID */
		if(pdn->mme_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req.mme_fqcsid, &pdn->mme_csid);
		}
		/* set PGWC FQ-CSID */
		if (context->cp_mode  != SAEGWC) {
			set_fq_csid_t(&pfcp_sess_est_req.pgw_c_fqcsid, &pdn->pgw_csid);
		}
	} else {
		/* Set PGW FQ-CSID */
		if (pdn->pgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req.pgw_c_fqcsid, &pdn->pgw_csid);
		}
		/* Set SGW C FQ_CSID */
		if (pdn->sgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req.sgw_c_fqcsid, &pdn->sgw_csid);
		}
		/* Set MME FQ-CSID */
		if(pdn->mme_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req.mme_fqcsid, &pdn->mme_csid);
		}
	}

	/* Fetch and update resp info */
	/* Lookup Stored the session information. */
	if (get_sess_entry(pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add response in entry in SM_HASH\n", LOG_VALUE);
		return -1;
	}

	reset_resp_info_structure(resp);

	resp->linked_eps_bearer_id = pdn->default_bearer_id;
	resp->state = PFCP_SESS_EST_REQ_SNT_STATE ;
	resp->proc = RESTORATION_RECOVERY_PROC;
	/* Update  PDN procedure */
	pdn->proc = RESTORATION_RECOVERY_PROC;
	pdn->state = PFCP_SESS_EST_REQ_SNT_STATE;

	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
		/* Think about it , if CP connected with multiple DP */
		ret = set_dest_address(pdn->upf_ip, &upf_pfcp_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req,
				pfcp_msg);

		ret = set_dest_address(pdn->upf_ip, &upf_pfcp_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}
		if ( pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0 ){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error sending in "
				"PFCP Session Establishment Request: %i\n", LOG_VALUE, errno);
		return -1;
	}
	RTE_SET_USED(node_addr);
	return 0;
}

/**
 * @brief  : Fucnton to get sess ID and send session est. request to peer node
 * @param  : csids
 * @param  : node_addr, node address
 * @return : Returns 0 on success, -1 otherwise
 */
static int
create_sess_by_csid_entry(fqcsid_t *peer_csids, node_address_t *node_addr)
{
	int ret = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	node_address_t addr = {0};
	peer_csid_key_t key = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;

	memcpy(&addr, node_addr, sizeof(node_address_t));

	/* Get the session ID by csid */
	for (uint8_t itr1 = 0; itr1 < peer_csids->num_csid; itr1++) {
		sess_csid *tmp = NULL;
		sess_csid *current = NULL;

		key.iface = SX_PORT_ID;
		key.peer_local_csid = peer_csids->local_csid[itr1];
		memcpy(&key.peer_node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found, CSID: %u\n", LOG_VALUE,
					peer_csids->local_csid[itr1]);
			continue;
		}

		if (tmp->cp_seid == 0 && tmp->next == 0 ) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			uint32_t teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				current = current->next;
				continue;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" TEID : %u\n", LOG_VALUE, teid_key);

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || !context) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: UE contetx not found fot TEID %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				current = current->next;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"ERROR : Failed to get PDN context for seid : %u \n",
					LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				current = current->next;
				continue;
			}

			/* PDN upf ip address and peer node address,
			 * if not match than we assume CP connected to the onthere DP */
			if(COMPARE_IP_ADDRESS(pdn->upf_ip, addr) != 0) {
				(pdn->upf_ip.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"Match Not Found : Peer Node IPv6 Address : "IPv6_FMT" ,"
							" PDN upf ipv6 addres : "IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr)),
							IPv6_PRINT(IPv6_CAST(pdn->upf_ip.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"Match Not Found : Peer Node IPv4 Address : "IPV4_ADDR" ,"
							" PDN upf ipv4 addres : "IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr),
							IPV4_ADDR_HOST_FORMAT(pdn->upf_ip.ipv4_addr));
				current = current->next;
				continue;
			}

			if (process_pfcp_sess_est_req(pdn, node_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error while Processing "
					"PFCP Session Establishment Request TEID %u \n", LOG_VALUE, teid_key);
				/* Assign Next node address */
				current = current->next;
				continue;
			}

			/* Assign Next node address */
			current = current->next;

			/* Update session establishment request send counter for recovery */
			num_sess++;

		} /* while loop */

	} /* for loop */

	return 0;
}

/* Function to re-create affected session with peer node */
int
create_peer_node_sess(node_address_t *node_addr, uint8_t iface) {

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":START\n", LOG_VALUE);
	fqcsid_t csids = {0};
	fqcsid_t *peer_csids = NULL;

	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(node_addr,
			UPDATE_NODE);
	if (peer_csids == NULL) {
		/* Delete UPF hash entry */
		if (iface == SX_PORT_ID) {
			/* Delete entry from teid info list for given upf*/

			delete_entry_from_teid_list(*node_addr, &upf_teid_info_head);

			if (rte_hash_del_key(upf_context_by_ip_hash, &node_addr->ipv4_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Error on upf_context_by_ip_hash del\n", LOG_VALUE);
			}
		}
		(node_addr->ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer CSIDs are not found, Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer CSIDs are not found, Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
		return -1;
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_csids->local_csid[itr];
		memcpy(&key.node_addr, &peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_peer_csid_entry(&key, iface, UPDATE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Entry not found for "
				"peer CSIDs\n", LOG_VALUE);
			continue;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		memcpy(&csids.node_addr, &tmp->node_addr, sizeof(node_address_t));
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Local CSIDs not found\n", LOG_VALUE);
		return -1;
	}

	if (iface == SX_PORT_ID) {
		create_sess_by_csid_entry(peer_csids, node_addr);
	}
	return 0;
}

/* Function to send pfcp association setup request in recovery mode */
int
process_aasociation_setup_req(peer_addr_t *peer_addr)
{
	int ret = 0;
	upf_context_t *upf_context = NULL;
	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};
	node_address_t node_value = {0};
	node_address_t cp_node_value = {0};

	if (peer_addr->type == PDN_IP_TYPE_IPV4) {

		uint8_t temp[IPV6_ADDRESS_LEN] = {0};
		fill_ip_addr(config.pfcp_ip.s_addr, temp, &cp_node_value);
		node_value.ipv4_addr = peer_addr->ipv4.sin_addr.s_addr;
		node_value.ip_type = PDN_IP_TYPE_IPV4;

	} else if ((peer_addr->type == PDN_IP_TYPE_IPV6)
				|| (peer_addr->type == PDN_IP_TYPE_IPV4V6)) {
		fill_ip_addr(0, config.pfcp_ip_v6.s6_addr, &cp_node_value);
		memcpy(node_value.ipv6_addr,
				peer_addr->ipv6.sin6_addr.s6_addr, IPV6_ADDRESS_LEN);
		node_value.ip_type = PDN_IP_TYPE_IPV6;
	}

	/* Lookup upf context of peer node */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(node_value), (void **) &(upf_context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND IN "
			"UPF HASH \n", LOG_VALUE);
		return -1;
	}

	/* Changing status and state */
	upf_context->assoc_status = ASSOC_IN_PROGRESS;
	upf_context->state = PFCP_ASSOC_REQ_SNT_STATE;

	/* Filling pfcp associtaion setup request */
	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);

	/*Filling Node ID*/
	set_node_id(&pfcp_ass_setup_req.node_id, cp_node_value);

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, pfcp_msg);

	/* ask vishal :  Do we need request time for recovery */
	/*  Do we need to update cli stat */
	/* Peer node address */
	ret = set_dest_address(node_value, &upf_pfcp_sockaddr);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}

	if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Error in sending Session "
			"Association Setup Request\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Association request sent to "
		"peer node\n", LOG_VALUE);
	return 0;

}

/**
 * @brief  : Function to start thread in recovery mode
 * @param  : arg, arguments
 * @return : Returns nothing
 */
static void*
recov_est_thread_func(void *arg) {

	RTE_SET_USED(arg);
	//uint32_t *peer_addr = (uint32_t *) arg;
	(recov_peer_addr.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" RECOVERY MODE: Thread Start, peer ipv6 node : ["IPv6_FMT"]\n\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(recov_peer_addr.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" RECOVERY MODE: Thread Start, peer ipv4 node : ["IPV4_ADDR"]\n\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(recov_peer_addr.ipv4_addr));

	/* Dump Session information on UP */
	create_peer_node_sess(&recov_peer_addr, SX_PORT_ID);

	(recov_peer_addr.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" RECOVERY MODE: Thread Stop, peer ipv6 node : ["IPv6_FMT"]\n\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(recov_peer_addr.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" RECOVERY MODE: Thread Stop, peer ipv4 node : ["IPV4_ADDR"]\n\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(recov_peer_addr.ipv4_addr));

	/* Checking All session est. response are received or not */
	/* There no critical segment, so we are not using thread sync. technique */
	while (num_sess != 0) {
		usleep(SLEEP_TIME);
	}

	/* Deinit RECOVERY MODE */
	recovery_flag = 0;

	pthread_kill(recov_thread, 0);
	return NULL;
}

/* Function to  process recov association response */
int
process_asso_resp(void *_msg, peer_addr_t *peer_addr) {

	int ret = 0;
	upf_context_t *upf_context = NULL;
	msg_info *msg = (msg_info *)_msg;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ip), (void **) &(upf_context));

	if (ret < 0) {
		(msg->upf_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"NO ENTRY FOUND IN UPF HASH IPv6 ["IPv6_FMT"]\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(msg->upf_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"NO ENTRY FOUND IN UPF HASH IPv4 ["IPV4_ADDR"]\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(msg->upf_ip.ipv4_addr));
		return -1;
	}

	if (msg->upf_ip.ip_type == PDN_TYPE_IPV4) {
		recov_peer_addr.ip_type = PDN_TYPE_IPV4;
		recov_peer_addr.ipv4_addr = msg->upf_ip.ipv4_addr;
	} else {
		recov_peer_addr.ip_type = PDN_TYPE_IPV6;
		memcpy(&recov_peer_addr.ipv6_addr,
				&msg->upf_ip.ipv6_addr, sizeof(node_address_t));
	}
	upf_context->assoc_status = ASSOC_ESTABLISHED;
	upf_context->state = PFCP_ASSOC_RESP_RCVD_STATE;


	/* Checking Assign TEIDRI */
	if((msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range != upf_context->teid_range) ||
			(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri != upf_context->teidri)){
		(msg->upf_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ERROR : TEID RANGE MATCH NOT FOUND ,NODE ADDR IPv6: ["IPv6_FMT"] ,"
					" PERVIOUS TEID RANGE : [%d] TEIDRI : [%d]"
					"CURRENT TEID RANGE : [%d] TEIDRI : [%d] \n", LOG_VALUE,
					IPv6_PRINT(IPv6_CAST(msg->upf_ip.ipv6_addr)), upf_context->teid_range,
					upf_context->teidri,
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range,
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ERROR : TEID RANGE MATCH NOT FOUND ,NODE ADDR IPv4: ["IPV4_ADDR"] ,"
					" PERVIOUS TEID RANGE : [%d] TEIDRI : [%d]"
					"CURRENT TEID RANGE : [%d] TEIDRI : [%d] \n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT(msg->upf_ip.ipv4_addr), upf_context->teid_range,
					upf_context->teidri,
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range,
					msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teidri);
		/* Cleanup is on low priority */
		/* Cleanip Initiate for peer node */
		del_peer_node_sess(&recov_peer_addr, SX_PORT_ID);
		return -1;
	}

	(peer_addr->type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"TEID RANGE MATCT FOUND : NODE IPv6 ADDR : ["IPv6_FMT"] , PERVIOUS TEID RANGE : [%d] \n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_addr->ipv6.sin6_addr.s6_addr)),
				upf_context->teid_range):
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"TEID RANGE MATCT FOUND : NODE IPv4 ADDR : ["IPV4_ADDR"] , PERVIOUS TEID RANGE : [%d] \n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_addr->ipv4.sin_addr.s_addr), upf_context->teid_range);


	ret = pthread_create(&recov_thread, NULL, &recov_est_thread_func, NULL);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT
				"\nCan't create RECOVRY MODE thread :[%s]", LOG_VALUE, strerror(ret));
		return ret;
	}
	else {
		clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT
				"\n RECOVERY MODE thread created successfully\n", LOG_VALUE);
	}

	return 0;

}

/* Function to process pfpc session establishment response
 * in recovery mode  while recovering affected session */
int
process_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"RECOVERY MODE : session establishment response received\n", LOG_VALUE);
	if (pfcp_sess_est_rsp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ERROR:%s\n",
				LOG_VALUE, strerror(errno));
		return -1;
	}

	int ret = 0;
	uint8_t num_csid = 0;
	node_address_t node_addr = {0};
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint64_t sess_id = pfcp_sess_est_rsp->header.seid_seqno.has_seid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to update UE "
				"State for teid: %u\n", LOG_VALUE, teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get response "
			"entry in SM_HASH for SEID : 0x%x \n", LOG_VALUE, sess_id);
		return -1;
	}

	/* Need to think on eps_bearer_id*/
	int ebi_index = GET_EBI_INDEX(resp->linked_eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to get pdn for ebi_index : %d \n", LOG_VALUE);
		return -1;
	}

	pdn->state = CONNECTED_STATE;

	uint16_t old_csid = pdn->up_csid.local_csid[pdn->up_csid.num_csid - 1];
	sess_csid *tmp1 = NULL;
	peer_csid_key_t key = {0};
	fqcsid_t *tmp = NULL;
	sess_fqcsid_t *fqcsid = NULL;
	if (context->up_fqcsid == NULL) {
		fqcsid = rte_zmalloc_socket(NULL, sizeof(sess_fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
					"memory for fqcsids entry\n", LOG_VALUE);
			return -1;
		}
	} else {
		fqcsid = context->up_fqcsid;
	}

	/* UP FQ-CSID */
	if (pfcp_sess_est_rsp->up_fqcsid.header.len) {
		if (pfcp_sess_est_rsp->up_fqcsid.number_of_csids) {

			if (pfcp_sess_est_rsp->up_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
				memcpy(&(node_addr.ipv4_addr),
						pfcp_sess_est_rsp->up_fqcsid.node_address, IPV4_SIZE);
				node_addr.ip_type =  pfcp_sess_est_rsp->up_fqcsid.fqcsid_node_id_type;
			} else {
				memcpy(&(node_addr.ipv6_addr),
						pfcp_sess_est_rsp->up_fqcsid.node_address, IPV6_ADDRESS_LEN);
				node_addr.ip_type = pfcp_sess_est_rsp->up_fqcsid.fqcsid_node_id_type;
			}
			/* Stored the UP CSID by UP Node address */
			tmp = get_peer_addr_csids_entry(&node_addr, ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Add the "
						"SGW-U CSID by SGW Node address, Error : %s \n",
						LOG_VALUE, strerror(errno));
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			memcpy(&tmp->node_addr, &node_addr, sizeof(node_address_t));

			for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->up_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[itr]) {
						match = 1;
						break;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[itr];
				}
			}

			if (fqcsid->num_csid) {
				match_and_add_pfcp_sess_fqcsid(&(pfcp_sess_est_rsp->up_fqcsid), fqcsid);
			} else {
				add_pfcp_sess_fqcsid(&(pfcp_sess_est_rsp->up_fqcsid), fqcsid);
			}

			/* Coping UP csid */
			fill_pdn_fqcsid_info(&pdn->up_csid, fqcsid);

			for (uint8_t itr2 = 0; itr2 < tmp->num_csid; itr2++) {
				if (tmp->local_csid[itr2] == old_csid) {
					for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}
		}
	} else {
		/* TODO: Add the handling if SGW or PGW not support Partial failure */
		tmp = get_peer_addr_csids_entry(&pdn->upf_ip,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"the SGW-U CSID by SGW Node address, Error : %s \n",
					LOG_VALUE, strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		memcpy(&tmp->node_addr, &pdn->upf_ip, sizeof(node_address_t));
		memcpy(&fqcsid->node_addr[fqcsid->num_csid],
				&tmp->node_addr, sizeof(node_address_t));
	}

	/* Link peer node SGW or PGW csid with local csid */
	if (pdn->up_csid.num_csid) {
		if (context->cp_mode != PGWC) {
			ret = update_peer_csid_link(&pdn->up_csid, &pdn->sgw_csid);
		} else {
			ret = update_peer_csid_link(&pdn->up_csid, &pdn->pgw_csid);
		}

		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Update "
					"FQ-CSID link while PFCP Session Establishment Response: %s \n",
					LOG_VALUE, strerror(errno));

			return -1;
		}

		if (old_csid != pdn->up_csid.local_csid[num_csid]) {
			/* Link session with Peer CSID */
			link_sess_with_peer_csid(&pdn->up_csid, pdn, SX_PORT_ID);
			/* Remove old csid */
			key.iface = SX_PORT_ID;
			key.peer_local_csid = old_csid;
			memcpy(&key.peer_node_addr,
					&pdn->up_csid.node_addr, sizeof(node_address_t));
			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);
			remove_sess_entry(tmp1, pdn->seid, &key);
		}
	}

	/* Update the UP CSID in the context */
	if (context->up_fqcsid == NULL)
		context->up_fqcsid = fqcsid;

	return 0;
}
