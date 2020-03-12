
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
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "clogger.h"
#include "gw_adapter.h"
#include "pfcp.h"
#include "csid_struct.h"


#ifdef CP_BUILD
#include "cp_config.h"
#include "cp.h"

static pthread_t recov_thread;
uint32_t recov_peer_addr;
extern volatile uint8_t recovery_flag;
extern pfcp_config_t pfcp_config;
extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;

/* num_sess : Contain Number of session est. req sent to the peer node while Recover affected session's */
volatile uint64_t num_sess ;

#endif /* CP_BUILD */

/**
 * @brief  : Fill create pdr ie
 * @param  : create_pdr, buffer to be filled
 * @param  : pdr, pdr information
 * @param  : bearer, bearer information
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_create_pdr(pfcp_create_pdr_ie_t *create_pdr, pdr_t *pdr, eps_bearer *bearer) {

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
	if ((pfcp_config.cp_type == SGWC) ||
			(pdr->pdi.src_intfc.interface_value != SOURCE_INTERFACE_VALUE_CORE)) {
		int len = 0;
		len = sizeof(pfcp_fteid_ie_t) - /*(sizeof(create_pdr->pdi.local_fteid.ipv4_address) + */
				( sizeof(create_pdr->pdi.local_fteid.ipv6_address)
				+ sizeof(create_pdr->pdi.local_fteid.choose_id));

		pfcp_set_ie_header(&(create_pdr->pdi.local_fteid.header), PFCP_IE_FTEID,
				(len - sizeof(pfcp_ie_header_t)));

		//create_pdr->pdi.local_fteid->fteid_spare = 0;
		//create_pdr->pdi.local_fteid->chid = 0;
		//create_pdr->pdi.local_fteid->ch = 0;
		//create_pdr->pdi.local_fteid->v6 = 0;
		create_pdr->pdi.local_fteid.v4 = 1;
		create_pdr->pdi.local_fteid.teid = pdr->pdi.local_fteid.teid;
		create_pdr->pdi.local_fteid.ipv4_address = pdr->pdi.local_fteid.ipv4_address;

		pdi_header_len += len;
	}

	if ((pfcp_config.cp_type != SGWC) &&
			(pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE)) {
		/* ->  netework Instance */
		pfcp_set_ie_header(&(create_pdr->pdi.ntwk_inst.header), PFCP_IE_NTWK_INST,
							(sizeof(pfcp_ntwk_inst_ie_t) - sizeof(pfcp_ie_header_t)));

		pdi_header_len += sizeof(pfcp_ntwk_inst_ie_t);

		strncpy((char *)create_pdr->pdi.ntwk_inst.ntwk_inst,
					(char *)&pdr->pdi.ntwk_inst.ntwk_inst, 32);
		/* -> UE IP address */
		int len = sizeof(pfcp_ue_ip_address_ie_t)
					-(sizeof(create_pdr->pdi.ue_ip_address.ipv6_address)
					+ sizeof(create_pdr->pdi.ue_ip_address.ipv6_pfx_dlgtn_bits));
		pfcp_set_ie_header(&((create_pdr)->pdi.ue_ip_address.header), PFCP_IE_UE_IP_ADDRESS,
				(len - sizeof(pfcp_ie_header_t)));

		//create_pdr->pdi.ue_ip.ue_ip_addr_spare = 0;
		//create_pdr->pdi.ue_ip.ipv6d = 0;
		//create_pdr->pdi.ue_ip.sd = 0;
		create_pdr->pdi.ue_ip_address.v4 = 1;
		//create_pdr->pdi.ue_ip.v6 = 0;

		create_pdr->pdi.ue_ip_address.ipv4_address = pdr->pdi.ue_addr.ipv4_address;
		pdi_header_len += len;

	}

	pdr_header_len += pdi_header_len + sizeof(pfcp_ie_header_t);
	pfcp_set_ie_header(&(create_pdr->pdi.header), IE_PDI, pdi_header_len);

	/* Outer header removal */
	if((pfcp_config.cp_type != SGWC) &&
			 pdr->pdi.src_intfc.interface_value  == SOURCE_INTERFACE_VALUE_ACCESS) {
		pfcp_set_ie_header(&(create_pdr->outer_hdr_removal.header),
				PFCP_IE_OUTER_HDR_REMOVAL, UINT8_SIZE);

		pdr_header_len += sizeof(pfcp_outer_hdr_removal_ie_t);

		create_pdr->outer_hdr_removal.outer_hdr_removal_desc = 0;
	}

	/* FAR ID */
	pfcp_set_ie_header(&(create_pdr->far_id.header), PFCP_IE_FAR_ID,
						(sizeof(pfcp_far_id_ie_t) - sizeof(pfcp_ie_header_t)));

	pdr_header_len += sizeof(pfcp_far_id_ie_t);

	create_pdr->far_id.far_id_value = pdr->far.far_id_value;

	/* UUR ID */
	create_pdr->urr_id_count = pdr->urr_id_count;
	for (uint8_t itr = 0; itr < pdr->urr_id_count; itr++) {
		pfcp_set_ie_header(&(create_pdr->urr_id[itr].header), PFCP_IE_URR_ID, UINT32_SIZE);

		create_pdr->urr_id[itr].urr_id_value = pdr->urr.urr_id_value;

		/* If Multiple urr id in one pdr */
		if (pdr->urr_id_count > 1 ) {
			create_pdr->urr_id[itr].urr_id_value = pdr->urr_id[itr].urr_id;
		}

		pdr_header_len += sizeof(pfcp_urr_id_ie_t);
	}

#ifdef GX_BUILD
	/* QER ID */
	if(pfcp_config.cp_type != SGWC) {
		uint8_t idx = 0;
		create_pdr->qer_id_count = pdr->qer_id_count;
		for(int itr1 = 0; itr1 < pdr->qer_id_count; itr1++) {
			pfcp_set_ie_header(&(create_pdr->qer_id[itr1].header), PFCP_IE_QER_ID,
								(sizeof(pfcp_qer_id_ie_t) - sizeof(pfcp_ie_header_t)));
			pdr_header_len += sizeof(pfcp_qer_id_ie_t);

			create_pdr->qer_id[itr1].qer_id_value = bearer->qer_id[idx].qer_id;
			idx++;
		}
	}
#else
	RTE_SET_USED(bearer);
#endif /* GX_BUILD */

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
fill_create_far(pfcp_create_far_ie_t *create_far, pdr_t *pdr, eps_bearer *bearer) {
	/* Filling create FAR */
	int far_hdr_len = 0;
	/* -> FAR ID */
	pfcp_set_ie_header(&(create_far->far_id.header), PFCP_IE_FAR_ID,
						(sizeof(pfcp_far_id_ie_t) - sizeof(pfcp_ie_header_t)));

	far_hdr_len += sizeof(pfcp_far_id_ie_t);

	create_far->far_id.far_id_value = pdr->far.far_id_value;

	/* -> Apply Action */
	pfcp_set_ie_header(&(create_far->apply_action.header), IE_APPLY_ACTION_ID, UINT8_SIZE);
	//create_far->acreate_farpply_action.apply_act_spare = 0;
	//create_far->apply_action.apply_act_spare2 = 0;
	//create_far->apply_action.apply_act_spare3 = 0;
	//create_far->apply_action.dupl = 0;
	//create_far->apply_action.nocp = 0;
	//create_far->apply_action.buff = 0;
	create_far->apply_action.forw = 1;
	create_far->apply_action.dupl= GET_DUP_STATUS(bearer->pdn->context);
	//create_far->apply_action.drop = 0;

	far_hdr_len += UINT8_SIZE + sizeof(pfcp_ie_header_t);
	/* -> Forwarding Parameters */
	int frw_hdr_len = 0;
	/* --> Destination Interface */
	pfcp_set_ie_header(&(create_far->frwdng_parms.dst_intfc.header),
								IE_DEST_INTRFACE_ID, UINT8_SIZE);

	frw_hdr_len += sizeof(pfcp_dst_intfc_ie_t);

	create_far->frwdng_parms.dst_intfc.interface_value =
										pdr->far.dst_intfc.interface_value;

	 if((pfcp_config.cp_type == SGWC) ||
	                         (pdr->far.dst_intfc.interface_value == DESTINATION_INTERFACE_VALUE_ACCESS)) {
		/* --> outer header creation */
		int len =(sizeof(create_far->frwdng_parms.outer_hdr_creation.ipv4_address)
				   + sizeof(create_far->frwdng_parms.outer_hdr_creation.teid)
				   + sizeof(create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc));

		pfcp_set_ie_header(&(create_far->frwdng_parms.outer_hdr_creation.header),
				PFCP_IE_OUTER_HDR_CREATION, len);

		frw_hdr_len += len + sizeof(pfcp_ie_header_t);;

		create_far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc = 0x0100;
		/* SGWC --> access --> ENB S1U */
		/* SAEGWC --> access --> ENB S1U */
		if (((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type ==  SAEGWC)) &&
				(pdr->far.dst_intfc.interface_value == DESTINATION_INTERFACE_VALUE_ACCESS)) {
			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s1u_enb_gtpu_teid;
			create_far->frwdng_parms.outer_hdr_creation.ipv4_address = bearer->s1u_enb_gtpu_ipv4.s_addr;
		}
		/* In far not found destinatiion instarface value, it's by default 0  pdr->far.dst_intfc.interface_value
		 * so insted of far we use pdi */
		/* SGWC --> core --> PGW S5S8  */
		if ((pfcp_config.cp_type == SGWC) &&
				(pdr->far.dst_intfc.interface_value ==  DESTINATION_INTERFACE_VALUE_CORE)) {
			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s5s8_pgw_gtpu_teid;
			create_far->frwdng_parms.outer_hdr_creation.ipv4_address = bearer->s5s8_pgw_gtpu_ipv4.s_addr;
		}
		/* PGWC --> access --> SGW S5S8 */
		if ((pfcp_config.cp_type == PGWC) &&
					pdr->far.dst_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
			create_far->frwdng_parms.outer_hdr_creation.teid = bearer->s5s8_sgw_gtpu_teid;
			create_far->frwdng_parms.outer_hdr_creation.ipv4_address = bearer->s5s8_sgw_gtpu_ipv4.s_addr;

		}
	}
	pfcp_set_ie_header(&(create_far->frwdng_parms.header), IE_FRWDNG_PARMS, frw_hdr_len);

	far_hdr_len += (frw_hdr_len + sizeof(pfcp_ie_header_t));

	pfcp_set_ie_header(&(create_far->header), IE_CREATE_FAR, far_hdr_len);

	return (far_hdr_len + sizeof(pfcp_ie_header_t));
}

#ifdef GX_BUILD
/**
 * @brief  : Fill create qer ie
 * @param  : pfcp_sess_est_req, buffer to be filled
 * @param  : bearer, bearer information
 * @return : Returns 0 on success, -1 otherwise
 */
static int
fill_create_qer(pfcp_sess_estab_req_t *pfcp_sess_est_req, eps_bearer *bearer) {

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
#endif /* GX_BUILD */

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
process_pfcp_sess_est_req(ue_context *context, uint32_t node_addr)
{
	uint32_t seq = 0;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};

	for(uint8_t itr = 0; itr < context->num_pdns; itr++) {

		pdn = context->pdns[itr];

		if(pdn == NULL)
			continue;

		/* PDN upf ip address and peer node address, if not match than we assume CP connected to the onthere DP */
		if(pdn->upf_ipv4.s_addr != node_addr) {
			clLog(clSystemLog, eCLSeverityDebug, "%s:%d Match Not Found : Peer Node Address : %u , PDN upf ip addres : %u\n",
						__func__, __LINE__, node_addr, pdn->upf_ipv4.s_addr);
			//return -1;
		}

		/* need to think anout it */
		seq = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, seq);

		/* Filling header */
		set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req.header), PFCP_SESSION_ESTABLISHMENT_REQUEST,
				HAS_SEID, seq);

		/* Assing DP SEID */
		clLog(clSystemLog, eCLSeverityDebug, "%s:%d : DP SEID %u\n",
					__func__, __LINE__, pdn->dp_seid);

		pfcp_sess_est_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

		char pAddr[INET_ADDRSTRLEN] ;
		inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

		unsigned long node_value = inet_addr(pAddr);

		set_node_id(&(pfcp_sess_est_req.node_id), node_value);

		set_fseid(&(pfcp_sess_est_req.cp_fseid), pdn->seid, node_value);

		/* Filling PDN structure*/
		pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
		pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
		pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
		pfcp_sess_est_req.pdn_type.pdn_type =  1;

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
				fill_create_pdr(&(pfcp_sess_est_req.create_pdr[pdr_idx]), bearer->pdrs[itr2], bearer);
				fill_create_far(&(pfcp_sess_est_req.create_far[pdr_idx]), bearer->pdrs[itr2], bearer);
				fill_create_urr(&(pfcp_sess_est_req.create_urr[pdr_idx]), bearer->pdrs[itr2]);

				if (pfcp_config.cp_type != SGWC) {
#ifdef GX_BUILD
					for(int sdf_itr1 = 0; sdf_itr1 < bearer->pdrs[itr2]->pdi.sdf_filter_cnt; sdf_itr1++) {
						enum flow_status f_status = pdn->policy.pcc_rule[sdf_itr1].dyn_rule.flow_status;

						fill_create_pdr_sdf_rules(pfcp_sess_est_req.create_pdr, bearer->dynamic_rules[sdf_itr1], pdr_idx);
						fill_gate_status(&pfcp_sess_est_req, pdr_idx, f_status);

					}
#endif /* GX_BUILD */
				}
				pdr_idx++;
			}

#ifdef GX_BUILD
			if(pfcp_config.cp_type != SGWC) {
				/* Need to think about it. */
				int idx = 0;
				uint8_t qer_count = 0;
				for (uint8_t itr3 = 0; itr3 < bearer->pdr_count; itr3++) {
					qer_count = bearer->pdrs[itr3]->qer_id_count;
					for(uint8_t itr4 = 0; itr4 < qer_count; itr4++) {
						pfcp_sess_est_req.create_pdr[itr3].qer_id[itr4].qer_id_value =
							bearer->qer_id[idx].qer_id;
					}
					idx++;

				}

				fill_create_qer(&(pfcp_sess_est_req), bearer);
				pfcp_sess_est_req.create_qer_count += bearer->qer_count;

			}
#endif /* GX_BUIDL */

		} /* for loop 1 */

		/* Fill the fqcsid into the session est request */
		if (pfcp_config.cp_type != PGWC) {
			/* Set SGW FQ-CSID */
			if ((context->sgw_fqcsid)->num_csid) {
				set_fq_csid_t(&pfcp_sess_est_req.sgw_c_fqcsid, context->sgw_fqcsid);
				(pfcp_sess_est_req.sgw_c_fqcsid).node_address = ntohl(pfcp_config.pfcp_ip.s_addr);
			}
			/* Set MME FQ-CSID */
			if((context->mme_fqcsid)->num_csid) {
				set_fq_csid_t(&pfcp_sess_est_req.mme_fqcsid, context->mme_fqcsid);
			}
			/* set PGWC FQ-CSID */
			if (pfcp_config.cp_type != SAEGWC) {
				set_fq_csid_t(&pfcp_sess_est_req.pgw_c_fqcsid, context->pgw_fqcsid);
			}
		} else {
			/* Set PGW FQ-CSID */
			if ((context->pgw_fqcsid)->num_csid) {
				set_fq_csid_t(&pfcp_sess_est_req.pgw_c_fqcsid, context->pgw_fqcsid);
				(pfcp_sess_est_req.pgw_c_fqcsid).node_address = ntohl(pfcp_config.pfcp_ip.s_addr);
			}
			/* Set SGW C FQ_CSID */
			if ((context->sgw_fqcsid)->num_csid) {
				set_fq_csid_t(&pfcp_sess_est_req.sgw_c_fqcsid, context->sgw_fqcsid);
			}
			/* Set MME FQ-CSID */
			if((context->mme_fqcsid)->num_csid) {
				set_fq_csid_t(&pfcp_sess_est_req.mme_fqcsid, context->mme_fqcsid);
			}
		}

		/* Fetch and update resp info */
		/* Lookup Stored the session information. */
		if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Failed to add response in entry in SM_HASH\n", __file__
					,__func__, __LINE__);
			return -1;
		}

		resp->eps_bearer_id = pdn->default_bearer_id;
		resp->state = PFCP_SESS_EST_REQ_SNT_STATE ;
		resp->proc = RESTORATION_RECOVERY_PROC;
		/* Update  PDN procedure */
		pdn->proc = RESTORATION_RECOVERY_PROC;
		pdn->state = PFCP_SESS_EST_REQ_SNT_STATE;

		uint8_t pfcp_msg[2048]={0};
		/* Think about it , if CP connected with multiple DP */
		upf_pfcp_sockaddr.sin_addr.s_addr = pdn->upf_ipv4.s_addr;
		int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg, INTERFACE);

		pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
		header->message_len = htons(encoded - 4);

		upf_pfcp_sockaddr.sin_addr.s_addr = node_addr;
		if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ){
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Error sending: %i\n",
					__func__, __LINE__, errno);
			return -1;
		 }
	} /* for loop */
	return 0;
}

/**
 * @brief  : Fucnton to get sess ID and send session est. request to peer node
 * @param  : csids
 * @param  : node_addr, node address
 * @return : Returns 0 on success, -1 otherwise
 */
static int
create_sess_by_csid_entry(fqcsid_t *csids, uint32_t node_addr)
{
	int ret = 0;
	ue_context *context = NULL;

	/* Get the session ID by csid */
	for (uint8_t itr1 = 0; itr1 < csids->num_csid; itr1++) {
		sess_csid *tmp = NULL;
		sess_csid *current = NULL;

		tmp = get_sess_csid_entry(csids->local_csid[itr1], REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					FORMAT"Entry not found, CSID: %u\n", ERR_MSG,
					csids->local_csid[itr1]);
			continue;
		}

		if (tmp->cp_seid == 0 && tmp->next == 0 ) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			uint32_t teid_key = UE_SESS_ID(current->cp_seid);

			clLog(clSystemLog, eCLSeverityDebug, FORMAT" TEID : %u\n", ERR_MSG, teid_key);

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || !context) {
				clLog(clSystemLog, eCLSeverityCritical,
						FORMAT"Error: UE contetx not found fot TEID %u \n",
						ERR_MSG, teid_key);
				/* Assign Next node address */
				current = current->next;
				continue;
			}

			if (process_pfcp_sess_est_req(context, node_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: TEID %u \n",
						ERR_MSG, teid_key);
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
create_peer_node_sess(uint32_t node_addr, uint8_t iface) {

	clLog(clSystemLog, eCLSeverityDebug, "%s:START\n", __func__);
	//int ret = 0;
	fqcsid_t csids = {0};
	fqcsid_t *peer_csids = NULL;

	/* Get peer CSID associated with node */
	/*ntohl()*/
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
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer CSIDs are not found, Node_Addr:"IPV4_ADDR"\n",
				ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
		return -1;
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_csids->local_csid[itr];
		key.node_addr = peer_csids->node_addr;

		tmp = get_peer_csid_entry(&key, iface);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug, FORMAT"Entry not found \n", ERR_MSG);
			return -1;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		csids.node_addr = tmp->node_addr;
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug, FORMAT"Local CSIDs not found\n", ERR_MSG);
		return -1;
	}

	if (iface == SX_PORT_ID) {
		create_sess_by_csid_entry(&csids, node_addr);
	}
	return 0;
}

/*  Function to get peer recovery time stamp */
//int
//get_peer_recovery_time_stamp(uint32_t *ip, uint32_t *recov_time) {
//
//	int ret = 0;
//	uint32_t key = UINT32_MAX;
//
//	/* copy peer node address */
//	memcpy(&key,ip,UINT32_SIZE);
//
//	ret = rte_hash_add_key_data(heartbeat_recovery_hash,
//			(const void *)&key, recov_time);
//	if (ret < 0) {
//		clLog(clSystemLog, eCLSeverityCritical, FORMAT"ERROR : %s\n", ERR_MSG,
//				strerror(ret));
//		return ret;
//	}
//
//	return ret;
//}

/* Function to send pfcp association setup request in recovery mode */
int
process_aasociation_setup_req(uint32_t node_addr)
{
	int ret = 0;
	upf_context_t *upf_context = NULL;
	pfcp_assn_setup_req_t pfcp_ass_setup_req = {0};

	/* Lookup upf context of peer node */
	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(node_addr), (void **) &(upf_context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"NO ENTRY FOUND IN UPF HASH [%u]\n",
				ERR_MSG, node_addr);
		return -1;
	}

	/* Changing status and state */
	upf_context->assoc_status = ASSOC_IN_PROGRESS;
	upf_context->state = PFCP_ASSOC_REQ_SNT_STATE;

	/* Filling pfcp associtaion setup request */
	fill_pfcp_association_setup_req(&pfcp_ass_setup_req);

	uint8_t pfcp_msg[256] = {0};
	int encoded = encode_pfcp_assn_setup_req_t(&pfcp_ass_setup_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	/* ask vishal :  Do we need request time for recovery */
	/*  Do we need to update cli stat */
	/* Peer node address */
	upf_pfcp_sockaddr.sin_addr.s_addr = node_addr;
	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,"Error sending\n\n");
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,"Association request sent to peer node : [%u]\n\n",
				node_addr);
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
	clLog(clSystemLog, eCLSeverityDebug,"RECOVERY MODE: Thread Start , peer node : [%u]\n\n",
			recov_peer_addr);

	/* */
	create_peer_node_sess(recov_peer_addr, SX_PORT_ID);


	clLog(clSystemLog, eCLSeverityDebug,"RECOVERY MODE: Thread Stop , peer node : [%u]\n\n",
			recov_peer_addr);

	/* Checking All session est. response are received or not */
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
process_asso_resp(void *_msg, struct sockaddr_in *peer_addr) {

	int ret = 0;
	upf_context_t *upf_context = NULL;
	msg_info *msg = (msg_info *)_msg;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(msg->upf_ipv4.s_addr), (void **) &(upf_context));

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, FORMAT"NO ENTRY FOUND IN UPF HASH [%u]\n",
				ERR_MSG, msg->upf_ipv4.s_addr);
		return -1;
	}

	recov_peer_addr = msg->upf_ipv4.s_addr;
	upf_context->assoc_status = ASSOC_ESTABLISHED;
	upf_context->state = PFCP_ASSOC_RESP_RCVD_STATE;

	/* Checking Assign TEIDRI */
	if(msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range != upf_context->teidri){
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"ERROR : TEIDRI MATCH NOT FOUND ,NODE ADDR : [%u] , PERVIOUS TEIDRI : [%d]"
				"TEIDRI : [%d] \n", ERR_MSG, msg->upf_ipv4.s_addr, upf_context->teidri,
				msg->pfcp_msg.pfcp_ass_resp.user_plane_ip_rsrc_info[0].teid_range);
		/* Cleanup is on low priority */
		/* Cleanip Initiate for peer node */
		del_peer_node_sess(recov_peer_addr, SX_PORT_ID);
		return -1;
	}

	/* Adding ip to cp  heartbeat when dp returns the association response*/
	//add_ip_to_heartbeat_hash(peer_addr,
	//					msg->pfcp_msg.pfcp_ass_resp.rcvry_time_stmp.rcvry_time_stmp_val);


	clLog(clSystemLog, eCLSeverityDebug, "TEIDRI MATCT FOUND : NODE ADDR : [%u] , PERVIOUS TEIDRI : [%d] \n",
				peer_addr->sin_addr.s_addr, upf_context->teidri);


	ret  = pthread_create(&recov_thread, NULL, &recov_est_thread_func, NULL);
	if (ret != 0) {
		clLog(clSystemLog, eCLSeverityInfo, "\ncan't create RECOVRY MODE thread :[%s]", strerror(ret));
		return ret;
	}
	else {
		clLog(clSystemLog, eCLSeverityInfo, "\n RECOVERY MODE thread created successfully\n");
	}

	return 0;

}

/* Function to process pfpc session establishment response in recovery mode  while recovering affected session */
int
process_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp)
{
	clLog(clSystemLog, eCLSeverityDebug, "RECOVERY MODE : session establishment response received  \n");
	if (pfcp_sess_est_rsp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"ERROR:%s\n",
				ERR_MSG, strerror(errno));
		return -1;
	}

	int ret = 0;
	//eps_bearer *bearer = NULL;
	struct resp_info *resp = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint64_t sess_id = pfcp_sess_est_rsp->header.seid_seqno.has_seid.seid;
	//uint64_t dp_sess_id = pfcp_sess_est_rsp->up_fseid.seid;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(sess_id, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Failed to get response entry in SM_HASH for SEID : 0x%x \n", __file__
				,__func__, __LINE__, sess_id);
		return -1;
	}


	/* Need to think on eps_bearer_id*/
	//uint8_t ebi_index = UE_BEAR_ID(sess_id) - 5;
	uint8_t ebi_index = resp->eps_bearer_id - 5;
	//bearer = context->eps_bearers[ebi_index];

	/* Update the UE state */
	pdn = GET_PDN(context, ebi_index);
	if(pdn == NULL){
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Failed to get pdn \n", __func__, __LINE__);
		return -1;
	}

	pdn->state = CONNECTED_STATE;


	uint16_t old_csid =
		(context->up_fqcsid)->local_csid[(context->up_fqcsid)->num_csid - 1];
	fqcsid_t *tmp = NULL;
	fqcsid_t *fqcsid = NULL;
	fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to allocate the memory for fqcsids entry\n",
				ERR_MSG);
		return -1;
	}

	/* SGW FQ-CSID */
	if (pfcp_sess_est_rsp->sgw_u_fqcsid.header.len) {
		if (pfcp_sess_est_rsp->sgw_u_fqcsid.number_of_csids) {
			/* Stored the SGW CSID by SGW Node address */
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->sgw_u_fqcsid.node_address,
					ADD);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			tmp->node_addr = pfcp_sess_est_rsp->sgw_u_fqcsid.node_address;

			for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->sgw_u_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr]) {
						match = 1;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr];
				}
			}
			for(uint8_t itr1 = 0; itr1 < pfcp_sess_est_rsp->sgw_u_fqcsid.number_of_csids; itr1++) {
					fqcsid->local_csid[fqcsid->num_csid++] =
						pfcp_sess_est_rsp->sgw_u_fqcsid.pdn_conn_set_ident[itr1];
			}

			fqcsid->node_addr = pfcp_sess_est_rsp->sgw_u_fqcsid.node_address;

			for (uint8_t itr2 = 0; itr2 < tmp->num_csid; itr2++) {
				if (tmp->local_csid[itr2] == old_csid) {
					for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_est_rsp->pgw_u_fqcsid.header.len) {
		if (pfcp_sess_est_rsp->pgw_u_fqcsid.number_of_csids) {
			/* Stored the PGW CSID by PGW Node address */
			tmp = get_peer_addr_csids_entry(pfcp_sess_est_rsp->pgw_u_fqcsid.node_address,
					ADD);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			tmp->node_addr = pfcp_sess_est_rsp->pgw_u_fqcsid.node_address;

			for(uint8_t itr = 0; itr < pfcp_sess_est_rsp->pgw_u_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr]) {
						match = 1;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr];
				}
			}
			for(uint8_t itr1 = 0; itr1 < pfcp_sess_est_rsp->pgw_u_fqcsid.number_of_csids; itr1++) {
					fqcsid->local_csid[fqcsid->num_csid++] =
						pfcp_sess_est_rsp->pgw_u_fqcsid.pdn_conn_set_ident[itr1];
			}

			fqcsid->node_addr = pfcp_sess_est_rsp->pgw_u_fqcsid.node_address;

			for (uint8_t itr2 = 0; itr2 < tmp->num_csid; itr2++) {
				if (tmp->local_csid[itr2] == old_csid) {
					for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}
		}
	}
	/* TODO: Add the handling if SGW or PGW not support Partial failure */
	/* Link peer node SGW or PGW csid with local csid */
	if (pfcp_config.cp_type != PGWC) {
		ret = update_peer_csid_link(fqcsid, context->sgw_fqcsid);
	} else {
		ret = update_peer_csid_link(fqcsid, context->pgw_fqcsid);
	}

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Update the UP CSID in the context */
	context->up_fqcsid = fqcsid;

	return 0;
}
