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
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"

#ifdef CP_BUILD
#include "ue.h"
#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "ipc_api.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "gtpc_session.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#endif /* CP_BUILD */

#ifdef DP_BUILD
extern struct in_addr dp_comm_ip;
#endif /* DP_BUILD */

#ifdef CP_BUILD
pfcp_config_t pfcp_config;

extern int gx_app_sock;

#define size sizeof(pfcp_sess_mod_req_t)
/* Header Size of set_upd_forwarding_param ie */
#define UPD_PARAM_HEADER_SIZE 4
extern int pfcp_fd;

/* len of flags*/
#define FLAG_LEN 2

void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req)
{
	uint32_t seq = 1;

	memset(pfcp_sess_del_req, 0, sizeof(pfcp_sess_del_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_DELETION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_req->header),
		PFCP_SESSION_DELETION_REQUEST, HAS_SEID, seq);

}

void
fill_pfcp_sess_set_del_req( pfcp_sess_set_del_req_t *pfcp_sess_set_del_req)
{

	uint32_t seq = 1;
	char sgwc_addr[INET_ADDRSTRLEN] = {0};
	char pgwc_addr[INET_ADDRSTRLEN] = {0};
	char mme_addr[INET_ADDRSTRLEN]  = {0};
	char sgwu_addr[INET_ADDRSTRLEN] = {0};
	char pgwu_addr[INET_ADDRSTRLEN] = {0};
	uint32_t node_value = 0;

	/*Added hardcoded value to remove compile error.Right now,we are using
	function. Will remove hard value  */
	const char* pAddr = "192.168.0.10";
	const char* twan_addr = "192.16.0.1";
	const char* epdg_addr = "192.16.0.2";
	unsigned long sgwc_value = 0;

	memset(pfcp_sess_set_del_req, 0, sizeof(pfcp_sess_set_del_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_SET_DELETION_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, HAS_SEID, seq);

	node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgw_c_fqcsid), sgwc_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgw_c_fqcsid), pgwc_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwu_addr, INET_ADDRSTRLEN);
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgw_u_fqcsid), sgwu_value);

	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgw_u_fqcsid), pgwu_value);

	// set of twan fqcsid
	//TODO : IP addres for twan is hardcoded
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->twan_fqcsid), twan_value);

	// set of epdg fqcsid
	//TODO : IP addres for epdgg is hardcoded
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->epdg_fqcsid), epdg_value);

	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->mme_fqcsid), mme_value);

}

/* REVIEW: Context will remove after merging */
void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer *bearer,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[], uint8_t x2_handover_flag)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	if( header != NULL)
		clLog(sxlogger, eCLSeverityDebug, "TEID[%d]\n", header->teid.has_teid.teid);

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/*SP: This depends on condition in pcrf data(pcrf will send bar_rule_id if it needs to be delated). Need to handle after pcrf integration*/
	/* removing_bar(&(pfcp_sess_mod_req->remove_bar)); */

	//set create PDR

	/************************************************
	 *  cp_type  count     FTEID_1          FTEID_2 *
	 *************************************************
	 In case MBR received from MME:-
	 SGWC         1      enodeB               -
	 PGWC         -        -                  -
	 SAEGWC       1      enodeB               -
	 *************************************************
	 In case of CSResp received from PGWC to SGWC :-
	 SGWC <----CSResp--- PGWC
	 |
	 pfcp_sess_mod_req
	 |
	 v
	 SGWU
	 In above scenario:
	 count = 1 ,     FTEID_1 = s5s8 PGWU
	 ************************************************/
	/*SP: create pdr IE is not needed in session modification request , hence removing*/
	/*
	pfcp_sess_mod_req->create_pdr_count = 1;

	for( int i = 0; i < pfcp_sess_mod_req->create_pdr_count ; i++)
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[i]));
	*/

	if (pfcp_sess_mod_req->create_pdr_count) {
		fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req, bearer);
	}

	/*SP: This depends on condition  if the CP function requests the UP function to create a new BAR
	  Need to add condition to check if CP needs creation of BAR*/
	for( int i = 0; i < pfcp_sess_mod_req->create_pdr_count ; i++){
		if((pfcp_sess_mod_req->create_pdr[i].header.len) &&
				(pfcp_sess_mod_req->create_pdr[i].far_id.header.len)){
			for( int j = 0; j < pfcp_sess_mod_req->create_far_count ; j++){
				if(pfcp_sess_mod_req->create_far[i].bar_id.header.len){
					/* TODO: Pass bar_id from pfcp_session_mod_req->create_far[i].bar_id.bar_id_value
					   to set bar_id*/
					creating_bar(&(pfcp_sess_mod_req->create_bar));
				}
			}
		}
	}

	/*SP: Adding FAR IE*/
	for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count ; itr1++) {
		for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
			if(bearer->pdrs[itr]->pdi.src_intfc.interface_value !=
					update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value){
				pdr_ctxt = bearer->pdrs[itr];
				updating_far(&(pfcp_sess_mod_req->update_far[itr1]));
				pfcp_sess_mod_req->update_far[itr1].far_id.far_id_value =
					pdr_ctxt->far.far_id_value;
				pfcp_sess_mod_req->update_far[itr1].apply_action.forw = PRESENT;
				if (pfcp_sess_mod_req->update_far[itr1].apply_action.forw == PRESENT) {
					uint16_t len = 0;
					len += set_upd_forwarding_param(&(pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms));
					/* Currently take as hardcoded value */
					len += UPD_PARAM_HEADER_SIZE;
					pfcp_sess_mod_req->update_far[itr1].header.len += len;
				}
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.outer_hdr_creation.teid =
					update_far[itr1].upd_frwdng_parms.outer_hdr_creation.teid;
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
					(update_far[itr1].upd_frwdng_parms.outer_hdr_creation.ipv4_address);
				pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value =
					update_far[itr1].upd_frwdng_parms.dst_intfc.interface_value;

				if(x2_handover_flag) {

					set_pfcpsmreqflags(&(pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags));
					pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.pfcpsmreq_flags.sndem = 1;
					pfcp_sess_mod_req->update_far[itr1].header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);
					pfcp_sess_mod_req->update_far[itr1].upd_frwdng_parms.header.len += sizeof(struct  pfcp_pfcpsmreq_flags_ie_t);

				}
			}

		}
	}

	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case SAEGWC :
			if(pfcp_sess_mod_req->create_pdr_count){
				for(int itr = 0; itr < pfcp_sess_mod_req->create_pdr_count; itr++) {
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.teid =
						bearer->pdrs[itr]->pdi.local_fteid.teid ;
					/* TODO: Revisit this for change in yang */
					pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
						htonl(bearer->pdrs[itr]->pdi.ue_addr.ipv4_address);
					pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
						bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
					pfcp_sess_mod_req->create_pdr[itr].pdi.src_intfc.interface_value =
						bearer->pdrs[itr]->pdi.src_intfc.interface_value;
				}
			}
			break;

		case PGWC :
			break;

		default :
			printf("%s:%d default pfcp sess mod req\n", __func__, __LINE__);
			break;
	}

	// set of update QER
	/*SP: No QER is not generated previously, No update needed*/
	/*
	pfcp_sess_mod_req->update_qer_count = bearer->qer_count;

	for(int i=0; i < pfcp_sess_mod_req->update_qer_count; i++ ){
		updating_qer(&(pfcp_sess_mod_req->update_qer[i]));
		pfcp_sess_mod_req->update_qer[i] == bearer->qer_id.qer.id;
	}
	*/

	// set of update BAR
	/*SP: If previously created BAR needs to be modified, this IE should be included*/
	/*
	 updating_bar(&(pfcp_sess_mod_req->update_bar));
	*/

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	      excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}

	/*SP: This IE is included if node supports Partial failure handling support
	      excluding this IE since we dont have this support  */
	/*
	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->sgw_c_fqcsid), sgwc_value);

	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_mod_req->mme_fqcsid), mme_value);

	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->pgw_c_fqcsid), pgwc_value);

	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_mod_req->epdg_fqcsid), epdg_value);

	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_mod_req->twan_fqcsid), twan_value);
	*/

	 /*SP: Not in use*/
	 /*
		set_up_inactivity_timer(&(pfcp_sess_mod_req->user_plane_inact_timer));
	 */

	/*SP: This IE is included if QAURR flag is set (this flag is in PFCPSMReq-Flags IE) or Query URR IE is present,
	  Adding check to exclud  this IE if any of these condition is not satisfied*/
	if(pfcp_sess_mod_req->pfcpsmreq_flags.qaurr ||
			pfcp_sess_mod_req->query_urr_count){
		set_query_urr_refernce(&(pfcp_sess_mod_req->query_urr_ref));
	}

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_mod_req->trc_info));

}

void
sdf_pkt_filter_to_string(sdf_pkt_fltr *sdf_flow,
		char *sdf_str , uint8_t direction)
{
	char local_ip[INET_ADDRSTRLEN];
	char remote_ip[INET_ADDRSTRLEN];

	snprintf(local_ip, sizeof(local_ip), "%s",
			inet_ntoa(sdf_flow->local_ip_addr));
	snprintf(remote_ip, sizeof(remote_ip), "%s",
			inet_ntoa(sdf_flow->remote_ip_addr));

        if (direction == TFT_DIRECTION_DOWNLINK_ONLY) {
                snprintf(sdf_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
                                PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
                                " 0x%"PRIx8"/0x%"PRIx8"",
                                local_ip, sdf_flow->local_ip_mask, remote_ip,
                                sdf_flow->remote_ip_mask,
                                (sdf_flow->local_port_low),
                                (sdf_flow->local_port_high),
                                (sdf_flow->remote_port_low),
                                (sdf_flow->remote_port_high),
                                sdf_flow->proto_id, sdf_flow->proto_mask);
        } else if (direction == TFT_DIRECTION_UPLINK_ONLY) {
                snprintf(sdf_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
                                PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16
                                " 0x%"PRIx8"/0x%"PRIx8"",
                                local_ip, sdf_flow->local_ip_mask, remote_ip,
                                sdf_flow->remote_ip_mask,
                                (sdf_flow->local_port_low),
                                (sdf_flow->local_port_high),
                                (sdf_flow->remote_port_low),
                                (sdf_flow->remote_port_high),
                                sdf_flow->proto_id, sdf_flow->proto_mask);
		}
}

void
fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		eps_bearer *bearer)
{
	pfcp_sess_mod_req->create_pdr_count = bearer->pdr_count;

	for(int i = 0; i < pfcp_sess_mod_req->create_pdr_count; i++) {
		pfcp_sess_mod_req->create_pdr[i].qer_id_count = 1;
		//pfcp_sess_mod_req->create_pdr[i].qer_id_count = bearer->qer_count;
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[i]), bearer->pdrs[i]->pdi.src_intfc.interface_value);
		pfcp_sess_mod_req->create_far_count++;
		creating_far(&(pfcp_sess_mod_req->create_far[i]));
	}

	for(int itr = 0; itr < pfcp_sess_mod_req->create_pdr_count ; itr++) {
		pfcp_sess_mod_req->create_pdr[itr].pdr_id.rule_id  =
			bearer->pdrs[itr]->rule_id;
		pfcp_sess_mod_req->create_pdr[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;
		pfcp_sess_mod_req->create_pdr[itr].precedence.prcdnc_val =
			bearer->pdrs[itr]->prcdnc_val;

		pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.teid =
			bearer->pdrs[itr]->pdi.local_fteid.teid;

		if((pfcp_config.cp_type == SGWC) ||
				(bearer->pdrs[itr]->pdi.src_intfc.interface_value ==
				SOURCE_INTERFACE_VALUE_ACCESS)) {
			/*No need to send ue ip and network instance for pgwc access interface or
			 * for any sgwc interface */
			uint32_t size_ie = 0;
			size_ie = pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t);
			size_ie = size_ie + pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].header.len =
				pfcp_sess_mod_req->create_pdr[itr].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.header.len = 0;
			pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.header.len = 0;
		}else{
			pfcp_sess_mod_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
				bearer->pdrs[itr]->pdi.ue_addr.ipv4_address;
			strncpy((char *)pfcp_sess_mod_req->create_pdr[itr].pdi.ntwk_inst.ntwk_inst,
				(char *)&bearer->pdrs[itr]->pdi.ntwk_inst.ntwk_inst, 32);
		}

		if (
				((PGWC == pfcp_config.cp_type) || (SAEGWC == pfcp_config.cp_type)) &&
				(SOURCE_INTERFACE_VALUE_CORE ==
				bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {

			uint32_t size_ie = 0;

			size_ie = pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_mod_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_mod_req->create_pdr[itr].pdi.header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].header.len =
				pfcp_sess_mod_req->create_pdr[itr].header.len - size_ie;
			pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.header.len = 0;

		} else {
			pfcp_sess_mod_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
		}

		pfcp_sess_mod_req->create_pdr[itr].pdi.src_intfc.interface_value =
			bearer->pdrs[itr]->pdi.src_intfc.interface_value;

		pfcp_sess_mod_req->create_far[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;

#ifdef GX_BUILD
		if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
			pfcp_sess_mod_req->create_pdr[itr].qer_id_count =
				bearer->pdrs[itr]->qer_id_count;
			for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr[itr].qer_id_count; itr1++) {
				pfcp_sess_mod_req->create_pdr[itr].qer_id[itr1].qer_id_value =
					bearer->pdrs[itr]->qer_id[itr1].qer_id;
			}
		}
#endif

		if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {
			pfcp_sess_mod_req->create_far[itr].apply_action.forw = PRESENT;
			if (pfcp_sess_mod_req->create_far[itr].apply_action.forw == PRESENT) {
				uint16_t len = 0;

				if (
						(SAEGWC == pfcp_config.cp_type) ||
						(SOURCE_INTERFACE_VALUE_ACCESS ==
						 bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {
					set_destination_interface(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc));
					pfcp_set_ie_header(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms.header),
							IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

					pfcp_sess_mod_req->create_far[itr].frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

					len += sizeof(pfcp_dst_intfc_ie_t);
					len += UPD_PARAM_HEADER_SIZE;

					pfcp_sess_mod_req->create_far[itr].header.len += len;

					pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
						bearer->pdrs[itr]->far.dst_intfc.interface_value;
				} else {
					pfcp_sess_mod_req->create_far[itr].apply_action.forw = NO_FORW_ACTION;
				}
			}
		} else
		if ((SGWC == pfcp_config.cp_type) &&
			(DESTINATION_INTERFACE_VALUE_CORE ==
			 bearer->pdrs[itr]->far.dst_intfc.interface_value) &&
			(bearer->s5s8_pgw_gtpu_teid != 0) &&
			(bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0))
		{
			uint16_t len = 0;
			len += set_forwarding_param(&(pfcp_sess_mod_req->create_far[itr].frwdng_parms));
			/* Currently take as hardcoded value */
			len += UPD_PARAM_HEADER_SIZE;
			pfcp_sess_mod_req->create_far[itr].header.len += len;

			pfcp_sess_mod_req->create_far[itr].apply_action.forw = PRESENT;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->pdrs[itr]->far.outer_hdr_creation.ipv4_address;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.outer_hdr_creation.teid =
					bearer->pdrs[itr]->far.outer_hdr_creation.teid;
			pfcp_sess_mod_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
					bearer->pdrs[itr]->far.dst_intfc.interface_value;
		}

	} /*for loop*/

#ifdef GX_BUILD
	if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
		pfcp_sess_mod_req->create_qer_count = bearer->qer_count;
		qer_t *qer_context = NULL;
		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_qer_count ; itr1++) {
			creating_qer(&(pfcp_sess_mod_req->create_qer[itr1]));
			pfcp_sess_mod_req->create_qer[itr1].qer_id.qer_id_value  =
				bearer->qer_id[itr1].qer_id;
			qer_context = get_qer_entry(pfcp_sess_mod_req->create_qer[itr1].qer_id.qer_id_value);
			/* Assign the value from the PDR */
			if(qer_context){
				pfcp_sess_mod_req->create_qer[itr1].maximum_bitrate.ul_mbr  =
					qer_context->max_bitrate.ul_mbr;
				pfcp_sess_mod_req->create_qer[itr1].maximum_bitrate.dl_mbr  =
					qer_context->max_bitrate.dl_mbr;
				pfcp_sess_mod_req->create_qer[itr1].guaranteed_bitrate.ul_gbr  =
					qer_context->guaranteed_bitrate.ul_gbr;
				pfcp_sess_mod_req->create_qer[itr1].guaranteed_bitrate.dl_gbr  =
					qer_context->guaranteed_bitrate.dl_gbr;
			}
		}

		for(int itr1 = 0; itr1 < pfcp_sess_mod_req->create_pdr_count ; itr1++) {
			fill_sdf_rules_modification(pfcp_sess_mod_req, bearer, itr1);
		}
	}
#endif /* GX_BUILD */

}

void fill_gate_status(pfcp_sess_estab_req_t *pfcp_sess_est_req,
	int qer_counter,
	enum flow_status f_status)
{
    switch(f_status)
    {
        case FL_ENABLED_UPLINK:
            pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_OPEN;
	    pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_CLOSED;
        break;

        case FL_ENABLED_DOWNLINK:
            pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_CLOSED;
	    pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_OPEN;
        break;

        case FL_ENABLED:
            pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_OPEN;
	    pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_OPEN;
        break;

        case FL_DISABLED:
            pfcp_sess_est_req->create_qer[qer_counter].gate_status.ul_gate  = UL_GATE_CLOSED;
	    pfcp_sess_est_req->create_qer[qer_counter].gate_status.dl_gate  = UL_GATE_CLOSED;
        break;
        case FL_REMOVED:
            /*TODO*/
        break;
    }
}

void sdf_pkt_filter_add(pfcp_sess_estab_req_t* pfcp_sess_est_req,
    eps_bearer* bearer,
    int pdr_counter,
    int sdf_filter_count,
    int dynamic_filter_cnt,
    int flow_cnt,
    uint8_t direction)
{
    int len = 0;
    pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].fd = 1;
    sdf_pkt_filter_to_string(&(bearer->dynamic_rules[dynamic_filter_cnt]->flow_desc[flow_cnt].sdf_flw_desc),
        (char*)(pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

    pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
        strlen((char*)(&pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc));

    len += FLAG_LEN;
    len += sizeof(uint16_t);
    len += pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

    pfcp_set_ie_header(
        &(pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

    /*VG updated the header len of pdi as sdf rules has been added*/
    pfcp_sess_est_req->create_pdr[pdr_counter].pdi.header.len += (len + sizeof(pfcp_ie_header_t));
    pfcp_sess_est_req->create_pdr[pdr_counter].header.len += (len + sizeof(pfcp_ie_header_t));
}

void sdf_pkt_filter_mod(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
    eps_bearer* bearer,
    int pdr_counter,
    int sdf_filter_count,
    int dynamic_filter_cnt,
    int flow_cnt,
    uint8_t direction)
{
    int len = 0;
    pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].fd = 1;
    sdf_pkt_filter_to_string(&(bearer->dynamic_rules[dynamic_filter_cnt]->flow_desc[flow_cnt].sdf_flw_desc),
        (char*)(pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc), direction);

    pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc =
        strlen((char*)(&pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].flow_desc));

    len += FLAG_LEN;
    len += sizeof(uint16_t);
    len += pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].len_of_flow_desc;

    pfcp_set_ie_header(
        &(pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter[sdf_filter_count].header), PFCP_IE_SDF_FILTER, len);

    /*VG updated the header len of pdi as sdf rules has been added*/
    pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.header.len += (len + sizeof(pfcp_ie_header_t));
    pfcp_sess_mod_req->create_pdr[pdr_counter].header.len += (len + sizeof(pfcp_ie_header_t));
}

int fill_sdf_rules_modification(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
	eps_bearer* bearer,
	int pdr_counter)
{
    int ret = 0;
    int sdf_filter_count = 0;
    /*VG convert pkt_filter_strucutre to char string*/
    for(int index = 0; index < bearer->num_dynamic_filters; index++) {

        pfcp_sess_mod_req->create_pdr[pdr_counter].precedence.prcdnc_val = bearer->dynamic_rules[index]->precedence;
        // itr is for flow information counter
        // sdf_filter_count is for SDF information counter
        for(int itr = 0; itr < bearer->dynamic_rules[index]->num_flw_desc; itr++) {

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {

                if((pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

                    sdf_pkt_filter_mod(
                        pfcp_sess_mod_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_UPLINK_ONLY);
                    sdf_filter_count++;
                }

            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {
                if((pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
                    sdf_pkt_filter_mod(
                        pfcp_sess_mod_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_DOWNLINK_ONLY);
                    sdf_filter_count++;
                }
            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }
        }

	pfcp_sess_mod_req->create_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

    }
    return ret;
}

int fill_sdf_rules(pfcp_sess_estab_req_t* pfcp_sess_est_req,
	eps_bearer* bearer,
	int pdr_counter)
{
    int ret = 0;
    int sdf_filter_count = 0;
    /*VG convert pkt_filter_strucutre to char string*/
    for(int index = 0; index < bearer->num_dynamic_filters; index++) {

        pfcp_sess_est_req->create_pdr[pdr_counter].precedence.prcdnc_val = bearer->dynamic_rules[index]->precedence;
        // itr is for flow information counter
        // sdf_filter_count is for SDF information counter
        for(int itr = 0; itr < bearer->dynamic_rules[index]->num_flw_desc; itr++) {

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {

                if((pfcp_sess_est_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_UPLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {

                    sdf_pkt_filter_add(
                        pfcp_sess_est_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_UPLINK_ONLY);
                    sdf_filter_count++;
                }

            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }

            if(bearer->dynamic_rules[index]->flow_desc[itr].sdf_flow_description != NULL) {
                if((pfcp_sess_est_req->create_pdr[pdr_counter].pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE) &&
                    ((bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_DOWNLINK_ONLY) ||
                    (bearer->dynamic_rules[index]->flow_desc[itr].sdf_flw_desc.direction == TFT_DIRECTION_BIDIRECTIONAL))) {
                    sdf_pkt_filter_add(
                        pfcp_sess_est_req, bearer, pdr_counter, sdf_filter_count, index, itr, TFT_DIRECTION_DOWNLINK_ONLY);
                    sdf_filter_count++;
                }
            } else {
                clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Empty SDF rules\n", __file__, __func__, __LINE__);
            }
        }

	pfcp_sess_est_req->create_pdr[pdr_counter].pdi.sdf_filter_count = sdf_filter_count;

    }
    return ret;
}

int
fill_qer_entry(pdn_connection *pdn, eps_bearer *bearer,uint8_t itr)
{
	int ret = -1;
	qer_t *qer_ctxt = NULL;
	qer_ctxt = rte_zmalloc_socket(NULL, sizeof(qer_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (qer_ctxt == NULL) {
		fprintf(stderr, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return ret;
	}
	qer_ctxt->qer_id = bearer->qer_id[itr].qer_id;;
	qer_ctxt->session_id = pdn->seid;
	qer_ctxt->max_bitrate.ul_mbr = bearer->qos.ul_mbr;
	qer_ctxt->max_bitrate.dl_mbr = bearer->qos.dl_mbr;
	qer_ctxt->guaranteed_bitrate.ul_gbr = bearer->qos.ul_gbr;
	qer_ctxt->guaranteed_bitrate.dl_gbr = bearer->qos.dl_gbr;

	ret = add_qer_entry(qer_ctxt->qer_id,qer_ctxt);
	if(ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding qer entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return ret;
	}

	return ret;
}

int
fill_pdr_entry(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t iface, uint8_t itr)
{
	char mnc[4] = {0};
	char mcc[4] = {0};
	char nwinst[32] = {0};
	pdr_t *pdr_ctxt = NULL;
	int ret;

	if (context->serving_nw.mnc_digit_3 == 15) {
		sprintf(mnc, "0%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2);
	} else {
		sprintf(mnc, "%u%u%u", context->serving_nw.mnc_digit_1,
				context->serving_nw.mnc_digit_2,
				context->serving_nw.mnc_digit_3);
	}

	sprintf(mcc, "%u%u%u", context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);

	sprintf(nwinst, "mnc%s.mcc%s", mnc, mcc);

	pdr_ctxt = rte_zmalloc_socket(NULL, sizeof(pdr_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (pdr_ctxt == NULL) {
		fprintf(stderr, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}
	memset(pdr_ctxt,0,sizeof(pdr_t));

	pdr_ctxt->rule_id =  generate_pdr_id();
	pdr_ctxt->prcdnc_val =  1;
	pdr_ctxt->far.far_id_value = generate_far_id();
	pdr_ctxt->session_id = pdn->seid;
	/*to be filled in fill_sdf_rule*/
	pdr_ctxt->pdi.sdf_filter_cnt = 0;
	pdr_ctxt->pdi.src_intfc.interface_value = iface;
	strncpy((char * )pdr_ctxt->pdi.ntwk_inst.ntwk_inst, (char *)nwinst, 32);

	/* TODO: NS Add this changes after DP related changes of VS
	 * if(pfcp_config.cp_type != SGWC){
	 * pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;
	 * }
	 */

#ifdef GX_BUILD
	if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
		/* TODO Hardcode 1 set because one PDR contain only 1 QER entry
		 * Revist again in case of multiple rule support
		 */
		pdr_ctxt->qer_id_count = 1;
        	if(iface == SOURCE_INTERFACE_VALUE_ACCESS)
        	{
            		pdr_ctxt->qer_id[0].qer_id = bearer->qer_id[QER_INDEX_FOR_ACCESS_INTERFACE].qer_id;
        	}else if(iface == SOURCE_INTERFACE_VALUE_CORE)
        	{
           		pdr_ctxt->qer_id[0].qer_id = bearer->qer_id[QER_INDEX_FOR_CORE_INTERFACE].qer_id;
        	}
	}
#endif

	pdr_ctxt->pdi.ue_addr.ipv4_address = pdn->ipv4.s_addr;
	if (iface == SOURCE_INTERFACE_VALUE_ACCESS) {
		pdr_ctxt->pdi.local_fteid.teid = bearer->s1u_sgw_gtpu_teid;
		pdr_ctxt->pdi.local_fteid.ipv4_address = 0;

		if ((SGWC == pfcp_config.cp_type) &&
                (bearer->s5s8_pgw_gtpu_ipv4.s_addr != 0) &&
                (bearer->s5s8_pgw_gtpu_teid != 0)) {
            pdr_ctxt->far.actions.forw = 2;
            pdr_ctxt->far.dst_intfc.interface_value = DESTINATION_INTERFACE_VALUE_CORE;
            pdr_ctxt->far.outer_hdr_creation.ipv4_address =
                bearer->s5s8_pgw_gtpu_ipv4.s_addr;
            pdr_ctxt->far.outer_hdr_creation.teid =
                bearer->s5s8_pgw_gtpu_teid;
        } else {
            pdr_ctxt->far.actions.forw = 0;
        }

		if ((pfcp_config.cp_type == PGWC) ||
				(SAEGWC == pfcp_config.cp_type)) {
			pdr_ctxt->far.dst_intfc.interface_value =
				DESTINATION_INTERFACE_VALUE_CORE;
		}
	} else{
		if(pfcp_config.cp_type == SGWC){
			pdr_ctxt->pdi.local_fteid.teid = (bearer->s5s8_sgw_gtpu_teid);
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
		}else{
			pdr_ctxt->pdi.local_fteid.teid = 0;
			pdr_ctxt->pdi.local_fteid.ipv4_address = 0;
			pdr_ctxt->far.actions.forw = 0;
			if(pfcp_config.cp_type == PGWC){
				pdr_ctxt->far.outer_hdr_creation.ipv4_address =
					bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				pdr_ctxt->far.outer_hdr_creation.teid =
					bearer->s5s8_sgw_gtpu_teid;
				pdr_ctxt->far.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;
			}
		}
	}

	bearer->pdrs[itr] = pdr_ctxt;
	ret = add_pdr_entry(bearer->pdrs[itr]->rule_id, bearer->pdrs[itr]);
	if ( ret != 0) {
		clLog(sxlogger, eCLSeverityCritical, "[%s]:[%s]:[%d] Adding pdr entry Error: %d \n", __file__,
				__func__, __LINE__, ret);
		return -1;
	}
	return 0;
}

void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		ue_context *context, uint8_t ebi_index, uint32_t seq)
{
	/*TODO :generate seid value and store this in array
	  to send response from cp/dp , first check seid is there in array or not if yes then
	  fill that seid in response and if not then seid =0 */

	int ret = 0;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	upf_context_t *upf_ctx = NULL;

	bearer = context->eps_bearers[ebi_index];
	pdn = context->eps_bearers[ebi_index]->pdn;

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return;
	}

	memset(pfcp_sess_est_req,0,sizeof(pfcp_sess_estab_req_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req->header), PFCP_SESSION_ESTABLISHMENT_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_est_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(pAddr);

	set_node_id(&(pfcp_sess_est_req->node_id), node_value);

	set_fseid(&(pfcp_sess_est_req->cp_fseid), pdn->seid, node_value);

	pfcp_sess_est_req->create_pdr_count = bearer->pdr_count;

	for(int i = 0; i < pfcp_sess_est_req->create_pdr_count; i++) {
       /* TODO Hardcode 1 set because one PDR contain only 1 QER entry
        * Revist again in case of multiple rule support
        */
		pfcp_sess_est_req->create_pdr[i].qer_id_count = 1;
		creating_pdr(&(pfcp_sess_est_req->create_pdr[i]), bearer->pdrs[i]->pdi.src_intfc.interface_value);
		pfcp_sess_est_req->create_far_count++;
		creating_far(&(pfcp_sess_est_req->create_far[i]));
	}

	/* SGW Relocation Case*/
	/*SP: Need to think of this*/
	//if(context->indication_flag.oi != 0) {
	//	pfcp_sess_est_req->create_far_count = 2;
	//}


	for(int itr = 0; itr < pfcp_sess_est_req->create_pdr_count ; itr++) {
			pfcp_sess_est_req->create_pdr[itr].pdr_id.rule_id  =
			bearer->pdrs[itr]->rule_id;
		pfcp_sess_est_req->create_pdr[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;
		pfcp_sess_est_req->create_pdr[itr].precedence.prcdnc_val =
			bearer->pdrs[itr]->prcdnc_val;

		if (
				((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) &&
				(bearer->pdrs[itr]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE)) {
			/*No need to send fteid for pgwc core interface*/
			uint32_t size_teid = 0;
			size_teid = pfcp_sess_est_req->create_pdr[itr].pdi.local_fteid.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_est_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_est_req->create_pdr[itr].pdi.header.len - size_teid;
			pfcp_sess_est_req->create_pdr[itr].header.len =
				pfcp_sess_est_req->create_pdr[itr].header.len - size_teid;
			pfcp_sess_est_req->create_pdr[itr].pdi.local_fteid.header.len = 0;
		}else{
			pfcp_sess_est_req->create_pdr[itr].pdi.local_fteid.teid =
				bearer->pdrs[itr]->pdi.local_fteid.teid;
			pfcp_sess_est_req->create_pdr[itr].pdi.local_fteid.ipv4_address =
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address;
		}

		if((pfcp_config.cp_type == SGWC) ||
				 (bearer->pdrs[itr]->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS)){
			/*No need to send ue ip and network instance for pgwc access interface or
			 * for any sgwc interface */
			uint32_t size_ie = 0;
			size_ie = pfcp_sess_est_req->create_pdr[itr].pdi.ue_ip_address.header.len +
				sizeof(pfcp_ie_header_t);
			size_ie = size_ie + pfcp_sess_est_req->create_pdr[itr].pdi.ntwk_inst.header.len +
				sizeof(pfcp_ie_header_t);
			pfcp_sess_est_req->create_pdr[itr].pdi.header.len =
				pfcp_sess_est_req->create_pdr[itr].pdi.header.len - size_ie;
			pfcp_sess_est_req->create_pdr[itr].header.len =
				pfcp_sess_est_req->create_pdr[itr].header.len - size_ie;
			pfcp_sess_est_req->create_pdr[itr].pdi.ue_ip_address.header.len = 0;
			pfcp_sess_est_req->create_pdr[itr].pdi.ntwk_inst.header.len = 0;
		}else{
			pfcp_sess_est_req->create_pdr[itr].pdi.ue_ip_address.ipv4_address =
				bearer->pdrs[itr]->pdi.ue_addr.ipv4_address;
			strncpy((char *)pfcp_sess_est_req->create_pdr[itr].pdi.ntwk_inst.ntwk_inst,
					(char *)&bearer->pdrs[itr]->pdi.ntwk_inst.ntwk_inst, 32);
		}

		pfcp_sess_est_req->create_pdr[itr].pdi.src_intfc.interface_value =
			bearer->pdrs[itr]->pdi.src_intfc.interface_value;

		pfcp_sess_est_req->create_far[itr].far_id.far_id_value =
			bearer->pdrs[itr]->far.far_id_value;

		/* SGW Relocation*/
		if(context->indication_flag.oi != 0) {
			uint8_t len  = 0;
			if(itr == 1) {
				pfcp_sess_est_req->create_far[itr].apply_action.forw = PRESENT;
				len += set_forwarding_param(&(pfcp_sess_est_req->create_far[itr].frwdng_parms));
				len += UPD_PARAM_HEADER_SIZE;
				pfcp_sess_est_req->create_far[itr].header.len += len;

				pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->s1u_enb_gtpu_ipv4.s_addr;

				pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.teid =
					bearer->s1u_enb_gtpu_teid;
				pfcp_sess_est_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
					DESTINATION_INTERFACE_VALUE_ACCESS;

			} else if(itr == 0) {
				pfcp_sess_est_req->create_far[itr].apply_action.forw = PRESENT;
				len += set_forwarding_param(&(pfcp_sess_est_req->create_far[itr].frwdng_parms));
				len += UPD_PARAM_HEADER_SIZE;
				pfcp_sess_est_req->create_far[itr].header.len += len;

				pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.ipv4_address =
					bearer->s5s8_pgw_gtpu_ipv4.s_addr;
				pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.teid =
					bearer->s5s8_pgw_gtpu_teid;
				pfcp_sess_est_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
					 DESTINATION_INTERFACE_VALUE_CORE;
			}
		}

#ifdef GX_BUILD
		if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
			pfcp_sess_est_req->create_pdr[itr].qer_id_count =
				bearer->pdrs[itr]->qer_id_count;
			for(int itr1 = 0; itr1 < pfcp_sess_est_req->create_pdr[itr].qer_id_count; itr1++) {
				pfcp_sess_est_req->create_pdr[itr].qer_id[itr1].qer_id_value =
					bearer->pdrs[itr]->qer_id[itr1].qer_id;
			}
		}
#endif

		if ((pfcp_config.cp_type == PGWC) || (SAEGWC == pfcp_config.cp_type)) {
			pfcp_sess_est_req->create_far[itr].apply_action.forw = PRESENT;
			if (pfcp_sess_est_req->create_far[itr].apply_action.forw == PRESENT) {
				uint16_t len = 0;

				if ((SAEGWC == pfcp_config.cp_type) ||
						(SOURCE_INTERFACE_VALUE_ACCESS == bearer->pdrs[itr]->pdi.src_intfc.interface_value)) {
					set_destination_interface(&(pfcp_sess_est_req->create_far[itr].frwdng_parms.dst_intfc));
					pfcp_set_ie_header(&(pfcp_sess_est_req->create_far[itr].frwdng_parms.header),
							IE_FRWDNG_PARMS, sizeof(pfcp_dst_intfc_ie_t));

					pfcp_sess_est_req->create_far[itr].frwdng_parms.header.len = sizeof(pfcp_dst_intfc_ie_t);

					len += sizeof(pfcp_dst_intfc_ie_t);
					len += UPD_PARAM_HEADER_SIZE;

					pfcp_sess_est_req->create_far[itr].header.len += len;
					pfcp_sess_est_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
						bearer->pdrs[itr]->far.dst_intfc.interface_value;
				} else {
					len += set_forwarding_param(&(pfcp_sess_est_req->create_far[itr].frwdng_parms));
					/* Currently take as hardcoded value */
					len += UPD_PARAM_HEADER_SIZE;
					pfcp_sess_est_req->create_far[itr].header.len += len;

					pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.ipv4_address =
						bearer->pdrs[itr]->far.outer_hdr_creation.ipv4_address;
					pfcp_sess_est_req->create_far[itr].frwdng_parms.outer_hdr_creation.teid =
						bearer->pdrs[itr]->far.outer_hdr_creation.teid;
					pfcp_sess_est_req->create_far[itr].frwdng_parms.dst_intfc.interface_value =
						bearer->pdrs[itr]->far.dst_intfc.interface_value;
				}
			}
		}
	} /*for loop*/

#ifdef GX_BUILD
	if (pfcp_config.cp_type == PGWC || pfcp_config.cp_type == SAEGWC){
		pfcp_sess_est_req->create_qer_count = bearer->qer_count;
		qer_t *qer_context = NULL;
		for(int itr1 = 0; itr1 < pfcp_sess_est_req->create_qer_count ; itr1++) {
			creating_qer(&(pfcp_sess_est_req->create_qer[itr1]));
			pfcp_sess_est_req->create_qer[itr1].qer_id.qer_id_value  =
				bearer->qer_id[itr1].qer_id;;
			qer_context = get_qer_entry(pfcp_sess_est_req->create_qer[itr1].qer_id.qer_id_value);
			/* Assign the value from the PDR */
			if(qer_context){
				pfcp_sess_est_req->create_qer[itr1].maximum_bitrate.ul_mbr  =
					qer_context->max_bitrate.ul_mbr;
				pfcp_sess_est_req->create_qer[itr1].maximum_bitrate.dl_mbr  =
					qer_context->max_bitrate.dl_mbr;
				pfcp_sess_est_req->create_qer[itr1].guaranteed_bitrate.ul_gbr  =
					qer_context->guaranteed_bitrate.ul_gbr;
				pfcp_sess_est_req->create_qer[itr1].guaranteed_bitrate.dl_gbr  =
					qer_context->guaranteed_bitrate.dl_gbr;
			}
		}

		for(int itr1 = 0; itr1 < pfcp_sess_est_req->create_pdr_count ; itr1++) {
			fill_sdf_rules(pfcp_sess_est_req, bearer, itr1);

			// Update flow status
            enum flow_status f_status = bearer->dynamic_rules[0]->flow_status; // consider dynamic rule is 1 only /*TODO*/
			// assuming no of qer and pdr is same /*TODO*/
           	fill_gate_status(pfcp_sess_est_req,itr1,f_status);
		}

	}
#endif /* GX_BUILD */

	/* VS: Set the pdn connection type */
	set_pdn_type(&(pfcp_sess_est_req->pdn_type), &(pdn->pdn_type));

#if 0
	creating_bar(&(pfcp_sess_est_req->create_bar));

	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->sgw_c_fqcsid), sgwc_value);

	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_est_req->mme_fqcsid), mme_value);

	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->pgw_c_fqcsid), pgwc_value);

	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_est_req->epdg_fqcsid), epdg_value);

	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_est_req->twan_fqcsid), twan_value);

	set_up_inactivity_timer(&(pfcp_sess_est_req->user_plane_inact_timer));

	set_user_id(&(pfcp_sess_est_req->user_id));
#endif

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_est_req->trc_info));

}

/* VS: Fill ULI information into UE context from CSR*/
static int
fill_uli_info(gtp_user_loc_info_ie_t *uli, ue_context *context)
{
	if (uli->lai) {
		context->uli.lai = uli->lai;
		context->uli.lai2.lai_mcc_digit_2 = uli->lai2.lai_mcc_digit_2;
		context->uli.lai2.lai_mcc_digit_1 = uli->lai2.lai_mcc_digit_1;
		context->uli.lai2.lai_mnc_digit_3 = uli->lai2.lai_mnc_digit_3;
		context->uli.lai2.lai_mcc_digit_3 = uli->lai2.lai_mcc_digit_3;
		context->uli.lai2.lai_mnc_digit_2 = uli->lai2.lai_mnc_digit_2;
		context->uli.lai2.lai_mnc_digit_1 = uli->lai2.lai_mnc_digit_1;
		context->uli.lai2.lai_lac = uli->lai2.lai_lac;
	}

	if (uli->tai) {
		context->uli.tai = uli->tai;
		context->uli.tai2.tai_mcc_digit_2 = uli->tai2.tai_mcc_digit_2;
		context->uli.tai2.tai_mcc_digit_1 = uli->tai2.tai_mcc_digit_1;
		context->uli.tai2.tai_mnc_digit_3 = uli->tai2.tai_mnc_digit_3;
		context->uli.tai2.tai_mcc_digit_3 = uli->tai2.tai_mcc_digit_3;
		context->uli.tai2.tai_mnc_digit_2 = uli->tai2.tai_mnc_digit_2;
		context->uli.tai2.tai_mnc_digit_1 = uli->tai2.tai_mnc_digit_1;
		context->uli.tai2.tai_tac = uli->tai2.tai_tac;
	}

	if (uli->rai) {
		context->uli.rai = uli->rai;
		context->uli.rai2.ria_mcc_digit_2 = uli->rai2.ria_mcc_digit_2;
		context->uli.rai2.ria_mcc_digit_1 = uli->rai2.ria_mcc_digit_1;
		context->uli.rai2.ria_mnc_digit_3 = uli->rai2.ria_mnc_digit_3;
		context->uli.rai2.ria_mcc_digit_3 = uli->rai2.ria_mcc_digit_3;
		context->uli.rai2.ria_mnc_digit_2 = uli->rai2.ria_mnc_digit_2;
		context->uli.rai2.ria_mnc_digit_1 = uli->rai2.ria_mnc_digit_1;
		context->uli.rai2.ria_lac = uli->rai2.ria_lac;
		context->uli.rai2.ria_rac = uli->rai2.ria_rac;
	}

	if (uli->sai) {
		context->uli.sai = uli->sai;
		context->uli.sai2.sai_mcc_digit_2 = uli->sai2.sai_mcc_digit_2;
		context->uli.sai2.sai_mcc_digit_1 = uli->sai2.sai_mcc_digit_1;
		context->uli.sai2.sai_mnc_digit_3 = uli->sai2.sai_mnc_digit_3;
		context->uli.sai2.sai_mcc_digit_3 = uli->sai2.sai_mcc_digit_3;
		context->uli.sai2.sai_mnc_digit_2 = uli->sai2.sai_mnc_digit_2;
		context->uli.sai2.sai_mnc_digit_1 = uli->sai2.sai_mnc_digit_1;
		context->uli.sai2.sai_lac = uli->sai2.sai_lac;
		context->uli.sai2.sai_sac = uli->sai2.sai_sac;
	}

	if (uli->cgi) {
		context->uli.cgi = uli->cgi;
		context->uli.cgi2.cgi_mcc_digit_2 = uli->cgi2.cgi_mcc_digit_2;
		context->uli.cgi2.cgi_mcc_digit_1 = uli->cgi2.cgi_mcc_digit_1;
		context->uli.cgi2.cgi_mnc_digit_3 = uli->cgi2.cgi_mnc_digit_3;
		context->uli.cgi2.cgi_mcc_digit_3 = uli->cgi2.cgi_mcc_digit_3;
		context->uli.cgi2.cgi_mnc_digit_2 = uli->cgi2.cgi_mnc_digit_2;
		context->uli.cgi2.cgi_mnc_digit_1 = uli->cgi2.cgi_mnc_digit_1;
		context->uli.cgi2.cgi_lac = uli->cgi2.cgi_lac;
		context->uli.cgi2.cgi_ci = uli->cgi2.cgi_ci;
	}

	if (uli->ecgi) {
		context->uli.ecgi = uli->ecgi;
		context->uli.ecgi2.ecgi_mcc_digit_2 = uli->ecgi2.ecgi_mcc_digit_2;
		context->uli.ecgi2.ecgi_mcc_digit_1 = uli->ecgi2.ecgi_mcc_digit_1;
		context->uli.ecgi2.ecgi_mnc_digit_3 = uli->ecgi2.ecgi_mnc_digit_3;
		context->uli.ecgi2.ecgi_mcc_digit_3 = uli->ecgi2.ecgi_mcc_digit_3;
		context->uli.ecgi2.ecgi_mnc_digit_2 = uli->ecgi2.ecgi_mnc_digit_2;
		context->uli.ecgi2.ecgi_mnc_digit_1 = uli->ecgi2.ecgi_mnc_digit_1;
		context->uli.ecgi2.ecgi_spare = uli->ecgi2.ecgi_spare;
		context->uli.ecgi2.eci = uli->ecgi2.eci;
	}

	if (uli->macro_enodeb_id) {
		context->uli.macro_enodeb_id = uli->macro_enodeb_id;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_2 =
			uli->macro_enodeb_id2.menbid_mcc_digit_2;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_1 =
			uli->macro_enodeb_id2.menbid_mcc_digit_1;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_3 =
			uli->macro_enodeb_id2.menbid_mnc_digit_3;
		context->uli.macro_enodeb_id2.menbid_mcc_digit_3 =
			uli->macro_enodeb_id2.menbid_mcc_digit_3;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_2 =
			uli->macro_enodeb_id2.menbid_mnc_digit_2;
		context->uli.macro_enodeb_id2.menbid_mnc_digit_1 =
			uli->macro_enodeb_id2.menbid_mnc_digit_1;
		context->uli.macro_enodeb_id2.menbid_spare =
			uli->macro_enodeb_id2.menbid_spare;
		context->uli.macro_enodeb_id2.menbid_macro_enodeb_id =
			uli->macro_enodeb_id2.menbid_macro_enodeb_id;
		context->uli.macro_enodeb_id2.menbid_macro_enb_id2 =
			uli->macro_enodeb_id2.menbid_macro_enb_id2;

	}

	if (uli->extnded_macro_enb_id) {
		context->uli.extnded_macro_enb_id = uli->extnded_macro_enb_id;
		context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
			uli->extended_macro_enodeb_id2.emenbid_mcc_digit_1;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_3;
		context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
			uli->extended_macro_enodeb_id2.emenbid_mcc_digit_3;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_2;
		context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
			uli->extended_macro_enodeb_id2.emenbid_mnc_digit_1;
		context->uli.extended_macro_enodeb_id2.emenbid_smenb =
			uli->extended_macro_enodeb_id2.emenbid_smenb;
		context->uli.extended_macro_enodeb_id2.emenbid_spare =
			uli->extended_macro_enodeb_id2.emenbid_spare;
		context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
			uli->extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
		context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
			uli->extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
	}

	return 0;
}

static int
fill_context_info(create_sess_req_t *csr, ue_context *context)
{
	context->s11_sgw_gtpc_ipv4 = pfcp_config.s11_ip;
	context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;
	context->s11_mme_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;


	/* VS: Stored the serving network information in UE context */
	context->serving_nw.mnc_digit_1 = csr->serving_network.mnc_digit_1;
	context->serving_nw.mnc_digit_2 = csr->serving_network.mnc_digit_2;
	context->serving_nw.mnc_digit_3 = csr->serving_network.mnc_digit_3;
	context->serving_nw.mcc_digit_1 = csr->serving_network.mcc_digit_1;
	context->serving_nw.mcc_digit_2 = csr->serving_network.mcc_digit_2;
	context->serving_nw.mcc_digit_3 = csr->serving_network.mcc_digit_3;

	if(csr->indctn_flgs.header.len != 0) {
		context->indication_flag.oi = csr->indctn_flgs.indication_oi;
	}

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(csr->sender_fteid_ctl_plane.ipv4_address);

	return 0;
}
static int
fill_pdn_info(create_sess_req_t *csr, pdn_connection *pdn)
{

	pdn->apn_ambr.ambr_downlink = csr->apn_ambr.apn_ambr_dnlnk;
	pdn->apn_ambr.ambr_uplink = csr->apn_ambr.apn_ambr_uplnk;
	pdn->apn_restriction = csr->max_apn_rstrct.rstrct_type_val;

	if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV4)
		pdn->pdn_type.ipv4 = 1;
	else if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV6)
		pdn->pdn_type.ipv6 = 1;
	else if (csr->pdn_type.pdn_type_pdn_type == PDN_TYPE_IPV4_IPV6) {
		pdn->pdn_type.ipv4 = 1;
		pdn->pdn_type.ipv6 = 1;
	}

	if (csr->chrgng_char.header.len)
		memcpy(&pdn->charging_characteristics,
				&csr->chrgng_char.chrgng_char_val,
				sizeof(csr->chrgng_char.chrgng_char_val));

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = ntohl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		pdn->s5s8_pgw_gtpc_ipv4.s_addr = csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address;

	} else if (pfcp_config.cp_type == PGWC){
		pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_pgw_gtpc_ipv4.s_addr = ntohl(pdn->s5s8_pgw_gtpc_ipv4.s_addr); //NIKHIL
		pdn->s5s8_sgw_gtpc_ipv4.s_addr = csr->sender_fteid_ctl_plane.ipv4_address;

		/* Note: s5s8_pgw_gtpc_teid generated from
		 * s5s8_pgw_gtpc_base_teid and incremented
		 * for each pdn connection, similar to
		 * s11_sgw_gtpc_teid
		 */
		set_s5s8_pgw_gtpc_teid(pdn);
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;


	}

	/*VS:TODO*/
	if (pfcp_config.cp_type == SGWC) {
		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address);
	}

	/* Note: s5s8_pgw_gtpc_teid updated by
	 *                  * process_sgwc_s5s8_create_session_response (...)
	 *                                   */
	//pdn->s5s8_pgw_gtpc_teid = csr->s5s8pgw_pmip.teid_gre;

	return 0;
}

int
check_interface_type(uint8_t iface){
	switch(iface){
		case GTPV2C_IFTYPE_S1U_ENODEB_GTPU:
			if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_SGW_GTPU:
			if (pfcp_config.cp_type == PGWC){
				return DESTINATION_INTERFACE_VALUE_ACCESS;
			}
			break;
		case GTPV2C_IFTYPE_S5S8_PGW_GTPU:
			if (pfcp_config.cp_type == SGWC){
				return DESTINATION_INTERFACE_VALUE_CORE;
			}
			break;
		case GTPV2C_IFTYPE_S1U_SGW_GTPU:
		case GTPV2C_IFTYPE_S11_MME_GTPC:
		case GTPV2C_IFTYPE_S11S4_SGW_GTPC:
		case GTPV2C_IFTYPE_S11U_SGW_GTPU:
		case GTPV2C_IFTYPE_S5S8_SGW_GTPC:
		case GTPV2C_IFTYPE_S5S8_PGW_GTPC:
		case GTPV2C_IFTYPE_S5S8_SGW_PIMPv6:
		case GTPV2C_IFTYPE_S5S8_PGW_PIMPv6:
		default:
			return -1;
			break;
	}
	return -1;
}

int
fill_dedicated_bearer_info(eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn)
{
	int ret = 0;
	upf_context_t *upf_ctx = NULL;

	bearer->s5s8_sgw_gtpu_ipv4.s_addr = context->eps_bearers[pdn->default_bearer_id - 5]->s5s8_sgw_gtpu_ipv4.s_addr;

#ifdef CP_BUILD
#ifdef GX_BUILD
	/* TODO: Revisit this for change in yang*/
	if (pfcp_config.cp_type != SGWC){
		bearer->qer_count = NUMBER_OF_QER_PER_BEARER;
		for(uint8_t itr=0; itr < bearer->qer_count; itr++){
			bearer->qer_id[itr].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer, itr);
		}
	}
#endif /* GX_BUILD*/
#endif /* CP_BUILD */

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	bearer->pdr_count = NUMBER_OF_PDR_PER_BEARER;
	for(uint8_t itr=0; itr < bearer->pdr_count; itr++){
		switch(itr){
			case SOURCE_INTERFACE_VALUE_ACCESS:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_ACCESS, itr);
				break;
			case SOURCE_INTERFACE_VALUE_CORE:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_CORE, itr);
				break;
			default:
				break;
		}
	}

	bearer->pdn = pdn;

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(pdn->upf_ipv4.s_addr),
			(void **) &(upf_ctx));
	if (ret < 0) {
		clLog(sxlogger, eCLSeverityDebug, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n",
			__func__, __LINE__, (pdn->upf_ipv4.s_addr));
		return GTPV2C_CAUSE_INVALID_PEER;
	}

	if (pfcp_config.cp_type == SGWC) {
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_sgwu_ip;
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);

		set_s5s8_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
	}else if (pfcp_config.cp_type == SAEGWC) {
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	} else if (pfcp_config.cp_type == PGWC) {
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = upf_ctx->s5s8_pgwu_ip;

		set_s5s8_pgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	}

	RTE_SET_USED(context);
	return 0;
}

static int
fill_bearer_info(create_sess_req_t *csr, eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn)
{

	/* Need to re-vist this ARP[Allocation/Retention priority] handling portion */
	bearer->qos.arp.priority_level =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pl;
	bearer->qos.arp.preemption_capability =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pci;
	bearer->qos.arp.preemption_vulnerability =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.pvi;

	/* TODO: Implement TFTs on default bearers
	 * if (create_session_request.bearer_tft_ie) {
	 * }**/

	/* VS: Fill the QCI value */
	bearer->qos.qci =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.qci;
	bearer->qos.ul_mbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_uplnk;
	bearer->qos.dl_mbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_dnlnk;
	bearer->qos.ul_gbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_uplnk;
	bearer->qos.dl_gbr =
		csr->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_dnlnk;

	bearer->s1u_sgw_gtpu_teid = 0;
	bearer->s5s8_sgw_gtpu_teid = 0;

	if (pfcp_config.cp_type == PGWC){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid = csr->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.teid_gre_key;
	}

#ifdef CP_BUILD
#ifdef GX_BUILD
	/* TODO: Revisit this for change in yang*/
	if (pfcp_config.cp_type != SGWC){
		bearer->qer_count = NUMBER_OF_QER_PER_BEARER;
		for(uint8_t itr=0; itr < bearer->qer_count; itr++){
			bearer->qer_id[itr].qer_id = generate_qer_id();
			fill_qer_entry(pdn, bearer,itr);
		}
	}
#endif /* GX_BUILD*/
#endif /* CP_BUILD */

	/*SP: As per discussion Per bearer two pdrs and fars will be there*/
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         2      s5s8 PGWU          NA
	 SAEGWC       2      s1u SAEGWU         NA
	 ************************************************/

	bearer->pdr_count = NUMBER_OF_PDR_PER_BEARER;
	for(uint8_t itr=0; itr < bearer->pdr_count; itr++){
		switch(itr){
			case SOURCE_INTERFACE_VALUE_ACCESS:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_ACCESS, itr);
				break;
			case SOURCE_INTERFACE_VALUE_CORE:
				fill_pdr_entry(context, pdn, bearer, SOURCE_INTERFACE_VALUE_CORE, itr);
				break;
			default:
				break;
		}
	}

	bearer->pdn = pdn;

	RTE_SET_USED(context);
	return 0;
}

#ifdef GX_BUILD
static int
gen_ccr_request(ue_context *context, uint8_t ebi_index)
{
	/* VS: Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg ccr_request = {0};
	gx_context_t *gx_context = NULL;

	/* VS: Generate unique call id per PDN connection */
	context->pdns[ebi_index]->call_id = generate_call_id();

	/** Allocate the memory for Gx Context
	 */
	gx_context = rte_malloc_socket(NULL,
					sizeof(gx_context_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* VS: Generate unique session id for communicate over the Gx interface */
	if (gen_sess_id_for_ccr(gx_context->gx_sess_id,
				context->pdns[ebi_index]->call_id)) {
		RTE_LOG_DP(ERR, CP, "%s:%d Error: %s \n", __func__, __LINE__,
				strerror(errno));
		return -1;
	}

	/* Maintain the gx session id in context */
	memcpy(context->pdns[ebi_index]->gx_sess_id,
			gx_context->gx_sess_id , strlen(gx_context->gx_sess_id));

	/* VS: Maintain the PDN mapping with call id */
	if (add_pdn_conn_entry(context->pdns[ebi_index]->call_id,
				context->pdns[ebi_index]) != 0) {
		fprintf(stderr, "%s:%d Failed to add pdn entry with call id\n", __func__, __LINE__);
		return -1;
	}

	/* VS: Set the Msg header type for CCR */
	ccr_request.msg_type = GX_CCR_MSG ;

	/* VS: Set Credit Control Request type */
	ccr_request.data.ccr.presence.cc_request_type = PRESENT;
	ccr_request.data.ccr.cc_request_type = INITIAL_REQUEST ;

	/* VG: Set Credit Control Bearer opertaion type */
	ccr_request.data.ccr.presence.bearer_operation = PRESENT;
	ccr_request.data.ccr.bearer_operation = ESTABLISHMENT ;

	/* VS:TODO: Need to check the bearer identifier value */
	ccr_request.data.ccr.presence.bearer_identifier = PRESENT ;
	ccr_request.data.ccr.bearer_identifier.len =
		int_to_str((char *)ccr_request.data.ccr.bearer_identifier.val,
				(context->eps_bearers[ebi_index])->eps_bearer_id);

	/* VS: Fill the Credit Crontrol Request to send PCRF */
	if(fill_ccr_request(&ccr_request.data.ccr, context, ebi_index, gx_context->gx_sess_id) != 0) {
		fprintf(stderr, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
		return -1;
	}

	/* Update UE State */
	context->state = CCR_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = CCR_SNT_STATE;
	gx_context->proc = context->proc;

	/* VS: Maintain the Gx context mapping with Gx Session id */
	if (gx_context_entry_add(gx_context->gx_sess_id, gx_context) < 0) {
		RTE_LOG_DP(ERR, CP, "%s:%d Error: %s \n", __func__, __LINE__,
				strerror(errno));
		return -1;
	}

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_ccr_calc_length(&ccr_request.data.ccr);
	buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(ccr_request.msg_type),
	    RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		fprintf(stderr, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	/* VS: Fill the CCR header values */
	memcpy(buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));

	if (gx_ccr_pack(&(ccr_request.data.ccr),
				(unsigned char *)(buffer + sizeof(ccr_request.msg_type)), msg_len) == 0) {
		fprintf(stderr, "ERROR:%s:%d Packing CCR Buffer... \n", __func__, __LINE__);
		return -1;

	}

	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len + sizeof(ccr_request.msg_type));
	return 0;
}
#endif /* GX_BUILD */

int
process_create_sess_req(create_sess_req_t *csr,
		ue_context **_context, struct in_addr *upf_ipv4)
{
	int ret = 0;
	struct in_addr ue_ip = {0};
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if(csr->mapped_ue_usage_type.header.len > 0) {
		apn_requested->apn_usage_type = csr->mapped_ue_usage_type.mapped_ue_usage_type;
	}

	uint8_t ebi_index = csr->bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi - 5;


	if (pfcp_config.cp_type != SGWC) {
		ret = acquire_ip(&ue_ip);
	}
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
	ret = create_ue_context(&csr->imsi.imsi_number_digits, csr->imsi.header.len,
			csr->bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi, &context, apn_requested);
	if (ret)
		return ret;

	if (csr->mei.header.len)
		memcpy(&context->mei, &csr->mei.mei, csr->mei.header.len);

	memcpy(&context->msisdn, &csr->msisdn.msisdn_number_digits, csr->msisdn.header.len);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		if (fill_context_info(csr, context) != 0)
			return -1;
	}else{
		context->s11_mme_gtpc_teid = csr->sender_fteid_ctl_plane.teid_gre_key;
	}

	/* Retrive procedure of CSR */
	context->proc = get_csr_proc(csr);

	/* VS: Stored the RAT TYPE information in UE context */
	if (csr->rat_type.header.len != 0) {
		context->rat_type.rat_type = csr->rat_type.rat_type;
		context->rat_type.len = csr->rat_type.header.len;
	}

	/* VS: Stored the RAT TYPE information in UE context */
	if (csr->uli.header.len != 0) {
		if (fill_uli_info(&csr->uli, context) != 0)
			return -1;
	}

	/* VS: Stored the mapped ue usage type information in UE context */
	if (csr->mapped_ue_usage_type.header.len != 0) {
		context->mapped_ue_usage_type =
			csr->mapped_ue_usage_type.mapped_ue_usage_type;
	} else
		context->mapped_ue_usage_type = -1;

	/* VS: Maintain the sequence number of CSR */
	if(csr->header.gtpc.teid_flag == 1)
		context->sequence = csr->header.teid.has_teid.seq;
	else
		context->sequence = csr->header.teid.no_teid.seq;

	pdn = context->eps_bearers[ebi_index]->pdn;
	pdn->apn_in_use = apn_requested;


	/* Store upf ipv4 in pdn structure */
	pdn->upf_ipv4 = *upf_ipv4;

	if (fill_pdn_info(csr, pdn) != 0)
		return -1;

	bearer = context->eps_bearers[ebi_index];

	if (pfcp_config.cp_type == SGWC) {
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;

		context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	} else if (pfcp_config.cp_type == PGWC) {
		/* VS: Maitain the fqdn into table */
		memcpy(pdn->fqdn, (char *)csr->sgw_u_node_name.fqdn,
				csr->sgw_u_node_name.header.len);

		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		context->pdns[ebi_index]->seid = SESS_ID(pdn->s5s8_pgw_gtpc_teid, bearer->eps_bearer_id);
	} else {
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);
		context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	}

	if (fill_bearer_info(csr, bearer, context, pdn) != 0)
		return -1;

	/* SGW Handover Storage */
	if (csr->indctn_flgs.header.len != 0)
	{
		memcpy(&(pdn->ipv4.s_addr) ,&(csr->paa.pdn_addr_and_pfx), IPV4_SIZE);
		/*TODO:ntohl is done as in csr response there is htonl*/
		pdn->ipv4.s_addr = ntohl(pdn->ipv4.s_addr);
		context->indication_flag.oi = csr->indctn_flgs.indication_oi;
		pdn->s5s8_pgw_gtpc_teid = csr->pgw_s5s8_addr_ctl_plane_or_pmip.teid_gre_key;
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid = csr->bearer_contexts_to_be_created.s5s8_u_pgw_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_teid =   csr->bearer_contexts_to_be_created.s1u_enb_fteid.teid_gre_key;
		bearer->s1u_enb_gtpu_ipv4.s_addr = csr->bearer_contexts_to_be_created.s1u_enb_fteid.ipv4_address;

	}
	context->pdns[ebi_index]->dp_seid = 0;

#ifdef GX_BUILD
	if ((pfcp_config.cp_type == PGWC) || (pfcp_config.cp_type == SAEGWC)) {

		if (gen_ccr_request(context, ebi_index)) {
			RTE_LOG_DP(ERR, CP, "%s:%d Error: %s \n", __func__, __LINE__,
					strerror(errno));
			return -1;
		}
	}
#endif /* GX_BUILD */

	/* VS: Store the context of ue in pdn*/
	pdn->context = context;

	/* VS: Return the UE context */
	*_context = context;
	return 0;

}

int
process_pfcp_sess_est_request(uint32_t teid, uint8_t ebi_index)
{
	int ret = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	upf_context_t *upf_ctx = NULL;
	uint32_t sequence = 0;
	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};

	/* VS: Retrive the UE Context */
	ret = get_ue_context(teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &((context->pdns[ebi_index])->upf_ipv4.s_addr),
			(void **) &(upf_ctx));
	if (ret < 0) {
		clLog(sxlogger, eCLSeverityDebug, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n",
			__func__, __LINE__, (context->pdns[ebi_index])->upf_ipv4.s_addr);
		return GTPV2C_CAUSE_INVALID_PEER;
	}

	bearer = context->eps_bearers[ebi_index];
	if (pfcp_config.cp_type == SGWC) {
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
		set_s5s8_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_sgw_gtpu_teid, upf_ctx->s5s8_sgwu_ip, SOURCE_INTERFACE_VALUE_CORE);
	}else if (pfcp_config.cp_type == SAEGWC) {
		set_s1u_sgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s1u_sgw_gtpu_teid, upf_ctx->s1u_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	} else if (pfcp_config.cp_type == PGWC){
		set_s5s8_pgw_gtpu_teid(bearer, context);
		update_pdr_teid(bearer, bearer->s5s8_pgw_gtpu_teid, upf_ctx->s5s8_pgwu_ip, SOURCE_INTERFACE_VALUE_ACCESS);
	}

	sequence = get_pfcp_sequence_number(PFCP_SESSION_ESTABLISHMENT_REQUEST, sequence);
	fill_pfcp_sess_est_req(&pfcp_sess_est_req, context, ebi_index, sequence);

	/* Need to discuss with himanshu */
	if (pfcp_config.cp_type == PGWC) {
		/* VS: Update the PGWU IP address */
		(context->eps_bearers[ebi_index])->s5s8_pgw_gtpu_ipv4.s_addr =
			htonl(upf_ctx->s5s8_pgwu_ip);

		/* Filling PDN structure*/
		pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
		pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
		pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
		pfcp_sess_est_req.pdn_type.pdn_type =  1;
	} else {
		(context->eps_bearers[ebi_index])->s5s8_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s5s8_sgwu_ip);
		(context->eps_bearers[ebi_index])->s1u_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s1u_ip);
	}

	/* Update UE State */
	context->state = PFCP_SESS_EST_REQ_SNT_STATE;

	/* Allocate the memory for response
	 */
	resp = rte_malloc_socket(NULL,
					sizeof(struct resp_info),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Set create session response */
	//if (pfcp_config.cp_type == PGWC)
	//	resp->sequence = (htonl(context->sequence) >> 8);
	//else
	//	resp->sequence = context->sequence;


	resp->eps_bearer_id = ebi_index;
	//resp->s11_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	//resp->context = context;
	resp->msg_type = GTP_CREATE_SESSION_REQ;
	resp->state = PFCP_SESS_EST_REQ_SNT_STATE;
	resp->proc = context->proc;

	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		fprintf(stderr, "%s:%d Error sending: %i\n",
				__func__, __LINE__, errno);
		return -1;
	} else {

		get_current_time(cp_stats.stat_timestamp);

		/*pfcp-session-estab-req-sent*/
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_est_req.header.message_type,REQ,
				cp_stats.stat_timestamp);
	}

	if (add_sess_entry(context->pdns[ebi_index]->seid, resp) != 0) {
		fprintf(stderr, "%s:%d Failed to add response in entry in SM_HASH\n",
				__func__, __LINE__);
		return -1;
	}
	return 0;
}

uint8_t
process_pfcp_sess_est_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		uint64_t dp_sess_id)
{
	int ret = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			fprintf(stderr, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the UE state */
	context->state = PFCP_SESS_EST_RESP_RCVD_STATE;

	/*TODO need to think on eps_bearer_id*/
	uint8_t ebi_index = resp->eps_bearer_id;

	pdn = context->eps_bearers[ebi_index]->pdn;
	bearer = context->eps_bearers[ebi_index];
	pdn->dp_seid = dp_sess_id;

	if (pfcp_config.cp_type == SAEGWC) {
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, pdn, bearer);

		s11_mme_sockaddr.sin_addr.s_addr =
						htonl(context->s11_mme_gtpc_ipv4.s_addr);

	} else if (pfcp_config.cp_type == PGWC) {
		/*TODO: This needs to be change after support libgtpv2 on S5S8*/
		/* set_pgwc_s5s8_create_session_response(gtpv2c_tx,
				(htonl(context->sequence) >> 8), pdn, bearer); */

		create_sess_rsp_t cs_resp = {0};

		//uint32_t  seq_no = 0;
		//seq_no = bswap_32(resp->sequence);
		//seq_no = seq_no >> 8;
		fill_pgwc_create_session_response(&cs_resp,
			context->sequence, context, ebi_index);

		uint16_t msg_len = encode_create_sess_rsp(&cs_resp, (uint8_t*)gtpv2c_tx);
		msg_len = msg_len - 4;
		gtpv2c_header_t *header;
		header = (gtpv2c_header_t*) gtpv2c_tx;
			header->gtpc.message_len = htons(msg_len);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						htonl(pdn->s5s8_sgw_gtpc_ipv4.s_addr);
	}else if (pfcp_config.cp_type == SGWC) {
		uint16_t msg_len = 0;
		upf_context_t *upf_context = NULL;

		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
				(const void*) &((context->pdns[ebi_index])->upf_ipv4.s_addr),
				(void **) &(upf_context));

		if (ret < 0) {
			RTE_LOG_DP(DEBUG, DP, "%s:%d NO ENTRY FOUND IN UPF HASH [%u]\n", __func__,
					__LINE__, (context->pdns[ebi_index])->upf_ipv4.s_addr);
			return GTPV2C_CAUSE_INVALID_PEER;
		}

		if(context->indication_flag.oi == 1) {

			memset(gtpv2c_tx, 0, MAX_GTPV2C_UDP_LEN);
			set_modify_bearer_request(gtpv2c_tx, pdn, bearer);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);

			resp->state = MBR_REQ_SNT_STATE;
			context->state = resp->state;
			context->proc = SGW_RELOCATION_PROC;
			return 0;

		}

		/*Add procedure based call here
		 * for pdn -> CSR
		 * for sgw relocation -> MBR
		 */

		create_sess_req_t cs_req = {0};

		ret = fill_cs_request(&cs_req, context, ebi_index);

		if (ret < 0) {
			RTE_LOG_DP(DEBUG, DP, "%s:Failed to create the CSR request \n", __func__);
			return 0;
		}

		msg_len = encode_create_sess_req(
				&cs_req,
				(uint8_t*)gtpv2c_tx);

		msg_len = msg_len - 4;
		gtpv2c_header_t *header;
		header = (gtpv2c_header_t*) gtpv2c_tx;
		header->gtpc.message_len = htons(msg_len);

		if (ret < 0)
			fprintf(stderr, "%s:%d Failed to generate S5S8 SGWC CSR.\n",
					__func__, __LINE__);

		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[ebi_index]->s5s8_pgw_gtpc_ipv4.s_addr);

		/* Update the session state */
		resp->state = CS_REQ_SNT_STATE;

		/* Update the UE state */
		context->state = CS_REQ_SNT_STATE;
		return 0;
	}

	update_sys_stat(number_of_users,INCREMENT);
	update_sys_stat(number_of_active_session, INCREMENT);

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	context->state = CONNECTED_STATE;

	return 0;
}

int process_pfcp_sess_mod_req_handover(mod_bearer_req_t *mb_req)

{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	pdn->s5s8_sgw_gtpc_ipv4.s_addr = mb_req->sender_fteid_ctl_plane.ipv4_address;

	/* TODO something with modify_bearer_request.delay if set */

	bearer->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;
	if (mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len  != 0){
		bearer->s1u_enb_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address;
		bearer->s1u_enb_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s1u_enb_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s1u_enb_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.interface_type);
		update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		pfcp_sess_mod_req.update_far_count++;
	}
	if (mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.header.len  != 0){
		/* SGW Relocation */
		bearer->s5s8_sgw_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_sgw_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.interface_type);
		if ( pfcp_config.cp_type != PGWC) {
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		}
		pfcp_sess_mod_req.update_far_count++;
	}

	context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearer, pdn, update_far, 0);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	}

	/* Update UE State */
	context->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	get_current_time(cp_stats.stat_timestamp);
	update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
						pfcp_sess_mod_req.header.message_type,REQ,
						cp_stats.stat_timestamp);

	/*Retrive the session information based on session id. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", context->pdns[ebi_index]->seid);
		return -1;
	}

	context->sequence = mb_req->header.teid.has_teid.seq;
	/* Set create session response */
	resp->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	context->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	context->proc= SGW_RELOCATION_PROC;//GTP_MODIFY_BEARER_REQ;
	resp->proc = context->proc;

	return 0;
}


int
process_pfcp_sess_mod_request(mod_bearer_req_t *mb_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if (!mb_req->bearer_contexts_to_be_modified.eps_bearer_id.header.len
			|| !mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len) {
		fprintf(stderr, "%s:%d Dropping packet\n",
				__func__, __LINE__);
		return GTPV2C_CAUSE_INVALID_LENGTH;
	}

	ebi_index = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
				"%s:%d Received modify bearer on non-existent EBI - "
				"Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"%s:%d Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn = bearer->pdn;

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key))
		context->s11_mme_gtpc_teid = mb_req->bearer_contexts_to_be_modified.s11_u_mme_fteid.teid_gre_key;

	bearer->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;
	uint8_t x2_handover = 0;

	if (mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.header.len  != 0){

		if(bearer->s1u_enb_gtpu_ipv4.s_addr != 0) {
			if((mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key)
					!= bearer->s1u_enb_gtpu_teid  ||
					(mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address) !=
					bearer->s1u_enb_gtpu_ipv4.s_addr) {

				x2_handover = 1;
			}
		}

		bearer->s1u_enb_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.ipv4_address;
		bearer->s1u_enb_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s1u_enb_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s1u_enb_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s1_enodeb_fteid.interface_type);
		update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		pfcp_sess_mod_req.update_far_count++;

	}

	if (mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.header.len  != 0){
		bearer->s5s8_sgw_gtpu_ipv4.s_addr =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.ipv4_address;
		bearer->s5s8_sgw_gtpu_teid =
			mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.teid_gre_key;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_sgw_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(mb_req->bearer_contexts_to_be_modified.s58_u_sgw_fteid.interface_type);
		if ( pfcp_config.cp_type != PGWC) {
			update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		}
		pfcp_sess_mod_req.update_far_count++;
	}

	context->pdns[ebi_index]->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, bearer, pdn, update_far, x2_handover);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	} else {

		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,REQ,
				cp_stats.stat_timestamp);
	}

	/* Update the Sequence number for the request */
	context->sequence = mb_req->header.teid.has_teid.seq;

	/* Update UE State */
	context->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, context->pdns[ebi_index]->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set create session response */
	resp->eps_bearer_id = mb_req->bearer_contexts_to_be_modified.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

#ifdef GX_BUILD
static int
gen_reauth_response(ue_context *context, uint8_t ebi_index)
{
	/* VS: Initialize the Gx Parameters */
	uint16_t msg_len = 0;
	char *buffer = NULL;
	gx_msg raa = {0};
	pdn_connection *pdn = NULL;
	gx_context_t *gx_context = NULL;
	uint16_t msg_type_ofs = 0;
	uint16_t msg_body_ofs = 0;
	uint16_t rqst_ptr_ofs = 0;
	uint16_t msg_len_total = 0;

	pdn = context->eps_bearers[ebi_index]->pdn;

	/* Allocate the memory for Gx Context */
	gx_context = rte_malloc_socket(NULL,
			sizeof(gx_context_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	//strncpy(gx_context->gx_sess_id, context->pdns[ebi_index]->gx_sess_id, strlen(context->pdns[ebi_index]->gx_sess_id));


	raa.data.cp_raa.session_id.len = strlen(pdn->gx_sess_id);
	memcpy(raa.data.cp_raa.session_id.val, pdn->gx_sess_id, raa.data.cp_raa.session_id.len);

	raa.data.cp_raa.presence.session_id = PRESENT;

	/* VS: Set the Msg header type for CCR */
	raa.msg_type = GX_RAA_MSG;

	/* Result code */
	raa.data.cp_raa.result_code = 2001;
	raa.data.cp_raa.presence.result_code = PRESENT;

	/* Update UE State */
	context->state = RE_AUTH_ANS_SNT_STATE;

	/* VS: Set the Gx State for events */
	gx_context->state = RE_AUTH_ANS_SNT_STATE;

	/* VS: Calculate the max size of CCR msg to allocate the buffer */
	msg_len = gx_raa_calc_length(&raa.data.cp_raa);
	msg_body_ofs = sizeof(raa.msg_type);
	rqst_ptr_ofs = msg_len + msg_body_ofs;
	msg_len_total = rqst_ptr_ofs + sizeof(context->eps_bearers[ebi_index]->rqst_ptr);

	//buffer = rte_zmalloc_socket(NULL, msg_len + sizeof(uint64_t) + sizeof(raa.msg_type),
	//		RTE_CACHE_LINE_SIZE, rte_socket_id());
	buffer = rte_zmalloc_socket(NULL, msg_len_total,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (buffer == NULL) {
		fprintf(stderr, "Failure to allocate CCR Buffer memory"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	memcpy(buffer + msg_type_ofs, &raa.msg_type, sizeof(raa.msg_type));

	//if (gx_raa_pack(&(raa.data.cp_raa), (unsigned char *)(buffer + sizeof(raa.msg_type)), msg_len) == 0 )
	if (gx_raa_pack(&(raa.data.cp_raa), (unsigned char *)(buffer + msg_body_ofs), msg_len) == 0 )
		printf("RAA Packing failure\n");

	//memcpy((unsigned char *)(buffer + sizeof(raa.msg_type) + msg_len), &(context->eps_bearers[1]->rqst_ptr),
	memcpy((unsigned char *)(buffer + rqst_ptr_ofs), &(context->eps_bearers[ebi_index]->rqst_ptr),
			sizeof(context->eps_bearers[ebi_index]->rqst_ptr));
#if 0
	printf("While packing RAA %p %p\n", (void*)(context->eps_bearers[1]->rqst_ptr),
			*(void**)(buffer+rqst_ptr_ofs));

	printf("msg_len_total [%d] msg_type_ofs[%d] msg_body_ofs[%d] rqst_ptr_ofs[%d]\n",
			msg_len_total, msg_type_ofs, msg_body_ofs, rqst_ptr_ofs);
#endif
	/* VS: Write or Send CCR msg to Gx_App */
	send_to_ipc_channel(gx_app_sock, buffer,
			msg_len_total);
			//msg_len + sizeof(raa.msg_type) + sizeof(unsigned long));

	return 0;
}
#endif

uint8_t
process_pfcp_sess_mod_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			fprintf(stderr, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
	}

	/* Update the UE state */
	context->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	ebi_index = resp->eps_bearer_id - 5;
	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"%s:%d Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n", __func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/* Fill the modify bearer response */
		set_modify_bearer_response(gtpv2c_tx,
				context->sequence, context, bearer);

		resp->state = CONNECTED_STATE;
		/* Update the UE state */
		context->state = CONNECTED_STATE;
		return 0;

	} else if (resp->msg_type == GTP_CREATE_SESSION_RSP) {
		/* Fill the Create session response */
		set_create_session_response(
				gtpv2c_tx, context->sequence, context, bearer->pdn, bearer);

	} else if (resp->msg_type == GX_RAR_MSG) {
		/* TODO: NC Need to remove hard coded pti value */
	    set_create_bearer_request(gtpv2c_tx, context->sequence, context,
				bearer, ebi_index, 0, NULL, 0);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		context->state = CREATE_BER_REQ_SNT_STATE;

		if (SAEGWC == pfcp_config.cp_type) {
			s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);
		} else {
		    s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);
		}

		return 0;

	} else if (resp->msg_type == GTP_CREATE_BEARER_REQ) {
		set_create_bearer_request(
				gtpv2c_tx, context->sequence, context, bearer,
				resp->eps_bearer_id, 0, resp->eps_bearer_lvl_tft, resp->tft_header_len);

		resp->state = CREATE_BER_REQ_SNT_STATE;
		context->state = CREATE_BER_REQ_SNT_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

		return 0;

	} else if (resp->msg_type == GTP_CREATE_BEARER_RSP) {

		if ((SAEGWC == pfcp_config.cp_type) || (PGWC == pfcp_config.cp_type)) {
#ifdef GX_BUILD
			gen_reauth_response(context, resp->eps_bearer_id - 5);
#endif
		} else {
			set_create_bearer_response(
				gtpv2c_tx, context->sequence, context, bearer, resp->eps_bearer_id, 0);

			resp->state = CONNECTED_STATE;
			context->state = CONNECTED_STATE;

			s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(context->pdns[0]->s5s8_pgw_gtpc_ipv4.s_addr);

			return 0;
		}
	} else if(resp->msg_type == GTP_DELETE_SESSION_REQ){
		if (pfcp_config.cp_type == SGWC) {
			uint8_t encoded_msg[512];

			/* Indication flags not required in DSR for PGWC */
			resp->gtpc_msg.dsr.indctn_flgs.header.len = 0;
			encode_del_sess_req(
					(del_sess_req_t *)&(resp->gtpc_msg.dsr),
					encoded_msg);

			gtpv2c_header *header;
			header =(gtpv2c_header*) encoded_msg;

			ret =
				gen_sgwc_s5s8_delete_session_request((gtpv2c_header_t *)encoded_msg,
						gtpv2c_tx, htonl(bearer->pdn->s5s8_pgw_gtpc_teid),
						header->teid_u.has_teid.seq,
						resp->eps_bearer_id);

			s5s8_recv_sockaddr.sin_addr.s_addr =
				resp->s5s8_pgw_gtpc_ipv4;

			/* Update the session state */
			resp->state = DS_REQ_SNT_STATE;

			/* Update the UE state */
			ret = update_ue_state(context->s11_sgw_gtpc_teid,
					DS_REQ_SNT_STATE);
			if (ret < 0) {
				fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
			}

			clLog(sxlogger, eCLSeverityDebug, "SGWC:%s: "
					"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
					inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

			return ret;
		}
	} else {
		/* Fill the release bearer response */
		set_release_access_bearer_response(gtpv2c_tx,
				context->sequence, context->s11_mme_gtpc_teid);

		/* Update the session state */
		resp->state = IDEL_STATE;

		/* Update the UE state */
		context->state = IDEL_STATE;

		s11_mme_sockaddr.sin_addr.s_addr =
						htonl(context->s11_mme_gtpc_ipv4.s_addr);

		clLog(sxlogger, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n",
				__func__, __LINE__,
				inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

		return 0;
	}

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	context->state = CONNECTED_STATE;

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(sxlogger, eCLSeverityDebug, "%s:%d s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
				__LINE__, inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	return 0;
}

int
process_sgwc_delete_session_request(del_sess_req_t *del_req)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &del_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ebi_index = del_req->lbi.ebi_ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		fprintf(stderr,
				"Received modify bearer on non-existent EBI - "
				"Dropping packet\n");
		return -EPERM;
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	pdn = bearer->pdn;

	bearer->eps_bearer_id = del_req->lbi.ebi_ebi;

	fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, &del_req->header, context, pdn);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	} else {

		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,REQ,
				cp_stats.stat_timestamp);
	}

	/* Update UE State */
	context->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update the sequence number */
	context->sequence =
		del_req->header.teid.has_teid.seq;

	/*Retrive the session information based on session id. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", context->pdns[ebi_index]->seid);
		return -1;
	}

	resp->gtpc_msg.dsr = *del_req;
	resp->eps_bearer_id = del_req->lbi.ebi_ebi;
	resp->s5s8_pgw_gtpc_ipv4 = htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc = context->proc;

	return 0;
}

int
process_pfcp_sess_del_request(del_sess_req_t *ds_req)
{

	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t s5s8_pgw_gtpc_teid = 0;
	uint32_t s5s8_pgw_gtpc_ipv4 = 0;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	uint64_t ebi_index = ds_req->lbi.ebi_ebi - 5;

	/* Lookup and get context of delete request */
	ret = delete_context(ds_req, &context, &s5s8_pgw_gtpc_teid,
			&s5s8_pgw_gtpc_ipv4);
	if (ret)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->pdns[ebi_index]->dp_seid;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("%s:%d Error sending: %i\n", __func__, __LINE__, errno);
		return -1;
	} else  {

		get_current_time(cp_stats.stat_timestamp);
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_del_req.header.message_type,REQ,
				cp_stats.stat_timestamp);
	}

	/* Update the sequence number */
	context->sequence =
		ds_req->header.teid.has_teid.seq;

	/* Update UE State */
	context->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, context->pdns[ebi_index]->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
	resp->gtpc_msg.dsr = *ds_req;
	resp->eps_bearer_id = ds_req->lbi.ebi_ebi;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;
	resp->proc = context->proc;

	return 0;
}

int
del_rule_entries(ue_context *context, uint8_t ebi_index)
{
	int ret = 0;
	pdr_t *pdr_ctx =  NULL;

	/*Delete all pdr, far, qer entry from table */
#ifdef GX_BUILD
    for(uint8_t itr = 0; itr < context->eps_bearers[ebi_index]->qer_count ; itr++) {
 		if( del_qer_entry(context->eps_bearers[ebi_index]->qer_id[itr].qer_id) != 0 ){
			fprintf(stderr,
					"%s %s %d %s - Error del_pdr_entry deletion\n",__file__,
					__func__, __LINE__, strerror(ret));
		}
    }
#endif
	for(uint8_t itr = 0; itr < context->eps_bearers[ebi_index]->pdr_count ; itr++) {
		pdr_ctx = context->eps_bearers[ebi_index]->pdrs[itr];
		if(pdr_ctx == NULL) {
			fprintf(stderr,
					"%s %s %d %s - Error no pdr entry \n",__file__,
					__func__, __LINE__, strerror(ret));
		}
		if( del_pdr_entry(context->eps_bearers[ebi_index]->pdrs[itr]->rule_id) != 0 ){
			fprintf(stderr,
					"%s %s %d %s - Error del_pdr_entry deletion\n",__file__,
					__func__, __LINE__, strerror(ret));
		}
	}
	return 0;
}

uint8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen )
{
	int ret = 0;
	uint8_t ebi_index = 0;
	uint16_t msg_len = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	del_sess_rsp_t del_resp = {0};
	uint32_t teid = UE_SESS_ID(sess_id);

	//eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_DEL_RESP_RCVD_STATE;

	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
			fprintf(stderr, "%s:%d Failed to update UE State for teid: %u\n",
					__func__, __LINE__,
					teid);
	}

	/* Update the UE state */
	context->state = PFCP_SESS_DEL_RESP_RCVD_STATE;

	ebi_index = resp->eps_bearer_id - 5;
	pdn = context->eps_bearers[ebi_index]->pdn;

#ifdef GX_BUILD
	if ( pfcp_config.cp_type != SGWC) {

		gx_context_t *gx_context = NULL;

		/* Retrive Gx_context based on Sess ID. */
		ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
				(const void*)(pdn->gx_sess_id),
				(void **)&gx_context);
		if (ret < 0) {
			RTE_LOG_DP(ERR, CP, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
					pdn->gx_sess_id);
			return -1;
		}

		/* VS: Set the Msg header type for CCR-T */
		ccr_request->msg_type = GX_CCR_MSG ;

		/* VS: Set Credit Control Request type */
		ccr_request->data.ccr.presence.cc_request_type = PRESENT;
		ccr_request->data.ccr.cc_request_type = TERMINATION_REQUEST ;

		/* VG: Set Credit Control Bearer opertaion type */
		ccr_request->data.ccr.presence.bearer_operation = PRESENT;
		ccr_request->data.ccr.bearer_operation = TERMINATION ;

		/* VS: Fill the Credit Crontrol Request to send PCRF */
		if(fill_ccr_request(&ccr_request->data.ccr, context, ebi_index, pdn->gx_sess_id) != 0) {
			fprintf(stderr, "%s:%d Failed CCR request filling process\n", __func__, __LINE__);
			return -1;
		}
		/* Update UE State */
		context->state = CCR_SNT_STATE;

		/* VS: Set the Gx State for events */
		gx_context->state = CCR_SNT_STATE;
		gx_context->proc = context->proc;

		/* VS: Calculate the max size of CCR msg to allocate the buffer */
		*msglen = gx_ccr_calc_length(&ccr_request->data.ccr);

	}
#else
	 RTE_SET_USED(msglen);
	 RTE_SET_USED(ccr_request);

#endif /* GX_BUILD */

	if ( pfcp_config.cp_type == PGWC) {

		fill_pgwc_ds_sess_rsp(&del_resp, context->sequence,
				pdn->s5s8_sgw_gtpc_teid);

		uint16_t msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

		gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
		header->gtpc.message_len = htons(msg_len -4);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						htonl(context->pdns[ebi_index]->s5s8_sgw_gtpc_ipv4.s_addr);

		/* Delete entry from session entry */
		if (del_sess_entry(sess_id) != 0){
			fprintf(stderr, "%s:%d NO Session Entry Found for Key sess ID:%lu\n",
					__func__, __LINE__, sess_id);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		clLog(sxlogger, eCLSeverityDebug, "PGWC:%s:%d "
				"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__, __LINE__,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

		if ( del_rule_entries(context, ebi_index) != 0 ){
			fprintf(stderr,
					"%s %s - Error on delete rule entries\n",__file__,
					strerror(ret));
		}
		/* Delete UE context entry from UE Hash */
		if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
			fprintf(stderr,
					"%s %s - Error on ue_context_by_fteid_hash deletion\n",__file__,
					strerror(ret));
		}
		ret = delete_sgwc_context(teid, &context, &sess_id);
		if (ret)
			return ret;

		rte_free(context);
		return 0;
	}


	/* Fill gtpv2c structure for sending on s11 interface */
	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_resp, GTP_DELETE_SESSION_RSP,
			context->s11_mme_gtpc_teid, context->sequence);
	set_cause_accepted_ie((gtpv2c_header_t *) &del_resp, IE_INSTANCE_ZERO);

	del_resp.cause.header.len = ntohs(del_resp.cause.header.len);

	/*Encode the S11 delete session response message. */
	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);

	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(s11logger, eCLSeverityDebug, "SAEGWC:%s:%d"
			"s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__, __LINE__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));


	/* Delete entry from session entry */
	if (del_sess_entry(sess_id) != 0){
		fprintf(stderr, "%s:%d NO Session Entry Found for Key sess ID:%lu\n",
				__func__, __LINE__, sess_id);
		return -1;
	}

	if (del_rule_entries(context, ebi_index) != 0) {
		fprintf(stderr,
				"%s %s - Error on delete rule entries\n",__file__,
				strerror(ret));
	}
	/* Delete UE context entry from UE Hash */
	if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
		fprintf(stderr,
				"%s %s - Error on ue_context_by_fteid_hash del\n",__file__,
				strerror(ret));
	}

	ret = delete_sgwc_context(teid, &context, &sess_id);
	if (ret)
		return ret;

	//Free UE context
	rte_free(context);
	return 0;
}

void
fill_pfcp_sess_mod_req_delete( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, ue_context *context, pdn_connection *pdn)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	pdr_t *pdr_ctxt = NULL;
	int ret = 0;
	eps_bearer *bearer;

	RTE_SET_USED(context);  /* NK:to be checked */

	if ((ret = upf_context_entry_lookup(pdn->upf_ipv4.s_addr,
					&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	if( header != NULL)
		clLog(sxlogger, eCLSeverityDebug, "TEID[%d]\n", header->teid.has_teid.teid);

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = pdn->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), pdn->seid, node_value);

	/*SP: Adding FAR IE*/
	pfcp_sess_mod_req->update_far_count = 0;
	for (int index = 0; index < pdn->num_bearer; index++){
		bearer = pdn->eps_bearers[index];
		if(bearer){
			for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
				pdr_ctxt = bearer->pdrs[itr];
				if(pdr_ctxt){
					updating_far(&(pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count]));
					pfcp_sess_mod_req->update_far[pfcp_sess_mod_req->update_far_count].far_id.far_id_value = pdr_ctxt->far.far_id_value;
					pfcp_sess_mod_req->update_far_count++;
				}
			}
		}
	}

	switch (pfcp_config.cp_type)
	{
		case SGWC :
			if(pfcp_sess_mod_req->update_far_count){
				for(uint8_t itr1 = 0; itr1 < pfcp_sess_mod_req->update_far_count; itr1++) {
					pfcp_sess_mod_req->update_far[itr1].apply_action.drop = PRESENT;
				}
			}
			break;

		default :
			printf("default pfcp sess mod req\n");
			break;
	}

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));
	pfcp_sess_mod_req->pfcpsmreq_flags.drobu = PRESENT;

	/*SP: This IE is included if one of DROBU and QAURR flag is set,
	  excluding this IE since we are not setting  any of this flag  */
	if(!pfcp_sess_mod_req->pfcpsmreq_flags.qaurr &&
			!pfcp_sess_mod_req->pfcpsmreq_flags.drobu){
		pfcp_sess_mod_req->pfcpsmreq_flags.header.len = 0;
	}
}

uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t teid = UE_SESS_ID(sess_id);

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	/* Update the session state */
	resp->state = PFCP_SESS_MOD_RESP_RCVD_STATE;

	ebi_index = resp->eps_bearer_id - 5;
	/* Retrieve the UE context */
	ret = get_ue_context(teid, &context);
	if (ret < 0) {
	         fprintf(stderr, "%s:%d Failed to update UE State for teid: %u\n",
	                 __func__, __LINE__,
	                 teid);
	}

	/* Update the UE state */
	ret = update_ue_state(context->pdns[ebi_index]->s5s8_pgw_gtpc_teid,
			PFCP_SESS_MOD_RESP_RCVD_STATE);
	if (ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State for teid: %u\n", __func__,
				context->pdns[ebi_index]->s5s8_pgw_gtpc_teid);
	}

	bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}
	/* Fill the modify bearer response */

	set_modify_bearer_response_handover(gtpv2c_tx,
			context->sequence, context, bearer);

	/* Update the session state */
	resp->state = CONNECTED_STATE;
	context->state = CONNECTED_STATE;
	/* Update the UE state */
	ret = update_ue_state(context->s11_sgw_gtpc_teid,
			CONNECTED_STATE);
	if (ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
	}

	s5s8_recv_sockaddr.sin_addr.s_addr =
		htonl(bearer->pdn->s5s8_sgw_gtpc_ipv4.s_addr);

	clLog(sxlogger, eCLSeverityDebug, "%s: s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));
	return 0;
}

#endif /* CP_BUILD */

#ifdef DP_BUILD
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_sess_set_del_resp)
{

	/*take seq no from set del request when it is implemented*/
	uint32_t seq  = 1;
	uint32_t node_value = 0 ;

	memset(pfcp_sess_set_del_resp, 0, sizeof(pfcp_sess_set_del_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_resp->header),
		PFCP_SESSION_SET_DELETION_RESPONSE, NO_SEID, seq);

	set_node_id(&(pfcp_sess_set_del_resp->node_id), node_value);
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_sess_set_del_resp->cause), REQUESTACCEPTED);
	//TODO Replace IE_NODE_ID with the  real offendID
	set_offending_ie(&(pfcp_sess_set_del_resp->offending_ie), PFCP_IE_NODE_ID );

}

void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t *
		pfcp_sess_del_resp, uint8_t cause, int offend)
{

	uint32_t seq  = 1;
	memset(pfcp_sess_del_resp, 0, sizeof(pfcp_sess_del_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_resp->header), PFCP_SESSION_DELETION_RESPONSE,
			HAS_SEID, seq);

	set_cause(&(pfcp_sess_del_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING ||
			cause == MANDATORYIEMISSING) {

		set_offending_ie(&(pfcp_sess_del_resp->offending_ie), offend);
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_del_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_del_resp->ovrld_ctl_info));
}

void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend)
{
	uint32_t seq  = 1;
	memset(pfcp_sess_modify_resp, 0, sizeof(pfcp_sess_mod_rsp_t));

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_modify_resp->header),
			PFCP_SESSION_MODIFICATION_RESPONSE, HAS_SEID, seq);

	set_cause(&(pfcp_sess_modify_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING
			|| cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_modify_resp->offending_ie), offend);
	}

	//created_bar
	// Need to do
	if(cause == REQUESTACCEPTED){
		if(pfcp_session_mod_req->create_pdr_count > 0 &&
				pfcp_session_mod_req->create_pdr[0].pdi.local_fteid.ch){
			set_created_pdr_ie(&(pfcp_sess_modify_resp->created_pdr));
		}
	}

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_modify_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_modify_resp->ovrld_ctl_info));

	if(cause == RULECREATION_MODIFICATIONFAILURE){
		set_failed_rule_id(&(pfcp_sess_modify_resp->failed_rule_id));
	}

	// filling of ADURI
	// Need to do
	if(pfcp_session_mod_req->pfcpsmreq_flags.qaurr ||
			pfcp_session_mod_req->query_urr_count){
		set_additional_usage(&(pfcp_sess_modify_resp->add_usage_rpts_info));
	}

	// filling of CRTEP
	// Need to do
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		set_created_traffic_endpoint(&(pfcp_sess_modify_resp->createdupdated_traffic_endpt));

}

void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_resp,
			uint8_t cause, int offend, struct in_addr dp_comm_ip,
			pfcp_sess_estab_req_t *pfcp_session_request)
{
	uint32_t seq  = 0;
	uint32_t node_value = 0;

	memset(pfcp_sess_est_resp, 0, sizeof(pfcp_sess_estab_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_resp->header),
			PFCP_SESSION_ESTABLISHMENT_RESPONSE, HAS_SEID, seq);

	set_node_id(&(pfcp_sess_est_resp->node_id), dp_comm_ip.s_addr);
	set_cause(&(pfcp_sess_est_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING || cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_est_resp->offending_ie), offend);
	}

	if(REQUESTACCEPTED == cause) {
		uint64_t up_seid = pfcp_session_request->header.seid_seqno.has_seid.seid;;
		set_fseid(&(pfcp_sess_est_resp->up_fseid), up_seid, node_value);
	}

	if(pfcp_ctxt.cp_supported_features & CP_LOAD) {
		set_lci(&(pfcp_sess_est_resp->load_ctl_info));
	}

	if(pfcp_ctxt.cp_supported_features & CP_OVRL) {
		set_olci(&(pfcp_sess_est_resp->ovrld_ctl_info));
	}

	/* TODO: Need to add condition for below
	char sgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), sgwu_addr, INET_ADDRSTRLEN);
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->sgw_u_fqcsid), sgwu_value);

	char pgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->pgw_u_fqcsid), pgwu_value); */


	if(RULECREATION_MODIFICATIONFAILURE == cause) {
		set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
	}
}
#endif /* DP_BUILD */
