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
#include "main.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_enum.h"

#ifdef CP_BUILD
#include "ue.h"
#include "req_resp.h"
#include "gtpv2c_set_ie.h"
#include "cp_config.h"
#endif /* CP_BUILD */

#ifdef DP_BUILD
extern struct in_addr dp_comm_ip;
#endif /* DP_BUILD */

#ifdef CP_BUILD
pfcp_config_t pfcp_config;

#define size sizeof(pfcp_sess_mod_req_t)
extern int pfcp_fd;

struct app_params app;

int
delete_context(delete_session_request_t *ds_req,
			ue_context **_context, uint32_t *s5s8_pgw_gtpc_teid,
			uint32_t *s5s8_pgw_gtpc_ipv4);

void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req)
{
	uint32_t seq = 1;

	memset(pfcp_sess_del_req, 0, sizeof(pfcp_sess_del_req_t));

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

void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header,
		ue_context *context, eps_bearer *bearer, pdn_connection *pdn)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(context->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	if( header != NULL)
		clLog(sxlogger, eCLSeverityDebug, "TEID[%d]\n", header->teid.has_teid.teid);

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	if(header != NULL) {
		if(header->gtpc.teid_flag == 1)
			seq = header->teid.has_teid.seq;
		else
			seq = header->teid.no_teid.seq;
	}

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = context->seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), context->seid, node_value);

	/*SP: This depends on condition in pcrf data(pcrf will send bar_rule_id if it needs to be delated). Need to handle after pcrf integration*/
	/* removing_bar(&(pfcp_sess_mod_req->remove_bar)); */

	if (upf_ctx->up_supp_features & UP_PDIU )
		removing_traffic_endpoint(&(pfcp_sess_mod_req->rmv_traffic_endpt));

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
	pfcp_sess_mod_req->update_far_count = 1;
	for( int i = 0; i < pfcp_sess_mod_req->update_far_count ; i++)
		updating_far(&(pfcp_sess_mod_req->update_far[i]));


	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case SAEGWC :
			if(pfcp_sess_mod_req->create_pdr_count){
				pfcp_sess_mod_req->create_pdr[0].pdi.local_fteid.teid = bearer->s1u_enb_gtpu_teid;
				/* TODO: Revisit this for change in yang */
				pfcp_sess_mod_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
				pfcp_sess_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address = htonl(bearer->s1u_enb_gtpu_ipv4.s_addr) ;
				pfcp_sess_mod_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;
			}else if(pfcp_sess_mod_req->update_far_count){
				pfcp_sess_mod_req->update_far[0].apply_action.forw = PRESENT;
				if (pfcp_sess_mod_req->update_far[0].apply_action.forw == PRESENT) {
					uint16_t len = 0;
					len += set_upd_forwarding_param(&(pfcp_sess_mod_req->update_far[0].upd_frwdng_parms));
					/* Currently take as hardcoded value */
					len += 4; /* Header Size of set_upd_forwarding_param ie */
					pfcp_sess_mod_req->update_far[0].header.len += len;
				}

				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.teid = bearer->s1u_enb_gtpu_teid;
				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.ipv4_address = htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.dst_intfc.interface_value =  SOURCE_INTERFACE_VALUE_ACCESS;
			}
			break;

		case PGWC :
			/* modification request for split is only when handover indication flag is on in CSR */
			/* need to handle HO scenario*/
			if(pfcp_sess_mod_req->update_far_count){
				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.teid = bearer->s5s8_sgw_gtpu_teid;
				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.outer_hdr_creation.ipv4_address  = htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr) ;
				pfcp_sess_mod_req->update_far[0].upd_frwdng_parms.dst_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;
			}

			break;

		default :
			printf("default pfcp sess mod req\n");
			break;
	}

	if (upf_ctx->up_supp_features & UP_PDIU)
		creating_traffic_endpoint(&(pfcp_sess_mod_req->create_traffic_endpt));

	// set of update QER
	/*SP: No QER is not generated previously, No update needed*/
	/*
	pfcp_sess_mod_req->update_qer_count = 2;

	for(int i=0; i < pfcp_sess_mod_req->update_qer_count; i++ )
		updating_qer(&(pfcp_sess_mod_req->update_qer[i]));
	*/

	// set of update BAR
	/*SP: If previously created BAR needs to be modified, this IE should be included*/
	/*
	 updating_bar(&(pfcp_sess_mod_req->update_bar));
	*/

	 if (upf_ctx->up_supp_features & UP_PDIU)
		 updating_traffic_endpoint(&(pfcp_sess_mod_req->upd_traffic_endpt));

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
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		create_session_request_t *csr,
		ue_context *context, eps_bearer *bearer, pdn_connection *pdn)
{
	/*TODO :generate seid value and store this in array
	  to send response from cp/dp , first check seid is there in array or not if yes then
	  fill that seid in response and if not then seid =0 */
	uint32_t seq = 0;

	int ret = 0;
	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(context->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return;
	}

	memset(pfcp_sess_est_req,0,sizeof(pfcp_sess_estab_req_t));

	if(csr != NULL) {
		if(csr->header.gtpc.teid_flag == 1)
			seq = csr->header.teid.has_teid.seq;
		else
			seq = csr->header.teid.no_teid.seq;
	}

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req->header), PFCP_SESSION_ESTABLISHMENT_REQUEST,
			HAS_SEID, seq);

	pfcp_sess_est_req->header.seid_seqno.has_seid.seid = context->seid;

	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);

	unsigned long node_value = inet_addr(pAddr);

	set_node_id(&(pfcp_sess_est_req->node_id), node_value);

	set_fseid(&(pfcp_sess_est_req->cp_fseid), context->seid, node_value);

	//creating pdr for Fteid only,TODO : Rules will be implemented later
	/************************************************
	 *  cp_type  count      FTEID_1        FTEID_2 *
	 *************************************************
	 SGWC         2      s1u  SGWU      s5s8 SGWU
	 PGWC         1      s5s8 PGWU          -
	 SAEGWC       1      s1u SAEGWU         -
	 ************************************************/

	/* VS: REVIEW: Need to remove this hard coded values */
	if (SGWC == pfcp_config.cp_type) {
		pfcp_sess_est_req->create_pdr_count = 2;
		pfcp_sess_est_req->create_far_count = 1;
	} else if(PGWC == pfcp_config.cp_type) {
		pfcp_sess_est_req->create_pdr_count = 1;
		pfcp_sess_est_req->create_far_count = 1;
	} else {
		pfcp_sess_est_req->create_pdr_count = 1;
		pfcp_sess_est_req->create_far_count = 1;
	}

	for(int i = 0; i < pfcp_sess_est_req->create_pdr_count; i++) {
		creating_pdr(&(pfcp_sess_est_req->create_pdr[i]));
	}

	for(int i = 0; i < pfcp_sess_est_req->create_far_count; i++) {
		creating_far(&(pfcp_sess_est_req->create_far[i]));
	}

	char mnc[4] = {0};
	char mcc[4] = {0};
	char nwinst[32] = {0};

	if (csr->serving_nw.mcc_mnc.mnc_digit_3 == 15) {
		sprintf(mnc, "0%u%u", csr->serving_nw.mcc_mnc.mnc_digit_1,
			csr->serving_nw.mcc_mnc.mnc_digit_2);
	} else {
		sprintf(mnc, "%u%u%u", csr->serving_nw.mcc_mnc.mnc_digit_1,
				csr->serving_nw.mcc_mnc.mnc_digit_2,
				csr->serving_nw.mcc_mnc.mnc_digit_3);
	}

	sprintf(mcc, "%u%u%u", csr->serving_nw.mcc_mnc.mcc_digit_1,
			csr->serving_nw.mcc_mnc.mcc_digit_2,
			csr->serving_nw.mcc_mnc.mcc_digit_3);

	sprintf(nwinst, "mnc%s.mcc%s", mnc, mcc);

	switch (pfcp_config.cp_type)
	{
		case SGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = (bearer->s1u_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s1u_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;

			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.teid = (bearer->s5s8_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[1].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s5s8_sgwu_ip);
			pfcp_sess_est_req->create_pdr[1].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;

			pfcp_sess_est_req->create_far[0].apply_action.forw = 0;

			strncpy((char *)pfcp_sess_est_req->create_pdr[0].pdi.ntwk_inst.ntwk_inst, nwinst, 32);//strnlen(nwinst, 255) + 1);
			strncpy((char *)pfcp_sess_est_req->create_pdr[1].pdi.ntwk_inst.ntwk_inst, nwinst, 32);//strnlen(nwinst, 255) + 1);

			break;

		case PGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = (bearer->s5s8_pgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s5s8_pgwu_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
			strncpy((char *)pfcp_sess_est_req->create_pdr[0].pdi.ntwk_inst.ntwk_inst, nwinst, 32);//strnlen(nwinst, 255) + 1);

			pfcp_sess_est_req->create_far[0].apply_action.forw = PRESENT;
			if (pfcp_sess_est_req->create_far[0].apply_action.forw == PRESENT) {
				uint16_t len = 0;
				len += set_forwarding_param(&(pfcp_sess_est_req->create_far[0].frwdng_parms));
				/* Currently take as hardcoded value */
				len += 4; /* Header Size of set_forwarding_param ie */
				pfcp_sess_est_req->create_far[0].header.len += len;
			}

			pfcp_sess_est_req->create_far[0].frwdng_parms.outer_hdr_creation.ipv4_address = htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr);
			pfcp_sess_est_req->create_far[0].frwdng_parms.outer_hdr_creation.teid = htonl(bearer->s5s8_sgw_gtpu_teid);
			pfcp_sess_est_req->create_far[0].frwdng_parms.dst_intfc.interface_value = DESTINATION_INTERFACE_VALUE_CORE;
			break;

		case SAEGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = (bearer->s1u_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = pdn->ipv4.s_addr;
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s1u_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
			strncpy((char *)pfcp_sess_est_req->create_pdr[0].pdi.ntwk_inst.ntwk_inst, nwinst, 32);//strnlen(nwinst, 255) + 1);
			pfcp_sess_est_req->create_far[0].apply_action.forw = 0;
			break;

		default :
			printf("Default PFCP Sess Est Req\n");
			break;
	}

//	creating_bar(&(pfcp_sess_est_req->create_bar));

	if(csr != NULL) {
		set_pdn_type(&(pfcp_sess_est_req->pdn_type), &(csr->pdn_type));
	}

//	char sgwc_addr[INET_ADDRSTRLEN] ;
//	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), sgwc_addr, INET_ADDRSTRLEN);
//	unsigned long sgwc_value = inet_addr(sgwc_addr);
//	set_fq_csid( &(pfcp_sess_est_req->sgw_c_fqcsid), sgwc_value);
//
//	char mme_addr[INET_ADDRSTRLEN] ;
//	inet_ntop(AF_INET, &(pfcp_config.s11_mme_ip), mme_addr, INET_ADDRSTRLEN);
//	unsigned long mme_value = inet_addr(mme_addr);
//	set_fq_csid( &(pfcp_sess_est_req->mme_fqcsid), mme_value);
//
//	char pgwc_addr[INET_ADDRSTRLEN] ;
//	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pgwc_addr, INET_ADDRSTRLEN);
//	unsigned long pgwc_value = inet_addr(pgwc_addr);
//	set_fq_csid( &(pfcp_sess_est_req->pgw_c_fqcsid), pgwc_value);
//
//	//TODO : IP addres for epdgg is hardcoded
//	const char* epdg_addr = "0.0.0.0";
//	uint32_t epdg_value = inet_addr(epdg_addr);
//	set_fq_csid( &(pfcp_sess_est_req->epdg_fqcsid), epdg_value);
//
//	//TODO : IP addres for twan is hardcoded
//	const char* twan_addr = "0.0.0.0";
//	uint32_t twan_value = inet_addr(twan_addr);
//	set_fq_csid( &(pfcp_sess_est_req->twan_fqcsid), twan_value);
//
//	set_up_inactivity_timer(&(pfcp_sess_est_req->user_plane_inact_timer));
//
//	set_user_id(&(pfcp_sess_est_req->user_id));

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_est_req->trc_info));

}

static int
fill_context_info(create_session_request_t *csr, ue_context *context)
{
	context->s11_sgw_gtpc_ipv4 = pfcp_config.s11_ip;
	context->s11_mme_gtpc_teid = csr->sender_ftied.teid_gre;
	context->s11_mme_gtpc_ipv4 = csr->sender_ftied.ip.ipv4;

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(csr->sender_ftied.ip.ipv4.s_addr);
#ifdef USE_REST
		/* Add a entry for MME */
		if (s11_mme_sockaddr.sin_addr.s_addr != 0) {
			if ((add_node_conn_entry((uint32_t)s11_mme_sockaddr.sin_addr.s_addr,
									S11_SGW_PORT_ID)) != 0) {
				RTE_LOG_DP(ERR, DP, "Failed to add connection entry for MME\n");
			}
		}
#endif /* USE_REST */

	return 0;
}
static int
fill_pdn_info(create_session_request_t *csr, pdn_connection *pdn)
{

	pdn->apn_ambr.ambr_downlink = csr->ambr.apn_ambr_dl;
	pdn->apn_ambr.ambr_uplink = csr->ambr.apn_ambr_ul;
	pdn->apn_restriction = csr->apn_restriction.restriction_type;

	if (csr->pdn_type.pdn_type == PDN_TYPE_IPV4)
		pdn->pdn_type.ipv4 = 1;
	else if (csr->pdn_type.pdn_type == PDN_TYPE_IPV6)
		pdn->pdn_type.ipv6 = 1;
	else if (csr->pdn_type.pdn_type == PDN_TYPE_IPV4_IPV6) {
		pdn->pdn_type.ipv4 = 1;
		pdn->pdn_type.ipv6 = 1;
	}

	if (csr->charging_characteristics.header.len)
		memcpy(&pdn->charging_characteristics,
				&csr->charging_characteristics.value,
				sizeof(csr->charging_characteristics.value));

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_pgw_gtpc_ipv4 = csr->s5s8pgw_pmip.ip.ipv4;

	} else if (pfcp_config.cp_type == PGWC){
		pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		pdn->s5s8_sgw_gtpc_ipv4 = csr->sender_ftied.ip.ipv4;

		/* Note: s5s8_pgw_gtpc_teid generated from
		 * s5s8_pgw_gtpc_base_teid and incremented
		 * for each pdn connection, similar to
		 * s11_sgw_gtpc_teid
		 */
		set_s5s8_pgw_gtpc_teid(pdn);
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = csr->sender_ftied.teid_gre;


	}

	/*VS:TODO*/
	if (pfcp_config.cp_type == SGWC) {
		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(csr->s5s8pgw_pmip.ip.ipv4.s_addr);
		uint32_t dstIp = (uint32_t)s5s8_recv_sockaddr.sin_addr.s_addr;
		csUpdateIp(inet_ntoa(*((struct in_addr *)&dstIp)), 2, 0);
#ifdef USE_REST
		/* Add a entry for MME */
		if (s5s8_recv_sockaddr.sin_addr.s_addr != 0) {
			if ((add_node_conn_entry((uint32_t)s5s8_recv_sockaddr.sin_addr.s_addr,
									S5S8_SGWC_PORT_ID)) != 0) {
				RTE_LOG_DP(ERR, DP, "Failed to add connection entry for PGW-C\n");
			}
		}
#endif /* USE_REST */
	}

	/* Note: s5s8_pgw_gtpc_teid updated by
	 *                  * process_sgwc_s5s8_create_session_response (...)
	 *                                   */
	//pdn->s5s8_pgw_gtpc_teid = csr->s5s8pgw_pmip.teid_gre;

	return 0;
}

static int
fill_bearer_info(create_session_request_t *csr, eps_bearer *bearer,
		ue_context *context, pdn_connection *pdn, upf_context_t *upf_ctx)
{


	/* Need to re-vist this ARP[Allocation/Retention priority] handling portion */
	bearer->qos.arp.priority_level =
		csr->bearer_context.bearer_qos.pci_pl_pvi.pl;
	bearer->qos.arp.preemption_capability =
		csr->bearer_context.bearer_qos.pci_pl_pvi.pci;
	bearer->qos.arp.preemption_vulnerability =
		csr->bearer_context.bearer_qos.pci_pl_pvi.pvi;

	/* TODO: Implement TFTs on default bearers
	 * if (create_session_request.bearer_tft_ie) {
	 * }**/

	bearer->qos.qos.ul_mbr =
		csr->bearer_context.bearer_qos.maximum_bit_rate_for_uplink;
	bearer->qos.qos.dl_mbr =
		csr->bearer_context.bearer_qos.maximum_bit_rate_for_downlink;
	bearer->qos.qos.ul_gbr =
		csr->bearer_context.bearer_qos.guaranteed_bit_rate_for_uplink;
	bearer->qos.qos.dl_gbr =
		csr->bearer_context.bearer_qos.guaranteed_bit_rate_for_downlink;

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s5s8_sgwu_ip);
		/* TODO : Need to think on s1u ip and pfcp context */
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
		 *                  * Computation same as s1u_sgw_gtpu_teid
		 *                                   */
		set_s1u_sgw_gtpu_teid(bearer, context);
		set_s5s8_sgw_gtpu_teid(bearer, context);
	} else if (pfcp_config.cp_type == PGWC){
		bearer->s5s8_sgw_gtpu_ipv4 = csr->sender_ftied.ip.ipv4;
		bearer->s5s8_sgw_gtpu_teid = csr->sender_ftied.teid_gre;
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s5s8_pgwu_ip);

		/* Note: s5s8_pgw_gtpu_teid = s5s8_pgw_gtpc_teid */
		bearer->s5s8_pgw_gtpu_teid = pdn->s5s8_pgw_gtpc_teid;

	}
	bearer->pdn = pdn;

	return 0;
}
int
process_pfcp_sess_est_request(create_session_request_t *csr,
				struct in_addr *upf_ipv4)
{
	int ret = 0;
	struct in_addr ue_ip;
	ue_context *context =  NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	/* TODO: Need to think on static variable */
	//static uint32_t process_pfcp_sgwc_s5s8_cs_req_cnt;

	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};

	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(upf_ipv4->s_addr,
			&upf_ctx)) < 0) {
		clLog(sxlogger, eCLSeverityCritical, "%s : Error: %d \n", __func__, ret);
		return ret;
	}

	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	uint8_t ebi_index = csr->bearer_context.ebi.eps_bearer_id - 5;
	ret = acquire_ip(&ue_ip);
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
	ret = create_ue_context(csr->imsi.imsi, csr->imsi.header.len,
			csr->bearer_context.ebi.eps_bearer_id, &context, apn_requested);
	if (ret)
		return ret;

	if (csr->mei.header.len)
		memcpy(&context->mei, csr->mei.mei, csr->mei.header.len);

	memcpy(&context->msisdn, &csr->msisdn.msisdn, csr->msisdn.header.len);

	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		if (fill_context_info(csr, context) != 0)
			return -1;
	}

	/* Store upf ipv4 */
	context->upf_ipv4 = *upf_ipv4;

	pdn = context->pdns[ebi_index];
	pdn->apn_in_use = apn_requested;
	pdn->ipv4.s_addr = htonl(ue_ip.s_addr);

	if (fill_pdn_info(csr, pdn) != 0)
		return -1;

	bearer = context->eps_bearers[ebi_index];

	if (fill_bearer_info(csr, bearer, context, pdn, upf_ctx) != 0)
		return -1;

	if (pfcp_config.cp_type == SGWC) {
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;

		context->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	} else if (pfcp_config.cp_type == PGWC) {
		context->seid = SESS_ID(pdn->s5s8_sgw_gtpc_teid, bearer->eps_bearer_id);
	} else {
		context->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	}

	fill_pfcp_sess_est_req(&pfcp_sess_est_req, csr, context, bearer, pdn);
	/* Need to discuss with himanshu */
	if (pfcp_config.cp_type == PGWC) {
		/* Filling PDN structure*/
		pfcp_sess_est_req.pdn_type.header.type = PFCP_IE_PDN_TYPE;
		pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
		pfcp_sess_est_req.pdn_type.pdn_type_spare = 0;
		pfcp_sess_est_req.pdn_type.pdn_type =  1;
	}

	/* Update UE State */
	context->state = SESS_EST_REQ_SNT_STATE;

	/* Allocate the memory for response
	 */
	resp = rte_malloc_socket(NULL,
					sizeof(struct resp_info),
					RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Set create session response */
	resp->s11_msg.csr = *csr;
	resp->eps_bearer_id = csr->bearer_context.ebi.eps_bearer_id;
	resp->sequence = csr->header.teid.has_teid.seq;
	resp->s11_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	resp->context = context;
	resp->msg_type = GTP_CREATE_SESSION_REQ;
	resp->state = SESS_EST_REQ_SNT_STATE;

	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		fprintf(stderr, "Error sending: %i\n", errno);
		return -1;
	} else {
		cp_stats.session_establishment_req_sent++;
		get_current_time(cp_stats.session_establishment_req_sent_time);
	}

	if (add_sess_entry(context->seid, resp) != 0) {
		fprintf(stderr, "Failed to add response in entry in SM_HASH\n");
		return -1;
	}

	return 0;
}

uint8_t
process_pfcp_sess_est_resp(uint64_t sess_id, gtpv2c_header *gtpv2c_tx)
{
	int ret = 0;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	/* Update the session state */
	resp->state = SESS_EST_RESP_RCVD_STATE;

	/* Update the UE state */
	ret = update_ue_state(resp->s11_sgw_gtpc_teid,
			SESS_EST_RESP_RCVD_STATE);
	if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State for teid: %u\n", __func__,
					resp->s11_sgw_gtpc_teid);
	}

	/*TODO need to think on eps_bearer_id*/
	uint8_t ebi_index = resp->eps_bearer_id - 5;
	pdn = (resp->context)->pdns[ebi_index];
	bearer = (resp->context)->eps_bearers[ebi_index];

	if (pfcp_config.cp_type == SAEGWC) {
		set_create_session_response(
				gtpv2c_tx, resp->sequence, resp->context, pdn, bearer);

		s11_mme_sockaddr.sin_addr.s_addr =
						htonl((resp->context)->s11_mme_gtpc_ipv4.s_addr);

	} else if (pfcp_config.cp_type == PGWC) {
		/*TODO: This needs to be change after support libgtpv2 on S5S8*/
		set_pgwc_s5s8_create_session_response(gtpv2c_tx,
				resp->sequence, pdn, bearer);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						pdn->s5s8_sgw_gtpc_ipv4.s_addr;
	}

	if (pfcp_config.cp_type == SGWC) {
		uint8_t encoded_msg[512];
		uint16_t msg_len = 0;

		upf_context_t *upf_context = NULL;

		ret = rte_hash_lookup_data(upf_context_by_ip_hash,
				(const void*) &((resp->context)->upf_ipv4.s_addr), (void **) &(upf_context));

		if (ret < 0) {
			RTE_LOG_DP(DEBUG, DP, "%s:NO ENTRY FOUND IN UPF HASH [%u]\n", __func__,
					(resp->context)->upf_ipv4.s_addr);
			return 0;
		}

		encode_create_session_request_t(
				(create_session_request_t *)&(resp->s11_msg.csr),
				encoded_msg, &msg_len);


		gtpv2c_header *header;
		header =(gtpv2c_header*) encoded_msg;


		/*TODO: Need to remove following parser when we get parser from libgtpv2 */
		ret = gen_sgwc_s5s8_create_session_request((gtpv2c_header *)encoded_msg,
				//gtpv2c_tx, resp->s11_msg.csr.header.teid.has_teid.seq,
				gtpv2c_tx, header->teid_u.has_teid.seq,
				pdn, bearer, upf_context->fqdn);

		if (ret < 0)
			fprintf(stderr, "Failed to generate S5S8 SGWC CSR.\n");

		s5s8_recv_sockaddr.sin_addr.s_addr =
				htonl(resp->s11_msg.csr.s5s8pgw_pmip.ip.ipv4.s_addr);

		/* Update the session state */
		resp->state = CS_REQ_SNT_STATE;

		/* Update the UE state */
		ret = update_ue_state(resp->s11_sgw_gtpc_teid,
				CS_REQ_SNT_STATE);
		if (ret < 0) {
				fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}
		return 0;
	}

	/* Update the session state */
	resp->state = CONNECTED_STATE;

	/* Update the UE state */
	ret = update_ue_state(resp->s11_sgw_gtpc_teid,
			CONNECTED_STATE);
	if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
	}

	return 0;
}

int
process_pfcp_sess_mod_request(modify_bearer_request_t *mb_req)
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

	if (!mb_req->bearer_context.ebi.header.len
			|| !mb_req->bearer_context.s1u_enodeb_ftied.header.len) {
		fprintf(stderr, "%s:Dropping packet\n", __func__);
		return -EPERM;
	}

	ebi_index = mb_req->bearer_context.ebi.eps_bearer_id - 5;
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

	/* TODO something with modify_bearer_request.delay if set */

	if (mb_req->s11_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req->s11_mme_fteid.teid_gre))
		context->s11_mme_gtpc_teid = mb_req->s11_mme_fteid.teid_gre;

	bearer->s1u_enb_gtpu_ipv4 =
		mb_req->bearer_context.s1u_enodeb_ftied.ip.ipv4;
	bearer->s1u_enb_gtpu_teid =
		mb_req->bearer_context.s1u_enodeb_ftied.teid_gre;

	bearer->eps_bearer_id = mb_req->bearer_context.ebi.eps_bearer_id;

	context->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &mb_req->header, context, bearer, pdn);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	} else {
		cp_stats.session_modification_req_sent++;
		get_current_time(cp_stats.session_modification_req_sent_time);
	}

	/* Update UE State */
	context->state = SESS_MOD_REQ_SNT_STATE;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(context->seid, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", context->seid);
		return -1;
	}

	/* Set create session response */
	resp->eps_bearer_id = mb_req->bearer_context.ebi.eps_bearer_id;
	resp->sequence = mb_req->header.teid.has_teid.seq;
	resp->s11_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	resp->context = context;
	resp->msg_type = GTP_MODIFY_BEARER_REQ;
	resp->state = SESS_MOD_REQ_SNT_STATE;

	return 0;
}

uint8_t
process_pfcp_sess_mod_resp(uint64_t sess_id, gtpv2c_header *gtpv2c_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	eps_bearer *bearer  = NULL;
	struct resp_info *resp = NULL;

	/* Retrive the session information based on session id. */
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	/* Update the session state */
	resp->state = SESS_MOD_RESP_RCVD_STATE;

	/* Update the UE state */
	ret = update_ue_state(resp->s11_sgw_gtpc_teid,
			SESS_MOD_RESP_RCVD_STATE);
	if (ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State for teid: %u\n", __func__,
				resp->s11_sgw_gtpc_teid);
	}

	ebi_index = resp->eps_bearer_id - 5;
	bearer = (resp->context)->eps_bearers[ebi_index];
	if (!bearer) {
		fprintf(stderr,
				"Retrive modify bearer context but EBI is non-existent- "
				"Bitmap Inconsistency - Dropping packet\n");
		return -EPERM;
	}

	if (resp->msg_type == GTP_MODIFY_BEARER_REQ) {
		/* Fill the modify bearer response */
		set_modify_bearer_response(gtpv2c_tx,
				resp->sequence, resp->context, bearer);

		/* Update the session state */
		resp->state = CONNECTED_STATE;

		/* Update the UE state */
		ret = update_ue_state(resp->s11_sgw_gtpc_teid,
				CONNECTED_STATE);
		if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}

	} else if (resp->msg_type == GTP_CREATE_SESSION_RSP) {
		/* Fill the Create session response */
		set_create_session_response(
				gtpv2c_tx, resp->sequence, resp->context, bearer->pdn, bearer);

		/* Update the session state */
		resp->state = CONNECTED_STATE;

		/* Update the UE state */
		ret = update_ue_state(resp->s11_sgw_gtpc_teid,
				CONNECTED_STATE);
		if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}

	} else {
		/* Fill the release bearer response */
		set_release_access_bearer_response(gtpv2c_tx,
				resp->sequence, resp->s11_mme_gtpc_teid);

		/* Update the session state */
		resp->state = IDEL_STATE;

		/* Update the UE state */
		ret = update_ue_state(resp->s11_sgw_gtpc_teid,
				IDEL_STATE);
		if (ret < 0) {
			fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}
	}

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl((resp->context)->s11_mme_gtpc_ipv4.s_addr);

	clLog(sxlogger, eCLSeverityDebug, "%s: s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
				inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	return 0;
}

int
process_pfcp_sess_del_request(delete_session_request_t *ds_req)
{

	int ret = 0;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	uint32_t s5s8_pgw_gtpc_teid = 0;
	uint32_t s5s8_pgw_gtpc_ipv4 = 0;
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};

	/* Lookup and get context of delete request */
	ret = delete_context(ds_req, &context, &s5s8_pgw_gtpc_teid,
			&s5s8_pgw_gtpc_ipv4);
	if (ret)
		return ret;

	/* Fill pfcp structure for pfcp delete request and send it */
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	context->seid = SESS_ID(context->s11_sgw_gtpc_teid, ds_req->linked_ebi.eps_bearer_id);
	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->seid;

	if(ds_req->header.gtpc.teid_flag == 1)
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no =
				ds_req->header.teid.has_teid.seq;
	else
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no =
				ds_req->header.teid.no_teid.seq;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
		return -1;
	} else  {
		cp_stats.session_deletion_req_sent++;
		get_current_time(cp_stats.session_deletion_req_sent_time);
	}

	/* Update UE State */
	context->state = SESS_DEL_REQ_SNT_STATE;

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(context->seid, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", context->seid);
		return -1;
	}

	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
	resp->s11_msg.dsr = *ds_req;
	resp->eps_bearer_id = ds_req->linked_ebi.eps_bearer_id;
	resp->sequence = ds_req->header.teid.has_teid.seq;
	resp->s5s8_pgw_gtpc_teid = s5s8_pgw_gtpc_teid;
	resp->s5s8_pgw_gtpc_ipv4 = s5s8_pgw_gtpc_ipv4;
	resp->context = context;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = SESS_DEL_REQ_SNT_STATE;

	return 0;
}

uint8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header *gtpv2c_tx)
{
	int ret = 0;
	uint16_t msg_len = 0;
	struct resp_info *resp = NULL;
	delete_session_response_t del_resp = {0};

	/* Lookup entry in hash table on the basis of session id*/
	if (get_sess_entry(sess_id, &resp) != 0){
		fprintf(stderr, "NO Session Entry Found for sess ID:%lu\n", sess_id);
		return -1;
	}

	/* Update the session state */
	resp->state = SESS_DEL_RESP_RCVD_STATE;

	/* Update the UE state */
	ret = update_ue_state((resp->context)->s11_sgw_gtpc_teid,
			SESS_DEL_RESP_RCVD_STATE);
	if (ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State for teid: %u\n", __func__,
				resp->s11_sgw_gtpc_teid);
	}

	if (pfcp_config.cp_type == SGWC) {
		uint16_t msg_len = 0;
		uint8_t encoded_msg[512];

		encode_delete_session_request_t(
				(delete_session_request_t *)&(resp->s11_msg.dsr),
				encoded_msg, &msg_len);

		gtpv2c_header *header;
		header =(gtpv2c_header*) encoded_msg;

		ret =
			gen_sgwc_s5s8_delete_session_request((gtpv2c_header *)encoded_msg,
					gtpv2c_tx, resp->s5s8_pgw_gtpc_teid,
					header->teid_u.has_teid.seq, resp->eps_bearer_id);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						resp->s5s8_pgw_gtpc_ipv4;

		/* Update the session state */
		resp->state = DS_REQ_SNT_STATE;

		/* Update the UE state */
		ret = update_ue_state((resp->context)->s11_sgw_gtpc_teid,
				DS_REQ_SNT_STATE);
		if (ret < 0) {
				fprintf(stderr, "%s:Failed to update UE State.\n", __func__);
		}

		clLog(sxlogger, eCLSeverityDebug, "SGWC:%s: "
				"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));

		return ret;

	} else if ( pfcp_config.cp_type == PGWC) {
		set_gtpv2c_teid_header(gtpv2c_tx, GTP_DELETE_SESSION_RSP,
					resp->s5s8_sgw_gtpc_del_teid_ptr,
					resp->sequence);

		set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						resp->s5s8_pgw_gtpc_ipv4;

		/* Delete entry from session entry */
		if (del_sess_entry(sess_id) != 0){
			fprintf(stderr, "NO Session Entry Found for Key sess ID:%lu\n", sess_id);
			return -1;
		}


		clLog(sxlogger, eCLSeverityDebug, "PGWC:%s: "
				"s5s8_recv_sockaddr.sin_addr.s_addr :%s\n", __func__,
				inet_ntoa(*((struct in_addr *)&s5s8_recv_sockaddr.sin_addr.s_addr)));
		return 0;
	}

	/* Fill gtpv2c structure for sending on s11 interface */
	set_gtpv2c_teid_header((gtpv2c_header *) &del_resp, GTP_DELETE_SESSION_RSP,
			(resp->context)->s11_mme_gtpc_teid, resp->sequence);
	set_cause_accepted_ie((gtpv2c_header *) &del_resp, IE_INSTANCE_ZERO);

	/*Encode the S11 delete session response message. */
	encode_delete_session_response_t(&del_resp, (uint8_t *)gtpv2c_tx,
			&msg_len);

	gtpv2c_tx->gtpc.length = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl((resp->context)->s11_mme_gtpc_ipv4.s_addr);

	clLog(s11logger, eCLSeverityDebug, "SAEGWC:%s:"
			"s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	/* Delete entry from session entry */
	if (del_sess_entry(sess_id) != 0){
		fprintf(stderr, "NO Session Entry Found for Key sess ID:%lu\n", sess_id);
		return -1;
	}

	return 0;
}

#endif /* CP_BUILD */

#ifdef DP_BUILD
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_sess_set_del_resp)
{

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
