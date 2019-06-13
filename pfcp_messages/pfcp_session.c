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
#endif /* CP_BUILD */

#ifdef DP_BUILD
extern struct in_addr dp_comm_ip;
#endif /* DP_BUILD */

#ifdef CP_BUILD
pfcp_config_t pfcp_config;

int
delete_context(delete_session_request_t *ds_req, ue_context **_context);

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

#define size sizeof(pfcp_sess_mod_req_t)

extern int pfcp_fd;

struct app_params app;

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
		gtpv2c_header *header,
		ue_context *context, eps_bearer *bearer, pdn_connection *pdn)
{
	uint32_t seq = 0;
	upf_context_t *upf_ctx = NULL;
	int ret = 0;

	if ((ret = upf_context_entry_lookup(context->upf_ipv4.s_addr,
			&upf_ctx)) < 0) {
		RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
		return;
	}

	if( header != NULL)
		RTE_LOG_DP(DEBUG, CP, "TEID[%d]\n", header->teid_u.has_teid.teid);

	memset(pfcp_sess_mod_req, 0, sizeof(pfcp_sess_mod_req_t));

	if(header != NULL) {
		if(header->gtpc.teidFlg == 1)
			seq = header->teid_u.has_teid.seq;
		else
			seq = header->teid_u.no_teid.seq;
	}

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header), PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);

	pfcp_sess_mod_req->header.seid_seqno.has_seid.seid = context->seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req->cp_fseid), context->seid, node_value);

	removing_bar(&(pfcp_sess_mod_req->remove_bar));

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
	pfcp_sess_mod_req->create_pdr_count = 1;

	for( int i = 0; i < pfcp_sess_mod_req->create_pdr_count ; i++)
		creating_pdr(&(pfcp_sess_mod_req->create_pdr[i]));

	switch (pfcp_config.cp_type)
	{
		case SGWC :
		case SAEGWC :
			pfcp_sess_mod_req->create_pdr[0].pdi.local_fteid.teid = bearer->s1u_enb_gtpu_teid;
			/* TODO: Revisit this for change in yang */
			pfcp_sess_mod_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
			pfcp_sess_mod_req->create_pdr[0].pdi.local_fteid.ipv4_address = htonl(bearer->s1u_enb_gtpu_ipv4.s_addr) ;
			pfcp_sess_mod_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;
			break;

		case PGWC :
			/* modification request for split is only when handover indication flag is on in CSR */
			/* need to handle HO scenario*/
			break;

		default :
			printf("default pfcp sess mod req\n");
			break;
	}

	creating_bar(&(pfcp_sess_mod_req->create_bar));

	if (upf_ctx->up_supp_features & UP_PDIU)
		creating_traffic_endpoint(&(pfcp_sess_mod_req->create_traffic_endpt));

	// set of update QER

	pfcp_sess_mod_req->update_qer_count = 2;

	for(int i=0; i < pfcp_sess_mod_req->update_qer_count; i++ )
		updating_qer(&(pfcp_sess_mod_req->update_qer[i]));


	// set of update BAR
	 updating_bar(&(pfcp_sess_mod_req->update_bar));

	 if (upf_ctx->up_supp_features & UP_PDIU)
		 updating_traffic_endpoint(&(pfcp_sess_mod_req->upd_traffic_endpt));

	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreq_flags));

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

	set_up_inactivity_timer(&(pfcp_sess_mod_req->user_plane_inact_timer));

	set_query_urr_refernce(&(pfcp_sess_mod_req->query_urr_ref));

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
		RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
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

	if (pfcp_config.cp_type == SGWC || pfcp_config.cp_type == PGWC )
		pfcp_sess_est_req->create_pdr_count = 2;
	else
		pfcp_sess_est_req->create_pdr_count = 1;

	for(int i = 0; i < pfcp_sess_est_req->create_pdr_count; i++)
		creating_pdr(&(pfcp_sess_est_req->create_pdr[i]));

	switch (pfcp_config.cp_type)
	{
		case SGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = htonl(bearer->s1u_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s1u_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;

			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.teid = htonl(bearer->s5s8_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[1].pdi.ue_ip_address.ipv4_address = (pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s5s8_sgwu_ip);
			pfcp_sess_est_req->create_pdr[1].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;
			break;

		case PGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = htonl(bearer->s5s8_pgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s5s8_pgwu_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;

			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.teid = htonl(bearer->s5s8_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[1].pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[1].pdi.local_fteid.ipv4_address =(bearer->s5s8_sgw_gtpu_ipv4.s_addr);
			pfcp_sess_est_req->create_pdr[1].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_CORE;
			break;

		case SAEGWC :
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.teid = htonl(bearer->s1u_sgw_gtpu_teid);
			pfcp_sess_est_req->create_pdr[0].pdi.ue_ip_address.ipv4_address = pdn->ipv4.s_addr;
			pfcp_sess_est_req->create_pdr[0].pdi.local_fteid.ipv4_address =
					htonl(upf_ctx->s1u_ip);
			pfcp_sess_est_req->create_pdr[0].pdi.src_intfc.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
			break;

		default :
			printf("Default PFCP Sess Est Req\n");
			break;
	}

	creating_bar(&(pfcp_sess_est_req->create_bar));

	if(csr != NULL) {
		set_pdn_type(&(pfcp_sess_est_req->pdn_type), &(csr->pdn_type));
	}

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

	if (upf_ctx->up_supp_features & UP_TRACE)
		set_trace_info(&(pfcp_sess_est_req->trc_info));

}

int
process_pfcp_sess_est_request(gtpv2c_header *gtpv2c_rx,
		create_session_request_t *csr,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx,
		char *sgwu_fqdn, struct in_addr *upf_ipv4)
{
	int ret = 0;
	ue_context *context =  NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct in_addr ue_ip;
	/* TODO: Need to think on static variable */
	static uint32_t process_pfcp_sgwc_s5s8_cs_req_cnt;

	pfcp_sess_estab_req_t pfcp_sess_est_req = {0};

	upf_context_t *upf_ctx = NULL;

	if ((ret = upf_context_entry_lookup(upf_ipv4->s_addr,
			&upf_ctx)) < 0) {
		RTE_LOG_DP(ERR, CP, "%s : Error: %d \n", __func__, ret);
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
			csr->bearer_context.ebi.eps_bearer_id, &context);
	if (ret)
		return ret;

	if (csr->mei.header.len)
		memcpy(&context->mei, csr->mei.mei, csr->mei.header.len);

	memcpy(&context->msisdn, &csr->msisdn.msisdn, csr->msisdn.header.len);

	context->s11_sgw_gtpc_ipv4 = pfcp_config.s11_ip;
	context->s11_mme_gtpc_teid = csr->sender_ftied.teid_gre;
	context->s11_mme_gtpc_ipv4 = csr->sender_ftied.ip.ipv4;

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(csr->sender_ftied.ip.ipv4.s_addr);

	/* Store upf ipv4 */
	context->upf_ipv4 = *upf_ipv4;

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_in_use = apn_requested;
		pdn->apn_ambr.ambr_downlink = csr->ambr.apn_ambr_dl;
		pdn->apn_ambr.ambr_uplink = csr->ambr.apn_ambr_ul;
		pdn->apn_restriction = csr->apn_restriction.restriction_type;
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);

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

		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.s5s8_ip;
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = (context->s11_sgw_gtpc_teid);
		pdn->s5s8_pgw_gtpc_ipv4 = csr->s5s8pgw_pmip.ip.ipv4;

		if (pfcp_config.cp_type == SGWC) {
			s5s8_recv_sockaddr.sin_addr.s_addr =
					htonl(csr->s5s8pgw_pmip.ip.ipv4.s_addr);
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
		pdn->s5s8_pgw_gtpc_teid = csr->s5s8pgw_pmip.teid_gre;
	}

	bearer = context->eps_bearers[ebi_index];
	{
		/* VS: Need to re-vist this ARP[Allocation/Retention priority] handling portion */
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

		bearer->s5s8_sgw_gtpu_ipv4.s_addr = htonl(upf_ctx->s5s8_sgwu_ip);
		/* TODO : Need to think on s1u ip and pfcp context */
		bearer->s1u_sgw_gtpu_ipv4.s_addr = upf_ctx->s1u_ip;

		/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
		 *                  * Computation same as s1u_sgw_gtpu_teid
		 *                                   */
		set_s1u_sgw_gtpu_teid(bearer, context);
		set_s5s8_sgw_gtpu_teid(bearer, context);
		bearer->pdn = pdn;
	}

	/*fill_pfcp_sess_est_req(&pfcp_sess_est_req, &csr );*/
	context->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);
	fill_pfcp_sess_est_req(&pfcp_sess_est_req, csr, context, bearer, pdn);

	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_sess_estab_req_t(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_config.cp_type == SGWC) {
		ret = gen_sgwc_s5s8_create_session_request(gtpv2c_rx,
				gtpv2c_s5s8_tx, csr->header.teid.has_teid.seq,
				pdn, bearer, sgwu_fqdn);
		RTE_LOG_DP(DEBUG, CP, "NGIC- create_session.c::"
				"\n\tprocess_create_session_request::case= %d;"
				"\n\tprocess_pfcp_sgwc_s5s8_cs_req_cnt= %u;"
				"\n\tgen_create_s5s8_session_request= %d\n",
				spgw_cfg, process_pfcp_sgwc_s5s8_cs_req_cnt++,
				ret);
	} else if (pfcp_config.cp_type == SAEGWC) {
		set_create_session_response(
				gtpv2c_s11_tx, csr->header.teid.has_teid.seq,
				context, pdn, bearer);
	}

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		fprintf(stderr, "Error sending: %i\n", errno);
	} else {
		cp_stats.session_establishment_req_sent++;
	}


	return 0;
}

int
process_pfcp_sess_mod_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	ue_context *context = NULL;
	eps_bearer *bearer  = NULL;
	pdn_connection *pdn =  NULL;
	modify_bearer_request_t mb_req = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	decode_modify_bearer_request_t((uint8_t *) gtpv2c_rx, &mb_req);

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &mb_req.header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	if (!mb_req.bearer_context.ebi.header.len
			|| !mb_req.bearer_context.s1u_enodeb_ftied.header.len) {
		fprintf(stderr, "Dropping packet\n");
		return -EPERM;
	}

	ebi_index = mb_req.bearer_context.ebi.eps_bearer_id - 5;
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

	if (mb_req.s11_mme_fteid.header.len &&
			(context->s11_mme_gtpc_teid != mb_req.s11_mme_fteid.teid_gre))
		context->s11_mme_gtpc_teid = mb_req.s11_mme_fteid.teid_gre;

	bearer->s1u_enb_gtpu_ipv4 =
		mb_req.bearer_context.s1u_enodeb_ftied.ip.ipv4;

	bearer->s1u_enb_gtpu_teid =
		mb_req.bearer_context.s1u_enodeb_ftied.teid_gre;

	bearer->eps_bearer_id = mb_req.bearer_context.ebi.eps_bearer_id;

	context->seid = SESS_ID(context->s11_sgw_gtpc_teid, bearer->eps_bearer_id);

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, gtpv2c_rx, context, bearer, pdn);

	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	set_modify_bearer_response(gtpv2c_s11_tx,
		mb_req.header.teid.has_teid.seq, context, bearer);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	} else {
		cp_stats.session_modification_req_sent++;
	}

	return 0;
}

int
process_pfcp_sess_del_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
{

	int ret = 0;
	ue_context *context = NULL;
	delete_session_request_t ds_req = {0};
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};

	decode_delete_session_request_t((uint8_t *) gtpv2c_rx, &ds_req);

	if (spgw_cfg == SGWC) {
		pdn_connection *pdn = NULL;
		uint32_t s5s8_pgw_gtpc_del_teid;
		static uint32_t process_sgwc_s5s8_ds_req_cnt;
		/* s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */

		ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				(const void *) &ds_req.header.teid.has_teid.teid,
				(void **) &context);

		if (ret < 0 || !context)
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

		uint8_t del_ebi_index = ds_req.linked_ebi.eps_bearer_id - 5;
		pdn = context->pdns[del_ebi_index];
		/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
		 * key->ue_context_by_fteid_hash */
		s5s8_pgw_gtpc_del_teid = htonl(pdn->s5s8_pgw_gtpc_teid);
		ret =
			gen_sgwc_s5s8_delete_session_request(gtpv2c_rx,
					gtpv2c_s5s8_tx, s5s8_pgw_gtpc_del_teid,
					gtpv2c_rx->teid_u.has_teid.seq, ds_req.linked_ebi.eps_bearer_id);
		RTE_LOG(DEBUG, CP, "NGIC- delete_session.c::"
				"\n\tprocess_delete_session_request::case= %d;"
				"\n\tprocess_sgwc_s5s8_ds_req_cnt= %u;"
				"\n\tue_ip= pdn->ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
				"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
				"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
				"\n\tgen_delete_s5s8_session_request= %d\n",
				spgw_cfg, process_sgwc_s5s8_ds_req_cnt++,
				inet_ntoa(pdn->ipv4),
				inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
				pdn->s5s8_sgw_gtpc_teid,
				inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
				pdn->s5s8_pgw_gtpc_teid,
				ret);

		s5s8_recv_sockaddr.sin_addr.s_addr =
						htonl(pdn->s5s8_pgw_gtpc_ipv4.s_addr);

		return ret;
	}

	gtpv2c_s11_tx->teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;
	ret = delete_context(&ds_req, &context);
	if (ret)
		return ret;

	pfcp_sess_del_rsp_t *pfcp_sess_del_resp =
					malloc(sizeof(pfcp_sess_del_rsp_t));
	memset(pfcp_sess_del_resp, 0, sizeof(pfcp_sess_del_rsp_t));

	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	context->seid = SESS_ID(context->s11_sgw_gtpc_teid,ds_req.linked_ebi.eps_bearer_id);
	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->seid;

	if(ds_req.header.gtpc.teid_flag == 1)
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no =
				ds_req.header.teid.has_teid.seq;
	else
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no =
				ds_req.header.teid.no_teid.seq;


	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ){
		printf("Error sending: %i\n",errno);
	} else  {
		cp_stats.session_deletion_req_sent++;
	}

	set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
			ntohl(context->s11_mme_gtpc_teid), gtpv2c_rx->teid_u.has_teid.seq);
	set_cause_accepted_ie(gtpv2c_s11_tx, IE_INSTANCE_ZERO);

	s11_mme_sockaddr.sin_addr.s_addr =
					htonl(context->s11_mme_gtpc_ipv4.s_addr);
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
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *
		pfcp_sess_modify_resp, uint8_t cause, int offend)
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
	set_created_pdr_ie(&(pfcp_sess_modify_resp->created_pdr));

	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_modify_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_modify_resp->ovrld_ctl_info));

	set_failed_rule_id(&(pfcp_sess_modify_resp->failed_rule_id));

	// filling of ADURI
	// Need to do
	set_additional_usage(&(pfcp_sess_modify_resp->add_usage_rpts_info));

	// filling of CRTEP
	// Need to do
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		set_created_traffic_endpoint(&(pfcp_sess_modify_resp->createdupdated_traffic_endpt));

}

void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_resp,
			uint8_t cause, int offend)
{
	uint32_t seq  = 0;
	uint32_t node_value = 0;

	memset(pfcp_sess_est_resp,0,sizeof(pfcp_sess_estab_rsp_t)) ;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_resp->header),
			PFCP_SESSION_ESTABLISHMENT_RESPONSE, HAS_SEID, seq);

	set_node_id(&(pfcp_sess_est_resp->node_id), node_value);

	//set cause
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_sess_est_resp->cause), cause);

	if(cause == CONDITIONALIEMISSING
			|| cause == MANDATORYIEMISSING) {
		set_offending_ie(&(pfcp_sess_est_resp->offending_ie), offend);
	}

	uint64_t up_seid = pfcp_sess_est_resp->header.seid_seqno.has_seid.seid ;
	set_fseid(&(pfcp_sess_est_resp->up_fseid), up_seid, node_value);


	//creating pdr for Fteid only,TODO : Rules will be implemented later
	/************************************************
	 *  cp_type     count    FTEID_1        FTEID_2 *
	 *************************************************
	 SGWU         2      s1u  SGWU      s5s8 SGWU
	 PGWU         2      s5s8 PGWU      s5s8SGWU
	 SAEGWU       1      s1u SAEGWU         -
	 ************************************************/
/*
	if (app.spgw_cfg == SGWU || app.spgw_cfg == PGWU )
		pfcp_sess_est_resp->created_pdr_cnt = 2;
	else
		pfcp_sess_est_resp->created_pdr_count = 1;

	for(int i=0; i < pfcp_sess_est_resp->created_pdr_count; i++ )
		set_created_pdr_ie(&(pfcp_sess_est_resp->created_pdr[i]));
*/
	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_est_resp->load_ctl_info));

	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_est_resp->ovrld_ctl_info));

	char sgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), sgwu_addr, INET_ADDRSTRLEN);
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->sgw_u_fqcsid), sgwu_value);

	char pgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(dp_comm_ip), pgwu_addr, INET_ADDRSTRLEN);
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->pgw_u_fqcsid), pgwu_value);

	set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
}
#endif /* DP_BUILD */
