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

#include <errno.h>

#include <rte_debug.h>

#include "pfcp_set_ie.h"
#include "cp.h"
#include "pfcp_messages.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "pfcp_association.h"

#if defined(PFCP_COMM) && defined(CP_BUILD)
#include "../cp/ue.h"
#include "../cp/gtpv2c_set_ie.h"
#include "../libgtpv2c/include/req_resp.h"
int
delete_context(delete_session_request_t *ds_req,
                        ue_context **_context);
#endif

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4
#define size sizeof(pfcp_session_modification_request_t)

pfcp_config_t pfcp_config;
extern pfcp_context_t pfcp_ctxt;
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];

void
fill_pfcp_sess_del_req( pfcp_session_deletion_request_t *pfcp_sess_del_req)
{
	memset(pfcp_sess_del_req,0,sizeof(pfcp_session_deletion_request_t));
	uint32_t seq = 1;
	memset(pfcp_sess_del_req,0,sizeof(pfcp_session_deletion_request_t));

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_req->header),PFCP_SESSION_DELETION_REQUEST,
			HAS_SEID,seq);
}

void
fill_pfcp_sess_set_del_req( pfcp_session_set_deletion_request_t *pfcp_sess_set_del_req)
{
	uint32_t seq = 1;
	memset(pfcp_sess_set_del_req,0,sizeof(pfcp_session_set_deletion_request_t));

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),PFCP_SESSION_SET_DELETION_REQUEST,
			HAS_SEID,seq);
	 // set of node id
	const char* pAddr = "192.168.0.10";
	uint32_t node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id),node_value);

	// set of sgwc fqcsid
	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),sgwc_addr, INET_ADDRSTRLEN);	
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgwc_fqcsid),sgwc_value);

	// set of pgwc fqcsid
	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pgwc_pfcp_ip[0]),pgwc_addr, INET_ADDRSTRLEN);	
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgwc_fqcsid),pgwc_value);

	// set of sgwu fqcsid
	char sgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwu_pfcp_ip[0]),sgwu_addr, INET_ADDRSTRLEN);	
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->sgwu_fqcsid),sgwu_value);

	// set of pgwu fqcsid
	char pgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pgwu_pfcp_ip[0]),pgwu_addr, INET_ADDRSTRLEN);	
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->pgwu_fqcsid),pgwu_value);

	// set of twan fqcsid
	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "192.16.0.1";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->twan_fqcsid),twan_value);

	// set of epdg fqcsid
	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "192.16.0.2";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->epdg_fqcsid),epdg_value);

	// set of mme fqcsid
	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.mme_s11_ip[0]),mme_addr, INET_ADDRSTRLEN);	
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_set_del_req->mme_fqcsid),mme_value);

}
#if defined(PFCP_COMM) && defined(CP_BUILD)
void
fill_pfcp_sess_mod_req( pfcp_session_modification_request_t *pfcp_sess_mod_req,modify_bearer_request_t *mbr)
#else
void
fill_pfcp_sess_mod_req( pfcp_session_modification_request_t *pfcp_sess_mod_req)
#endif
{
	uint32_t seq = 1;
#if defined(PFCP_COMM) && defined(CP_BUILD)
	RTE_LOG(DEBUG, CP, "TEID[%d]\n",mbr->s11_mme_fteid.teid_gre);
#endif
	memset(pfcp_sess_mod_req,0,sizeof(pfcp_session_modification_request_t));

#if defined(PFCP_COMM) && defined(CP_BUILD) 
	if(mbr->header.gtpc.teid_flag == 1)
		seq = mbr->header.teid.has_teid.seq;
	else
		seq = mbr->header.teid.no_teid.seq;
#endif
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req->header),PFCP_SESSION_MODIFICATION_REQUEST,
					           HAS_SEID, seq);
	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);

	// set of cp_fseid
	uint64_t cp_seid = pfcp_sess_mod_req->header.seid_seqno.has_seid.seid;
	set_fseid(&(pfcp_sess_mod_req->cp_fseid),cp_seid,node_value);

	//set of remove bar
	removing_bar(&(pfcp_sess_mod_req->remove_bar));

	//set of remove traffic end point
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		removing_traffic_endpoint(&(pfcp_sess_mod_req->remove_traffic_endpoint));

	//set create PDR

	creating_pdr(&(pfcp_sess_mod_req->create_pdr));
	
	// set of create BAR
	creating_bar(&(pfcp_sess_mod_req->create_bar));

	//set of create traffic end point
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		creating_traffic_endpoint(&(pfcp_sess_mod_req->create_traffic_endpoint));

	// set of update QER
	 updating_qer(&(pfcp_sess_mod_req->update_qer));

	// set of update BAR
	 updating_bar(&(pfcp_sess_mod_req->update_bar));

	//set of update traffic end point
	 if( pfcp_ctxt.up_supported_features & UP_PDIU )
		 updating_traffic_endpoint(&(pfcp_sess_mod_req->update_traffic_endpoint));

	//set of pfcpsmreqflags
	set_pfcpsmreqflags(&(pfcp_sess_mod_req->pfcpsmreqflags));

	// set of sgwc fqcsid
	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),sgwc_addr, INET_ADDRSTRLEN);	
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->sgwc_fqcsid),sgwc_value);

	// set of mme fqcsid
	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.mme_s11_ip[0]),mme_addr, INET_ADDRSTRLEN);	
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_mod_req->mme_fqcsid),mme_value);

	// set of pgwc fqcsid
	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pgwc_pfcp_ip[0]),pgwc_addr, INET_ADDRSTRLEN);	
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_mod_req->pgwc_fqcsid),pgwc_value);

	// set of epdg fqcsid
	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_mod_req->epdg_fqcsid),epdg_value);

	// set of twan fqcsid
	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_mod_req->twan_fqcsid),twan_value);

	// set of UP inactivity timer
	set_up_inactivity_timer(&(pfcp_sess_mod_req->user_plane_inactivity_timer));

	//set of query urr refernce
	set_query_urr_refernce(&(pfcp_sess_mod_req->query_urr_reference));

	// set of trace info
	if( pfcp_ctxt.up_supported_features & UP_TRACE )
		set_trace_info(&(pfcp_sess_mod_req->trace_information));

}

#if defined(PFCP_COMM) && defined(CP_BUILD)
void
fill_pfcp_sess_est_req( pfcp_session_establishment_request_t *pfcp_sess_est_req,create_session_request_t *csr)
#else
void
fill_pfcp_sess_est_req( pfcp_session_establishment_request_t *pfcp_sess_est_req)
#endif
{
	uint32_t seq = 1;
	/*TODO :generate seid value and store this in array
	 to send response from cp/dp , first check seid is there in array or not if yes then 
	 fill that seid in response and if not then seid =0 */

	memset(pfcp_sess_est_req,0,sizeof(pfcp_session_establishment_request_t));

#if defined(PFCP_COMM) && defined(CP_BUILD) 
	if(csr->header.gtpc.teid_flag == 1)
		seq = csr->header.teid.has_teid.seq;
	else
		seq = csr->header.teid.no_teid.seq;
#endif
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_req->header),PFCP_SESSION_ESTABLISHMENT_REQUEST,
					           HAS_SEID, seq);

	// set of node id
	char pAddr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),pAddr, INET_ADDRSTRLEN);	
	unsigned long node_value = inet_addr(pAddr);

	set_node_id(&(pfcp_sess_est_req->node_id),node_value);

	// set of cp_fseid
	uint64_t cp_seid = pfcp_sess_est_req->header.seid_seqno.has_seid.seid ;
	set_fseid(&(pfcp_sess_est_req->cp_fseid),cp_seid,node_value);

	//creating pdr for Fteid only,TODO : Rules will be implemented later
	creating_pdr(&(pfcp_sess_est_req->create_pdr));

	// set of create BAR
	creating_bar(&(pfcp_sess_est_req->create_bar));

	// set of pdn type
#if defined(PFCP_COMM) && defined(CP_BUILD)
	set_pdn_type(&(pfcp_sess_est_req->pdn_type),&(csr->pdn_type));
#else
	set_pdn_type(&(pfcp_sess_est_req->pdn_type));
#endif
	
	//TODO can make generic function , if we can change the flag of FQ_CSID  specific to module
	// set of sgwc fqcsid
	char sgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwc_pfcp_ip[0]),sgwc_addr, INET_ADDRSTRLEN);	
	unsigned long sgwc_value = inet_addr(sgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->sgwc_fqcsid),sgwc_value);

	// set of mme fqcsid
	char mme_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.mme_s11_ip[0]),mme_addr, INET_ADDRSTRLEN);	
	unsigned long mme_value = inet_addr(mme_addr);
	set_fq_csid( &(pfcp_sess_est_req->mme_fqcsid),mme_value);

	// set of pgwc fqcsid
	char pgwc_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pgwc_pfcp_ip[0]),pgwc_addr, INET_ADDRSTRLEN);	
	unsigned long pgwc_value = inet_addr(pgwc_addr);
	set_fq_csid( &(pfcp_sess_est_req->pgwc_fqcsid),pgwc_value);

	// set of epdg fqcsid
	//TODO : IP addres for epdgg is hardcoded
	const char* epdg_addr = "0.0.0.0";
	uint32_t epdg_value = inet_addr(epdg_addr);
	set_fq_csid( &(pfcp_sess_est_req->epdg_fqcsid),epdg_value);

	// set of twan fqcsid
	//TODO : IP addres for twan is hardcoded
	const char* twan_addr = "0.0.0.0";
	uint32_t twan_value = inet_addr(twan_addr);
	set_fq_csid( &(pfcp_sess_est_req->twan_fqcsid),twan_value);

	// set of UP inactivity timer
	set_up_inactivity_timer(&(pfcp_sess_est_req->user_plane_inactivity_timer));

	// set of user id
	set_user_id(&(pfcp_sess_est_req->user_id));

	// set of trace info
	if( pfcp_ctxt.up_supported_features & UP_TRACE )
		set_trace_info(&(pfcp_sess_est_req->trace_information));

}

//modify the below function with gtpv2c_rx
#if defined(PFCP_COMM) && defined(CP_BUILD)
int
process_pfcp_sess_est_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx)
#else
int
process_pfcp_sess_est_request(void)
#endif
{
	pfcp_session_establishment_request_t pfcp_sess_est_req = {0};

#if defined(PFCP_COMM) && defined(CP_BUILD)
	int ret = 0;
	ue_context *context =  NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;
	struct in_addr ue_ip;
	create_session_request_t csr = { 0 };
	ret = decode_create_session_request_t((uint8_t *) gtpv2c_rx,
			&csr);
	if (!ret)
		return ret;

	if (csr.indication.header.len &&
			csr.indication.indication_value.uimsi) {
		fprintf(stderr, "Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n");
		return -EPERM;
	}

	if (!csr.indication.header.len
			|| !csr.apn_restriction.header.len
			|| !csr.bearer_context.header.len
			|| !csr.sender_ftied.header.len
			|| !csr.s5s8pgw_pmip.header.len
			|| !csr.imsi.header.len
			|| !csr.ambr.header.len
			|| !csr.pdn_type.header.len
			|| !csr.bearer_context.bearer_qos.header.len
			|| !csr.msisdn.header.len
			|| !(csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV4) ) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		return -EPERM;
	}

	if (csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV6 ||
			csr.pdn_type.pdn_type == PDN_IP_TYPE_IPV4V6) {
		fprintf(stderr, "IPv6 Not Yet Implemented - Dropping packet\n");
		return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}

	apn *apn_requested = get_apn((char *)csr.apn.apn, csr.apn.header.len);

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	uint8_t ebi_index = csr.bearer_context.ebi.eps_bearer_id - 5;
	ret = acquire_ip(&ue_ip);
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;
	/* set s11_sgw_gtpc_teid= key->ue_context_by_fteid_hash */
	ret = create_ue_context(csr.imsi.imsi, csr.imsi.header.len,
			csr.bearer_context.ebi.eps_bearer_id, &context);
	if (ret)
		return ret;
	if (csr.mei.header.len)
		memcpy(&context->mei, csr.mei.mei, csr.mei.header.len);

	memcpy(&context->msisdn, &csr.msisdn.msisdn, csr.msisdn.header.len);

	context->s11_sgw_gtpc_ipv4 = pfcp_config.sgwc_s11_ip[0];
	context->s11_mme_gtpc_teid = csr.sender_ftied.teid_gre;
	context->s11_mme_gtpc_ipv4 = csr.sender_ftied.ip.ipv4;
	//context->s11_mme_gtpc_ipv4 = pfcp_config.mme_s11_ip[0];

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_in_use = apn_requested;
		pdn->apn_ambr.ambr_downlink = csr.ambr.apn_ambr_dl;
		pdn->apn_ambr.ambr_uplink = csr.ambr.apn_ambr_ul;
		pdn->apn_restriction = csr.apn_restriction.restriction_type;
		pdn->ipv4.s_addr = htonl(ue_ip.s_addr);

		if (csr.pdn_type.pdn_type == PDN_TYPE_IPV4)
			pdn->pdn_type.ipv4 = 1;
		else if (csr.pdn_type.pdn_type == PDN_TYPE_IPV6)
			pdn->pdn_type.ipv6 = 1;
		else if (csr.pdn_type.pdn_type == PDN_TYPE_IPV4_IPV6) {
			pdn->pdn_type.ipv4 = 1;
			pdn->pdn_type.ipv6 = 1;
		}

		if (csr.charging_characteristics.header.len)
			memcpy(&pdn->charging_characteristics,
					&csr.charging_characteristics.value,
					sizeof(csr.charging_characteristics.value));

		pdn->s5s8_sgw_gtpc_ipv4 = pfcp_config.sgwc_s5s8_ip[0];
		/* Note: s5s8_sgw_gtpc_teid =
		 *                  * s11_sgw_gtpc_teid
		 *                                   */
		pdn->s5s8_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
		pdn->s5s8_pgw_gtpc_ipv4 = csr.s5s8pgw_pmip.ip.ipv4;

		/* Note: s5s8_pgw_gtpc_teid updated by
		 *                  * process_sgwc_s5s8_create_session_response (...)
		 *                                   */
		pdn->s5s8_pgw_gtpc_teid = csr.s5s8pgw_pmip.teid_gre;
	}

	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		 * if (create_session_request.bearer_tft_ie) {
		 * }**/

		bearer->qos.qos.ul_mbr =
			csr.bearer_context.bearer_qos.maximum_bit_rate_for_uplink;
		bearer->qos.qos.dl_mbr =
			csr.bearer_context.bearer_qos.maximum_bit_rate_for_downlink;
		bearer->qos.qos.ul_gbr =
			csr.bearer_context.bearer_qos.guaranteed_bit_rate_for_uplink;
		bearer->qos.qos.dl_gbr =
			csr.bearer_context.bearer_qos.guaranteed_bit_rate_for_downlink;
		//TODO modify the s1u_sgw_ip
		//bearer->s1u_sgw_gtpu_ipv4 = s1u_sgw_ip;
		bearer->s1u_sgw_gtpu_ipv4 = pfcp_config.sgwu_pfcp_ip[0];
		set_s1u_sgw_gtpu_teid(bearer, context);
		//bearer->s5s8_sgw_gtpu_ipv4 = s5s8_sgwu_ip;
		//TODO VG  :below mention must be replaced with sgwu
		bearer->s5s8_sgw_gtpu_ipv4 = pfcp_config.sgwc_s5s8_ip[0];
		/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
		 *                  * Computation same as s1u_sgw_gtpu_teid
		 *                                   */
		set_s5s8_sgw_gtpu_teid(bearer, context);
		bearer->pdn = pdn;
	}


#endif

#if defined(PFCP_COMM) && defined(CP_BUILD)
	fill_pfcp_sess_est_req(&pfcp_sess_est_req,&csr);
	context->seid = SESS_ID(context->s11_sgw_gtpc_teid,bearer->eps_bearer_id);
	pfcp_sess_est_req.header.seid_seqno.has_seid.seid = context->seid;
	pfcp_sess_est_req.cp_fseid.seid = context->seid;
	pfcp_sess_est_req.create_pdr.pdi.local_fteid.teid = htonl(bearer->s1u_sgw_gtpu_teid);
	pfcp_sess_est_req.create_pdr.pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
	pfcp_sess_est_req.create_pdr.pdi.local_fteid.ipv4_address = htonl(pfcp_ctxt.s1u_ip[0]);

#else
	fill_pfcp_sess_est_req(&pfcp_sess_est_req);
#endif
	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_session_establishment_request(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if(pfcp_ctxt.flag_ava_ip == true)
	{
		for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){

			if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC) {
				//TODO :TEMP 	pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;

				if ( pfcp_send(pfcp_sgwc_fd_arr[i],pfcp_msg,encoded,&pfcp_sgwu_sockaddr_arr[i]) < 0 )
					printf("Error sending: %i\n",errno);

#if defined (PFCP_COMM) && defined (CP_BUILD)
				set_create_session_response(
						gtpv2c_s11_tx, csr.header.teid.has_teid.seq,
						context, pdn, bearer);
#endif
			}else if (pfcp_config.cp_type == PGWC) {
				//TODO:TEMP pfcp_pgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;

				if (sendto(pfcp_pgwc_fd_arr[i],
							(char *) &pfcp_sess_est_req,
							sizeof(pfcp_sess_est_req),
							MSG_DONTWAIT,
							(struct sockaddr *)&pfcp_pgwu_sockaddr_arr[i],
							sizeof(pfcp_pgwu_sockaddr_arr[i])) < 0)
					printf("Error sending: %i\n",errno);
			}

		}
	} else {
		/*see flow diagram for implementation*/

	}
	return 0;
}

#if defined(PFCP_COMM) && defined(CP_BUILD)
int
process_pfcp_sess_mod_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx )
#else
int
process_pfcp_sess_mod_request(void)
#endif
{
	pfcp_session_modification_request_t pfcp_sess_mod_req = {0};
#if defined(PFCP_COMM) && defined(CP_BUILD)

	int ret ;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pdn_connection *pdn =  NULL;
	modify_bearer_request_t mb_req = {0};
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

	uint8_t ebi_index = mb_req.bearer_context.ebi.eps_bearer_id - 5;
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
#endif
	pfcp_session_modification_response_t *pfcp_sess_mod_resp = malloc(sizeof(pfcp_session_modification_response_t));
	memset(pfcp_sess_mod_resp,0,sizeof(pfcp_session_modification_response_t));

#if defined(PFCP_COMM) && defined(CP_BUILD)
	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req,&mb_req);
	context->seid = SESS_ID(context->s11_sgw_gtpc_teid,bearer->eps_bearer_id);
	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = context->seid;
	pfcp_sess_mod_req.cp_fseid.seid = context->seid;
	pfcp_sess_mod_req.create_pdr.pdi.local_fteid.teid = bearer->s1u_enb_gtpu_teid ;
	pfcp_sess_mod_req.create_pdr.pdi.local_fteid.ipv4_address = htonl(bearer->s1u_enb_gtpu_ipv4.s_addr) ;
	pfcp_sess_mod_req.create_pdr.pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
#else
	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req);

#endif
	uint8_t pfcp_msg[size]={0};
	int encoded = encode_pfcp_session_modification_request(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if(pfcp_ctxt.flag_ava_ip == true)
	{
		for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){
			if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC) {
				// TODO :TEMP pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;
				if ( pfcp_send(pfcp_sgwc_fd_arr[i],pfcp_msg,encoded,&pfcp_sgwu_sockaddr_arr[i]) < 0 )
					printf("Error sending: %i\n",errno);
			}
#if defined (PFCP_COMM) && defined (CP_BUILD)
			set_modify_bearer_response(gtpv2c_s11_tx, mb_req.header.teid.has_teid.seq,
					context,bearer);
#endif
		}
	}
	return 0;
}

#if defined(PFCP_COMM) && defined(CP_BUILD)
int
process_pfcp_sess_del_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx)
#else
int
process_pfcp_sess_del_request(void)
#endif
{
	pfcp_session_deletion_request_t pfcp_sess_del_req = {0};
#if defined(PFCP_COMM) && defined(CP_BUILD) 
	int ret ;
	ue_context *context = NULL;
	delete_session_request_t ds_req = {0};

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
		s5s8_pgw_gtpc_del_teid = pdn->s5s8_pgw_gtpc_teid;
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
#ifndef PFCP_COMM
		return ret;
#endif
	}
	gtpv2c_s11_tx->teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;
	ret = delete_context(&ds_req, &context);
	if (ret)
		return ret;
#endif
	pfcp_session_deletion_response_t *pfcp_sess_del_resp = malloc(sizeof(pfcp_session_deletion_response_t));
	memset(pfcp_sess_del_resp,0,sizeof(pfcp_session_deletion_response_t));

	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

#if defined(PFCP_COMM) && defined(CP_BUILD)
	context->seid = SESS_ID(context->s11_sgw_gtpc_teid,ds_req.linked_ebi.eps_bearer_id);
	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = context->seid;
	if(ds_req.header.gtpc.teid_flag == 1)
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no = ds_req.header.teid.has_teid.seq;
	else
		pfcp_sess_del_req.header.seid_seqno.has_seid.seq_no = ds_req.header.teid.no_teid.seq;
#endif
	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_session_deletion_request(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if(pfcp_ctxt.flag_ava_ip == true)
	{
		for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){

			if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC ) {
				//TODO TEMP pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_ctxt.ava_ip;
				if ( pfcp_send(pfcp_sgwc_fd_arr[i],pfcp_msg,encoded,&pfcp_sgwu_sockaddr_arr[i]) < 0 )
					printf("Error sending: %i\n",errno);
			}

#if defined(PFCP_COMM) && defined(CP_BUILD)
			set_gtpv2c_teid_header(gtpv2c_s11_tx, GTP_DELETE_SESSION_RSP,
					ntohl(context->s11_mme_gtpc_teid), gtpv2c_rx->teid_u.has_teid.seq);
			set_cause_accepted_ie(gtpv2c_s11_tx, IE_INSTANCE_ZERO);

#endif
		}
	}
	return 0;
}

void
fill_pfcp_sess_set_del_resp(pfcp_session_set_deletion_response_t *pfcp_sess_set_del_resp)
{
	uint32_t seq  = 1;
	memset(pfcp_sess_set_del_resp,0,sizeof(pfcp_session_set_deletion_response_t));
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_resp->header),PFCP_SESSION_SET_DELETION_RESPONSE,
				NO_SEID, seq);
	uint32_t node_value = 0 ;
	set_node_id(&(pfcp_sess_set_del_resp->node_id),node_value);
	// TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
	set_cause(&(pfcp_sess_set_del_resp->cause), CAUSE_VALUES_REQUESTACCEPTEDSUCCESS);  
	//TODO Replace IE_NODE_ID with the  real offendID
	set_offending_ie(&(pfcp_sess_set_del_resp->offending_ie),IE_NODE_ID );

}

void
fill_pfcp_sess_del_resp(pfcp_session_deletion_response_t *
			pfcp_sess_del_resp, uint8_t cause, int offend)
{

	uint32_t seq  = 1;
	memset(pfcp_sess_del_resp,0,sizeof(pfcp_session_deletion_response_t));
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_del_resp->header),PFCP_SESSION_DELETION_RESPONSE,
				HAS_SEID, seq);
	//set cause
	set_cause(&(pfcp_sess_del_resp->cause), cause);

	// filling of offending IE
	if(cause == CAUSE_VALUES_CONDITIONALIEMISSING ||
			 cause == CAUSE_VALUES_MANDATORYIEMISSING) {
		
		set_offending_ie(&(pfcp_sess_del_resp->offending_ie), offend);
	}

	// filling of LCI
	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_del_resp->load_control_information));

	// filling of OLCI
	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_del_resp->overload_control_information));
}

void
fill_pfcp_session_modify_resp(pfcp_session_modification_response_t *
			pfcp_sess_modify_resp, uint8_t cause, int offend)
{
	uint32_t seq  = 1;
	memset(pfcp_sess_modify_resp,0,sizeof(pfcp_session_modification_response_t));
	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_modify_resp->header),PFCP_SESSION_MODIFICATION_RESPONSE,
						HAS_SEID, seq);
	//set cause
	set_cause(&(pfcp_sess_modify_resp->cause), cause);

	// filling of offending IE

	if(cause == CAUSE_VALUES_CONDITIONALIEMISSING || cause == CAUSE_VALUES_MANDATORYIEMISSING) {
		
		set_offending_ie(&(pfcp_sess_modify_resp->offending_ie), offend);
	}

	//created_bar
	// Need to do
	set_created_pdr_ie(&(pfcp_sess_modify_resp->created_pdr));

	// filling of LCI
	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
		set_lci(&(pfcp_sess_modify_resp->load_control_information));

	// filling of OLCI
	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
		set_olci(&(pfcp_sess_modify_resp->overload_control_information));

	// filling of failed rule ID
	set_failed_rule_id(&(pfcp_sess_modify_resp->failed_rule_id));

	// filling of ADURI
	// Need to do
	set_additional_usage(&(pfcp_sess_modify_resp->additional_usage_reports_information));

	// filling of CRTEP
	// Need to do
	if( pfcp_ctxt.up_supported_features & UP_PDIU )
		set_created_traffic_endpoint(&(pfcp_sess_modify_resp->createdupdated_traffic_endpoint));

}

void
fill_pfcp_session_est_resp(pfcp_session_establishment_response_t *pfcp_sess_est_resp, uint8_t cause, int offend)
{
	uint32_t seq  = 1;
	memset(pfcp_sess_est_resp,0,sizeof(pfcp_session_establishment_response_t)) ;

	//filing of pfcp header
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_est_resp->header),PFCP_SESSION_ESTABLISHMENT_RESPONSE,
			HAS_SEID, seq);
	// filling of node id
	uint32_t node_value = 0;
	set_node_id(&(pfcp_sess_est_resp->node_id),node_value);

	//set cause
	 // TODO : REmove the CAUSE_VALUES_REQUESTACCEPTEDSUCCESS in set_cause
 
	set_cause(&(pfcp_sess_est_resp->cause), cause);

	if(cause == CAUSE_VALUES_CONDITIONALIEMISSING || cause == CAUSE_VALUES_MANDATORYIEMISSING) {

		// filling of offending IE
		set_offending_ie(&(pfcp_sess_est_resp->offending_ie), offend);
	}

	// filling of UP FSEID
	uint64_t up_seid = pfcp_sess_est_resp->header.seid_seqno.has_seid.seid ;
	set_fseid(&(pfcp_sess_est_resp->up_fseid),up_seid,node_value);

	set_created_pdr_ie(&(pfcp_sess_est_resp->created_pdr));

	// filling of LCI
	if( pfcp_ctxt.cp_supported_features & CP_LOAD )
	set_lci(&(pfcp_sess_est_resp->load_control_information));

	// filling of OLCI
	if( pfcp_ctxt.cp_supported_features & CP_OVRL )
	set_olci(&(pfcp_sess_est_resp->overload_control_information));

	// filling of sgwu FQCSID
	char sgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.sgwu_pfcp_ip[0]),sgwu_addr, INET_ADDRSTRLEN);	
	unsigned long sgwu_value = inet_addr(sgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->sgwu_fqcsid),sgwu_value);

	// filling of pgwu FQCSID
	char pgwu_addr[INET_ADDRSTRLEN] ;
	inet_ntop(AF_INET, &(pfcp_config.pgwu_pfcp_ip[0]),pgwu_addr, INET_ADDRSTRLEN);	
	unsigned long pgwu_value = inet_addr(pgwu_addr);
	set_fq_csid( &(pfcp_sess_est_resp->pgwu_fqcsid),pgwu_value);

	// filling of failed rule ID
	set_failed_rule_id(&(pfcp_sess_est_resp->failed_rule_id));
}

