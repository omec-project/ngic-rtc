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

#ifndef PFCP_SESSION_H
#define PFCP_SESSION_H

#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "gtpv2c.h"
#include "sm_struct.h"
#include "gtpv2c_ie.h"
#include "pfcp_set_ie.h"
#include "gtpv2c_set_ie.h"
#include "gtp_messages.h"
#endif

#define NUM_UE 10000
#define NUM_DP 100

typedef struct association_context{
	uint8_t       rx_buf[NUM_DP][NUM_UE];
	char sgwu_fqdn[NUM_DP][MAX_HOSTNAME_LENGTH];
	uint32_t      upf_ip;
	uint32_t      csr_cnt;
}association_context_t;

extern association_context_t assoc_ctxt[NUM_DP] ;

void
stats_update(uint8_t msg_type);

void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t
				*pfcp_sess_est_resp, uint8_t cause, int offend,
				struct in_addr dp_comm_ip,
				struct pfcp_sess_estab_req_t *pfcp_session_request);
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_sess_set_del_resp);

void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t
			*pfcp_sess_del_resp, uint8_t cause, int offend);

void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend);
#ifdef CP_BUILD
void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		ue_context *context, uint8_t ebi_index, uint32_t seq);

int
check_interface_type(uint8_t iface);

void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer *bearer,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[],  uint8_t handover_flag);

void
fill_pfcp_sess_mod_req_delete( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, ue_context *context, pdn_connection *pdn);

uint8_t
process_pfcp_sess_est_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		uint64_t dp_sess_id);

uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

uint8_t
process_pfcp_sess_mod_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

int
fill_pdr_entry(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t iface, uint8_t itr);

int
fill_qer_entry(pdn_connection *pdn, eps_bearer *bearer,uint8_t itr);

uint8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen);

void
fill_pgwc_create_session_response(create_sess_rsp_t *cs_resp,
				uint32_t sequence, struct ue_context_t *context, uint8_t ebi_index);
int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp);

int
process_sgwc_s5s8_delete_session_response(del_sess_rsp_t *ds_rsp, uint8_t *gtpv2c_tx);

int
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_rsp);

int
process_pgwc_s5s8_delete_session_request(del_sess_req_t *ds_req);

int
del_rule_entries(ue_context *context, uint8_t ebi_index);

void
sdf_pkt_filter_to_string(sdf_pkt_fltr *sdf_flow, char *sdf_str,uint8_t direction);

void sdf_pkt_filter_add(pfcp_sess_estab_req_t* pfcp_sess_est_req,eps_bearer* bearer,int pdr_counter,
int sdf_filter_count,int dynamic_filter_cnt,int flow_cnt,uint8_t direction);

void
sdf_pkt_filter_mod(pfcp_sess_mod_req_t* pfcp_sess_mod_req,
		eps_bearer* bearer,int pdr_counter,
		int sdf_filter_count, int dynamic_filter_cnt, int flow_cnt,
		uint8_t direction);

int
fill_sdf_rules(pfcp_sess_estab_req_t *pfcp_sess_est_req,
		eps_bearer *bearer, int pdr_counter);

int
fill_sdf_rules_modification(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		eps_bearer *bearer, int pdr_counter);

void
fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		eps_bearer *bearer);

int
fill_dedicated_bearer_info(eps_bearer *bearer, ue_context *context, pdn_connection *pdn);

void fill_gate_status(pfcp_sess_estab_req_t *pfcp_sess_est_req,int qer_counter,enum flow_status f_status);

#else
void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req);

void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req);
#endif /* CP_BUILD */

void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req);
void
fill_pfcp_sess_set_del_req( pfcp_sess_set_del_req_t *pfcp_sess_set_del_req);
#endif /* PFCP_SESSION_H */
