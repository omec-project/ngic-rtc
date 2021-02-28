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
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "cp_config.h"
#include "ipc_api.h"
#endif /* CP_BUILD */

#ifndef GTPC_SESSION_H
#define GTPC_SESSION_H

#define GTP_MSG_LEN		2048
/**
 * @brief  : Maintains seid, bearer id, sgw teid , pgw ip for cp
 */
struct gw_info {
	uint8_t eps_bearer_id;
	uint32_t s5s8_sgw_gtpc_teid;
	uint32_t s5s8_pgw_gtpc_ipv4;
	uint64_t seid;
};

enum modify_bearer_procedure {
	INITIAL_PDN_ATTACH = 01,
	UPDATE_PDN_CONNECTION,
	FORWARD_MBR_REQUEST,
	NO_UPDATE_MBR,
};

#ifdef CP_BUILD
/**
 * @brief  : deletes ue context information
 * @param  : ds_req, holds info from delete sess request
 * @param  : context, context to be deleted
 * @param  : s5s8_pgw_gtpc_teid, pgwc teid
 * @param  : s5s8_pgw_gtpc_ip, pgwc ip
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
delete_context(gtp_eps_bearer_id_ie_t lbi, uint32_t teid,
	ue_context **_context, pdn_connection **pdn);

/**
 * @brief  : Fill Create Sess Request
 * @param  : cs_req, request structure to be filled
 * @param  : context, ue context info
 * @param  : ebi_index, index of bearer in bearer array
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_cs_request(create_sess_req_t *cs_req, struct ue_context_t *context,
		int ebi_index );

/**
 * @brief  : Process create session response received on s5s8 interface in sgwc
 * @param  : cs_rsp, holds info received in response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp);

/**
 * @brief  : Fill delete session request
 * @param  : ds_req, request structure to be filled
 * @param  : context, ue context info
 * @param  : ebi_index, index of bearer in bearer array
 * @return : Returns nothing
 */
void
fill_ds_request(del_sess_req_t *ds_req, struct ue_context_t *context,
		 int ebi_index , uint32_t teid);
/**
 * @brief  : Fill delete session response on pgwc
 * @param  : ds_resp, response structure to be filled
 * @param  : sequence, sequence number
 * @param  : has_teid, teid info
 * @return : Returns nothing
 */
void
fill_del_sess_rsp(del_sess_rsp_t *ds_resp, uint32_t sequence, uint32_t has_teid);

/**
 * @brief  : Set values in create bearer request
 * @param  : gtpv2c_tx, transmission buffer to contain 'create bearer request' message
 * @param  : sequence, sequence number as described by clause 7.6 3gpp 29.274
 * @param  : pdn, pdn data structure pertaining to the bearer to be created
 * @param  : bearer, EPS Bearer data structure to be created
 * @param  : lbi, 'Linked Bearer Identifier': indicates the default bearer identifier
 *           associated to the PDN connection to which the dedicated bearer is to be
 *           created
 * @param  : pti, 'Procedure Transaction Identifier' according to clause 8.35 3gpp 29.274,
 *           as specified by table 7.2.3-1 3gpp 29.274, 'shall be the same as the one
 *           used in the corresponding bearer resource command'
 * @param  : resp
 * @param  : piggybacked flag
 * @param  : req_for_mme, flag to identify if req is being created for mme or not
 * @return : Returns 0 on sucess
 */
int
set_create_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	pdn_connection *pdn, uint8_t lbi, uint8_t pti, struct resp_info *resp, uint8_t piggybacked, bool req_for_mme);

/**
 * @brief  : Set values in create bearer response
 * @param  : gtpv2c_tx, transmission buffer to contain 'create bearer response' message
 * @param  : sequence, sequence number as described by clause 7.6 3gpp 29.274
 * @param  : pdn, pdn data structure pertaining to the bearer to be created
 * @param  : bearer, EPS Bearer data structure to be created
 * @param  : lbi, 'Linked Bearer Identifier': indicates the default bearer identifier
 *           associated to the PDN connection to which the dedicated bearer is to be
 *           created
 * @param  : pti, 'Procedure Transaction Identifier' according to clause 8.35 3gpp 29.274,
 *           as specified by table 7.2.3-1 3gpp 29.274, 'shall be the same as the one
 *           used in the corresponding bearer resource command'
 * @param  : resp
 * @return : Returns nothing
 */
int
set_create_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
		pdn_connection *pdn, uint8_t lbi, uint8_t pti, struct resp_info *resp);

/**
 * @brief  : Handles the processing at sgwc after receiving delete
 *           session request messages
 * @param  : ds_resp, holds info from response
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_delete_session_response(del_sess_rsp_t *ds_resp);

/**
 * @brief  : Proccesses create bearer response on sgwc
 * @param  : cb_rsp, holds data from response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_create_bearer_response(create_bearer_rsp_t *cb_rsp);

/**
 * @brief  : Proccesses update bearer request
 * @param  : ubr, holds data from request
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_update_bearer_request(upd_bearer_req_t *ubr);

/**
 * @brief  : Proccesses update bearer response received on s11 interface
 * @param  : ub_rsp, holds data from response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_s11_upd_bearer_response(upd_bearer_rsp_t *ub_rsp, ue_context *context);

/**
 * @brief  : Proccesses update bearer response received on s5s8 interface
 * @param  : ub_rsp, holds data from response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_s5s8_upd_bearer_response(upd_bearer_rsp_t *ub_rsp, ue_context *context);

/**
 * @brief  : Process CSR request for Context Replacement.
 * @param  : csr, Received CSR request.
 * @param  : cp_mode
 * @param  : apn_requested : Requested APN in CSR
 * @return : Returns 0 on success, -1 otherwise
 */
int
gtpc_context_replace_check(create_sess_req_t *csr, uint8_t cp_mode, apn *apn_requested);

/**
 * @brief  : Check MBRequest and decide the process for that MBR.
 * @param  : ue context
 * @return : Returns 0 on failure, and interger corresponing to a process.
 */
uint8_t
check_mbr_procedure(ue_context *context);

/**
 * @brief  : This Handler is used when SGWC receives the MBR request
 * @param  : pfcp_sess_mod_response, gtpv2c header, pdn, resp strcut,
 *           eps bearer, mbr procedure flag
 * @return : Returns 0 on failure, and interger corresponing to a process.
 */
int
process_pfcp_sess_mod_resp_mbr_req(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp,
		         gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn,
				 struct resp_info *resp, eps_bearer *bearer, uint8_t *mbr_procedure);

/**
 * @brief  : This Handler is used after Receiving Sess MODIFICATION RESPONSE
 *           when PGWC will receive Update PDN Connection Req.
 * @param  : UPDATE PDN CONNEC. SET REQ
 * @return : Returns 0 on failure, and interger corresponing to a process.
 */
int
proc_pfcp_sess_mbr_udp_csid_req(upd_pdn_conn_set_req_t *upd_req);


/**
 * @brief  : Check for difference in ULI IE received and context
 * @param  : ULI IE, ue context
 * @return : Returns 0 on failure, and interger corresponing to a process.
 */
void
check_for_uli_changes(gtp_user_loc_info_ie_t *uli, ue_context *context);

/**
 * @brief  : Generate CCR-U request and send to PCRF.
 * @param  : ue context, eps_bearer
 * @return : Returns 0 on failure, and interger corresponing to a process.
 */
int
gen_ccru_request(ue_context *context, eps_bearer *bearer, bearer_rsrc_cmd_t *bearer_rsrc_cmd);

/**
 * @brief  : Delete session context in case of context replacement.
 * @param  : context, UE context information.
 * @param  : pdn, pdn information
 * @return : Returns nothing.
 */
void
delete_sess_context(ue_context *context, pdn_connection *pdn);

/**
 * @brief  : Delete rules in bearer context.
 * @param  : bearer, Bearer context.
 * @return : Returns 0 on success, -1 otherwise
 */
int delete_rule_in_bearer(eps_bearer *bearer);

/**
 * @brief  : Delete Bearer Context associate with EBI.
 * @param  : pdn, pdn information.
 * @param  : ebi_index, Bearer index.
 * @return : Returns 0 on success, -1 otherwise
 */
int
delete_bearer_context(pdn_connection *pdn, int ebi_index );

#endif /*CP_BUILD*/
#endif
