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

/**
 * @brief  : Maintains seid, bearer id, sgw teid , pgw ip for cp
 */
struct gw_info {
	uint8_t eps_bearer_id;
	uint32_t s5s8_sgw_gtpc_teid;
	uint32_t s5s8_pgw_gtpc_ipv4;
	uint64_t seid;
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
	ue_context **_context, uint32_t *s5s8_pgw_gtpc_teid,
	uint32_t *s5s8_pgw_gtpc_ipv4);

/**
 * @brief  : Fill Create Sess Request
 * @param  : cs_req, request structure to be filled
 * @param  : context, ue context info
 * @param  : ebi_index, index of bearer in bearer array
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_cs_request(create_sess_req_t *cs_req, struct ue_context_t *context,
		uint8_t ebi_index);

/**
 * @brief  : Process create session response received on s5s8 interface in sgwc
 * @param  : cs_rsp, holds info received in response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp);

/**
 * @brief  : Fill create session response on pgwc
 * @param  : cs_resp, response structure to be filled
 * @param  : sequence, sequence number
 * @param  : context, ue context info
 * @param  : ebi_index, index of bearer in bearer array
 * @return : Returns nothing
 */
void
fill_pgwc_create_session_response(create_sess_rsp_t *cs_resp,
		uint32_t sequence, struct ue_context_t *context, uint8_t ebi_index);
/**
 * @brief  : Fill delete session request
 * @param  : ds_req, request structure to be filled
 * @param  : context, ue context info
 * @param  : ebi_index, index of bearer in bearer array
 * @return : Returns nothing
 */
void
fill_ds_request(del_sess_req_t *ds_req, struct ue_context_t *context,
		 uint8_t ebi_index);
/**
 * @brief  : Fill delete session response on pgwc
 * @param  : ds_resp, response structure to be filled
 * @param  : sequence, sequence number
 * @param  : has_teid, teid info
 * @return : Returns nothing
 */
void
fill_pgwc_ds_sess_rsp(del_sess_rsp_t *ds_resp, uint32_t sequence, uint32_t has_teid);

/**
 * @brief  : Process delete session request received on s5s8 interface , on pgwc
 * @param  : ds_req, holds info from request
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pgwc_s5s8_delete_session_request(del_sess_req_t *ds_req);

/**
 * @brief  : Process delete session response received on s5s8 interface , on sgwc
 * @param  : dsr, holds info from response
 * @param  : gtpv2c_tx, structure to be filled to send delete session response to mme
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_delete_session_response(del_sess_rsp_t *dsr, uint8_t *gtpv2c_tx);

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
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_resp);

/**
 * @brief  : Delete ue context on sgwc
 * @param  : gtpv2c_teid, teid
 * @param  : context, ue context to be deleted
 * @param  : seid, seid
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
delete_sgwc_context(uint32_t gtpv2c_teid, ue_context **_context, uint64_t *seid);

/**
 * @brief  : Proccesses create bearer response on pgwc
 * @param  : cb_rsp, holds data from response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp);

/**
 * @brief  : Proccesses create bearer response on sgwc
 * @param  : cb_rsp, holds data from response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp);

int
process_update_bearer_request(upd_bearer_req_t *ubr);

int
process_s11_upd_bearer_response(upd_bearer_rsp_t *ub_rsp);

int
process_s5s8_upd_bearer_response(upd_bearer_rsp_t *ub_rsp);

#endif /*CP_BUILD*/
#endif
