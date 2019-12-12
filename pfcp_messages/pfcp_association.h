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

#ifndef PFCP_ASSOC_H
#define PFCP_ASSOC_H

#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "sm_struct.h"
#endif /* CP_BUILD */

/**
 * @brief  : This is a function to fill pfcp association update response
 * @param  : pfcp_asso_update_resp is pointer to structure of pfcp association update response
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_update_resp(pfcp_assn_upd_rsp_t *pfcp_asso_update_resp);

/**
 * @brief  : This is a function to fill pfcp association setup request
 * @param  : pfcp_asso_setup_req is pointer to structure of pfcp association setup request
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_setup_req(pfcp_assn_setup_req_t *pfcp_ass_setup_req);

/**
 * @brief  : This is a function to fill pfcp association update request
 * @param  : pfcp_asso_update_req is pointer to structure of pfcp association update request
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_update_req(pfcp_assn_upd_req_t *pfcp_ass_update_req);

/**
 * @brief  : This is a function to fill pfcp association setup response
 * @param  : pfcp_asso_setup_resp is pointer to structure of pfcp association setup response
 * @param  : caues describes the whether request is accepted or not
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_setup_resp(pfcp_assn_setup_rsp_t *pfcp_ass_setup_resp, uint8_t cause);

/**
 * @brief  : This is a function to fill pfcp association release request
 * @param  : pfcp_asso_rel_req is pointer to structure of pfcp association release request
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_release_req(pfcp_assn_rel_req_t *pfcp_ass_rel_req);

/**
 * @brief  : This is a function to fill pfcp association release response
 * @param  : pfcp_asso_rel_resp is pointer to structure of pfcp association release response
 * @return : This function dose not return anything
 */
void
fill_pfcp_association_release_resp(pfcp_assn_rel_rsp_t *pfcp_ass_rel_resp);

/**
 * @brief  : This is a function to fill pfcp node report request
 * @param  : pfcp_node_rep_req is pointer to structure of pfcp node report request
 * @return : This function dose not return anything
 */
void
fill_pfcp_node_report_req(pfcp_node_rpt_req_t *pfcp_node_rep_req);

/**
 * @brief  : This is a function to fill pfcp node report response
 * @param  : pfcp_node_rep_resp is pointer to structure of pfcp node report response
 * @return : This function dose not return anything
 */
void
fill_pfcp_node_report_resp(pfcp_node_rpt_rsp_t *pfcp_node_rep_resp);

/**
 * @brief  : This is a function to fill pfcp heartbeat response
 * @param  : pfcp_heartbeat_resp is pointer to structure of pfcp heartbeat response
 * @return : This function dose not return anything
 */
void
fill_pfcp_heartbeat_resp(pfcp_hrtbeat_rsp_t *pfcp_heartbeat_resp);

/**
 * @brief  : This is a function to fill pfcp pfd management response
 * @param  : pfd_resp is pointer to structure of pfcp pfd management response
 * @param  : cause_id describes cause if requested or not
 * @param  : offending_ie describes IE due which request got rejected if any
 * @return : This function dose not return anything
 */
void
fill_pfcp_pfd_mgmt_resp(pfcp_pfd_mgmt_rsp_t *pfd_resp, uint8_t cause_id, int offending_ie);

/**
 * @brief  : This is a function to fill pfcp heartbeat request
 * @param  : pfcp_heartbeat_req is pointer to structure of pfcp heartbeat request
 * @param  : seq indicates the sequence number
 * @return : This function dose not return anything
 */
void
fill_pfcp_heartbeat_req(pfcp_hrtbeat_req_t *pfcp_heartbeat_req, uint32_t seq);

/**
 * @brief  : This is a function to fill pfcp session report request
 * @param  : pfcp_sess_req_resp is pointer to structure of pfcp session report request
 * @param  : seq indicates the sequence number
 * @return : This function dose not return anything
 */
void
fill_pfcp_sess_report_resp(pfcp_sess_rpt_rsp_t *pfcp_sess_rep_resp, uint32_t seq);

#ifdef CP_BUILD
/**
 * @brief  : This function processes pfcp associatiuon response
 * @param  : msg hold the data from pfcp associatiuon response
 * @param  : peer_addr denotes address of peer node
 * @return : Returns 0 in case of success else negative value
 */
uint8_t
process_pfcp_ass_resp(msg_info *msg, struct sockaddr_in *peer_addr);

/**
 * @brief  : This function adds csr to list of buffrered csrs
 * @param  : context hold information about ue context
 * @param  : upf_context hold information about upf context
 * @param  : ebi indicates eps bearer id
 * @return : Returns 0 in case of success else negative value
 */
int
buffer_csr_request(ue_context *context,
		upf_context_t *upf_context, uint8_t ebi);

/**
 * @brief  : This function processes incoming create session request
 * @param  : teid
 * @param  : eps_bearer_id indicates eps bearer id
 * @return : Returns 0 in case of success else negative value
 */
int
process_create_sess_request(uint32_t teid, uint8_t eps_bearer_id);

#endif /* CP_BUILD */
#endif /* PFCP_ASSOC_H */
