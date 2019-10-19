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

void
fill_pfcp_association_update_resp(pfcp_assn_upd_rsp_t *pfcp_asso_update_resp);

void
fill_pfcp_association_setup_req(pfcp_assn_setup_req_t *pfcp_ass_setup_req);

void
fill_pfcp_association_update_req(pfcp_assn_upd_req_t *pfcp_ass_update_req);

void
fill_pfcp_association_setup_resp(pfcp_assn_setup_rsp_t *pfcp_ass_setup_resp, uint8_t cause);

void
fill_pfcp_association_release_req(pfcp_assn_rel_req_t *pfcp_ass_rel_req);

void
fill_pfcp_association_release_resp(pfcp_assn_rel_rsp_t *pfcp_ass_rel_resp);

void
fill_pfcp_node_report_req(pfcp_node_rpt_req_t *pfcp_node_rep_req);

void
fill_pfcp_node_report_resp(pfcp_node_rpt_rsp_t *pfcp_node_rep_resp);

void
fill_pfcp_heartbeat_resp(pfcp_hrtbeat_rsp_t *pfcp_heartbeat_resp);

void
fill_pfcp_pfd_mgmt_resp(pfcp_pfd_mgmt_rsp_t *pfd_resp, uint8_t cause_id, int offending_ie);

void
fill_pfcp_heartbeat_req(pfcp_hrtbeat_req_t *pfcp_heartbeat_req, uint32_t seq);

void
fill_pfcp_sess_report_resp(pfcp_sess_rpt_rsp_t *pfcp_sess_rep_resp, uint32_t seq);

#ifdef CP_BUILD
uint8_t
process_pfcp_ass_resp(msg_info *msg, struct sockaddr_in *peer_addr);

int
buffer_csr_request(ue_context *context,
		upf_context_t *upf_context, uint8_t ebi);

int
process_create_sess_request(uint32_t teid, uint8_t eps_bearer_id);

#endif /* CP_BUILD */
#endif /* PFCP_ASSOC_H */
