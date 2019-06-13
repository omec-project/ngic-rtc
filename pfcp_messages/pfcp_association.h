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
#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4
#endif

void
fill_pfcp_association_update_resp(pfcp_association_update_response_t *pfcp_asso_update_resp);
void
fill_pfcp_association_setup_req(pfcp_association_setup_request_t *pfcp_ass_setup_req);
void
fill_pfcp_association_update_req(pfcp_association_update_request_t *pfcp_ass_update_req);
void
fill_pfcp_association_setup_resp(pfcp_association_setup_response_t *pfcp_ass_setup_resp, uint8_t cause);
void
fill_pfcp_association_release_req(pfcp_association_release_request_t *pfcp_ass_rel_req);
void
fill_pfcp_association_release_resp(pfcp_association_release_response_t *pfcp_ass_rel_resp);
void
fill_pfcp_node_report_req(pfcp_node_report_request_t *pfcp_node_rep_req);
void
fill_pfcp_node_report_resp(pfcp_node_report_response_t *pfcp_node_rep_resp);
void
fill_pfcp_heartbeat_resp(pfcp_heartbeat_response_t *pfcp_heartbeat_resp);
void
fill_pfcp_heartbeat_req(pfcp_heartbeat_request_t *pfcp_heartbeat_req, uint32_t seq);


#endif /* PFCP_ASSOC_H */
