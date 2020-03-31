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

#ifndef PFCP_UP_SESS_H
#define PFCP_UP_SESS_H

#include "pfcp_messages.h"

int8_t
process_up_assoc_req(pfcp_assn_setup_req_t *ass_setup_req, 
			pfcp_assn_setup_rsp_t *ass_setup_resp);
int8_t
process_up_session_estab_req(pfcp_sess_estab_req_t *sess_req, 
			pfcp_sess_estab_rsp_t *sess_resp);

int8_t
process_up_session_modification_req(pfcp_sess_mod_req_t *sess_mod_req, 
			pfcp_sess_mod_rsp_t *sess_mod_rsp);

int8_t
process_up_session_deletion_req(pfcp_sess_del_req_t *sess_del_req,
			pfcp_sess_del_rsp_t *sess_del_rsp);

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
#endif /* PFCP_UP_SESS_H */
