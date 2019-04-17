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
#include "../cp/gtpv2c.h"

#if defined(PFCP_COMM) && defined(CP_BUILD)
#include "../cp/gtpv2c_ie.h"
#include "../cp/gtpv2c_set_ie.h"
#include "gtpv2c_messages.h"
#include "req_resp.h"
#endif

#define NUM_UE 10000
#define NUM_DP 100
typedef struct association_context{
	//gtpv2c_header s11_rx_buf[NUM_UE];
	uint8_t       s11_rx_buf[NUM_UE][1000];
	uint32_t      upf_ip;
	uint32_t      csr_cnt;
}association_context_t;

extern association_context_t assoc_ctxt[NUM_DP] ;

void 
stats_update(uint8_t msg_type);

void
pfcp_gtpv2c_send(uint16_t gtpv2c_pyld_len, uint8_t *tx_buf,gtpv2c_header *gtpv2c_s11_rx);

void
fill_pfcp_session_est_resp(pfcp_session_establishment_response_t 
				*pfcp_sess_est_resp, uint8_t cause, int offend);
void
fill_pfcp_sess_set_del_resp(pfcp_session_set_deletion_response_t *pfcp_sess_set_del_resp);

void
fill_pfcp_sess_del_resp(pfcp_session_deletion_response_t 
			*pfcp_sess_del_resp, uint8_t cause, int offend);

void
fill_pfcp_session_modify_resp(pfcp_session_modification_response_t 
			*pfcp_sess_modify_resp, uint8_t cause, int offend);
#if defined(PFCP_COMM) && defined(CP_BUILD)
void
fill_pfcp_sess_est_req( pfcp_session_establishment_request_t *pfcp_sess_est_req,create_session_request_t *csr);
void
fill_pfcp_sess_mod_req( pfcp_session_modification_request_t *pfcp_sess_mod_req,modify_bearer_request_t *mbr);
#else
void
fill_pfcp_sess_est_req( pfcp_session_establishment_request_t *pfcp_sess_est_req);
void
fill_pfcp_sess_mod_req( pfcp_session_modification_request_t *pfcp_sess_mod_req);
#endif //PFCP_COMM
void
fill_pfcp_sess_del_req( pfcp_session_deletion_request_t *pfcp_sess_del_req);
void
fill_pfcp_sess_set_del_req( pfcp_session_set_deletion_request_t *pfcp_sess_set_del_req);
#endif /* PFCP_SESSION_H */
