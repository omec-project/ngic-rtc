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

#include "gtpv2c.h"
#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "req_resp.h"
#include "gtpv2c_ie.h"
#include "pfcp_set_ie.h"
#include "gtpv2c_set_ie.h"
#include "gtpv2c_messages.h"
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
				*pfcp_sess_est_resp, uint8_t cause, int offend);
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_sess_set_del_resp);

void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t
			*pfcp_sess_del_resp, uint8_t cause, int offend);

void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t
			*pfcp_sess_modify_resp, uint8_t cause, int offend);
#ifdef CP_BUILD
void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		create_session_request_t *csr, ue_context *context, eps_bearer *bearer,
		pdn_connection *pdn);

void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header *header, ue_context *context, eps_bearer *bearer,
		pdn_connection *pdn);
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
