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

#ifndef SM_ENUM_H
#define SM_ENUM_H

#include <stdio.h>
#include <stdint.h>

/* VS: Defined different states of the STATE Machine */
typedef enum {
	NONE_STATE,
	ASSOC_REQ_SNT_STATE,
	ASSOC_RESP_RCVD_STATE,
	SESS_EST_REQ_SNT_STATE,
	SESS_EST_RESP_RCVD_STATE,
	CONNECTED_STATE,
	IDEL_STATE,
	CS_REQ_SNT_STATE,
	CS_RESP_RCVD_STATE,
	SESS_MOD_REQ_SNT_STATE,
	SESS_MOD_RESP_RCVD_STATE,
	SESS_DEL_REQ_SNT_STATE,
	SESS_DEL_RESP_RCVD_STATE,
	DS_REQ_SNT_STATE,
	DS_RESP_RCVD_STATE,
	DDN_REQ_SNT_STATE,
	DDN_ACK_RCVD_STATE,
	END_STATE

}sm_state;

/* VS: Register different types of events */
typedef enum {
	NONE_EVNT,
	CS_REQ_RCVD_EVNT,
	PFCP_ASSOC_SETUP_SNT_EVNT,
	PFCP_ASSOC_SETUP_RESP_RCVD_EVNT,
	PFCP_SESS_EST_REQ_RCVD_EVNT,
	PFCP_SESS_EST_RESP_RCVD_EVNT,
	CS_RESP_RCVD_EVNT,
	MB_REQ_RCVD_EVNT,
	PFCP_SESS_MOD_REQ_RCVD_EVNT,
	PFCP_SESS_MOD_RESP_RCVD_EVNT,
	MB_RESP_RCVD_EVNT,
	REL_ACC_BER_REQ_RCVD_EVNT,
	DS_REQ_RCVD_EVNT,
	PFCP_SESS_DEL_REQ_RCVD_EVNT,
	PFCP_SESS_DEL_RESP_RCVD_EVNT,
	DS_RESP_RCVD_EVNT,
	ECHO_REQ_RCVD_EVNT,
	ECHO_RESP_RCVD_EVNT,
	DDN_ACK_RESP_RCVD_EVNT,
	PFCP_SESS_RPT_REQ_RCVD_EVNT,
	END_EVNT

}sm_event;


#endif
