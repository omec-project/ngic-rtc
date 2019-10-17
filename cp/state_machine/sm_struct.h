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

#ifndef SM_STRUCT_H
#define SM_STRUCT_H

#include "stdio.h"
#include "sm_enum.h"
#include "sm_hand.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages.h"
#include "gtpv2c_messages.h"


struct rte_hash *sm_hash;
extern char state_name[40];
extern char event_name[40];

enum source_interface {
	GX_IFACE = 1,
	S11_IFACE = 2,
	S5S8_IFACE = 3,
	PFCP_IFACE = 4,
};

//extern enum source_interface iface;

/* TODO: Need to optimized generic structure. */
typedef struct msg_info{
	uint8_t msg_type;
	uint8_t state;
	uint8_t event;

	char sgwu_fqdn[MAX_HOSTNAME_LENGTH];
	struct in_addr upf_ipv4;

	//enum source_interface iface;

	union s11_msg_info_t {
		create_session_request_t csr;
		modify_bearer_request_t mbr;
		delete_session_request_t dsr;
		rel_acc_ber_req rel_acc_ber_req_t;
		downlink_data_notification_t ddn_ack;
	}s11_msg;

	/*Remove gtpv2c header from here after support libgtpv2 on s5s8 interface */
	union s5s8_msg_info_t {
		gtpv2c_header gtpv2c_rx;
	}s5s8_msg;

	union pfcp_msg_info_t {
		pfcp_assn_setup_rsp_t pfcp_ass_resp;
		pfcp_sess_estab_rsp_t pfcp_sess_est_resp;
		pfcp_sess_mod_rsp_t pfcp_sess_mod_resp;
		pfcp_sess_del_rsp_t pfcp_sess_del_resp;
		pfcp_sess_rpt_req_t pfcp_sess_rep_req;
	}pfcp_msg;

}msg_info;

/*
 * Structure for handling CS/MB/DS request synchoronusly.
 * */
struct resp_info {
	uint8_t state;
	uint8_t msg_type;
	uint8_t eps_bearer_id;
	uint32_t sequence;
	uint32_t s11_sgw_gtpc_teid;
	uint32_t s11_mme_gtpc_teid;
	uint32_t s5s8_pgw_gtpc_teid;
	uint32_t s5s8_sgw_gtpc_del_teid_ptr;
	uint32_t s5s8_pgw_gtpc_ipv4;
	struct in_addr s11_mme_gtpc_ipv4;
	struct ue_context_t *context;

	/* TODO: Need to remove */
	union s11_msg_info {
		create_session_request_t csr;
		modify_bearer_request_t mbr;
		delete_session_request_t dsr;
	}s11_msg;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));


/* Declaration of state machine 2D array */
typedef int (*const EventHandler[END_STATE+1][END_EVNT+1])(void *t1, void *t2);

/* Create a session hash table to maintain the session information.*/
void
init_sm_hash(void);

/**
 * Add session entry in session table.
 */
uint8_t
add_sess_entry(uint64_t sess_id, struct resp_info *resp);

/**
 * Retrive session entry from session table.
 */
uint8_t
get_sess_entry(uint64_t sess_id, struct resp_info **resp);

/**
 * Retrive session state from session table.
 */
uint8_t
get_sess_state(uint64_t sess_id);

/**
 * Update session state in session table.
 */
uint8_t
update_sess_state(uint64_t sess_id, uint8_t state);

/**
 * Delete session entry from session table.
 */
uint8_t
del_sess_entry(uint64_t sess_id);

/**
 * Update UE state in UE Context.
 */
uint8_t
update_ue_state(uint32_t teid_key, uint8_t state);

/**
 * Retrive UE state from UE Context.
 */
uint8_t
get_ue_state(uint32_t teid_key);

/**
 * Get "last" param for cli
 */
void 
get_current_time(char *last_time_stamp);

/**
 * Get state name from enum
 */
const char * get_state_string(int value);

/**
 * Get event name from enum
 */
const char * get_event_string(int value);

#endif
