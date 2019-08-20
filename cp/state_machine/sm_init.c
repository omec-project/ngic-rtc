
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

#include <stdio.h>
#include <rte_hash_crc.h>

#include "ue.h"
#include "sm_struct.h"

#ifdef C3PO_OSS
#include "cp_config.h"
#endif /* C3PO_OSS */
#define SM_HASH_SIZE (1 << 18)

/**
 * Add session entry in state machine hash table.
 *
 * @param sess_id
 *	key.
 * @param resp_info Resp
 *	return 0 or 1.
 *
 */

char state_name[40];
char event_name[40];

uint8_t
add_sess_entry(uint64_t sess_id, struct resp_info *resp)
{
	int ret;
	struct resp_info *tmp = NULL;
	/* Lookup for session entry. */
	ret = rte_hash_lookup_data(sm_hash,
				&sess_id, (void **)&tmp);

	if ( ret < 0) {
		/* No session entry for sess_id
		 * Add session entry for sess_id at sm_hash.
		 */

		tmp = rte_malloc_socket(NULL,
						sizeof(struct resp_info),
						RTE_CACHE_LINE_SIZE, rte_socket_id());

		/* Assign the resp entry to tmp */
		memcpy(tmp, resp, sizeof(struct resp_info));

		/* Session Entry not present. Add session Entry */
		ret = rte_hash_add_key_data(sm_hash,
						&sess_id, resp);
		if (ret) {
			fprintf(stderr, "%s: Failed to add entry = %lu"
					"\n\tError= %s\n",
					__func__, sess_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, resp, sizeof(struct resp_info));
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Sess Entry add for Msg_Type:%u, Sess ID:%lu, State:%s\n",
			__func__, tmp->msg_type, sess_id, get_state_string(tmp->state));
	return 0;
}

uint8_t
get_sess_entry(uint64_t sess_id, struct resp_info **resp)
{
	int ret = 0;
	ret = rte_hash_lookup_data(sm_hash,
				&sess_id, (void **)resp);

	if ( ret < 0) {
		fprintf(stderr, "Entry not found for sess_id:%lu...\n", sess_id);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Msg_type:%u, Sess ID:%lu, State:%s\n",
			__func__, (*resp)->msg_type, sess_id, get_state_string((*resp)->state));
	return 0;

}

uint8_t
get_sess_state(uint64_t sess_id)
{
	int ret = 0;
	struct resp_info *resp = NULL;
	ret = rte_hash_lookup_data(sm_hash,
				&sess_id, (void **)&resp);

	if ( ret < 0) {
		fprintf(stderr, "%s:Entry not found for sess_id:%lu...\n", __func__,
				sess_id);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Msg_Type:%u, Sess ID:%lu, State:%s\n",
			__func__, resp->msg_type, sess_id, get_state_string(resp->state));

	return resp->state;

}

uint8_t
update_sess_state(uint64_t sess_id, uint8_t state)
{
	int ret = 0;
	struct resp_info *resp = NULL;
	ret = rte_hash_lookup_data(sm_hash,
				&sess_id, (void **)&resp);

	if ( ret < 0) {
		fprintf(stderr, "%s:Entry not found for sess_id:%lu...\n", __func__,
				sess_id);
		return -1;
	}

	resp->state = state;

	clLog(clSystemLog, eCLSeverityDebug, "%s: Msg_Type:%u, Sess ID:%lu, State:%s\n",
			__func__, resp->msg_type, sess_id, get_state_string(resp->state));

	return 0;

}

uint8_t
del_sess_entry(uint64_t sess_id)
{
	int ret = 0;
	struct resp_info *resp = NULL;

	/* Check Session Entry is present or Not */
	ret = rte_hash_lookup_data(sm_hash,
					&sess_id, (void **)&resp);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sm_hash, &sess_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:Entry not found for sess_id:%lu...\n",
						__func__, sess_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(resp);

	clLog(clSystemLog, eCLSeverityDebug, "%s: Sess ID:%lu\n",
			__func__, sess_id);

	return 0;
}

uint8_t
update_ue_state(uint32_t teid_key, uint8_t state)
{
	int ret = 0;
	ue_context *context = NULL;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				&teid_key, (void **)&context);

	if ( ret < 0) {
		fprintf(stderr, "%s:Failed to update UE State for Teid:%x...\n", __func__,
				teid_key);
		return -1;
	}
	context->state = state;

	clLog(clSystemLog, eCLSeverityDebug, "%s: Change UE State for Teid:%u, State:%s\n",
			__func__, teid_key, get_state_string(context->state));
	return 0;

}

uint8_t
get_ue_state(uint32_t teid_key)
{
	int ret = 0;
	ue_context *context = NULL;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				&teid_key, (void **)&context);

	if ( ret < 0) {
		fprintf(stderr, "Entry not found for teid:%x...\n", teid_key);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Teid:%u, State:%s\n",
			__func__, teid_key, get_state_string(context->state));
	return context->state;
}

/**
 * @brief Initializes the hash table used to account for CS/MB/DS req and resp handle sync.
 */
void
init_sm_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "state_machine_hash",
	    .entries = SM_HASH_SIZE,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_hash_crc,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	sm_hash = rte_hash_create(&rte_hash_params);
	if (!sm_hash) {
		rte_panic("%s hash create failed: %s (%u)\n",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

/**
 *@brief Used to update "last" param in cli
 */
void 
get_current_time(char *last_time_stamp)
{
	struct tm * last_timer;
	time_t rawtime;
	time (&rawtime);
	last_timer = localtime (&rawtime);
	strftime (last_time_stamp,80,"%FT%T",last_timer);
}

/**
 *@brief It return state name from enum
 */
const char * get_state_string(int value)
{
    switch(value) {
        case NONE_STATE:
            strcpy(state_name, "NONE_STATE");
            break;
        case ASSOC_REQ_SNT_STATE:
            strcpy(state_name, "ASSOC_REQ_SNT_STATE");
            break;
        case ASSOC_RESP_RCVD_STATE:
            strcpy(state_name, "ASSOC_RESP_RCVD_STATE");
            break;
        case SESS_EST_REQ_SNT_STATE:
            strcpy(state_name, "SESS_EST_REQ_SNT_STATE");
            break;
        case SESS_EST_RESP_RCVD_STATE:
            strcpy(state_name, "SESS_EST_RESP_RCVD_STATE");
            break;
        case CONNECTED_STATE:
            strcpy(state_name, "CONNECTED_STATE");
            break;
        case IDEL_STATE:
            strcpy(state_name, "IDEL_STATE");
            break;
        case CS_REQ_SNT_STATE:
            strcpy(state_name, "CS_REQ_SNT_STATE");
            break;
        case CS_RESP_RCVD_STATE:
            strcpy(state_name, "CS_RESP_RCVD_STATE");
            break;
        case SESS_MOD_REQ_SNT_STATE:
            strcpy(state_name, "SESS_MOD_REQ_SNT_STATE");
            break;
        case SESS_MOD_RESP_RCVD_STATE:
            strcpy(state_name, "SESS_MOD_RESP_RCVD_STATE");
            break;
        case SESS_DEL_REQ_SNT_STATE:
            strcpy(state_name, "SESS_DEL_REQ_SNT_STATE");
            break;
        case SESS_DEL_RESP_RCVD_STATE:
            strcpy(state_name, "SESS_DEL_RESP_RCVD_STATE");
            break;
        case DS_REQ_SNT_STATE:
            strcpy(state_name, "DS_REQ_SNT_STATE");
            break;
        case DS_RESP_RCVD_STATE:
            strcpy(state_name, "DS_RESP_RCVD_STATE");
            break;
        case DDN_REQ_SNT_STATE:
            strcpy(state_name, "DDN_REQ_SNT_STATE");
            break;
        case DDN_ACK_RCVD_STATE:
            strcpy(state_name, "DDN_ACK_RCVD_STATE");
            break;
        case END_STATE:
            strcpy(state_name, "END_STATE");
        default:
            strcpy(state_name, "UNDEFINED STATE");
            break;
    }
    return state_name;
}

/**
 *@brief It return event name from enum
 */ 
const char * get_event_string(int value)
{
    switch(value) {
        case NONE_EVNT:
            strcpy(event_name, "NONE_EVNT");
            break;
        case CS_REQ_RCVD_EVNT:
            strcpy(event_name, "CS_REQ_RCVD_EVNT");
            break;
        case PFCP_ASSOC_SETUP_SNT_EVNT:
            strcpy(event_name, "PFCP_ASSOC_SETUP_SNT_EVNT");
            break;
        case PFCP_ASSOC_SETUP_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_ASSOC_SETUP_RESP_RCVD_EVNT");
            break;
        case PFCP_SESS_EST_REQ_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_EST_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_EST_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_EST_RESP_RCVD_EVNT");
            break;
        case CS_RESP_RCVD_EVNT:
            strcpy(event_name, "CS_RESP_RCVD_EVNT");
            break;
        case MB_REQ_RCVD_EVNT:
            strcpy(event_name,"MB_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_MOD_REQ_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_MOD_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_MOD_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_MOD_RESP_RCVD_EVNT");
            break;
        case MB_RESP_RCVD_EVNT:
            strcpy(event_name,"MB_RESP_RCVD_EVNT");
            break;
        case REL_ACC_BER_REQ_RCVD_EVNT:
            strcpy(event_name, "REL_ACC_BER_REQ_RCVD_EVNT");
            break;
        case DS_REQ_RCVD_EVNT:
            strcpy(event_name, "DS_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_DEL_REQ_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_DEL_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_DEL_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_DEL_RESP_RCVD_EVNT");
            break;
        case DS_RESP_RCVD_EVNT:
            strcpy(event_name, "DS_RESP_RCVD_EVNT");
            break;
        case ECHO_REQ_RCVD_EVNT:
            strcpy(event_name, "DDN_ACK_RCVD_EVNT");
            break;
        case ECHO_RESP_RCVD_EVNT:
            strcpy(event_name, "ECHO_RESP_RCVD_EVNT");
            break;
        case DDN_ACK_RESP_RCVD_EVNT:
            strcpy(event_name, "DDN_ACK_RESP_RCVD_EVNT");
            break;
        case PFCP_SESS_RPT_REQ_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_RPT_REQ_RCVD_EVNT");
            break;
        case END_EVNT:
            strcpy(event_name, "END_EVNT");
            break;
        default:
            strcpy(event_name, "UNDEFINED EVNT");
            break;
    }
    return event_name;
}

