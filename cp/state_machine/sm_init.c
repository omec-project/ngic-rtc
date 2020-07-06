
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
#include "cp_config.h"

extern struct rte_hash *bearer_by_fteid_hash;

#define SM_HASH_SIZE (1 << 18)

char proc_name[40];
char state_name[40];
char event_name[40];

/**
 * @brief  : Add session entry in state machine hash table.
 * @param  : sess_id, key.
 * @param  : resp_info Resp
 * @return : 0 or 1.
 */
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
			clLog(clSystemLog, eCLSeverityCritical, "%s: Failed to add entry = %lu"
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
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Entry not found for sess_id:%lu...\n",__func__,
				__file__, __LINE__,sess_id);
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
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Entry not found for sess_id:%lu...\n",__func__,
				__file__, __LINE__,sess_id);
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
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d :Entry not found for sess_id:%lu...\n", __func__,
				__file__, __LINE__, sess_id);
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
					&sess_id, (void **)resp);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(sm_hash, &sess_id);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s %s %d:Entry not found for sess_id:%lu...\n",
						__func__, __file__, __LINE__, sess_id);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}
	}

	/* Free data from hash */
	rte_free(resp);

	clLog(clSystemLog, eCLSeverityDebug, "%s: Sess ID:%lu\n",
			__func__, sess_id);

	return 0;
}

uint8_t
update_ue_state(uint32_t teid_key, uint8_t state,  uint8_t ebi_index)
{
	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				&teid_key, (void **)&context);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State for Teid:%x...\n", __func__,
				teid_key);
		return -1;
	}
	pdn = GET_PDN(context , ebi_index);
	pdn->state = state;

	clLog(clSystemLog, eCLSeverityDebug, "%s: Change UE State for Teid:%u, State:%s\n",
			__func__, teid_key, get_state_string(pdn->state));
	return 0;

}

uint8_t
get_ue_state(uint32_t teid_key, uint8_t ebi_index)
{
	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				&teid_key, (void **)&context);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid_key);
		return -1;
	}
	pdn = GET_PDN(context , ebi_index);
	clLog(clSystemLog, eCLSeverityDebug, "%s: Teid:%u, State:%s\n",
			__func__, teid_key, get_state_string(pdn->state));
	return pdn->state;
}

int
get_pdn(uint32_t teid_key, pdn_connection **pdn)
{
	int ret = 0;
	ret = rte_hash_lookup_data(pdn_by_fteid_hash,
				&teid_key, (void **)pdn);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid_key);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Teid:%u\n",
			__func__, teid_key);
	return 0;

}

int8_t
get_bearer_by_teid(uint32_t teid_key, struct eps_bearer_t **bearer)
{
	int ret = 0;
        ret = rte_hash_lookup_data(bearer_by_fteid_hash,
                                        &teid_key, (void **)bearer);


        if ( ret < 0) {
               // clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid_key);
                return -1;
        }


        clLog(clSystemLog, eCLSeverityDebug, "%s: Teid %u\n",
                        __func__, teid_key);
        return 0;
}

int8_t
get_ue_context_by_sgw_s5s8_teid(uint32_t teid_key, ue_context **context)
{
	int ret = 0;
	struct eps_bearer_t *bearer = NULL;

	ret = get_bearer_by_teid(teid_key, &bearer);
	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Entry not found for teid:%x...\n", __func__, __LINE__, teid_key);
                return -1;
	}
	if(bearer != NULL && bearer->pdn != NULL && bearer->pdn->context != NULL ) {
		*context = bearer->pdn->context;
		return 0;
	}
	return -1;
}
/* This function use only in clean up while error */
int8_t
get_ue_context_while_error(uint32_t teid_key, ue_context **context)
{
	int ret = 0;
	struct eps_bearer_t *bearer = NULL;
	/* If teid key is sgwc s11 */
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
                                        &teid_key, (void **)context);
	if( ret < 0) {
		/* If teid key is sgwc s5s8 */
		ret = get_bearer_by_teid(teid_key, &bearer);
		if(ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Entry not found for teid:%x...\n", __func__, __LINE__, teid_key);
			return -1;
		}

     	   *context = bearer->pdn->context;
	}
	return 0;
}

int8_t
get_ue_context(uint32_t teid_key, ue_context **context)
{

	int ret = 0;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					&teid_key, (void **)context);


	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid_key);
		return -1;
	}


	clLog(clSystemLog, eCLSeverityDebug, "%s: Teid %u\n",
			__func__, teid_key);
	return 0;

}
/**
 * @brief  : Initializes the hash table used to account for CS/MB/DS req and resp handle sync.
 * @param  : No param
 * @return : Returns nothing
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
 * @brief  : It return procedure name from enum
 * @param  : value, procedure
 * @return : Returns procedure string
 */
const char * get_proc_string(int value)
{
	switch(value) {
		case NONE_PROC:
			strcpy(proc_name, "NONE_PROC");
			break;
		case INITIAL_PDN_ATTACH_PROC:
			strcpy(proc_name, "INITIAL_PDN_ATTACH_PROC");
			break;
		case SERVICE_REQUEST_PROC:
			strcpy(proc_name, "SERVICE_REQUEST_PROC");
			break;
		case SGW_RELOCATION_PROC:
			strcpy(proc_name, "SGW_RELOCATION_PROC");
			break;
		case CONN_SUSPEND_PROC:
			strcpy(proc_name, "CONN_SUSPEND_PROC");
			break;
		case DETACH_PROC:
			strcpy(proc_name, "DETACH_PROC");
			break;
		case DED_BER_ACTIVATION_PROC:
			strcpy(proc_name, "DED_BER_ACTIVATION_PROC");
			break;
		case PDN_GW_INIT_BEARER_DEACTIVATION:
			strcpy(proc_name, "PDN_GW_INIT_BEARER_DEACTIVATION");
			break;
		case MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC:
			strcpy(proc_name, "MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC");
			break;
		case UPDATE_BEARER_PROC:
			strcpy(proc_name, "UPDATE_BEARER_PROC");
			break;
		case RESTORATION_RECOVERY_PROC:
			strcpy(proc_name, "RESTORATION_RECOVERY_PROC");
			break;
		case END_PROC:
			strcpy(proc_name, "END_PROC");
			break;
		default:
			strcpy(proc_name, "UNDEFINED PROC");
			break;
	}
	return proc_name;
}

/**
 * @brief  : It return state name from enum
 * @param  : value, state
 * @return : Returns state string
 */
const char * get_state_string(int value)
{
    switch(value) {
        case SGWC_NONE_STATE:
            strcpy(state_name, "SGWC_NONE_STATE");
            break;
        case PFCP_ASSOC_REQ_SNT_STATE:
            strcpy(state_name, "PFCP_ASSOC_REQ_SNT_STATE");
            break;
        case PFCP_ASSOC_RESP_RCVD_STATE:
            strcpy(state_name, "PFCP_ASSOC_RESP_RCVD_STATE");
            break;
        case PFCP_SESS_EST_REQ_SNT_STATE:
            strcpy(state_name, "PFCP_SESS_EST_REQ_SNT_STATE");
            break;
        case PFCP_SESS_EST_RESP_RCVD_STATE:
            strcpy(state_name, "PFCP_SESS_EST_RESP_RCVD_STATE");
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
        case PFCP_SESS_MOD_REQ_SNT_STATE:
            strcpy(state_name, "PFCP_SESS_MOD_REQ_SNT_STATE");
            break;
        case PFCP_SESS_MOD_RESP_RCVD_STATE:
            strcpy(state_name, "PFCP_SESS_MOD_RESP_RCVD_STATE");
            break;
        case PFCP_SESS_DEL_REQ_SNT_STATE:
            strcpy(state_name, "PFCP_SESS_DEL_REQ_SNT_STATE");
            break;
        case PFCP_SESS_DEL_RESP_RCVD_STATE:
            strcpy(state_name, "PFCP_SESS_DEL_RESP_RCVD_STATE");
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
		case MBR_REQ_SNT_STATE:
			strcpy(state_name, "MBR_REQ_SNT_STATE");
			break;
		case MBR_RESP_RCVD_STATE:
			strcpy(state_name, "MBR_RESP_RCVD_STATE");
			break;
		case CREATE_BER_REQ_SNT_STATE:
			strcpy(state_name, "CREATE_BER_REQ_SNT_STATE");
			break;
		case RE_AUTH_ANS_SNT_STATE:
			 strcpy(state_name, "RE_AUTH_ANS_SNT_STATE");
			break;
		case PGWC_NONE_STATE:
		        strcpy(state_name, "PGWC_NONE_STATE");
		        break;
		case CCR_SNT_STATE:
		        strcpy(state_name, "CCR_SNT_STATE");
		        break;
		case CREATE_BER_RESP_SNT_STATE:
		        strcpy(state_name, "CREATE_BER_RESP_SNT_STATE");
		        break;
		case PFCP_PFD_MGMT_RESP_RCVD_STATE:
		        strcpy(state_name, "PFCP_PFD_MGMT_RESP_RCVD_STATE");
		        break;
		case ERROR_OCCURED_STATE:
		        strcpy(state_name, "ERROR_OCCURED_STATE");
				break;
		case UPDATE_BEARER_REQ_SNT_STATE:
		        strcpy(state_name, "UPDATE_BEARER_REQ_SNT_STATE");
				break;
		case UPDATE_BEARER_RESP_SNT_STATE:
		        strcpy(state_name, "UPDATE_BEARER_RESP_SNT_STATE");
				break;
		case DELETE_BER_REQ_SNT_STATE:
		    strcpy(state_name, "DELETE_BER_REQ_SNT_STATE");
			break;
		case CCRU_SNT_STATE:
		    strcpy(state_name, "CCRU_SNT_STATE");
			break;
		case PGW_RSTRT_NOTIF_REQ_SNT_STATE:
		    strcpy(state_name, "PGW_RSTRT_NOTIF_REQ_SNT_STATE");
			break;
		case UPD_PDN_CONN_SET_REQ_SNT_STATE:
		    strcpy(state_name, "UPD_PDN_CONN_SET_REQ_SNT_STATE");
			break;
		case DEL_PDN_CONN_SET_REQ_SNT_STATE:
		    strcpy(state_name, "DEL_PDN_CONN_SET_REQ_SNT_STATE");
			break;
		case DEL_PDN_CONN_SET_REQ_RCVD_STATE:
		    strcpy(state_name, "DEL_PDN_CONN_SET_REQ_RCVD_STATE");
			break;
		case PFCP_SESS_SET_DEL_REQ_SNT_STATE:
		    strcpy(state_name, "PFCP_SESS_SET_DEL_REQ_SNT_STATE");
			break;
		case PFCP_SESS_SET_DEL_REQ_RCVD_STATE:
		    strcpy(state_name, "PFCP_SESS_SET_DEL_REQ_RCVD_STATE");
			break;
		case END_STATE:
		    strcpy(state_name, "END_STATE");
			break;
		default:
		    strcpy(state_name, "UNDEFINED STATE");
		    break;
    }
    return state_name;
}

/**
 * @brief  : It return event name from enum
 * @param  : value, state
 * @return : Returns event string
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
	case RE_AUTH_REQ_RCVD_EVNT:
            strcpy(event_name, "RE_AUTH_REQ_RCVD_EVNT");
			break;
	case CREATE_BER_RESP_RCVD_EVNT:
            strcpy(event_name, "CREATE_BER_RESP_RCVD_EVNT");
			break;
	case CCA_RCVD_EVNT:
            strcpy(event_name, "CCA_RCVD_EVNT");
			break;
	case CREATE_BER_REQ_RCVD_EVNT:
            strcpy(event_name, "CREATE_BER_REQ_RCVD_EVNT");
			break;
	case PFCP_PFD_MGMT_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_PFD_MGMT_RESP_RCVD_EVNT");
			break;
	case ERROR_OCCURED_EVNT:
            strcpy(event_name, "ERROR_OCCURED_EVNT");
            break;
	case UPDATE_BEARER_REQ_RCVD_EVNT:
            strcpy(event_name, "UPDATE_BEARER_REQ_RCVD_EVNT");
            break;
	case UPDATE_BEARER_RSP_RCVD_EVNT:
            strcpy(event_name, "UPDATE_BEARER_RSP_RCVD_EVNT");
            break;
	case DELETE_BER_REQ_RCVD_EVNT:
            strcpy(event_name, "DELETE_BER_REQ_RCVD_EVNT");
            break;
	case DELETE_BER_RESP_RCVD_EVNT:
            strcpy(event_name, "DELETE_BER_RESP_RCVD_EVNT");
            break;
	case DELETE_BER_CMD_RCVD_EVNT:
            strcpy(event_name, "DELETE_BER_CMD_RCVD_EVNT");
            break;
	case CCAU_RCVD_EVNT:
            strcpy(event_name, "CCAU_RCVD_EVNT");
            break;
        case PFCP_SESS_SET_DEL_REQ_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_SET_DEL_REQ_RCVD_EVNT");
            break;
        case PFCP_SESS_SET_DEL_RESP_RCVD_EVNT:
            strcpy(event_name, "PFCP_SESS_SET_DEL_RSEP_RCVD_EVNT");
            break;
		case PGW_RSTRT_NOTIF_ACK_RCVD_EVNT:
		    strcpy(event_name, "PGW_RSTRT_NOTIF_ACK_RCVD_EVNT");
		    break;
		case UPD_PDN_CONN_SET_REQ_RCVD_EVNT:
		    strcpy(event_name, "UPD_PDN_CONN_SET_REQ_RCVD_EVNT");
		    break;
		case UPD_PDN_CONN_SET_RESP_RCVD_EVNT:
		    strcpy(event_name, "UPD_PDN_CONN_SET_RESP_RCVD_EVNT");
		    break;
		case DEL_PDN_CONN_SET_REQ_RCVD_EVNT:
		    strcpy(event_name, "DEL_PDN_CONN_SET_REQ_RCVD_EVNT");
		    break;
		case DEL_PDN_CONN_SET_RESP_RCVD_EVNT:
		    strcpy(event_name, "DEL_PDN_CONN_SET_RESP_RCVD_EVNT");
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

uint8_t
get_procedure(msg_info *msg)
{
	uint8_t proc = NONE_PROC;

	switch(msg->msg_type) {
		case GTP_CREATE_SESSION_REQ: {
			if (1 == msg->gtpc_msg.csr.indctn_flgs.indication_oi) {
				/*Set SGW Relocation Case */
				proc = SGW_RELOCATION_PROC;
			} else if (msg->gtpc_msg.csr.bearer_contexts_to_be_created.s5s8_u_pgw_fteid.header.len) {
				/* S1 Based Handover */
				proc = SERVICE_REQUEST_PROC;
			} else {
				proc = INITIAL_PDN_ATTACH_PROC;
			}

			break;
		}
		 case GTP_MODIFY_BEARER_REQ : {
	               proc = SGW_RELOCATION_PROC;
				   break;
	     }

		case GTP_DELETE_SESSION_REQ: {
		/*if (0 == msg->gtpc_msg.dsr.indctn_flgs.indication_oi &&
						msg->gtpc_msg.dsr.indctn_flgs.header.len !=0) {
				proc = SGW_RELOCATION_PROC;
			} else */{
				proc = DETACH_PROC;
			}

			break;
		}


		case GTP_DELETE_SESSION_RSP: {
				proc = DETACH_PROC;
			break;
		}
		case GTP_RELEASE_ACCESS_BEARERS_REQ: {
			proc = CONN_SUSPEND_PROC;

			break;
		}

		case GTP_CREATE_BEARER_REQ: {
			proc = DED_BER_ACTIVATION_PROC;

			break;
		}

		case GTP_CREATE_BEARER_RSP: {
			proc = DED_BER_ACTIVATION_PROC;

			break;
		}

		case GTP_DELETE_BEARER_REQ: {
			proc = PDN_GW_INIT_BEARER_DEACTIVATION;
			break;
		}

		case GTP_DELETE_BEARER_RSP: {
			proc = PDN_GW_INIT_BEARER_DEACTIVATION;

			break;
		}

		case GTP_UPDATE_BEARER_REQ: {
			proc = UPDATE_BEARER_PROC;

			break;
		}

		case GTP_UPDATE_BEARER_RSP: {
			proc = UPDATE_BEARER_PROC;

			break;
		}

		case GTP_DELETE_BEARER_CMD: {
			proc = MME_INI_DEDICATED_BEARER_DEACTIVATION_PROC;
			break;
		}
		case GTP_DELETE_PDN_CONNECTION_SET_REQ: {
			proc = RESTORATION_RECOVERY_PROC;

			break;
		}
		case GTP_DELETE_PDN_CONNECTION_SET_RSP: {
			proc = RESTORATION_RECOVERY_PROC;

			break;
		}
		case GTP_UPDATE_PDN_CONNECTION_SET_REQ: {
			proc = RESTORATION_RECOVERY_PROC;

			break;
		}
		case GTP_UPDATE_PDN_CONNECTION_SET_RSP: {
			proc = RESTORATION_RECOVERY_PROC;

			break;
		}
		case GTP_PGW_RESTART_NOTIFICATION_ACK: {
			proc = RESTORATION_RECOVERY_PROC;

			break;
		}
	}

	return proc;
}

uint8_t
get_csr_proc(create_sess_req_t *csr)
{
	if (1 == csr->indctn_flgs.indication_oi) {
		return SGW_RELOCATION_PROC;
	} else if (csr->bearer_contexts_to_be_created.s5s8_u_pgw_fteid.header.len) {
		return SERVICE_REQUEST_PROC;
	} else {
		return INITIAL_PDN_ATTACH_PROC;
	}
}

uint8_t
update_ue_proc(uint32_t teid_key, uint8_t proc, uint8_t ebi_index)
{
	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
				&teid_key, (void **)&context);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Failed to update UE State for Teid:%x...\n", __func__,
				teid_key);
		return -1;
	}

	if (context == NULL)
		return -1;

	pdn = GET_PDN(context, ebi_index);

	if (pdn == NULL)
		return -1;

	pdn->proc = proc;

	clLog(clSystemLog, eCLSeverityDebug,
			"%s: Change UE State for Teid:%u, Procedure:%s, State:%s\n",
			__func__, teid_key, get_proc_string(pdn->proc),
			get_state_string(pdn->state));

	return 0;

}
