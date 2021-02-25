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

#ifndef _GTPV2C_ERROR_RSP_H_
#define _GTPV2C_ERROR_RSP_H_

#include "ue.h"
#include "gtpv2c.h"
#include "sm_struct.h"
#include "gtpv2c_ie.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "./gx_app/include/gx.h"

extern struct rte_hash *bearer_by_fteid_hash;
/**
 * @brief  : Maintains data to be filled in error response
 */
typedef struct err_rsp_info_t
{
	uint8_t cp_mode;
	uint32_t sender_teid;
	uint32_t teid;
	uint32_t seq;
	uint8_t ebi;
	uint8_t offending;
	uint8_t bearer_count;
	uint8_t bearer_id[MAX_BEARERS];
}err_rsp_info;

/**
 * @brief  : Performs clean up task
 * @param  : ebi, bearer id
 * @param  : teid, teid value
 * @param  : imsi_val, imsi value
 * @param  : imsi_len, imsi length
 * @param  : seq, sequence
 * @param  : msg, message info
 * @return : Returns nothing
 */
int8_t clean_up_while_error(uint8_t ebi, ue_context *context, uint32_t teid,
		uint64_t *imsi_val, uint32_t seq, msg_info *msg);

/**
 * @brief  : Performs clean up task after create bearer error response
 * @param  : teid, teid value
 * @param  : msg_type, type of message
 * @param  : pdn, PDN structure
 * @return : Returns nothing
 */
int8_t clean_up_while_cbr_error(uint32_t teid, uint8_t msg_type, pdn_connection *pdn);

/**
 * @brief  : Set and send error response in case of processing create session request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void cs_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
						int iface);

/**
 * @brief  : Set and send error response in case of processing modify bearer request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void mbr_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
						int iface);

/**
 * @brief  : Set and send error response in case of processing delete session request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void ds_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
						int iface);

/**
 * @brief  : Gets information related to error and fills error response structure
 * @param  : msg, information related to message which caused error
 * @param  : err_rsp_info, structure to be filled
 * @param  : index, index of csr message in pending_csr array if parant message is csr
 * @return : Returns nothing
 */
void get_error_rsp_info(msg_info *msg, err_rsp_info *err_rsp_info, uint8_t index);

/**
 * @brief  : Set and send error response in case of processing update bearer request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void ubr_error_response(msg_info *msg, uint8_t cause_value, uint8_t cause_source,
		int iface);

/**
 * @brief  : set and send error response in case of processing delete bearer procedure.
 * @param  : msg, information related to message which caused error
 * @param  : cause value;cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void delete_bearer_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface);

/**
 * @brief  : set and send error response in case of processing delete bearer procedure for MME initiated bearer deactivation.
 * @param  : msg, information related to message which caused error
 * @param  : cause value;cause type of error
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */

void delete_bearer_cmd_failure_indication(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface);

/**
 * @brief  : Set and send error response in case of processing Change Notification Request
 * @param  : cause, cause value
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void
change_notification_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface);
/**
 * @brief  : Set and send error response in case of processing Change Notification Request
 * @param  : msg, message info
 * @param  : cause, cause value
 * @param  : cause_source, cause source of error
 * @param  : iface, interface on which response need to send
 * @return : Returns nothing
 */
void
release_access_bearer_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface);

/**
 * @brief  : Set and send error response in case of processing UPDATE PDN SET CONN. Request
 * @param  : msg, message info
 * @param  : cause, cause value
 * @param  : cause_source, cause source of error
 * @return : Returns nothing
 */
void
update_pdn_connection_set_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source);

/*
 * @brief  : set and send error response in case of processing bearer resource command.
 * @param  : msg, information related to message which caused error
 * @param  : cause value;cause type of error
 * @param  : cause value;cause type of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void send_bearer_resource_failure_indication(msg_info *msg,
		uint8_t cause_value, uint8_t cause_source, int iface);

/**
 * @brief  : Set and send error response in case of processing create bearer request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : cause value;cause type of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void cbr_error_response(msg_info *msg, uint8_t cause_value,
		uint8_t cause_source, int iface);

/**
 * @brief  : Set and send RAA error response in case of reauthentication request failure
 * @param  : pdn, pdn connection information
 * @param  : error, error value
 * @return : Returns nothing
 */
void gen_reauth_error_response(pdn_connection *pdn, int16_t error);

/**
 * @brief  : Set and send RAA error response in case of wrong seid rcvd
 * @param  : msg, msg information
 * @param  : gxmsg, gx msg information
 * @param  : cause_value, error cause value
 * @return : Returns nothing
 */
void gen_reauth_error_resp_for_wrong_seid_rcvd(msg_info *msg, gx_msg *gxmsg, int16_t cause_value);
/**
 * @brief  : Preocess sending of ccr-t message if there is any error while procesing gx message
 * @param  : msg, information related to message which caused error
 * @param  : ebi, bearer id
 * @param  : teid, teid value
 * @return : 0 on success, -1 on failure.
 */
int  send_ccr_t_req(msg_info *msg, uint8_t ebi, uint32_t teid);

/**
 * @brief  : Send Version not supported response to peer node.
 * @param  : iface, interface.
 * @param  : seq, sequesnce number.
 * @return : Returns nothing
 */
void send_version_not_supported(int iface, uint32_t seq);

/**
 * @brief  : Select respective error response function as per proc
 * @param  : msg, message info
 * @param  : cause_value, error cause message
 * @return : Returns nothing
 */
void
pfcp_modification_error_response(struct resp_info *resp, msg_info *msg, uint8_t cause_value);

/**
 * @brief  : Send error in case of fail in DNS.
 * @param  : pdn, PDN connection context information.
 * @param  : cause_value, error cause message
 * @return : Returns nothing
 */
void
send_error_resp(pdn_connection *pdn, uint8_t cause_value);

/**
 * @brief  : Select respective error response function as cca request type
 * @param  : cause, cause value
 * @param  : msg, message info
 * @return : Returns nothing
 */
void
gx_cca_error_response(uint8_t cause, msg_info *msg);

/**
 * @brief  : Cleans upf_context information
 * @param  : pdn, PDN connection context information.
 * @return : Returns nothing
 */
void
clean_up_upf_context(pdn_connection *pdn, ue_context *context);

/**
 * @brief  : cleans context hash
 * @param  : context,
 * @param  : teid,
 * @param  : imsi_val,
 * @return : Returns nothing
 */
int
clean_context_hash(ue_context *context, uint32_t teid, uint64_t *imsi_val, bool error_status);

/**
 * @brief  : clears the bearers, pdn, ue_context
 * @param  : teid
 * @param  : ebi_index
 * @return : Returns -1 on failure and 0 on success.
 */
int cleanup_ue_and_bearer(uint32_t teid, int ebi_index);

/**
 * @brief  : send delete session request to pgwc
 * @param  : context, context information.
 * @param  : ebi_index, Bearer index.
 * @return : Returns nothing
 */
void
send_delete_session_request_after_timer_retry(ue_context *context, int ebi_index);
#endif
