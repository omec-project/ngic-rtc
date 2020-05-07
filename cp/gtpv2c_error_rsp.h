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

/**
 * @brief  : Maintains data to be filled in error response
 */
typedef struct err_rsp_info_t
{
	uint32_t sender_teid;
	uint32_t teid;
	uint32_t seq;
	uint8_t ebi_index;
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
 * @return : Returns nothing
 */
int8_t clean_up_while_error(uint8_t ebi, uint32_t teid, uint64_t *imsi_val, uint16_t imsi_len, uint32_t seq );

/**
 * @brief  : Set and send error response in case of processing create session request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void cs_error_response(msg_info *msg, uint8_t cause_value, int iface);

/**
 * @brief  : Set and send error response in case of processing modify bearer request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void mbr_error_response(msg_info *msg, uint8_t cause_value, int iface);

/**
 * @brief  : Set and send error response in case of processing delete session request
 * @param  : msg, holds information related to message caused error
 * @param  : cause_value, cause type of error
 * @param  : iface, interface on which response to be sent
 * @return : Returns nothing
 */
void ds_error_response(msg_info *msg, uint8_t cause_value, int iface);

/**
 * @brief  : Gets information related to error and fills error response structure
 * @param  : msg, information related to message which caused error
 * @param  : err_rsp_info, structure to be filled
 * @param  : index, index of csr message in pending_csr array if parant message is csr
 * @return : Returns nothing
 */
void get_error_rsp_info(msg_info *msg, err_rsp_info *err_rsp_info, uint8_t index);

/**
 * @brief  : Gets information related to error and fills error response structure
 *           similar to get_error_rsp_info, but only gets called from error handler function
 * @param  : msg, information related to message which caused error
 * @param  : t2, structure to be filled
 * @param  : index, index of csr message in pending_csr array if parant message is csr
 * @return : Returns nothing
 */
void get_info_filled(msg_info *msg, err_rsp_info *t2 , uint8_t index);

void ubr_error_response(msg_info *msg, uint8_t cause_value, int iface);

void gen_reauth_error_response(pdn_connection *pdn, int16_t error);
#ifdef GX_BUILD
/**
 * @brief  : Preocess sending of ccr-t message if there is any error while procesing gx message
 * @param  : msg, information related to message which caused error
 * @param  : ebi, bearer id
 * @param  : teid, teid value
 * @return : Returns nothing
 */
void send_ccr_t_req(msg_info *msg, uint8_t ebi, uint32_t teid);
#endif /* GX_BUILD */

/**
 * @brief  : Send Version not supported response to peer node.
 * @param  : iface, interface.
 * @param  : seq, sequesnce number.
 * @return : Returns nothing
 */
void send_version_not_supported(int iface, uint32_t seq);

#endif
