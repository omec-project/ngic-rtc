/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#ifndef CP_APP_H_
#define CP_APP_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdbool.h>
#include "gx_app/include/gx_struct.h"
#include "gx_app/include/gx.h"

#ifdef CP_BUILD
#include "ue.h"
#endif /* CP_BUILD */

#include "gtp_messages.h"

#define SERVER_PATH "/usr/sock_server_cca_rar"
#define CLIENT_PATH "/usr/sock_client_ccr_raa"

#define MAX_PATH_LEN 32
#define MULTIPLIER 50
#define BUFFSIZE MULTIPLIER * 1024
#define BACKLOG  100
#define LENGTH sizeof(struct sockaddr_un)

/* IMSI length on gtpv2c */
#define BINARY_IMSI_LEN 8

/* IMSI length on gx */
#define STR_IMSI_LEN 16

/* MSISDN length on gtpv2c */
#define BINARY_MSISDN_LEN 6

/* MSISDN length on gx */
#define STR_MSISDN_LEN 12

extern int g_cp_sock;
extern int g_app_sock;

#pragma pack(1)

enum e_BUF_HDR {
	GX_RAR_MSG,
	GX_RAA_MSG,
	GX_CCR_MSG,
	GX_CCA_MSG,
};

enum pra_status {
	PRA_IN_AREA,
	PRA_OUT_AREA,
	PRA_INACTIVE,
};

/**
 * @brief  : Maintains data related to different gs messages
 */
typedef struct Gx_msg {
	uint8_t msg_type;
	uint16_t msg_len;
	union data_t {
		GxRAR cp_rar;
		GxRAA cp_raa;
		GxCCR cp_ccr;
		GxCCR ccr;
		GxCCA cp_cca;
	}data;
}gx_msg;

#pragma pack()

/**
 * @brief  : Handles processing of gx rar message
 * @param  : recv_buf, Received data from incoming message
 * @return : Returns nothing
 */
void
handle_gx_rar( unsigned char *recv_buf);

/**
 * @brief  : Handles processing of gx cca message
 * @param  : recv_buf, Received data from incoming message
 * @return : Returns nothing
 */
void
handle_gx_cca( unsigned char *recv_buf);

/**
 * @brief  : Handles incoming gx messages
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
msg_handler_gx( void );

/**
 * @brief  : Activate  interface for listening gx messages
 * @param  : No param
 * @return : Returns nothing
 */
void
start_cp_app( void );

#ifdef CP_BUILD
/**
 * @brief  : Fill ccr request
 * @param  : ccr, structure to be filled
 * @param  : context, ue context data
 * @param  : ebi_index, array index of bearer
 * @param  : sess_id, session id
 * @param  : flow_flag, 1 for bearer resource mod flow,else 0
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_ccr_request(GxCCR *ccr, ue_context *context,
					int ebi_index, char *sess_id, uint8_t flow_flag);

/**
 * @brief  : Fill Presence Reporting Area Info in CCA
 * @param  : presence_rprtng_area_info, structure to be filled
 * @param  : ue_pra_info, Presence Reporting Area in UE context
 * @return : Returns nothing
 */
void
fill_presence_rprtng_area_info(GxPresenceReportingAreaInformationList *presence_rprtng_area_info,
														presence_reproting_area_info_t *ue_pra_info);
#endif /* CP_BUILD */

/**
 * @brief  : Fill rat type ie
 * @param  : ccr_rat_type, parameter to be filled
 * @param  : csr_rat_type, input rat type
 * @return : Returns nothing
 */
void
fill_rat_type_ie( int32_t *ccr_rat_type, uint8_t csr_rat_type );

/**
 * @brief  : Fill user equipment information
 * @param  : ccr_user_eq_info, structure to be filled
 * @param  : csr_imei, imei value
 * @return : Returns nothing
 */
void
fill_user_equipment_info( GxUserEquipmentInfo *ccr_user_eq_info, uint64_t csr_imei );

/**
 * @brief  : Fill timezone information
 * @param  : ccr_tgpp_ms_timezone, structure to be filled
 * @param  : csr_ue_timezone, input data
 * @return : Returns nothing
 */
void
fill_3gpp_ue_timezone( Gx3gppMsTimezoneOctetString *ccr_tgpp_ms_timezone,
		gtp_ue_time_zone_ie_t csr_ue_timezone );

/**
 * @brief  : Fill subscription id information
 * @param  : subs_id, structure to be filled
 * @param  : imsi, imsi value
 * @param  : msisdn, msisdn value
 * @return : Returns nothing
 */
void
fill_subscription_id( GxSubscriptionIdList *subs_id, uint64_t imsi, uint64_t msisdn );

/**
 * @brief  : Process create bearer response and send raa message
 * @param  : sock, interface id to send raa
 * @return : Returns nothing
 */
void
process_create_bearer_resp_and_send_raa( int sock );

/**
 * @brief  : Convert binary data to string value
 * @param  : b_val, input binary data
 * @param  : s_val, parameter to store converted string
 * @param  : b_len, length of binary data
 * @param  : s_len, length of string
 * @return : Returns nothing
 */
void
bin_to_str(unsigned char *b_val, char *s_val, int b_len, int s_len);

/**
 * @brief  : Encode imsi to binary value
 * @param  : imsi, imput imsi value
 * @param  : imsi_len, length of imsi
 * @param  : bin_imsi, output value
 * @return : Returns nothing
 */
void
encode_imsi_to_bin(uint64_t imsi, int imsi_len, uint8_t *bin_imsi);

/**
 * @brief  : free dynamically allocated memory of cca msg.
 * @param  : cca, Structure to store cca msg.
 * @return : Returns nothing
 */
void
free_cca_msg_dynamically_alloc_memory(GxCCA *cca);

#endif /* CP_APP_H_ */
