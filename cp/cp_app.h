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

/* VG1 Temp inlude remove this after handling of CSR on gx*/
#include "../libgtpv2c/include/gtp_messages.h"


#define SERVER_PATH "/usr/sock_server"
#define CLIENT_PATH "/usr/sock_client"

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

typedef struct Gx_msg {
	uint8_t msg_type;
	union data_t {
		GxRAR cp_rar;
		GxRAA cp_raa;
		GxCCR cp_ccr;
		GxCCR ccr;
		GxCCA cp_cca;
	}data;
}gx_msg;

#pragma pack()

void
handle_gx_rar( unsigned char *recv_buf);

void
handle_gx_cca( unsigned char *recv_buf);

int
msg_handler_gx( void );

void
start_cp_app( void );

#ifdef CP_BUILD
int
fill_ccr_request(GxCCR *ccr, ue_context *context,
		uint8_t ebi_index, char *sess_id);

#endif /* CP_BUILD */

void
fill_rat_type_ie( int32_t *ccr_rat_type, uint8_t csr_rat_type );

void
fill_user_equipment_info( GxUserEquipmentInfo *ccr_user_eq_info, uint64_t csr_imei );

void
fill_3gpp_ue_timezone( Gx3gppMsTimezoneOctetString *ccr_tgpp_ms_timezone,
		gtp_ue_time_zone_ie_t csr_ue_timezone );

void
fill_subscription_id( GxSubscriptionIdList *subs_id, uint64_t imsi, uint64_t msisdn );

void
process_create_bearer_resp_and_send_raa( int sock );

void
bin_to_str(unsigned char *b_val, char *s_val, int b_len, int s_len);

#endif /* CP_APP_H_ */
