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


#ifndef __CDADMFAPI_H
#define __CDADMFAPI_H

#include <curl/curl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "gw_structs.h"

#define CONTENT_TYPE_JSON					"Content-Type: application/json"
#define X_USER_NAME							"X-User-Name: YOUR_NAME"
#define USER_AGENT							"curl/7.47.0"
#define UE_DB_KEY							"uedatabase"

#define LI_ID_KEY								"sequenceId"
#define IMSI_KEY								"imsi"
#define S11_KEY									"s11"
#define SGW_S5S8_C_KEY							"sgw-s5s8c"
#define PGW_S5S8_C_KEY							"pgw-s5s8c"
#define SXA_KEY									"sxa"
#define SXB_KEY									"sxb"
#define SXA_SXB_KEY								"sxasxb"
#define S1U_CONTENT_KEY							"s1u_content"
#define SGW_S5S8U_CONTENT_KEY					"sgw_s5s8u_content"
#define PGW_S5S8U_CONTENT_KEY					"pgw_s5s8u_content"
#define SGI_CONTENT_KEY							"sgi_content"
#define S1U_KEY									"s1u"
#define SGW_S5S8_U_KEY							"sgw-s5s8u"
#define PGW_S5S8_U_KEY							"pgw-s5s8u"
#define SGI_KEY									"sgi"
#define FORWARD_KEY								"forward"

#define MILLISECONDS				1000

#ifdef __cplusplus
extern "C" {
#endif

int registerCpOnDadmf(char *dadmf_ip,
		uint16_t dadmf_port, char *pfcp_ip,
		struct li_df_config_t *li_df_config, uint16_t *uiCntr);

int parseJsonReqFillStruct(const char *request,
		char **response, struct li_df_config_t *li_config, uint16_t *uiCntr);

int parseJsonReqForId(const char *request,
		char **response, uint64_t *uiIds, uint16_t *uiCntr);

int ConvertAsciiIpToNumeric(const char *ipAddr);
#ifdef __cplusplus
}
#endif

#endif /* #ifndef __CDADMFAPI_H */
