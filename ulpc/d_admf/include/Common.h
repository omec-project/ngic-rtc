/*
 * Copyright (c) 2020 Sprint
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


#ifndef __COMMON_H_
#define __COMMON_H_


#include <cstdlib>
#include <iostream>
#include <sstream>
#include <map>
#include <list>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "emgmt.h"
#include "esynch.h"
#include "epctools.h"

#include "rapidjson/filereadstream.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/pointer.h"

#include "UeEntry.h"


#define ADD_ACTION				1
#define ADD_ACK					2
#define UPDATE_ACTION				3
#define UPDATE_ACK				4
#define START_UE				5
#define START_UE_ACK				6
#define STOP_UE					7
#define STOP_UE_ACK				8
#define DELETE_ACTION				9
#define DELETE_ACK				10

#define ACK_CHECKER				100

#define SXA					1
#define SXB					2
#define SXA_SXB					3

#define CP_TYPE					1
#define DP_TYPE					2
#define CP_DP_TYPE				3

#define UPLINK					1
#define DOWNLINK				2
#define UPLINK_DOWNLINK				3

#define S1U					1
#define SGW_S5S8_U				2
#define PGW_S5S8_U				3
#define SGI					4

#define SXA_INTFC_NAME				"sxa"
#define SXB_INTFC_NAME				"sxb"
#define SXA_SXB_INTFC_NAME			"sxasxb"

#define S1U_INTFC_NAME				"s1u"
#define SGW_S5S8_U_INTFC_NAME			"sgw-s5s8u"
#define PGW_S5S8_U_INTFC_NAME			"pgw-s5s8u"
#define SGI_INTFC_NAME				"sgi"
#define SEQ_ID_KEY				"sequenceId"
#define IMSI_KEY				"imsi"

#define SIGNALLING_CONFIG_KEY			"signallingconfig"
#define S11_KEY					"s11"
#define SGW_S5S8_C_KEY				"sgw-s5s8c"
#define PGW_S5S8_C_KEY				"pgw-s5s8c"
#define SX_KEY					"sx"
#define SX_INTFC_KEY				"sxintfc"
#define CP_DP_TYPE_KEY				"type"

#define DATA_CONFIG_KEY				"dataconfig"
#define S1U_CONTENT_KEY				"s1u_content"
#define SGW_S5S8U_CONTENT_KEY			"sgw_s5s8u_content"
#define PGW_S5S8U_CONTENT_KEY			"pgw_s5s8u_content"
#define SGI_CONTENT_KEY				"sgi_content"
#define DATA_INTFC_CONFIG_KEY			"intfcconfig"
#define DATA_INTFC_NAME_KEY			"intfc"
#define DATA_DIRECTION_KEY			"direction"

#define FORWARD_KEY				"forward"

#define TIMER_KEY				"timer"
#define START_TIME_KEY				"starttime"
#define STOP_TIME_KEY				"stoptime"
#define REQUEST_SOURCE_KEY			"requestSource"
#define RESPONSE_MSG_KEY			"response_message"
#define RESPONSE_JSON_KEY			"response_json"
#define NOTIFY_TYPE_KEY				"notifyType"

#define D_ADMF_IP				"DADMF_IP"
#define D_ADMF_PORT				"DADMF_PORT"
#define ADMF_IP					"ADMF_IP"
#define ADMF_PORT				"ADMF_PORT"

#define UE_DB_KEY				"uedatabase"
#define CP_IP_ADDR_KEY				"cpipaddr"

#define ACK_KEY					"ack"
#define REQUEST_TYPE_KEY			"requestType"

#define CONTENT_TYPE_JSON			"Content-Type: application/json"
#define X_USER_NAME				"X-User-Name: YOUR_NAME"
#define USER_AGENT				"curl/7.47.0"

#define HTTP					"http://"
#define COLON					":"
#define SLASH					"/"
#define ADD_UE_ENTRY_URI			"addueentry"
#define UPDATE_UE_ENTRY_URI			"updateueentry"
#define DELETE_UE_ENTRY_URI			"deleteueentry"
#define REGISTER_CP_URI				"registercp"
#define NOTIFY_URI				"notify"
#define ACK_POST				"ack"
#define CONFIG_FILE_PATH			"./config/dadmf.conf"
#define EMPTY_STRING				""

#define TRUE					true
#define FALSE					false

#define SECONDS					60
#define MILLISECONDS				1000

#define MAX_VALUE_UINT16_T			65535

#define ZERO					0
#define ONE					1

#define OPERATION_DEBUG				1
#define OPERATION_LI				2
#define OPERATION_BOTH				3

#define D_ADMF_REQUEST				0
#define ADMF_REQUEST				1

#define LOG_SYSTEM				3
#define RET_SUCCESS				0
#define RET_FAILURE				-1

#define DISABLE					0
#define OFF					1
#define ON					2

#define HEADER_ONLY				1
#define HEADER_AND_DATA				2
#define DATA_ONLY				3

#define SAFE_DELETE(p) 				{ if (p) { delete(p); (p) = NULL; }}


/**
 * @brief  : Maintains D_ADMF configurations read from config file
 */
typedef struct configurations {
	cpStr		                dadmfIp;
	UShort                          dadmfPort;
	std::string   	                admfIp;
	UShort	                        admfPort;
	uint16_t			ackCheckTimeInMin;
} configurations_t;

/**
 * @brief  : Maintains default values for Ue attributes
 */
typedef struct UeDefaults {
	uint16_t			s11;
	uint16_t			sgw_s5s8c;
	uint16_t			pgw_s5s8c;
	uint16_t			sxa;
	uint16_t			sxb;
	uint16_t			sxasxb;
	uint16_t			s1u;
	uint16_t			sgw_s5s8u;
	uint16_t			pgw_s5s8u;
	uint16_t			sgi;
	uint16_t			s1u_content;
	uint16_t			sgw_s5s8u_content;
	uint16_t			pgw_s5s8u_content;
	uint16_t			sgi_content;
	uint16_t			forward;
} ue_defaults_t;

/**
 * @brief  : Converts ip-address from ascii format to integer using
             in_addr structure
 * @param  : ipAddr, ip-address in ascii format
 * @return : Returns ip-address in integer format
 */
int ConvertAsciiIpToNumeric(const char *ipAddr);

/**
 * @brief  : Calculates difference of time in request with current time
 * @param  : dateStr, startTime/stopTime in the IMSI object in
             format "%Y-%m-%dT%H:%M:%SZ"
 * @return : Returns difference of time in request with current time
 */
int64_t getTimeDiffInMilliSec(const std::string &dateStr);

/**
 * @brief  : Creates JSON object for Imsi and appends request 
             source flag before sending it to ADMF
             so as to identify request has came from D-ADMF
 * @param  : request, request body received in the request
 * @param  : imsi, Imsi for which timer has elapsed
 * @return : returns JSON in string format in case of success,
             return NULL in case of json parsing error
 */
std::string prepareJsonFromUeData(std::list<ue_data_t> &ueDataList);

/**
 * @brief  : Creates sequence Identifier for every Ue entry request
             to identify every request uniquely.
 * @param  : ueData, structure filled with Ue entry details.
 * @return : sequenceId generated.
 */
uint64_t generateSequenceIdentifier(ue_data_t &ueData);

/**
 * @brief  : Creates JSON object for Imsi whose timer has been elapsed,
             and needs to be sent to all registered CP's
 * @param  : ueData, structure filled with Ue details.
 * @return : returns JSON in string format
 */
std::string prepareJsonForCP(std::list<ue_data_t> &ueData);

/**
 * @brief  : Creates JSON object for list of Imsi's whose start time has
             been elapsed and needs to be notified to legacy admf if forward
             flag was set for that Imsi.
 * @param  : ueData, list of Imsi
 * @param  : notifyType, notification type can be startUe or stopUe.
 * @return : return JSON in string format
 */
std::string prepareJsonForStartUe(std::list<ue_data_t> &ueData, 
		uint8_t notifyType = 0);

/**
 * @brief  : Creates JSON object for Imsi whose stop timer has been elapsed,
             and needs to be sent to all registered CP's (and ADMF if forward
             flag was set for that Imsi
 * @param  : ueData structure filled with Ue details
 * @param  : notifyType, additional parameter sent while sending stop 
             notification to admf
 * @return : returns JSON in string format
 */
std::string prepareJsonForStopUe(std::list<delete_event_t> &ueData, 
		uint8_t notifyType = 0);

/**
 * @brief  : Creates JSON object for response
 * @param  : ueDataList, list of Ue entries whose request was succeeded.
 * @param  : responseMsg, response message with additional information.
 * @return : return response JSON in string format
 */
std::string prepareResponseJson(std::list<ue_data_t> &ueDataList, 
				std::string &responseMsg);

#endif /* __COMMON_H */
