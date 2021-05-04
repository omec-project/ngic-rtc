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

#include <iostream>

#include "rapidjson/filereadstream.h"
#include "rapidjson/document.h"
#include "rapidjson/prettywriter.h"
#include "rapidjson/pointer.h"


//#define RAPIDJSON_NAMESPACE	epctoolsrapidjson

#define ADD			1
#define UPDATE			2
#define DELETE			3

#define ADD_URI			"/addueentry"
#define UPDATE_URI		"/updateueentry"
#define DELETE_URI		"/deleteueentry"

#define ZERO			0
#define RETURN_SUCCESS		0
#define RETURN_FAILURE		-1
#define HTTP			"http://"
#define COLON			":"
#define ACK_POST		"/ack"
#define ACK_KEY			"ack"
#define SEQ_ID_KEY		"sequenceId"
#define IMSI_KEY		"imsi"
#define REQUEST_TYPE_KEY	"requestType"

#define ADMF_PACKET		10
#define ADMF_INTFC_PACKET	20
#define LEGACY_ADMF_ACK		30
#define ADMF_ACK		40
#define LEGACY_ADMF_PACKET	50
#define ADMF_INTFC_ACK		60

#define LOG_INTFC		3

#define SAFE_DELETE_PTR(p)	{ if (p) { delete(p); (p) = NULL; }}


typedef struct config {
	std::string			admfIp;
	std::string			legacyAdmfIp;
	uint16_t			admfPort;
	uint16_t			legacyAdmfPort;
	uint16_t			legacyAdmfIntfcPort;
	enum protocol			{tcp, udp, rest};
	protocol			interfaceProtocol;
} config_t;

#pragma pack(push, 1)
typedef struct admfIntfcPacket {
	uint32_t			packetLength;

	struct ueEntry {
		uint64_t		seqId;
		uint64_t		imsi;
		uint16_t		packetType;
		uint16_t		requestType;
		UChar			startTime[21];
		UChar			stopTime[21];
	} ue_entry_t;
} admf_intfc_packet_t;
#pragma pack(pop)

#pragma pack(push, 1)
struct UeDatabase {
	uint32_t			packetLen;

	struct ueEntry {
		uint16_t		requestType;
		uint16_t		packetType;
		uint16_t		bodyLength;
		uint16_t		requestStatus;
		UChar			requestBody[0];
        } ue_entry_t;
};
#pragma pack(pop)

#endif /* endif __COMMON_H_ */
