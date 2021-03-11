/*
 * Copyright (c) 2020 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#ifndef __COMMON_H_
#define __COMMON_H_

#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <netinet/ip.h>
#include <linux/ipv6.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <fstream>
#include <vector>

#include "epctools.h"
#include "esocket.h"
#include "elogger.h"
#include "emgmt.h"
#include "efd.h"


#define TRUE					1
#define DDF2					"DDF2"
#define DDF3					"DDF3"
#define PAYLOAD_MAX_LENGTH			4098
#define RET_SUCCESS				0
#define RET_FAILURE				1
#define DATA_TYPE				0
#define EVENT_TYPE				1
#define DEBUG_DATA				1
#define FORWARD_DATA				2
#define BOTH_FW_DG				3
#define TTL					64
#define ETHER_TYPE				0x0800
#define ETHER_TYPE_V6				0x86DD
#define IPV4_VERSION				4
#define IPV6_VERSION				6
#define INTERNET_HDR_LEN			5
#define UDP_CHECKSUM				0
#define UDP_CHECKSUM_IPV6			1
#define DDFPACKET_ACK				0xee
#define DFPACKET_ACK				0xff
#define DF_CONNECT_TIMER_VALUE			10000
#define BACKLOG_CONNECTIION			10
#define SEND_BUF_SIZE				4096
#define IPV6_ADDRESS_LEN			16
#define IPTYPE_IPV4				0
#define IPTYPE_IPV6				1

#define LOG_AUDIT 				3
#define LOG_SYSTEM				3
#define LOG_TEST3 				3
#define LOG_TEST3_SINKSET 			3
#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


/*
 * @brief  : Maintains data related to DDF packet received from CP/DP
 */
#pragma pack(push, 1)
typedef struct DdfPacket {

	uint32_t packetLength;

	struct PacketHeader {

		uint8_t typeOfPayload;
		uint64_t liIdentifier;
		uint64_t imsiNumber;
		uint8_t srcIpType;
		uint32_t sourceIpAddress;
		uint8_t srcIpv6[IPV6_ADDRESS_LEN];
		uint16_t sourcePort;
		uint8_t dstIpType;
		uint32_t destIpAddress;
		uint8_t dstIpv6[IPV6_ADDRESS_LEN];
		uint16_t destPort;
		uint8_t  operationMode;
		uint32_t sequenceNumber;
		uint32_t dataLength;

	} header;

	uint8_t data[0];
} DdfPacket_t;
#pragma pack(pop)

/*
 * @brief  : Maintains data related to acknowledgement packet
 */

#pragma pack(push, 1)
typedef struct AckPacket {

	uint8_t packetLength;

	struct AckPacketHeader {

		uint8_t packetType;
		uint32_t sequenceNumber;
	} header;

} AckPacket_t;
#pragma pack(pop)


/*
 * @brief  : Maintains data to be sent to DF
 */
#pragma pack(push, 1)
typedef struct DfPacket {

	uint32_t packetLength;

	struct PacketHeader {

		uint32_t sequenceNumber;
		uint64_t liIdentifier;
		uint64_t imsiNumber;
		uint32_t dataLength;
	} header;

	uint8_t data[0];
} DfPacket_t;
#pragma pack(pop)


/*
 * @brief  : Maintains data related to configurations required in DDFx
 */
struct Configurations {

	std::string strDModuleName;
	cpStr ddf_ip;
	UShort ddf_port;
	cpStr df_ip;
	UShort df_port;
	std::string strDFilePath;
	std::string strDirName;
};


#endif /* __COMMON_H_ */
