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
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <fstream>
#include <vector>

#include "epctools.h"
#include "esocket.h"
#include "elogger.h"
#include "emgmt.h"
#include "efd.h"

#define LEGACY_DF_ACK 						201
#define TRUE							1
#define RET_SUCCESS						0
#define RET_FAILURE						1
#define DFPACKET_ACK						0xff
#define DF_CONNECT_TIMER_VALUE					10000
#define BACKLOG_CONNECTIION					10

#define LOG_AUDIT  3
#define LOG_SYSTEM 3
#define LOG_TEST3 3
#define LOG_TEST3_SINKSET 3
#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


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

	std::string strModuleName;
	UShort legacyPort;
	std::string strPcapFilePath;
};


#endif /* __COMMON_H_ */
