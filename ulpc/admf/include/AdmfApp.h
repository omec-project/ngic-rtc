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


#ifndef __ADMF_APP_H_
#define __ADMF_APP_H_

#include <iostream>
#include <signal.h>
#include <limits>

#include "etevent.h"
#include "epctools.h"
#include "efd.h"
#include "BaseLegacyAdmfInterface.h"

#include "UeEntry.h"


#define LOG_SYSTEM		1
#define LOG_AUDIT		2
#define LOG_ADMF		3
#define LOG_SYSTEM_LEGACY	4
#define OPERATION_DEBUG		1
#define OPERATION_LI		2
#define OPERATION_BOTH		3
#define D_ADMF_IP		"DADMF_IP"
#define D_ADMF_PORT		"DADMF_PORT"
#define D_ADMF_REQUEST		0
#define ADMF_REQUEST		1
#define ZERO			0
#define ONE			1
#define REQUEST_SOURCE_KEY	"requestSource"
#define RET_SUCCESS		0
#define RET_FAILURE		-1
#define INVALID_IMSI		-1
#define EMPTY_STRING		""
#define TCP_PROT		"tcp"
#define UDP_PROT		"udp"
#define REST_PROT		"rest"
#define ADD_REQUEST		1
#define UPDATE_REQUEST		3
#define START_UE		5
#define STOP_UE			7
#define DELETE_REQUEST		9
#define ADMF_PACKET		10

#define SAFE_DELETE(p)		{ if (p) { delete(p); (p) = NULL; } }

#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


class AdmfInterface;
class DAdmfInterface;
class AdmfController;
class LegacyAdmfInterface;
class ConfigParser;


/**
 * @brief  : Maintains ADMF configurations read from config file
 */
typedef struct configurations {
	std::string			dadmfIp;
	std::string			legacyInterfaceIp;
	uint16_t			dadmfPort;
	uint16_t			admfPort;
	std::string			admfIp;
} configurations_t;

typedef struct legacyAdmfIntfcConfig {
	std::string			admfIp;
	std::string			legacyAdmfIp;
	uint16_t			admfPort;
	uint16_t			legacyAdmfPort;
	uint16_t			legacyAdmfIntfcPort;
	enum protocol 			{tcp, udp, rest};
	protocol 			interfaceProtocol;
	
} legacy_admf_intfc_config_t;

#pragma pack(push, 1)
typedef struct admfPacket {
        uint32_t                        packetLength;

        struct ueEntry {
                uint64_t                seqId;
                uint64_t                imsi;
                uint16_t                packetType;
                uint16_t                requestType;
                UChar                   startTime[21];
                UChar                   stopTime[21];
        } ue_entry_t;
} admf_packet_t;
#pragma pack(pop)

std::string
ConvertIpForRest(const std::string &strIp);


class AdmfApplication
{
	public:
		AdmfApplication() : mpAdmfInterface(NULL), mpLegacyAdmfInterface(NULL), 
					mpAdmfWorker(NULL)
		{
		}

		~AdmfApplication()
		{
		}

		/**
		 * @brief  : Initializes all required objects
		 * @param  : opt, command-line parameter
		 * @return : Returns nothing
		 */
		void startup(EGetOpt &opt, BaseLegacyAdmfInterface *legacyAdmfIntfc);

		/**
		 * @brief  : Deletes all the initialized objects before exiting the process
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void shutdown();

		/**
		 * @brief  : Sets shutdown event of EpcTools on handling the signal
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void setShutdownEvent() { mShutdown.set(); }

		/**
		 * @brief  : Waits until process is killed or shutdown event is set
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void waitForShutdown() { mShutdown.wait(); }

		/**
		 * @brief  : Getter method to fetch AdmfController reference
		 * @param  : No param
		 * @return : Returns reference to admfController
		 */
		AdmfController &getAdmfController() { return *mpAdmfWorker; }

		/**
                 * @brief  : Getter method to fetch DadmfInterface reference
                 * @param  : No param
                 * @return : Returns reference to dadmfInterface
                 */
		DAdmfInterface &getDadmfInterface() { return *mpDadmfInterface; }

		/**
                 * @brief  : Getter method to fetch AdmfInterface reference
                 * @param  : No param
                 * @return : Returns reference to admfInterface
                 */
		AdmfInterface &getAdmfInterface() { return *mpAdmfInterface; }

		/**
                 * @brief  : Getter method to fetch LegacyAdmfInterface reference
                 * @param  : No param
                 * @return : Returns reference to legacyAdmfInterface
                 */
		BaseLegacyAdmfInterface &getLegacyAdmfInterface() { return *mpLegacyAdmfInterface; }

		/**
		 * @brief  : Setter method to set LegacyAdmfInterface reference created
				by dynamic loading of library.
		 * @param  : ptr, pointer pointing to class object in library
		 * @return : Returns nothing
		 */
		void setLegacyAdmfInterface(BaseLegacyAdmfInterface *ptr)
		{ mpLegacyAdmfInterface = ptr; }

		/**
		 * @brief  : Getter method to fetch Ue entries which has not received ACK
		 * @param  : No param
		 * @return : Returns reference to map containing Ue entries.
		 */
		std::map<uint64_t, ack_t> &getMapPendingAck()
		{
			return mapPendingAck;
		}

		/**
		 * @brief  : Setter method to add Ue entry which has not received ACK
		 * @param  : ackMap, map containing Ue entries
		 * @return : Returns nothing
		 */
		void setMapPendingAck(const std::map<uint64_t, ack_t> ackMap)
		{
			mapPendingAck = ackMap;
		}

	private:
		AdmfInterface *mpAdmfInterface;
		DAdmfInterface *mpDadmfInterface;
		BaseLegacyAdmfInterface *mpLegacyAdmfInterface;
		EEvent mShutdown;
		AdmfController *mpAdmfWorker;

		std::map<uint64_t, ack_t> mapPendingAck;

};

#endif /* __ADMF_APP_H_ */
