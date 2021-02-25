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


#include "LegacyAdmfInterfaceTalker.h"
#include "Common.h"

LegacyAdmfInterfaceTalker :: 
LegacyAdmfInterfaceTalker(LegacyAdmfInterfaceThread &thread)
	: ESocket::TCP::TalkerPrivate(thread)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceTalker constructor");
}

LegacyAdmfInterfaceTalker ::
~LegacyAdmfInterfaceTalker()
{
}

Void
LegacyAdmfInterfaceTalker :: onConnect()
{
	LegacyAdmfInterface::log().debug("legacyAdmfClient connected");
}

Void
LegacyAdmfInterfaceTalker :: onReceive()
{
	uint8_t *packet = NULL;
	uint32_t packetLength = 0;
	UeDatabase *pkt = NULL;

	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceTalker onReceive()");

	try {
		while(true) {
			if (bytesPending() < (Int)sizeof(UeDatabase::packetLen) || 
					peek((pUChar)&packetLength, sizeof(UeDatabase::packetLen)) != 
					sizeof(UeDatabase::packetLen)) {
				break;

			}

			if (bytesPending() < (Int)packetLength) {
				break;
			}

			packet = new uint8_t[packetLength];
			std::memset(packet, 0, packetLength);

			if (read(packet, (Int)packetLength) != (Int)packetLength) {

				LegacyAdmfInterface::log().debug("Error reading packet data from "
						"Interface client - unable to read bytes: {}", packetLength);
				getThread().quit();
				break;
			}

			pkt = (UeDatabase *)packet;

			if (pkt->ue_entry_t.packetType == LEGACY_ADMF_PACKET) {

				LegacyAdmfInterface::log().info("Request received from legacy admf");
				LegacyAdmfInterface::log().debug("RequestBody: {}", 
						pkt->ue_entry_t.requestBody);

				char* jsonBody = new char[pkt->ue_entry_t.bodyLength];
				std::memset(jsonBody, 0, pkt->ue_entry_t.bodyLength);
				std::memcpy(jsonBody, pkt->ue_entry_t.requestBody, 
						pkt->ue_entry_t.bodyLength);

				int8_t ret = ((LegacyAdmfInterfaceThread&)getThread()).
                                                getLegacyAdmfInterface().
						sendRequestToAdmf(pkt->ue_entry_t.requestType, jsonBody);

				if (ret == RETURN_SUCCESS) {

					LegacyAdmfInterface::log().info("Curl request sent to Admf");
					pkt->ue_entry_t.packetType = ADMF_INTFC_ACK;
					pkt->ue_entry_t.requestStatus = RETURN_SUCCESS;
					LegacyAdmfInterface::log().debug("Writing packet back to legacy admf");
					write((pUChar)pkt, pkt->packetLen);

				} else {

					pkt->ue_entry_t.packetType = ADMF_INTFC_ACK;
					pkt->ue_entry_t.requestStatus = RETURN_FAILURE;
					LegacyAdmfInterface::log().debug("Failure while sending packet to admf");
					write((pUChar)pkt, pkt->packetLen);
				}

			} else {
				LegacyAdmfInterface::log().debug("Unexpected legacyAdmf packetType value ",
						pkt->ue_entry_t.packetType);
         		}

		}

	} catch (const std::exception &e) {
		LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceTalker :: "
				"LegacyAdmfClient exception: ", e.what());
		getThread().quit();
	}
}

Void
LegacyAdmfInterfaceTalker :: onClose()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceTalker onClose()");
}

Void
LegacyAdmfInterfaceTalker :: onError()
{
	LegacyAdmfInterface::log().debug("Error occurred in "
			"LegacyAdmfInterfaceTalker");
}

Void
LegacyAdmfInterfaceTalker :: sendAck(uint32_t seqNum)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceTalker sendAck()");
	std::string ackMsg("Request received");
	write((pUChar)(ackMsg).c_str(), (Int)ackMsg.size());
}
