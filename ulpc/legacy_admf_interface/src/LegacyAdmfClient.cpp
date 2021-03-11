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


#include "LegacyAdmfClient.h"
#include "LegacyAdmfInterfaceThread.h"
#include "Common.h"


LegacyAdmfClient :: LegacyAdmfClient(LegacyAdmfInterfaceThread &thread)
	: ESocket::TCP::TalkerPrivate(thread)
{
	LegacyAdmfInterface::log().debug("LeacyAdmfClient constructor");
}

LegacyAdmfClient :: ~LegacyAdmfClient()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfClient destructor");
}

Void
LegacyAdmfClient :: onConnect()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfClient :: onConnect()");
}

Void
LegacyAdmfClient :: onReceive()
{
	unsigned char buffer[4096];
	uint32_t packetLen = 0;
	LegacyAdmfInterface::log().debug("LegacyAdmfClient :: onReceive()");

	admf_intfc_packet_t *packet = (admf_intfc_packet_t *)buffer;

	try {
		while(true) {
			if (bytesPending() < (Int)sizeof(admfIntfcPacket::packetLength) ||
				peek((pUChar)&packetLen, sizeof(admfIntfcPacket::packetLength)) !=
				sizeof(admfIntfcPacket::packetLength)) {

				break;
			}

			if (bytesPending() < (Int)packetLen) {
				break;
			}

			if (read(buffer,packetLen) != (Int)packetLen) {
				LegacyAdmfInterface::log().debug("Error reading packet data - "
						"unable to read bytes : {}", packetLen);
				getThread().quit();
				break;
			}

			if (packet->ue_entry_t.packetType == LEGACY_ADMF_ACK) {

				LegacyAdmfInterface::log().info("ACK recieved from legacy admf for "
						" seqId: {}", packet->ue_entry_t.seqId);

				int8_t retValue = ((LegacyAdmfInterfaceThread&)getThread()).
						getLegacyAdmfInterface().sendAckToAdmf(packet);

				if (retValue == RETURN_SUCCESS) {

					LegacyAdmfInterface::log().info("ACK sent to admf");
					sendData(packet, ADMF_ACK);

				} else {

					LegacyAdmfInterface::log().debug("Failure while sending ack to admf.");

				}
			}

		}
		LegacyAdmfInterface::log().debug("Packet reading complete");

	} catch(const std::exception &e) {

		LegacyAdmfInterface::log().debug("LegacyAdmfClient Exception : {}", e.what());

	}
}

Void
LegacyAdmfClient :: onClose()
{
}

Void
LegacyAdmfClient :: onError()
{
	LegacyAdmfInterface::log().debug("Error in LegacyAdmfClient : "
			"Socket error : {}", getError());
}

Void
LegacyAdmfClient :: sendData(admf_intfc_packet_t *packet, uint16_t packetType)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfClient :: sendData()");

	UChar buffer[4096];

	admf_intfc_packet_t *pkt = (admf_intfc_packet_t*) buffer;
	std::memset(buffer, 0, sizeof(buffer));

	std::memset(pkt->ue_entry_t.startTime, 0, 21);
	std::memset(pkt->ue_entry_t.stopTime, 0, 21);

	pkt->ue_entry_t.seqId = packet->ue_entry_t.seqId;
	pkt->ue_entry_t.imsi = packet->ue_entry_t.imsi;

	std::memcpy(pkt->ue_entry_t.startTime, packet->ue_entry_t.startTime, 21);
	std::memcpy(pkt->ue_entry_t.stopTime, packet->ue_entry_t.stopTime, 21);

	pkt->ue_entry_t.packetType = packetType;
	pkt->ue_entry_t.requestType = packet->ue_entry_t.requestType;

	pkt->packetLength = sizeof(admf_intfc_packet_t);

	LegacyAdmfInterface::log().info("Sending packet to legacy admf for "
			"seqId: {} and packetType: {} with packetLength: {}",
			pkt->ue_entry_t.seqId, packetType, pkt->packetLength);

	write(buffer, pkt->packetLength);
}
