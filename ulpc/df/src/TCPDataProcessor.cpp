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

#include "Controller.h"
#include "TCPDataProcessor.h"


extern struct Configurations config;
uint32_t TCPDataProcessor::sequence_numb = 1;


DfListener::DfListener(TCPListener &thread)
	: ESocket::TCP::ListenerPrivate(thread)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


DfListener::~DfListener()
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


ESocket::TCP::TalkerPrivate *
DfListener::createSocket(ESocket::ThreadPrivate &thread)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: Talker object created.", __func__);

	return ((TCPListener &)thread).createDfTalker();
}


Void
DfListener::onClose()
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


Void
DfListener::onError()
{
	ELogger::log(LOG_SYSTEM).debug("{} :: DfListener socket error {}",
			__func__, getError());
}


TCPDataProcessor::TCPDataProcessor(TCPListener &thread)
	: ESocket::TCP::TalkerPrivate(thread)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


TCPDataProcessor::~TCPDataProcessor()
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


void
TCPDataProcessor::processPacket(uint8_t *buffer)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);

	DfPacket_t *dfPacket = (DfPacket_t *) buffer;

	ELogger::log(LOG_SYSTEM).debug("{} :: df packet packet details", __func__);
	ELogger::log(LOG_SYSTEM).debug("Packet length {}", ntohl(dfPacket->packetLength));
	ELogger::log(LOG_SYSTEM).debug("Sequence number {}", ntohl(dfPacket->header.sequenceNumber));
	ELogger::log(LOG_SYSTEM).debug("IMSI {}", dfPacket->header.imsiNumber);
	ELogger::log(LOG_SYSTEM).debug("LI identifier {}", dfPacket->header.liIdentifier);
	ELogger::log(LOG_SYSTEM).debug("Data length {}", ntohl(dfPacket->header.dataLength));
	ELogger::log(LOG_SYSTEM).debug("Data received is  {}", dfPacket->data);

	sendAck(dfPacket->header.sequenceNumber);

	((TCPListener &)getThread()).processData((DfPacket_t *) buffer);

	delete buffer;
	buffer = NULL;
}


Void
TCPDataProcessor::onConnect()
{
	UShort localPort =  getLocalPort();
	UShort remotePort =  getRemotePort();
	EString remoteIpAddress = getRemoteAddress();
	EString localIpAddr =  getLocalAddress();

	ELogger::log(LOG_SYSTEM).info("{} :: Client connected to DF server"
			" localIp={} localPort={} remoteIp={} remotePort={}", __func__,
			localIpAddr, localPort, remoteIpAddress, remotePort);
}


Void
TCPDataProcessor::onReceive()
{
	int ret = 0;
	uint8_t *packet = NULL;
	uint32_t packetLength = 0;

	try {

		while (true) {

			if (bytesPending() < (Int)sizeof(packetLength)) {
				break;
			}

			peek((pUChar)&packetLength, sizeof(packetLength));

			packetLength = ntohl(packetLength);

			ret = bytesPending();
			if (ret < (Int)packetLength) {
				break;
			}

			ELogger::log(LOG_SYSTEM).info("{} :: Received {} no of bytes on DF from remote ip {} bytes pending {}",
				__func__, packetLength, getRemoteAddress(), ret);

			packet = new uint8_t[packetLength];
			if (NULL == packet) {

				ELogger::log(LOG_SYSTEM).critical("{} :: Error while allocating {}"
						" bytes memory", __func__, packetLength);

				getThread().quit();

				break;
			}

			std::memset(packet, 0, packetLength);

			if (read(packet, (Int)packetLength) != (Int)packetLength) {

				ELogger::log(LOG_SYSTEM).critical("{} :: Error reading packet data"
						" from DDF client - unable to read {} bytes", __func__, packetLength);

				getThread().quit();

				break;
			}

			ELogger::log(LOG_SYSTEM).debug("{} :: DF packet sending for processing", __func__);

			if (NULL != packet) {

				processPacket(packet);
			}
		}
	}
	catch (const std::exception &e) {

		ELogger::log(LOG_SYSTEM).critical("{} :: DdfClient excption: {}",
				__func__, e.what());
	}
}


Void
TCPDataProcessor::onClose()
{
}


Void
TCPDataProcessor::onError()
{
	ELogger::log(LOG_SYSTEM).minor("{} :: DF socket error {}",
			__func__, getError());
}


Void
TCPDataProcessor::sendAck(uint32_t seqNbr)
{
	AckPacket_t *packet = new AckPacket_t;
	if (NULL == packet) {

		ELogger::log(LOG_SYSTEM).critical("{} :: Error while allocating {}"
				" bytes memory", __func__, sizeof(AckPacket_t));

		getThread().quit();
		return;
	}

	std::memset(packet, 0, sizeof(AckPacket_t));

	packet->packetLength = sizeof(AckPacket_t);
	packet->header.packetType = DFPACKET_ACK;
	packet->header.sequenceNumber = htonl(seqNbr);

	ELogger::log(LOG_SYSTEM).debug("{} :: Sending DFPACKET_ACK to D-DF", __func__);
	ELogger::log(LOG_SYSTEM).debug("Packet length {}", packet->packetLength);
	ELogger::log(LOG_SYSTEM).debug("Packet type {}", packet->header.packetType);
	ELogger::log(LOG_SYSTEM).debug("Sequence number {}", packet->header.sequenceNumber);

	write((pUChar)packet, packet->packetLength);

	delete packet;
	packet = NULL;
}
