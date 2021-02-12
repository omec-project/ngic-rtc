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

#include "TCPForwardInterface.h"


extern struct Configurations config;


TCPForwardInterface::TCPForwardInterface(TCPListener &thread)
	   : ESocket::TCP::TalkerPrivate(thread)
{
}


TCPForwardInterface :: ~TCPForwardInterface()
{
}


Void
TCPForwardInterface::onConnect()
{
	UShort localPort = getLocalPort();
	UShort remotePort = getRemotePort();
	EString localIp = getLocalAddress();
	EString remoteIp = getRemoteAddress();

	ELogger::log(LOG_SYSTEM).info("connected to DF server localIp={} localPort={}"
			" remoteIp={} remotePort={}", localIp, localPort, remoteIp, remotePort);

	((TCPListener&)getThread()).setPending();
}


Void
TCPForwardInterface::onReceive()
{
	Int ret = 0;
	uint8_t *packet = NULL;
	uint8_t packetLength = 0;

	try {

		while (true) {

			if ((bytesPending() < (Int)sizeof(packetLength)) ||
					(peek((pUChar)&packetLength, sizeof(packetLength)) != sizeof(packetLength))) {

				break;
			}

			ret = bytesPending();

			ELogger::log(LOG_SYSTEM).info("{} :: Received {} no of bytes on D-DF from DF. Pending bytes {}",
					__func__, packetLength, ret);

			if (ret < (Int)packetLength) {

				break;
			}

			packet = new uint8_t[packetLength];
			if (NULL == packet) {

				ELogger::log(LOG_SYSTEM).critical("Error while allocating {} bytes memory",
						packetLength);
				getThread().quit();

				break;
			}

			std::memset(packet, 0, packetLength);

			if (read(packet, packetLength) != (Int)packetLength) {

				ELogger::log(LOG_SYSTEM).critical("Error reading packet data from DF"
						" server - unable to read {} bytes", packetLength);
				getThread().quit();

				break;
			}

			AckPacket_t *ackPacket = (AckPacket_t *) packet;
			if (ackPacket->header.packetType == DFPACKET_ACK) {

				ELogger::log(LOG_SYSTEM).debug("ACK received from DF for [{}]",
						ntohl(ackPacket->header.sequenceNumber));

				/* process ack which is received from df */
				((TCPListener &)getThread()).msgCounter(ackPacket->header.sequenceNumber);
			} else {

				ELogger::log(LOG_SYSTEM).minor("Unexpected DF packetType value [{}]",
						ackPacket->header.packetType);

				break;
			}

			if (NULL != packet) {

				delete packet;
				packet = NULL;
			}
		}
	}
	catch (const std::exception &e) {

		ELogger::log(LOG_SYSTEM).critical("TCPForwardInterface excption: {}", e.what());
	}
}


Void
TCPForwardInterface::onClose()
{
	((TCPListener &)getThread()).checkSocket();
}


Void
TCPForwardInterface::onError()
{
	ELogger::log(LOG_SYSTEM).minor("DF socket error {}", getError());

	onClose();
}


Void
TCPForwardInterface::sendData(const DfPacket_t *pkt)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: sending DFPACKET_DATA for sequence"
			" number {} packet length {}", __func__,
			ntohl(pkt->header.sequenceNumber), ntohl(pkt->packetLength));

	try {
		write((pUChar)pkt, (Int)ntohl(pkt->packetLength));
	}
	catch (const  ESocket::TcpTalkerError_SendingPacket &e)
	{
		ELogger::log(LOG_SYSTEM).critical("{} :: Error {}", __func__, e.what());
		getThread().quit();
	}
}
