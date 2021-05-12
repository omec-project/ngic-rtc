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

#include "tcp_forwardinterface.h"

extern struct Configurations config_li;


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

	clLog(STANDARD_LOGID, eCLSeverityInfo, LOG_FORMAT"Connected to "
		"DDF server localIP = %s, loaclPort = %hu, "
		"remoteIp = %s, remotePort = %hu",
		LOG_VALUE, localIp, localPort, remoteIp, remotePort);

	((TCPListener&)getThread()).setPending();

	return;
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

			clLog(STANDARD_LOGID, eCLSeverityInfo, LOG_FORMAT"Received %c no "
					"of bytes on LI library, Pending bytes %d ",
					LOG_VALUE, packetLength, ret);

                        if (ret < (Int)packetLength) {

                                break;
                        }

                        packet = new uint8_t[packetLength];
                        if (NULL == packet) {
				clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Error while "
						"allocating %c bytes of memory",
						LOG_VALUE, packetLength);

                                getThread().quit();

                                break;
                        }

                        std::memset(packet, 0, packetLength);

                        if (read(packet, packetLength) != (Int)packetLength) {
				clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Error Reading "
						"pcaket data, unable to read %c bytes",
						LOG_VALUE, packetLength);

                                getThread().quit();

                                break;
                        }

                        AckPacket_t *ackPacket = (AckPacket_t *) packet;
                        if (ackPacket->header.packetType == DDFPACKET_ACK) {

				clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Ack received "
						"from DDF for %u",
						LOG_VALUE, ntohl(ackPacket->header.sequenceNumber));
				
				((TCPListener &)getThread()).msgCounter(ntohl(ackPacket->header.sequenceNumber));
                        } else {

				clLog(STANDARD_LOGID, eCLSeverityMinor, LOG_FORMAT"Unexpected packetType "
						"value %c", LOG_VALUE, ackPacket->header.packetType);

                                break;
                        }

                        if (NULL != packet) {

                                delete packet;
                                packet = NULL;
                        }
                }
        }
        catch (const std::exception &e) {
		clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"TCPForwardInterface excption: %s",
				LOG_VALUE, e.what());
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
	clLog(STANDARD_LOGID, eCLSeverityMinor, LOG_FORMAT"LI library "
			"socket error  %d",
			LOG_VALUE, getError());
	onClose();
}

Void
TCPForwardInterface::sendData(DdfPacket_t *pkt)
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"sending " 
			"DFPACKET_DATA for sequence number %u "
			"packet length %u",
			LOG_VALUE, ntohl(pkt->header.sequenceNumber), 
			ntohl(pkt->packetLength));

	try {
		write((pUChar)pkt, (Int)ntohl(pkt->packetLength));
	}
	catch (const  ESocket::TcpTalkerError_SendingPacket &e)
	{
		clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Error : %s",
				LOG_VALUE, e.what());
	}
}
