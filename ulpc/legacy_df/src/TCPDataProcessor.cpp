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


LegacyDfListener::LegacyDfListener(TCPListener &thread)
	: ESocket::TCP::ListenerPrivate(thread)
{
}


LegacyDfListener::~LegacyDfListener()
{
}


ESocket::TCP::TalkerPrivate *
LegacyDfListener::createSocket(ESocket::ThreadPrivate &thread)
{
	/* check return value foor NULL*/
	return ((TCPListener &)thread).createDdfTalker();
}


Void
LegacyDfListener::onClose()
{
}


Void
LegacyDfListener::onError()
{
	ELogger::log(LOG_SYSTEM).debug("LegacyDfListener socket error {}", getError());
}


TCPDataProcessor::TCPDataProcessor(TCPListener &thread)
	: ESocket::TCP::TalkerPrivate(thread)
{
}

TCPDataProcessor::~TCPDataProcessor()
{
}


void
TCPDataProcessor::processPacket(uint8_t *buffer)
{
	DfPacket_t *dfPacket = (DfPacket_t *) buffer;

	dfPacket->packetLength = ntohl(dfPacket->packetLength);
	dfPacket->header.sequenceNumber = ntohl(dfPacket->header.sequenceNumber);
	dfPacket->header.dataLength = ntohl(dfPacket->header.dataLength);

	ELogger::log(LOG_SYSTEM).debug("{} :: Received packet packet details", __func__);
	ELogger::log(LOG_SYSTEM).debug("Packet length {}", dfPacket->packetLength);
	ELogger::log(LOG_SYSTEM).debug("Sequence number {}", dfPacket->header.sequenceNumber);
	ELogger::log(LOG_SYSTEM).debug("LI Identifier {}", dfPacket->header.liIdentifier);
	ELogger::log(LOG_SYSTEM).debug("IMSI {}", dfPacket->header.imsiNumber);
	ELogger::log(LOG_SYSTEM).debug("Data length {}", dfPacket->header.dataLength);
	pcap_dumper_t *pcap_dumper = ((TCPListener &)getThread()).getPcapDumper(
			dfPacket->header.imsiNumber, dfPacket->header.liIdentifier);

	if ((pcap_dumper != NULL) && (NULL != dfPacket->data)) {

		dumpBufferInPcapFile(pcap_dumper, dfPacket->data, dfPacket->header.dataLength);
	}

	/* send acknowledgement to control plane and data plane */
	sendAck(dfPacket->header.sequenceNumber);

	if (NULL != buffer) {
                delete buffer;
                buffer = NULL;
        }
}

void
TCPDataProcessor::dumpBufferInPcapFile(pcap_dumper_t *pcap_dumper,
				uint8_t *dump_buf, uint32_t packetLength)
{
	struct pcap_pkthdr pcap_tx_header = {0};
	gettimeofday(&pcap_tx_header.ts, NULL);

	pcap_tx_header.caplen = packetLength;
	pcap_tx_header.len = packetLength;

	pcap_dump((u_char *) pcap_dumper, &pcap_tx_header, dump_buf);
	fflush(pcap_dump_file(pcap_dumper));
}


Void
TCPDataProcessor::onConnect()
{
	UShort localPort =  getLocalPort();
	UShort remotePort =  getRemotePort();
	std::string line = getRemoteAddress();
	EString localIpAddr =  getLocalAddress();

	std::stringstream stream(line);

	while(getline(stream, remoteIpAddress, ':'));

	ELogger::log(LOG_SYSTEM).info("Client connected to Legacy DF server localIp={}"
			" localPort={} remoteIp={} remotePort={}", localIpAddr, localPort,
			remoteIpAddress, remotePort);
}


Void
TCPDataProcessor::onReceive()
{
	Int ret = 0;
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

			ELogger::log(LOG_SYSTEM).info("{} :: Received {} no of bytes from {} on Legacy DF. bytes pending {}",
                                        __func__, packetLength, remoteIpAddress, ret);
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

			if (read(packet, (Int)packetLength) != (Int)packetLength) {

				ELogger::log(LOG_SYSTEM).critical("Error reading packet data from DDF client -"
						"unable to read {} bytes", packetLength);
				getThread().quit();

				break;
			}

			ELogger::log(LOG_SYSTEM).debug("{} :: Legacy DF packet sending for processing", __func__);

			if (NULL != packet) {

				processPacket(packet);
			}
		}
	}
	catch (const std::exception &e) {

		ELogger::log(LOG_SYSTEM).critical("DdfClient excption: {}", e.what());
	}
}


Void
TCPDataProcessor::onClose()
{
}


Void
TCPDataProcessor::onError()
{
	ELogger::log(LOG_SYSTEM).minor("Legacy DF socket error {}", getError());
}


Void
TCPDataProcessor::sendAck(const uint32_t &sequenceNumber)
{
	AckPacket_t *ackPacket = new AckPacket_t;
	if (NULL == ackPacket) {

		ELogger::log(LOG_SYSTEM).critical("{} :: Error while allocating {}"
				" bytes memory", __func__, sizeof(AckPacket_t));

		getThread().quit();
		return;
	}

	std::memset(ackPacket, 0, sizeof(AckPacket_t));

	uint32_t tempLen = sizeof(AckPacket_t);
	ackPacket->packetLength = (tempLen);
	ackPacket->header.packetType = LEGACY_DF_ACK;
	ackPacket->header.sequenceNumber = htonl(sequenceNumber);

	ELogger::log(LOG_SYSTEM).debug("{} :: sending DFPACKET_ACK to DF"
			" for sequence number {} Len  {}", __func__,
			ntohl(ackPacket->header.sequenceNumber), ackPacket->packetLength);

	ELogger::log(LOG_SYSTEM).info("Sending ACK with seq numb {}", ntohl(ackPacket->header.sequenceNumber));
	write((pUChar)ackPacket, (ackPacket->packetLength));

	delete ackPacket;
	ackPacket = NULL;
}

