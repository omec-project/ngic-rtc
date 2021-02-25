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


DdfListener::DdfListener(TCPListener &thread)
	: ESocket::TCP::ListenerPrivate(thread)	
{
}


DdfListener::~DdfListener()
{
}


ESocket::TCP::TalkerPrivate *
DdfListener::createSocket(ESocket::ThreadPrivate &thread)
{
	return ((TCPListener &)thread).createDdfTalker();
}


Void
DdfListener::onClose()
{
}


Void
DdfListener::onError()
{
	ELogger::log(LOG_SYSTEM).debug("DdfListener socket error {}", getError());
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
	uint8_t *pktPtr = NULL;
	uint32_t packetLength = 0;

	DdfPacket *ddfPacket = (DdfPacket *) buffer;

	ddfPacket->packetLength = ntohl(ddfPacket->packetLength);
	ddfPacket->header.sourceIpAddress = ntohl(ddfPacket->header.sourceIpAddress);
	ddfPacket->header.sourcePort = ntohs(ddfPacket->header.sourcePort);
	ddfPacket->header.destIpAddress = ntohl(ddfPacket->header.destIpAddress);
	ddfPacket->header.destPort = ntohs(ddfPacket->header.destPort);
	ddfPacket->header.sequenceNumber = ntohl(ddfPacket->header.sequenceNumber);
	ddfPacket->header.dataLength = ntohl(ddfPacket->header.dataLength);

	ELogger::log(LOG_SYSTEM).debug("packet length {}", ddfPacket->packetLength);
	ELogger::log(LOG_SYSTEM).debug("type of payload {}", ddfPacket->header.typeOfPayload);
	ELogger::log(LOG_SYSTEM).debug("li identifier {}", ddfPacket->header.liIdentifier);
	ELogger::log(LOG_SYSTEM).debug("imsi number {}", ddfPacket->header.imsiNumber);
	ELogger::log(LOG_SYSTEM).debug("source ip address {}", ddfPacket->header.sourceIpAddress);
	ELogger::log(LOG_SYSTEM).debug("source port {}", ddfPacket->header.sourcePort);
	ELogger::log(LOG_SYSTEM).debug("destination ip address {}", ddfPacket->header.destIpAddress);
	ELogger::log(LOG_SYSTEM).debug("destination port {}", ddfPacket->header.destPort);
	ELogger::log(LOG_SYSTEM).debug("sequence number {}", ddfPacket->header.sequenceNumber);
	ELogger::log(LOG_SYSTEM).debug("Operation node {}", ddfPacket->header.operationMode);
	ELogger::log(LOG_SYSTEM).debug("Data length {}", ddfPacket->header.dataLength);

	pktPtr = createPacket(ddfPacket, &packetLength);
	
	if ((ddfPacket->header.operationMode == DEBUG_DATA) ||
			(ddfPacket->header.operationMode == BOTH_FW_DG)) {

		pcap_dumper_t *pcap_dumper = ((TCPListener &)getThread()).getPcapDumper(
				ddfPacket->header.imsiNumber, ddfPacket->header.liIdentifier);

		if ((pcap_dumper != NULL) && (pktPtr != NULL)) {

			dumpBufferInPcapFile(pcap_dumper, pktPtr, packetLength);
		}
	}


	/* send packet to df */
	if ((ddfPacket->header.operationMode == FORWARD_DATA) ||
			(ddfPacket->header.operationMode == BOTH_FW_DG)) {

		if (NULL != pktPtr) {

			uint32_t dfPacketLength = sizeof(DfPacket_t) + packetLength;
			UChar *packet = new UChar[dfPacketLength];
			if (NULL == packet) {

				ELogger::log(LOG_SYSTEM).critical("{} :: Error while allocating"
						" {} bytes memory", __func__, dfPacketLength);

				return;
			}

			std::memset(packet, 0, dfPacketLength);
			DfPacket_t *dfPacket = (DfPacket_t *) packet;

			dfPacket->packetLength = htonl(dfPacketLength);
			dfPacket->header.sequenceNumber = htonl(sequence_numb++);
			dfPacket->header.liIdentifier = ddfPacket->header.liIdentifier;
			dfPacket->header.imsiNumber = ddfPacket->header.imsiNumber;
			dfPacket->header.dataLength = htonl(packetLength);

			std::memcpy(dfPacket->data, pktPtr, packetLength);

			ELogger::log(LOG_SYSTEM).debug("{} :: Sending packet to DF details", __func__);
			ELogger::log(LOG_SYSTEM).debug("Packet length {}", ntohl(dfPacket->packetLength));
			ELogger::log(LOG_SYSTEM).debug("Sequence number {}", ntohl(dfPacket->header.sequenceNumber));
			ELogger::log(LOG_SYSTEM).debug("LI identifier {}", dfPacket->header.liIdentifier);
			ELogger::log(LOG_SYSTEM).debug("Imsi {}", dfPacket->header.imsiNumber);
			ELogger::log(LOG_SYSTEM).debug("Data length {}", ntohl(dfPacket->header.dataLength));

			((TCPListener &)getThread()).sendPacketToDf(dfPacket);

			if (NULL != packet) {

				delete packet;
				packet = NULL;
			}
		}
	}

	if (NULL != pktPtr) {

		delete pktPtr;
		pktPtr = NULL;
	}

	if (NULL != buffer) {
		delete buffer;
		buffer = NULL;
	}
}

uint8_t *
TCPDataProcessor::createPacket(DdfPacket *ddfPacket, uint32_t *packetLength)
{
	uint8_t *packet = NULL;

	if ((ddfPacket->header.typeOfPayload == EVENT_TYPE) &&
			(config.strDModuleName == DDF2)) {

		uint16_t iLen = ddfPacket->header.dataLength +
				sizeof(struct ether_header) + sizeof(struct iphdr) +
				sizeof(struct udphdr);

		*packetLength = iLen;

		packet = new uint8_t[iLen];
		std::memset(packet, 0, iLen);

		struct ether_header *eh = (struct ether_header *) packet;
		memset(eh, '\0', sizeof(struct ether_addr));
		eh->ether_type = htons(ETHER_TYPE);

		struct iphdr *ih = (struct iphdr *) &eh[1];
		ih->daddr = ddfPacket->header.destIpAddress;
		ih->saddr = ddfPacket->header.sourceIpAddress;
		ih->protocol = IPPROTO_UDP;
		ih->version = IP_VERSION;
		ih->ihl = INTERNET_HDR_LEN;
		ih->tot_len = htons(iLen - sizeof(ether_header));
		ih->ttl = TTL;

		struct udphdr *uh = (struct udphdr *) &ih[1];
		uh->len = htons(iLen - sizeof(ether_header) - sizeof(iphdr));
		uh->dest = htons(ddfPacket->header.destPort);
		uh->source = htons(ddfPacket->header.sourcePort);
		uh->check = UDP_CHECKSUM;

		void *payload = &uh[1];
		memcpy(payload, ddfPacket->data, ddfPacket->header.dataLength);
	}

	if (ddfPacket->header.typeOfPayload == DATA_TYPE) {

		*packetLength = ddfPacket->header.dataLength;

		packet = new uint8_t[ddfPacket->header.dataLength];
		std::memset(packet, 0, ddfPacket->header.dataLength);

		memcpy(packet, ddfPacket->data, ddfPacket->header.dataLength);
	}

	return packet;
}


void
TCPDataProcessor::dumpBufferInPcapFile(pcap_dumper_t *pcap_dumper,
			uint8_t *packet, uint32_t packetLength)
{
	struct pcap_pkthdr pcap_tx_header = {0};
	gettimeofday(&pcap_tx_header.ts, NULL);

	pcap_tx_header.caplen = packetLength;
	pcap_tx_header.len = packetLength;

	pcap_dump((u_char *) pcap_dumper, &pcap_tx_header, packet);
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

	ELogger::log(LOG_SYSTEM).info("Client connected to DDF server localIp={}"
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

			ELogger::log(LOG_SYSTEM).info("{} :: Received {} no of bytes from {} on D-DF. bytes pending {}",
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

			ELogger::log(LOG_SYSTEM).debug("{} :: DDF packet sending for processing", __func__);

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
	ELogger::log(LOG_SYSTEM).debug("DDF socket error {}", getError());
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

	ackPacket->packetLength = sizeof(AckPacket_t);
	ackPacket->header.packetType = DDFPACKET_ACK;
	ackPacket->header.sequenceNumber = htonl(sequenceNumber);

	ELogger::log(LOG_SYSTEM).debug("{} :: sending DDFPACKET_ACK to control plane"
			" or data plane for sequence number {}", __func__,
			ackPacket->header.sequenceNumber);

	write((pUChar)ackPacket, ackPacket->packetLength);

	delete ackPacket;
	ackPacket = NULL;
}

