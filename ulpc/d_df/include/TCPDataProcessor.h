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

#ifndef __PCAP_DATA_PROCESSOR_H_
#define __PCAP_DATA_PROCESSOR_H_


#include <pcap.h>

#include "Common.h"
#include "TCPListener.h"


#define ERROR										-1
#define UDP_LEN										4096

class TCPListener;

class DdfListener : public ESocket::TCP::ListenerPrivate
{
	public:

		/*
		 *	@brief	:	Constructor of class DdfListener
		 */
		DdfListener(TCPListener &thread);

		/*
		 *	@brief	:	Destructor of class DdfListener
		 */
		~DdfListener();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onClose();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onError();

		/*
		 *	@brief	:	Function to create the instance of DDF talker
		 *	@param	:	thread, TCPListener thread
		 *	@return	:	Returns instance of talker
		 */
		ESocket::TCP::TalkerPrivate *createSocket(ESocket::ThreadPrivate &thread);

	private:

		/*
		 *	@brief	:	Constructor of class DdfListener
		 */
		DdfListener();
};

class TCPDataProcessor : public ESocket::TCP::TalkerPrivate
{
	public:
		/*
		 *	@brief	:	Constructor of class TCPDataProcessor
		 */
		TCPDataProcessor(TCPListener &thread);

		/*
		 *	@brief	:	Destructor of class TCPDataProcessor
		 */
		virtual ~TCPDataProcessor();

		/*
		 *	@brief	:	Function to create packet
		 *	@param	:	ddfPacket, DDFPacket pointer
		 *	@param	:	packetLength, Packet Length
		 *	@return	:	Returns packet
		 */

		uint8_t * createPacket(DdfPacket *ddfPacket, uint32_t *packetLength);

		/*
		 *	@brief	:	Function to dump packet buffer pcap in file
		 *	@param	:	pcap_dumper, pointer to pcap_dumper_t
		 *	@param	:	pktPtr, packet for dump
		 *	@param	:	packetLength,packet Length
		 *	@return	:	Returns nothing
		 */
		void dumpBufferInPcapFile(pcap_dumper_t *pcap_dumper, uint8_t *pktPtr,
				uint32_t packetLength);

		/*
		 *	@brief	:	Function to process data received from CP/DP
		 *	@param	:	buffer, collects packet/information to be processed
		 *	@return	:	Returns void
		 */
		void processPacket(uint8_t *buffer);

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onConnect();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onReceive();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onClose();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onError();

		/*
		 *	@brief	:	Function to send packet acknowledgement CP/DP
		 *	@param	:	buffer, collects packet/information to be processed
		 *	@return	:	Returns void
		 */
		Void sendAck(const uint32_t &sequenceNumber);

	private:

		/*
		 *	@brief	:	Constructor of class TCPDataProcessor
		 */
		TCPDataProcessor();

		std::string remoteIpAddress;
		static uint32_t sequence_numb;
};


#endif /* __PCAP_DATA_PROCESSOR_H_ */
