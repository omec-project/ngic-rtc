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

#include "Common.h"
#include "TCPListener.h"


#define ERROR										-1

class TCPListener;

class DfListener : public ESocket::TCP::ListenerPrivate
{
	public:

		/*
		 *  @brief  :   Constructor of class DdfListener
		 */
		DfListener(TCPListener &thread);

		/*
		 *  @brief  :   Destructor of class DdfListener
		 */
		~DfListener();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onClose();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onError();

		ESocket::TCP::TalkerPrivate *createSocket(ESocket::ThreadPrivate &thread);

	private:
		/*
		 *  @brief  :   Constructor of class DdfListener
		 */
		DfListener();
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
		 *  @brief  :   Function to process data received from DDF
		 *  @param  :   buffer, collects packet/information to be processed
		 *  @return :   Returns void
		 */
		void processPacket(uint8_t *buffer);

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onConnect();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onReceive();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onClose();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onError();


		/*
		 *  @brief  :   Function to send packet acknowledgement CP/DP
		 *  @param  :   buffer, collects packet/information to be processed
		 *  @return :   Returns void
		 */
		Void sendAck(uint32_t seqNbr);

	private:
		/*
		 *	@brief	:	Constructor of class TCPDataProcessor
		 */
		TCPDataProcessor();

		static uint32_t sequence_numb;
};


#endif /* __PCAP_DATA_PROCESSOR_H_ */
