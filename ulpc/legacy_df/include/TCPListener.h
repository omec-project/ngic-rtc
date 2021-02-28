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

#ifndef __TCPListener_H_
#define __TCPListener_H_


#include "Common.h"
#include "TCPDataProcessor.h"

class DdfListener;
class TCPDataProcessor;

class TCPListener : public ESocket::ThreadPrivate {

	public:

		/*
		 *	@brief	:	Constructor of class TCPListener
		 */
		TCPListener();
		/*
		 *	@brief	:	Constructor of class TCPListener
		 */
		~TCPListener();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onInit();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onQuit();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onClose();

		/*
		 *	@brief	:	Functionto indicate socket exception
		 *	@param	:	err, error type
		 *	@param	:	psocket, socket
		 *	@return	:	Returns void
		 */
		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		/*
		 *	@brief	:	Function creates instance of TCPDataProcessor
		 *	@param	:	No function arguments
		 *	@return	:	Returns TCPDataProcessor instance
		 */
		TCPDataProcessor *createDdfTalker();

		/* Void sendAck(DdfAckPacket_t &ackPacket); */

		/*
		 *	@brief	:	Function to fetch/create name of file to dump packet
		 *	@param	:	uiImsi, contains IMSI
		 *	@param	:	uiID, li identifier
		 *	@return	:	Returns pcap_dumper_t
		 */
		pcap_dumper_t * getPcapDumper(const uint64_t uiImsi, const uint64_t uiId);

		/*
		 *	@brief	:	Function to free pcap dumper map
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		void freePcapDumper();

		/*
		 *	@brief	:	Function to delete instance of TCPDataProcessor
		 *				on socket close, also tries re-connect to DF
		 *	@param	:	psocket, socket
		 *	@return	:	Returns void
		 */
		Void onSocketClosed(ESocket::BasePrivate *psocket);
	
	private:
		DdfListener *m_ptrListener = NULL;
		std::list<TCPDataProcessor *> m_ptrDataProcessor;
		std::map<std::string, pcap_dumper_t *> mapPcapDumper;
};


#endif /* __TCPListener_H_ */
