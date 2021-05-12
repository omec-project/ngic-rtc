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

#ifndef __TCPLISTENER_H_
#define __TCPLISTENER_H_


#include "common.h"
#include "tcp_forwardinterface.h"


class DdfListener;
class TCPForwardInterface;

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
		 *	@brief	:	Function connects to the DF
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void connect();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onTimer(EThreadEventTimer *ptimer);

		/*
		 *	@brief	:	Functionto indicate socket exception
		 *	@param	:	err, error type
		 *	@param	:	psocket, socket
		 *	@return	:	Returns void
		 */
		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		Void initDir(const uint8_t *ddf_ip, uint16_t port, const uint8_t *ddf_local_ip, uint8_t *mode);

		/*
		 *	@brief	:	Function to free pcap dumper map
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		void freePcapDumper();

		/*
		 *	@brief	:	Function sends packet to DF
		 *	@param	:	packet, packet/information to be sent
		 *	@return	:	Returns void
		 */
		Void sendPacketToDdf(DdfPacket_t *packet);

		/*
		 *	@brief	:	Function to delete instance of TCPDataProcessor
		 *				on socket close, also tries re-connect to DF
		 *	@param	:	psocket, socket
		 *	@return	:	Returns void
		 */
		Void onSocketClosed(ESocket::BasePrivate *psocket);

		/*
		 *	@brief	:	Function to delete instance of TCPDataProcessor
		 *				on socket close, also tries re-connect to DF
		 *	@param	:	psocket, socket
		 *	@return	:	Returns void
		 */
		Void onSocketError(ESocket::BasePrivate *psocket);

		/*
		 *	@brief	:	Function to start timer
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void startDfRetryTimer();

		/*
		 *	@brief	:	Function to stop timer
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void stopDfRetryTimer();

		/*
		 *	@brief	:	Function to indicate data is pending to send to DF
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void setPending();

		/*
		 *	@brief	:	Function sends pending data to DF
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void sendPending();

		/*
		 *	@brief	:	Function receives ack from DF and moves ptr to next packet,
		 *				for which ack is expected
		 *	@param	:	ack_number, acknowledgement number
		 *	@return	:	Returns void
		 */
		Void msgCounter(uint32_t ack_number);

		/*
		 *	@brief	:	Function creates folder to save database file
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void createFolder();

		/*
		 *	@brief	:	Function creates file to save packet
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		bool createFile();

		/*
		 *	@brief	:	Function to open the file and set pointer to file,
		 *				to read from it
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void readFile();

		/*
		 *	@brief	:	Function to delete database file
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void deleteFile();

		/*
		 *	@brief	:	Function to check space availability
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		bool checkAvailableSapce();

		/*
		 *	@brief	:	Function to check DF socket, get called from TCPForwardInterface
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void checkSocket();

		/*
		 *	@brief	:	Const function to get max number of msg used in semaphore
		 *	@param	:	No function arguments
		 *	@return	:	Returns long
		 */
		Long getMaxMsgs() const {

			return m_maxMsgs;
		}

		/*
		 *	@brief	:	Function to set max number of msg used in semaphore
		 *	@param	:	maxMsgs, max count of msg
		 *	@return	:	Returns this pointer
		 */
		TCPListener &setMaxMsgs(Long maxMsgs) {

			m_maxMsgs = maxMsgs;
			return *this;
		}

	private:
		Long m_maxMsgs;
		DdfListener *m_ptrListener = NULL;
		EThreadEventTimer m_dfRetryTimer;
		TCPForwardInterface *m_ptrForwardInterface = NULL;
		ESemaphorePrivate msg_cnt;

#define IP_ADDR_LEN_DDF 40

		uint8_t ipDdfAddr[IP_ADDR_LEN_DDF] = {'\0'};
		uint8_t ipDdfLocalAddr[IP_ADDR_LEN_DDF] = {'\0'};
		uint8_t *modeType = NULL;
		uint16_t portAddr = 0;
		

		std::ofstream fileWrite;                        /* file handler to write into file */
		std::ifstream fileRead;                         /* file handler to read from file */
		uint8_t writeBuf[SEND_BUF_SIZE];		/* buffer to write in file */
		uint8_t readBuf[SEND_BUF_SIZE];			/* buffer to read from file */
		uint8_t payloadBuf[SEND_BUF_SIZE];		/* buffer to read payload */

		std::vector<std::string> fileVect;              /* Vector to store file names */
		std::vector<std::string>::iterator vecIter;     /* Iterator for vector */

		uint16_t read_count = 0;                        /* Numb of packets read from file */
		uint16_t entry_cnt = 0;                         /* Numb of packets write into the file */
		uint16_t pkt_cnt = 0;                           /* Actual number of packets sent vs written into the file */

		bool timer_flag = 0;				/* flag to use same timer for re-connecting as \
								   well as to re-sending failed packets*/

		bool serveNextFile = 0;
		bool pending_data_flag = 0;                     /* Flag to indicate there is backlog to be send to DF */

		uint32_t read_bytes_track = 0;                  /* varible to track number of bytes read from the file */
		uint32_t send_bytes_track = 0;                  /* variable to track numb of bytes read from backlog to be sent to DF*/

		std::string file_name;                          /* Name of the current file in which packets ar being written/read from */
};


#endif /* __TCPLISTENER_H_ */
