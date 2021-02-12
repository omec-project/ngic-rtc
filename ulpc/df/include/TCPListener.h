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


class DfListener;
class TCPDataProcessor;

class TCPListener : public ESocket::ThreadPrivate {

	public:

		/*
		 *  @brief  :   Constructor of class TCPListener
		 */
		TCPListener();

		/*
		 *  @brief  :   Destructor of class TCPListener
		 */
		~TCPListener();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onInit();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onQuit();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onClose();

		/*
		 *  @brief  :   Function connects to the Legacy DF
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void connect();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onTimer(EThreadEventTimer *ptimer);


		/*
		 *  @brief  :   Functionto indicate socket exception
		 *  @param  :   err, error type
		 *  @param  :   psocket, socket
		 *  @return :   Returns void
		 */
		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		/*
		 *  @brief  :   Function tries to initialise legacy interface
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void InitLegacyAgain();

		/*
		 *  @brief  :   Function to start timer
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void startDfRetryTimer();

		/*
		 *  @brief  :   Function to stop timer
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void stopDfRetryTimer();


		/*
		 *  @brief  :   Function creates instance of TCPDataProcessor
		 *  @param  :   No function arguments
		 *  @return :   Returns TCPDataProcessor instance
		 */
		TCPDataProcessor *createDfTalker();

		/*
		 *  @brief  :   Function to process data received from DDF
		 *  @param  :   packet, object of struct DfPacket_t
		 *  @return :   Returns void
		 */
		Void processData(DfPacket_t *packet);

		/*
		 *  @brief  :   Function to delete instance of TCPDataProcessor
		 *              on socket close, also tries re-connect to DF
		 *  @param  :   psocket, socket
		 *  @return :   Returns void
		 */
		Void onSocketClosed(ESocket::BasePrivate *psocket);

		/*
		 *  @brief  :   Const function to get max number of msg used in semaphore
		 *  @param  :   No function arguments
		 *  @return :   Returns long
		 */
		Long getMaxMsgs() const {

			return m_maxMsgs;
		}

		/*
		 *  @brief  :   Function to set max number of msg used in semaphore
		 *  @param  :   maxMsgs, max count of msg
		 *  @return :   Returns this pointer
		 */
		TCPListener &setMaxMsgs(Long maxMsgs) {

			m_maxMsgs = maxMsgs;
			return *this;
		}

		/*
		 *  @brief  :   Function to indicate data is pending to send to legacy DF
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void setPending();

		/*
		 *  @brief  :   Function sends pending data to legacy DF
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void sendPending();

		/*
		 *  @brief  :   Function receives ack from legacy DF and moves ptr to next packet,
		 *              for which ack is expected
		 *  @param  :   ack_number, acknowledgement number
		 *  @return :   Returns void
		 */
		Void msgCounter(uint32_t ack_number);

		/*
		 *  @brief  :   Function creates folder to save database file
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void createFolder();

		/*
		 *  @brief  :   Function creates file to save packet
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		bool createFile();

		/*
		 *  @brief  :   Function to open the file and set pointer to file,
		 *              to read from it
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void readFile();

		/*
		 *  @brief  :   Function to delete database file
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void deleteFile();

		/*
		 *  @brief  :   Function to check space availability
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		bool checkAvailableSapce();

		/*
		 *  @brief  :   Function to check DF socket, get called from TCPForwardInterface
		 *  @param  :   No function arguments
		 *  @return :   Returns void
		 */
		Void checkSocket();

		/*
		 *  @brief  :   Function to set BaseLegacyInterface pointer value
		 *  @param  :   ptr, object of BaseLegacyInterface
		 *  @return :   Returns void
		 */
		Void setIntfcPtr(BaseLegacyInterface *ptr);

		Void resetFlag();
	private:
		Long m_maxMsgs;
		DfListener *m_ptrListener = NULL;
		EThreadEventTimer m_dfRetryTimer;
		std::list<TCPDataProcessor *> m_ptrDataProcessor;
		BaseLegacyInterface *m_legacyIntfc = NULL;
		ESemaphorePrivate msg_cnt;

		std::ofstream fileWrite;                        /* file handler to write into file */
		std::ifstream fileRead;                         /* file handler to read from file */
		int32_t read_bytes_track = 0;                  /* varible to track number of bytes read from the file */

		std::vector<std::string> fileVect;              /* Vector to store file names */
		std::vector<std::string>::iterator vecIter;     /* Iterator for vector */

		int16_t read_count = 0;                        /* Numb of packets read from file */
		int16_t entry_cnt = 0;                         /* Numb of packets write into the file */
		int16_t pkt_cnt = 0;                           /* Actual number of packets sent vs written into the file */

		std::atomic<bool> legacy_conn;		/* flag to indicate connection status with legacy Df */
		bool serveNextFile = 0;

		bool timer_flag = 0;                            /* flag to use same timer for re-connecting as \
									well as to re-sending failed packets*/
		
		bool pending_data_flag = 0;                     /* Flag to indicate there is backlog to be send to legacy DF */
		int32_t send_bytes_track = 0;                  /* variable to track numb of bytes read from backlog to be sent to legacy DF*/

		std::string file_name;                          /* Name of the current file in which packets ar being written/read from */
		std::string msgCntr_file_name;			/* Name of fle which msg counter is reffering */
};


#endif /* __TCPListener_H_ */
