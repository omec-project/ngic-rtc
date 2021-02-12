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

#ifndef _LEGACY_TCP_CLIENT_H_
#define _LEGACY_TCP_CLIENT_H_

#include "epctools.h"
#include "esocket.h"
#include "emgmt.h"

#include "LegacyClient.h"

#define LOG_SYSTEM									1
#define EMPTY_STRING								""
#define ZERO										0
#define RET_SUCCESS									0

#define DF_PACKET									200
#define LEGACY_DF_ACK								201

#pragma pack(push, 1)
struct DfPacket {
	uint32_t packetLen;

	struct DfPacketHdr {
		uint8_t packetType;
		uint32_t seqNo;
		uint32_t dataLen;
	} header;

	uint8_t data[0];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AckPacket {
	uint8_t packetLen;

	struct AckPacketHdr {
		uint8_t packetType;
		uint32_t seqNo;
	} header;

};
#pragma pack(pop)


class TCPThread;

class Talker : public ESocket::TCP::TalkerPrivate
{
	public:
		Talker(TCPThread &thread);
		virtual ~Talker();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onReceive();
		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onClose();
		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onError();
		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onConnect();

	private:
		Talker();
		uint32_t m_seq;
};

class TCPThread : public ESocket::ThreadPrivate {
	public:
		TCPThread();
		~TCPThread();

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onInit();
		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onQuit();
		/*
		 *  @brief  :   Library function of EPCTool
		 */
		void onClose();
		/*
                 *  @brief  :   Library function of EPCTool
                 */
                Void onTimer(EThreadEventTimer *ptimer);

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void onSocketClosed(ESocket::BasePrivate *psocket);

		Void onSocketError(ESocket::BasePrivate *psocket);

		/*
		 *  @brief  :   Library function of EPCTool
		 */
		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		Void startlDfRetryTimer();
		Void stoplDfRetryTimer();

		Talker *createTalker();
		Void deleteTalker();
		Talker *getTalker();

		void setRemoteIp(const std::string& strRemoteIp);
		void setRemotePort(uint16_t uiRemotePort);
		cpStr getRemoteIp();
		UShort getRemotePort();

	private:
		Talker *m_talker;
		cpStr m_remote_ip;
		UShort m_remote_port;
		EThreadEventTimer m_ldfRetryTimer;
		bool conn_flag = 0;
};

class LegacyTCPClient : public LegacyClient
{
	public:
		/*
		 *  @brief  :   Constructor of class BaseLegacyInterface
		 */
		LegacyTCPClient();

		/*
		 *  @brief  :   Destructor of class BaseLegacyInterface
		 */
		~LegacyTCPClient();

		/*
		 *  @brief  :   Function to initialise legacy interface
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		int8_t InitializeLegacyClient();

		/*
		 *  @brief  :   Function to connect with legacy DF
		 *  @param  :   strRemoteIp, legacy DF IP
		 *  @param	:	uiRemotePort, legacy DF port
		 *  @return :   Returns int8_t
		 */
		int8_t ConnectToLegacy(const std::string& strRemoteIp,
				uint16_t uiRemoteIp);

		/*
		 *  @brief  :   Function to send information/packet to legacy DF
		 *  @param  :   pkt, packet to be sent
		 *  @param	:	packetLen, size of packet
		 *  @return :   Returns int8_t
		 */
		int8_t SendMessageToLegacy(uint8_t *pkt, uint32_t packetLen);

		/*
		 *  @brief  :   Function to disconnect from legacy DF
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		int8_t DisconnectToLegacy();

		/*
		 *  @brief  :   Function to de-initialise legacy DF
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		int8_t DeinitializeLegacyClient();

		TCPThread * getThread();

	private:
		TCPThread *m_app;
};

/* Function which calls callback of DF to process ACK */
void to_df_callback(uint32_t ackNumb);

/* Function which calls callback of DF to notify Legacy DF socket close */
void to_socket_callback();

/* Function which calls callback of DF to notify Legacy DF is connected */
void to_conn_callback();

#endif /* _LEGACY_TCP_CLIENT_H_ */
