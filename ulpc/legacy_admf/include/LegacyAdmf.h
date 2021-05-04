/*
* Copyright (c) 2020 Sprint
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef _SAMPLE_ADMF_H_
#define _SAMPLE_ADMF_H_

#include <dlfcn.h>

#include "epctools.h"
#include "etevent.h"
#include "esocket.h"
#include "emgmt.h"

#define LOG_SYSTEM				1
#define EMPTY_STRING				""
#define ZERO					0
#define RET_SUCCESS				0
#define RET_FAILURE				1

#define ADMF_PACKET				10
#define ADMF_INTFC_PACKET			20
#define LEGACY_ADMF_ACK				30
#define ADMF_ACK				40
#define LEGACY_ADMF_PACKET			50
#define ADMF_INTFC_ACK          		60

#define IPV6_MAX_LEN				16
#define BACKLOG_CONNECTIION                 	100

#define ADD_UE_ENTRY_URI			"/addueentry"
#define UPDATE_UE_ENTRY_URI			"/updateueentry"
#define DELETE_UE_ENTRY_URI			"/deleteueentry"
#define UE_DB_KEY				"uedatabase"

#define ADD_REQUEST				1
#define UPDATE_REQUEST				2
#define DELETE_REQUEST				3

#define SAFE_DELETE(p)                          { if (NULL != p) { delete(p); (p) = NULL; }}


#pragma pack(push, 1)
struct legacyAdmfPacket {
	uint32_t				packetLength;

	struct ueEntry {
		uint64_t			seqId;
		uint64_t			imsi;
		uint16_t			packetType;
		uint16_t			requestType;
		UChar				startTime[21];
		UChar				stopTime[21];
	} ue_entry_t;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct AckPacket {
	uint8_t					packetLen;

	struct AckPacketHdr {
		uint8_t				packetType;
		uint64_t			imsi;
	} header;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct UeDatabase {
	uint32_t			packetLen;

	struct ueEntry {
		uint16_t		requestType;
		uint16_t		packetType;
		uint16_t		bodyLength;
		uint16_t		requestStatus;
		UChar			requestBody[2048];
	} ue_entry_t;
};
#pragma pack(pop)

/**
 * @brief  : Maintains Sample LegacyADMF configurations read from config file
 */
typedef struct configurations {
	std::string			nodeName;
	cpStr				serverIp;
	uint16_t			serverPort;
	cpStr				legAdmfIntfcIp;
	uint16_t			legAdmfIntfcPort;
} configurations_t;


class WorkerThread;
class LegacyAdmfApp;

class AddUeEntryPost : public EManagementHandler
{
	public:
		AddUeEntryPost(ELogger &audit, WorkerThread *mApp);
		WorkerThread *app;

		virtual Void process(const Pistache::Http::Request& request,
			Pistache::Http::ResponseWriter &response);

		virtual ~AddUeEntryPost() {}

	private:
		AddUeEntryPost();

};

class UpdateUeEntryPost : public EManagementHandler
{
	public:
		UpdateUeEntryPost(ELogger &audit, WorkerThread *mApp);
		WorkerThread *app;

		virtual Void process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response);

		virtual ~UpdateUeEntryPost() {}

	private:
		UpdateUeEntryPost();

};

class DeleteUeEntryPost : public EManagementHandler
{
	public:
		DeleteUeEntryPost(ELogger &audit, WorkerThread *mApp);
		WorkerThread *app;

		virtual Void process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response);

		virtual ~DeleteUeEntryPost() {}

	private:
		DeleteUeEntryPost();

};

class Talker : public ESocket::TCP::TalkerPrivate
{
	public:
		Talker(WorkerThread &thread);
		virtual ~Talker();

		void onReceive();
		void onClose();
		void onError();
		void onConnect();
		void sendData();

	private:
		Talker();
};

class IntfcClient : public ESocket::TCP::TalkerPrivate
{
	public:
		IntfcClient(WorkerThread &thread);
		virtual ~IntfcClient();

		Void onConnect();
		Void onReceive();
		Void onClose();
		Void onError();

		Void sendData(UeDatabase &ue);

	private:
		IntfcClient();
};


class Listener : public ESocket::TCP::ListenerPrivate {
	public:
		Listener(WorkerThread &thread);
		~Listener();

		void onError();
		ESocket::TCP::TalkerPrivate *createSocket(ESocket::ThreadPrivate &thread);

};

class WorkerThread : public ESocket::ThreadPrivate {
	public:
		WorkerThread();
		~WorkerThread();

		void onInit();
		void onQuit();
		void onClose();
		Void onError();
		Void connect();

		Void onSocketClosed(ESocket::BasePrivate *psocket);
		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		Talker *createTalker();

		UShort getLocalPort() const { return m_local_port; }

		Void sendRequestToInterface(uint16_t requestType, 
				std::string &requestBody);

	private:
		UShort m_local_port;
		Listener *m_listener;
		IntfcClient *m_client;
		std::list <Talker *> m_talker;
};

class LegacyAdmfApp
{
	public:
		LegacyAdmfApp();
		~LegacyAdmfApp();

		Void startup(EGetOpt &opt);
		Void shutdown();

		Void setShutdownEvent() {
			m_shutdown.set();
		}

		Void waitForShutdown() {
			m_shutdown.wait();
		}

	private:
		WorkerThread *m_app;
		EEvent m_shutdown;
		EManagementEndpoint *cCliPost;
		AddUeEntryPost *mAddUe;
		UpdateUeEntryPost *mUpdateUe;
		DeleteUeEntryPost *mDeleteUe;
};

#endif /* _SAMPLE_ADMF_H_ */
