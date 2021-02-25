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

#include <signal.h>
#include <iostream>
#include <limits>
#include <cstdlib>
#include <cstring>

#include "elogger.h"

#include "LegacyAdmf.h"

LegacyAdmfApp g_app;
configurations_t config;

void signal_handler(int signal)
{
	ELogger::log(LOG_SYSTEM).startup( "Caught signal ({})", signal );

	switch (signal)
	{
		case SIGINT:
		case SIGTERM:
			{
				ELogger::log(LOG_SYSTEM).startup("Setting shutdown event");
				g_app.setShutdownEvent();
				break;
			}
	}
}

Void init_signal_handler()
{
	sigset_t sigset;

	/* mask SIGALRM in all threads by default */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGRTMIN);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);

	struct sigaction sa;

	/* Setup the signal handler */
	sa.sa_handler = signal_handler;

	/* Restart the system call, if at all possible */
	sa.sa_flags = SA_RESTART;

	/* Block every signal during the handler */
	sigfillset(&sa.sa_mask);

	if (sigaction(SIGINT, &sa, NULL) == -1)
		throw EError( EError::Warning, errno, "Unable to register SIGINT handler");
	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGINT");

	if (sigaction(SIGTERM, &sa, NULL) == -1)
		throw EError( EError::Warning, errno, "Unable to register SIGTERM handler");
	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGTERM");

	if (sigaction(SIGRTMIN+1, &sa, NULL) == -1)
		throw EError( EError::Warning, errno, "Unable to register SIGRTMIN handler");
	ELogger::log(LOG_SYSTEM).startup( "signal handler registered for SIGRTMIN");
}

Void usage()
{
	cpStr msg =
		"USAGE: epc_app [--print] [--help] [--file optionfile]\n";

	std::cout << msg;
}

int
ReadConfigurations(EGetOpt &opt)
{
	config.nodeName = opt.get("/LegacyAdmfApp/NodeName", EMPTY_STRING);
	config.serverPort = (opt.get("/LegacyAdmfApp/ServerPort", ZERO));
	inet_aton(opt.get("LegacyAdmfApp/LegacyAdmfIntfcIp", EMPTY_STRING), &config.legAdmfIntfcIp);
	config.legAdmfIntfcPort = (opt.get("LegacyAdmfApp/LegacyAdmfIntfcPort", ZERO));

	ELogger::log(LOG_SYSTEM).debug("Configurations : NodeName {}",
			config.nodeName);
	ELogger::log(LOG_SYSTEM).debug("Configurations : ServerPort {}",
			config.serverPort);


	return RET_SUCCESS;
}

int main(int argc, char *argv[])
{
	EGetOpt::Option options[] = {
		{"-h", "--help", EGetOpt::no_argument, EGetOpt::dtNone},
		{"-f", "--file", EGetOpt::required_argument, EGetOpt::dtString},
		{"-p", "--print", EGetOpt::no_argument, EGetOpt::dtBool},
		{"", "", EGetOpt::no_argument, EGetOpt::dtNone},
	};

	EGetOpt opt;
	EString optfile;

	try
	{
		opt.loadCmdLine(argc, argv, options);
		if (opt.getCmdLine("-h,--help",false))
		{
			usage();
			return 0;
		}

		optfile.format("%s.json", argv[0]);
		if (EUtility::file_exists(optfile))
			opt.loadFile(optfile);

		optfile = opt.getCmdLine( "-f,--file", "__unknown__" );
		if (EUtility::file_exists(optfile))
			opt.loadFile(optfile);

		if (opt.getCmdLine( "-p,--print", false))
			opt.print();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		return 1;
	}

	try
	{
		EpcTools::Initialize(opt);
		ELogger::log(LOG_SYSTEM).startup("EpcTools initialization complete");

		ReadConfigurations(opt);

		try
		{
			init_signal_handler();

			g_app.startup(opt);
			g_app.waitForShutdown();
			g_app.shutdown();
		}
		catch(const std::exception& e)
		{
			ELogger::log(LOG_SYSTEM).major( e.what() );
		}

		ELogger::log(LOG_SYSTEM).startup("Shutting down EpcTools");
		EpcTools::UnInitialize();
	}
	catch(const std::exception& e)
	{
		std::cerr << e.what() << '\n';
		return 2;
	}

	return 0;
}

LegacyAdmfApp::LegacyAdmfApp()
{
}

LegacyAdmfApp::~LegacyAdmfApp()
{
}

Void LegacyAdmfApp::startup(EGetOpt &opt)
{
	try
	{
		m_app = new WorkerThread();
		m_app->init(1, 1, NULL, 200000);

		uint16_t restApiPort = (config.serverPort + 1);
		cCliPost = new EManagementEndpoint(restApiPort);

		mAddUe = new AddUeEntryPost(ELogger::log(LOG_SYSTEM), m_app);
		cCliPost->registerHandler(*mAddUe);

		mUpdateUe = new UpdateUeEntryPost(ELogger::log(LOG_SYSTEM), m_app);
		cCliPost->registerHandler(*mUpdateUe);

		mDeleteUe = new DeleteUeEntryPost(ELogger::log(LOG_SYSTEM), m_app);
		cCliPost->registerHandler(*mDeleteUe);

		cCliPost->start();

	}
	catch (...)
	{
		ELogger::log(LOG_SYSTEM).startup("Exception initializing Application");
		return;
	}
}

Void LegacyAdmfApp::shutdown()
{
	SAFE_DELETE(mAddUe);
	SAFE_DELETE(mUpdateUe);
	SAFE_DELETE(mDeleteUe);
	SAFE_DELETE(cCliPost);
}


/////////////////////////////////////////////////////////////////////////////
//////////////////////////////////REST API's/////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

AddUeEntryPost::AddUeEntryPost(ELogger &audit, WorkerThread *mApp)
	: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			ADD_UE_ENTRY_URI, audit), app(mApp)
{
}

Void
AddUeEntryPost::process(const Pistache::Http::Request& request,
		Pistache::Http::ResponseWriter &response)
{
	std::string requestBody;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;

	requestBody = request.body();

	ELogger::log(LOG_SYSTEM).debug("Request body: {}", requestBody);
	jsonReq.Parse(requestBody.c_str());

	if (jsonReq.HasParseError()) {
		ELogger::log(LOG_SYSTEM).info("Add:: Json parsing error. Invalid json");
		response.send(Pistache::Http::Code::Bad_Request, 
				"Add:: Json parsing error. Invalid JSON.\n");
		return;
	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr == jsonReq.MemberEnd()) {
		ELogger::log(LOG_SYSTEM).debug("Add:: Invalid json. Ue database "
				"not found in request");
		response.send(Pistache::Http::Code::Bad_Request, 
				"Add: Ue database not found in request. Invalid JSON.\n");
		return;
	}

	ELogger::log(LOG_SYSTEM).debug("Calling sendRequestToInterface");
	app->sendRequestToInterface(ADD_REQUEST, requestBody);

	response.send(Pistache::Http::Code::Ok, "Add Ue Request sent to "
			"legacy admf interface");
}

UpdateUeEntryPost::UpdateUeEntryPost(ELogger &audit, WorkerThread *mApp)
	: EManagementHandler( EManagementHandler::HttpMethod::httpPost,
			UPDATE_UE_ENTRY_URI, audit), app(mApp)
{
}

Void
UpdateUeEntryPost::process(const Pistache::Http::Request& request,
		Pistache::Http::ResponseWriter &response)
{
	std::string requestBody;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;

	requestBody = request.body();

	jsonReq.Parse(requestBody.c_str());

	if (jsonReq.HasParseError()) {
		ELogger::log(LOG_SYSTEM).info("Update:: Json parsing error. Invalid json");
		response.send(Pistache::Http::Code::Bad_Request,
				"Update:: Json parsing error. Invalid JSON.\n");
		return;
	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr == jsonReq.MemberEnd()) {
	ELogger::log(LOG_SYSTEM).debug("Update:: Invalid json. Ue database "
				"not found in request");
		response.send(Pistache::Http::Code::Bad_Request,
				"Update: Ue database not found in request. Invalid JSON.\n");
		return;
	}

	ELogger::log(LOG_SYSTEM).debug("Calling sendRequestToInterface");
	app->sendRequestToInterface(UPDATE_REQUEST, requestBody);

	response.send(Pistache::Http::Code::Ok, "Update Ue Request sent to "
			"legacy admf interface");
}

DeleteUeEntryPost::DeleteUeEntryPost(ELogger &audit, WorkerThread *mApp)
        : EManagementHandler( EManagementHandler::HttpMethod::httpPost,
                        DELETE_UE_ENTRY_URI, audit), app(mApp)
{
}

Void
DeleteUeEntryPost::process(const Pistache::Http::Request& request,
                Pistache::Http::ResponseWriter &response)
{
	std::string requestBody;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;

	requestBody = request.body();

	jsonReq.Parse(requestBody.c_str());

	if (jsonReq.HasParseError()) {
		ELogger::log(LOG_SYSTEM).info("Delete:: Json parsing error. Invalid json");
		response.send(Pistache::Http::Code::Bad_Request,
				"Delete:: Json parsing error. Invalid JSON.\n");
		return;
	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr == jsonReq.MemberEnd()) {
		ELogger::log(LOG_SYSTEM).debug("Delete:: Invalid json. Ue database "
				"not found in request");
		response.send(Pistache::Http::Code::Bad_Request,
				"Delete: Ue database not found in request. Invalid JSON.\n");
		return;
	}

	ELogger::log(LOG_SYSTEM).debug("Calling sendRequestToInterface");
	app->sendRequestToInterface(DELETE_REQUEST, requestBody);

	response.send(Pistache::Http::Code::Ok, "Delete Ue Request sent to "
			"legacy admf interface");
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// Talker //////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

Talker::Talker(WorkerThread &thread) :
	ESocket::TCP::TalkerPrivate(thread) {
}

Talker::~Talker() {
}

void
Talker::onConnect() {

	EString localIpAddr = getLocalAddress();
	UShort localPort = getLocalPort();

	ELogger::log(LOG_SYSTEM).info("server connected with local ip {} "
			"local port {}.", localIpAddr, localPort);

	((WorkerThread &)getThread()).connect();

}

void
Talker::onReceive() {

	UChar buffer[4096];
	uint32_t packetLen = 0;
	ELogger::log(LOG_SYSTEM).debug("Talker :: onReceive");
	legacyAdmfPacket *packet = (legacyAdmfPacket*)buffer;

	try
	{
		while (true)
		{
			if (bytesPending() < (Int)sizeof(legacyAdmfPacket::packetLength) ||
					peek((pUChar)&packetLen, sizeof(legacyAdmfPacket::packetLength)) !=
					sizeof(legacyAdmfPacket::packetLength))
			{
				break;
			}

			if (bytesPending() < (Int)packetLen)
			{
				break;
			}

			if (read(buffer,packetLen) != (Int)packetLen)
			{
				ELogger::log(LOG_SYSTEM).critical("Error reading packet data - \
						unable to read {} bytes", packetLen);
				getThread().quit();
				break;
			}

			if (packet->ue_entry_t.packetType == ADMF_INTFC_PACKET)
			{
				ELogger::log(LOG_SYSTEM).debug("packet contents packetLength [{}] "
						"seqId [{}] imsi [{}] startTime [{}] stopTime [{}] packetType [{}]"
						"requestType [{}] ", packet->packetLength, packet->ue_entry_t.seqId,
						packet->ue_entry_t.imsi, packet->ue_entry_t.startTime,
						packet->ue_entry_t.stopTime, packet->ue_entry_t.packetType,
						packet->ue_entry_t.requestType);

				ELogger::log(LOG_SYSTEM).info("Sequence Id [{}] imsi [{}] startTime [{}] stopTime [{}]",
						packet->ue_entry_t.seqId, packet->ue_entry_t.imsi, packet->ue_entry_t.startTime,
						packet->ue_entry_t.stopTime);

				/* formation of ack packet*/
				UChar ack[4096];

				legacyAdmfPacket *pkt = (legacyAdmfPacket *)ack;
				std::memset(ack, 0, sizeof(ack));
				std::memset(pkt->ue_entry_t.startTime, 0, 21);
				std::memset(pkt->ue_entry_t.stopTime, 0, 21);

				pkt->ue_entry_t.seqId = packet->ue_entry_t.seqId;
				pkt->ue_entry_t.imsi = packet->ue_entry_t.imsi;
				std::memcpy(pkt->ue_entry_t.startTime, packet->ue_entry_t.startTime, 21);
				std::memcpy(pkt->ue_entry_t.stopTime, packet->ue_entry_t.stopTime, 21);
				pkt->ue_entry_t.packetType = LEGACY_ADMF_ACK;
				pkt->ue_entry_t.requestType = packet->ue_entry_t.requestType;
				pkt->packetLength = sizeof(legacyAdmfPacket);

				write(ack, pkt->packetLength);

			}

			if (packet->ue_entry_t.packetType == ADMF_ACK) {

				ELogger::log(LOG_SYSTEM).debug("Final ack received for seqId: {} "
						"and imsi: {}", packet->ue_entry_t.seqId, packet->ue_entry_t.imsi);
			}
		}
	} catch (const ESocket::TcpTalkerError_SendingPacket &e) {

		std::cerr << e.what() << '\n'
			<< std::flush;
		getThread().quit();

	} catch (const std::exception &e) {

		std::cerr << e.what() << '\n'
			<< std::flush;
		getThread().quit();

	}
}

void
Talker::onClose() {

	/* ELogger::log(LOG_SYSTEM).info("socket closed."); */
}

void
Talker::onError() {

	ELogger::log(LOG_SYSTEM).info("socket error {}.", getError());

	onClose();
}

void
Talker::sendData() {
}

/////////////////////////////////////////////////////////////////////////////
///////////////////////////////////Interface Client//////////////////////////
/////////////////////////////////////////////////////////////////////////////

IntfcClient::IntfcClient(WorkerThread &thread)
	: ESocket::TCP::TalkerPrivate(thread)
{
}

IntfcClient::~IntfcClient()
{
}

Void
IntfcClient::onConnect()
{
	ELogger::log(LOG_SYSTEM).info("Connected to legacy interface");
}

Void
IntfcClient::onReceive()
{
	UChar buffer[4096];
	UeDatabase *packet = (UeDatabase*)buffer;
	uint32_t packetLength = 0;

	try
	{
		while (true)
		{
			if (bytesPending() < (Int)sizeof(UeDatabase::packetLen) ||
				peek((pUChar)&packetLength, sizeof(UeDatabase::packetLen)) != 
				sizeof(UeDatabase::packetLen)) {

				break;
			}

			if (bytesPending() < (Int)packetLength)
				break;

			if (read(buffer,packetLength) != (Int)packetLength) {

				ELogger::log(LOG_SYSTEM).critical("Error reading packet data from DF "
						"server - unable to read {} bytes", packetLength);
				getThread().quit();
				break;
			}

			if (packet->ue_entry_t.packetType == ADMF_INTFC_ACK) {

				if (packet->ue_entry_t.requestStatus == RET_SUCCESS) {
					ELogger::log(LOG_SYSTEM).debug("Ack received: request sent to admf ");
				} else if (packet->ue_entry_t.requestStatus == RET_FAILURE) {
					ELogger::log(LOG_SYSTEM).debug("LegacyInterface failed to send "
							"request to admf");
				}

			} else {
				ELogger::log(LOG_SYSTEM).minor("Unexpected DF packetType value [{}]", 
						packet->ue_entry_t.packetType);
			}
		}
	}
	catch (const std::exception &e)
	{
		ELogger::log(LOG_SYSTEM).critical("IntfcClient excption: {}", e.what());
	}
}

Void
IntfcClient::onClose()
{
}

Void
IntfcClient::onError()
{
	/* ELogger::log(LOG_SYSTEM).minor("Interface socket error {} ", getError()); */
	onClose();
}

Void
IntfcClient::sendData(UeDatabase &ue)
{
	ELogger::log(LOG_SYSTEM).debug("Writing packet on socket");
	write((pUChar)&ue, ue.packetLen);
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// Listener ////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

Listener::Listener(WorkerThread &thread) :
		ESocket::TCP::ListenerPrivate(thread)  {
}

Listener::~Listener() {
}

void
Listener::onError() {

	ELogger::log(LOG_SYSTEM).critical("socket error {}.", getError());
}

ESocket::TCP::TalkerPrivate *
Listener::createSocket(ESocket::ThreadPrivate &thread) {

	return ((WorkerThread &)thread).createTalker();
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// WorkerThread ////////////////////////////
/////////////////////////////////////////////////////////////////////////////

WorkerThread::WorkerThread() {

	m_listener = NULL;
	m_local_port = config.serverPort;
}

WorkerThread::~WorkerThread() {

	if (NULL != m_listener) {
		delete m_listener;
		m_listener = NULL;
	}

	if (!m_talker.empty()) {

		std::list <Talker *>::const_iterator constItr;
		for (constItr = m_talker.begin(); constItr != m_talker.end();
				++constItr) {

			Talker *talker = m_talker.front();

			m_talker.pop_front();

			delete talker;
			talker = NULL;
		}
	}
}

void
WorkerThread::onInit() {

	m_listener = new Listener(*this);
	m_listener->listen(m_local_port, 100);

	ELogger::log(LOG_SYSTEM).info("Waiting for connection on port {}",
			m_local_port);

	connect();
}

void
WorkerThread::onQuit() {

	if (m_listener) {
		delete m_listener;
		m_listener = NULL;
	}
}

void
WorkerThread::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	ELogger::log(LOG_SYSTEM).info("WorkerThread::errorHandler() - "
			"socket exception -  {}", err.what());
}

Talker *
WorkerThread::createTalker() {

	Talker *talker = new Talker(*this);
	if (NULL != talker) {

		m_talker.push_back(talker);
		return talker;
	}

	return NULL;
}

void
WorkerThread::onClose() {

	ELogger::log(LOG_SYSTEM).debug("WorkerThread closed.");

	quit();
}

Void 
WorkerThread::onError() {
	onClose();
}

Void
WorkerThread::connect() {
	m_client = new IntfcClient(*this);
	m_client->connect(inet_ntoa(config.legAdmfIntfcIp), 
			(UShort)config.legAdmfIntfcPort);
	ELogger::log(LOG_SYSTEM).info("LegacyAdmfIntfc connection initiated on "
			"port: {}", (UShort)config.legAdmfIntfcPort);
}

Void
WorkerThread::onSocketClosed(ESocket::BasePrivate *psocket) {

	if (psocket == m_listener) {

		ELogger::log(LOG_SYSTEM).debug("Listener socket closed");
		m_listener = NULL;

	} else if (!m_talker.empty()) {

		std::list <Talker *>::iterator itr;
		itr = std::find(m_talker.begin(), m_talker.end(), psocket);
		if (itr != m_talker.end()) {

			m_talker.erase(itr);
		}
	}

	delete psocket;
}

Void
WorkerThread::sendRequestToInterface(uint16_t requestType, 
		std::string &requestBody) {

	UeDatabase ue;

	ue.ue_entry_t.requestType = requestType;
	ue.ue_entry_t.packetType = LEGACY_ADMF_PACKET;

	uint32_t requestLen = requestBody.size() + 1;
	ue.ue_entry_t.bodyLength = requestLen;
	ue.ue_entry_t.requestStatus = RET_FAILURE;

	std::memcpy(ue.ue_entry_t.requestBody, requestBody.c_str(), requestLen);

	ue.packetLen = sizeof(UeDatabase) + requestLen;

	m_client->sendData(ue);

}
