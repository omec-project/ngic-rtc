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

#include "LegacyTCPClient.h"
#include "LegacyInterface.h"

LegacyTCPClient::LegacyTCPClient() {
}

LegacyTCPClient::~LegacyTCPClient() {
	if (NULL != m_app) {
		delete m_app;
	}
}

int8_t
LegacyTCPClient::InitializeLegacyClient() {

	try
	{
		m_app = new TCPThread();
		m_app->init(1, 1, NULL, 200000);
	}
	catch (...)
	{
		LegacyInterface::log().startup("Exception initializing Application");
		return -1;
	}

	return 0;
}

int8_t
LegacyTCPClient::ConnectToLegacy(const std::string& strRemoteIp,
		uint16_t uiRemotePort) {

	m_app->setRemoteIp(strRemoteIp);
	m_app->setRemotePort(uiRemotePort);

	LegacyInterface::log().info("{}: Connecting to Legacy DF", __func__);	
	getThread()->createTalker()->connect(getThread()->getRemoteIp(),
			getThread()->getRemotePort());

	return 0;
}

int8_t
LegacyTCPClient::SendMessageToLegacy(uint8_t *pkt, uint32_t packetLen) {
	LegacyInterface::log().info("Sending packet to Legacy DF SendMessageToLegacy");	
	try {
			getThread()->getTalker()->write(pkt, packetLen);
	}
	catch(const ESocket::TcpTalkerError_SendingPacket &e) {

		LegacyInterface::log().debug("error while writing {}", e.what());
	}

	return 0;
}

int8_t
LegacyTCPClient::DisconnectToLegacy() {
	return 0;
}

int8_t
LegacyTCPClient::DeinitializeLegacyClient() {
	return 0;
}

TCPThread *
LegacyTCPClient::getThread() {

	return m_app;
}
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// Talker //////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

Talker::Talker(TCPThread &thread) :
	ESocket::TCP::TalkerPrivate(thread) {
}

Talker::~Talker() {
}

void
Talker::onConnect() {

	EString localIpAddr = getLocalAddress();
	UShort localPort = getLocalPort();
	EString remoteIpAddr = getRemoteAddress();
	UShort remotePort = getRemotePort();

	LegacyInterface::log().info("socket connected with local ip {}	"
			"local port {}	remote ip {}	remote port {}", localIpAddr,
			localPort, remoteIpAddr, remotePort);

	to_conn_callback();
//	conn_flag = 0;
	((TCPThread&)getThread()).stoplDfRetryTimer();
}

void
Talker::onReceive() {

	uint8_t *ack = NULL;
	uint8_t packetLen = 0;

	try
	{
		while (true)
		{
			if (bytesPending() < (Int)sizeof(packetLen) ||
					peek((pUChar)&packetLen, sizeof(packetLen)) != sizeof(packetLen))
			{
				break;
			}


			if (bytesPending() < (Int)packetLen)
			{
				break;
			}

			ack = new uint8_t[packetLen];
			if (ack == NULL) {
				LegacyInterface::log().debug("Error while allocating {} bytes memory",
						packetLen);
			}
			std::memset(ack, 0, packetLen);

			if (read(ack, packetLen) != (Int)packetLen)
			{
				LegacyInterface::log().critical("Error reading packet data - unable to read {} bytes", packetLen);
				break;
			}

			AckPacket *packet = (AckPacket*)ack;
			if (packet->header.packetType == LEGACY_DF_ACK)
			{
				LegacyInterface::log().debug("packet contents packetLen [{}] "
						"packetType [{}] seqNo [{}]", packet->packetLen,
						packet->header.packetType, ntohl(packet->header.seqNo));

				to_df_callback(ntohl(packet->header.seqNo));
			}
		}
	}
	catch (const  ESocket::TcpTalkerError_SendingPacket &e)
	{
		std::cerr << e.what() << '\n' << std::flush;
	}
	catch (const  std::exception &e)
	{
		std::cerr << e.what() << '\n' << std::flush;
	}
}

void
Talker::onClose() {

	LegacyInterface::log().info("socket closed.");
}

void
Talker::onError() {
	onClose();
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////// TCPThread ///////////////////////////////
/////////////////////////////////////////////////////////////////////////////

TCPThread::TCPThread() {

	m_talker = NULL;
}

TCPThread::~TCPThread() {

}

void
TCPThread::onInit() {
#define TIME_INTERVAL 1000

	m_ldfRetryTimer.setInterval(TIME_INTERVAL);
	m_ldfRetryTimer.setOneShot(False);
	initTimer(m_ldfRetryTimer);
	LegacyInterface::log().info("{}: Timer has been intitialised", __func__);

	m_remote_ip = getRemoteIp();
	m_remote_port = getRemotePort();

	LegacyInterface::log().info("connecting to server on Ip {} port {}",
				m_remote_ip, m_remote_port);
}

void
TCPThread::onQuit() {
}

void
TCPThread::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	LegacyInterface::log().debug("TCPThread::errorHandler() - "
			"socket exception -  {}", err.what());
}

Void
TCPThread::onTimer(EThreadEventTimer *ptimer)
{
        if (ptimer->getId() == m_ldfRetryTimer.getId()) {
		createTalker()->connect(getRemoteIp(), getRemotePort());
	}
}

Void
TCPThread::startlDfRetryTimer()
{
	m_ldfRetryTimer.start();
        LegacyInterface::log().debug("Timer started for retrying connecting to Legacy DF ");
}

Void
TCPThread::stoplDfRetryTimer()
{
	conn_flag = 0;
        m_ldfRetryTimer.stop();
        LegacyInterface::log().debug("Timer stopped for retrying connecting to Legacy DF ");
}

Talker *
TCPThread::createTalker() {

	if (m_talker != NULL )
		onSocketClosed(m_talker);

	m_talker = new Talker(*this);
	if (NULL != m_talker) {
		return m_talker;
	}

	return NULL;
}

void 
TCPThread::onSocketClosed(ESocket::BasePrivate *psocket) {

	LegacyInterface::log().info("{} socket closed {}", __func__,
                        ((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress());

	if ((NULL != psocket) && (psocket == m_talker)) {
                delete m_talker;
		m_talker = NULL;
        }

	if (conn_flag != 1) {
		to_socket_callback();			/* calls function from DF */
		startlDfRetryTimer();
		LegacyInterface::log().info("{} Timer has been started to retry for connection", __func__);
		conn_flag = 1;
	}
}

void 
TCPThread::onSocketError(ESocket::BasePrivate *psocket) {

	LegacyInterface::log().info("{} socket error {} {} ", __func__,
                        ((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress(), 
			psocket->getErrorDescription());

	onSocketClosed(psocket);
}

void
TCPThread::setRemoteIp(const std::string& strRemoteIp) {

	m_remote_ip = strRemoteIp.c_str();
}

void
TCPThread::setRemotePort(uint16_t uiRemotePort) {

	m_remote_port = uiRemotePort;
}

cpStr
TCPThread::getRemoteIp() {

	return m_remote_ip;
}

UShort
TCPThread::getRemotePort() {

	return m_remote_port;
}

Talker *
TCPThread::getTalker() {

	return m_talker;
}
