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

#include "Common.h"
#include "TCPListener.h"


extern struct Configurations config;


TCPListener :: TCPListener ()
	: m_maxMsgs(10),
	  m_ptrListener(NULL),
	  m_ptrDataProcessor{NULL}
{
	msg_cnt.init(m_maxMsgs);
	fileVect.reserve(70);
	legacy_conn = 1;

	ELogger::log(LOG_SYSTEM).debug("{} :: ", __func__);
}


TCPListener :: ~TCPListener()
{
}

Void
TCPListener::setIntfcPtr(BaseLegacyInterface *ptr)
{
	m_legacyIntfc = ptr;
}

Void
TCPListener::onInit()
{
#define TIMER_INTERVAL 1000

	m_dfRetryTimer.setInterval(TIMER_INTERVAL);
	m_dfRetryTimer.setOneShot(False);
	initTimer(m_dfRetryTimer);

	m_ptrListener = new DfListener(*this);

//	m_ptrListener->listen(config.df_port, BACKLOG_CONNECTIION);

	m_ptrListener->getLocalAddress().setAddress(config.df_ip, config.df_port);
	m_ptrListener->setBacklog(BACKLOG_CONNECTIION);

	m_ptrListener->listen();

	ELogger::log(LOG_SYSTEM).info("{} :: DF listener started on port {}.",
			__func__, config.df_port);

	createFolder();
	if (createFile() == 0) {
		vecIter = fileVect.begin();
		readFile();
	}

	if (m_legacyIntfc != NULL) {
		/* Initialise legacy interface */
		m_legacyIntfc->InitializeLegacyInterface(config.strCommMode);

		/* Connect to the legacy DF through legacy interface*/
		m_legacyIntfc->ConnectWithLegacyInterface(config.strRemoteIp,
				config.uiRemotePort);
	} else {
		ELogger::log(LOG_SYSTEM).info("m_legacyIntfc is Null not yet set ... ");
		sleep(10);
		InitLegacyAgain();
	}
}

Void
TCPListener::InitLegacyAgain()
{
	if (m_legacyIntfc != NULL) {
		/* Initialise legacy interface */
		m_legacyIntfc->InitializeLegacyInterface(config.strCommMode);

		/* Connect to the legacy DF through legacy interface*/
		m_legacyIntfc->ConnectWithLegacyInterface(config.strRemoteIp,
				config.uiRemotePort);
	} else {
		ELogger::log(LOG_SYSTEM).critical("m_legacyIntfc is Null not yet set in InitLegacyAgain() ... ");
	}
}

Void
TCPListener::onQuit()
{
	if (NULL != m_ptrListener) {

		delete m_ptrListener;
		m_ptrListener = NULL;

		ELogger::log(LOG_SYSTEM).debug("{} :: close and delete listener socket.",
				__func__);
	}

	m_legacyIntfc->DeinitalizeLegacyInterface();

	m_ptrDataProcessor.clear();
}

Void
TCPListener::onTimer(EThreadEventTimer *ptimer)
{
        if (ptimer->getId() == m_dfRetryTimer.getId()) {
                ELogger::log(LOG_SYSTEM).debug("Recovery timer expired, "
                                "sending failed packets");

                sendPending();
        }
}


Void
TCPListener::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	ELogger::log(LOG_SYSTEM).debug("{} :: TCPListener::errorHandler() -"
			" socket exception -  {}", __func__, err.what());
}

Void
TCPListener::startDfRetryTimer()
{
	m_dfRetryTimer.start();
	ELogger::log(LOG_SYSTEM).debug("Timer started for retrying failure messages to Legacy DF ");
}

Void
TCPListener::stopDfRetryTimer()
{
	m_dfRetryTimer.stop();
	ELogger::log(LOG_SYSTEM).debug("Timer stopped for retrying failure messages to Legacy DF ");
}


TCPDataProcessor *
TCPListener::createDfTalker()
{
	TCPDataProcessor *talker = new TCPDataProcessor(*this);
	if (NULL != talker) {

		m_ptrDataProcessor.push_back(talker);

		ELogger::log(LOG_SYSTEM).debug("{} :: Talker object is created.", __func__);

		return talker;
	}

	ELogger::log(LOG_SYSTEM).critical("{} :: Failed to create talker object.",
			__func__);
	return NULL;
}


Void
TCPListener::onSocketClosed(ESocket::BasePrivate *psocket) {

	if (psocket == m_ptrListener) {

		ELogger::log(LOG_SYSTEM).debug("{} :: Listener socket closed and delete.",
				__func__);

		m_ptrListener = NULL;

	} else if (!m_ptrDataProcessor.empty()) {

		std::list <TCPDataProcessor *>::iterator itr;
		itr = std::find(m_ptrDataProcessor.begin(), m_ptrDataProcessor.end(),
				psocket);
		if (itr != m_ptrDataProcessor.end()) {

			m_ptrDataProcessor.erase(itr);

			ELogger::log(LOG_SYSTEM).debug("{} :: Talker socket closed and deleted.",
					__func__);
		}
	}

	delete psocket;
}

Void
TCPListener::onSocketError(ESocket::BasePrivate *psocket) {
        ELogger::log(LOG_SYSTEM).info("{} socket error {} {} ", __func__,
                        ((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress(),
                        psocket->getErrorDescription());

        onSocketClosed(psocket);
}

Void TCPListener::processData(DfPacket_t *packet)
{
	bool space_flag = 0;            /* Flag to indicate space availibility on disc */

	ELogger::log(LOG_SYSTEM).debug("Received DDFPACKET_DATA for"
	" sequence number {} size {}", ntohl(packet->header.sequenceNumber),
	ntohl(packet->packetLength));

#define MAX_ENTRY_COUNT 10000

	if (entry_cnt > (MAX_ENTRY_COUNT - 1)) {
		if(pkt_cnt != entry_cnt) {
			setPending();
		}
		entry_cnt = 0;
		pkt_cnt = 0;
		fileWrite.close();
		createFile();
	}

#define SEND_BUF_SIZE 4096

	DfPacket_t *pkt = NULL;
	uint32_t tempLen = sizeof(DfPacket_t) + ntohl(packet->header.dataLength);
	uint8_t buf[tempLen];

	if (checkAvailableSapce() == 0) {

		std::memset(buf, '\0', tempLen);

		pkt = (DfPacket_t *)buf;

		pkt->packetLength = htonl(tempLen);
		pkt->header.sequenceNumber = packet->header.sequenceNumber;
		pkt->header.liIdentifier = packet->header.liIdentifier;
		pkt->header.imsiNumber = packet->header.imsiNumber;
		pkt->header.dataLength = packet->header.dataLength;
		std::memcpy(pkt->data, packet->data, ntohl(pkt->header.dataLength));

		std::memset(writeBuf, '\0', SEND_BUF_SIZE);

		uint16_t ret = 0;
		ret = snprintf((char *)writeBuf, SEND_BUF_SIZE, "%u,%u,%lu,%lu,%u,", ntohl(pkt->packetLength),
				ntohl(pkt->header.sequenceNumber), pkt->header.liIdentifier,
				pkt->header.imsiNumber, ntohl(pkt->header.dataLength));
		memcpy(writeBuf + ret, pkt->data, ntohl(pkt->header.dataLength));

		fileWrite.write((const char *)writeBuf, SEND_BUF_SIZE);
		entry_cnt++;

	}
	else
		space_flag = 1;

	if ((m_legacyIntfc) && (pkt_cnt+1 == entry_cnt))
	{
		if (legacy_conn == 0) {
			if(msg_cnt.Decrement(False)) {
				m_legacyIntfc->SendMessageToLegacyInterface(buf, ntohl(pkt->packetLength));

				if (space_flag == 0)
					pkt_cnt++;
			}
		}
	} else if (pkt_cnt+1 != entry_cnt) {
		ELogger::log(LOG_SYSTEM).debug("DF code going in recovery due to mismatch in count of packets");
		setPending();

	}
}

Void TCPListener::resetFlag()
{
	legacy_conn = 0;
	ELogger::log(LOG_SYSTEM).debug("{}: Legacy DF is connected", __func__);
}

Void TCPListener::setPending()
{
	if (legacy_conn == 1) {
		ELogger::log(LOG_SYSTEM).debug("{}: Legacy DF is not connected, "
		"returning from recovery ", __func__);
		return;
	}

	ELogger::log(LOG_SYSTEM).debug("DF code going in recovery due to some backlog of msg");

	if ((pkt_cnt == -1) && (serveNextFile == 1)) {
		ELogger::log(LOG_SYSTEM).debug("{} : There is another file to serve for recovery"
			", waiting for ack from prev", __func__);

		return;
	}

	if (pending_data_flag == 1) {
		ELogger::log(LOG_SYSTEM).debug("{} : Recovery is in progress", __func__);
		return;
	}

	if(NULL != m_legacyIntfc) {

                pending_data_flag = 1;
                ELogger::log(LOG_SYSTEM).debug("{} : Recovery flag pending_data_flag is set to 1", __func__);

                if (serveNextFile == 0) {
                        send_bytes_track = read_bytes_track;
                        pkt_cnt = read_count;
                }

                startDfRetryTimer();
                ELogger::log(LOG_SYSTEM).debug("{} : Timer has been started to serve recovery", __func__);
        }
}

Void TCPListener::sendPending()
{
	if(send_bytes_track != read_bytes_track) {
		stopDfRetryTimer();

		if (serveNextFile == 0) {
                        send_bytes_track = read_bytes_track;
                        pkt_cnt = read_count;
                }

		startDfRetryTimer();
		return;
	}

	if (legacy_conn == 1) {
		ELogger::log(LOG_SYSTEM).debug("{}: Legacy DF is not yet connected", __func__);
		pending_data_flag = 0;
		return;
	}

	if (send_bytes_track == -1) {
		ELogger::log(LOG_SYSTEM).debug("No new packet flowed to Legacy DF");
		pending_data_flag = 0;
		return ;
	}

	if ((m_legacyIntfc) && (msg_cnt.Decrement(False))) {

		std::memset(readBuf, '\0', SEND_BUF_SIZE);

		fileRead.seekg(send_bytes_track, std::ios::beg);
		fileRead.read((char *)readBuf, SEND_BUF_SIZE);

		if(fileRead.eof()) {
			ELogger::log(LOG_SYSTEM).debug("{} : File is empty, no packets to serve recovery",
					__func__);
			fileRead.close();
			m_dfRetryTimer.stop();

			if(vecIter == fileVect.end()) {
				serveNextFile = 0;
				ELogger::log(LOG_SYSTEM).debug("{}: No furthur file to serve recovery",
						__func__);
			} else {
				pkt_cnt = -1;
				serveNextFile = 1;
				ELogger::log(LOG_SYSTEM).debug("{}: Next File is there to serve recovery",
						__func__);
			}

			vecIter = fileVect.begin();
			while(*vecIter++ != file_name);

			fileRead.open(file_name, std::ios::in);
			if (fileRead.fail()) {
				ELogger::log(LOG_SYSTEM).info("[{}->{}:{}] : Opening of file {} fails for read mode",
						__file__, __FUNCTION__, __LINE__, file_name);
			}

			msg_cnt.Increment();

			pending_data_flag = 0;
			return;
		}

		uint32_t pktLen = 0;
		uint32_t seqNum = 0;
		uint32_t dataLen = 0;
		uint64_t liId = 0;
		uint64_t imsi = 0;

		std::memset(payloadBuf, '\0', SEND_BUF_SIZE);

		sscanf((const char *)readBuf, ("%u,%u,%lu,%lu,%u"), &pktLen, &seqNum, &liId, &imsi, &dataLen);


		uint16_t cnt = 0;
                uint16_t iter = 0;

#define NUMB_OF_DELIMITERS 5

                for(iter = 0; iter < SEND_BUF_SIZE; iter++) {
                        if (readBuf[iter] == ',')
                                cnt++;
                        if (cnt == NUMB_OF_DELIMITERS) {
                                iter++;
                                break;
                        }
                }
                std::memcpy(payloadBuf, readBuf + iter, SEND_BUF_SIZE-iter-1);


		uint8_t buf[pktLen];
		std::memset(buf, '\0', pktLen);

	        DfPacket_t *pkt = (DfPacket_t *)buf;

                pkt->header.sequenceNumber = htonl(seqNum);
                pkt->header.liIdentifier = liId;
                pkt->header.imsiNumber = imsi;
                pkt->header.dataLength = htonl(dataLen);
                pkt->packetLength = htonl(pktLen);
                std::memcpy(pkt->data, payloadBuf, ntohl(pkt->header.dataLength));

		ELogger::log(LOG_SYSTEM).debug("{} ::recovery df packet packet details", __func__);
		ELogger::log(LOG_SYSTEM).debug("Packet length {}", pktLen);
		ELogger::log(LOG_SYSTEM).debug("Sequence number {}", seqNum);
		ELogger::log(LOG_SYSTEM).debug("IMSI {}", pkt->header.imsiNumber);
		ELogger::log(LOG_SYSTEM).debug("LI identifier {}", pkt->header.liIdentifier);
		ELogger::log(LOG_SYSTEM).debug("Data length {}", dataLen);

		ELogger::log(LOG_SYSTEM).info("Sending recovery for failed packet with seq number {}",
				seqNum);

		if (m_legacyIntfc) {
			m_legacyIntfc->SendMessageToLegacyInterface(buf, ntohl(pkt->packetLength));
			pkt_cnt++;

			send_bytes_track += SEND_BUF_SIZE;
		}
	}
}

Void TCPListener::msgCounter(uint32_t ack_number)
{
	ELogger::log(LOG_SYSTEM).info("{} :Acknowledgement received from DF for sequence number {}",
			__func__, ack_number);
	msg_cnt.Increment();

#define MAX_ENTRY_COUNT 10000

	uint8_t str[SEND_BUF_SIZE];

	std::memset(str, '\0', SEND_BUF_SIZE);

	fileRead.seekg(read_bytes_track, std::ios::beg);
	fileRead.read((char *)str, SEND_BUF_SIZE);

	if (!fileRead.eof()) {
		read_bytes_track += SEND_BUF_SIZE;
		read_count++;

		ELogger::log(LOG_SYSTEM).debug("{} : read_count is {}", __func__, read_count);
	} else {
		ELogger::log(LOG_SYSTEM).debug("{} :No furthur data available in file {}", __func__, file_name);

		fileRead.close();
		vecIter = fileVect.begin();

                while(*vecIter++ != file_name);

		fileRead.open(file_name, std::ios::in);
                if (fileRead.fail()) {
                	ELogger::log(LOG_SYSTEM).info("[{}->{}:{}] : Opening of file {} fails for read mode",
                        	__file__, __FUNCTION__, __LINE__, file_name);
                }
	}
	if (read_count > (MAX_ENTRY_COUNT - 1)) {
		ELogger::log(LOG_SYSTEM).debug("{} : ACK received for whole file read_count is {}", __func__, read_count);

		if(vecIter == fileVect.end()) {
			ELogger::log(LOG_SYSTEM).debug("{} : Reached to last file, no more files ", __func__);
		} else {
			ELogger::log(LOG_SYSTEM).debug("{} : Next file is present, reading ", __func__);
			read_count = 0;
			read_bytes_track = 0;
			fileRead.close();
			deleteFile();
			readFile();
			serveNextFile = 0;

		}
	}
}

Void TCPListener::createFolder()
{
#define FILE_PERM 0777
	std::string dir_name = config.strDirName;
	struct stat check_dir;

	if(stat(dir_name.c_str(), &check_dir) == 0) {
		ELogger::log(LOG_SYSTEM).info("[{}->{}:{}] : Folder already exist",
				__file__, __FUNCTION__, __LINE__);
	} else if ((mkdir(dir_name.c_str(), FILE_PERM)) != -1){
		ELogger::log(LOG_SYSTEM).info("[{}->{}:{}] : Folder created successfully",
				__file__, __FUNCTION__, __LINE__);
	}
}


bool TCPListener::createFile()
{
	std::string file_name;

	time_t time_now;
	struct tm *time_current;

	time_now = time(0);
	time_current = localtime(&time_now);

#define DELIMITER_CHAR  "_"
#define EXTENSION_TYPE  ".data"
#define DB_FILE_NAME    "/DataBase"

	file_name = config.strDirName + DB_FILE_NAME + DELIMITER_CHAR +
		std::to_string(time_current->tm_hour) + DELIMITER_CHAR +
		std::to_string(time_current->tm_min) + DELIMITER_CHAR +
		std::to_string(time_current->tm_sec) + EXTENSION_TYPE;

	fileWrite.open(file_name, std::ios::app);
	if (fileWrite.fail() || (checkAvailableSapce() == 1)) {
		ELogger::log(LOG_SYSTEM).critical("[{}->{}:{}] : Creating {} fails in create_store_dir for write mode",
				__file__, __FUNCTION__, __LINE__, file_name);

		return 1;
	} else {
		fileVect.push_back(file_name);
	}

	return 0;
}


Void TCPListener::readFile()
{
	if(vecIter != fileVect.end()) {
		file_name = *vecIter++;
		msgCntr_file_name.clear();
		msgCntr_file_name =file_name;

		fileRead.open(file_name, std::ios::in);
		if (fileRead.fail()) {
			ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Opening of file {} fails for read mode",
					__file__, __FUNCTION__, __LINE__, file_name);
		}
	} else {
		vecIter = fileVect.begin();
                while(*vecIter++ != file_name);
	}
}

Void TCPListener::deleteFile()
{
	if (remove (msgCntr_file_name.c_str()) == 0) {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : File {} deleted successfully",
				__file__, __FUNCTION__, __LINE__, msgCntr_file_name);
	} else {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Problem in deleting file {} ",
				__file__, __FUNCTION__, __LINE__, msgCntr_file_name);
	}
}

bool TCPListener::checkAvailableSapce()
{
	struct statvfs stat;

	if (statvfs((config.strDirName).c_str(), &stat) != 0)
		return 1;

	if (stat.f_bsize * stat.f_bavail < 512) {
		ELogger::log(LOG_SYSTEM).critical("[{}->{}:{}] : Space issue in {} directory, storing of packets may hamper",
				__file__, __FUNCTION__, __LINE__, config.strDirName);

		return 1;
	}

	return 0;
}

Void
TCPListener::checkSocket()
{

	ELogger::log(LOG_SYSTEM).debug("Legacy DF socket is closed");

	legacy_conn = 1;
}

