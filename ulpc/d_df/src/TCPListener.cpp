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
#include "TCPForwardInterface.h"


extern struct Configurations config;


TCPListener :: TCPListener ()
	: m_maxMsgs(10),
	  m_ptrListener(NULL),
	  m_ptrDataProcessor{NULL},
	  m_ptrForwardInterface(NULL)
{
	msg_cnt.init(m_maxMsgs);
	fileVect.reserve(70);
}


TCPListener :: ~TCPListener()
{
}


Void
TCPListener::onInit()
{
#define TIMER_INTERVAL 1000

	m_dfRetryTimer.setInterval(TIMER_INTERVAL);
	m_dfRetryTimer.setOneShot(False);
	initTimer(m_dfRetryTimer);

	m_ptrListener = new DdfListener(*this);
	
//	m_ptrListener->listen(config.ddf_port, BACKLOG_CONNECTIION);

	m_ptrListener->getLocalAddress().setAddress(config.ddf_ip, config.ddf_port);
	m_ptrListener->setBacklog(BACKLOG_CONNECTIION);

	m_ptrListener->listen();

	ELogger::log(LOG_SYSTEM).info("DDF listener started on port {}",
			config.ddf_port);
	createFolder();
	if (createFile() == 0) {
		vecIter = fileVect.begin();
		readFile();
	}
	connect();
}


Void
TCPListener::onQuit()
{
	if (NULL != m_ptrListener) {

		freePcapDumper();

		delete m_ptrListener;
		m_ptrListener = NULL;
	}

	if ((NULL != m_ptrForwardInterface) &&
			(m_ptrForwardInterface->getState() == ESocket::SocketState::Connected)) {

		m_ptrForwardInterface->close();
	}

	m_ptrDataProcessor.clear();

	fileWrite.close();
	fileRead.close();

	fileVect.clear();
}


Void
TCPListener::onTimer(EThreadEventTimer *ptimer)
{
	if (ptimer->getId() == m_dfRetryTimer.getId()) {
		if (timer_flag == 1) {
			ELogger::log(LOG_SYSTEM).debug("Connecting to DF");
			connect();
		} else {
			ELogger::log(LOG_SYSTEM).debug("Sending failed packets to DF");
			sendPending();
		}
	}
}


Void
TCPListener::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	ELogger::log(LOG_SYSTEM).debug("TCPListener::errorHandler() - socket exception"
			" -  {}", err.what());
}

Void
TCPListener::startDfRetryTimer()
{
	m_dfRetryTimer.start();
	ELogger::log(LOG_SYSTEM).debug("Timer started for retrying failure messages/re-connecting to DF ");
}

Void
TCPListener::stopDfRetryTimer()
{
	m_dfRetryTimer.stop();
	ELogger::log(LOG_SYSTEM).debug("Timer stopped for retrying failure messages/re-connecting to DF ");
}


Void
TCPListener::connect()
{
	m_ptrForwardInterface = new TCPForwardInterface(*this);
	if (NULL == m_ptrForwardInterface) {

		ELogger::log(LOG_SYSTEM).info("Failed to create object of"
				" Forward Interface.");
		return;
	}

	m_ptrForwardInterface->connect(config.df_ip, config.df_port);

	ELogger::log(LOG_SYSTEM).info("DF connection initiated");
}


TCPDataProcessor *
TCPListener::createDdfTalker()
{
	TCPDataProcessor *talker = new TCPDataProcessor(*this);
	if (NULL != talker) {

		m_ptrDataProcessor.push_back(talker);
		return talker;
	}

	return NULL;
}


Void
TCPListener::sendPacketToDf(const DfPacket_t *packet)
{
	bool space_flag = 0;            /* Flag to indicate space availibility on disc */

	ELogger::log(LOG_SYSTEM).debug("{} :: sending DFPACKET_DATA for sequence"
			" number {}", __func__, packet->header.sequenceNumber);

#define MAX_ENTRY_COUNT 10000

	if (entry_cnt > (MAX_ENTRY_COUNT-1)) {
		if(pkt_cnt != entry_cnt) {
			 ELogger::log(LOG_SYSTEM).debug("{} :: Packet sequence numb mismatched "
                                "packet count {} entry count {}", __func__, pkt_cnt, entry_cnt);

			setPending();
		}

		entry_cnt = 0;
		pkt_cnt = 0;

		fileWrite.close();

		createFile();
	}

	if (checkAvailableSapce() == 0) {

		uint16_t ret = 0;

		std::memset(writeBuf, '\0', SEND_BUF_SIZE);

		ret = snprintf((char *)writeBuf, SEND_BUF_SIZE, "%u,%u,%lu,%lu,%u,", ntohl(packet->packetLength),
				ntohl(packet->header.sequenceNumber), packet->header.liIdentifier,
				packet->header.imsiNumber, ntohl(packet->header.dataLength));
		std::memcpy(writeBuf + ret, packet->data, ntohl(packet->header.dataLength));

		fileWrite.write((const char *)writeBuf, SEND_BUF_SIZE);
		entry_cnt++;
	}
	else
		space_flag = 1;

	if ((NULL != m_ptrForwardInterface) &&
			(m_ptrForwardInterface->getState() == ESocket::SocketState::Connected) &&
			(pkt_cnt+1 == entry_cnt)) {
		if(msg_cnt.Decrement(False)) {
			m_ptrForwardInterface->sendData(packet);
			if (space_flag == 0)
				pkt_cnt++;
		}
	} else if (pkt_cnt+1 != entry_cnt) {
		ELogger::log(LOG_SYSTEM).debug("{} :: Packet sequence numb mismatched as DDF not conn"
                        "packet count {} entry count {}", __func__, pkt_cnt, entry_cnt);

		setPending();
	}
}

Void
TCPListener::setPending()
{
	if ((pkt_cnt == -1) && (serveNextFile == 1)) {
                ELogger::log(LOG_SYSTEM).debug("{} : There is another file to serve for recovery"
                        ", waiting for ack from prev", __func__);

                return;
        }

        if (pending_data_flag == 1) {
                ELogger::log(LOG_SYSTEM).debug("{} : Recovery is in progress", __func__);

                return;
        }


	if ((NULL != m_ptrForwardInterface) &&
                        (m_ptrForwardInterface->getState() == ESocket::SocketState::Connected)) {
		if (timer_flag == 1) {
			ELogger::log(LOG_SYSTEM).debug("{}: Stopping timer as DF is connected to DDF",
					__func__);

			stopDfRetryTimer();
			timer_flag = 0;
		}
		pending_data_flag = 1;

		if (serveNextFile == 0) {
			send_bytes_track = read_bytes_track;
			pkt_cnt = read_count;
		}
		startDfRetryTimer();
	        ELogger::log(LOG_SYSTEM).debug("{} : Timer has been started for recovery, "
				"pending_data_flag is set to 1", __func__);
	}
}


Void
TCPListener::sendPending()
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

	if ((NULL != m_ptrForwardInterface) &&
			(m_ptrForwardInterface->getState() == ESocket::SocketState::Connected) &&
			(msg_cnt.Decrement(False))) {

		std::memset(readBuf, '\0', SEND_BUF_SIZE);

		fileRead.seekg(send_bytes_track, std::ios::beg);
		fileRead.read((char *)readBuf, SEND_BUF_SIZE);

		if(fileRead.eof()) {
			ELogger::log(LOG_SYSTEM).debug("{} : File is empty, no packets to serve recovery",
					 __func__);

			fileRead.close();
			m_dfRetryTimer.stop();

			if(vecIter == fileVect.end()) {
				ELogger::log(LOG_SYSTEM).debug("{}: Timer has been stopped as recovery"
				" is completed", __func__);

				serveNextFile = 0;
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
		memcpy(payloadBuf, readBuf + iter, SEND_BUF_SIZE-iter-1);

//		UChar *buf = [SEND_BUF_SIZE];
		std::memset(readBuf, '\0', SEND_BUF_SIZE);

		DfPacket_t *pkt = (DfPacket_t *)readBuf;

		pkt->header.sequenceNumber = htonl(seqNum);
		pkt->header.liIdentifier = liId;
		pkt->header.imsiNumber = imsi;
		pkt->header.dataLength = htonl(dataLen);
		pkt->packetLength = htonl(pktLen);
		std::memcpy(pkt->data, payloadBuf, ntohl(pkt->header.dataLength));

		ELogger::log(LOG_SYSTEM).info("{}: Sending failed message to DF with seq numb {}",
				__func__, seqNum);
		ELogger::log(LOG_SYSTEM).debug("{}: Sending failed message to DF with seq numb {}",
				__func__, seqNum);

		m_ptrForwardInterface->sendData(pkt);
		pkt_cnt++;

		send_bytes_track += SEND_BUF_SIZE;
	}
}

Void
TCPListener::msgCounter(uint32_t ack_number)
{
	ELogger::log(LOG_SYSTEM).info("Acknowledgement received from DF"
			" for sequence number {}", ack_number);
	ELogger::log(LOG_SYSTEM).debug("Acknowledgement received from DF"
			" for sequence number {}", ack_number);
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
		ELogger::log(LOG_SYSTEM).info("No furthur data available"
				"in file {}", file_name);
		ELogger::log(LOG_SYSTEM).debug("No furthur data available"
				"in file {}", file_name);

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
                        ELogger::log(LOG_SYSTEM).debug("{} : Reached to last file, no more files {}", __func__);
                } else {
                        ELogger::log(LOG_SYSTEM).debug("{} : Next file is present, reading the same {}", __func__);

                        read_count = 0;
                        read_bytes_track = 0;
                        fileRead.close();
                        deleteFile();
                        readFile();
                        serveNextFile = 0;

                }
        }

}

Void
TCPListener::createFolder()
{
	std::string dir_name = config.strDirName;
	struct stat check_dir;

#define FILE_PERM	0777

	if(stat(dir_name.c_str(), &check_dir) == 0) {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Folder already exist",
				__file__, __FUNCTION__, __LINE__);
	} else if ((mkdir(dir_name.c_str(), FILE_PERM)) != -1){
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Folder created successfully",
				__file__, __FUNCTION__, __LINE__);
	}
}

bool
TCPListener::createFile()
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
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Opening {} fails in for write mode",
				__file__, __FUNCTION__, __LINE__, file_name);
		return 1;
	} else {
		fileVect.push_back(file_name);
	}

	return 0;
}

Void
TCPListener::readFile()
{
	if(vecIter != fileVect.end()) {
		file_name = *vecIter++;

		fileRead.open(file_name, std::ios::in);
		if (fileRead.fail()) {
			ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Opening of file {}"
					"fails for read mode",
					__file__, __FUNCTION__, __LINE__, file_name);
		}
	}
}

Void
TCPListener::deleteFile()
{
	if (remove (file_name.c_str()) == 0) {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : File {} deleted successfully",
				__file__, __FUNCTION__, __LINE__, file_name);

	} else {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Problem in deleting file {} ",
				__file__, __FUNCTION__, __LINE__, file_name);
	}
}

bool
TCPListener::checkAvailableSapce()
{
	struct statvfs stat;

	if (statvfs((config.strDirName).c_str(), &stat) != 0)
		return 1;

#define MIN_SPACE 512

	if (stat.f_bsize * stat.f_bavail < MIN_SPACE) {
		ELogger::log(LOG_SYSTEM).debug("[{}->{}:{}] : Space issue in {} directory,"
				"storing of packets may hamper",
				__file__, __FUNCTION__, __LINE__, config.strDirName);
		return 1;
	}

	return 0;
}


Void
TCPListener::onSocketClosed(ESocket::BasePrivate *psocket) {

	if (psocket == m_ptrListener) {

		ELogger::log(LOG_SYSTEM).info("Listener socket closed");
		freePcapDumper();
		m_ptrListener = NULL;

	} else if (!m_ptrDataProcessor.empty()) {

		std::list <TCPDataProcessor *>::iterator itr;
		itr = std::find(m_ptrDataProcessor.begin(), m_ptrDataProcessor.end(),
				psocket);
		if (itr != m_ptrDataProcessor.end()) {

			m_ptrDataProcessor.erase(itr);
		}
	}
	ELogger::log(LOG_SYSTEM).info("{} socket closed {}", __func__,
			((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress());

	if (NULL != psocket) {

		delete psocket;
	}
}

Void
TCPListener::onSocketError(ESocket::BasePrivate *psocket) {
        ELogger::log(LOG_SYSTEM).info("{} socket error {} {} ", __func__,
                        ((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress(),
                        psocket->getErrorDescription());

        onSocketClosed(psocket);
}

Void
TCPListener::checkSocket()
{
	if(m_ptrForwardInterface->getState() != ESocket::SocketState::Connected) {
		if (timer_flag == 0)
			startDfRetryTimer();

		timer_flag = 1;
	}
}

pcap_dumper_t *
TCPListener::getPcapDumper(const uint64_t uiImsi, const uint64_t uiId)
{
	pcap_t *pcap = NULL;
	pcap_dumper_t *pcap_dumper = NULL;
	std::map<std::string, pcap_dumper_t *>::const_iterator itr;

	pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);

	std::string strFileName = config.strDFilePath;
	strFileName += std::to_string(uiImsi);
	strFileName += "_";
	strFileName += std::to_string(uiId);
	strFileName += ".pcap";

	ELogger::log(LOG_SYSTEM).debug("File name {}", strFileName);

	itr = mapPcapDumper.find(strFileName);
	if (itr != mapPcapDumper.end()) {

		pcap_dumper = itr->second;
	} else {

		pcap_dumper = (pcap_dumper_t *)malloc(sizeof(pcap_dumper));
		if (NULL == pcap_dumper) {

			ELogger::log(LOG_SYSTEM).critical("[{}->{}:{}] : Error while allocating"
					" memory to pcap dumper", __file__, __FUNCTION__, __LINE__);
			return NULL;
		}

		if (access(strFileName.c_str(), F_OK) != ERROR) {

			pcap_dumper = pcap_dump_open_append(pcap, strFileName.c_str());
		} else {

			pcap_dumper = pcap_dump_open(pcap, strFileName.c_str());
		}

		mapPcapDumper.insert({strFileName, pcap_dumper});
	}

	return pcap_dumper;
}

void
TCPListener::freePcapDumper()
{
	std::map<std::string, pcap_dumper_t *>::iterator itr;

	for (itr = mapPcapDumper.begin(); itr != mapPcapDumper.end(); ++itr) {

		free(itr->second);
		itr->second = NULL;
	}

	mapPcapDumper.clear();
}

