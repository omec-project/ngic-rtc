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

#include "tcp_listener.h"
#include "tcp_forwardinterface.h"


extern struct Configurations config_li;


TCPListener :: TCPListener ()
	: m_maxMsgs(10),
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

}


Void
TCPListener::onQuit()
{
	if ((NULL != m_ptrForwardInterface) &&
			(m_ptrForwardInterface->getState() == ESocket::SocketState::Connected)) {

		m_ptrForwardInterface->close();
	}

	fileWrite.close();
	fileRead.close();

	fileVect.clear();
}


Void
TCPListener::onTimer(EThreadEventTimer *ptimer)
{
	if (ptimer->getId() == m_dfRetryTimer.getId()) {
		if (timer_flag == 1) {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Timer has been "
					"expired trying to reconnect for %s",
					LOG_VALUE, modeType);
			connect();
		} else {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Timer has been "
					"expired sending failed packets for %s",
					LOG_VALUE, modeType);
			sendPending();
		}
	}
}


Void
TCPListener::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
}

Void
TCPListener::startDfRetryTimer()
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Starting Timer for %s",
			LOG_VALUE, modeType);
	m_dfRetryTimer.start();
}

Void
TCPListener::stopDfRetryTimer()
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Stoping Timer for %s",
			LOG_VALUE, modeType);
	m_dfRetryTimer.stop();
}

Void
TCPListener::initDir(const uint8_t *ddf_ip, uint16_t port, const uint8_t *ddf_local_ip,
		uint8_t *mode)
{
	std::memcpy(ipDdfAddr, ddf_ip, strlen((const char*)ddf_ip));
	std::memcpy(ipDdfLocalAddr, ddf_local_ip, strlen((const char*)ddf_local_ip));
	portAddr = port;
	modeType = mode;

	clLog(STANDARD_LOGID, eCLSeverityInfo, LOG_FORMAT"IP address is %s "
			"port is %hu, Local IP address is %s Mode is %s",
			LOG_VALUE, ipDdfAddr, portAddr, ipDdfLocalAddr, modeType);

	createFolder();
	if (createFile() == 0) {
		vecIter = fileVect.begin();
		readFile();
	}
}

Void
TCPListener::connect()
{
	m_ptrForwardInterface = new TCPForwardInterface(*this);
	if (NULL == m_ptrForwardInterface) {

		clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Issue in "
				"creating object of TCPForwardInterface",
				LOG_VALUE);

		return;
	}

	try {
		struct sockaddr_in addr4 = {0};
		struct sockaddr_in6 addr6 = {0};

		if (inet_pton(AF_INET, (const char *)ipDdfLocalAddr, &addr4.sin_addr.s_addr)) {

			addr4.sin_family = AF_INET;
			ESocket::Address address(addr4);
			m_ptrForwardInterface->setLocal(address);

		} else if (inet_pton(AF_INET6, (const char *)ipDdfLocalAddr, addr6.sin6_addr.s6_addr)) {

			addr6.sin6_family = AF_INET6;
			ESocket::Address address(addr6);
			m_ptrForwardInterface->setLocal(address);
		}

		m_ptrForwardInterface->connect((cpStr)ipDdfAddr, portAddr);
	}
	catch (const std::exception &e) {
		/* clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"TCPListener exception: %s",
				LOG_VALUE, e.what()); */
	}
}

Void
TCPListener::sendPacketToDdf(DdfPacket_t *packet)
{
	bool space_flag = 0;            /* Flag to indicate space availibility on disc */

	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Sending DDFPACKET_DATA "
			"for sequence numb %u to %s",
			LOG_VALUE, packet->header.sequenceNumber, modeType);

#define MAX_ENTRY_COUNT 10000

	if (entry_cnt > MAX_ENTRY_COUNT) {
		if(pkt_cnt != entry_cnt) {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Sequence numb  "
					"mismatched packet count %hu to  entry count %hu %s",
					LOG_VALUE, pkt_cnt, entry_cnt, modeType);

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

		ret = snprintf((char *)writeBuf, SEND_BUF_SIZE, "%u,%lu,%lu,%c,%u,%u,%c,%u,%u,%hu,%hu,%c,%c,", 
				ntohl(packet->packetLength), packet->header.liIdentifier, 
				packet->header.imsiNumber, packet->header.operationMode, 
				ntohl(packet->header.sequenceNumber), ntohl(packet->header.dataLength),
				packet->header.typeOfPayload, packet->header.sourceIpAddress,
				packet->header.destIpAddress, packet->header.sourcePort,
				packet->header.destPort, packet->header.src_ip_type, 
				packet->header.dst_ip_type);

		std::memcpy(writeBuf + ret, packet->header.src_ipv6, IPV6_ADDRESS_LEN);
		ret += IPV6_ADDRESS_LEN;
		writeBuf[ret] = ',';
		ret++;

		std::memcpy(writeBuf + ret, packet->header.dst_ipv6, IPV6_ADDRESS_LEN);
		ret += IPV6_ADDRESS_LEN;
		writeBuf[ret] = ',';
		ret++;

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
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Packet sequence numb  "
				"mismatched packet count %hu to  entry count %hu %s",
				LOG_VALUE, pkt_cnt, entry_cnt, modeType);

		setPending();
	}
}

Void
TCPListener::setPending()
{
	if ((pkt_cnt == -1) && (serveNextFile == 1)) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Another file is present "
				"to serve recovery for %s",
				LOG_VALUE, modeType);
      		return;
        }

        if (pending_data_flag == 1) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Recovery is in progress "
				"for %s",
				LOG_VALUE, modeType);

                return;
        }

	if ((NULL != m_ptrForwardInterface) &&
                        (m_ptrForwardInterface->getState() == ESocket::SocketState::Connected)) {
                if (timer_flag == 1) {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Stopping timer "
					"as connected to %s",
					LOG_VALUE, modeType);

                        stopDfRetryTimer();
                        timer_flag = 0;
                }
                pending_data_flag = 1;

                if (serveNextFile == 0) {
                        send_bytes_track = read_bytes_track;
                        pkt_cnt = read_count;
                }
                startDfRetryTimer();
        }
}


Void
TCPListener::sendPending()
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Checking any pending "
			"packets availbale for %s",
			LOG_VALUE, modeType);

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
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"File is empty, "
					"no packets to serve for %s",
					LOG_VALUE, modeType);

			fileRead.close();
			stopDfRetryTimer();

			if(vecIter == fileVect.end()) {
				clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Timer is stopped, "
						"recovery is completed for %s",
						LOG_VALUE, modeType);

				serveNextFile = 0;
			} else {
				pkt_cnt = -1;
                                serveNextFile = 1;
				clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Next file is, "
						"present to serve recovery for %s",
						LOG_VALUE, modeType);
			}

			vecIter = fileVect.begin();
                        while(*vecIter++ != file_name);

			fileRead.open(file_name, std::ios::in);
			if (fileRead.fail()) {
				clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Opening of file, "
						"failed for %s",
						LOG_VALUE, modeType);
			}

			msg_cnt.Increment();

			pending_data_flag = 0;
			return;
		}

		uint32_t pktLen = 0;
		uint8_t  typePyld = 0;
                uint64_t liId = 0;
                uint64_t imsi = 0;
		uint8_t srcIpType = 0;
		uint32_t srcIp = 0;
		uint8_t srcIpv6[IPV6_ADDRESS_LEN] = {'\0'};
		uint16_t srcPrt = 0;
		uint8_t destIpType = 0;
		uint32_t destIp = 0;
		uint8_t destIpv6[IPV6_ADDRESS_LEN] = {'\0'};
		uint16_t destPrt = 0;
		uint8_t opMode = 0;
                uint32_t seqNum = 0;
                uint32_t dataLen = 0;
                
		std::memset(payloadBuf, '\0', SEND_BUF_SIZE);

		sscanf((const char *)readBuf, ("%u,%lu,%lu,%c,%u,%u,%c,%u,%u,%hu,%hu,%c,%c"), &pktLen, 
			&liId, &imsi, &opMode, &seqNum, &dataLen, &typePyld, &srcIp, &destIp, &srcPrt, 
			&destPrt, &srcIpType, &destIpType);

		uint16_t cnt = 0;
                uint16_t iter = 0;
#define NUMB_OF_DELIMITERS 13

                for(iter = 0; iter < SEND_BUF_SIZE; iter++) {
                        if (readBuf[iter] == ',')
                                cnt++;
			else
				continue;

                        if (cnt == NUMB_OF_DELIMITERS) {
                                iter++;
				memcpy(srcIpv6, readBuf + iter, IPV6_ADDRESS_LEN);
                        }
			else if (cnt == NUMB_OF_DELIMITERS + 1) {
                                iter++;
				memcpy(destIpv6, readBuf + iter, IPV6_ADDRESS_LEN);
			}
			else if (cnt == NUMB_OF_DELIMITERS + 2) {
                                iter++;
				memcpy(payloadBuf, readBuf + iter, SEND_BUF_SIZE-iter-1);
                                break;
			}
                }

		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Data read from file is, "
				"pktLen = %u, typePyld = %c, liId = %lu, imsi = %lu, srcIpType = %c, "
				"srcIp = %u, srcIpv6 = %s, srcPrt = %hu, destIpType = %c, destIp = %u, "
				"destIpv6 = %s, destPrt = %hu, opMode = %c, seqNum = %u, "
				"dataLen = %u", LOG_VALUE, pktLen, typePyld, liId, imsi, srcIpType, srcIp, 
				srcIpv6, srcPrt, destIpType, destIp, destIpv6, destPrt, opMode, seqNum, dataLen);

                std::memset(readBuf, '\0', SEND_BUF_SIZE);
		DdfPacket_t *pkt = (DdfPacket_t *)readBuf;

		pkt->header.typeOfPayload = typePyld;
		pkt->header.liIdentifier = liId;
		pkt->header.imsiNumber = imsi;
		pkt->header.src_ip_type = srcIpType;
		pkt->header.sourceIpAddress = srcIp;
		pkt->header.sourcePort = srcPrt;
		pkt->header.dst_ip_type = destIpType; 
		pkt->header.destIpAddress = destIp;
		pkt->header.destPort = destPrt;
		pkt->header.operationMode = opMode;
		pkt->header.dataLength = htonl(dataLen);
		pkt->header.sequenceNumber = htonl(seqNum);
		pkt->packetLength = htonl(pktLen);

		std::memcpy(pkt->header.src_ipv6, srcIpv6, IPV6_ADDRESS_LEN);
		std::memcpy(pkt->header.dst_ipv6, destIpv6, IPV6_ADDRESS_LEN);
		std::memcpy(pkt->data, payloadBuf, ntohl(pkt->header.dataLength));

		clLog(STANDARD_LOGID, eCLSeverityInfo, LOG_FORMAT"Sending failed "
				"msg with seq numb %u for %s",
				LOG_VALUE, ntohl(pkt->header.sequenceNumber), modeType);
	
		m_ptrForwardInterface->sendData(pkt);
		pkt_cnt++;

		send_bytes_track += SEND_BUF_SIZE;
	}
}

Void
TCPListener::msgCounter(uint32_t ack_number)
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Acknowledgement "
			"received from %s for sequence numb %u",
			LOG_VALUE, modeType, ack_number);

	msg_cnt.Increment();

#define MAX_ENTRY_COUNT 10000

#define SEND_BUF_SIZE 4096

	uint8_t str[SEND_BUF_SIZE];
        std::memset(str, '\0', SEND_BUF_SIZE);

        fileRead.seekg(read_bytes_track, std::ios::beg);
        fileRead.read((char *)str, SEND_BUF_SIZE);

        if (!fileRead.eof()) {
                read_bytes_track += SEND_BUF_SIZE;
                read_count++;

		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"read_count is %hu "
				"for file %s for %s",
				LOG_VALUE, read_count, file_name.c_str(), modeType);
        } else {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"No furthur data "
				"available in file %s for %s",
				LOG_VALUE, file_name.c_str(), modeType);

                fileRead.close();

                vecIter = fileVect.begin();

                while(*vecIter++ != file_name);

                fileRead.open(file_name, std::ios::in);
                if (fileRead.fail()) {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Opening of "
					"file %s fails in read mode for %s",
					LOG_VALUE, file_name.c_str(), modeType);
                }
        }
	
	if (read_count > (MAX_ENTRY_COUNT - 1)) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"ACK received "
				"for whole file %s  read_count is %hu for %s",
				LOG_VALUE, file_name.c_str(), read_count, modeType);

                if(vecIter == fileVect.end()) {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Reached to last "
					"file, no more files for %s",
					LOG_VALUE, modeType);
                } else {
			clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Next file is "
					"present, reading for %s",
					LOG_VALUE, modeType);

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
	std::string dir_name = config_li.strDirName;
	struct stat check_dir;

#define FILE_PERM	0777

	if(stat(dir_name.c_str(), &check_dir) == 0) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Folder already exist",
				LOG_VALUE);
	} else if ((mkdir(dir_name.c_str(), FILE_PERM)) != -1){
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Folder created successfully",
				LOG_VALUE);
	}
}

bool
TCPListener::createFile()
{
	std::string file_name;

	time_t time_now;
	struct tm *time_current;
	std::string modetypeS((const char *)modeType);

	time_now = time(0);
	time_current = localtime(&time_now);

#define DELIMITER_CHAR  "_"
#define EXTENSION_TYPE  ".data"
#define DB_FILE_NAME    "/li_packets"

	file_name = config_li.strDirName + DB_FILE_NAME + modetypeS + 
		DELIMITER_CHAR + std::to_string(time_current->tm_hour) + 
		DELIMITER_CHAR + std::to_string(time_current->tm_min) + 
		DELIMITER_CHAR + std::to_string(time_current->tm_sec) + 
		EXTENSION_TYPE;

	fileWrite.open(file_name, std::ios::app);
	if (fileWrite.fail() || (checkAvailableSapce() == 1)) {
		clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Opening %s fails ",
				"in for write mode",
				LOG_VALUE, file_name.c_str());
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
			clLog(STANDARD_LOGID, eCLSeverityCritical, LOG_FORMAT"Opening %s fails ",
					"in for read mode",
					LOG_VALUE, file_name.c_str());
		}
	}
}

Void
TCPListener::deleteFile()
{
	if (remove (file_name.c_str()) == 0) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"File %s deleted ",
				"successfully",
				LOG_VALUE, file_name.c_str());

	} else {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Problem in deleting ",
				"file %s",
				LOG_VALUE, file_name.c_str());
	}
}

bool
TCPListener::checkAvailableSapce()
{
	struct statvfs stat;

	if (statvfs((config_li.strDirName).c_str(), &stat) != 0)
		return 1;

#define MIN_SPACE 512

	if (stat.f_bsize * stat.f_bavail < MIN_SPACE) {
		clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Space issue in %s ",
				"directory, storing of packets may hamper",
				LOG_VALUE, config_li.strDirName.c_str());
		return 1;
	}

	return 0;
}


Void
TCPListener::onSocketClosed(ESocket::BasePrivate *psocket) {
	if (NULL != psocket) {

		delete psocket;
	}
}

Void
TCPListener::onSocketError(ESocket::BasePrivate *psocket) {
#if 0
        ELogger::log(LOG_SYSTEM).info("{} socket error {} {} ", __func__,
                        ((ESocket::TCP::TalkerPrivate*)psocket)->getRemoteAddress(),
                        psocket->getErrorDescription());
#endif

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
