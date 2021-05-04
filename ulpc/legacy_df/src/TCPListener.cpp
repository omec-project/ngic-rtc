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
	: m_ptrListener(NULL),
	  m_ptrDataProcessor{NULL}
{
}


TCPListener :: ~TCPListener()
{
}


Void
TCPListener::onInit()
{

	m_ptrListener = new LegacyDfListener(*this);

//	m_ptrListener->listen(config.legacyPort, BACKLOG_CONNECTIION);

	m_ptrListener->getLocalAddress().setAddress(config.legacyIp, config.legacyPort);
	m_ptrListener->setBacklog(BACKLOG_CONNECTIION);

	m_ptrListener->listen();

	ELogger::log(LOG_SYSTEM).info("Legacy DF listener started on port {}",
			config.legacyPort);
}

Void
TCPListener::onQuit()
{
	if (NULL != m_ptrListener) {

		freePcapDumper();
		delete m_ptrListener;
		m_ptrListener = NULL;
	}

	m_ptrDataProcessor.clear();

}

Void
TCPListener::errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	ELogger::log(LOG_SYSTEM).debug("TCPListener::errorHandler() - socket exception"
			" -  {}", err.what());
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
TCPListener::onSocketClosed(ESocket::BasePrivate *psocket) {

	if (psocket == m_ptrListener) {

		ELogger::log(LOG_SYSTEM).debug("Listener socket closed");
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

pcap_dumper_t *
TCPListener::getPcapDumper(const uint64_t uiImsi, const uint64_t uiId)
{
	pcap_t *pcap = NULL;
	pcap_dumper_t *pcap_dumper = NULL;
	std::map<std::string, pcap_dumper_t *>::const_iterator itr;

	pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);

	std::string strFileName = config.strPcapFilePath;
	strFileName += std::to_string(uiImsi);
	strFileName += "_";
	strFileName += std::to_string(uiId);
	strFileName += ".pcap";

	ELogger::log(LOG_SYSTEM).debug("PCAP file name is {}", strFileName);

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
	std::map<std::string, pcap_dumper_t *>::const_iterator itr;

	for (itr = mapPcapDumper.begin(); itr != mapPcapDumper.end(); ++itr) {

		free(itr->second);
	}

	mapPcapDumper.clear();
}

