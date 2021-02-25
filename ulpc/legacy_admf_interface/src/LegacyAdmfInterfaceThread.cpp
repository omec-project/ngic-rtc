/*
 * Copyright (c) 2020 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include "LegacyAdmfInterfaceThread.h"
#include "Common.h"


BEGIN_MESSAGE_MAP(LegacyAdmfInterfaceThread, ESocket::ThreadPrivate)
END_MESSAGE_MAP()

LegacyAdmfInterfaceThread ::
LegacyAdmfInterfaceThread(LegacyAdmfInterface *intfc)
	:	legAdmfIntfc(intfc),
		legAdmfIntfcListener(NULL),
		legAdmfIntfcTalker(NULL),
		legAdmfClient(NULL),
		quitting(false)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread constructor");
}

LegacyAdmfInterfaceThread :: ~LegacyAdmfInterfaceThread()
{
}

Void
LegacyAdmfInterfaceThread :: onInit()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread onInit");
	legAdmfConnectTimer.setOneShot(True);
	initTimer(legAdmfConnectTimer);

	legAdmfIntfcListener = new LegacyAdmfInterfaceListener(*this);
	legAdmfIntfcListener->listen(getLegacyAdmfInterfacePort(), 10);
	LegacyAdmfInterface::log().info("Interface listening on port: {}",
			getLegacyAdmfInterfacePort());

	connect();

}

Void
LegacyAdmfInterfaceThread :: onQuit()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread onQuit");
	SAFE_DELETE_PTR(legAdmfIntfcListener);

	if (legAdmfClient) {
		legAdmfClient->close();
	}
}

Void
LegacyAdmfInterfaceThread :: onSocketClosed(ESocket::BasePrivate *psocket)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread onSocketClosed");

	if (psocket == legAdmfIntfcListener) {

		legAdmfIntfcListener = NULL;
		LegacyAdmfInterface::log().debug("Legacy Admf Intfc Listener set to NULL");

	} else if (psocket == legAdmfIntfcTalker) {

		legAdmfIntfcTalker = NULL;
		LegacyAdmfInterface::log().debug("Legacy Admf Intfc Talker set to NULL");

	} else if (psocket == legAdmfClient) {

		legAdmfClient = NULL;
		LegacyAdmfInterface::log().debug("Legacy Admf Client set to NULL");
		startLegacyAdmfConnectTimer();
	}
}

Void
LegacyAdmfInterfaceThread :: onClose()
{
}

Void
LegacyAdmfInterfaceThread :: onTimer(EThreadEventTimer *ptimer)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread onTimer()");
	if (ptimer->getId() == legAdmfConnectTimer.getId())
		connect();
}

Void
LegacyAdmfInterfaceThread :: errorHandler(EError &err, ESocket::BasePrivate *psocket)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread errorHandler() - "
			"socket exception : {}", err.what());
}

Void
LegacyAdmfInterfaceThread :: processData(void *packet)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread processData()");
	if ((legAdmfClient) && (legAdmfClient)->getState() == ESocket::SocketState::Connected)
	{
		admf_intfc_packet_t *admfIntfcPacket_t = 
				(reinterpret_cast<admf_intfc_packet_t *>(packet));

		legAdmfClient->sendData(admfIntfcPacket_t, ADMF_INTFC_PACKET);
	}
}

Void
LegacyAdmfInterfaceThread :: connect()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread connect()");
	legAdmfClient = new LegacyAdmfClient(*this);
	LegacyAdmfInterface::log().debug("LegacyAdmfIp: {}", getLegacyAdmfIp());
	LegacyAdmfInterface::log().debug("LegacyAdmfPort: {}", getLegacyAdmfPort());
	legAdmfClient->connect((getLegacyAdmfIp()).c_str(), getLegacyAdmfPort());

	LegacyAdmfInterface::log().info("Connected to legacyAdmf");
}

LegacyAdmfInterfaceTalker
*LegacyAdmfInterfaceThread :: createLegacyAdmfTalker()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread "
			"createLegacyAdmfTalker()");
	legAdmfIntfcTalker = new LegacyAdmfInterfaceTalker(*this);
	return legAdmfIntfcTalker;
}

Void
LegacyAdmfInterfaceThread :: startLegacyAdmfConnectTimer(Long ms)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread "
			"startLegacyAdmfConnectTimer()");
	legAdmfConnectTimer.setInterval(ms);
	legAdmfConnectTimer.start();
}

Void
LegacyAdmfInterfaceThread :: sendPending()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceThread sendPending()");
}
