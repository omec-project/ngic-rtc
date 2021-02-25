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


#ifndef __LEGACY_ADMF_INTERFACE_THREAD_H_
#define __LEGACY_ADMF_INTERFACE_THREAD_H_

#include <iostream>
#include <cstdlib>

#include "epctools.h"
#include "etevent.h"
#include "esocket.h"

#include "LegacyAdmfInterfaceListener.h"
#include "LegacyAdmfInterfaceTalker.h"
#include "LegacyAdmfClient.h"
#include "LegacyAdmfInterface.h"


class LegacyAdmfInterfaceListener;
class LegacyAdmfInterfaceTalker;
class LegacyAdmfClient;
class LegacyAdmfInterface;

class LegacyAdmfInterfaceThread : public ESocket::ThreadPrivate
{
	public:
		LegacyAdmfInterfaceThread(LegacyAdmfInterface *intfc);
		~LegacyAdmfInterfaceThread();

		Void onInit();
		Void onQuit();
		Void onSocketClosed(ESocket::BasePrivate *psocket);
		Void onClose();
		Void onTimer(EThreadEventTimer *ptimer);

		Void errorHandler(EError &err, ESocket::BasePrivate *psocket);

		Void processData(void *packet);

		Void connect();

		LegacyAdmfInterfaceTalker *createLegacyAdmfTalker();

		UShort getLegacyAdmfPort() const 
		{
			return legacyAdmfPort;
		}
		LegacyAdmfInterfaceThread &setLegacyAdmfPort(uint16_t port) 
		{
			legacyAdmfPort = port;
			return *this;
		}

		std::string getLegacyAdmfIp() const
		{
			return legacyAdmfIp;
		}
		LegacyAdmfInterfaceThread &setLegacyAdmfIp(std::string ip)
		{
			legacyAdmfIp = ip;
			return *this;
		}

		UShort getLegacyAdmfInterfacePort() const
		{
			return legacyAdmfInterfacePort;
		}
		LegacyAdmfInterfaceThread &setLegacyAdmfInterfacePort(uint16_t port)
		{
			legacyAdmfInterfacePort = port;
			return *this;
		}

		Void startLegacyAdmfConnectTimer(Long ms = 100000);

		LegacyAdmfInterface &getLegacyAdmfInterface()
		{
			return *legAdmfIntfc;
		}

		Void sendPending();

		DECLARE_MESSAGE_MAP()

	private:
		LegacyAdmfInterface *legAdmfIntfc;
		LegacyAdmfInterfaceListener *legAdmfIntfcListener;
		LegacyAdmfInterfaceTalker *legAdmfIntfcTalker;
		LegacyAdmfClient *legAdmfClient;
		EThreadEventTimer legAdmfConnectTimer;
		UShort legacyAdmfPort;
		std::string legacyAdmfIp;
		UShort legacyAdmfInterfacePort;
		Bool quitting;
};

#endif		/* endif __LEGACY_ADMF_INTERFACE_THREAD_H_ */
