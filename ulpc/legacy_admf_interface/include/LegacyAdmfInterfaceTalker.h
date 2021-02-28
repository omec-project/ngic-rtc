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


#ifndef __LEGACY_ADMF_INTERFACE_TALKER_H_
#define __LEGACY_ADMF_INTERFACE_TALKER_H_

#include <iostream>
#include <cstdlib>

#include "epctools.h"
#include "etevent.h"
#include "esocket.h"

#include "LegacyAdmfInterfaceThread.h"


class LegacyAdmfInterfaceThread;

class LegacyAdmfInterfaceTalker : public ESocket::TCP::TalkerPrivate
{
	public:
		LegacyAdmfInterfaceTalker(LegacyAdmfInterfaceThread &thread);
		virtual ~LegacyAdmfInterfaceTalker();

		Void onConnect();
		Void onReceive();
		Void onClose();
		Void onError();

		Void sendAck(uint32_t seqNum);

	private:
		LegacyAdmfInterfaceTalker();

};

#endif	/* endif __LEGACY_ADMF_INTERFACE_TALKER_H_ */
