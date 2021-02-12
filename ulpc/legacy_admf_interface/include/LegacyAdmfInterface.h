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


#ifndef __LEGACY_ADMF_INTERFACE_H_
#define __LEGACY_ADMF_INTERFACE_H_


#include "BaseLegacyAdmfInterface.h"
#include "LegacyAdmfInterfaceThread.h"


class LegacyAdmfInterface : public BaseLegacyAdmfInterface
{
	private:
		static LegacyAdmfInterface *ladmfInstance;
		static int refCnt;
		LegacyAdmfInterfaceThread *legacyAdmfIntfcThread;
		static ELogger *logger;

	public:
		LegacyAdmfInterface();
		~LegacyAdmfInterface();

		void ConfigureLogger(ELogger &log)
		{
			logger = &log;
			logger->debug("LegacyAdmfInterface ELogger has been initilized");
		}

		void startup(void *conf);
		uint16_t sendMessageToLegacyAdmf(void *packet);
		int8_t sendAckToAdmf(admf_intfc_packet_t *packet);
		int8_t sendRequestToAdmf(uint16_t requestType, const char *requestBody);
		void shutdown();

		static ELogger &log() { return *logger; }

};

#endif /* __LEGACY_ADMF_INTERFACE_H_ */
