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

#ifndef __BASE_LEGACY_ADMF_INTERFACE_H_
#define __BASE_LEGACY_ADMF_INTERFACE_H_

#include <iostream>
#include <cstdlib>

#include "epctools.h"
#include "etevent.h"
#include "esocket.h"
#include "elogger.h"

#include "Common.h"


class BaseLegacyAdmfInterface
{
	public:
		BaseLegacyAdmfInterface() {}
		virtual ~BaseLegacyAdmfInterface() {}
		virtual void ConfigureLogger(ELogger &log) = 0;
		virtual void startup(void *conf) = 0;
		virtual uint16_t sendMessageToLegacyAdmf(void *packet) = 0;
		virtual int8_t sendAckToAdmf(admf_intfc_packet_t *packet) = 0;
		virtual int8_t sendRequestToAdmf(uint16_t requestType, const char* requestBody) = 0;
		virtual void shutdown() = 0;

};

typedef BaseLegacyAdmfInterface* create_t();
typedef void destroy_t(BaseLegacyAdmfInterface*);


#endif /* __BASE_LEGACY_ADMF_INTERFACE_H_ */
