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

#include "LegacyInterface.h"
#include "LegacyClient.h"
#include "LegacyTCPClient.h"

ELogger *LegacyInterface::logger = NULL;

LegacyInterface::LegacyInterface() {
}

LegacyInterface::~LegacyInterface() {
}

int8_t
LegacyInterface::InitializeLegacyInterface(const std::string& strCommMode) {

	/* object created using factory pattern as per communication medium */
	legacyClient = LegacyClient::CreateLegacyClientObj(strCommMode);

	legacyClient->InitializeLegacyClient();

	return 0;
}

int8_t
LegacyInterface::ConnectWithLegacyInterface(const std::string& strRemoteIp,
		uint16_t uiRemotePort) {

	legacyClient->ConnectToLegacy(strRemoteIp, uiRemotePort);

	return 0;
}

int8_t
LegacyInterface::SendMessageToLegacyInterface(uint8_t *pkt,
		uint32_t packetLen) {

	legacyClient->SendMessageToLegacy(pkt, packetLen);

	return 0;
}

int8_t
LegacyInterface::DisconnectWithLegacyInterface() {
	return 0;
}

int8_t
LegacyInterface::DeinitalizeLegacyInterface() {
	legacyClient->DeinitializeLegacyClient();
	return 0;
}

void (*dfCall)(uint32_t ) = NULL;		/* Call back function to send ACK */
void (*sockCall)() = NULL;		/* Call back function to notify Legacy DF Socket close */
void (*connCall)() = NULL;		/* Call back function to notify Legacy DF Socket close */

void to_df_callback(uint32_t ackNumb)
{
	dfCall(ackNumb);
}

void to_socket_callback()
{
	sockCall();
}

void to_conn_callback()
{
	connCall();
}

// Class factories

extern "C" BaseLegacyInterface* GetInstance(void)
{
	return new LegacyInterface();
}

extern "C" void ReleaseInstance(BaseLegacyInterface *ptr)
{
	delete ptr;
}

extern "C" void register_function( void (*ackFromLegacy)(uint32_t ))
{
	dfCall = ackFromLegacy;
}

extern "C" void register_Closefunction( void (*sockColseLegacy)())
{
	sockCall = sockColseLegacy;
}

extern "C" void register_Connfunction( void (*sockConnLegacy)())
{
	connCall = sockConnLegacy;
}
