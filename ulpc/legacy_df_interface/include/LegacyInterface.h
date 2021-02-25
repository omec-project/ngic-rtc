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

#ifndef _LEGACY_INTERFACE_H_
#define _LEGACY_INTERFACE_H_

#include <stdint.h>
#include <iostream>
#include "BaseLegacyInterface.h"

class LegacyClient;

class LegacyInterface : public BaseLegacyInterface
{
	public:
		/*
		 *  @brief  :   Constructor of class BaseLegacyInterface
		 */
		LegacyInterface();

		/*
		 *  @brief  :   Destructor of class BaseLegacyInterface
		 */
		~LegacyInterface();
	
		/*
		 *  @brief  :   Function to assign EGetOpt object
		 *  @param  :   opt, EGetOpt object
		 *  @return :   Returns void
		 */
		void ConfigureLogger(ELogger &log)
		{
			logger = &log;
			logger->debug("LegacyInterface ELogger has been initilized");
		}

		/*
		 *  @brief  :   Function to initialise legacy interface
		 *  @param  :   strCommMode, mode of communication
		 *  @return :   Returns int8_t
		 */
		int8_t InitializeLegacyInterface(const std::string& strCommMode);

		/*
		 *  @brief  :   Function to connect with legacy DF
		 *  @param  :   strRemoteIp, legacy DF IP
		 *  @param	:	uiRemotePort, legacy DF port
		 *  @return :   Returns int8_t
		 */
		int8_t ConnectWithLegacyInterface(const std::string& strRemoteIp,
				uint16_t uiRemotePort);

		/*
		 *  @brief  :   Function to send information/packet to legacy DF
		 *  @param  :   pkt, packet to be sent
		 *  @param	:	packetLen, size of packet
		 *  @return :   Returns int8_t
		 */
		int8_t SendMessageToLegacyInterface(uint8_t *pkt, uint32_t packetLen);

		/*
		 *  @brief  :   Function to disconnect from legacy DF
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		int8_t DisconnectWithLegacyInterface();

		/*
		 *  @brief  :   Function to de-initialise legacy DF
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		int8_t DeinitalizeLegacyInterface();

		static ELogger &log() { return *logger; }

	private:
		static ELogger *logger;
		LegacyClient *legacyClient;
};

#endif /* _LEGACY_INTERFACE_H_ */
