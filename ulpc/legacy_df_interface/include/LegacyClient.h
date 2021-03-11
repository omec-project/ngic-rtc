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

#ifndef _LEGACY_CLIENT_H_
#define _LEGACY_CLIENT_H_

#include <stdint.h>

#include <iostream>

#define TCP_COMM_MEDIUM								"TCP"

class LegacyClient
{
	public:
		/*
		 *  @brief  :   Constructor of class LegacyClient
		 */
		LegacyClient() {};

		/*
		 *  @brief  :   Destructor of class LegacyClient
		 */
		virtual ~LegacyClient() {};

		/*
		 *  @brief  :   Virtual function to initialise legacy interface
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		virtual int8_t InitializeLegacyClient() = 0;

		/*
		 *  @brief  :   Virtual function to connect with legacy DF
		 *  @param  :   strRemoteIp, legacy DF IP
		 *  @param	:	uiRemotePort, legacy DF port
		 *  @return :   Returns int8_t
		 */
		virtual int8_t ConnectToLegacy(const std::string& strRemoteIp,
				uint16_t uiRemotePort) = 0;

		/*
		 *  @brief  :   Virtual function to send information/packet to legacy DF
		 *  @param  :   pkt, packet to be sent
		 *  @param	:	packetLen, size of packet
		 *  @return :   Returns int8_t
		 */
		virtual int8_t SendMessageToLegacy(uint8_t *pkt, uint32_t packetLen) = 0;

		/*
		 *  @brief  :   Virtual function to disconnect from legacy DF
		 *  @param  :   No arguments
		 *  @return :   Returns int8_t
		 */
		virtual int8_t DisconnectToLegacy() = 0;

		/*
		 *  @brief  :   Virtual function to de-initialise legacy DF
		 *  @param  :   No arguments
		 *  @return :   Return int8_t
		 */
		virtual int8_t DeinitializeLegacyClient() = 0;

		/*
		 *  @brief  :   Function to create legacy client object
		 *  @param  :   strConfig, type of connection
		 *  @return :   Returns static LegacyClient pointer
		 */
		static LegacyClient *CreateLegacyClientObj(const std::string& strConfig);
};


#endif /* _LEGACY_CLIENT_H_ */
