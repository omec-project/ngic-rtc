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

#include "li_controller.h"
#include "li_interface.h"

struct Configurations config_li;

int32_t init_ddf(void)
{
	config_li.strDirName = "logs/store_retry_db";
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Initialising "
		"data folder to: %s",
		LOG_VALUE, (config_li.strDirName).c_str());

	return 0;
}

void *create_ddf_tunnel(char *ddf_ip, uint16_t port, char *ddf_local_ip,
		const uint8_t *mode)
{
	clLog(STANDARD_LOGID, eCLSeverityInfo, LOG_FORMAT"Connection  "
		"request received for: %s",
		LOG_VALUE, mode);

	Controller *dFController = new Controller;

	dFController->startUp((uint8_t *)ddf_ip, port, (uint8_t *)ddf_local_ip,
			(uint8_t *)mode);

	dFController->getListener()->connect();

	return dFController;
}

uint32_t send_li_data_pkt(void *obj, uint8_t *packet, uint32_t len)
{
	clLog(STANDARD_LOGID, eCLSeverityDebug, LOG_FORMAT"Packet "
		"received with length: %u",
		LOG_VALUE, len);

	Controller *dFController = reinterpret_cast<Controller *>(obj);
	dFController->getListener()->sendPacketToDdf((DdfPacket_t *)packet);

	return len;
}

void deinit_ddf(void)
{
	Controller * dFController = Controller::getInstance();

	dFController->setShutdownEvent();
}
