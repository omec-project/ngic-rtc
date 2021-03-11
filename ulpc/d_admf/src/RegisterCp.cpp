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


#include "RegisterCp.h"
#include "DAdmf.h"

RegisterCpPost::RegisterCpPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost, 
			SLASH REGISTER_CP_URI, audit)
{}

Void
RegisterCpPost::process(const Pistache::Http::Request& request, 
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE::Document jsonReq;

	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::vector<std::string> vecCpConfigTmp;
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::list<ue_data_t> cpList;

	jsonReq.Parse(request.body().c_str());
	if (jsonReq.HasParseError()) {
		ELogger::log(LOG_SYSTEM).info("Register CP: Json parsing error. "
						"Invalid Json.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid JSON.");
		ptrInstance->ReleaseInstance();
		return;
	}

	if (!jsonReq.HasMember(CP_IP_ADDR_KEY) || 
			!jsonReq[CP_IP_ADDR_KEY].IsString()) {
		ELogger::log(LOG_SYSTEM).info("Register CP: Invalid post data.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Post Data.");
		ptrInstance->ReleaseInstance();
		return;
	}

	std::string strCpIpAddr = jsonReq[CP_IP_ADDR_KEY].GetString();

	vecCpConfigTmp = ptrInstance->getPtrCpConfig()->getVecCpConfig();
	mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();

	/* Check Cp ip address in vector if not found then add in vector */
	if (vecCpConfigTmp.end() ==
			std::find(vecCpConfigTmp.begin(), vecCpConfigTmp.end(), strCpIpAddr)) {

		/* Add Cp ip address in vector */
		vecCpConfigTmp.push_back(strCpIpAddr);

		/* Add Cp ip address in Cp database */
		ptrInstance->getPtrCpConfig()->UpdateCpConfig(ADD_ACTION, strCpIpAddr);

		ptrInstance->getPtrCpConfig()->setVecCpConfig(vecCpConfigTmp);

	} else {

		ELogger::log(LOG_SYSTEM).info("CP already exist");
	}

	ue_data_t ueDataTmp;

	for (std::map<uint64_t, ue_data_t>::iterator itr =
			mapUeConfigTmp.begin();
			itr != mapUeConfigTmp.end(); ++itr) {

		ueDataTmp = itr->second;

		int64_t startTimeinMilliSec = getTimeDiffInMilliSec(ueDataTmp.strStartTime);
		int64_t stopTimeInMilliSec = getTimeDiffInMilliSec(ueDataTmp.strStopTime);

		if (startTimeinMilliSec <= ZERO && stopTimeInMilliSec > ZERO) {

			cpList.push_back(ueDataTmp);

		}
	}

	std::string cpRequest = prepareJsonForCP(cpList);

	ELogger::log(LOG_SYSTEM).debug("Response to Register CP: {}", cpRequest);
	response.send(Pistache::Http::Code::Ok, cpRequest);

	ptrInstance->ReleaseInstance();
}
