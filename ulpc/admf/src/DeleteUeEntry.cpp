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


#include <list>

#include "estats.h"
#include "etime.h"
#include "elogger.h"

#include "AdmfApp.h"
#include "DeleteUeEntry.h"
#include "DAdmfInterface.h"
#include "AdmfController.h"
#include "AdmfInterface.h"
#include "UeEntry.h"


DeleteUeEntryPost :: DeleteUeEntryPost(ELogger &audit, AdmfApplication &app)  
: EManagementHandler( EManagementHandler::HttpMethod::httpPost,
			DELETE_UE_ENTRY, audit ), mApp(app)
{
}

void
DeleteUeEntryPost :: process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE :: Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	std::list<delete_event_t *> ueEntries;
	std::string requestBody;
	uint16_t requestSource = ADMF_REQUEST;

	requestBody.assign(request.body());
	jsonReq.Parse(requestBody.c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_ADMF).info("Delete Ue Request: Json parsing error. "
						"Invalid Json.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Json.\n");
		return;

	}

	itr = jsonReq.FindMember(REQUEST_SOURCE_KEY);
        if (itr != jsonReq.MemberEnd()) {

                ELogger::log(LOG_ADMF).debug("Delete Ue request came from D_ADMF");
		requestSource = itr->value.GetUint();

        }

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];
		for (RAPIDJSON_NAMESPACE::SizeType iCnt = ZERO; 
			iCnt < jsonUeArray.Size(); ++iCnt) {

			delete_event_t *lpDeleteEvent = new delete_event_t();

			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				if (SEQ_ID_KEY == itr->name) {

					lpDeleteEvent->uiSeqIdentifier = itr->value.GetUint64();

				} else if (IMSI_KEY == itr->name) {

					lpDeleteEvent->uiImsi = itr->value.GetUint64();

				}
			}

			ueEntries.push_back(lpDeleteEvent);
		}
	}

	mApp.getAdmfController().deleteUeController(ueEntries,
			requestBody, requestSource);

	ELogger::log(LOG_ADMF).debug("Response: Delete Ue Entry processed successfully.");
	response.send(Pistache::Http::Code::Ok, "Delete Ue Entry processed sucessfully\n");

}
