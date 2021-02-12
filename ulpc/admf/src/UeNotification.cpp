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
#include "UeNotification.h"
#include "DAdmfInterface.h"
#include "AdmfController.h"
#include "AdmfInterface.h"
#include "UeEntry.h"


UeNotificationPost :: UeNotificationPost(ELogger &audit, AdmfApplication &app) 
: EManagementHandler( EManagementHandler::HttpMethod::httpPost,
			NOTIFY_URI, audit ), mApp(app)
{
}

void
UeNotificationPost :: process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE :: Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	std::list<ue_notify_t *> ueEntries;
	std::string requestBody;
	uint16_t requestSource = ADMF_REQUEST;

	requestBody.assign(request.body());
	jsonReq.Parse(requestBody.c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_ADMF).info("Notication: Json parsing error. "
						"Invalid Json.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Json.\n");
		return;

	}

	itr = jsonReq.FindMember(REQUEST_SOURCE_KEY);
        if (itr != jsonReq.MemberEnd()) {

                ELogger::log(LOG_ADMF).debug("Request source key found");
		requestSource = itr->value.GetUint();

        }

	if (requestSource != D_ADMF_REQUEST) {

		ELogger::log(LOG_ADMF).debug("Notification did not came from DADMF");
		response.send(Pistache::Http::Code::Unauthorized, "Request source not verified\n");
		return;
	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];

		for (RAPIDJSON_NAMESPACE::SizeType iCnt = ZERO; 
			iCnt < jsonUeArray.Size(); ++iCnt) {

			ue_notify_t *notifyEvent = new ue_notify_t();

			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				if (SEQ_ID_KEY == itr->name) {

					notifyEvent->uiSeqIdentifier = itr->value.GetUint64();

				} else if (IMSI_KEY == itr->name) {

					notifyEvent->uiImsi = itr->value.GetUint64();

				} else if (TIMER_KEY == itr->name) {

					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
							itr->value.MemberBegin();
							iterator != itr->value.MemberEnd(); ++iterator) {

						if (START_TIME_KEY == iterator->name) {

							std::string startTime = iterator->value.GetString();
							notifyEvent->strStartTime = startTime;

						} else if (STOP_TIME_KEY == iterator->name) {

							std::string stopTime = iterator->value.GetString();
							notifyEvent->strStopTime = stopTime;

						}

					}

				} 

			}

			itr = jsonReq.FindMember(NOTIFY_TYPE_KEY);
			if (itr != jsonReq.MemberEnd()) {

				notifyEvent->notifyType = itr->value.GetUint();

			}

			ueEntries.push_back(notifyEvent);
		}
	}

	mApp.getAdmfController().notifyUeController(ueEntries, requestBody);

	ELogger::log(LOG_ADMF).debug("Response: Notification processed successfully.");
	response.send(Pistache::Http::Code::Ok, "Notification processed sucessfully\n");

}
