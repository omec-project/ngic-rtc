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


#define RAPIDJSON_NAMESPACE ulpcrapidjson
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "DeleteUeEntry.h"
#include "DAdmf.h"


DeleteUeEntryPost::DeleteUeEntryPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost, 
			SLASH DELETE_UE_ENTRY_URI, audit)
{}

Void
DeleteUeEntryPost::process(const Pistache::Http::Request& request, 
				Pistache::Http::ResponseWriter &response)
{
	bool bFlagNotFound = FALSE;
	bool bInvalidImsi = FALSE;
	bool bSeqIdNotExist = FALSE;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;

	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::map<uint64_t, EUeTimer*> mapStartUeTimerTmp;
	std::map<uint64_t, EUeTimer*> mapStopUeTimerTmp;
	std::list<delete_event_t> ueDataList;
	std::list<ue_data_t> responseUeList;

	jsonReq.Parse(request.body().c_str());

	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_SYSTEM).info("Delete Ue Request: Json parsing error. "
						"Invalid Json.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid JSON.\n");
		ptrInstance->ReleaseInstance();
		return;

	}

	itr = jsonReq.FindMember(UE_DB_KEY);

	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];

		for (RAPIDJSON_NAMESPACE::SizeType iCnt = ZERO; 
					iCnt < jsonUeArray.Size(); ++iCnt) {

			delete_event_t ueData;

			itr = jsonUeArray[iCnt].FindMember(SEQ_ID_KEY);
			if (itr == jsonUeArray[iCnt].MemberEnd()) {

				bSeqIdNotExist = TRUE;
				continue;
			}

			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				if ((itr->name == SEQ_ID_KEY)) {

					ueData.uiSeqIdentifier = itr->value.GetUint64();

				} else if ((itr->name == IMSI_KEY)) {

					ueData.uiImsi = (itr->value).GetUint64();
				
				}

			}

			ptrInstance->lock();
			mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();
			mapStartUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStartUeTimers();
			mapStopUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStopUeTimers();

			/* Check UE entry is present in db if found then remove from map */
			if (mapUeConfigTmp.end() !=
					mapUeConfigTmp.find(ueData.uiSeqIdentifier)) {

				if (mapUeConfigTmp[ueData.uiSeqIdentifier].uiImsi != ueData.uiImsi) {

					ELogger::log(LOG_SYSTEM).debug("SeqId and Imsi does not match {} -> {}",
							ueData.uiSeqIdentifier, ueData.uiImsi);
					bInvalidImsi = TRUE;
					ptrInstance->unlock();
					continue;
				}

				ELogger::log(LOG_SYSTEM).debug("Delete:: Ue entry found");
				mapUeConfigTmp[ueData.uiSeqIdentifier].ackReceived = DELETE_ACTION;

				ptrInstance->getPtrUeConfig()->UpdateUeConfig(
						DELETE_ACTION, mapUeConfigTmp[ueData.uiSeqIdentifier]);
				ptrInstance->getPtrUeConfig()->UpdateUeConfig(
						ADD_ACTION, mapUeConfigTmp[ueData.uiSeqIdentifier]);


				EUeTimer *mp_clitimer = NULL;
				if (mapStartUeTimerTmp.end() != 
						mapStartUeTimerTmp.find(ueData.uiSeqIdentifier)) {

					mp_clitimer = mapStartUeTimerTmp[ueData.uiSeqIdentifier];
					mp_clitimer->getTimer().stop();
					mapStartUeTimerTmp.erase(ueData.uiSeqIdentifier);
					ELogger::log(LOG_SYSTEM).debug("Stopping start timer for Ue entry with "
							"seqId: {}", ueData.uiSeqIdentifier);

				}

				if (mapStopUeTimerTmp.end() != 
						mapStopUeTimerTmp.find(ueData.uiSeqIdentifier)) {

					mp_clitimer = mapStopUeTimerTmp[ueData.uiSeqIdentifier];
					mp_clitimer->getTimer().stop();
					mapStopUeTimerTmp.erase(ueData.uiSeqIdentifier);
					ELogger::log(LOG_SYSTEM).debug("Stopping stop timer for Ue entry with "
							"seqId: {}", ueData.uiSeqIdentifier);

				}

				ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);
				ptrInstance->getPtrUeConfig()->setMapStartUeTimers(mapStartUeTimerTmp);
				ptrInstance->getPtrUeConfig()->setMapStopUeTimers(mapStopUeTimerTmp);

				ueDataList.push_back(ueData);

			} else {

				bFlagNotFound = TRUE;
				ptrInstance->unlock();
				continue;
			}

			ptrInstance->unlock();
		}
	}

	if (ueDataList.size() > ZERO) {

		std::string validImsiRequest = prepareJsonForStopUe(ueDataList);

		if (!validImsiRequest.empty()) {

			ELogger::log(LOG_SYSTEM).info("Delete: sending request to all CP's");
			ptrInstance->SendRequestToAllCp(DELETE_UE_ENTRY_URI, validImsiRequest);

			ELogger::log(LOG_SYSTEM).debug("Delete: Sending Delete UE request to ADMF.");
			ptrInstance->SendRequestToAdmf(DELETE_UE_ENTRY_URI, validImsiRequest);

		} else {

			ELogger::log(LOG_SYSTEM).debug("Delete: Request body creation failed");

		}

		for (delete_event_t ueData : ueDataList) {

			ue_data_t ueEntry;
			ueEntry.uiSeqIdentifier = ueData.uiSeqIdentifier;
			ueEntry.uiImsi = ueData.uiImsi;

			responseUeList.push_back(ueEntry);
		}

	}

	std::string responseMessage;
	std::string responseJson;
	if (TRUE == bFlagNotFound) {

		ELogger::log(LOG_SYSTEM).debug("Delete Ue: Some of the Ue entries "
				"not found.");
		responseMessage.assign("Some of the Ue Entries Not Found. "
				"Ue Entries in response_json deleted successfully");

	} else if (TRUE == bInvalidImsi) {

		ELogger::log(LOG_SYSTEM).debug("Delete Ue: Some Ue Enties does not match");
		responseMessage.assign("SequenceId and Imsi pair does not match. "
				"Ue Entries in response_json deleted successfully");

	} else if (TRUE == bSeqIdNotExist) {

		ELogger::log(LOG_SYSTEM).debug("Delete Ue: Some Ue entries sequenceId "
				"not found in request.");
		responseMessage.assign("SequenceId for some Ue Entries not found in request. "
				"Ue Entries in response_json deleted successfully");

	} else {

		ELogger::log(LOG_SYSTEM).debug("Ue entry deleted successfully.");
		responseMessage.assign("Ue Entries Deleted Successfully.");
	
	}

	responseJson = prepareResponseJson(responseUeList, responseMessage);
	response.send(Pistache::Http::Code::Ok, responseJson);

	ptrInstance->ReleaseInstance();

}
