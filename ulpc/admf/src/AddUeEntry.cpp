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

#include "emgmt.h"
#include "estats.h"
#include "etime.h"
#include "elogger.h"

#include "AdmfApp.h"
#include "AddUeEntry.h"
#include "UeEntry.h"
#include "AdmfInterface.h"
#include "DAdmfInterface.h"
#include "AdmfController.h"


AddUeEntryPost :: AddUeEntryPost(ELogger &audit, AdmfApplication &app)  
: EManagementHandler( EManagementHandler::HttpMethod::httpPost,
			ADD_UE_ENTRY, audit ), mApp(app)
{
}

void
AddUeEntryPost :: process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE :: Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	std::list<ue_data_t *> ueEntries;
	std::string requestBody;
	uint16_t requestSource = ADMF_REQUEST;

	requestBody.assign(request.body());
	jsonReq.Parse(requestBody.c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_ADMF).info("Add Ue Entry::Json Parsing Error. "
						"Invalid Json");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Json.\n");
		return;

	}

	itr = jsonReq.FindMember(REQUEST_SOURCE_KEY);
	if (itr != jsonReq.MemberEnd()) {

		ELogger::log(LOG_ADMF).debug("Add::Request source key found");
		requestSource = itr->value.GetUint();

        }

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];

		for (RAPIDJSON_NAMESPACE::SizeType iCnt = ZERO; 
				iCnt < jsonUeArray.Size(); ++iCnt) {

			ue_data_t *lpUeEntryEvent = new ue_data_t();
			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				if (SEQ_ID_KEY == itr->name) {

					if (requestSource == D_ADMF_REQUEST) {
						uint64_t seqId = itr->value.GetUint64();
						lpUeEntryEvent->uiSeqIdentifier = seqId;
					}

				} else if (IMSI_KEY == itr->name) {

					uint64_t imsi = itr->value.GetUint64();
					lpUeEntryEvent->uiImsi = imsi;

				} else if (SIGNALLING_CONFIG_KEY == itr->name) {

					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
							itr->value.MemberBegin();
							iterator != itr->value.MemberEnd(); ++iterator) {

						if (S11_KEY == iterator->name) {

							uint16_t s11 = iterator->value.GetUint();
							lpUeEntryEvent->uiS11 = s11;

						} else if (SGW_S5S8_C_KEY == iterator->name) {

							uint16_t sgws5s8 = iterator->value.GetUint();
							lpUeEntryEvent-> uiSgws5s8c = sgws5s8;

						} else if (PGW_S5S8_C_KEY == iterator->name) {

							uint16_t pgws5s8 = iterator->value.GetUint();
							lpUeEntryEvent->uiPgws5s8c = pgws5s8;

						} else if (SX_KEY == iterator->name) {

							std::map<uint16_t, uint16_t> sxMap;
							for (RAPIDJSON_NAMESPACE::SizeType iCount = ZERO;
								iCount < iterator->value.Size(); ++iCount) {

								uint16_t sxIntfc, cpDpType;
								for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iter =
									iterator->value[iCount].MemberBegin();
									iter != iterator->value[iCount].MemberEnd();
									++iter) {

									if (SX_INTFC_KEY == iter->name) {

										sxIntfc = iter->value.GetUint();

									} else if (CP_DP_TYPE_KEY == iter->name) {

										cpDpType = iter->value.GetUint();

									}
								}

								sxMap.insert({sxIntfc, cpDpType});
							}

							lpUeEntryEvent->mapSxConfig = sxMap;
						}
					}

				} else if (DATA_CONFIG_KEY == itr->name) {

					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
						itr->value.MemberBegin();
						iterator != itr->value.MemberEnd(); ++iterator) {

						if (S1U_CONTENT_KEY == iterator->name) {

							uint16_t s1uContent = iterator->value.GetUint();
							lpUeEntryEvent->s1uContent = s1uContent;

						} else if (SGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t sgwContent = iterator->value.GetUint();
							lpUeEntryEvent->sgwS5S8Content = sgwContent;

						} else if (PGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t pgwContent = iterator->value.GetUint();
							lpUeEntryEvent->pgwS5S8Content = pgwContent;

						} else if (SGI_CONTENT_KEY == iterator->name) {

							uint16_t sgiContent = iterator->value.GetUint();
							lpUeEntryEvent->sgiContent = sgiContent;

						} else if (DATA_INTFC_CONFIG_KEY == iterator->name) {

							std::map<uint16_t, uint16_t> intfcMap;
							for (RAPIDJSON_NAMESPACE::SizeType iCount = ZERO;
								iCount < iterator->value.Size(); ++iCount) {

								uint16_t intfcName, direction;
								for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iter =
									iterator->value[iCount].MemberBegin();
									iter != iterator->value[iCount].MemberEnd();
									++iter) {

									if (DATA_INTFC_NAME_KEY == iter->name) {

										intfcName = iter->value.GetUint();

									} else if (DATA_DIRECTION_KEY == iter->name) {

										direction = iter->value.GetUint();

									}
								}

								intfcMap.insert({intfcName, direction});
							}

							lpUeEntryEvent->mapIntfcConfig = intfcMap;
						}
					}

				} else if (FORWARD_KEY == itr->name) {

					uint16_t forward = itr->value.GetUint();
					lpUeEntryEvent->uiForward = forward;

				} else if (TIMER_KEY == itr->name) {

					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
						itr->value.MemberBegin();
						iterator != itr->value.MemberEnd(); ++iterator) {

						if (START_TIME_KEY == iterator->name) {

							std::string startTime = iterator->value.GetString();
							lpUeEntryEvent->strStartTime = startTime;

						} else if (STOP_TIME_KEY == iterator->name) {

							std::string stopTime = iterator->value.GetString();
							lpUeEntryEvent->strStopTime = stopTime;

						}
					}
				}
			}

			ueEntries.push_back(lpUeEntryEvent);
		}
	}

	mApp.getAdmfController().addUeController(ueEntries,
		requestBody, requestSource);

	ELogger::log(LOG_ADMF).debug("Response: Add Ue Entry processed successfully");
	response.send(Pistache::Http::Code::Ok, "Add Ue Entry processed "
			"successfully\n");

}
