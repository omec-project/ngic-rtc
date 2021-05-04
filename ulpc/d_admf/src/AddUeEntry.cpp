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


#include "AddUeEntry.h"
#include "DAdmf.h"
#include "UeTimer.h"

extern ue_defaults_t ue_default;

void
AddEntryInSxMap(std::map<uint16_t, uint16_t> &mapSxConfig, 
			uint16_t uiSxIntfc, uint16_t uiCpDpType)
{
	if (mapSxConfig.end() == mapSxConfig.find(uiSxIntfc)) {

		mapSxConfig.insert({uiSxIntfc, uiCpDpType});

	} else {

		if (CP_DP_TYPE == uiCpDpType) {

			mapSxConfig[uiSxIntfc] = uiCpDpType;

		} else {

			uint16_t uiOldType = mapSxConfig.find(uiSxIntfc)->second;
			if (((CP_TYPE == uiOldType) && (DP_TYPE == uiCpDpType)) ||
					((DP_TYPE == uiOldType) && (CP_TYPE == uiCpDpType))) {

				mapSxConfig[uiSxIntfc] = CP_DP_TYPE;

			}
		}
	}
}

void
AddEntryInIntfcMap(std::map<uint16_t, uint16_t> &mapIntfcConfig, 
				uint16_t uiIntfc, uint16_t uiDir)
{
	if (mapIntfcConfig.end() == mapIntfcConfig.find(uiIntfc)) {

		mapIntfcConfig.insert({uiIntfc, uiDir});

	} else {

		if (UPLINK_DOWNLINK == uiDir) {

			mapIntfcConfig[uiIntfc] = uiDir;

		} else {

			uint16_t uiOldDir = mapIntfcConfig.find(uiIntfc)->second;
			if (((UPLINK == uiOldDir) && (DOWNLINK == uiDir)) ||
					((DOWNLINK == uiOldDir) && (UPLINK == uiDir))) {

				mapIntfcConfig[uiIntfc] = UPLINK_DOWNLINK;

			}
		}
	}
}

AddUeEntryPost::AddUeEntryPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost, 
			SLASH ADD_UE_ENTRY_URI, audit)
{}

Void
AddUeEntryPost::process(const Pistache::Http::Request& request, 
				Pistache::Http::ResponseWriter &response)
{
	bool iFlagInvalidImsi = FALSE;
	bool iFlagInvalidCmd = FALSE;
	bool iFlagNoImsi = FALSE;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::map<uint64_t, EUeTimer*> mapStartUeTimerTmp;
	std::map<uint64_t, EUeTimer*> mapStopUeTimerTmp;
	std::list<ue_data_t> validUeList;
	std::list<ue_data_t> responseUeList;

	jsonReq.Parse(request.body().c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_SYSTEM).info("Add Ue Request: Json parsing error. "
						"Invalid Json");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Json.\n");
		ptrInstance->ReleaseInstance();
		return;

	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];

		for (RAPIDJSON_NAMESPACE::SizeType iCnt = ZERO; 
				iCnt < jsonUeArray.Size(); ++iCnt) {

			ue_data_t ueDataTmp = {ZERO};
			std::set<uint8_t> attributesInReq;

			attributesInReq.clear();

			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				/* Need to check datatype using itr->value.GetType() */
				if (IMSI_KEY == itr->name) {

					ueDataTmp.uiImsi = itr->value.GetUint64();
					attributesInReq.insert(IMSI_ATTR);

				} else if (SIGNALLING_CONFIG_KEY == itr->name) {

					attributesInReq.insert(SIGNALLING_CONFIG_ATTR);
					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
							itr->value.MemberBegin(); 
							iterator != itr->value.MemberEnd(); ++iterator) {

						if (S11_KEY == iterator->name) {

							uint16_t s11 = iterator->value.GetUint();
							if (s11 == OFF || s11 == ON) {

								ueDataTmp.uiS11 = s11;
								attributesInReq.insert(S11_ATTR);

							} else {

								ueDataTmp.uiS11 = ue_default.s11;

							}

						} else if (SGW_S5S8_C_KEY == iterator->name) {

							uint16_t sgws5s8c = iterator->value.GetUint();
							if (sgws5s8c == OFF || sgws5s8c == ON) {

								ueDataTmp.uiSgws5s8c = sgws5s8c;
								attributesInReq.insert(SGW_S5S8_C_ATTR);

							} else {

								ueDataTmp.uiSgws5s8c = ue_default.sgw_s5s8c;

							}

						} else if (PGW_S5S8_C_KEY == iterator->name) {

							uint16_t pgws5s8c = iterator->value.GetUint();
							if (pgws5s8c == OFF || pgws5s8c == ON) {

								ueDataTmp.uiPgws5s8c = pgws5s8c;
								attributesInReq.insert(PGW_S5S8_C_ATTR);

							} else {

								ueDataTmp.uiPgws5s8c = ue_default.pgw_s5s8c;

							}

						} else if (SX_KEY == iterator->name) {

							for (RAPIDJSON_NAMESPACE::SizeType iCount = ZERO;
									iCount < iterator->value.Size(); ++iCount) {

								uint16_t uiSxIntfc = ZERO;
								uint16_t uiCpDpType = ZERO;
								for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iter =
										iterator->value[iCount].MemberBegin();
										iter != iterator->value[iCount].MemberEnd(); 
										++iter) {

									if (SX_INTFC_KEY == iter->name) {

										uint16_t sxIntfc = iter->value.GetUint();
										if (sxIntfc == SXA || sxIntfc == SXB ||
												sxIntfc == SXA_SXB) {

											uiSxIntfc = sxIntfc;

										} else {

											continue;

										}

									} else if (CP_DP_TYPE_KEY == iter->name) {

										uint16_t cpDpType = iter->value.GetUint();
										if (cpDpType == CP_TYPE || cpDpType == DP_TYPE ||
												cpDpType == CP_DP_TYPE || cpDpType == DISABLE) {

											uiCpDpType = cpDpType;

										} else {

											continue;

										}

									}
								}

								if (uiSxIntfc != ZERO) {

									AddEntryInSxMap(ueDataTmp.mapSxConfig, uiSxIntfc, uiCpDpType);

								}
							}
						}
					}

				} else if (DATA_CONFIG_KEY == itr->name) {

					attributesInReq.insert(DATA_CONFIG_ATTR);
					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
							itr->value.MemberBegin();
							iterator != itr->value.MemberEnd(); ++iterator) {

						if (S1U_CONTENT_KEY == iterator->name) {

							uint16_t s1u_content = iterator->value.GetUint();
							if (s1u_content == HEADER_ONLY || s1u_content == HEADER_AND_DATA ||
									s1u_content == DATA_ONLY) {

								ueDataTmp.s1uContent = s1u_content;
								attributesInReq.insert(S1U_CONTENT_ATTR);

							} else {

								ueDataTmp.s1uContent = ue_default.s1u_content;

							}

						} else if (SGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t sgw_s5s8_content = iterator->value.GetUint();
							if (sgw_s5s8_content == HEADER_ONLY ||
									sgw_s5s8_content == HEADER_AND_DATA ||
									sgw_s5s8_content == DATA_ONLY) {

								ueDataTmp.sgwS5S8Content = sgw_s5s8_content;
								attributesInReq.insert(SGW_S5S8U_CONTENT_ATTR);

							} else {

								ueDataTmp.sgwS5S8Content = ue_default.sgw_s5s8u_content;

							}

						} else if (PGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t pgw_s5s8u_content = iterator->value.GetUint();
							if (pgw_s5s8u_content == HEADER_ONLY ||
									pgw_s5s8u_content == HEADER_AND_DATA ||
									pgw_s5s8u_content == DATA_ONLY) {

								ueDataTmp.pgwS5S8Content = pgw_s5s8u_content;
								attributesInReq.insert(PGW_S5S8U_CONTENT_ATTR);

							} else {

								ueDataTmp.pgwS5S8Content = ue_default.pgw_s5s8u_content;

							}

						} else if (SGI_CONTENT_KEY == iterator->name) {

							uint16_t sgiContent = iterator->value.GetUint();
							if (sgiContent == HEADER_ONLY || sgiContent == HEADER_AND_DATA ||
									sgiContent == DATA_ONLY) {

								ueDataTmp.sgiContent = sgiContent;
								attributesInReq.insert(SGI_CONTENT_ATTR);

							} else {

								ueDataTmp.sgiContent = ue_default.sgi_content;

							}

						} else if (DATA_INTFC_CONFIG_KEY == iterator->name) {

							for (RAPIDJSON_NAMESPACE::SizeType iCount = ZERO;
									iCount < iterator->value.Size(); ++iCount) {

								uint16_t uiIntfcName = ZERO;
								uint16_t uiDirection = ZERO;

								for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iter =
										iterator->value[iCount].MemberBegin();
										iter != iterator->value[iCount].MemberEnd(); 
										++iter) {

									if (DATA_INTFC_NAME_KEY == iter->name) {

										uint16_t intfcName = iter->value.GetUint();
										if (intfcName == S1U || intfcName == SGW_S5S8_U ||
												intfcName == PGW_S5S8_U || intfcName == SGI) {

											uiIntfcName = intfcName;

										} else {

											continue;

										}

									} else if (DATA_DIRECTION_KEY == iter->name) {

										uint16_t direction = iter->value.GetUint();
										if (direction == UPLINK || direction == DOWNLINK ||
												direction == UPLINK_DOWNLINK || direction == DISABLE) {

											uiDirection = direction;

										} else {

											continue;

										}

									}	
								}

								if (uiIntfcName != ZERO) {

									AddEntryInIntfcMap(ueDataTmp.mapIntfcConfig, uiIntfcName,
											uiDirection);

								}
							}
						}
					}

				} else if (FORWARD_KEY == itr->name) {

					uint16_t forward = itr->value.GetUint();
					if (forward == OPERATION_DEBUG || forward == OPERATION_LI ||
							forward == OPERATION_BOTH) {

						ueDataTmp.uiForward = forward;
						attributesInReq.insert(FORWARD_ATTR);

					} else {

						ueDataTmp.uiForward = ue_default.forward;

					}

				} else if (TIMER_KEY == itr->name) {

					for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator iterator =
							itr->value.MemberBegin(); 
							iterator != itr->value.MemberEnd(); ++iterator) {

						if (START_TIME_KEY == iterator->name) {

							ueDataTmp.strStartTime = iterator->value.GetString();
							attributesInReq.insert(START_TIME_ATTR);

						} else if (STOP_TIME_KEY == iterator->name) {

							ueDataTmp.strStopTime = iterator->value.GetString();
							attributesInReq.insert(STOP_TIME_ATTR);

						}
					}
				}
			}

			std::set<uint8_t>::iterator setIter;
			setIter = attributesInReq.find(IMSI_ATTR);
			if (setIter == attributesInReq.end()) {
				ELogger::log(LOG_SYSTEM).debug("IMSI not found in request");
				iFlagNoImsi = TRUE;
				continue;
			}

			setIter = attributesInReq.find(START_TIME_ATTR);
			if (setIter == attributesInReq.end()) {
				ELogger::log(LOG_SYSTEM).debug("StartTime not found in request");
				iFlagInvalidImsi = TRUE;
				continue;
			}

			setIter = attributesInReq.find(STOP_TIME_ATTR);
			if (setIter == attributesInReq.end()) {
				ELogger::log(LOG_SYSTEM).debug("StopTime not found in request");
				iFlagInvalidImsi = TRUE;
				continue;
			}

			setIter = attributesInReq.find(S11_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.uiS11 = ue_default.s11;
			}

			setIter = attributesInReq.find(SGW_S5S8_C_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.uiSgws5s8c = ue_default.sgw_s5s8c;

			}

			setIter = attributesInReq.find(PGW_S5S8_C_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.uiPgws5s8c = ue_default.pgw_s5s8c;

			}

			setIter = attributesInReq.find(S1U_CONTENT_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.s1uContent = ue_default.s1u_content;

			}

			setIter = attributesInReq.find(SGW_S5S8U_CONTENT_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.sgwS5S8Content = ue_default.sgw_s5s8u_content;

			}

			setIter = attributesInReq.find(PGW_S5S8U_CONTENT_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.pgwS5S8Content = ue_default.pgw_s5s8u_content;

			}

			setIter = attributesInReq.find(SGI_CONTENT_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.sgiContent = ue_default.sgi_content;

			}

			setIter = attributesInReq.find(FORWARD_ATTR);
			if (setIter == attributesInReq.end()) {

				ueDataTmp.uiForward = ue_default.forward;

			}

			ueDataTmp.uiSeqIdentifier = generateSequenceIdentifier(ueDataTmp);
			ueDataTmp.ackReceived = ADD_ACTION;

			mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();
			mapStartUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStartUeTimers();
			mapStopUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStopUeTimers();


			int64_t timeToStart = getTimeDiffInMilliSec(ueDataTmp.strStartTime);
			int64_t timeToStop = getTimeDiffInMilliSec(ueDataTmp.strStopTime);

			if ((timeToStart <= ZERO) || (timeToStop <= ZERO) ||
					(timeToStop <= timeToStart)) {

				ELogger::log(LOG_SYSTEM).debug("Invalid timer value for IMSI: {}", 
								ueDataTmp.uiImsi);
				iFlagInvalidImsi = TRUE;
				continue;

			}

			ueDataTmp.iTimeToStart = timeToStart;
			ueDataTmp.iTimeToStop = timeToStop;

			ELogger::log(LOG_SYSTEM).debug("Adding UE entry in DB for IMSI: {}",
							ueDataTmp.uiImsi);
			/* Add Ue entry in map */
			mapUeConfigTmp.insert({ueDataTmp.uiSeqIdentifier, ueDataTmp});

			/* Add Ue entry in ue database */
			ptrInstance->getPtrUeConfig()->UpdateUeConfig(ADD_ACTION, ueDataTmp);

			/* Create timer to send add request to CP when startTime is reached */
			EUeTimer *startUeTimer = new EUeTimer(ueDataTmp, START_UE);
			ptrInstance->getTimerThread()->InitTimer(*startUeTimer);
			startUeTimer->setStrJsonRequest(request.body());

			/* Create timer to send delete request to CP when stopTime is reached */
			EUeTimer *stopUeTimer = new EUeTimer(ueDataTmp, STOP_UE);
			ptrInstance->getTimerThread()->InitTimer(*stopUeTimer);
		
			/* Add StartUe timer entry in map */
			mapStartUeTimerTmp.insert({ueDataTmp.uiSeqIdentifier, startUeTimer});
			mapStopUeTimerTmp.insert({ueDataTmp.uiSeqIdentifier, stopUeTimer});

			ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);
			ptrInstance->getPtrUeConfig()->setMapStartUeTimers(mapStartUeTimerTmp);
			ptrInstance->getPtrUeConfig()->setMapStopUeTimers(mapStopUeTimerTmp);

			if (ueDataTmp.uiForward	== OPERATION_LI ||
					ueDataTmp.uiForward == OPERATION_BOTH) {

				validUeList.push_back(ueDataTmp);

			}
				
			responseUeList.push_back(ueDataTmp);

		}
	} else {
		iFlagInvalidCmd = TRUE;
	}

	if (validUeList.size() > ZERO) {
		std::string admfRequest = prepareJsonFromUeData(validUeList);

		if (!admfRequest.empty()) {

			ELogger::log(LOG_SYSTEM).info("Sending Add UE request to ADMF.");
			ptrInstance->SendRequestToAdmf(ADD_UE_ENTRY_URI, admfRequest);

		} else {

			ELogger::log(LOG_SYSTEM).debug("Request body creation for ADMF failed");

		}
	}

	std::string responseMessage;
	std::string responseJson;

	if (TRUE == iFlagNoImsi) {

		ELogger::log(LOG_SYSTEM).debug("Response: Some Ue's does not contain IMSI "
				"value.");
		responseMessage.assign("Some Ue's does not contain IMSI value in request. "
				"Ue entries in response_json added successfully");

	} else if (TRUE == iFlagInvalidImsi) {

		ELogger::log(LOG_SYSTEM).debug("Response: Some Ue's contains invalid "
				"timer value.");
		responseMessage.assign("Some Ue's contains invalid timer value. "
				"Ue entries in response_json added successfully");

	} else if (TRUE == iFlagInvalidCmd) {
	
		ELogger::log(LOG_SYSTEM).debug("Invalid curl command parameters.");
		responseMessage.assign("Invalid curl command parameters.");

	} else {

		ELogger::log(LOG_SYSTEM).debug("Ue Entries added successfully.");
		responseMessage.assign("Ue Entries Added Successfully.");

	}

	responseJson = prepareResponseJson(responseUeList, responseMessage);
	response.send(Pistache::Http::Code::Ok, responseJson);
	ptrInstance->ReleaseInstance();

}
