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


#include <set>

#include "UpdateUeEntry.h"
#include "DAdmf.h"

void
UpdateEntryInMap(std::map<uint16_t, uint16_t> &mapConfig, uint16_t uiKey, 
			uint16_t uiValue)
{
	std::map<uint16_t, uint16_t>::iterator itr = mapConfig.begin();

	itr = mapConfig.find(uiKey);
	if (mapConfig.end() != itr) {
		mapConfig[uiKey] = uiValue;
	}
}

UpdateUeEntryPost::UpdateUeEntryPost(ELogger &audit)
: EManagementHandler(EManagementHandler::HttpMethod::httpPost, 
			SLASH UPDATE_UE_ENTRY_URI, audit)
{}

Void
UpdateUeEntryPost::process(const Pistache::Http::Request& request, 
				Pistache::Http::ResponseWriter &response)
{
	bool iFlagEntryNotFound = FALSE;
	bool iFlagInvalidImsi = FALSE;
	bool iFlagSeqIdNotExist = FALSE;
	RAPIDJSON_NAMESPACE::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::map<uint64_t, EUeTimer*> mapStartUeTimerTmp;
	std::map<uint64_t, EUeTimer*> mapStopUeTimerTmp;
	std::list<ue_data_t> cpList;
	std::list<ue_data_t> admfList;

	jsonReq.Parse(request.body().c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_SYSTEM).info("Update UE request: Json parsing error. "
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

			itr = jsonUeArray[iCnt].FindMember(SEQ_ID_KEY);
			if (itr == jsonUeArray[iCnt].MemberEnd()) {

				ELogger::log(LOG_SYSTEM).debug("Sequence Id not found. Invalid Ue Entry");
				iFlagSeqIdNotExist = TRUE;
				continue;
			}

			ue_data_t ueDataTmp = {ZERO};
			std::set<uint8_t> attributesInReq;

			attributesInReq.clear();

			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {

				/* Need to check datatype using itr->value.GetType() */
				if (SEQ_ID_KEY == itr->name) {

					ueDataTmp.uiSeqIdentifier = itr->value.GetUint64();
					attributesInReq.insert(SEQ_ID_ATTR);

				} else if (IMSI_KEY == itr->name) {

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

							}

						} else if (SGW_S5S8_C_KEY == iterator->name) {

							uint16_t sgws5s8c = iterator->value.GetUint();
							if (sgws5s8c == OFF || sgws5s8c == ON) {

								ueDataTmp.uiSgws5s8c = sgws5s8c;
								attributesInReq.insert(SGW_S5S8_C_ATTR);

							}

						} else if (PGW_S5S8_C_KEY == iterator->name) {

							uint16_t pgws5s8c = iterator->value.GetUint();
							if (pgws5s8c == OFF || pgws5s8c == ON) {

								ueDataTmp.uiPgws5s8c = pgws5s8c;
								attributesInReq.insert(PGW_S5S8_C_ATTR);

							}

						} else if (SX_KEY == iterator->name) {

							attributesInReq.insert(SX_ATTR);
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

									ueDataTmp.mapSxConfig[uiSxIntfc] = uiCpDpType;

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

							}

						} else if (SGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t sgw_s5s8_content = iterator->value.GetUint();
							if (sgw_s5s8_content == HEADER_ONLY ||
									sgw_s5s8_content == HEADER_AND_DATA ||
									sgw_s5s8_content == DATA_ONLY) {

								ueDataTmp.sgwS5S8Content = sgw_s5s8_content;
								attributesInReq.insert(SGW_S5S8U_CONTENT_ATTR);

							}

						} else if (PGW_S5S8U_CONTENT_KEY == iterator->name) {

							uint16_t pgw_s5s8u_content = iterator->value.GetUint();
							if (pgw_s5s8u_content == HEADER_ONLY ||
									pgw_s5s8u_content == HEADER_AND_DATA ||
									pgw_s5s8u_content == DATA_ONLY) {

								ueDataTmp.pgwS5S8Content = pgw_s5s8u_content;
								attributesInReq.insert(PGW_S5S8U_CONTENT_ATTR);

							}

                   				} else if (SGI_CONTENT_KEY == iterator->name) {

							uint16_t sgiContent = iterator->value.GetUint();
							if (sgiContent == HEADER_ONLY || sgiContent == HEADER_AND_DATA ||
									sgiContent == DATA_ONLY) {

								ueDataTmp.sgiContent = sgiContent;
								attributesInReq.insert(SGI_CONTENT_ATTR);

							}

						} else if (DATA_INTFC_CONFIG_KEY == iterator->name) {

							attributesInReq.insert(INTFC_CONFIG_ATTR);
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

									ueDataTmp.mapIntfcConfig[uiIntfcName] = uiDirection;

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

					}

				} else if (TIMER_KEY == itr->name) {

					attributesInReq.insert(TIMER_ATTR);
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

			ptrInstance->lock();
			mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();
			mapStartUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStartUeTimers();
			mapStopUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStopUeTimers();

			/* Check UE entry is present in db or not if found then update it */
			if (mapUeConfigTmp.end() !=
					mapUeConfigTmp.find(ueDataTmp.uiSeqIdentifier)) {

				std::set<uint8_t>::iterator setIter;
				uint64_t imsiTmp = ZERO;
				int64_t timeToStart = getTimeDiffInMilliSec(ueDataTmp.strStartTime);
				int64_t timeToStop = getTimeDiffInMilliSec(ueDataTmp.strStopTime);

				setIter = attributesInReq.find(IMSI_ATTR);
				if (setIter != attributesInReq.end()) {

					imsiTmp = mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].uiImsi;

				}

				/* Check if pair of sequence identifier and imsi in the request 
					matches the pair in DB */
				if (imsiTmp != ueDataTmp.uiImsi) {

					iFlagInvalidImsi = True;
					ptrInstance->unlock();
					continue;

				}

				/* Check if StartTime and StopTime has valid value which is 
					greater than current Time */
				if (!(ueDataTmp.strStartTime.empty()) & 
						!(ueDataTmp.strStopTime.empty())) {

					if ((timeToStart <= ZERO) || (timeToStop <= ZERO)) {

						ELogger::log(LOG_SYSTEM).debug("Invalid timer value for Imsi: {}", 
										ueDataTmp.uiImsi);
						iFlagInvalidImsi = TRUE;
						ptrInstance->unlock();
						continue;

					}

					ueDataTmp.iTimeToStart = timeToStart;
					ueDataTmp.iTimeToStop = timeToStop;
				}

				setIter = attributesInReq.find(SIGNALLING_CONFIG_ATTR);
				if (setIter != attributesInReq.end()) {

					setIter = attributesInReq.find(S11_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].uiS11 =
							ueDataTmp.uiS11;

					}

					setIter = attributesInReq.find(SGW_S5S8_C_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].uiSgws5s8c =
							ueDataTmp.uiSgws5s8c;

					}

					setIter = attributesInReq.find(PGW_S5S8_C_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].uiPgws5s8c =
							ueDataTmp.uiPgws5s8c;

					}
	
					setIter = attributesInReq.find(SX_ATTR);
					if (setIter != attributesInReq.end()) {

						for (std::map<uint16_t, uint16_t>::iterator itr = 
								ueDataTmp.mapSxConfig.begin();
								itr != ueDataTmp.mapSxConfig.end(); itr++) {

							mapUeConfigTmp[ueDataTmp.uiSeqIdentifier]
								.mapSxConfig[itr->first] = itr->second;

						}
					}
				}
	
				setIter = attributesInReq.find(DATA_CONFIG_ATTR);
				if (setIter != attributesInReq.end()) {

					setIter = attributesInReq.find(S1U_CONTENT_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].s1uContent =
							ueDataTmp.s1uContent;

					}

					setIter = attributesInReq.find(SGW_S5S8U_CONTENT_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].sgwS5S8Content =
							ueDataTmp.sgwS5S8Content;

					}

					setIter = attributesInReq.find(PGW_S5S8U_CONTENT_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].pgwS5S8Content =
							ueDataTmp.pgwS5S8Content;

					}

					setIter = attributesInReq.find(SGI_CONTENT_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].sgiContent =
							ueDataTmp.sgiContent;

					}

					setIter = attributesInReq.find(INTFC_CONFIG_ATTR);
					if (setIter != attributesInReq.end()) {

						for (std::map<uint16_t, uint16_t>::iterator itr = 
								ueDataTmp.mapIntfcConfig.begin();
								itr != ueDataTmp.mapIntfcConfig.end(); itr++) {

							mapUeConfigTmp[ueDataTmp.uiSeqIdentifier]
								.mapIntfcConfig[itr->first] = itr->second;

						}
					}
				}

				/* Update forward / debug related configurations */
				setIter = attributesInReq.find(FORWARD_ATTR);
				if (setIter != attributesInReq.end()) {

					mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].uiForward =
						ueDataTmp.uiForward;

				}

				/* Update timer related configurations */
				setIter = attributesInReq.find(TIMER_ATTR);
				if (setIter != attributesInReq.end()) {

					setIter = attributesInReq.find(START_TIME_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].strStartTime =
							ueDataTmp.strStartTime;
						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].iTimeToStart =
							timeToStart;

					}

					setIter = attributesInReq.find(STOP_TIME_ATTR);
					if (setIter != attributesInReq.end()) {

						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].strStopTime =
							ueDataTmp.strStopTime;
						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].iTimeToStop =
							timeToStop;

					}
				}

				mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].ackReceived = UPDATE_ACTION;

				/* Update Ue entry in ue database */
				ptrInstance->getPtrUeConfig()->UpdateUeConfig(DELETE_ACTION,
						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier]);
				ptrInstance->getPtrUeConfig()->UpdateUeConfig(ADD_ACTION,
						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier]);

				ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);

				/* If start time value is going to update */
				if (!ueDataTmp.strStartTime.empty()) {

					if (mapStartUeTimerTmp.end() != 
							mapStartUeTimerTmp.find(ueDataTmp.uiSeqIdentifier)) {

						/* Delete old Ue timer object */
						EUeTimer *mp_clitimer_old = 
								mapStartUeTimerTmp[ueDataTmp.uiSeqIdentifier];
						mp_clitimer_old->getTimer().stop();

						/* Delete old Ue timer entry from map */
						mapStartUeTimerTmp.erase(ueDataTmp.uiSeqIdentifier);

						/* Register new timer object */
						EUeTimer *mp_clitimer_new = new EUeTimer(
								mapUeConfigTmp[ueDataTmp.uiSeqIdentifier], START_UE);

						mp_clitimer_new->setStrJsonRequest(request.body());

						if (timeToStart > ZERO) {
							ptrInstance->getTimerThread()->InitTimer(*mp_clitimer_new);
						}

						/* Add new start Ue timer entry in map */
						mapStartUeTimerTmp.insert({ueDataTmp.uiSeqIdentifier, mp_clitimer_new});

					}
				}

				/* If stop time value is going to update */
				if (!ueDataTmp.strStopTime.empty()) {

					if (mapStopUeTimerTmp.end() != 
							mapStopUeTimerTmp.find(ueDataTmp.uiSeqIdentifier)) {

						/* Delete old Ue timer object */
						EUeTimer *mp_clitimer_old = 
								mapStopUeTimerTmp[ueDataTmp.uiSeqIdentifier];
						mp_clitimer_old->getTimer().stop();

						/* Delete old Ue timer entry from map */
						mapStopUeTimerTmp.erase(ueDataTmp.uiSeqIdentifier);

						/* Register new timer object */
						EUeTimer *mp_clitimer_new = new EUeTimer(
								mapUeConfigTmp[ueDataTmp.uiSeqIdentifier], STOP_UE);

						ptrInstance->getTimerThread()->InitTimer(*mp_clitimer_new);

						/* Add new stop Ue timer entry in map */
						mapStopUeTimerTmp.insert({ueDataTmp.uiSeqIdentifier, mp_clitimer_new});

					}
				}

				ptrInstance->getPtrUeConfig()->setMapStartUeTimers(mapStartUeTimerTmp);
				ptrInstance->getPtrUeConfig()->setMapStopUeTimers(mapStopUeTimerTmp);

				int64_t newTimeToStart = getTimeDiffInMilliSec(
						mapUeConfigTmp[ueDataTmp.uiSeqIdentifier].strStartTime);
				/* Check if Imsi request has already been sent to registered CP's */
				if (newTimeToStart < ZERO) {

					cpList.push_back(mapUeConfigTmp[ueDataTmp.uiSeqIdentifier]);

				}

			} else {

				iFlagEntryNotFound = TRUE;
				ptrInstance->unlock();
				continue;

			}

			ptrInstance->unlock();
			admfList.push_back(ueDataTmp);
		}
	}

	if (cpList.size() > ZERO ) {

		std::string cpRequest = prepareJsonForCP(cpList);

		if(!cpRequest.empty()) {

			ELogger::log(LOG_SYSTEM).info("Update: Sending Update UE request to CP for "
					"all Imsi whose startTime has already elapsed.");
			ptrInstance->SendRequestToAllCp(UPDATE_UE_ENTRY_URI, cpRequest);
			
		} else {

			ELogger::log(LOG_SYSTEM).debug("Update: Request body creation for CP");

		}
	}

	if (admfList.size() > ZERO) {

		std::string admfRequest = prepareJsonFromUeData(admfList);

		if (!admfRequest.empty()) {

			ELogger::log(LOG_SYSTEM).info("Update: Sending Add UE request to ADMF.");
			ptrInstance->SendRequestToAdmf(UPDATE_UE_ENTRY_URI, admfRequest);

		} else {

			ELogger::log(LOG_SYSTEM).debug("Update: Request body creation for ADMF");

		}
	}

	std::string responseMessage;
	std::string responseJson;
	if (TRUE == iFlagEntryNotFound) {

		ELogger::log(LOG_SYSTEM).debug("Response: Some Ue Entries not found.");
		responseMessage.assign("Some Ue Entries Not Found. "
				"Ue Entries in response_json updated successfully");

	} else if (TRUE == iFlagSeqIdNotExist) {

		ELogger::log(LOG_SYSTEM).debug("SeqId not found in some Ue Entries");
		responseMessage.assign("SequenceId not found in some Ue Entries. "
				"Ue Entries in response_json updated successfully");

	} else if (TRUE == iFlagInvalidImsi) {

		ELogger::log(LOG_SYSTEM).debug("Some Ue's contains invalid Imsi or "
				"timer values.");
		responseMessage.assign("Some Ue's contains invalid Imsi or timer values. "
				"Ue Entries in response_json updated successfully");

	} else {

		ELogger::log(LOG_SYSTEM).debug("Ue entry updated successfully.");
		responseMessage.assign("Ue Entries Updated Successfully.");

	}

	responseJson = prepareResponseJson(admfList, responseMessage);
	response.send(Pistache::Http::Code::Ok, responseJson);
	ptrInstance->ReleaseInstance();

}
