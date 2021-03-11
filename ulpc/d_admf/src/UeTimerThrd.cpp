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


#include <iostream>
#include <locale>
#include <memory.h>
#include <signal.h>

#include "epc/epctools.h"
#include "epc/etevent.h"
#include "epc/esocket.h"
#include "epc/einternal.h"
#include "epc/emgmt.h"
#include "epc/etimerpool.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "UeTimer.h"
#include "DAdmf.h"
#include "Common.h"

EThreadUeTimer::EThreadUeTimer() {}

Void
EThreadUeTimer::InitTimer(EUeTimer &obj)
{
	if (START_UE == obj.getTimerAction()) {

		obj.getTimer().setInterval(obj.getUeData().iTimeToStart);
	} else if (STOP_UE == obj.getTimerAction()) {

		obj.getTimer().setInterval(obj.getUeData().iTimeToStop);
	} 
	
	obj.getTimer().setOneShot(true);

	initTimer(obj.getTimer());

	obj.getTimer().start();

	if (START_UE == obj.getTimerAction())
		ELogger::log(LOG_SYSTEM).info("StartUe Timer created for Imsi: {} "
				"with interval: {}", obj.getUeData().uiImsi, obj.getUeData().iTimeToStart);
	else if (STOP_UE == obj.getTimerAction())
		ELogger::log(LOG_SYSTEM).info("StopUe Timer created for Imsi: {} "
				"with interval: {}", obj.getUeData().uiImsi, obj.getUeData().iTimeToStop);

	mapUeTimers[obj.getTimer().getId()] = &obj;
}


Void
EThreadUeTimer::onTimer(EThreadEventTimer *pTimer)
{
	EUeTimer *ueTimerObj;
	std::map <uint32_t, EUeTimer*>::iterator itr;
	
	ELogger::log(LOG_SYSTEM).info("Hit Ontimer with timer Id is {}", pTimer->getId());

	itr = mapUeTimers.find(pTimer->getId());
	if (itr != mapUeTimers.end()) {

		ueTimerObj = itr->second;
	} else {

		return;
	}	

	ELogger::log(LOG_SYSTEM).info("Action is {}", ueTimerObj->getTimerAction());

	std::string strRequest;
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::map<uint64_t, EUeTimer*> mapStartUeTimerTmp;
	std::map<uint64_t, EUeTimer*> mapStopUeTimerTmp;
	std::list<ue_data_t> ueDataList;
	std::list<delete_event_t> deleteList;

	if (START_UE == ueTimerObj->getTimerAction()) {

		if (pTimer->getId() == ueTimerObj->getTimer().getId()) {

			ELogger::log(LOG_SYSTEM).info("StartUe Timer elapsed for seqId: {} "
					"and Imsi: {}", ueTimerObj->getUeData().uiSeqIdentifier,
					ueTimerObj->getUeData().uiImsi);

			ueTimerObj->getTimer().stop();

			/* Prepare json to send Imsi request to all registered CP's */
			ueDataList.push_back(ueTimerObj->getUeData());
			strRequest = prepareJsonForCP(ueDataList);

			if (!strRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Start Ue: sending request to all CP's");

				int8_t ret = RET_FAILURE;
				if (ueTimerObj->getUeData().ackReceived == ADD_ACTION || 
						ueTimerObj->getUeData().ackReceived == ADD_ACK) {

					ELogger::log(LOG_SYSTEM).debug("Sending request to CP using add uri");
					ret = ptrInstance->SendRequestToAllCp(ADD_UE_ENTRY_URI, strRequest);

				}

				if (ueTimerObj->getUeData().ackReceived == UPDATE_ACTION || 
						ueTimerObj->getUeData().ackReceived == UPDATE_ACK) {

					ELogger::log(LOG_SYSTEM).debug("Sending request to CP using update uri");
					ret = ptrInstance->SendRequestToAllCp(UPDATE_UE_ENTRY_URI, 
							strRequest);

				}

				if (ret == RET_SUCCESS) {

					ELogger::log(LOG_SYSTEM).info("Start Ue request sent to all "
							"registered CP's");
					ptrInstance->lock();
					mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();
					mapStartUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStartUeTimers();
					mapStopUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStopUeTimers();
					mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier].ackReceived = START_UE;
					ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);
					ptrInstance->getPtrUeConfig()->UpdateUeConfig(
							DELETE_ACTION, mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier]);
					ptrInstance->getPtrUeConfig()->UpdateUeConfig(
							ADD_ACTION, mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier]);
					ptrInstance->unlock();

				} else
					ELogger::log(LOG_SYSTEM).debug("Failure occurred while sending "
							"Start Ue request to registered CP's");


			} else
				ELogger::log(LOG_SYSTEM).debug("Request body creation for CP failed :: "
						"Empty Start Ue request body for SeqId: {} and Imsi: {}", 
						ueTimerObj->getUeData().uiSeqIdentifier, ueTimerObj->getUeData().uiImsi);

			if (ueTimerObj->getUeData().uiForward == OPERATION_LI || 
					ueTimerObj->getUeData().uiForward == OPERATION_BOTH) {

				std::string startRequest = prepareJsonForStartUe(ueDataList, START_UE);

				if (!startRequest.empty()) {

					ELogger::log(LOG_SYSTEM).info("Sending start notification to ADMF "
							" for seqId: {} and imsi: {}", ueTimerObj->getUeData().uiSeqIdentifier, 
							ueTimerObj->getUeData().uiImsi);

					int8_t ret = ptrInstance->SendNotificationToAdmf(NOTIFY_URI, startRequest);

					if (ret == RET_SUCCESS) {

						ELogger::log(LOG_SYSTEM).info("Start Notification sent to ADMF");

					} else
						ELogger::log(LOG_SYSTEM).debug("Failure occurred while sending "
								"start notification to ADMF");

				} else
					ELogger::log(LOG_SYSTEM).debug("Request body creation for ADMF failed :: "
							"Empty Start Ue request body for Imsi: {}",
							ueTimerObj->getUeData().uiImsi);
			}
			ueDataList.clear();

			mapUeTimers.erase(pTimer->getId());
		}
	} else if (STOP_UE == ueTimerObj->getTimerAction()) {

		if (pTimer->getId() == ueTimerObj->getTimer().getId()) {

			ELogger::log(LOG_SYSTEM).info("StopUe timer elapsed for Imsi: {}", 
					ueTimerObj->getUeData().uiImsi);

			ueTimerObj->getTimer().stop();

			ptrInstance->lock();
			mapStartUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStartUeTimers();
			mapStopUeTimerTmp = ptrInstance->getPtrUeConfig()->getMapStopUeTimers();
			mapStartUeTimerTmp.erase(ueTimerObj->getUeData().uiSeqIdentifier);
			mapStopUeTimerTmp.erase(ueTimerObj->getUeData().uiSeqIdentifier);

			ptrInstance->getPtrUeConfig()->setMapStartUeTimers(mapStartUeTimerTmp);
			ptrInstance->getPtrUeConfig()->setMapStopUeTimers(mapStopUeTimerTmp);
			ptrInstance->unlock();

			delete_event_t deleteUeData;
			deleteUeData.uiSeqIdentifier = ueTimerObj->getUeData().uiSeqIdentifier;
			deleteUeData.uiImsi = ueTimerObj->getUeData().uiImsi;

			deleteList.push_back(deleteUeData);
			strRequest = prepareJsonForStopUe(deleteList, STOP_UE);

			if (!strRequest.empty()) {
				/* Send curl request to all register CP */
				ELogger::log(LOG_SYSTEM).info("Stop Ue: Sending Delete Ue request "
								 "to all Cp's");

				int8_t ret = ptrInstance->SendRequestToAllCp(DELETE_UE_ENTRY_URI, 
						strRequest);

				if (ret == RET_SUCCESS) {

					ELogger::log(LOG_SYSTEM).info("Stop Ue request sent to all "
							"registered CP's");
					ptrInstance->lock();
					mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();
					mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier].ackReceived = STOP_UE;
					ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);
					ptrInstance->getPtrUeConfig()->UpdateUeConfig(
							DELETE_ACTION, mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier]);
					ptrInstance->getPtrUeConfig()->UpdateUeConfig(
							ADD_ACTION, mapUeConfigTmp[ueTimerObj->getUeData().uiSeqIdentifier]);
					ptrInstance->unlock();

				} else
					ELogger::log(LOG_SYSTEM).debug("Failure occurred while sending "
							"Stop Ue request to registered CP's");

				if (ueTimerObj->getUeData().uiForward == OPERATION_LI ||
					ueTimerObj->getUeData().uiForward == OPERATION_BOTH) {

					ELogger::log(LOG_SYSTEM).info("Sending stop notification to ADMF "
							"for seqId: {} and imsi: {}",
							ueTimerObj->getUeData().uiSeqIdentifier,
							ueTimerObj->getUeData().uiImsi);

					int8_t ret = ptrInstance->SendNotificationToAdmf(NOTIFY_URI, strRequest);

					if (ret == RET_SUCCESS) {

						ELogger::log(LOG_SYSTEM).info("Stop Notification sent to ADMF.");

					} else
						ELogger::log(LOG_SYSTEM).debug("Failure occurred while sending "
								"Stop Notification to ADMF.");

				}

			} else {

				ELogger::log(LOG_SYSTEM).debug("Request body creation for CP failed :: "
						"Empty Stop Ue request body for Imsi: {}", ueTimerObj->getUeData().uiImsi);

			}
			deleteList.clear();
			mapUeTimers.erase(pTimer->getId());
		}

	}

	ptrInstance->ReleaseInstance();
}
