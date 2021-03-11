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

EThreadAckTimer::EThreadAckTimer() {
}

Void
EThreadAckTimer::onInit(void)
{
	timer.setInterval(timeToElapse);
	timer.setOneShot(false);
	initTimer(timer);
	timer.start();

	ELogger::log(LOG_SYSTEM).info("Ack checker timer created with interval: "
			"{}", timeToElapse);
}


Void
EThreadAckTimer::onTimer(EThreadEventTimer *pTimer)
{	
	std::string strRequest;
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::map<uint64_t, EUeTimer*> mapStartUeTimerTmp;
	std::map<uint64_t, EUeTimer*> mapStopUeTimerTmp;
	std::list<ue_data_t> ueDataList;
	std::list<delete_event_t> deleteList;

	if (pTimer->getId() == timer.getId()) {

		std::list<ue_data_t> addList;
		std::list<ue_data_t> updateList;
		std::list<delete_event_t> deleteList;
		std::list<ue_data_t> startNotifyList;
		std::list<delete_event_t> stopNotifyList;
		ELogger::log(LOG_SYSTEM).debug("ACK_CHECKER timer elapsed");

		ptrInstance->lock();
		mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();

		for (auto entry : mapUeConfigTmp) {

			ue_data_t ueData = entry.second;
			if (ueData.ackReceived == ADD_ACTION) {

				if (ueData.uiForward == OPERATION_LI ||
						ueData.uiForward == OPERATION_BOTH) {
					addList.push_back(ueData);
				}

			} else if (ueData.ackReceived == UPDATE_ACTION) {

				if (ueData.uiForward == OPERATION_LI ||
						ueData.uiForward == OPERATION_BOTH) {
					updateList.push_back(ueData);
				}

			} else if (ueData.ackReceived == START_UE) {

				if (ueData.uiForward == OPERATION_LI ||
						ueData.uiForward == OPERATION_BOTH) {
					startNotifyList.push_back(ueData);
				}

			} else if (ueData.ackReceived == STOP_UE) {

				delete_event_t stopUe = {0};
				if (ueData.uiForward == OPERATION_LI ||
						ueData.uiForward == OPERATION_BOTH) {
					stopUe.uiSeqIdentifier = ueData.uiSeqIdentifier;
					stopUe.uiImsi = ueData.uiImsi;
					stopNotifyList.push_back(stopUe);
				}

			} else if (ueData.ackReceived == DELETE_ACTION) {

				delete_event_t deleteUe = {0};
				if (ueData.uiForward == OPERATION_LI ||
						ueData.uiForward == OPERATION_BOTH) {
					deleteUe.uiSeqIdentifier = ueData.uiSeqIdentifier;
					deleteUe.uiImsi = ueData.uiImsi;
					deleteList.push_back(deleteUe);
				}

			}
		}

		ptrInstance->unlock();

		if (addList.size() > ZERO) {

			std::string addRequest = prepareJsonFromUeData(addList);

			if (!addRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Re-Sending add request for ue entries "
						"which did not received ack");
				ptrInstance->SendRequestToAdmf(ADD_UE_ENTRY_URI, addRequest);

			} else
				ELogger::log(LOG_SYSTEM).debug("Add Retry: Request body creation failed");
		}

		if (updateList.size() > ZERO) {

			std::string updateRequest = prepareJsonFromUeData(updateList);

			if (!updateRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Re-Sending update request for ue entries "
						"which did not received ack");
				ptrInstance->SendRequestToAdmf(UPDATE_UE_ENTRY_URI, updateRequest);

			} else
				ELogger::log(LOG_SYSTEM).debug("Update Retry: Request body "
						"creation failed");
		}

		if (deleteList.size() > ZERO) {

			std::string deleteRequest = prepareJsonForStopUe(deleteList);

			if (!deleteRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Re-Sending delete request for ue entries "
						"which did not received ack");
				ptrInstance->SendRequestToAdmf(DELETE_UE_ENTRY_URI, deleteRequest);

			} else
				ELogger::log(LOG_SYSTEM).debug("Delete Retry: Request body "
						"creation failed");
		}

		if (startNotifyList.size() > ZERO) {

			std::string startRequest = prepareJsonForStartUe(startNotifyList, 
							START_UE);

			if (!startRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Re-Sending start notification for "
						"for ue entries which did not received ack");
				ptrInstance->SendNotificationToAdmf(NOTIFY_URI, startRequest);

			} else
				ELogger::log(LOG_SYSTEM).debug("StartNotify Retry: Request body "
						"creation failed");
		}
		
		if (stopNotifyList.size() > ZERO) {

			std::string stopRequest = prepareJsonForStopUe(stopNotifyList, STOP_UE);

			if (!stopRequest.empty()) {

				ELogger::log(LOG_SYSTEM).info("Re-Sending stop notification for "
						"for ue entries which did not received ack");
				ptrInstance->SendNotificationToAdmf(NOTIFY_URI, stopRequest);

			} else
				ELogger::log(LOG_SYSTEM).debug("StopNotify Retry: Request body "
						"creation failed");
		}

		ELogger::log(LOG_SYSTEM).debug("ACK_CHECKER timer started again");
	}

	ptrInstance->ReleaseInstance();
}

Void
EThreadAckTimer::onQuit(void)
{
}
