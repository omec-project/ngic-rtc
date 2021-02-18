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

#include "epc/emgmt.h"
#include "elogger.h"
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "AdmfController.h"
#include "LegacyAdmfInterface.h"
#include "DAdmfInterface.h"


int AdmfController::iRefCnt = ZERO;
AdmfController *AdmfController :: mpInstance = NULL;

AdmfController :: AdmfController (AdmfApplication &app) : mApp(app)
{
	// private constructor as this class is Singleton
}

AdmfController * AdmfController :: getInstance(AdmfApplication &app)
{
	if (mpInstance == NULL) {
		mpInstance = new AdmfController (app);
	}

	++iRefCnt;
	return mpInstance;
}

void
AdmfController::ReleaseInstance(void)
{
	--iRefCnt;

	if((ZERO == iRefCnt) && (NULL != mpInstance)) {
		SAFE_DELETE(mpInstance);
	}
}

void
AdmfController :: addUeController (std::list<ue_data_t *> &ueEntries,
				std::string &requestBody, uint16_t requestSource)
{
	ELogger::log(LOG_ADMF).debug("[{}->{}:{}]", __file__,
					__FUNCTION__, __LINE__);
	
	if (requestSource != D_ADMF_REQUEST) {

		ELogger::log(LOG_ADMF).info("Sending Add Ue request to D_ADMF.");
		mApp.getDadmfInterface().sendRequestToDadmf(ADD_UE_ENTRY, requestBody);

	} else {

		std::map<uint64_t, ack_t> mapPendingAckTmp;
		mapPendingAckTmp = mApp.getMapPendingAck();

		for (ue_data_t *ueEntry : ueEntries) {

			if (ueEntry->uiForward == OPERATION_LI || 
					ueEntry->uiForward == OPERATION_BOTH) {

				admf_packet_t *admfPacket_t = new admf_packet_t();

				admfPacket_t->ue_entry_t.seqId = ueEntry->uiSeqIdentifier;
				admfPacket_t->ue_entry_t.imsi = ueEntry->uiImsi;

				uint16_t startLength = (ueEntry->strStartTime).size() + ONE;
				std::memset(admfPacket_t->ue_entry_t.startTime, ZERO, startLength);
				std::memcpy(admfPacket_t->ue_entry_t.startTime, 
						(ueEntry->strStartTime).c_str(), startLength);

				uint16_t stopLength = (ueEntry->strStopTime).size() + ONE;
				std::memset(admfPacket_t->ue_entry_t.stopTime, ZERO, stopLength);
				std::memcpy(admfPacket_t->ue_entry_t.stopTime, 
						(ueEntry->strStopTime).c_str(), stopLength);

				admfPacket_t->ue_entry_t.packetType = ADMF_PACKET;
				admfPacket_t->ue_entry_t.requestType = ADD_REQUEST;
				admfPacket_t->packetLength = sizeof(admf_packet_t);

				ELogger::log(LOG_ADMF).info("Sending Add Ue request to Legacy ADMF.");
				mApp.getLegacyAdmfInterface().sendMessageToLegacyAdmf((void *)admfPacket_t);

				/* Maintaining Ue entry in map for which ACK has not received */
				ack_t ackObj;
				ackObj.uiSeqIdentifier = ueEntry->uiSeqIdentifier;
				ackObj.uiImsi = ueEntry->uiImsi;
				ackObj.uiRequestType = ADD_REQUEST;

				mapPendingAckTmp.insert({ueEntry->uiSeqIdentifier, ackObj});

			}
		}

		mApp.setMapPendingAck(mapPendingAckTmp);
	}

}

void
AdmfController :: modifyUeController (std::list<ue_data_t *> &ueEntries,
			std::string &requestBody, uint16_t requestSource)
{
	ELogger::log(LOG_ADMF).debug("[{}->{}:{}]", __file__,
					__FUNCTION__, __LINE__);
	if (requestSource != D_ADMF_REQUEST) {

		ELogger::log(LOG_ADMF).info("Sending Update Ue request to D_ADMF");
		mApp.getDadmfInterface().sendRequestToDadmf(UPDATE_UE_ENTRY, requestBody);

	} else {

		std::map<uint64_t, ack_t> mapPendingAckTmp;
                mapPendingAckTmp = mApp.getMapPendingAck();

		for (ue_data_t *ueEntry : ueEntries) {

			if (ueEntry->uiForward == OPERATION_LI ||
				ueEntry->uiForward == OPERATION_BOTH) {

				admf_packet_t *admfPacket_t = new admf_packet_t();

				admfPacket_t->ue_entry_t.seqId = ueEntry->uiSeqIdentifier;
				admfPacket_t->ue_entry_t.imsi = ueEntry->uiImsi;

				uint16_t startLength = (ueEntry->strStartTime).size() + 1;
				std::memset(admfPacket_t->ue_entry_t.startTime, 0, startLength);
				std::memcpy(admfPacket_t->ue_entry_t.startTime, 
						(ueEntry->strStartTime).c_str(), startLength);

				uint16_t stopLength = (ueEntry->strStopTime).size() + 1;
				std::memset(admfPacket_t->ue_entry_t.stopTime, 0, stopLength);
				std::memcpy(admfPacket_t->ue_entry_t.stopTime,
						(ueEntry->strStopTime).c_str(), stopLength);

				admfPacket_t->ue_entry_t.packetType = ADMF_PACKET;
				admfPacket_t->ue_entry_t.requestType = UPDATE_REQUEST;
				admfPacket_t->packetLength = sizeof(admf_packet_t);

				ELogger::log(LOG_ADMF).info("Sending Update Ue request to Legacy ADMF.");
				mApp.getLegacyAdmfInterface().sendMessageToLegacyAdmf((void *)admfPacket_t);

				/* Maintaining Ue entry in map for which ACK has not received */
				ack_t ackObj;
				ackObj.uiSeqIdentifier = ueEntry->uiSeqIdentifier;
				ackObj.uiImsi = ueEntry->uiImsi;
				ackObj.uiRequestType = UPDATE_REQUEST;

				mapPendingAckTmp.insert({ueEntry->uiSeqIdentifier, ackObj});

			}
		}

		mApp.setMapPendingAck(mapPendingAckTmp);

	}

}

void
AdmfController :: deleteUeController (std::list<delete_event_t *> &ueEntries,
				std::string &requestBody, uint16_t requestSource)
{
	ELogger::log(LOG_ADMF).debug("[{}->{}:{}]", __file__,
					__FUNCTION__, __LINE__);

	if (requestSource != D_ADMF_REQUEST) {

		ELogger::log(LOG_ADMF).info("Sending Delete Ue request to D_ADMF");
		mApp.getDadmfInterface().sendRequestToDadmf(DELETE_UE_ENTRY, requestBody);

	} else {

		std::map<uint64_t, ack_t> mapPendingAckTmp;
                mapPendingAckTmp = mApp.getMapPendingAck();

		for (delete_event_t *ueEntry : ueEntries) {

			admf_packet_t *admfPacket_t = new admf_packet_t();

			admfPacket_t->ue_entry_t.seqId = ueEntry->uiSeqIdentifier;
			admfPacket_t->ue_entry_t.imsi = ueEntry->uiImsi;

			std::memset(admfPacket_t->ue_entry_t.startTime, 0, 21);
			std::memset(admfPacket_t->ue_entry_t.stopTime, 0, 21);

			admfPacket_t->ue_entry_t.packetType = ADMF_PACKET;
			admfPacket_t->ue_entry_t.requestType = DELETE_REQUEST;
			admfPacket_t->packetLength = sizeof(admf_packet_t);

			ELogger::log(LOG_ADMF).info("Sending Delete Ue request to Legacy ADMF.");
			mApp.getLegacyAdmfInterface().sendMessageToLegacyAdmf((void *)admfPacket_t);

			/* Maintaining Ue entry in map for which ACK has not received */
			ack_t ackObj;
			ackObj.uiSeqIdentifier = ueEntry->uiSeqIdentifier;
			ackObj.uiImsi = ueEntry->uiImsi;
			ackObj.uiRequestType = DELETE_REQUEST;

			mapPendingAckTmp.insert({ueEntry->uiSeqIdentifier, ackObj});

			mApp.setMapPendingAck(mapPendingAckTmp);
		}

	}

}

void
AdmfController :: notifyUeController(std::list<ue_notify_t *> &ueEntries,
			std::string &requestBody)
{

	std::map<uint64_t, ack_t> mapPendingAckTmp;
	mapPendingAckTmp = mApp.getMapPendingAck();

	for (ue_notify_t *ueEntry : ueEntries) {

		admf_packet_t *admfPacket_t = new admf_packet_t();

		admfPacket_t->ue_entry_t.seqId = ueEntry->uiSeqIdentifier;
		admfPacket_t->ue_entry_t.imsi = ueEntry->uiImsi;

		uint16_t startLength = (ueEntry->strStartTime).size() + 1;
		std::memset(admfPacket_t->ue_entry_t.startTime, 0, startLength);
		std::memcpy(admfPacket_t->ue_entry_t.startTime,
				(ueEntry->strStartTime).c_str(), startLength);

		uint16_t stopLength = (ueEntry->strStopTime).size() + 1;
		std::memset(admfPacket_t->ue_entry_t.stopTime, 0, stopLength);
		std::memcpy(admfPacket_t->ue_entry_t.stopTime,
				(ueEntry->strStopTime).c_str(), stopLength);

		admfPacket_t->ue_entry_t.packetType = ADMF_PACKET;
		admfPacket_t->ue_entry_t.requestType = ueEntry->notifyType;
		admfPacket_t->packetLength = sizeof(admf_packet_t);

		ELogger::log(LOG_ADMF).info("Sending notification request to Legacy ADMF.");

		mApp.getLegacyAdmfInterface().sendMessageToLegacyAdmf((void *)admfPacket_t);

		/* Maintaining Ue entry in map for which ACK has not received */
		ack_t ackObj;
		ackObj.uiSeqIdentifier = ueEntry->uiSeqIdentifier;
		ackObj.uiImsi = ueEntry->uiImsi;
		ackObj.uiRequestType = ueEntry->notifyType;

		mapPendingAckTmp.insert({ueEntry->uiSeqIdentifier, ackObj});

		mApp.setMapPendingAck(mapPendingAckTmp);
	}
}
