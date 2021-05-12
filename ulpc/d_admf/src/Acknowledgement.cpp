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


#include <map>

#include "AcknowledgementPost.h"
#include "DAdmf.h"
#include "UeEntry.h"
#include "Common.h"


AcknowledgementPost :: AcknowledgementPost(ELogger &audit)
: EManagementHandler( EManagementHandler::HttpMethod::httpPost,
			SLASH ACK_POST, audit )
{
}

void
AcknowledgementPost :: process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE :: Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	DAdmfApp *ptrInstance = DAdmfApp::GetInstance();
	std::map<uint64_t, ue_data_t> mapUeConfigTmp;
	std::string requestBody;
	ack_t ack;

	requestBody.assign(request.body());
	jsonReq.Parse(requestBody.c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_SYSTEM).info("Acknowledgement: Json parsing error. "
						"Invalid Json.");
		response.send(Pistache::Http::Code::Bad_Request, "Invalid Json.\n");
		return;

	}

	itr = jsonReq.FindMember(ACK_KEY);
	if (itr != jsonReq.MemberEnd()) {

		const RAPIDJSON_NAMESPACE::Value& ackObj = jsonReq[ACK_KEY];

		for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
				ackObj.MemberBegin();
				itr != ackObj.MemberEnd(); ++itr) {

			if (SEQ_ID_KEY == itr->name) {

				ack.uiSeqIdentifier = itr->value.GetUint64();

			} else if (IMSI_KEY == itr->name) {

				ack.uiImsi = itr->value.GetUint64();

			} else if (REQUEST_TYPE_KEY == itr->name) {

				ack.uiRequestType = itr->value.GetUint64();

			}

		}

	}

	ptrInstance->lock();
	mapUeConfigTmp = ptrInstance->getPtrUeConfig()->getMapUeConfig();

	if (mapUeConfigTmp.end() != mapUeConfigTmp.find(ack.uiSeqIdentifier)) {

		ELogger::log(LOG_SYSTEM).debug("SeqId found in map");
		if (mapUeConfigTmp[ack.uiSeqIdentifier].uiImsi == ack.uiImsi) {

			ELogger::log(LOG_SYSTEM).debug("imsi matched for seqId");
			if (ack.uiRequestType == ADD_ACTION) {

				ELogger::log(LOG_SYSTEM).debug("Ack received for Add request");
				mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived = ADD_ACK;

			} else if (ack.uiRequestType == UPDATE_ACTION) {

				ELogger::log(LOG_SYSTEM).debug("Ack received for update request");
				mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived = UPDATE_ACK;

			} else if (ack.uiRequestType == DELETE_ACTION) {

				ELogger::log(LOG_SYSTEM).debug("Ack received for delete request");
				mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived = DELETE_ACK;

			} else if (ack.uiRequestType == START_UE) {

				ELogger::log(LOG_SYSTEM).debug("Ack received for start notification");
				mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived = START_UE_ACK;

			} else if (ack.uiRequestType == STOP_UE) {

				ELogger::log(LOG_SYSTEM).debug("Ack received for stop notification");
				mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived = STOP_UE_ACK;

			}

			ptrInstance->getPtrUeConfig()->UpdateUeConfig(
					DELETE_ACTION, mapUeConfigTmp[ack.uiSeqIdentifier]);
			ptrInstance->getPtrUeConfig()->UpdateUeConfig(
					ADD_ACTION, mapUeConfigTmp[ack.uiSeqIdentifier]);

			if (mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived == DELETE_ACK ||
					mapUeConfigTmp[ack.uiSeqIdentifier].ackReceived == STOP_UE_ACK) {

				ELogger::log(LOG_SYSTEM).debug("Deleting Ue entry from map for seqId: {}",
						ack.uiSeqIdentifier);
				/* Delete Ue entry from map */
				mapUeConfigTmp.erase(ack.uiSeqIdentifier);

			}

			ELogger::log(LOG_SYSTEM).info("Ack Response: Ack received on DAdmf "
					"for seqId: {}", ack.uiSeqIdentifier);
			response.send(Pistache::Http::Code::Ok, "Ack received\n");

		} else {

			ELogger::log(LOG_SYSTEM).debug("Ack Response: Invalid seqId "
					"for provided imsi");
			response.send(Pistache::Http::Code::Bad_Request, 
					"DAdmf : Invalid seqId and imsi pair\n");
		}

	} else {

		ELogger::log(LOG_SYSTEM).debug("Ack Response: SeqId not found. "
				"Invalid SeqId");
	}

	ptrInstance->getPtrUeConfig()->setMapUeConfig(mapUeConfigTmp);
	ptrInstance->unlock();
	ptrInstance->ReleaseInstance();

}
