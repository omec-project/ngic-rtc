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

#include "estats.h"
#include "etime.h"
#include "elogger.h"

#include "AcknowledgementPost.h"
#include "AdmfApp.h"
#include "DAdmfInterface.h"
#include "AdmfInterface.h"
#include "UeEntry.h"


AcknowledgementPost :: AcknowledgementPost(ELogger &audit, AdmfApplication &app) 
: EManagementHandler(EManagementHandler::HttpMethod::httpPost,
			ACK_POST, audit), mApp(app)
{
}

void
AcknowledgementPost :: process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response)
{
	RAPIDJSON_NAMESPACE :: Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;
	std::string requestBody;
	ack_t ack;
	std::map<uint64_t, ack_t> mapPendingAckTmp;

	requestBody.assign(request.body());
	jsonReq.Parse(requestBody.c_str());
	if (jsonReq.HasParseError()) {

		ELogger::log(LOG_ADMF).info("Acknowledgement: Json parsing error. "
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

	mapPendingAckTmp = mApp.getMapPendingAck();
	int8_t respValue = RET_FAILURE;

	if (mapPendingAckTmp.end() != mapPendingAckTmp.find(ack.uiSeqIdentifier)) {

		if (mapPendingAckTmp[ack.uiSeqIdentifier].uiImsi == ack.uiImsi &&
			mapPendingAckTmp[ack.uiSeqIdentifier].uiRequestType == ack.uiRequestType) {

			respValue = mApp.getDadmfInterface().sendAckToDadmf(ACK_POST, requestBody);

			if (respValue == RET_SUCCESS) {

				ELogger::log(LOG_ADMF).info("Ack Response: Ack sent to DAdmf");
				response.send(Pistache::Http::Code::Ok, "Ack sent to DAdmf\n");
				mapPendingAckTmp.erase(ack.uiSeqIdentifier);
				mApp.setMapPendingAck(mapPendingAckTmp);

			} else {

				ELogger::log(LOG_ADMF).debug("Failed to send ack to DAdmf");
				response.send(Pistache::Http::Code::Connection_Closed_Without_Response,
						"Failed to send ack to DAdmf\n");
			}

		} else {

			ELogger::log(LOG_ADMF).debug("Ack Response: Invalid seqId "
					"for provided imsi");
			response.send(Pistache::Http::Code::Bad_Request, 
					"Invalid seqId and imsi pair\n");
		}

	} else {

		ELogger::log(LOG_ADMF).debug("Ack Response: Invalid seqId. "
				"Ue Entry not found");
		response.send(Pistache::Http::Code::Bad_Request,
				"Invalid seqId. Ue Entry not found\n");
	}

}
