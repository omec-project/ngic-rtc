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


#include <cstdlib>
#include <cstring>
#include <ctime>

#define RAPIDJSON_HAS_STDSTRING 1

#include "epc/epctools.h"
#include "epc/etevent.h"
#include "epc/esocket.h"
#include "epc/einternal.h"
#include "epc/emgmt.h"

#define RAPIDJSON_NAMESPACE ulpcrapidjson
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "Common.h"
#include "DAdmf.h"


extern ue_defaults_t ue_default;

int
ConvertAsciiIpToNumeric(const char *ipAddr)
{
	struct in_addr addr;

	/* IP Address to in_addr */
	if (inet_aton(ipAddr, &addr) == ZERO) {
		return RET_FAILURE;
	}

	return addr.s_addr;
}

int64_t
getTimeDiffInMilliSec(const std::string &dateStr)
{
	time_t now;
	struct tm newTime;

	time(&now);
	strptime(dateStr.c_str(), "%Y-%m-%dT%H:%M:%SZ", &newTime);
	int32_t seconds = difftime(mktime(&newTime), now);
	int64_t mSeconds = seconds * MILLISECONDS;

	return mSeconds;
}


std::string
prepareJsonFromUeData(std::list<ue_data_t> &ueDataList)
{
	RAPIDJSON_NAMESPACE::Document jsonDoc;
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator = 
				jsonDoc.GetAllocator();
	RAPIDJSON_NAMESPACE::Value ueDBArr(RAPIDJSON_NAMESPACE::kArrayType);
	ueDBArr.SetArray();

	for (ue_data_t ueData : ueDataList) {

		RAPIDJSON_NAMESPACE::Document ueDBDoc(RAPIDJSON_NAMESPACE::kObjectType);
		ueDBDoc.SetObject();

		ueDBDoc.AddMember(SEQ_ID_KEY, ueData.uiSeqIdentifier, allocator);
		ueDBDoc.AddMember(IMSI_KEY, ueData.uiImsi, allocator);

		RAPIDJSON_NAMESPACE::Value signallingConfigDoc(
				RAPIDJSON_NAMESPACE::kObjectType);
		signallingConfigDoc.SetObject();

		signallingConfigDoc.AddMember(S11_KEY, ueData.uiS11, allocator);
		signallingConfigDoc.AddMember(SGW_S5S8_C_KEY, ueData.uiSgws5s8c, allocator);
		signallingConfigDoc.AddMember(PGW_S5S8_C_KEY, ueData.uiPgws5s8c, allocator);

		RAPIDJSON_NAMESPACE::Value sxArr(RAPIDJSON_NAMESPACE::kArrayType);
		sxArr.SetArray();

		for (std::map<uint16_t, uint16_t>::iterator it = ueData.mapSxConfig.begin();
				it != ueData.mapSxConfig.end(); ++it) {

			RAPIDJSON_NAMESPACE::Document sxDoc(RAPIDJSON_NAMESPACE::kObjectType);
			sxDoc.SetObject();

			sxDoc.AddMember(SX_INTFC_KEY, it->first, allocator);
			sxDoc.AddMember(CP_DP_TYPE_KEY, it->second, allocator);

			sxArr.PushBack(sxDoc, allocator);
		}

		signallingConfigDoc.AddMember(SX_KEY, sxArr, allocator);

		ueDBDoc.AddMember(SIGNALLING_CONFIG_KEY, signallingConfigDoc, allocator);

		RAPIDJSON_NAMESPACE::Value dataConfigDoc(RAPIDJSON_NAMESPACE::kObjectType);
		dataConfigDoc.SetObject();

		dataConfigDoc.AddMember(S1U_CONTENT_KEY, ueData.s1uContent, allocator);
		dataConfigDoc.AddMember(SGW_S5S8U_CONTENT_KEY, ueData.sgwS5S8Content, 
				allocator);
		dataConfigDoc.AddMember(PGW_S5S8U_CONTENT_KEY, ueData.pgwS5S8Content, 
				allocator);
		dataConfigDoc.AddMember(SGI_CONTENT_KEY, ueData.sgiContent, allocator);

		RAPIDJSON_NAMESPACE::Value intfcConfigArr(RAPIDJSON_NAMESPACE::kArrayType);
        	intfcConfigArr.SetArray();

		for (std::map<uint16_t, uint16_t>::iterator itr = 
				ueData.mapIntfcConfig.begin();
				itr != ueData.mapIntfcConfig.end(); ++itr) {

			RAPIDJSON_NAMESPACE::Document intfcConfigDoc(
					RAPIDJSON_NAMESPACE::kObjectType);
			intfcConfigDoc.SetObject();

			intfcConfigDoc.AddMember(DATA_INTFC_NAME_KEY, itr->first, allocator);
			intfcConfigDoc.AddMember(DATA_DIRECTION_KEY, itr->second, allocator);

			intfcConfigArr.PushBack(intfcConfigDoc, allocator);
		}

		dataConfigDoc.AddMember(DATA_INTFC_CONFIG_KEY, intfcConfigArr, allocator);

		ueDBDoc.AddMember(DATA_CONFIG_KEY, dataConfigDoc, allocator);

		ueDBDoc.AddMember(FORWARD_KEY, ueData.uiForward, allocator);

		RAPIDJSON_NAMESPACE::Value timerObjDoc(RAPIDJSON_NAMESPACE::kObjectType);
		timerObjDoc.SetObject();

		const char *chStartTime = (ueData.strStartTime).c_str();
		const char *chStopTime = (ueData.strStopTime).c_str();

		RAPIDJSON_NAMESPACE::Value startTime;
		startTime.SetString(chStartTime, (ueData.strStartTime).size(), allocator);

		RAPIDJSON_NAMESPACE::Value stopTime;
		stopTime.SetString(chStopTime, (ueData.strStopTime).size(), allocator);

		timerObjDoc.AddMember(START_TIME_KEY, startTime, allocator);
		timerObjDoc.AddMember(STOP_TIME_KEY, stopTime, allocator);

		ueDBDoc.AddMember(TIMER_KEY, timerObjDoc, allocator);

		ueDBArr.PushBack(ueDBDoc, allocator);

	}

	jsonDoc.AddMember(UE_DB_KEY, ueDBArr, allocator);
	jsonDoc.AddMember(REQUEST_SOURCE_KEY, D_ADMF_REQUEST, allocator);

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();
}

uint64_t
generateSequenceIdentifier(ue_data_t &ueData)
{
	uint64_t sequenceIdentifier = ZERO;

	uint64_t startDiff = ((getTimeDiffInMilliSec(ueData.strStartTime)) / 
				MILLISECONDS);
	uint64_t stopDiff = ((getTimeDiffInMilliSec(ueData.strStopTime)) / 
				MILLISECONDS);

	uint64_t timeDiff = startDiff - stopDiff;

	srand((uint64_t)time(0));

	uint64_t randomNum = (rand() % MILLISECONDS) + (rand() % MILLISECONDS);

	sequenceIdentifier = ueData.uiImsi + ueData.uiS11 + ueData.uiSgws5s8c
				+ ueData.uiPgws5s8c + ueData.uiPgws5s8c
				+ ueData.uiForward + ueData.s1uContent
				+ ueData.sgwS5S8Content + ueData.pgwS5S8Content
				+ ueData.sgiContent + timeDiff + randomNum;

	return sequenceIdentifier;
				
}


std::string
prepareJsonForStartUe(std::list<ue_data_t> &ueDataList, uint8_t notifyType)
{
	RAPIDJSON_NAMESPACE::Document jsonDoc;
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator = 
			jsonDoc.GetAllocator();
	RAPIDJSON_NAMESPACE::Value ueDBArr(RAPIDJSON_NAMESPACE::kArrayType);
	ueDBArr.SetArray();

	for (ue_data_t ueData : ueDataList) {

		RAPIDJSON_NAMESPACE::Document ueDBDoc(RAPIDJSON_NAMESPACE::kObjectType);
		ueDBDoc.SetObject();

		ueDBDoc.AddMember(SEQ_ID_KEY, ueData.uiSeqIdentifier, allocator);
		ueDBDoc.AddMember(IMSI_KEY, ueData.uiImsi, allocator);

		RAPIDJSON_NAMESPACE::Value timerObjDoc(RAPIDJSON_NAMESPACE::kObjectType);
		timerObjDoc.SetObject();

		const char *chStartTime = (ueData.strStartTime).c_str();
		const char *chStopTime = (ueData.strStopTime).c_str();

		RAPIDJSON_NAMESPACE::Value startTime;
		startTime.SetString(chStartTime, (ueData.strStartTime).size(), allocator);

		RAPIDJSON_NAMESPACE::Value stopTime;
		stopTime.SetString(chStopTime, (ueData.strStopTime).size(), allocator);

		timerObjDoc.AddMember(START_TIME_KEY, startTime, allocator);
		timerObjDoc.AddMember(STOP_TIME_KEY, stopTime, allocator);

		ueDBDoc.AddMember(TIMER_KEY, timerObjDoc, allocator);

		ueDBArr.PushBack(ueDBDoc, allocator);

	}

	jsonDoc.AddMember(UE_DB_KEY, ueDBArr, allocator);

	if (notifyType == START_UE || notifyType == STOP_UE) {

		jsonDoc.AddMember(NOTIFY_TYPE_KEY, notifyType, allocator);
	}

	jsonDoc.AddMember(REQUEST_SOURCE_KEY, D_ADMF_REQUEST, allocator);

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();
}


std::string
prepareJsonForCP(std::list<ue_data_t> &ueDataList)
{
	RAPIDJSON_NAMESPACE::Document jsonDoc;
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator = 
			jsonDoc.GetAllocator();
	RAPIDJSON_NAMESPACE::Value ueDBArr(RAPIDJSON_NAMESPACE::kArrayType);
	ueDBArr.SetArray();

	for (ue_data_t ueData : ueDataList) {

		RAPIDJSON_NAMESPACE::Document ueDBDoc(RAPIDJSON_NAMESPACE::kObjectType);
		ueDBDoc.SetObject();

		ueDBDoc.AddMember(SEQ_ID_KEY, ueData.uiSeqIdentifier, allocator);
		ueDBDoc.AddMember(IMSI_KEY, ueData.uiImsi, allocator);
		ueDBDoc.AddMember(S11_KEY, ueData.uiS11, allocator);
		ueDBDoc.AddMember(SGW_S5S8_C_KEY, ueData.uiSgws5s8c, allocator);
		ueDBDoc.AddMember(PGW_S5S8_C_KEY, ueData.uiPgws5s8c, allocator);

		if (ueData.mapSxConfig.size() == 0) {

			ueDBDoc.AddMember(SXA_INTFC_NAME, ue_default.sxa, allocator);
			ueDBDoc.AddMember(SXB_INTFC_NAME, ue_default.sxb, allocator);
			ueDBDoc.AddMember(SXA_SXB_INTFC_NAME, ue_default.sxasxb, allocator);

		} else {

			for (std::map<uint16_t, uint16_t>::iterator it = ueData.mapSxConfig.begin();
					it != ueData.mapSxConfig.end(); ++it) {

				switch (it->first) {
					case SXA:
						ueDBDoc.AddMember(SXA_INTFC_NAME, it->second, allocator);
						break;
					case SXB:
						ueDBDoc.AddMember(SXB_INTFC_NAME, it->second, allocator);
						break;
					case SXA_SXB:
						ueDBDoc.AddMember(SXA_SXB_INTFC_NAME, it->second, allocator);
						break;
				}
			}

		}

		ueDBDoc.AddMember(S1U_CONTENT_KEY, ueData.s1uContent, allocator);
		ueDBDoc.AddMember(SGW_S5S8U_CONTENT_KEY, ueData.sgwS5S8Content, allocator);
		ueDBDoc.AddMember(PGW_S5S8U_CONTENT_KEY, ueData.pgwS5S8Content, allocator);
		ueDBDoc.AddMember(SGI_CONTENT_KEY, ueData.sgiContent, allocator);

		if (ueData.mapIntfcConfig.size() == 0) {

			ueDBDoc.AddMember(S1U_INTFC_NAME, ue_default.s1u, allocator);
			ueDBDoc.AddMember(SGW_S5S8_U_INTFC_NAME, ue_default.sgw_s5s8u, allocator);
			ueDBDoc.AddMember(PGW_S5S8_U_INTFC_NAME, ue_default.pgw_s5s8u, allocator);
			ueDBDoc.AddMember(SGI_INTFC_NAME, ue_default.sgi, allocator);

		} else {

			for (std::map<uint16_t, uint16_t>::iterator itr = 
					ueData.mapIntfcConfig.begin();
					itr != ueData.mapIntfcConfig.end(); ++itr) {

				switch (itr->first) {
					case S1U:
						ueDBDoc.AddMember(S1U_INTFC_NAME, itr->second, allocator);
						break;
					case SGW_S5S8_U:
						ueDBDoc.AddMember(SGW_S5S8_U_INTFC_NAME, itr->second, allocator);
						break;
					case PGW_S5S8_U:
						ueDBDoc.AddMember(PGW_S5S8_U_INTFC_NAME, itr->second, allocator);
						break;
					case SGI:
						ueDBDoc.AddMember(SGI_INTFC_NAME, itr->second, allocator);
						break;
				}
			}

		}

		ueDBDoc.AddMember(FORWARD_KEY, ueData.uiForward, allocator);

		ueDBArr.PushBack(ueDBDoc, allocator);

	}

	jsonDoc.AddMember(UE_DB_KEY, ueDBArr, allocator);

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();
}

std::string
prepareJsonForStopUe(std::list<delete_event_t> &ueDataList, uint8_t notifyType)
{
	RAPIDJSON_NAMESPACE::Document jsonDoc;
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator = 
			jsonDoc.GetAllocator();
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Value ueDBArr(RAPIDJSON_NAMESPACE::kArrayType);
	ueDBArr.SetArray();

	for (delete_event_t ueData : ueDataList) {

		RAPIDJSON_NAMESPACE::Document ueDBDoc(RAPIDJSON_NAMESPACE::kObjectType);
		ueDBDoc.SetObject();
		ueDBDoc.AddMember(SEQ_ID_KEY, ueData.uiSeqIdentifier, allocator);
		ueDBDoc.AddMember(IMSI_KEY, ueData.uiImsi, allocator);

		ueDBArr.PushBack(ueDBDoc, allocator);
	}

	jsonDoc.AddMember(UE_DB_KEY, ueDBArr, allocator);
	jsonDoc.AddMember(REQUEST_SOURCE_KEY, D_ADMF_REQUEST, allocator);

	if (notifyType == START_UE || notifyType == STOP_UE) {

		jsonDoc.AddMember(NOTIFY_TYPE_KEY, notifyType, allocator);

	}

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();
}

std::string
prepareResponseJson(std::list<ue_data_t> &ueDataList, std::string &responseMsg)
{
	RAPIDJSON_NAMESPACE::Document jsonDoc;
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator = 
			jsonDoc.GetAllocator();
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Value ueDBArr(RAPIDJSON_NAMESPACE::kArrayType);
	ueDBArr.SetArray();
	RAPIDJSON_NAMESPACE::Value ueDataDoc(RAPIDJSON_NAMESPACE::kObjectType);
	ueDataDoc.SetObject();

	RAPIDJSON_NAMESPACE::Value respMsg;
	respMsg.SetString(RAPIDJSON_NAMESPACE::StringRef(responseMsg.c_str()));
	jsonDoc.AddMember(RESPONSE_MSG_KEY, respMsg, allocator);

	for (ue_data_t ueData : ueDataList) {

		RAPIDJSON_NAMESPACE::Document ueDBDoc(RAPIDJSON_NAMESPACE::kObjectType);
		ueDBDoc.SetObject();
		ueDBDoc.AddMember(SEQ_ID_KEY, ueData.uiSeqIdentifier, allocator);
		ueDBDoc.AddMember(IMSI_KEY, ueData.uiImsi, allocator);

		ueDBArr.PushBack(ueDBDoc, allocator);
	}

	ueDataDoc.AddMember(UE_DB_KEY, ueDBArr, allocator);

	jsonDoc.AddMember(RESPONSE_JSON_KEY, ueDataDoc, allocator);

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();
}
