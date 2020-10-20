/*
 * Copyright (c) 2019 Sprint
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

#include <stdio.h>
#include <stdarg.h>

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
#include <queue>

#define RAPIDJSON_NAMESPACE statsrapidjson
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>

#include "cdadmfapi.h"
#include "gw_adapter.h"

extern int clSystemLog;

int parseJsonReqForId(const char *request, char **response, uint64_t *uiIds,
		uint16_t *uiCntr)
{
	statsrapidjson::Document jsonReq;
	RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr;

	jsonReq.Parse(request);
	if(jsonReq.HasParseError()) {
		if (response)
			*response = strdup("{\"result\": \"ERROR\"}");
		return 400;
	}

	itr = jsonReq.FindMember(UE_DB_KEY);
	if (itr != jsonReq.MemberEnd()) {
		const RAPIDJSON_NAMESPACE::Value& jsonUeArray = jsonReq[UE_DB_KEY];

		for (RAPIDJSON_NAMESPACE::SizeType iCnt = 0; iCnt < jsonUeArray.Size(); ++iCnt) {
			for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
					jsonUeArray[iCnt].MemberBegin();
					itr != jsonUeArray[iCnt].MemberEnd(); ++itr) {
				if ((LI_ID_KEY == itr->name) && ((itr->value).IsUint64())) {
					uiIds[*uiCntr] = (itr->value).GetUint64();
				}
			}

			(*uiCntr)++;
		}
	}

	if (response)
		*response = strdup("{\"result\": \"OK\"}");

	return 200;
}

int parseJsonReqFillStruct(const char *request,
		char **response, struct li_df_config_t *li_df_config, uint16_t *uiCntr) {

	statsrapidjson::Document jsonReq;

	jsonReq.Parse(request);
	if(jsonReq.HasParseError()) {

		*response = strdup("{\"result\": \"ERROR\"}");
		return 400;
	}

	if(!jsonReq.HasMember(UE_DB_KEY) || !jsonReq[UE_DB_KEY].IsArray()) {

		*response = strdup("{\"result\": \"ERROR\"}");
		return 400;
	}

	const statsrapidjson::Value& ueDatabase = jsonReq[UE_DB_KEY];

	for (statsrapidjson::Value::ConstValueIterator itr = ueDatabase.Begin();
			itr != ueDatabase.End(); ++itr) {
		const statsrapidjson::Value& ueObject = *itr;

		if (!ueObject.IsObject()) {
			return -1;
		}

		for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
				ueObject.MemberBegin();
				itr != ueObject.MemberEnd(); ++itr) {
			/* Need to check datatype using itr->value.GetType() */
			if (LI_ID_KEY == itr->name) {
				li_df_config[*uiCntr].uiId = itr->value.GetUint64();
			} else if (IMSI_KEY == itr->name) {
				li_df_config[*uiCntr].uiImsi = itr->value.GetUint64();
			} else if (S11_KEY == itr->name) {
				li_df_config[*uiCntr].uiS11 = itr->value.GetUint();
			} else if (SGW_S5S8_C_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8C = itr->value.GetUint();
			} else if (PGW_S5S8_C_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8C = itr->value.GetUint();
			} else if (SXA_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxa = itr->value.GetUint();
			} else if (SXB_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxb = itr->value.GetUint();
			} else if (SXA_SXB_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxaSxb = itr->value.GetUint();
			} else if (S1U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiS1uContent = itr->value.GetUint();
			} else if (SGW_S5S8U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8UContent = itr->value.GetUint();
			} else if (PGW_S5S8U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8UContent = itr->value.GetUint();
			} else if (SGI_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgiContent = itr->value.GetUint();
			} else if (S1U_KEY == itr->name) {
				li_df_config[*uiCntr].uiS1u = itr->value.GetUint();
			} else if (SGW_S5S8_U_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8U = itr->value.GetUint();
			} else if (PGW_S5S8_U_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8U = itr->value.GetUint();
			} else if (SGI_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgi = itr->value.GetUint();
			} else if (FORWARD_KEY == itr->name) {
				li_df_config[*uiCntr].uiForward = itr->value.GetUint();
			}
		}

		(*uiCntr)++;
	}

	return 200;
}

size_t
jsonResponseCallback(char *contents, size_t size, size_t nmemb, void *userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

int
sendRegisterCpCurlReq(std::string strDadmfIpAddr,
		std::string strDadmfPort, std::string strCpIpAddr,
		std::string &strJsonResponse) {
	CURL *curlHandle;
	CURLcode curlReturnCode;

#define IP_LEN 16
	char buf[IP_LEN];

	std::string strPostFields = "{\"cpipaddr\":\"" + strCpIpAddr + "\"}";
	std::string strDadmfUrl;

	if (inet_pton(AF_INET, (const char *)strDadmfIpAddr.c_str(), buf)) {	
		strDadmfUrl = "http://" + strDadmfIpAddr + ":" +
			strDadmfPort + "/registercp";
	} else if (inet_pton(AF_INET6, (const char *)strDadmfIpAddr.c_str(), buf)) {
		strDadmfUrl = "http://[" + strDadmfIpAddr + "]:" +
			strDadmfPort + "/registercp";
	}

	curl_global_init(CURL_GLOBAL_ALL);
	curlHandle = curl_easy_init();
	if(curlHandle)
	{
		struct curl_slist *curlHeaderParam = NULL;
		curlHeaderParam = curl_slist_append(curlHeaderParam, CONTENT_TYPE_JSON);
		curlHeaderParam = curl_slist_append(curlHeaderParam, X_USER_NAME);

		curl_easy_setopt(curlHandle, CURLOPT_URL, strDadmfUrl.c_str());

		/* Register Callback For Response */
		curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, jsonResponseCallback);

		/* Pass Structure To Copy Data In Callback */
		curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &strJsonResponse);

		/* User Agent is Required For Some Servers */
		curl_easy_setopt(curlHandle, CURLOPT_USERAGENT, USER_AGENT);

		/* POST Request Parameters */
		curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, strPostFields.c_str());

		/* Header Parameters */
		curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, curlHeaderParam);

		/* Set timeout Parameter */
		curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 2L);

		/* Send Curl Request And It Returns Return Code */
		curlReturnCode = curl_easy_perform(curlHandle);
		if(curlReturnCode != CURLE_OK) {
			return -1;
		}

		/* Cleanup */
		curl_slist_free_all(curlHeaderParam);
		curl_easy_cleanup(curlHandle);
	}

	curl_global_cleanup();
	return 0;
}

int
registerCpOnDadmf(char *dadmf_addr,
		uint16_t dadmf_port, char *pfcp_addr,
		struct li_df_config_t *li_df_config, uint16_t *uiCntr) {

	int ret = -1;
	std::string strJsonResponse;
	std::string strDadmfPort = std::to_string(dadmf_port);
	std::string strCpIpAddr = (pfcp_addr);
	std::string strDadmfIpAddr = dadmf_addr;

	ret = sendRegisterCpCurlReq(strDadmfIpAddr,
			strDadmfPort, strCpIpAddr, strJsonResponse);
	if (ret < 0) {
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			"Lawful Interception Database As Follows\n%s\n", strJsonResponse.c_str());

	statsrapidjson::Document jsonResp;

	jsonResp.Parse(strJsonResponse.c_str());
	if(jsonResp.HasParseError()) {
		return -1;
	}

	if(!jsonResp.HasMember(UE_DB_KEY) || !jsonResp[UE_DB_KEY].IsArray()) {
		return -1;
	}

	const statsrapidjson::Value& ueDatabase = jsonResp[UE_DB_KEY];

	for (statsrapidjson::Value::ConstValueIterator itr = ueDatabase.Begin();
			itr != ueDatabase.End(); ++itr) {
		const statsrapidjson::Value& ueObject = *itr;

		if (!ueObject.IsObject()) {
			return -1;
		}

		for (RAPIDJSON_NAMESPACE::Value::ConstMemberIterator itr =
				ueObject.MemberBegin();
				itr != ueObject.MemberEnd(); ++itr) {
			/* Need to check datatype using itr->value.GetType() */
			if (LI_ID_KEY == itr->name) {
				li_df_config[*uiCntr].uiId = itr->value.GetUint64();
			} else if (IMSI_KEY == itr->name) {
				li_df_config[*uiCntr].uiImsi = itr->value.GetUint64();
			} else if (S11_KEY == itr->name) {
				li_df_config[*uiCntr].uiS11 = itr->value.GetUint();
			} else if (SGW_S5S8_C_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8C = itr->value.GetUint();
			} else if (PGW_S5S8_C_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8C = itr->value.GetUint();
			} else if (SXA_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxa = itr->value.GetUint();
			} else if (SXB_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxb = itr->value.GetUint();
			} else if (SXA_SXB_KEY == itr->name) {
				li_df_config[*uiCntr].uiSxaSxb = itr->value.GetUint();
			} else if (S1U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiS1uContent = itr->value.GetUint();
			} else if (SGW_S5S8U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8UContent = itr->value.GetUint();
			} else if (PGW_S5S8U_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8UContent = itr->value.GetUint();
			} else if (SGI_CONTENT_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgiContent = itr->value.GetUint();
			} else if (S1U_KEY == itr->name) {
				li_df_config[*uiCntr].uiS1u = itr->value.GetUint();
			} else if (SGW_S5S8_U_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgwS5s8U = itr->value.GetUint();
			} else if (PGW_S5S8_U_KEY == itr->name) {
				li_df_config[*uiCntr].uiPgwS5s8U = itr->value.GetUint();
			} else if (SGI_KEY == itr->name) {
				li_df_config[*uiCntr].uiSgi = itr->value.GetUint();
			} else if (FORWARD_KEY == itr->name) {
				li_df_config[*uiCntr].uiForward = itr->value.GetUint();
			}
		}

		(*uiCntr)++;
	}

	return 0;
}

int
ConvertAsciiIpToNumeric(const char *ipAddr) {
	struct in_addr addr;

	/* IP Address to in_addr */
	if (inet_aton(ipAddr, &addr) == 0) {
		printf("Failed for inet_aton\n");
		return -1;
	}

	return addr.s_addr;
}
