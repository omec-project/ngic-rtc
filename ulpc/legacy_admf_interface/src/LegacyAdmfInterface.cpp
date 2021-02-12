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
#include <inttypes.h>
#include <curl/curl.h>

#include "LegacyAdmfInterface.h"
#include "Common.h"

#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"


config_t *intfc_config;

int LegacyAdmfInterface :: refCnt = ZERO;
LegacyAdmfInterface * LegacyAdmfInterface :: ladmfInstance = NULL;
ELogger *LegacyAdmfInterface::logger = NULL;


LegacyAdmfInterface :: LegacyAdmfInterface ()
	: legacyAdmfIntfcThread(NULL)
{
}

LegacyAdmfInterface :: ~LegacyAdmfInterface ()
{
}

void
LegacyAdmfInterface :: startup(void *conf)
{
	try {
		LegacyAdmfInterface::log().debug("LegacyAdmfInterface :: startup()");
		intfc_config = (reinterpret_cast<config_t *>(conf));

		legacyAdmfIntfcThread = new LegacyAdmfInterfaceThread(this);

		legacyAdmfIntfcThread->setLegacyAdmfPort(intfc_config->legacyAdmfPort);
		legacyAdmfIntfcThread->setLegacyAdmfIp(
				std::string(inet_ntoa(intfc_config->legacyAdmfIp)));
		legacyAdmfIntfcThread->setLegacyAdmfInterfacePort(
				intfc_config->legacyAdmfIntfcPort);

		legacyAdmfIntfcThread->init(1, 1, NULL, 200000);

	} catch (const std::exception &e) {
		std::cerr << e.what() << "\n";
	}
}

void
LegacyAdmfInterface :: shutdown()
{
	if (legacyAdmfIntfcThread) {
		legacyAdmfIntfcThread->quit();
		legacyAdmfIntfcThread->join();
	}

	SAFE_DELETE_PTR(legacyAdmfIntfcThread);
}

uint16_t
LegacyAdmfInterface :: sendMessageToLegacyAdmf(void *packet)
{
	LegacyAdmfInterface::log().info("Request received from ADMF");
	legacyAdmfIntfcThread->processData(packet);

	return RETURN_SUCCESS;
}


size_t
jsonRespCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}


int8_t
sendCurlRequest(const char *url, const char *requestBody)
{

	std::string strJsonResponse;
	CURL *curl;
	CURLcode res;

	curl_global_init(CURL_GLOBAL_ALL);
	curl = curl_easy_init();

	if (curl) {

		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers,
				"Content-Type: application/json");
		headers = curl_slist_append(headers, "X-User-Name: YOUR_NAME");


		curl_easy_setopt(curl, CURLOPT_URL, url);

		curl_easy_setopt(curl, CURLOPT_USERAGENT, "legacy-admf-interface");

		/* Register Callback For Response */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jsonRespCallback);

		/* Pass Structure To Copy Data In Callback */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strJsonResponse);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBody);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(requestBody));

		/* Curl request timeout */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);

		res = curl_easy_perform(curl);

		LegacyAdmfInterface::log().debug("Response code: {}", res);
		LegacyAdmfInterface::log().debug("Response json: {}", strJsonResponse);

		if (res != CURLE_OK) {
			return RETURN_FAILURE;
		}

		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();

	return RETURN_SUCCESS;
}


std::string
prepareJsonForAdmf(admf_intfc_packet_t *packet)
{

	RAPIDJSON_NAMESPACE::Document jsonDoc;
	jsonDoc.SetObject();
	RAPIDJSON_NAMESPACE::Document::AllocatorType& allocator =
			jsonDoc.GetAllocator();

	RAPIDJSON_NAMESPACE::Value ackDoc(RAPIDJSON_NAMESPACE::kObjectType);
	ackDoc.SetObject();

	ackDoc.AddMember(SEQ_ID_KEY, packet->ue_entry_t.seqId, allocator);
	ackDoc.AddMember(IMSI_KEY, packet->ue_entry_t.imsi, allocator);
	ackDoc.AddMember(REQUEST_TYPE_KEY, packet->ue_entry_t.requestType, allocator);

	jsonDoc.AddMember(ACK_KEY, ackDoc, allocator);

	RAPIDJSON_NAMESPACE::StringBuffer strbuf;
	RAPIDJSON_NAMESPACE::Writer<RAPIDJSON_NAMESPACE::StringBuffer> writer(strbuf);
	jsonDoc.Accept(writer);

	return strbuf.GetString();

}


int8_t
LegacyAdmfInterface :: sendAckToAdmf(admf_intfc_packet_t *packet)
{

	std::string ackJson = prepareJsonForAdmf(packet);

	std::string strUrl = HTTP + std::string(inet_ntoa(intfc_config->admfIp))
			+ COLON + to_string(intfc_config->admfPort) + ACK_POST;

	LegacyAdmfInterface::log().info("Sending ACK to ADMF");
	LegacyAdmfInterface::log().debug("Url: {}", strUrl);
	LegacyAdmfInterface::log().debug("Request body: {}", ackJson);

	int8_t retValue = sendCurlRequest(strUrl.c_str(), ackJson.c_str());

	return retValue;

}

int8_t
LegacyAdmfInterface :: sendRequestToAdmf(uint16_t requestType, 
		const char *requestBody)
{

	std::string requestUri;
	if (requestType == ADD)
		requestUri.assign(ADD_URI);
	if (requestType == UPDATE)
		requestUri.assign(UPDATE_URI);
	if (requestType == DELETE)
		requestUri.assign(DELETE_URI);

	std::string strUrl = HTTP + std::string(inet_ntoa(intfc_config->admfIp))
			+ COLON + to_string(intfc_config->admfPort) + requestUri;

	LegacyAdmfInterface::log().info("Sending request to admf");
	LegacyAdmfInterface::log().debug("URI: {}", strUrl);
	LegacyAdmfInterface::log().debug("RequestBody: {}", requestBody);

	int8_t retValue = sendCurlRequest(strUrl.c_str(), requestBody);

	return retValue;

}


extern "C" BaseLegacyAdmfInterface* getInstance(void)
{
	return new LegacyAdmfInterface();
}

extern "C" void releaseInstance(BaseLegacyAdmfInterface *ptr)
{
	SAFE_DELETE_PTR(ptr);
}
