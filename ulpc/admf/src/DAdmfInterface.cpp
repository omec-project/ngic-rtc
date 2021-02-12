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


#include <curl/curl.h>

#include "elogger.h"

#include "UeEntry.h"
#include "AdmfApp.h"
#include "DAdmfInterface.h"


extern configurations_t config;

int DAdmfInterface :: iRefCnt = ZERO;
DAdmfInterface *DAdmfInterface :: mpInstance = NULL;

DAdmfInterface :: DAdmfInterface (AdmfApplication &app) : mApp(app)
{
	// private constructor as this class is Singleton
}

DAdmfInterface :: ~DAdmfInterface ()
{
}

DAdmfInterface * DAdmfInterface :: getInstance(AdmfApplication &app)
{
	if (mpInstance == NULL) {
		mpInstance = new DAdmfInterface (app);
	}

	++iRefCnt;
	return mpInstance;
}

void
DAdmfInterface :: ReleaseInstance(void)
{
	--iRefCnt;

	if((ZERO == iRefCnt) && (NULL != mpInstance)) {
		SAFE_DELETE(mpInstance);
	}
}

size_t
jsonResponseCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
}

int8_t
DAdmfInterface :: sendRequest (const char *requestBody, const char *url)
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

		curl_easy_setopt(curl, CURLOPT_USERAGENT, "admf");

		/* Register Callback For Response */
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, jsonResponseCallback);

		/* Pass Structure To Copy Data In Callback */
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &strJsonResponse);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, requestBody);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(requestBody));

		/* Curl request timeout */
		curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2L);

		res = curl_easy_perform(curl);

		if (res != CURLE_OK) {
			ELogger::log(LOG_ADMF).debug("Curl request failed.");
			return RET_FAILURE;
		}

		ELogger::log(LOG_ADMF).debug("Response: {}", strJsonResponse);
		curl_slist_free_all(headers);
		curl_easy_cleanup(curl);
	}
	curl_global_cleanup();

	return RET_SUCCESS;
}

int8_t
DAdmfInterface :: sendRequestToDadmf(const std::string &requestUrl, 
					const std::string &requestBody)
{
	ELogger :: log(LOG_ADMF).debug("[{}->{}:{}] Json Request = {} ", 
				__file__, __FUNCTION__, __LINE__, requestBody);

	int8_t returnValue = RET_FAILURE;
	std::string dAdmfUrl(HTTPS);
	dAdmfUrl = dAdmfUrl + std::string(inet_ntoa(config.dadmfIp)) + COLON;
	dAdmfUrl = dAdmfUrl + to_string(config.dadmfPort);
	dAdmfUrl = dAdmfUrl + requestUrl;
	ELogger::log(LOG_ADMF).info("Sending curl request to D_ADMF: {}", dAdmfUrl);
	returnValue = sendRequest(requestBody.c_str(), dAdmfUrl.c_str());

	return returnValue;
}

int8_t
DAdmfInterface :: sendAckToDadmf(const std::string &requestUrl,
					const std::string &requestBody)
{
	ELogger :: log(LOG_ADMF).debug("[{}->{}:{}] Ack Request = {} ",
				__file__, __FUNCTION__, __LINE__, requestBody);

	int8_t returnValue = RET_FAILURE;
	std::string dAdmfUrl(HTTPS);
	dAdmfUrl = dAdmfUrl + std::string(inet_ntoa(config.dadmfIp)) + COLON;
	dAdmfUrl = dAdmfUrl + to_string(config.dadmfPort);
	dAdmfUrl = dAdmfUrl + requestUrl;

	ELogger::log(LOG_ADMF).info("Sending ack to D_ADMF: {}", dAdmfUrl);
	returnValue = sendRequest(requestBody.c_str(), dAdmfUrl.c_str());

	return returnValue;
}
