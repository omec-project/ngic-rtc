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
#include "emgmt.h"
#include "esynch.h"
#include "epctools.h"
#include "DAdmf.h"

extern configurations_t config;

int DAdmfApp::iRefCntr = ZERO;
DAdmfApp* DAdmfApp::ptrInstance = NULL;

std::string
ConvertIpForRest(const std::string &strIp) {

	char buf[IPV6_MAX_LEN];
	std::string strRestFormat;

	if (inet_pton(AF_INET, (const char *)strIp.c_str(), buf)) {
		strRestFormat = strIp;
	} else if (inet_pton(AF_INET6, (const char *)strIp.c_str(), buf)) {
		strRestFormat = "[" + strIp + "]";
	}
	
	return strRestFormat;
}

size_t
jsonResponseCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

int8_t
sendCurlRequest(const std::string &strUrl, const std::string &strPostData)
{

	std::string strJsonResponse;

	CURL *curlHandle;
	CURLcode curlReturnCode;

	curl_global_init(CURL_GLOBAL_ALL);
	curlHandle = curl_easy_init();
	if (curlHandle) {

		struct curl_slist *curlHeaderParam = NULL;
		curlHeaderParam = curl_slist_append(curlHeaderParam, CONTENT_TYPE_JSON);
		curlHeaderParam = curl_slist_append(curlHeaderParam, X_USER_NAME);

		curl_easy_setopt(curlHandle, CURLOPT_URL, strUrl.c_str());

		/* Register Callback For Response */
		curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, jsonResponseCallback);

		/* Pass Structure To Copy Data In Callback */
		curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, &strJsonResponse);

		/* User Agent is Required For Some Servers */
		curl_easy_setopt(curlHandle, CURLOPT_USERAGENT, USER_AGENT);

		/* POST Request Parameters */
		curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDS, strPostData.c_str());

		/* Header Parameters */
		curl_easy_setopt(curlHandle, CURLOPT_HTTPHEADER, curlHeaderParam);

		curl_easy_setopt(curlHandle, CURLOPT_POSTFIELDSIZE, 
				(long)strlen(strPostData.c_str()));

		/* Curl request timeout */
		curl_easy_setopt(curlHandle, CURLOPT_TIMEOUT, 2L);


		/* Send Curl Request And It Returns Return Code */
		curlReturnCode = curl_easy_perform(curlHandle);

		if (curlReturnCode != CURLE_OK) {
			ELogger::log(LOG_SYSTEM).debug("Curl request send failed.");
			return RET_FAILURE;
		}

		ELogger::log(LOG_SYSTEM).debug("Response: {}", strJsonResponse);
		/* Cleanup */
		curl_slist_free_all(curlHeaderParam);
		curl_easy_cleanup(curlHandle);
	}

	curl_global_cleanup();

	return RET_SUCCESS;
}

DAdmfApp::DAdmfApp()
{
	ptrUeConfig = new UeConfigAsCSV(UECONFIGFILEPATH);
	ptrCpConfig = new CpConfigAsCSV(CPCONFIGFILEPATH);
}

DAdmfApp::~DAdmfApp()
{
	SAFE_DELETE(ptrUeConfig);
	SAFE_DELETE(ptrCpConfig);
}

DAdmfApp*
DAdmfApp::GetInstance(void)
{
	if (NULL == ptrInstance) {
		ptrInstance = new DAdmfApp();
	}

	++iRefCntr;
	return ptrInstance;
}

void
DAdmfApp::ReleaseInstance(void)
{
	--iRefCntr;

	if ((ZERO == iRefCntr) && (NULL != ptrInstance)) {
		SAFE_DELETE(ptrInstance);
	}
}

int8_t
DAdmfApp::SendRequestToAllCp(const std::string &strURI, 
		const std::string &strPostData)
{
	std::string strUrl, strJsonResponse;
	int8_t return_value = RET_FAILURE;
	uint8_t success_cnt = ZERO;

	ELogger::log(LOG_SYSTEM).info("Sending request to all CP's.");
	for (uint32_t uiCnt = ZERO; uiCnt < ptrCpConfig->getVecCpConfig().size(); 
			++uiCnt) {

		std::string strIp = ConvertIpForRest(ptrCpConfig->getVecCpConfig()[uiCnt]);
		strUrl = HTTP + strIp + ":12997/" + strURI;

		ELogger::log(LOG_SYSTEM).info("CP URI: {}", strUrl);
		return_value = sendCurlRequest(strUrl, strPostData);

		if (return_value == RET_SUCCESS)
			++success_cnt;
	}

	if (success_cnt == ZERO) {

		ELogger::log(LOG_SYSTEM).info("Request to all CP's failed");
		return RET_FAILURE;

	} else {

		if ((success_cnt > ZERO) &&
				(success_cnt < ptrCpConfig->getVecCpConfig().size())) {
			ELogger::log(LOG_SYSTEM).info("Request to some CP's passed. "
					"Some of them got failed");
		}

		return RET_SUCCESS;

	}
}

int8_t
DAdmfApp::SendRequestToAdmf(const std::string &strURI, 
		const std::string &strPostData)
{
	std::string strUrl;
	int8_t return_value;

	std::string strTemp = ConvertIpForRest(config.admfIp);
	strUrl = HTTP + strTemp + COLON +
			to_string(config.admfPort) + SLASH + strURI;

	ELogger::log(LOG_SYSTEM).info("Sending request to ADMF. URI: {}", strUrl);
	return_value = sendCurlRequest(strUrl, strPostData);

	return return_value;
}

int8_t
DAdmfApp::SendNotificationToAdmf(const std::string &strURI,
		const std::string &strPostData)
{
	std::string strUrl;
	int8_t return_value;

	std::string strIp = ConvertIpForRest(config.admfIp);
	strUrl = HTTP + strIp + COLON +
			to_string(config.admfPort) + SLASH + strURI;

	ELogger::log(LOG_SYSTEM).info("Sending notification to ADMF. URI:{}", strUrl);
	return_value = sendCurlRequest(strUrl, strPostData);

	return return_value;
}

void
DAdmfApp::startup(EGetOpt &opt)
{
	std::string dadmf_ip = ConvertIpForRest(config.dadmfIp);
	Pistache::Address addr(dadmf_ip, config.dadmfPort);
	mpCliPost = new EManagementEndpoint(addr);
	
	mpAddUeEntryPost = new AddUeEntryPost(ELogger::log(LOG_SYSTEM));
	mpCliPost->registerHandler(*mpAddUeEntryPost);

	mpUpdtUeEntryPost = new UpdateUeEntryPost(ELogger::log(LOG_SYSTEM));
	mpCliPost->registerHandler(*mpUpdtUeEntryPost);

	mpDelUeEntryPost = new DeleteUeEntryPost(ELogger::log(LOG_SYSTEM));
	mpCliPost->registerHandler(*mpDelUeEntryPost);

	mpRegisterCpPost = new RegisterCpPost(ELogger::log(LOG_SYSTEM));
	mpCliPost->registerHandler(*mpRegisterCpPost);

	mpAckPost = new AcknowledgementPost(ELogger::log(LOG_SYSTEM));
	mpCliPost->registerHandler(*mpAckPost);

	mpCliPost->start();
	ELogger::log(LOG_SYSTEM).info("Starting ACK_CHECKER timer with time ");
	
	/* Start a timer to check requests which has received ACK after every 
		certain interval of time and resend that request */
	ue_data_t ueData = {0};
	uint64_t time = config.ackCheckTimeInMin * SECONDS * MILLISECONDS;

	ELogger::log(LOG_SYSTEM).info("Starting ACK_CHECKER timer with time "
				"interval: {}", time);

	ackCheckTimer = new EThreadAckTimer();
	ackCheckTimer->setTimeToElapse(time);
	ackCheckTimer->init(1, 1, NULL, 2000);
	
	timerThread = new EThreadUeTimer();
	timerThread->init(1, 1, NULL, 2000);

	getPtrUeConfig()->ReadUeConfig();
}

void
DAdmfApp::shutdown()
{
	SAFE_DELETE(mpAddUeEntryPost);
	SAFE_DELETE(mpUpdtUeEntryPost);
	SAFE_DELETE(mpDelUeEntryPost);
	SAFE_DELETE(mpRegisterCpPost);
	SAFE_DELETE(mpAckPost);
	SAFE_DELETE(mpCliPost);

	timerThread->quit();
	SAFE_DELETE(timerThread);

	ackCheckTimer->quit();
	SAFE_DELETE(ackCheckTimer);
}

UeConfig*
DAdmfApp::getPtrUeConfig()
{
	return ptrUeConfig;
}

void
DAdmfApp::setPtrUeConfig(UeConfig* ueConfig)
{
	ptrUeConfig = ueConfig;
}

CpConfig*
DAdmfApp::getPtrCpConfig()
{
	return ptrCpConfig;
}

void
DAdmfApp::setPtrCpConfig(CpConfig* cpConfig)
{
	ptrCpConfig = cpConfig;
}

EThreadUeTimer*
DAdmfApp::getTimerThread()
{
	return timerThread;
}

void
DAdmfApp::lock()
{
	pthread_mutex_lock(&mLock);
}

void
DAdmfApp::unlock()
{
	pthread_mutex_unlock(&mLock);
}
