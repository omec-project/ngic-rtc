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


#ifndef __DADMF_INTERFACE_H_
#define __DADMF_INTERFACE_H_

#include <iostream>

#include "AdmfApp.h"


#define HTTPS			"http://"
#define COLON			":"
#define ADD_UE_ENTRY		"/addueentry"
#define UPDATE_UE_ENTRY		"/updateueentry"
#define DELETE_UE_ENTRY		"/deleteueentry"
#define ACK_POST		"/ack"
#define NOTIFY_URI		"/notify"


class AdmfApplication;


class DAdmfInterface
{
	private: 
		static int iRefCnt;
		static DAdmfInterface *mpInstance;
		AdmfApplication &mApp;
		DAdmfInterface(AdmfApplication &app);
	public:
		~DAdmfInterface();

		/**
                 * @brief  : Creates singleton object of DAdmfInterface
                 * @param  : app, reference to AdmfApplication object
                 * @return : Returns reference to DAdmfInterface
                 */
		static DAdmfInterface* getInstance(AdmfApplication &app);

		/**
		 * @brief  : Sends curl request to D_ADMF url
		 * @param  : requestBody, request body to use in POST request
		 * @return : Returns 0 on success, -1 on error
		 */
		static int8_t sendRequest(const char *requestBody, const char *url);

		/**
		 * @brief  : Forms a request URL and calls method to send request to D_ADMF
      		 * @param  : requestUrl, url-suffix (addueentry, updateueentry, deleteueentry)
		 * @return : Returns 0 on success, -1 on error
		 */
		int8_t sendRequestToDadmf(const std::string &requestUrl,
					const std::string &requestBody);

		/**
		 * @brief  : Forms a request URL and calls method to send ACK to D_ADMF
		 * @param  : requestUrl, url-suffix (ack)
		 * @return : Returns 0 on Success, -1 on Error
		 */
		int8_t sendAckToDadmf(const std::string &requestUrl, 
					const std::string &requestBody);

		/**
		 * @brief  : Decreases reference count. Deletes the object if reference
				count becomes zero.
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void ReleaseInstance(void);
};


#endif /* __DADMF_INTERFACE_H_ */
