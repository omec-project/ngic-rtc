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


#ifndef __ADMF_CONTROLLER_H_
#define __ADMF_CONTROLLER_H_

#include <iostream>
#include <memory>
#include <list>

#include "UeEntry.h"
#include "AdmfApp.h"


class UeEntry;
class DeleteEvent;
class AdmfApplication;


class AdmfController
{
	private:
		static int iRefCnt;
		static AdmfController *mpInstance;
		AdmfApplication &mApp;
		AdmfController(AdmfApplication &app);
        
	public:
		/**
                 * @brief  : Creates singleton object of AdmfController
		 * @param  : No param
		 * @return : Returns reference to singleton DAdmf object
		 */
		static AdmfController* getInstance(AdmfApplication &app);

		/**
		 * @brief  : Handles Add Ue Request. Forwards this request to D-ADMF
                             if request has not came from D-ADMF. Forwards
                             request to LegacyAdmfInterface if forward flag
                             is set to LI or both
		 * @param  : ueEntries, list of Ue entries parsed from request body object
		 * @param  : requestBody, request body received in the request
		 * @param  : dadmfRequestFlag, to identify it request has came from D-ADMF
		 */
		void addUeController(std::list <ue_data_t *> &ueEntries, 
					std::string &requestBody, 
					uint16_t requestSource);

		/**
		 * @brief  : Handles Update Ue Request. Forwards this request to D-ADMF
                             if request has not came from D-ADMF. Forwards
                             request to LegacyAdmfInterface if forward flag
                             is set to LI or both
		 * @param  : ueEntries, list of Ue entries parsed from request body object
		 * @param  : requestBody, request body received in the request
		 * @param  : dadmfRequestFlag, to identify it request has came from D-ADMF
		 */
		void modifyUeController(std::list <ue_data_t *> &ueEntries, 
					std::string &requestBody, 
					uint16_t requestSource);

		/**
		 * @brief  : Handles Delete Ue Request. Forwards this request to D-ADMF
                             if request has not came from D-ADMF. Forwards
                             request to LegacyAdmfInterface if forward flag
                             is set to LI or both
		 * @param  : ueEntries, list of Ue entries parsed from request body object
		 * @param  : requestBody, request body received in the request
		 * @param  : dadmfRequestFlag, to identify it request has came from D-ADMF
		 */
		void deleteUeController(std::list <delete_event_t *> &ueEntries, 
					std::string &requestBody, 
					uint16_t requestSource);

		/**
		 * @brief  : Handles start/stop notifications for Ue entries whose starttime
				or stoptime has been elapsed and forward flag is set.
		 * @param  : ueEntries, list of Ue entries parsed from request body object
		 * @param  : requestBody, request body received in the request
		 * @return : Returns nothing
		 */
		void notifyUeController(std::list<ue_notify_t *> &ueEntries,
                        		std::string &requestBody);

		/**
		 * @brief  : Decreases reference count. Deletes the object if reference 
				count becomes zero.
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void ReleaseInstance();

};

#endif /* __ADMF_CONTROLLER_H_ */
