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


#ifndef __ADD_UE_ENTRY_H_
#define __ADD_UE_ENTRY_H_


#include <string>
#include <iostream>

#include "emgmt.h"

class AdmfApplication;

class AddUeEntryPost : public EManagementHandler
{
	public:
		AddUeEntryPost(ELogger &audit, AdmfApplication &app); 
		AdmfApplication &mApp;

		/**
		 * @brief  : Processes the addUeEntry rest request on admf
		 * @param  : request, reference to request object
		 * @param  : response, reference to response object
		 * @return : Returns nothing
		 */
		virtual Void process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response);

		virtual ~AddUeEntryPost() {}

	private:
		AddUeEntryPost();

};


#endif /* __ADD_UE_ENTRY_H_ */
