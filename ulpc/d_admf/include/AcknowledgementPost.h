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


#ifndef __ACK_POST_H_
#define __ACK_POST_H_


#include "emgmt.h"
#include "elogger.h"
#include "Common.h"


class AcknowledgementPost : public EManagementHandler
{
	public:
		AcknowledgementPost(ELogger &audit); 

		/**
                 * @brief  : Processes the acknowledgement from ADMF
                 * @param  : request, reference to request object
                 * @param  : response, reference to response object
                 * @return : Returns nothing
                 */
		virtual Void process(const Pistache::Http::Request& request,
				Pistache::Http::ResponseWriter &response);

		virtual ~AcknowledgementPost() {}

	private:
		AcknowledgementPost();

};


#endif /* __ACK_POST_H_ */
