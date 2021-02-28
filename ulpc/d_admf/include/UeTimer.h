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


#ifndef __UETIMER_H_
#define __UETIMER_H_

#include "emgmt.h"
#include "etevent.h"
#include "elogger.h"

#include "Common.h"


class EUeTimer
{
	public:
		EUeTimer(const ue_data_t &ueData, uint8_t action);

		/**
                 * @brief  : Getter method to fetch request body
                 * @param  : No param
                 * @return : Returns strJsonRequest if it is set, empty string otherwise
                 */
		std::string getStrJsonRequest() { return strJsonRequest; }

		/**
		 * @brief  : Setter method to set request body
		 * @param  : request, request body received with request
		 * @return : Returns nothing
		 */
		void setStrJsonRequest(const std::string &request)
		{ strJsonRequest = request; }


		uint64_t getTimeToElapse() { return timeToElapse; }

		void setTimeToElapse(const uint64_t time)
		{ timeToElapse = time; }	

		EThreadEventTimer& getTimer() {
			return timer;
		}

		ue_data_t getUeData() {
			return ueData;
		}

		uint64_t getTimerAction() {
			return timerAction;
		}

	private:
		ue_data_t ueData;
		uint8_t timerAction;
		std::string strJsonRequest;
		uint64_t timeToElapse;
		EThreadEventTimer timer;
};

#endif /* __UETIMER_H_ */
