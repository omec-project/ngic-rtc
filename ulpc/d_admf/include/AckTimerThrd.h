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


#ifndef __ACKTIMERTHRD_H_
#define __ACKTIMERTHRD_H_

#include "emgmt.h"
#include "etevent.h"
#include "elogger.h"

#include "Common.h"


class EThreadAckTimer : public EThreadPrivate
{
	public:
		EThreadAckTimer();

		/**
		 * @brief  : EpcTools callback function on timer object initialization
		 * @param  : No param
		 * @return : Returns nothing
		 */
		Void onInit(void);

		/**
		 * @brief  : EpcTools callback function on timer elapsed
		 * @param  : *pTimer, reference to timer object
		 * @return : Returns nothing
		 */
		Void onTimer(EThreadEventTimer *pTimer);

		/**
		 * @brief  : EpcTools callback function when timer quits
		 * @param  : No param
		 * @return : Returns nothing
		 */
		Void onQuit(void);

		void setTimeToElapse(const uint64_t time) {
			timeToElapse = time;
		}	

	private:
		uint64_t timeToElapse;
		EThreadEventTimer timer;
};

#endif /* __ACKTIMERTHRD_H_ */
