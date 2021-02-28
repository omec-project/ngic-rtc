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


#ifndef __UETIMERTHRD_H_
#define __UETIMERTHRD_H_

#include "emgmt.h"
#include "etevent.h"
#include "elogger.h"

#include "Common.h"


class EThreadUeTimer : public EThreadPrivate
{
	public:
		EThreadUeTimer();
		
		/**
		 * @brief  : EpcTools callback function on timer elapsed
		 * @param  : *pTimer, reference to timer object
		 * @return : Returns nothing
		 */
		Void onTimer(EThreadEventTimer *pTimer);
	
		Void InitTimer(EUeTimer &timer);
	private:
		std::map <uint32_t, EUeTimer *> mapUeTimers;
};

#endif /* __UETIMERTHRD_H_ */
