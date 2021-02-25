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
#include <locale>
#include <memory.h>
#include <signal.h>

#include "epc/epctools.h"
#include "epc/etevent.h"
#include "epc/esocket.h"
#include "epc/einternal.h"
#include "epc/emgmt.h"
#include "epc/etimerpool.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "UeTimer.h"
#include "DAdmf.h"
#include "Common.h"


EUeTimer::EUeTimer(const ue_data_t &ueDataTmp, uint8_t action) : 
			ueData(ueDataTmp), timerAction(action)
{
	timeToElapse = MILLISECONDS;
}


