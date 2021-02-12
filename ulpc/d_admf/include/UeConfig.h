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

#ifndef __UE_CONFIG_H_
#define __UE_CONFIG_H_


#include <map>

#include "Common.h"
#include "UeTimer.h"


#define UE_TMP_FILE			"database/uedb_tmp.csv"
#define SEQ_ID_ATTR			0
#define IMSI_ATTR			1
#define S11_ATTR			2
#define SGW_S5S8_C_ATTR			3
#define PGW_S5S8_C_ATTR			4
#define SX_ATTR				5
#define S1U_CONTENT_ATTR		6
#define SGW_S5S8U_CONTENT_ATTR		7
#define PGW_S5S8U_CONTENT_ATTR		8
#define SGI_CONTENT_ATTR		9
#define INTFC_CONFIG_ATTR		10
#define FORWARD_ATTR			11
#define START_TIME_ATTR			12
#define STOP_TIME_ATTR			13
#define ACK_RCVD_ATTR			14
#define	SIGNALLING_CONFIG_ATTR		15
#define DATA_CONFIG_ATTR		16
#define TIMER_ATTR			17

#define KEY				0
#define VALUE				1

class UeConfig
{
	protected:
		std::map<uint64_t, ue_data_t> mapUeConfig;
		std::map<uint64_t, EUeTimer*> mapStartUeTimers;
		std::map<uint64_t, EUeTimer*> mapStopUeTimers;
	public:
		UeConfig() {}

		virtual int8_t ReadUeConfig(void) = 0;
		/**
		 * @brief  : Virtual method. Extended class needs to implement this method
		 * @param  : uiAction, action can be add(1)/update(2)/delete(3)
		 * @param  : mod_ue_data, structure representing the Ue entry
		 * @return : Returns 0 in case of Success, -1 otherwise
		 */
		virtual int8_t UpdateUeConfig(uint8_t uiAction, 
				ue_data_t &modUeData) = 0;

		std::map<uint64_t, ue_data_t> &getMapUeConfig()
		{
			return mapUeConfig;
		}

		void setMapUeConfig(const std::map<uint64_t, ue_data_t> ueMap)
		{
			mapUeConfig = ueMap;
		}

		std::map<uint64_t, EUeTimer*> &getMapStartUeTimers()
		{
			return mapStartUeTimers;
		}

		void setMapStartUeTimers(const std::map<uint64_t, EUeTimer*> 
				startTimerMap)
		{
			mapStartUeTimers = startTimerMap;
		}

		std::map<uint64_t, EUeTimer*> &getMapStopUeTimers()
		{
			return mapStopUeTimers;
		}

		void setMapStopUeTimers(const std::map<uint64_t, EUeTimer*> 
				stopTimerMap)
		{
			mapStopUeTimers = stopTimerMap;
		}

		virtual ~UeConfig() {};
};

#endif /* __UE_CONFIG_H_ */
