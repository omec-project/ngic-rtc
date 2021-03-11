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

#ifndef __UE_ENTRY_H_
#define __UE_ENTRY_H_

#include <iostream>


/**
 * @brief  : Maintains data related to UE entry
 */
typedef struct ue_data {
	uint64_t			uiSeqIdentifier;
	uint64_t			uiImsi;
	int64_t				iTimeToStart;
	int64_t				iTimeToStop;
	uint16_t			uiS11;
	uint16_t			uiSgws5s8c;
	uint16_t			uiPgws5s8c;
	uint16_t			uiForward;
	uint16_t			s1uContent;
	uint16_t			sgwS5S8Content;
	uint16_t			pgwS5S8Content;
	uint16_t			sgiContent;
	uint16_t			ackReceived;
	std::string			strStartTime;
	std::string			strStopTime;
	std::map<uint16_t, uint16_t>	mapSxConfig;
	std::map<uint16_t, uint16_t>	mapIntfcConfig;
} ue_data_t;


typedef struct delete_event {
	uint64_t			uiSeqIdentifier;
	uint64_t			uiImsi;
} delete_event_t;


typedef struct UENotification {
	uint64_t			uiSeqIdentifier;
	uint64_t			uiImsi;
	uint16_t			notifyType;
	std::string			strStartTime;
	std::string			strStopTime;
} ue_notify_t;


typedef struct ack {
	uint64_t			uiSeqIdentifier;
	uint64_t			uiImsi;
	uint16_t			uiRequestType;
} ack_t;
#endif
