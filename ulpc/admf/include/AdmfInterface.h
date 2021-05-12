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


#ifndef __ADMF_INTERFACE_H_
#define __ADMF_INTERFACE_H_

#include <iostream>

#include "AddUeEntry.h"
#include "ModifyUeEntry.h"
#include "DeleteUeEntry.h"
#include "AcknowledgementPost.h"
#include "UeNotification.h"

#define IPV6_MAX_LEN			16

#define SEQ_ID_KEY			"sequenceId"
#define IMSI_KEY			"imsi"
#define SIGNALLING_CONFIG_KEY		"signallingconfig"
#define S11_KEY				"s11"
#define SGW_S5S8_C_KEY			"sgw-s5s8c"
#define PGW_S5S8_C_KEY			"pgw-s5s8c"
#define GX_KEY				"gx"
#define SX_KEY				"sx"
#define SX_INTFC_KEY			"sxintfc"
#define CP_DP_TYPE_KEY			"type"
#define DATA_CONFIG_KEY			"dataconfig"
#define S1U_CONTENT_KEY			"s1u_content"
#define SGW_S5S8U_CONTENT_KEY		"sgw_s5s8u_content"
#define PGW_S5S8U_CONTENT_KEY		"pgw_s5s8u_content"
#define SGI_CONTENT_KEY			"sgi_content"
#define DATA_INTFC_CONFIG_KEY		"intfcconfig"
#define DATA_INTFC_NAME_KEY		"intfc"
#define DATA_DIRECTION_KEY		"direction"

#define FORWARD_KEY			"forward"
#define TIMER_KEY			"timer"
#define START_TIME_KEY			"starttime"
#define STOP_TIME_KEY			"stoptime"

#define REQUEST_SOURCE			"request_source"
#define UE_DB_KEY			"uedatabase"
#define ACK_KEY				"ack"
#define REQUEST_TYPE_KEY		"requestType"
#define NOTIFY_TYPE_KEY			"notifyType"


class AdmfApplication;

class AdmfInterface
{
	private:
		static int iRefCnt;
		static AdmfInterface *mpInstance;
		AdmfApplication &mApp;
		EGetOpt &mOpt;
		EManagementEndpoint *mpLadmfEp;
		AddUeEntryPost *mpAddUeEntry;
		ModifyUeEntryPost *mpModUeEntry;
		DeleteUeEntryPost *mpDelUeEntry;
		AcknowledgementPost *mpAck;
		UeNotificationPost *mpNotify;

		AdmfInterface(AdmfApplication &app, EGetOpt &opt);

	public:
		/**
		 * @brief  : Initializes all references for Add, Update, Delete rest requests
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void admfInit();

		/**
		 * @brief  : Creates singleton object of AdmfInterface
		 * @param  : app, reference to AdmfApplication object
		 * @param  : opt, reference to command-line parameter
		 */
		static AdmfInterface* getInstance(AdmfApplication &app,
							EGetOpt &opt);

		/**
		 * @brief  : Decreases reference count. Deletes the object if reference
				count becomes zero.
		 * @param  : No param
		 * @return : Returns nothing
		 */	
		void ReleaseInstance(void);

		~AdmfInterface();
};

#endif /* __ADMF_INTERFACE_H_ */
