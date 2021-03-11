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


#ifndef __D_ADMF_H_
#define __D_ADMF_H_

#include <iostream>
#include <pthread.h>

#include "epc/etevent.h"
#include "epc/epctools.h"

#include "UeConfigAsCSV.h"
#include "CpConfigAsCSV.h"
#include "AddUeEntry.h"
#include "UpdateUeEntry.h"
#include "DeleteUeEntry.h"
#include "RegisterCp.h"
#include "AcknowledgementPost.h"
#include "UeTimerThrd.h"
#include "AckTimerThrd.h"

#define IPV6_MAX_LEN			16

#define UECONFIGFILEPATH		"database/uedb.csv"
#define CPCONFIGFILEPATH		"database/cpdb.csv"

class DAdmfApp
{
	static int iRefCntr;
	static DAdmfApp *ptrInstance;
	pthread_mutex_t mLock;

	public:
                /**
		 * @brief  : Creates singleton object of DAdmfApp and increment 
                             the reference count
		 * @param  : No param
		 * @return : Returns reference to singleton DAdmf object
		 */
		static DAdmfApp* GetInstance(void);

		/**
		 * @brief  : Releases DAdmf singleton object if reference count is zero
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void ReleaseInstance(void);

                /**
		 * @brief  : Sends Add, Update, Delete Ue Entry To All CP's
		 * @param  : strURI, url suffix (addueentry, updateueentry, deleteueentry)
		 * @param  : strPostData, request body to send
		 * @return : Returns 0 in case of Success, -1 otherwise
		 */
		int8_t SendRequestToAllCp(const std::string &strURI, 
				const std::string &strPostData);
		
		/**
		 * @brief  : Sends Add, Update, Delete Ue Entry to Admf if forward flag 
                             is set fo LI(1) or Both(2)
		 * @param  : strURI, url suffix (addueentry, updateueentry, deleteueentry)
		 * @param  : strPostData, request body to send
		 * @return : Returns 0 in case of Success, -1 otherwise
		 */
		int8_t SendRequestToAdmf(const std::string &strURI, 
				const std::string &strPostData);

		/**
		 * @brief  : Sends notification to admf when start time for Ue entry elapses.
		 * @param  : strURI, url suffix (start, stop)
		 * @param  : strPostData, request body to send
		 * @return : Returns 0 in case of Success, -1 otherwise
		 */
		int8_t SendNotificationToAdmf(const std::string &strURI,
				const std::string &strPostData);

		/**
		 * @brief  : Initializes all required objects
		 * @param  : opt, command-line parameter
		 * @return : Returns nothing
		 */
		void startup(EGetOpt &opt);

		/**
		 * @brief  : Deletes all the initialized objects before exiting the process
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void shutdown();

		/**
		 * @brief  : Sets shutdown event of EpcTools on handling the signal
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void setShutdownEvent(void)
		{
			mShutdown.set();
		}

		/**
		 * @brief  : Waits until process is killed or shutdown event is set
		 * @param  : No param
		 * @return : Returns nothing
		 */
		void waitForShutdown(void) { mShutdown.wait(); }

		UeConfig* getPtrUeConfig();

		void setPtrUeConfig(UeConfig* ueConfig);

		CpConfig* getPtrCpConfig();

		void setPtrCpConfig(CpConfig* cpConfig);

		EThreadUeTimer* getTimerThread();
		void lock();

		void unlock();

		~DAdmfApp();

	private:
		EEvent mShutdown;
		DAdmfApp();
		UeConfig *ptrUeConfig;
		CpConfig *ptrCpConfig;
		AddUeEntryPost *mpAddUeEntryPost;
		UpdateUeEntryPost *mpUpdtUeEntryPost;
		DeleteUeEntryPost *mpDelUeEntryPost;
		RegisterCpPost *mpRegisterCpPost;
		AcknowledgementPost *mpAckPost;
		EManagementEndpoint *mpCliPost;
		EThreadAckTimer *ackCheckTimer;
		EThreadUeTimer *timerThread;
};

#endif /* __D_ADMF_H_ */
