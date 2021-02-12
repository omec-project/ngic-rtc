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


#include "elogger.h"

#include "AdmfInterface.h"
#include "AdmfApp.h"

extern configurations_t config;

int AdmfInterface :: iRefCnt = ZERO;
AdmfInterface * AdmfInterface :: mpInstance = NULL;

AdmfInterface :: AdmfInterface (AdmfApplication &app, EGetOpt &opt) : 
				mApp (app), mOpt (opt)
{

}

AdmfInterface :: ~AdmfInterface ()
{
	mpLadmfEp -> shutdown();
	SAFE_DELETE(mpAddUeEntry);
	SAFE_DELETE(mpModUeEntry);
	SAFE_DELETE(mpDelUeEntry);
	SAFE_DELETE(mpAck);
	SAFE_DELETE(mpNotify);
	SAFE_DELETE(mpLadmfEp);
}


AdmfInterface * AdmfInterface :: getInstance(AdmfApplication &app, 
						EGetOpt &opt)
{
	if (mpInstance == NULL) {
		mpInstance = new AdmfInterface (app, opt);
	}

	++iRefCnt;
	return mpInstance;
}

void
AdmfInterface :: ReleaseInstance(void)
{
	--iRefCnt;

	if ((ZERO == iRefCnt) && (NULL != mpInstance)) {
		SAFE_DELETE(mpInstance);
	}
}

void
AdmfInterface :: admfInit ()
{
	mpLadmfEp = new EManagementEndpoint(config.admfPort);
 
	mpAddUeEntry = new AddUeEntryPost(ELogger::log(LOG_ADMF), mApp);
	mpLadmfEp -> registerHandler(*mpAddUeEntry);
    
	mpModUeEntry = new ModifyUeEntryPost(ELogger::log(LOG_ADMF), mApp);
	mpLadmfEp -> registerHandler(*mpModUeEntry);
    
	mpDelUeEntry = new DeleteUeEntryPost(ELogger::log(LOG_ADMF), mApp);
	mpLadmfEp -> registerHandler(*mpDelUeEntry);

	mpAck = new AcknowledgementPost(ELogger::log(LOG_ADMF), mApp);
	mpLadmfEp -> registerHandler(*mpAck);

	mpNotify = new UeNotificationPost(ELogger::log(LOG_ADMF), mApp);
	mpLadmfEp -> registerHandler(*mpNotify);

	mpLadmfEp -> start ();
}
