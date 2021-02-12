/*
 * Copyright (c) 2020 Sprint
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include "Common.h"
#include "Controller.h"
#include "TCPListener.h"


uint8_t Controller :: iRefCntr = 0;
Controller * Controller :: controller = NULL;


Controller :: Controller()
{
}


Controller :: ~Controller()
{
}


Controller *
Controller :: getInstance()
{
	if (controller == NULL) {

		controller = new Controller();
		if (NULL == controller) {

			return NULL;
		}
	}

	++iRefCntr;
	return controller;
}


Void
Controller :: startUp(EGetOpt &opt, BaseLegacyInterface *legacyIntfc)
{
	try {

		listenerObject = new TCPListener;
		listenerObject->setIntfcPtr(legacyIntfc);
		listenerObject->init(1, 1, NULL, 100000);

	}
	catch (...) {

		ELogger::log(LOG_SYSTEM).startup("Exception initializing Application");
		return;
	}
}


Void
Controller :: shutdown()
{
	if (NULL != listenerObject) {

		listenerObject->quit();
		listenerObject->join();

		delete listenerObject;
		listenerObject = NULL;
	}
}

void
Controller :: releaseInstance()
{
	--iRefCntr;

	if ((iRefCntr == 0) && (controller != NULL)) {

		delete controller;
		controller = NULL;
	}
}

void ackFromLegacy (uint32_t ack_number) {
	/* this function will get called from legacyInterface.so */
	ELogger::log(LOG_SYSTEM).debug("Acknowledgement received from Legacy DF for sequence number {}", ack_number);

	Controller * dFController = Controller::getInstance();
	dFController->getListener()->msgCounter(ack_number);
}

void sockColseLegacy()
{
	Controller * dFController = Controller::getInstance();
	dFController->getListener()->checkSocket();
}

void sockConnLegacy()
{
	Controller * dFController = Controller::getInstance();

	dFController->getListener()->resetFlag();
	dFController->getListener()->setPending();
}
