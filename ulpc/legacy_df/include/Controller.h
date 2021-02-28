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

#ifndef __DF_CONTROLLER_
#define __DF_CONTROLLER_


#include "Common.h"
#include "TCPListener.h"


class Controller
{
		/*
		 *	@brief	:	Construstor of class Controller, initialises
		 *				object for TCPListener
		 */
		Controller();

		/*
		 *	@brief	:	Destructor of class Controller, destructs
		 *				object of TCPListener
		 */
		~Controller();

	public:

		/*
		 *	@brief	:	Function to get unique instance of class Controller
		 *	@param	:	No parameters
		 *	@return	:	Returns unique instance of class Controller
		 */
		static Controller * getInstance();

		/*
		 *	@brief	:	Function to release instance of class Controller
		 *	@param	:	No parameters
		 *	@return	:	Returns nothing
		 */
		void releaseInstance();

		/*
		 *	@brief	:	Function to delete listener object
		 *	@param	:	No parameters
		 *	@return	:	Returns nothing
		 */
		Void shutdown();

		/*
		 *	@brief	:	Function to create listener object
		 *	@param	:	No parameters
		 *	@return	:	Returns nothing
		 */
		Void startUp();

		/*
		 *	@brief	:	Function to set shutdown event
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void setShutdownEvent() {
			m_shutdown.set();
		}

		/*
		 *	@brief	:	Function waits for shutdown
		 *	@param	:	No function arguments
		 *	@return	:	Returns void
		 */
		Void waitForShutdown() {
			m_shutdown.wait();
		}

	private:
		EEvent m_shutdown;
		static uint8_t iRefCntr;
		TCPListener *listenerObject;
		static Controller *controller;
};


#endif /* __DF_CONTROLLER_ */
