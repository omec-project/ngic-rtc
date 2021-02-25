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

#ifndef __TCP_FORWARD_INTERFACE_H_
#define __TCP_FORWARD_INTERFACE_H_


#include "TCPListener.h"


class TCPListener;

class TCPForwardInterface : public ESocket::TCP::TalkerPrivate
{
	public:

		/*
		 *	@brief	:	Constructor of class TCPListener
		 */
		TCPForwardInterface(TCPListener &thread);

		/*
		 *	@brief	:	Constructor of class TCPListener
		 */
		virtual ~TCPForwardInterface();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onConnect();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onReceive();

		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onClose();
		/*
		 *	@brief	:	Library function of EPCTool
		 */
		Void onError();

		/*
		 *	@brief	:	Function to send data to DF
		 *	@param	:	df, packet/information to be sent to DF
		 *	@return	:	Returns void
		 */
		Void sendData(const DfPacket_t *df);

	private:
		/*
		 *	@brief	:	Constructor of class TCPListener
		 */
		TCPForwardInterface();
};


#endif /* __TCP_FORWARD_INTERFACE_H_ */
