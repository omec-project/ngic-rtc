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


#include "LegacyAdmfInterfaceListener.h"

LegacyAdmfInterfaceListener :: 
LegacyAdmfInterfaceListener(LegacyAdmfInterfaceThread &thread)
	:	ESocket::TCP::ListenerPrivate(thread)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceListener constructor");
}

LegacyAdmfInterfaceListener ::
~LegacyAdmfInterfaceListener()
{
}

ESocket::TCP::TalkerPrivate
*LegacyAdmfInterfaceListener :: createSocket(ESocket::ThreadPrivate &thread)
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceListener :: createSocket");
	return ((LegacyAdmfInterfaceThread&)thread).createLegacyAdmfTalker();
}

Void
LegacyAdmfInterfaceListener :: onClose()
{
	LegacyAdmfInterface::log().debug("LegacyAdmfInterfaceListener :: onClose()");
}

Void
LegacyAdmfInterfaceListener :: onError()
{
	LegacyAdmfInterface::log().debug("Error occurred in LegacyAdmfInterfaceListener");
}
