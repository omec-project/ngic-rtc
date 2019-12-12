/*Copyright (c) 2019 Sprint
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

#ifndef __SV_IES_DECODE_H__
#define __SV_IES_DECODE_H__
#include "sv_ies.h"
/**
* Decodes stn_sr to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    stn_sr
* @return
*   number of decoded bytes.
*/
int decode_gtp_stn_sr_ie(uint8_t *buf,
    gtp_stn_sr_ie_t *value);

#endif /*__GTP_IES_DECODE_H__*/