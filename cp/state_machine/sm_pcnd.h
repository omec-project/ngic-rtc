/*
 * Copyright (c) 2019 Sprint
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

#ifndef SM_PCND_H
#define SM_PCND_H

#include "sm_enum.h"
#include "sm_hand.h"
#include "sm_struct.h"
#include "pfcp_messages.h"
#include "gtp_messages.h"
#ifdef USE_DNS_QUERY
#include "pfcp_set_ie.h"
#endif /* USE_DNS_QUERY */

uint8_t
gtpv2c_pcnd_check(gtpv2c_header_t *gtpv2c_rx, int bytes_rx);

uint8_t
gtpc_pcnd_check(gtpv2c_header_t *gtpv2c_rx, msg_info *msg, int bytes_rx);

uint8_t
gtpc_s5s8_pcnd_check(gtpv2c_header_t *gtpv2c_rx, msg_info *msg, int bytes_rx);

uint8_t
pfcp_pcnd_check(uint8_t *pfcp_rx, msg_info *msg, int bytes_rx);

uint8_t
gx_pcnd_check(gx_msg *gx_rx, msg_info *msg);

#ifdef USE_DNS_QUERY
int
get_upf_ip(ue_context *ctxt, upfs_dnsres_t **_entry,
		uint32_t **upf_ip);

#endif /* USE_DNS_QUERY */
#endif
