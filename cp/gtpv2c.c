/*
 * Copyright (c) 2017 Intel Corporation
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


#include "ue.h"
#include "gtpv2c.h"
#include "interface.h"
#include "gtpv2c_ie.h"
#include "gtpv2c_set_ie.h"


in_port_t s11_port;
in_port_t s5s8_port;
struct sockaddr_in s11_sockaddr;
struct sockaddr_in s5s8_sockaddr;

uint8_t s11_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s11_tx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t pfcp_tx_buf[MAX_GTPV2C_UDP_LEN];

#ifdef USE_REST
/* ECHO PKTS HANDLING */
uint8_t echo_tx_buf[MAX_GTPV2C_UDP_LEN];
#endif /* USE_REST */


uint8_t s5s8_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s5s8_tx_buf[MAX_GTPV2C_UDP_LEN];

gtpv2c_ie *
get_first_ie(gtpv2c_header_t *gtpv2c_h)
{
	if (gtpv2c_h) {
		gtpv2c_ie *first_ie = IE_BEGIN(gtpv2c_h);
		if (NEXT_IE(first_ie) <= GTPV2C_IE_LIMIT(gtpv2c_h))
			return first_ie;
	}
	return NULL;
}


gtpv2c_ie *
get_next_ie(gtpv2c_ie *gtpv2c_ie_ptr, gtpv2c_ie *limit)
{
	if (gtpv2c_ie_ptr) {
		gtpv2c_ie *first_ie = NEXT_IE(gtpv2c_ie_ptr);
		if (NEXT_IE(first_ie) <= limit)
			return first_ie;
	}
	return NULL;
}

void
set_gtpv2c_header(gtpv2c_header_t *gtpv2c_tx,
				uint8_t teid_flag, uint8_t type,
				uint32_t has_teid, uint32_t seq)
{
	gtpv2c_tx->gtpc.version = GTP_VERSION_GTPV2C;
	gtpv2c_tx->gtpc.piggyback = 0;
	gtpv2c_tx->gtpc.message_type = type;
	gtpv2c_tx->gtpc.spare = 0;
	gtpv2c_tx->gtpc.teid_flag = teid_flag;

	if (teid_flag) {
	   gtpv2c_tx->teid.has_teid.teid = has_teid;
	   gtpv2c_tx->teid.has_teid.seq = seq;
	} else {
	   gtpv2c_tx->teid.no_teid.seq  = seq;
	}

	gtpv2c_tx->gtpc.message_len = teid_flag ?
			htons(sizeof(gtpv2c_tx->teid.has_teid)) :
			htons(sizeof(gtpv2c_tx->teid.no_teid));
}


void
set_gtpv2c_teid_header(gtpv2c_header_t *gtpv2c_tx, uint8_t type,
	uint32_t teid, uint32_t seq)
{
	/* Default set teid_flag = 1 */
	set_gtpv2c_header(gtpv2c_tx, 1, type, teid, seq);
}


void
set_gtpv2c_echo(gtpv2c_header_t *gtpv2c_tx,
			uint8_t teid_flag, uint8_t type,
			uint32_t teid, uint32_t seq)
{
	set_gtpv2c_header(gtpv2c_tx, teid_flag, type, teid, seq);
	set_recovery_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
}

