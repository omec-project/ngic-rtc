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

#include <rte_log.h>
#include <rte_common.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "ipv4.h"
#include "gtpv2c.h"
#include "util.h"

#include <rte_cfgfile.h>

#define GTPU_HDR_LEN   8
#define IPV4_HDR_LEN   20
#define ETH_HDR_LEN    14
#define UDP_HDR_LEN    8
#define IP_PROTO_UDP   17
#define UDP_PORT_GTPU  2152
#define GTPU_OFFSET    50

#define GTPu_VERSION	0x20
#define GTPu_PT_FLAG	0x10
#define GTPu_E_FLAG		0x04
#define GTPu_S_FLAG		0x02
#define GTPu_PN_FLAG	0x01

#define PKT_SIZE    54

#define CONN_ENTRIY_FILE "../config/static_arp.cfg"

//int32_t conn_cnt = 0;
//struct conn_ipv4_key conn_arr_keys[512] = {0};

typedef struct gtpuHdr_s {
	uint8_t version_flags;
	uint8_t msg_type;
	uint16_t tot_len;
	uint32_t teid;
	uint16_t seq_no;		/**< Optional fields if E, S or PN flags set */
} __attribute__((__packed__)) gtpuHdr_t;


/* GTPU-Recovery Information Element */
typedef struct gtpu_recovery_ie_t {
    uint8_t type;
    uint8_t restart_cntr;
} gtpu_recovery_ie;


static uint16_t gtpu_seqnb = 1;

/* Brief: Function to build GTP-U echo request
 * @ Input param: echo_pkt rte_mbuf pointer
 * @ Output param: none
 * Return: void
 */
void 
build_gtpv2_echo_request(gtpv2c_header *echo_pkt)
{
	//printf("Check : %u, sizeof:%lu", entry->port, sizeof(echo_pkt)); 

	//set_gtpv2c_echo(echo_pkt, gtpv2c_rx->gtpc.teidFlg, GTP_ECHO_REQ, 1, gtpu_seqnb);
	set_gtpv2c_echo(echo_pkt, 1, GTP_ECHO_REQ, 0, gtpu_seqnb);
	gtpu_seqnb++;
}
