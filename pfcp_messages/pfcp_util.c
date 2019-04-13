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

#include <errno.h>
#include <stdbool.h>

#include <rte_debug.h>

#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "pfcp_set_ie.h"
#include "pfcp_messages.h"
#include "pfcp_util.h"

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

struct rte_hash *node_id_hash;
struct rte_hash *heartbeat_recovery_hash;
extern pfcp_context_t pfcp_ctxt;
struct rte_hash *associated_upf_hash;
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
void
get_upf_list(struct in_addr *p_upf_list)
{
	inet_aton("192.168.125.80",&p_upf_list[0]);
}

void
get_ava_ip( struct in_addr *upf_list)
{
	pfcp_ctxt.ava_ip = upf_list[0];
	pfcp_ctxt.flag_ava_ip = true;
	/*
	char cmd[100]= {0};
	for(int i=0;i<10;i++){
		sprintf(cmd,"ping -c1  %s -w 2 > /dev/null" ,inet_ntoa(upf_list[i]));
		if ( system((const char *)cmd) == 0)
		{
			//printf ("\nUPF_list [%d]: IP[%s] Exists",i,inet_ntoa(upf_list[i]));
			pfcp_ctxt.ava_ip = upf_list[i];
			pfcp_ctxt.flag_ava_ip = true;
			break;
		}
		else
		{
			//printf ("\nUPF_list [%d]: IP[%s] not reachable",i,inet_ntoa(upf_list[i]));
		}
	}
	*/
}

int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);

	uint32_t bytes = recvfrom(pfcp_sgwc_fd_arr[0], msg_payload, size, 0,
			(struct sockaddr *)peer_addr, &addr_len);
	return bytes;
}

int
pfcp_send(int fd,void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes = sendto(fd,
			(uint8_t *) msg_payload,
			size,
			MSG_DONTWAIT,
			(struct sockaddr *)peer_addr,
			addr_len);
	return bytes;
}

long 
uptime(void)
{
    struct sysinfo s_info;
    int error = sysinfo(&s_info);
    if(error != 0)
    {
        printf("code error in uptime = %d\n", error);
    }
    return s_info.uptime;
}

void 
create_node_id_hash(void)
{

	struct rte_hash_parameters rte_hash_params = {
		.name = "node_id_hash",
		.entries = LDB_ENTRIES_DEFAULT,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	node_id_hash = rte_hash_create(&rte_hash_params);
	if (!node_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void
create_associated_upf_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "associated_upf_hash",
		.entries = 50,
		.key_len = UINT32_SIZE,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	associated_upf_hash = rte_hash_create(&rte_hash_params);
	if (!associated_upf_hash) {
		rte_panic("%s Associated UPF hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

uint32_t
current_ntp_timestamp(void) {

	struct timeval tim;
	uint8_t ntp_time[8] = {0};
	uint32_t timestamp = 0;

	gettimeofday(&tim, NULL);
	time_to_ntp(&tim, ntp_time);

	timestamp |= ntp_time[0] << 24 | ntp_time[1] << 16 | ntp_time[2] << 8 | ntp_time[3];

	return timestamp;
}

void
time_to_ntp(struct timeval *tv, uint8_t *ntp)
{
	uint64_t ntp_tim = 0;
	uint8_t len = (uint8_t)sizeof(ntp)/sizeof(ntp[0]);
	uint8_t *p = ntp + len;

	int i = 0;

	ntp_tim = tv->tv_usec;
	ntp_tim <<= 32;
	ntp_tim /= 1000000;

	// we set the ntp in network byte order
	for (i = 0; i < len/2; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

	ntp_tim = tv->tv_sec;
	ntp_tim += OFFSET;

	// let's go with the fraction of second /
	for (; i < len; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

}
