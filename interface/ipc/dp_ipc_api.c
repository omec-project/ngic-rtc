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

#include <stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_cfgfile.h>
#include <rte_errno.h>
#include <errno.h>

#include "../cp/cp.h"
#include "interface.h"
#include "udp/vepc_udp.h"
#include "dp_ipc_api.h"
#include "../../pfcp_messages/pfcp_util.h"

#ifdef CP_BUILD
#include "../cp/cp_app.h"
#include "../cp/cp_stats.h"
#include "../cp/cp_config.h"
#include "../cp/state_machine/sm_struct.h"
extern int g_cp_sock;
#endif /* CP_BUILD */


void iface_ipc_register_msg_cb(int msg_id,
				int (*msg_cb)(struct msgbuf *msg_payload))
{
	struct ipc_node *node;

	node = &basenode[msg_id];
	node->msg_id = msg_id;
	node->msg_cb = msg_cb;
}

/********************************** DP API ************************************/
void iface_init_ipc_node(void)
{
	basenode = rte_zmalloc("iface_ipc", sizeof(struct ipc_node) * MSG_END,
			RTE_CACHE_LINE_SIZE);
	if (basenode == NULL)
		exit(0);
}

#ifndef CP_BUILD
int
udp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);

	int bytes = recvfrom(my_sock.sock_fd, msg_payload, size, 0,
			(struct sockaddr *)peer_addr, &addr_len);
	/*if (bytes < size) {
		RTE_LOG_DP(ERR, DP, "Failed recv msg !!!\n");
		return -1;
	}*/
	return bytes;
}
#endif /* CP_BUILD */

/**
 * @brief Function to Process msgs.
 *
 */
int iface_remove_que(enum cp_dp_comm id)
{

#ifdef SDN_ODL_BUILD
	if (id == COMM_ZMQ) {
		int rc;
		struct zmqbuf zbuf = {0};

		rc = comm_node[id].recv((void *)&zbuf, sizeof(struct zmqbuf));

		rc = dp_lifecycle_process(&zbuf, rc);
		if (rc <= 0)
			return rc;
		return zmq_mbuf_process(&zbuf, rc);
	}
#else
	RTE_SET_USED(id);
	struct sockaddr_in peer_addr;
	int bytes_rx = 0;
#ifdef CP_BUILD
	if ((bytes_rx = pfcp_recv(pfcp_rx, 512,
			&peer_addr)) < 0) {
#else
	if ((bytes_rx = udp_recv(pfcp_rx, 512,
			&peer_addr)) < 0) {
#endif /* CP_BUILD*/
		perror("msgrecv");
		return -1;
	}
	process_pfcp_msg(pfcp_rx, &peer_addr);
#endif /*SDN_ODL_BUILD*/

	return 0;
}

/**
 * @brief Function to Poll message que.
 *
 */


void iface_process_ipc_msgs(void)
{
	int n, rv;
	fd_set readfds;
	struct timeval tv;
	struct sockaddr_in peer_addr;

	/* Clear the set ahead of time */
	FD_ZERO(&readfds);

	/* Setting Descriptors */
	FD_SET(my_sock.sock_fd, &readfds);

#ifdef CP_BUILD

	int max = 0;

	/* add s11 fd*/
	if ((spgw_cfg  == SGWC) || (spgw_cfg == SAEGWC)) {
		FD_SET(my_sock.sock_fd_s11, &readfds);
	}

	/*add s5s8 fd*/
	if (spgw_cfg != SAEGWC) {
		FD_SET(my_sock.sock_fd_s5s8, &readfds);
	}

	/*add gx fd*/
	if ((spgw_cfg == PGWC)) {
		FD_SET(g_cp_sock, &readfds);
	}

	if (spgw_cfg == SGWC) {
		max = (my_sock.sock_fd > my_sock.sock_fd_s11 ?
				my_sock.sock_fd : my_sock.sock_fd_s11);
		max = (max > my_sock.sock_fd_s5s8 ? max : my_sock.sock_fd_s5s8);
	}
	if (spgw_cfg == SAEGWC) {
		max = (my_sock.sock_fd > my_sock.sock_fd_s11 ?
				my_sock.sock_fd : my_sock.sock_fd_s11);
	}
	if (spgw_cfg == PGWC) {
		max = (my_sock.sock_fd > my_sock.sock_fd_s5s8 ?
				my_sock.sock_fd : my_sock.sock_fd_s5s8);
		max = (g_cp_sock > max ? g_cp_sock : max);

	}

	n = max + 1;
#else

	n = my_sock.sock_fd + 1;

#endif
	/* wait until either socket has data
	 *  ready to be recv()d (timeout 10.5 secs)
	 */
#ifdef NGCORE_SHRINK
	tv.tv_sec = 1;
	tv.tv_usec = 500000;
#else
	tv.tv_sec = 10;
	tv.tv_usec = 500000;
#endif
	rv = select(n, &readfds, NULL, NULL, &tv);
	if (rv == -1) {
		/*TODO: Need to Fix*/
		//perror("select"); /* error occurred in select() */
	} else if (rv > 0) {
		/* one or both of the descriptors have data */
		if (FD_ISSET(my_sock.sock_fd, &readfds))
				process_pfcp_msg(pfcp_rx, &peer_addr);
#ifdef CP_BUILD
		if ((spgw_cfg  == SGWC) || (spgw_cfg == SAEGWC)) {
			if (FD_ISSET(my_sock.sock_fd_s11, &readfds)) {
					msg_handler_s11();
			}
		}

		if (spgw_cfg != SAEGWC) {
			if (FD_ISSET(my_sock.sock_fd_s5s8, &readfds)) {
					msg_handler_s5s8();
			}
		}

		if ((spgw_cfg == PGWC)) {
			if (FD_ISSET(g_cp_sock, &readfds))
					msg_handler(g_cp_sock);
		}
#endif

	}
}

