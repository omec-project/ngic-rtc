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

#include "interface.h"
#include "udp/vepc_udp.h"
#include "dp_ipc_api.h"


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

/**
 * @brief Function to Process msgs.
 *
 */
int iface_remove_que(enum cp_dp_comm id)
{


#ifdef CP_BUILD
#ifdef ZMQ_COMM
	if (id == COMM_ZMQ) {
		int rc;

		rc = comm_node[id].recv((void *)&r_buf, sizeof(struct resp_msgbuf));

		if (rc <= 0)
			return rc;
		process_resp_msg((void *)&r_buf);
	}
#else
	RTE_SET_USED(id);

	if (comm_node[id].recv((void *)&rbuf,
				sizeof(struct msgbuf)) < 0) {
		perror("msgrecv");
		return -1;
	}

	process_comm_msg((void *)&rbuf);
#endif /* ZMQ_COMM */
#else
	if (comm_node[id].init == NULL)
		return 0;
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
#endif /*SDN_ODL_BUILD*/
#ifdef ZMQ_COMM
	if (id == COMM_ZMQ) {
		int rc;

		rc = comm_node[id].recv((void *)&rbuf, sizeof(struct msgbuf));

		if (rc <= 0)
			return rc;
		process_comm_msg((void *)&rbuf);
	}
#else
	if (id == COMM_SOCKET) {
		if (comm_node[id].recv((void *)&rbuf,
					sizeof(struct msgbuf)) < 0) {
			perror("msgrecv");
			return -1;
		}
		process_comm_msg((void *)&rbuf);
	}
#endif /* ZMQ_COMM */
#endif /*CP_BUILD*/

	return 0;
}


/**
 * @brief Function to Poll message que.
 *
 */
int iface_process_ipc_msgs(void)
{
	int ret = 0;
	int n, rv;
	fd_set readfds;
	struct timeval tv;

	/* clear the set ahead of time */
	FD_ZERO(&readfds);

	/* add our descriptors to the set */
	FD_SET(my_sock.sock_fd, &readfds);

	/* since we got s2 second, it's the "greater", so we use that
	 * for the n param in select()
	 */
	n = my_sock.sock_fd + 1;

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
	if (rv == -1)	{
		perror("select");	/* error occurred in select() */
	} else if (rv > 0) {
		/* one or both of the descriptors have data */
		if (FD_ISSET(my_sock.sock_fd, &readfds))
			ret = iface_remove_que(COMM_SOCKET);
	}
	return ret;
}

