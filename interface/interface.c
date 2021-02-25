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
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>

#include "util.h"
#include "interface.h"
#include "dp_ipc_api.h"
#include "clogger.h"

#ifndef CP_BUILD
#include "up_acl.h"
#else
#include "gtpv2c.h"
#include "ipc_api.h"

extern uint8_t recovery_flag;
extern int gx_app_sock;
extern int gx_app_sock_read;
extern int msg_handler_gx( void );
#endif /* CP_BUILD */

/*
 * UDP Setup
 */
udp_sock_t my_sock = {0};

/* VS: ROUTE DISCOVERY */
extern int route_sock;


struct in_addr dp_comm_ip;
struct in_addr cp_comm_ip;
uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
extern void print_perf_statistics(void);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

extern struct ipc_node *basenode;
extern struct rte_hash *heartbeat_recovery_hash;

struct rte_hash *node_id_hash;

#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) ((1==ntohl(1)) ? (x) : ((uint64_t)ntohl((x) & 0xFFFFFFFF) << 32) | ntohl((x) >> 32))

#define IFACE_FILE "../config/interface.cfg"
#define SET_CONFIG_IP(ip, file, section, entry) \
do {\
	entry = rte_cfgfile_get_entry(file, section, #ip);\
	if (entry == NULL)\
	rte_panic("%s not found in %s", #ip, IFACE_FILE);\
	if (inet_aton(entry, &ip) == 0)\
	rte_panic("Invalid %s in %s", #ip, IFACE_FILE);\
} while (0)
#define SET_CONFIG_PORT(port, file, section, entry) \
do {\
	entry = rte_cfgfile_get_entry(file, section, #port);\
	if (entry == NULL)\
	rte_panic("%s not found in %s", #port, IFACE_FILE);\
	if (sscanf(entry, "%"SCNu16, &port) != 1)\
	rte_panic("Invalid %s in %s", #port, IFACE_FILE);\
} while (0)

/**
 * @brief : API to create udp socket.
 * @param : recv_ip,
 * @param : recv_port,
 * @param : sock,
 */
static int create_udp_socket(struct in_addr recv_ip, uint16_t recv_port,
		udp_sock_t *sock)
{
	sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock->sock_fd == -1) {
		perror("socket error: ");
		close(sock->sock_fd);
		return -1;
	}

	memset(&sock->my_addr, 0x0, sizeof(struct sockaddr_in));
	sock->my_addr.sin_family = AF_INET;
	sock->my_addr.sin_port = htons(recv_port);
	sock->my_addr.sin_addr.s_addr = htonl(recv_ip.s_addr);
	if (bind(sock->sock_fd, (struct sockaddr *)&sock->my_addr,
			sizeof(struct sockaddr_in)) == -1)
		return -1;

	return 0;
}

int
udp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);

	int bytes = recvfrom(my_sock.sock_fd, msg_payload, size, 0,
			(struct sockaddr *)peer_addr, &addr_len);
	return bytes;
}

/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{

		clLog(clSystemLog, eCLSeverityMajor,LOG_FORMAT"IFACE: DP Initialization\n", LOG_VALUE);
		create_udp_socket(dp_comm_ip, dp_comm_port, &my_sock);
		clLog(clSystemLog, eCLSeverityMajor, "Data-Plane IFACE Initialization Complete\n");
}

#ifdef CP_BUILD
void process_cp_msgs(void)
{
	int max = 0;
	int n = 0, rv = 0;
	fd_set readfds = {0};
	struct sockaddr_in peer_addr = {0};

	/* Reset Collections */
	FD_ZERO(&readfds);

	/* Add PFCP_FD in the set */
	FD_SET(my_sock.sock_fd, &readfds);

	/* Add S11_FD in the set */
	if (pfcp_config.cp_type != PGWC) {
		FD_SET(my_sock.sock_fd_s11, &readfds);
	}

	/* Add S5S8_FD in the set */
	FD_SET(my_sock.sock_fd_s5s8, &readfds);

	/* Add GX_FD in the set */
	if ((pfcp_config.use_gx) && pfcp_config.cp_type != SGWC) {
		FD_SET(gx_app_sock_read, &readfds);
	}

	/* Set the MAX FD's stored into the set */
	max = my_sock.sock_fd;
	max = (my_sock.sock_fd_s11 > max ? my_sock.sock_fd_s11: max);
	max = (my_sock.sock_fd_s5s8 > max ? my_sock.sock_fd_s5s8: max);

	if ((pfcp_config.use_gx) && pfcp_config.cp_type != SGWC) {
		max = (gx_app_sock_read > max ? gx_app_sock_read : max);
	}

	n = max + 1;

	rv = select(n, &readfds, NULL, NULL, NULL);
	if (rv == -1) {
		/*TODO: Need to Fix*/
		//perror("select"); /* error occurred in select() */
	} else if (rv > 0) {
		/* when recovery mode is initiate, only pfcp message we handle, and other msg is in socket queue */
		if (recovery_flag == 1) {
			if (FD_ISSET(my_sock.sock_fd, &readfds)) {
					process_pfcp_msg(pfcp_rx, &peer_addr);
			} else {
				return;
			}
		}


		if ((pfcp_config.use_gx) && pfcp_config.cp_type != SGWC &&
			(FD_ISSET(gx_app_sock_read, &readfds))) {
					msg_handler_gx();
		}

		if (FD_ISSET(my_sock.sock_fd, &readfds)) {
			process_pfcp_msg(pfcp_rx, &peer_addr);
		}
		if (pfcp_config.cp_type != PGWC) {
			if (FD_ISSET(my_sock.sock_fd_s11, &readfds)) {
					msg_handler_s11();
			}
		}

		if (FD_ISSET(my_sock.sock_fd_s5s8, &readfds)) {
				msg_handler_s5s8();
		}
	}
}
#else /*End of CP_BUILD*/

void process_dp_msgs(void) {

	int n = 0, rv = 0;
	fd_set readfds = {0};
	struct sockaddr_in peer_addr = {0};

	FD_ZERO(&readfds);

	/* Add PFCP_FD in the set */
	FD_SET(my_sock.sock_fd, &readfds);

	n = my_sock.sock_fd + 1;

	rv = select(n, &readfds, NULL, NULL, NULL);
	if (rv == -1) {
		/*TODO: Need to Fix*/
		//perror("select"); /* error occurred in select() */
	} else if (rv > 0) {
		/* one or both of the descriptors have data */
		if (FD_ISSET(my_sock.sock_fd, &readfds))
				process_pfcp_msg(pfcp_rx, &peer_addr);

	}
}
#endif /*DP_BUILD*/
