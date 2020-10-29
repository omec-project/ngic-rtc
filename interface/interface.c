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
#include "gw_adapter.h"
#ifndef CP_BUILD
#include "up_acl.h"
#else
#include "gtpv2c.h"
#include "ipc_api.h"

extern pfcp_config_t config;
extern uint8_t recovery_flag;
extern int gx_app_sock;
extern int gx_app_sock_v6;

extern int gx_app_sock_read;
extern int gx_app_sock_read_v6;
extern int msg_handler_gx( void );
#endif /* CP_BUILD */

/*
 * UDP Setup
 */
udp_sock_t my_sock = {0};

/* ROUTE DISCOVERY */
extern int route_sock;
extern int clSystemLog;
struct in_addr dp_comm_ip;
struct in6_addr dp_comm_ipv6;
uint8_t dp_comm_ip_type;
peer_addr_t up_pfcp_sockaddr;

struct in_addr cp_comm_ip;
struct in6_addr cp_comm_ip_v6;
uint8_t cp_comm_ip_type;
peer_addr_t cp_pfcp_sockaddr;

uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
extern void print_perf_statistics(void);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

extern struct ipc_node *basenode;
extern struct rte_hash *heartbeat_recovery_hash;

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
 * @param : dp_comm_ipv4,
 * @param : dp_comm_ipv6,
 * @param : dp_comm_ip_type,
 * @param : recv_port,
 * @param : sock,
 */
static int create_udp_socket(struct in_addr dp_comm_ipv4, struct in6_addr dp_comm_ipv6,
				uint8_t dp_comm_ip_type, uint16_t recv_port, udp_sock_t *sock)
{
	dp_comm_port = htons(recv_port);

	if (dp_comm_ip_type == PDN_TYPE_IPV6 || dp_comm_ip_type == PDN_TYPE_IPV4_IPV6) {


		int mode = 1, ret = 0;
		socklen_t v6_addr_len = sizeof(up_pfcp_sockaddr.ipv6);

		sock->sock_fd_v6 = socket(AF_INET6, SOCK_DGRAM, 0);

		if (sock->sock_fd_v6 < 0) {
			rte_panic("Socket call error : %s", strerror(errno));
			return -1;
		}

		/*Below Option allows to bind to same port for multiple IPv6 addresses*/
		setsockopt(sock->sock_fd_v6, SOL_SOCKET, SO_REUSEPORT, &mode, sizeof(mode));

		/*Below Option allows to bind to same port for IPv4 and IPv6 addresses*/
		setsockopt(sock->sock_fd_v6, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&mode, sizeof(mode));

		up_pfcp_sockaddr.ipv6.sin6_family = AF_INET6;
		inet_pton(AF_INET6, (char *)dp_comm_ipv6.s6_addr,
							up_pfcp_sockaddr.ipv6.sin6_addr.s6_addr);
		up_pfcp_sockaddr.ipv6.sin6_port = dp_comm_port;

		ret = bind(sock->sock_fd_v6, (struct sockaddr *) &up_pfcp_sockaddr.ipv6, v6_addr_len);
		if (ret < 0) {
			rte_panic("Bind error for V6 UDP socket : %s\n",
				strerror(errno));
			return -1;
		}

		up_pfcp_sockaddr.type = PDN_TYPE_IPV6;


	}

	if (dp_comm_ip_type == PDN_TYPE_IPV4 || dp_comm_ip_type == PDN_TYPE_IPV4_IPV6) {

		int mode = 1;
		sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);

		socklen_t v4_addr_len = sizeof(up_pfcp_sockaddr.ipv4);

		if (sock->sock_fd < 0) {
			rte_panic("Socket call error : %s", strerror(errno));
			return -1;
		}

		/*Below Option allows to bind to same port for multiple IPv6 addresses*/
		setsockopt(sock->sock_fd, SOL_SOCKET, SO_REUSEPORT, &mode, sizeof(mode));

		bzero(up_pfcp_sockaddr.ipv4.sin_zero, sizeof(up_pfcp_sockaddr.ipv4.sin_zero));

		up_pfcp_sockaddr.ipv4.sin_family = AF_INET;
		up_pfcp_sockaddr.ipv4.sin_port = dp_comm_port;
		up_pfcp_sockaddr.ipv4.sin_addr.s_addr = dp_comm_ipv4.s_addr;

		int ret = bind(sock->sock_fd, (struct sockaddr *) &up_pfcp_sockaddr.ipv4, v4_addr_len);
		if (ret < 0) {
			rte_panic("Bind error for V4 UDP Socket %s:%u - %s\n",
				inet_ntoa(up_pfcp_sockaddr.ipv4.sin_addr),
				ntohs(up_pfcp_sockaddr.ipv4.sin_port),
				strerror(errno));
			return -1;
		}

		up_pfcp_sockaddr.type = PDN_TYPE_IPV4;

	}

	return 0;
}

int
udp_recv(void *msg_payload, uint32_t size, peer_addr_t *peer_addr, bool is_ipv6)
{
	socklen_t v4_addr_len = sizeof(peer_addr->ipv4);
	socklen_t v6_addr_len = sizeof(peer_addr->ipv6);

	int bytes = 0;

	if (!is_ipv6) {

		bytes = recvfrom(my_sock.sock_fd, msg_payload, size,
					MSG_DONTWAIT, (struct sockaddr *) &peer_addr->ipv4,
					&v4_addr_len);

		peer_addr->type |= PDN_TYPE_IPV4;
		clLog(clSystemLog, eCLSeverityDebug, "pfcp received bytes "
				"with IPv4 Address");

	} else {

		bytes = recvfrom(my_sock.sock_fd_v6, msg_payload, size,
						MSG_DONTWAIT, (struct sockaddr *) &peer_addr->ipv6,
						&v6_addr_len);

		peer_addr->type |= PDN_TYPE_IPV6;
		clLog(clSystemLog, eCLSeverityDebug, "pfcp received bytes "
				"with IPv6 Address");

	}

	if (bytes == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Error while recieving from "
			"PFCP socket");
	}

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
		create_udp_socket(dp_comm_ip, dp_comm_ipv6, dp_comm_ip_type, dp_comm_port, &my_sock);
		clLog(clSystemLog, eCLSeverityMajor, "Data-Plane IFACE Initialization Complete\n");
}

#ifdef CP_BUILD
void process_cp_msgs(void)
{
	int max = 0;
	int n = 0, rv = 0;
	fd_set readfds = {0};
	peer_addr_t peer_addr = {0};

	/* Reset Collections */
	FD_ZERO(&readfds);

	/* Add PFCP_FD in the set */
	if(my_sock.sock_fd > 0)
		FD_SET(my_sock.sock_fd, &readfds);
	if(my_sock.sock_fd_v6 > 0)
		FD_SET(my_sock.sock_fd_v6, &readfds);

	/* Add S11_FD in the set */
	if (config.cp_type != PGWC) {
		if(my_sock.sock_fd_s11 > 0)
			FD_SET(my_sock.sock_fd_s11, &readfds);
		if(my_sock.sock_fd_s11_v6 > 0)
			FD_SET(my_sock.sock_fd_s11_v6, &readfds);
	}

	/* Add S5S8_FD in the set */
	if(my_sock.sock_fd_s5s8 > 0)
		FD_SET(my_sock.sock_fd_s5s8, &readfds);
	if(my_sock.sock_fd_s5s8_v6 > 0)
		FD_SET(my_sock.sock_fd_s5s8_v6, &readfds);

	/* Add GX_FD in the set */
	if ((config.use_gx) && config.cp_type != SGWC) {
		if(gx_app_sock_read > 0)
			FD_SET(gx_app_sock_read, &readfds);
	}

	/* Set the MAX FD's stored into the set */
	max = my_sock.sock_fd;
	max = (my_sock.sock_fd_v6 > max ? my_sock.sock_fd_v6: max);
	max = (my_sock.sock_fd_s11 > max ? my_sock.sock_fd_s11: max);
	max = (my_sock.sock_fd_s11_v6 > max ? my_sock.sock_fd_s11_v6: max);
	max = (my_sock.sock_fd_s5s8 > max ? my_sock.sock_fd_s5s8: max);
	max = (my_sock.sock_fd_s5s8_v6 > max ? my_sock.sock_fd_s5s8_v6: max);

	if ((config.use_gx) && config.cp_type != SGWC) {
		max = (gx_app_sock_read > max ? gx_app_sock_read : max);
		max = (gx_app_sock_read_v6 > max ? gx_app_sock_read_v6 : max);
	}

	n = max + 1;

	rv = select(n, &readfds, NULL, NULL, NULL);
	if (rv == -1) {
		/*TODO: Need to Fix*/
		//perror("select"); /* error occurred in select() */
	} else if (rv > 0) {
		/* when recovery mode is initiate, CP handle only pfcp message, and other msg is in socket queue */
		if (recovery_flag == 1) {

			if (FD_ISSET(my_sock.sock_fd, &readfds)) {
					process_pfcp_msg(pfcp_rx, &peer_addr, NOT_PRESENT);
			}

			if (FD_ISSET(my_sock.sock_fd_v6, &readfds)) {
					process_pfcp_msg(pfcp_rx, &peer_addr, PRESENT);
			}

			return;
		}

		if ((config.use_gx) && config.cp_type != SGWC &&
			(FD_ISSET(gx_app_sock_read, &readfds))) {
					msg_handler_gx();
		}

		if (FD_ISSET(my_sock.sock_fd, &readfds)) {

			process_pfcp_msg(pfcp_rx, &peer_addr, NOT_PRESENT);
		}

		if (FD_ISSET(my_sock.sock_fd_v6, &readfds)){
			process_pfcp_msg(pfcp_rx, &peer_addr, PRESENT);
		}

		if (config.cp_type != PGWC) {
			if (FD_ISSET(my_sock.sock_fd_s11, &readfds)) {
				msg_handler_s11(NOT_PRESENT);
			}

			if(FD_ISSET(my_sock.sock_fd_s11_v6, &readfds)){
				msg_handler_s11(PRESENT);
			}
		}

		if (FD_ISSET(my_sock.sock_fd_s5s8, &readfds)) {
				msg_handler_s5s8(NOT_PRESENT);
		}

		if(FD_ISSET(my_sock.sock_fd_s5s8_v6, &readfds)){
				msg_handler_s5s8(PRESENT);
		}
	}
}
#else /*End of CP_BUILD*/

void process_dp_msgs(void) {

	int n = 0, rv = 0, max = 0;
	fd_set readfds = {0};
	peer_addr_t peer_addr = {0};

	FD_ZERO(&readfds);

	/* Add PFCP_FD in the set */
	if(my_sock.sock_fd > 0)
		FD_SET(my_sock.sock_fd, &readfds);
	if(my_sock.sock_fd_v6 > 0)
		FD_SET(my_sock.sock_fd_v6, &readfds);

	max = my_sock.sock_fd;
	max = (my_sock.sock_fd_v6 > max ? my_sock.sock_fd_v6 : max);

	n = max + 1;

	rv = select(n, &readfds, NULL, NULL, NULL);
	if (rv == -1) {
		/*TODO: Need to Fix*/
		//perror("select"); /* error occurred in select() */
	} else if (rv > 0) {
		/* one or both of the descriptors have data */
		if (FD_ISSET(my_sock.sock_fd, &readfds))
				process_pfcp_msg(pfcp_rx, &peer_addr, NOT_PRESENT);

		if(FD_ISSET(my_sock.sock_fd_v6, &readfds))
				process_pfcp_msg(pfcp_rx, &peer_addr, PRESENT);

	}
}
#endif /*DP_BUILD*/
