/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef __VEPC_UDP_H__
#define __VEPC_UDP_H__
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @brief udp socket structure.
 */
typedef struct udp_sock_t {
	struct sockaddr_in my_addr;
	struct sockaddr_in other_addr;
	int sock_fd;
} udp_sock_t;

/**
 * @brief API to create udp socket.
 */
int
__create_udp_socket(struct in_addr send_ip, uint16_t send_port,
		uint16_t recv_port, udp_sock_t *__sock);

/**
 * @brief API to send pkts over udp socket.
 */
int __send_udp_packet(udp_sock_t *__sock, void *data, int size);

/**
 * @brief API to listen on udp socket.
 */
int __create_udp_listen_socket(const char *ip, uint16_t port);
#endif /* __VEPC_UDP_H__*/
