/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "vepc_udp.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <fcntl.h>

/**
 * @brief API to create udp socket.
 */
int __create_udp_socket(struct in_addr send_ip, uint16_t send_port,
		uint16_t recv_port, udp_sock_t *__sock)
{
	__sock->sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (__sock->sock_fd == -1) {
		perror("socket error: ");
		close(__sock->sock_fd);
		return -1;
	}

	memset(&__sock->other_addr, 0x0, sizeof(struct sockaddr_in));

	__sock->other_addr.sin_family = AF_INET;
	__sock->other_addr.sin_port = htons(send_port);
	__sock->other_addr.sin_addr = send_ip;

	memset(&__sock->my_addr, 0x0, sizeof(struct sockaddr_in));
	__sock->my_addr.sin_family = AF_INET;
	__sock->my_addr.sin_port = htons(recv_port);
	__sock->my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(__sock->sock_fd, (struct sockaddr *)&__sock->my_addr,
			sizeof(struct sockaddr_in)) == -1)
		return -1;

	return 0;
}

/**
 * @brief API to send pkts over udp socket.
 */
int __send_udp_packet(udp_sock_t *__sock, void *data, int size)
{
	return sendto(__sock->sock_fd,
	       data,
	       size,
	       MSG_DONTWAIT,
	       (struct sockaddr *)&__sock->other_addr,
	       sizeof(__sock->other_addr));
}


int __create_udp_listen_socket(const char *ip, uint16_t port)
{
	int sockfd;
	struct sockaddr_in addr;
	int rc;
	int option = 1;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&option,
		   sizeof(int));

	int flags = fcntl(sockfd, F_GETFL);

	flags |= O_NONBLOCK;
	fcntl(sockfd, F_SETFL, flags);

	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(ip);
	addr.sin_port = htons(port);
	rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

	if (rc == -1) {
		perror("bind error: ");
		close(sockfd);
		return -1;
	}

	return sockfd;
}
