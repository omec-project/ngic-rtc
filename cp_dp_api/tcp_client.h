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



#ifndef _TCP_CLIENT_H_
#define _TCP_CLIENT_H_
#define IPV4_ADDR_MAX_LEN 16
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes for TCP based connections for LI.
*/
#ifdef DP_BUILD
#include "up_main.h"
#else
#include "cp.h"
#endif
#include "clogger.h"
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <net/if.h>
/*
 * Define type of Action need to take
 * TCP_GET, Get tcp sockfd already created
 * TCP_CREATE, Create a new sockfd
 */
enum TCP_SOCKET {
	TCP_GET = 0,
	TCP_CREATE = 1
};

/**
 * @brief  : Get tcp tunnel sockfd if exist or create new
 * @param  : ip, Ip address of remote server for which we want/create sockfd
 * @param  : port, port no for creating sockfd if new ip
 * @param  : create, variable to identify  to create new sockfd if not present
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
get_tcp_tunnel(uint32_t ip, uint16_t port, int create);

/**
 * @brief  : Send pkts over TCP for LI
 * @param  : sock, sockfd on which we need to send
 * @param  : pkt, pkt need to copy
 * @param  : size, size of pkt
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
send_li_data_pkt(int sock, void *pkt, int size);

/**
 * @brief  : Add the sock fd to the sock arr which is not present in that arry
 * @param  : sock_arr, Array sockfd on which we need to add new fd
 * @param  : arr_size, the no of fd in sock_arr
 * @param  : fd, new fd to be added
 * @return : Nothing
 */
void
insert_fd(int *sock_arr, uint32_t *arr_size, int fd);

/**
 * @brief  : Clean up socket create from li ddf component
 * @param  : ddf_ip, IP address of DDF
 * @param  : ddf_port, Port of DDF
 * @return : 0 in case of success, if fails it return -1
 */
int
Cleanup_sock_ddf_ip_hash(uint32_t ddf_ip, uint16_t ddf_port);

#endif /*_TCP_CLIENT_H_*/
