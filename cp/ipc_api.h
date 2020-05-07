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
#ifndef IPC_API_H
#define IPC_API_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>

/**
 * @brief  : Performs Gx Interface Unix socket creation
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
create_ipc_channel(void );

/**
 * @brief  : Performs Gx Socket Bind
 * @param  : sock, GX socket id
 * @param  : sock_addr, socket address info
 * @param  : path, Filepath
 * @return : Returns nothing
 */
void
bind_ipc_channel(int sock, struct sockaddr_un sock_addr,const  char *path);

/**
 * @brief  : Performs Gx_app client connection
 * @param  : sock, GX socket id
 * @param  : sock_addr, socket address info
 * @param  : path, Filepath
 * @return : Returns nothing
 */
void
connect_to_ipc_channel(int sock, struct sockaddr_un sock_addr, const char *path);

/**
 * @brief  : Performs Socket connection accept function
 * @param  : sock, socket id
 * @param  : sock_addr, socket address info
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
accept_from_ipc_channel(int sock, struct sockaddr_un sock_addr);

/**
 * @brief  : Enables Unix Server waiting for Gx_app client connection
 * @param  : sock, socket id
 * @return : Returns nothing
 */
void
listen_ipc_channel(int sock);

/**
 * @brief  : Retrive peer node name
 * @param  : sock, socket id
 * @param  : sock_addr, socket address info
 * @return : Returns nothing
 */
void
get_peer_name(int sock, struct sockaddr_un sock_addr);

/**
 * @brief  : Accept data from created ipc channel
 * @param  : sock, socket id
 * @param  : buf, buffer to store incoming data
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
recv_from_ipc_channel(int sock, char *buf);

/**
 * @brief  : Send data to created ipc channel
 * @param  : sock, socket id
 * @param  : buf, buffer to store data to be sent
 * @param  : len, total data length
 * @return : Returns nothing
 */
void
send_to_ipc_channel(int sock, char *buf, int len);

/**
 * @brief  : Close ipc channel
 * @param  : sock, socket id
 * @return : Returns nothing
 */
void
close_ipc_channel(int sock);

#endif /* IPC_API_H*/
