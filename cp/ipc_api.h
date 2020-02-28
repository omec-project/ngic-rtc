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

int
create_ipc_channel(void );

void
bind_ipc_channel(int sock, struct sockaddr_un sock_addr,const  char *path);

void
connect_to_ipc_channel(int sock, struct sockaddr_un sock_addr, const char *path);

int
accept_from_ipc_channel(int sock, struct sockaddr_un sock_addr);

void
listen_ipc_channel(int sock);

void
get_peer_name(int sock, struct sockaddr_un sock_addr);

int
recv_from_ipc_channel(int sock, char *buf);

void
send_to_ipc_channel(int sock, char *buf, int len);

void
close_ipc_channel(int sock);

#endif /* IPC_API_H*/
