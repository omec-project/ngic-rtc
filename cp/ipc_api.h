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
send_to_ipc_channel(int sock, char *buf);

void
close_ipc_channel(int sock);

#endif /* IPC_API_H*/
