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



#include "tcp_client.h"

#ifdef CP_BUILD
pfcp_config_t pfcp_config;
#endif

#ifdef DP_BUILD
extern struct app_params app;
#endif

int
create_ddf_tunnel(uint32_t ip, uint16_t port, char intfc_name[DDF_INTFC_LEN]) {
	int flag = 1;
	int sock = -1;
	int sendbuff = 0;
	struct ifreq ifr;
	struct sockaddr_in serv_addr = {0};

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Socket creation error \n", LOG_VALUE);

		return -1;
	}

	setsockopt(sock, SOL_SOCKET, TCP_NODELAY, (char *) &flag, sizeof(int));
	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", intfc_name);

	if ((setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Not able to bind %s interface \n", LOG_VALUE, intfc_name);

		return -1;
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = ip;

	if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Connection Failed with IP: "IPV4_ADDR" and Port: %u \n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(ip)), port);

		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"TCP Socket Created with FD: %d\n", LOG_VALUE, sock);

	return sock;
}

int
send_li_data_pkt(int sock, void *pkt, int size){
	if(sock > 0)
		return send(sock , pkt, size, 0);
	return -1;
}

void
insert_fd(int *sock_arr, uint32_t *arr_size, int fd){

	if(*arr_size == 0){
		sock_arr[*arr_size] = fd;
		*arr_size = *arr_size + 1;
		return;
	}

	for(uint32_t i =0 ; i < *arr_size; i++){
		if(sock_arr[i] == fd)
			return;
	}

	sock_arr[*arr_size] = fd;
	*arr_size = *arr_size + 1;
	return;
}
