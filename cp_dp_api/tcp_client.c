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
get_tcp_tunnel(uint32_t ip, uint16_t port, int create){

	//TODO : Check if ip is rechable of not
	//else tcp connect will waith for 2min for SYN_ACK

	int ret = 0;
	int *sock = NULL;
	char ip_port[30];
	snprintf(ip_port,30,"%u%u",ip,port);

	ret = rte_hash_lookup_data(sock_by_ddf_ip_hash,
				ip_port, (void **)&sock);

	if (ret < 0 ) {
		if(create == TCP_GET){
			clLog(clSystemLog, eCLSeverityCritical, "%s: Failed to get TCP Socket FD\n", __func__);
			return -1;
		}
		struct sockaddr_in serv_addr;

		/* VK : allocate memory for tcp_sock_fd info*/
		sock = rte_zmalloc("tcp_sock_fd", sizeof(int),
		        RTE_CACHE_LINE_SIZE);
		if (sock == NULL){
		    clLog(clSystemLog, eCLSeverityCritical, "%s: Failed to allocate memory for socket\n", __func__);
		    return -1;
		}
		/*VK : Creating TCP sock FD */
		if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			clLog(clSystemLog, eCLSeverityCritical,"Socket creation error \n");
			return -1;
		}

		int flag = 1;
		setsockopt(*sock,            /* socket affected */
					SOL_SOCKET,     /* set option at TCP level */
					TCP_NODELAY,     /* name of option */
					(char *) &flag,  /* the cast is historical
					                                    cruft */
					sizeof(int));    /* length of option value */

		int sendbuff = 0;
		/* VK : Set SO_SNDBUF to 0 so that TCP allow transmission
		 * of smallest packet also. */
		setsockopt(*sock, SOL_SOCKET, SO_SNDBUF, &sendbuff, sizeof(sendbuff));

		/* bind to specific interface */
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		#ifdef CP_BUILD
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", pfcp_config.ddf_intfc);
		#endif

		#ifdef DP_BUILD
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", app.ddf_intfc);
		#endif

		if ((setsockopt(*sock, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr))) < 0) {

			#ifdef CP_BUILD
			clLog(clSystemLog, eCLSeverityCritical,
				"Not able to bind %s interface \n", pfcp_config.ddf_intfc);
			#endif

			#ifdef DP_BUILD
			clLog(clSystemLog, eCLSeverityCritical,
				"Not able to bind %s interface \n", app.ddf_intfc);
			#endif

			return -1;
		}

		serv_addr.sin_family = AF_INET;
		serv_addr.sin_port = htons(port);

		/* VK : Converting ip in const string to add to sin_addr*/
		char *ip_str;
		ip_str = (char *)malloc(sizeof(uint32_t));
		snprintf(ip_str,IPV4_ADDR_MAX_LEN,""IPV4_ADDR"",IPV4_ADDR_HOST_FORMAT(ip));

		if(inet_pton(AF_INET, ip_str, &serv_addr.sin_addr)<=0)
		{
			clLog(clSystemLog, eCLSeverityCritical,
							"Invalid address/ Address not supported \n");
			return -1;
		}


		/*VK : Connecting To TCP sever */
		if (connect(*sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
		{
			clLog(clSystemLog, eCLSeverityDebug,
					"Connection Failed with ip %s and port %u \n",ip_str,port);
			return -1;
		}

		ret = rte_hash_add_key_data(sock_by_ddf_ip_hash,
						ip_port, sock);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, "Adding TCP scoket failed");
			return -1;
		}
	}
	clLog(clSystemLog, eCLSeverityDebug, "%s:  TCP Socket Created with FD %d\n", __func__,*sock);
	return *sock;
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

int
Cleanup_sock_ddf_ip_hash(uint32_t ddf_ip, uint16_t ddf_port) {
	int ret = -1;
	char ip_port[30];
	int *sock = NULL;

	snprintf(ip_port, 30, "%u%u", ddf_ip, ddf_port);

	/* Check ddf entry is present or Not */
	ret = rte_hash_lookup_data(sock_by_ddf_ip_hash,
			ip_port, (void **)&sock);
	if (ret) {
		/* Entry is present in ddf hash. Delete entry from ddf hash */
		ret = rte_hash_del_key(sock_by_ddf_ip_hash, ip_port);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					"%s:%d Entry not found for ip_port:%s...\n",
					__func__, __LINE__, ip_port);
			return -1;
		}
	}

	return 0;
}
