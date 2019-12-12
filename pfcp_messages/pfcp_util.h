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

#ifndef PFCP_UTIL_H
#define PFCP_UTIL_H

#include <sys/sysinfo.h>
#include <stdint.h>
#include <arpa/inet.h>

#ifdef CP_BUILD
#include "ue.h"
#include "gtp_messages.h"
#endif /* CP_BUILD */

extern uint32_t start_time;
extern struct rte_hash *node_id_hash;
extern struct rte_hash *heartbeat_recovery_hash;

#ifdef CP_BUILD
/**
 * @brief  : Get upf list
 * @param  : pdn, pdn connection information
 * @return : Returns upf count in case of success , 0 if dn list not found, -1 otherwise
 */
int
get_upf_list(pdn_connection *pdn);

/**
 * @brief  : Get upf ip
 * @param  : context, ue context information
 * @param  : eps_index, index of entry in array for particular bearer
 * @param  : upf_ip, param to store resulting ip
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dns_query_lookup(pdn_connection *pdn, uint32_t **upf_ip);
#endif /* CP_BUILD */

/**
 * @brief  : Read data from peer node
 * @param  : msg_payload, buffer to store received data
 * @param  : size, max size to read data
 * @param  : peer_addr, peer node address
 * @return : Returns received number of bytes
 */
int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr);

/**
 * @brief  : Send data to peer node
 * @param  : fd, socket or file descriptor to use to send data
 * @param  : msg_payload, buffer to store data to be send
 * @param  : size, max size to send data
 * @param  : peer_addr, peer node address
 * @return : Returns sent number of bytes
 */
int
pfcp_send(int fd,void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr);

/**
 * @brief  : Returns system seconds since boot
 * @param  : No param
 * @return : Returns number of system seconds since boot
 */
long
uptime(void);

/**
 * @brief  : Creates node id hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_node_id_hash(void );

/**
 * @brief  : creates associated upf hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_associated_upf_hash(void );

/**
 * @brief  : Checks current ntp timestamp
 * @param  : No param
 * @return : Returns timestamp value
 */
uint32_t
current_ntp_timestamp(void);

/**
 * @brief  : Converts timeval to ntp format
 * @param  : tv, input timeval
 * @param  : ntp, converted ntp time
 * @return : Returns nothing
 */
void
time_to_ntp(struct timeval *tv, uint8_t *ntp);

#endif /* PFCP_UTIL_H */
