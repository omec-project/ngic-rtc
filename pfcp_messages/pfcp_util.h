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
int
get_upf_list(pdn_connection *pdn);

int
dns_query_lookup(ue_context *context, uint8_t eps_index, uint32_t **upf_ip);
#endif /* CP_BUILD */

int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr);

int
pfcp_send(int fd,void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr);

long
uptime(void);

void
create_node_id_hash(void );

void
create_associated_upf_hash(void );

uint32_t
current_ntp_timestamp(void);

void
time_to_ntp(struct timeval *tv, uint8_t *ntp);

#endif /* PFCP_UTIL_H */
