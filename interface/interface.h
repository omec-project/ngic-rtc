/*
 * Copyright (c) 2017 Intel Corporation
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

#ifndef _INTERFACE_H_
#define _INTERFACE_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of CP/DP module constructor and communication interface type.
 */
#include <stdint.h>
#include <inttypes.h>

#include <rte_hash.h>

#ifdef SDN_ODL_BUILD
	#include "zmqsub.h"
#endif		/* SDN_ODL_BUILD  */

#include "vepc_cp_dp_api.h"
#include "vepc_udp.h"

//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

extern int num_dp;

uint8_t zmq_comm_switch;

#ifdef SDN_ODL_BUILD
char zmq_sub_ifconnect[128];
char zmq_pub_ifconnect[128];

extern struct in_addr fpc_ip;
extern uint16_t fpc_port;
extern uint16_t fpc_topology_port;
extern struct in_addr cp_nb_ip;
extern uint16_t cp_nb_port;

#endif

extern udp_sock_t my_sock;

/**
 * @brief  : CP DP communication message type
 */
enum cp_dp_comm {
	COMM_QUEUE,
	COMM_SOCKET,
	COMM_ZMQ,
	COMM_END,
};

/**
 * @brief  : CP DP Communication message structure.
 */
struct comm_node {
	int status;					/*set if initialized*/
	int (*init)(void);				/*init function*/
	int (*send)(void *msg_payload, uint32_t size);	/*send function*/
	int (*recv)(void *msg_payload, uint32_t size);	/*receive function*/
	int (*destroy)(void);			/*uninit and free function*/
};
struct comm_node comm_node[COMM_END];
struct comm_node *active_comm_msg;

/**
 * @brief  : Registor CP DP Communication message type.
 * @param  : id
 *           id - identifier for type of communication.
 * @param  : init
 *           init - initialize function.
 * @param  : send
 *           send - send function.
 * @param  : recv
 *           recv - receive function.
 * @param  : destroy
 *           destroy - destroy function.
 * @return : Returns nothing
 */
void register_comm_msg_cb(enum cp_dp_comm id,
		int (*init)(void),
		int (*send)(void *msg_payload, uint32_t size),
		int (*recv)(void *msg_payload, uint32_t size),
		int (*destroy)(void));

/**
 * @brief  : Set CP DP Communication type.
 * @param  : id
 *           id - identifier for type of communication.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int set_comm_type(enum cp_dp_comm id);

/**
 * @brief  : Unset CP DP Communication type.
 * @param  : id
 *           id - identifier for type of communication.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int unset_comm_type(enum cp_dp_comm id);

/**
 * @brief  : Process CP DP Communication msg type.
 * @param  : buf
 *           buf - message buffer.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_comm_msg(void *buf);

/**
 * @brief  : Process PFCP message.
 * @param  : buf_rx
 *           buf - message buffer.
 * @param  : bytes_rx
 *           received message buffer size
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_msg(uint8_t *buf_rx,
		struct sockaddr_in *peer_addr);

/**
 * @brief  : Process DP CP Response
 * @param  : buf
 *           buf - message buffer.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_resp_msg(void *buf);

/**
 * @brief  : Initialize iface message passing
 *           This function is not thread safe and should only be called once by DP.
 * @param  : No param
 * @return : Returns nothing
 */
void iface_module_constructor(void);

/**
 * @brief  : Functino to handle signals.
 * @param  : signo
 *           signal number signal to be handled
 * @return : Returns nothing
 */
void sig_handler(int signo);

#endif /* _INTERFACE_H_ */
