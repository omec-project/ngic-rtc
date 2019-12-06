/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
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

extern void parse_arg_host(const char *optarg, struct in_addr *addr);

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

#ifdef ZMQ_COMM
#if defined (CP_BUILD) && defined (MULTI_UPFS)
/* for TAILQ */
#include <sys/queue.h>
/**
 * Used to hold registered UPF context.
 * Also becomes a part of the TAILQ list node
 */
typedef struct upf_context {
	char zmq_pull_ifconnect[128];
	char zmq_push_ifconnect[128];
	void *zmqpull_sockctxt;
	void *zmqpull_sockcet;
	void *zmqpush_sockctxt;
	void *zmqpush_sockcet;

	TAILQ_ENTRY(upf_context) entries;
} upf_context;
/* running upf count */
extern uint8_t upf_count;
extern struct in_addr dp_comm_ip;
extern struct in_addr cp_comm_ip;
extern uint16_t dp_comm_port;
extern uint16_t cp_comm_port;
extern struct in_addr cp_nb_ip;
extern uint16_t cp_nb_port;
/* head of the dp list */
TAILQ_HEAD(, upf_context) upf_list;
/**
 * @brief
 * Used by CP to check for new DP registration requests
 * @return
 */
void check_for_new_dps(void);
/**
 * @brief
 * Used by CP to intialize the CP northbound port (for registration)
 * @return
 */
void init_dp_sock(void);
#define MAX_UPFS               16
#elif defined (MULTI_UPFS) /* CP_BUILD && MULTI_UPFS */
extern struct in_addr cp_nb_ip;
extern uint16_t cp_nb_port;
#endif /* MULTI_UPFS */
char zmq_pull_ifconnect[128];
char zmq_push_ifconnect[128];

extern struct in_addr zmq_cp_ip, zmq_dp_ip;
extern uint16_t zmq_cp_pull_port, zmq_dp_pull_port;
extern uint16_t zmq_cp_push_port, zmq_dp_push_port;
#endif	/* ZMQ_COMM */

extern udp_sock_t my_sock;

/* CP DP communication message type*/
enum cp_dp_comm {
	COMM_QUEUE,
	COMM_SOCKET,
	COMM_ZMQ,
	COMM_END,
};
/**
 * CP DP Communication message structure.
 */
#if defined (CP_BUILD) && defined (MULTI_UPFS)
struct comm_node {
	int status;                                     /*set if initialized*/
	int (*init)(void);                              /*init function*/
	int (*send)(struct upf_context *upf, void *msg_payload, uint32_t size);    /*send function*/
	int (*recv)(struct upf_context *upf, void *msg_payload, uint32_t size);    /*receive function*/
	int (*destroy)(struct upf_context *upf);                   /*uninit and free function*/
};
#else
struct comm_node {
	int status;					/*set if initialized*/
	int (*init)(void);				/*init function*/
	int (*send)(void *msg_payload, uint32_t size);	/*send function*/
	int (*recv)(void *msg_payload, uint32_t size);	/*receive function*/
	int (*destroy)(void);			/*uninit and free function*/
};
#endif /* MULTI_UPFS */
struct comm_node comm_node[COMM_END];
struct comm_node *active_comm_msg;

/**
 * Registor CP DP Communication message type.
 * @param id
 *	id - identifier for type of communication.
 * @param  init
 *	init - initialize function.
 * @param  send
 *	send - send function.
 * @param  recv
 *	recv - receive function.
 * @param  destroy
 *	destroy - destroy function.
 *
 * @return
 *	None
 */
#if defined (CP_BUILD) && defined (MULTI_UPFS)
void register_comm_msg_cb(enum cp_dp_comm id,
			  int (*init)(void),
			  int (*send)(struct upf_context *upf, void *msg_payload, uint32_t size),
			  int (*recv)(struct upf_context *upf, void *msg_payload, uint32_t size),
			  int (*destroy)(struct upf_context *upf));
#else
void register_comm_msg_cb(enum cp_dp_comm id,
		int (*init)(void),
		int (*send)(void *msg_payload, uint32_t size),
		int (*recv)(void *msg_payload, uint32_t size),
		int (*destroy)(void));
#endif
#if defined (DP_BUILD) && defined (ZMQ_COMM) && defined (MULTI_UPFS)
/**
 * Register DP to a central CP NF
 */
void
send_dp_credentials(void);
#endif
/**
 * Set CP DP Communication type.
 * @param id
 *	id - identifier for type of communication.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int set_comm_type(enum cp_dp_comm id);
/**
 * Unset CP DP Communication type.
 * @param id
 *	id - identifier for type of communication.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int unset_comm_type(enum cp_dp_comm id);
/**
 * Process CP DP Communication msg type.
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int process_comm_msg(void *buf);

/**
 * Process DP CP Response
 * @param buf
 *	buf - message buffer.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
int process_resp_msg(void *buf);
/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void);

/**
 * @brief Functino to handle signals.
 */
void sig_handler(int signo);

#endif /* _INTERFACE_H_ */
