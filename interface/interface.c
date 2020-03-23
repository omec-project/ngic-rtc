/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_debug.h>

#include "interface.h"
#include "util.h"
#include "meter.h"
#include "dp_ipc_api.h"
#include "gtpv2c_ie.h"
#ifdef SDN_ODL_BUILD
#include "zmqsub.h"
#include "zmqpub.h"
#ifdef CP_BUILD
#include "nb.h"
#endif
#endif
#ifndef CP_BUILD
#include "cdr.h"
#endif
#ifdef ZMQ_COMM
#include "zmq_push_pull.h"
#include "cp.h"
#endif
#ifdef USE_AF_PACKET
#include <libmnl/libmnl.h>
#endif

#include "main.h"

#include "../dp/perf_timer.h"

#ifdef SGX_CDR
	#define DEALERIN_IP "dealer_in_ip"
	#define DEALERIN_PORT "dealer_in_port"
	#define DEALERIN_MRENCLAVE "dealer_in_mrenclave"
	#define DEALERIN_MRSIGNER "dealer_in_mrsigner"
	#define DEALERIN_ISVSVN "dealer_in_isvsvn"
	#define DP_CERT_PATH "dp_cert_path"
	#define DP_PKEY_PATH "dp_pkey_path"
#endif /* SGX_CDR */

/*
 * UDP Setup
 */
udp_sock_t my_sock;

extern char *config_update_base_folder;
/* VS: ROUTE DISCOVERY */
extern int route_sock;

struct in_addr dp_comm_ip;
struct in_addr cp_comm_ip;
uint16_t dp_comm_port;
uint16_t cp_comm_port;

#ifdef SDN_ODL_BUILD
struct in_addr fpc_ip;
uint16_t fpc_port;
uint16_t fpc_topology_port;

struct in_addr cp_nb_ip;
uint16_t cp_nb_port;
#endif

#ifdef ZMQ_COMM
struct in_addr zmq_cp_ip, zmq_dp_ip;
uint16_t zmq_cp_pull_port, zmq_dp_pull_port;
uint16_t zmq_cp_push_port, zmq_dp_push_port;
struct in_addr cp_nb_ip;
uint16_t cp_nb_port;
#define MAX_TCP_PORT		65536
#endif	/* ZMQ_COMM */

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
extern void print_perf_statistics(void);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

extern struct ipc_node *basenode;

#if defined (CP_BUILD) && defined (MULTI_UPFS)
/* current running count of registered UPFs */
uint8_t upf_count = 0;

/**
 * Comm backend changes since we need to tell which upf context we need to send to
 */
void register_comm_msg_cb(enum cp_dp_comm id,
			  int (*init)(void),
			  int (*send)(struct upf_context *upf, void *msg_payload, uint32_t size),
			  int (*recv)(struct upf_context *upf, void *msg_payload, uint32_t size),
			  int (*destroy)(struct upf_context *upf))
{
	struct comm_node *node;
	struct upf_context *upf;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;

	TAILQ_FOREACH(upf, &upf_list, entries) {
		node->init();
	}
}
#else
void register_comm_msg_cb(enum cp_dp_comm id,
			int (*init)(void),
			int (*send)(void *msg_payload, uint32_t size),
			int (*recv)(void *msg_payload, uint32_t size),
			int (*destroy)(void))
{
	struct comm_node *node;

	node = &comm_node[id];
	node->init = init;
	node->send = send;
	node->recv = recv;
	node->destroy = destroy;
	node->status = 0;
#ifndef MULTI_UPFS
	/* delay initialization till you get confirmation from cp */
	node->init();
#endif
}
#endif

int set_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status == 0 && comm_node[id].init != NULL) {
		active_comm_msg = &comm_node[id];
		comm_node[id].status = 1;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot set communication type\n");
		return -1;
	}
	return 0;
}

int unset_comm_type(enum cp_dp_comm id)
{
	if (comm_node[id].status) {
#if defined (CP_BUILD) && defined (MULTI_UPFS)
		/* delete all upf contexts */
		struct upf_context *upf;
		while ((upf = TAILQ_FIRST(&upf_list))) {
			active_comm_msg->destroy(upf);
			TAILQ_REMOVE(&upf_list, upf, entries);
			free(upf);
		}
#else
		active_comm_msg->destroy();
#endif
		comm_node[id].status = 0;
	} else {
		RTE_LOG_DP(ERR, DP,"Error: Cannot unset communication type\n");
		return -1;
	}
	return 0;
}

int process_comm_msg(void *buf)
{
	struct msgbuf *rbuf = (struct msgbuf *)buf;
	struct ipc_node *cb;

	if (rbuf->mtype >= MSG_END)
		return -1;

	/* Callback APIs */
	cb = &basenode[rbuf->mtype];

#ifdef ZMQ_COMM
	int rc = cb->msg_cb(rbuf);
	if (rc == 0) {
		struct resp_msgbuf resp = {0};

		switch(rbuf->mtype) {
			case MSG_SESS_CRE: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = rbuf->dp_id.id;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
#if defined (CP_BUILD) && defined (MULTI_UPFS)
				if (!TAILQ_EMPTY(&upf_list))
					zmq_mbuf_push(TAILQ_FIRST(&upf_list), (void *)&resp, sizeof(resp));
#else
				zmq_mbuf_push((void *)&resp, sizeof(resp));
#endif
				break;
			}
			case MSG_SESS_MOD: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = rbuf->dp_id.id;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
#if defined (CP_BUILD) && defined (MULTI_UPFS)
				if (!TAILQ_EMPTY(&upf_list))
					zmq_mbuf_push(TAILQ_FIRST(&upf_list), (void *)&resp, sizeof(resp));
#else
				zmq_mbuf_push((void *)&resp, sizeof(resp));
#endif
				break;
			}
			case MSG_SESS_DEL: {
				resp.op_id = rbuf->msg_union.sess_entry.op_id;
				resp.dp_id.id = rbuf->dp_id.id;
				resp.mtype = DPN_RESPONSE;
				resp.sess_id = rbuf->msg_union.sess_entry.sess_id;
#if defined (CP_BUILD) && defined (MULTI_UPFS)
				if (!TAILQ_EMPTY(&upf_list))
					zmq_mbuf_push(TAILQ_FIRST(&upf_list), (void *)&resp, sizeof(resp));
#else
				zmq_mbuf_push((void *)&resp, sizeof(resp));
#endif
				break;
			}
		default:
			break;
		}
	}
	return 0;
#else
	return cb->msg_cb(rbuf);
#endif  /* ZMQ_COMM */

}

#ifdef ZMQ_COMM
#if defined (DP_BUILD) && defined(MULTI_UPFS)
/**
 * Registers a newly spawned DP to the CP
 */
void
send_dp_credentials(void)
{
	static char addr_string[128] = {0};
	static char hostname[256] = {0};
	char *hp;
	struct reg_msg_bundle rmb;
	/* setting up ZMQ-based sockets */
	void *context = zmq_ctx_new();
	void *requester = zmq_socket(context, ZMQ_REQ);
	snprintf(addr_string, sizeof(addr_string),
		 "%s://%s:%u", "tcp", inet_ntoa(cp_nb_ip), cp_nb_port);
	RTE_LOG_DP(INFO, API, "Iface: connecting to %s\n", addr_string);
	/* connect */
	if (zmq_connect(requester, addr_string) != 0) {
		rte_exit(EXIT_FAILURE, "Iface: failed to connect to CP!\n");
	}

	RTE_LOG_DP(INFO, API, "Iface: sent join request. Waiting for response\n");

	hp = getenv("DP_NAME");
	if (hp) {
		strcpy(hostname, hp);
		RTE_LOG_DP(INFO, API, "Found DP_NAME environment variable %s \n", hostname );
	} else if (gethostname(hostname, sizeof(hostname)) == -1) { /* get hostname */
		rte_exit(EXIT_FAILURE, "Unable to retreive hostname of DP!\n");
	}
	RTE_LOG_DP(INFO, API, "DP hostname %s \n", hostname );

	/* build message */
	rmb.dp_comm_ip.s_addr = dp_comm_ip.s_addr;
	rmb.s1u_ip.s_addr = app.s1u_ip;
	strncpy(rmb.hostname, hostname, sizeof(hostname));

	/* send request */
	if (zmq_send(requester, (void *)&rmb, sizeof(rmb), 0) == -1) {
		rte_exit(EXIT_FAILURE, "Iface: failed to send registration request to CP!\n");
	}
	/* get response */
	if (zmq_recv(requester, &cp_comm_port, sizeof(cp_comm_port), 0) == -1) {
		rte_exit(EXIT_FAILURE, "Iface: failed to recv registration ack from CP!\n");
	}
	RTE_LOG_DP(INFO, API, "Iface: Received ACK. I'm registered!\n");

	/* setting up CP connection port */
	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		 "%s://%s:%u", "tcp", inet_ntoa(cp_comm_ip), cp_comm_port);
	zmq_close(requester);
	zmq_ctx_destroy(context);

	/* initialize underlying ZMQ fabric */
	comm_node[COMM_ZMQ].init();
}
#endif /* DP_BUILD && MULTI_UPFS */

#ifdef CP_BUILD
int process_resp_msg(void *buf)
{
	int rc;
	struct resp_msgbuf *rbuf = (struct resp_msgbuf *)buf;

	if (rbuf->mtype >= MSG_END)
		return -1;

	switch(rbuf->mtype) {
	case DPN_RESPONSE:
		del_resp_op_id(rbuf->op_id);
		break;

	case MSG_DDN:
		/* DDN Callback API */
		rc= cb_ddn(rbuf->sess_id);

		if (rc < 0)
				return -1;
		break;

	default:
		break;
	}

	return 0;
}
#endif /* CP_BUILD */

#if defined (CP_BUILD) && defined (MULTI_UPFS)
/* this sock is used to listen for new DPs who want to register */
void *dp_sock;
void *dp_sock_context;
void
init_dp_sock(void)
{
	static char addr_string[128] = {0};
	snprintf(addr_string, sizeof(addr_string),
		 "%s://*:%u", "tcp", cp_nb_port);
	dp_sock_context = zmq_ctx_new();
	/* create socket */
	dp_sock = zmq_socket(dp_sock_context, ZMQ_REP);
	/* bind to cp_nb_port */
	int rc = zmq_bind(dp_sock, addr_string);
	fprintf(stderr, "Binding to %s\n", addr_string);
	if (rc != 0) {
		rte_exit(EXIT_FAILURE, "zmq_bind() failed!\n");
	}

	/* 1st descriptor is for registration socket */
	zmq_items[0].socket = dp_sock;
	zmq_items[0].events = ZMQ_POLLIN;
}

/**
 * Check if DP tries to reconnect
 */
struct upf_context *
check_upf_exists(char *zp_ifconnect)
{
	struct upf_context *item;
	struct upf_context *item_temp;

	TAILQ_FOREACH_SAFE(item, &upf_list, entries, item_temp) {
		if (!strcmp(item->zmq_pull_ifconnect, zp_ifconnect)) {
			return item;
		}
	}

	return NULL;
}
/**
 * Called right after zmq_poll if an event is observed on descriptor `0`
 */
void
check_for_new_dps(void)
{
	struct in_addr a;
	uint32_t addr;
	struct reg_msg_bundle msg_bundle;
	memset(&addr, 0, sizeof(addr));
	/* receive request */
	int n = zmq_recv(dp_sock, &msg_bundle, sizeof(msg_bundle), 0);
	assert(n != -1);
	a.s_addr = msg_bundle.dp_comm_ip.s_addr;
	s1u_sgw_ip.s_addr = msg_bundle.s1u_ip.s_addr;
	RTE_SET_USED(a);
	uint8_t done = 0;

	/* verify */
	if (n > 0) {
		struct upf_context *upc;
		char zmq_pull_ifconnect[128];
#if ZMQ_DIRECT
		snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
			 "%s://%s:%u", "tcp", inet_ntoa(a), dp_comm_port);
#else
		snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
			 "%s://%s:%u", "tcp", inet_ntoa(a), zmq_cp_pull_port);
#endif
		/* bypass upf creation if entry already exists */
		upc = check_upf_exists(zmq_pull_ifconnect);
		if (upc == NULL)
			upc = rte_calloc(NULL, 1, sizeof(struct upf_context), 0);
		if (upc != NULL) {
#if ZMQ_DIRECT
			/* register pull and push sockets */
			if (upc->zmq_pull_ifconnect[0] == '\0')
				strcpy(upc->zmq_pull_ifconnect, zmq_pull_ifconnect);
				//snprintf(upc->zmq_pull_ifconnect, sizeof(upc->zmq_pull_ifconnect),
				//	 "%s://%s:%u", "tcp", inet_ntoa(a), dp_comm_port);
#else
			/* register pull and push sockets */
			if (upc->zmq_pull_ifconnect[0] == '\0')
				strcpy(upc->zmq_pull_ifconnect, zmq_pull_ifconnect);
				//snprintf(upc->zmq_pull_ifconnect, sizeof(upc->zmq_pull_ifconnect),
				//	 "%s://%s:%u", "tcp", inet_ntoa(a), zmq_cp_pull_port);
#endif
			fprintf(stderr, "%s\n", upc->zmq_pull_ifconnect);
#if ZMQ_DIRECT
			if (upc->zmq_push_ifconnect[0] == '\0')
				snprintf(upc->zmq_push_ifconnect, sizeof(upc->zmq_push_ifconnect),
					 "%s://%s:%u", "tcp", inet_ntoa(cp_comm_ip),
					 (++cp_comm_port % MAX_TCP_PORT));
#else
			if (upc->zmq_push_ifconnect[0] == '\0')
				snprintf(upc->zmq_push_ifconnect, sizeof(upc->zmq_push_ifconnect),
					 "%s://%s:%u", "tcp", inet_ntoa(a), zmq_cp_push_port);
#endif
			fprintf(stderr, "%s\n", upc->zmq_push_ifconnect);
			if (upc->zmqpull_sockctxt == NULL) {
				upf_count++;
				TAILQ_INSERT_HEAD(&upf_list, upc, entries);
				/* Socket to talk to Client */
				upc->zmqpull_sockctxt = zmq_ctx_new();
				upc->zmqpull_sockcet = zmq_socket(upc->zmqpull_sockctxt, ZMQ_PULL);
#if ZMQ_DIRECT
				do {
					fprintf(stderr, "ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
						upc->zmq_push_ifconnect, ZMQ_DEV_ID);
					n = zmq_bind(upc->zmqpull_sockcet, upc->zmq_push_ifconnect);
					if (n == 0)
						done = 1;
					else {
						fprintf(stderr, "ZMQ Server connect to: \t%s failed. Trying %u\n",
							upc->zmq_push_ifconnect, cp_comm_port);
						snprintf(upc->zmq_push_ifconnect, sizeof(upc->zmq_push_ifconnect),
							 "%s://%s:%u", "tcp", inet_ntoa(cp_comm_ip),
							 (++cp_comm_port % MAX_TCP_PORT));
					}
				} while (done == 0);

				upc->cp_comm_port = cp_comm_port;
#else
				fprintf(stderr, "ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
					upc->zmq_pull_ifconnect, ZMQ_DEV_ID);
				n = zmq_connect(upc->zmqpull_sockcet, upc->zmq_pull_ifconnect);
				assert(n == 0);
#endif
				upc->zmqpush_sockctxt = zmq_ctx_new();
				upc->zmqpush_sockcet = zmq_socket(upc->zmqpush_sockctxt, ZMQ_PUSH);
#if ZMQ_DIRECT
				fprintf(stderr, "ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
					upc->zmq_pull_ifconnect, ZMQ_DEV_ID);
				n = zmq_connect(upc->zmqpush_sockcet, upc->zmq_pull_ifconnect);
				assert(n == 0);
#else
				fprintf(stderr, "ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
					upc->zmq_push_ifconnect, ZMQ_DEV_ID);
				n = zmq_connect(upc->zmqpush_sockcet, upc->zmq_push_ifconnect);
				assert(n == 0);
#endif
				/* add the pull descriptor to poll list */
				zmq_items[upf_count].socket = upc->zmqpull_sockcet;
				zmq_items[upf_count].events = ZMQ_POLLIN | ZMQ_POLLERR;
				upc->cp_comm_port = cp_comm_port;
			}
		} else {
			rte_exit(EXIT_FAILURE, "Can't allocate memory for upc!\n");
		}
		assert(zmq_send(dp_sock, &upc->cp_comm_port, (size_t)2, 0) != -1);
		/* resolve upf context to dpInfo */
		if (resolve_upf_context_to_dpInfo(upc, msg_bundle.hostname, s1u_sgw_ip) == 0) {
			RTE_LOG_DP(INFO, CP, "Invalid dpname %s received from edge \n", msg_bundle.hostname);
		} else {
			/* send packet filter to registered upf */
			init_pkt_filter_for_dp(upc->dpId);
		}
	}
	/* re-initialize registration socket */
	zmq_close(dp_sock);
	zmq_ctx_destroy(dp_sock_context);
	init_dp_sock();
}

/**
 *
 */
struct upf_context *
fetch_upf_context_via_sock(void *socket)
{
	struct upf_context *upf = NULL;

	TAILQ_FOREACH(upf, &upf_list, entries) {
		if (upf->zmqpull_sockcet == socket)
			return upf;
	}

	RTE_LOG_DP(ERR, API, "Can't find the right upf for the zmq epoll event on sock %p\n",
		   socket);

	return NULL;
}

/* Definitions change since we need to tell which upf contexts need to be used */
static int
zmq_cp_init_socket(void)
{
	/*
	 * zmqpull/zmqpush init
	 */
	if (zmq_pull_create() != 0)
		RTE_LOG_DP(ERR, API, "ZMQ Server failed!\n");
	if (zmq_push_create() != 0)
		RTE_LOG_DP(ERR, API, "ZMQ Client failed!\n");

	return 0;
}

static int
zmq_cp_send_socket(struct upf_context *upf, void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpush send
	 */
	return zmq_mbuf_push(upf, zmqmsgbuf, zmqmsgbufsz);
}

static int
zmq_cp_recv_socket(struct upf_context *upf, void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpull recv
	 */
	int zmqmsglen = zmq_mbuf_pull(upf, buf, zmqmsgbufsz);

	if (zmqmsglen > 0) {
		RTE_LOG_DP(DEBUG, DP,
			   "Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			   zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

static int
zmq_cp_destroy(struct upf_context *upf)
{
	/*
	 * zmqpush/zmqpull destroy
	 */
	zmq_push_pull_destroy(upf);
	return 0;
}
#else /* MULTI_UPFS */
static int
zmq_init_socket(void)
{
	/*
	 * zmqpull/zmqpush init
	 */
	zmq_pull_create();
	return zmq_push_create();
}

static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpush send
	 */
	return zmq_mbuf_push(zmqmsgbuf, zmqmsgbufsz);
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqpull recv
	 */
	int zmqmsglen = zmq_mbuf_pull(buf, zmqmsgbufsz);

	if (zmqmsglen > 0) {
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqpush/zmqpull destroy
	 */
	zmq_push_pull_destroy();
	return 0;
}
#endif /* CP_BUILD && MULTI_UPFS */
#else  /* ZMQ_COMM */

static int
udp_send_socket(void *msg_payload, uint32_t size)
{
	if (__send_udp_packet(&my_sock, msg_payload, size) < 0)
		RTE_LOG_DP(ERR, DP, "Failed to send msg !!!\n");

	/* Workaround to avoid out of order packets on DP. In case of load it
	 * is observed that packets are received out of order at DP e.g. MB is
	 * received before CS, hence causing issue in session establishment */
	usleep(50);
	return 0;
}
#if !defined(CP_BUILD) || !defined(SDN_ODL_BUILD)
static int
udp_recv_socket(void *msg_payload, uint32_t size)
{
	uint32_t bytes = recvfrom(my_sock.sock_fd, msg_payload, size, 0,
			NULL, NULL);
	if (bytes < size) {
		RTE_LOG_DP(ERR, DP, "Failed recv msg !!!\n");
		return -1;
	}
	return 0;
}
#endif  /* !CP_BUILD || !SDN_ODL_BUILD */
#ifdef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_cp_socket(void)
{
	/*
	 * UDP init
	 */
	/* TODO IP and port parameters */
	if (__create_udp_socket(dp_comm_ip, dp_comm_port, cp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create CP UDP Socket Failed "
			"for IP %s:%u!!!\n",
			inet_ntoa(dp_comm_ip), dp_comm_port);

	return 0;
}

#endif		/* ZMQ_COMM */
#endif		/* CP_BUILD */

#ifndef CP_BUILD
/**
 * Init listen socket.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
static int
udp_init_dp_socket(void)
{
	if (__create_udp_socket(cp_comm_ip, cp_comm_port, dp_comm_port,
			&my_sock) < 0)
		rte_exit(EXIT_FAILURE, "Create DP UDP Socket "
			"Failed for IP %s:%d!!!\n",
			inet_ntoa(cp_comm_ip), cp_comm_port);
	return 0;
}

/**
 * UDP packet receive API.
 * @param msg_payload
 *	msg_payload - message payload from communication API.
 * @param size
 *	size - size of message payload.
 *
 * @return
 *	0 - success
 *	-1 - fail
 */
/**
 * Code Rel. Jan 30, 2017
 * UDP recvfrom used for PCC, ADC, Session table initialization.
 * Needs to be from SDN controller as code & data models evolve.
 */
#ifdef SDN_ODL_BUILD
static int
zmq_init_socket(void)
{
	/*
	 * zmqsub init
	 */
	zmq_pubsocket_create();
	return zmq_subsocket_create();
}
static int
zmq_send_socket(void *zmqmsgbuf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	return zmq_mbuf_send(zmqmsgbuf, sizeof(struct zmqbuf));
}

static int
zmq_recv_socket(void *buf, uint32_t zmqmsgbufsz)
{
	/*
	 * zmqsub recv
	 */
	int zmqmsglen = zmq_mbuf_rcv(buf, zmqmsgbufsz);

	if (zmqmsglen > 0)	{
		RTE_LOG_DP(DEBUG, DP,
			"Rcvd zmqmsglen= %d:\t zmqmsgbufsz= %u\n",
			zmqmsglen, zmqmsgbufsz);
	}
	return zmqmsglen;
}

#ifdef PRINT_NEW_RULE_ENTRY
/**
 * @Name : print_sel_type_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_sel_type_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		switch (adc->sel_type) {
		case DOMAIN_NAME:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Name :%s\n",
				adc->u.domain_name);
			break;

		case DOMAIN_IP_ADDR:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			break;

		case DOMAIN_IP_ADDR_PREFIX:
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Ip :%d\n",
				(adc->u.domain_ip.u.ipv4_addr));
			RTE_LOG_DP(DEBUG, DP, " ---> Domain Prefix :%d\n",
				adc->u.domain_prefix.prefix);
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				adc->sel_type);
			break;
		}
	}
}

/**
 * @Name : print_adc_val
 * @arguments : [In] pointer to adc rule structure element
 * @return : void
 * @Description : Function to print ADC rules values.
 */
static void print_adc_val(struct adc_rules *adc)
{
	if (NULL != adc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", adc->rule_id);

		print_sel_type_val(adc);

		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_pcc_val
 * @arguments : [In] pointer to pcc rule structure element
 * @return : void
 * @Description : Function to print PCC rules values.
 */
static void print_pcc_val(struct pcc_rules *pcc)
{
	if (NULL != pcc) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> PCC Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Rule id : %d\n", pcc->rule_id);
		RTE_LOG_DP(DEBUG, DP, " ---> metering_method :%d\n",
			pcc->metering_method);
		RTE_LOG_DP(DEBUG, DP, " ---> charging_mode :%d\n",
			pcc->charging_mode);
		RTE_LOG_DP(DEBUG, DP, " ---> rating_group :%d\n",
			pcc->rating_group);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_status :%d\n",
			pcc->rule_status);
		RTE_LOG_DP(DEBUG, DP, " ---> gate_status :%d\n",
			pcc->gate_status);
		RTE_LOG_DP(DEBUG, DP, " ---> session_cont :%d\n",
			pcc->session_cont);
		RTE_LOG_DP(DEBUG, DP, " ---> monitoring_key :%d\n",
			pcc->monitoring_key);
		RTE_LOG_DP(DEBUG, DP, " ---> precedence :%d\n",
			pcc->precedence);
		RTE_LOG_DP(DEBUG, DP, " ---> level_of_report :%d\n",
			pcc->report_level);
		RTE_LOG_DP(DEBUG, DP, " ---> mute_status :%d\n",
			pcc->mute_notify);
		RTE_LOG_DP(DEBUG, DP, " ---> drop_pkt_count :%ld\n",
			pcc->drop_pkt_count);
		RTE_LOG_DP(DEBUG, DP, " ---> redirect_info :%d\n",
			pcc->redirect_info.info);
		RTE_LOG_DP(DEBUG, DP, " ---> ul_mbr_mtr_profile_idx :%d\n",
			pcc->qos.ul_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> dl_mbr_mtr_profile_idx :%d\n",
			pcc->qos.dl_mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> ADC Index :%d\n",
			pcc->adc_idx);
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Index count:%d\n",
			pcc->sdf_idx_cnt);
		for(int i =0; i< pcc->sdf_idx_cnt; ++i)
			RTE_LOG_DP(DEBUG, DP, " ---> SDF IDx [%d]:%d\n",
				i, pcc->sdf_idx[i]);
		RTE_LOG_DP(DEBUG, DP, " ---> rule_name:%s\n", pcc->rule_name);
		RTE_LOG_DP(DEBUG, DP, " ---> sponsor_id:%s\n", pcc->sponsor_id);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_mtr_val
 * @arguments : [In] pointer to mtr entry structure element
 * @return : void
 * @Description : Function to print METER rules values.
 */
static void print_mtr_val(struct mtr_entry *mtr)
{
	if (NULL != mtr) {
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "=========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> Meter profile index :%d\n",
				mtr->mtr_profile_index);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CIR :%ld\n",
			mtr->mtr_param.cir);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter CBS :%ld\n",
			mtr->mtr_param.cbs);
		RTE_LOG_DP(DEBUG, DP, " ---> Meter EBS :%ld\n",
			mtr->mtr_param.ebs);
		RTE_LOG_DP(DEBUG, DP, " ---> Metering Method :%d\n",
				mtr->metering_method);
		RTE_LOG_DP(DEBUG, DP, "=========================================\n\n");
	}
}

/**
 * @Name : print_sdf_val
 * @arguments : [In] pointer to pkt_filter structure element
 * @return : void
 * @Description : Function to print SDF rules values.
 */
static void print_sdf_val(struct pkt_filter *sdf)
{
	if (NULL != sdf) {
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");
		RTE_LOG_DP(DEBUG, DP, " ---> SDF Rule Method ::\n");
		RTE_LOG_DP(DEBUG, DP, "==========================================\n");

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			RTE_LOG_DP(DEBUG, DP, " ---> pcc_rule_id :%d\n",
				sdf->pcc_rule_id);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_type :%d\n",
				sdf->sel_rule_type);
			RTE_LOG_DP(DEBUG, DP, " ---> rule_str : %s\n",
				sdf->u.rule_str);
			RTE_LOG_DP(DEBUG, DP, "====================================\n\n");
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct
			 * five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf->sel_rule_type);
			break;
		}
	}
}
#endif /*PRINT_NEW_RULE_ENTRY*/

/**
 * Name : parse_adc_val
 * argument :
 * selctor type pointed to adc rule type
 * [In] pointer (arm) to zmq rcv structure element
 * [Out] pointer (adc) to adc rules structure element
 * @return
 * 0 - success
 * -1 - fail
 * Description : Function to parse adc rules values into
 * adc_rules struct.
 * Here parse values as per selector type (DOMAIN_NAME,
 * DOMAIN_IP_ADDR, and DOMAIN_IP_ADDR_PREFIX), domain name,
 * domain ip addr, domain prefix parameters values from recv buf and
 * stored into adc_rules struct.
 * ref.doc: message_sdn.docx
 * section : Table No.11 ADC Rules
 */
static int parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc)
{
	if (arm != NULL) {
		switch (sel_type) {
		case DOMAIN_NAME:
			strncpy(adc->u.domain_name, (char *)((arm)+1),
					*(uint8_t *)(arm));

#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif
			return 0;

		case DOMAIN_IP_ADDR_PREFIX:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
			adc->u.domain_prefix.prefix =
				rte_bswap16(*(uint16_t *)((arm) + 4));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
			return 0;

		case DOMAIN_IP_ADDR:
			adc->u.domain_ip.u.ipv4_addr =
				ntohl(*(uint32_t *)(arm));
#ifdef PRINT_NEW_RULE_ENTRY
				print_adc_val(adc);
#endif  /* PRINT_NEW_RULE_ENTRY */
			return 0;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Selector Type: %d\n",
				sel_type);
			return -1;
		}
	}
	return -1;
}

/**
 * @Name : get_sdf_indices
 * @argument :
 * 	[IN] sdf_idx : String containing comma separater SDF index values
 * 	[OUT] out_sdf_idx : Array of integers converted from sdf_idx
 * @return : 0 - success, -1 fail
 * @Description : Convert sdf_idx array in to array of integers for SDF index
 * values.
 * Sample input : "[0, 1, 2, 3]"
 */
static uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx)
{
	char *tmp = strtok (sdf_idx,",");
	int i = 0;

	while ((NULL != tmp) && (i < MAX_SDF_IDX_COUNT)) {
		out_sdf_idx[i++] = atoi(tmp);
		tmp = strtok (NULL, ",");
	}
	return i;
}

/**
 * @Name : zmq_buf_process
 * @argument :
 * 	[IN] zmqmsgbuf_rx : Pointer to received zmq buffer
 * 	[IN] zmqmsglen : Length of the zmq buffer
 * @return : 0 - success
 * @Description : Converts zmq message type to session_info or
 * respective rules info
 */

int
zmq_mbuf_process(struct zmqbuf *zmqmsgbuf_rx, int zmqmsglen)
{
	int ret;
	struct msgbuf buf = {0};
	struct zmqbuf zmqmsgbuf_tx;
	struct msgbuf *rbuf = &buf;
	struct session_info *sess = &rbuf->msg_union.sess_entry;

	memset(sess, 0, sizeof(*sess));

	rbuf->mtype = MSG_END;

	switch (zmqmsgbuf_rx->type) {
	case CREATE_SESSION: {
		struct create_session_t *csm =
			&zmqmsgbuf_rx->msg_union.create_session_msg;

		rbuf->mtype = MSG_SESS_CRE;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.iptype = IPTYPE_IPV4;
		sess->ue_addr.u.ipv4_addr = ntohl(csm->ue_ipv4);
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->ul_s1_info.sgw_teid = csm->s1u_sgw_teid;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr =
			ntohl(csm->s1u_sgw_ipv4);
		sess->dl_s1_info.enb_teid = 0;

		switch(app.spgw_cfg) {
		case SGWU:
			/* Configure PGWU IP addr */
			sess->ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
			sess->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			break;

		case PGWU:
			/* Configure SGWU IP addr */
			sess->dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
			sess->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr = ntohl(csm->s5s8_ipv4);
			sess->dl_s1_info.enb_teid = csm->s1u_sgw_teid;

			/* Add default pcc rule entry for dl */
			sess->num_dl_pcc_rules = 1;
			sess->dl_pcc_rule_id[0] = 1;
			break;

		default:
			break;
		}

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(csm->session_id);
		sess->client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = csm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = csm->op_id;
		zmqmsgbuf_tx.topic_id = csm->controller_topic;
		break;
	}

	case MODIFY_BEARER: {
		struct modify_bearer_t *mbm =
			&zmqmsgbuf_rx->msg_union.modify_bearer_msg;
		rbuf->mtype = MSG_SESS_MOD;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->ul_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		sess->dl_s1_info.enb_addr.u.ipv4_addr =
			ntohl(mbm->s1u_enodeb_ipv4);
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = mbm->s1u_enodeb_teid;

		sess->num_ul_pcc_rules = 1;
		sess->ul_pcc_rule_id[0] = 1;
		sess->num_dl_pcc_rules = 1;
		sess->dl_pcc_rule_id[0] = 1;

		sess->sess_id = rte_bswap64(mbm->session_id);
		zmqmsgbuf_tx.msg_union.dpn_response.client_id = mbm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = mbm->op_id;
		zmqmsgbuf_tx.topic_id = mbm->controller_topic;
		break;
	}

	case DELETE_SESSION: {
		struct delete_session_t *dsm =
			&zmqmsgbuf_rx->msg_union.delete_session_msg;
		rbuf->mtype = MSG_SESS_DEL;
		rbuf->dp_id.id = DPN_ID;

		sess->ue_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->ul_s1_info.sgw_teid = 0;
		sess->dl_s1_info.enb_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.sgw_addr.u.ipv4_addr = 0;
		sess->dl_s1_info.enb_teid = 0;

		sess->sess_id = rte_bswap64(dsm->session_id);

		zmqmsgbuf_tx.msg_union.dpn_response.client_id = dsm->client_id;
		zmqmsgbuf_tx.msg_union.dpn_response.op_id = dsm->op_id;
		zmqmsgbuf_tx.topic_id = dsm->controller_topic;
		break;
	}

	case ADC_RULE: {
		/*
		 * @brief Coverts zmq message into ADC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.11 ADC Table
		 */
		static uint8_t rule_num = 1;
		uint8_t *buf = (uint8_t *)&(zmqmsgbuf_rx->msg_union.adc_rule_m);
		struct adc_rules *adc =
			&(rbuf->msg_union.adc_filter_entry);

		rbuf->mtype = MSG_ADC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		adc->sel_type = *(uint8_t *)(buf);

		adc->rule_id = rule_num++;

		ret = parse_adc_buf(adc->sel_type, (((char *)(buf) + 1)), adc);

		if (ret < 0){
			RTE_LOG_DP(ERR, DP, "Failed to filled adc structure\n");
		}
		break;
	}

	case PCC_RULE: {
		/**
		 * @brief Coverts zmq message into PCC Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.12 PCC Table
		 */
		static uint8_t rule_id_t = 1;
		struct pcc_rules_t *pcc_t =
			&(zmqmsgbuf_rx->msg_union.pcc_rules_m);
		struct pcc_rules *pcc = &(rbuf->msg_union.pcc_entry);
		uint8_t sdf_idx[MAX_SDF_STR_LEN]={0};
		uint8_t len=0, offset = 0;

		rbuf->mtype = MSG_PCC_TBL_ADD;
		rbuf->dp_id.id = DPN_ID;

		pcc->rule_id = rule_id_t++;
		pcc->metering_method = pcc_t->metering_method;
		pcc->charging_mode = pcc_t->charging_mode;
		pcc->rating_group = rte_bswap16(pcc_t->rating_group);
		pcc->rule_status = pcc_t->rule_status;
		pcc->gate_status = pcc_t->gate_status;
		pcc->session_cont = pcc_t->session_cont;
		pcc->monitoring_key = rte_bswap32(pcc_t->monitoring_key);
		pcc->precedence = rte_bswap32(pcc_t->precedence);
		pcc->report_level = pcc_t->level_of_report;
		pcc->mute_notify = pcc_t->mute_status;
		pcc->drop_pkt_count = rte_bswap64(pcc_t->drop_pkt_count);
		pcc->qos.ul_mtr_profile_index = rte_bswap16(pcc_t->ul_mtr_profile_idx);
		pcc->qos.dl_mtr_profile_index = rte_bswap16(pcc_t->dl_mtr_profile_idx);
		pcc->redirect_info.info = pcc_t->redirect_info;
		pcc->adc_idx = rte_bswap32(pcc_t->adc_idx);

		/**
		 * ref.table no 12 PCC table info will help know the code
		 * len(SDF_FILTER_IDX), 0 : [0-4]
		 * SDF_FILTER_IDX, 5: [5 - len1]
		 * len(RULE_NAME), 5 + len1 :
		 * RULE_NAME, [5+len1] + 5
		 * len(SPONSOR_ID),  [5+len1] + [ 5 + len2]
		 * SPONSOR_ID) [5+len1] + [5+len2] + 5
		 */
		strncpy(sdf_idx, ((char *)(&(pcc_t->adc_idx))+5),
					*(uint8_t *)(&(pcc_t->adc_idx)+1));

		offset = *(uint8_t *)((char *)(&(pcc_t->adc_idx))+ 5 +
							*(uint8_t *)(&(pcc_t->adc_idx)+1));

		strncpy(pcc->rule_name, ((char *)(&(pcc_t->adc_idx)) + 6 +
					*(uint8_t *)(&(pcc_t->adc_idx)+1)), offset);

		strncpy(pcc->sponsor_id, ((char *)(&(pcc_t->adc_idx)) + 7 +
					offset + *(uint8_t *)(&(pcc_t->adc_idx)+1)), MAX_LEN);

		len = *(uint8_t *)(&(pcc_t->adc_idx)+1);

		/**sdf indices are present only if adc is not present*/
		if(-1 == pcc->adc_idx){
			/* Convert array of sdf index value to integers */
			pcc->sdf_idx_cnt = get_sdf_indices(sdf_idx, pcc->sdf_idx);
		}
#ifdef PRINT_NEW_RULE_ENTRY
		print_pcc_val(pcc);
#endif  /* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case METER_RULE: {
		/**
		 * @brief Coverts zmq message into Meter Rules info
		 * ref.Doc : message_sdn_dp.docx
		 * section : Table No.13 Meter Table
		 */
		struct mtr_entry_t *mtr_t =
			&(zmqmsgbuf_rx->msg_union.mtr_entry_m);
		struct mtr_entry *mtr = &(rbuf->msg_union.mtr_entry);

		rbuf->mtype = MSG_MTR_ADD;
		rbuf->dp_id.id = DPN_ID;

		mtr->mtr_profile_index =
			rte_bswap16(mtr_t->meter_profile_index);
		mtr->mtr_param.cir = rte_bswap64(mtr_t->cir);
		mtr->mtr_param.cbs = rte_bswap64(mtr_t->cbs);
		mtr->mtr_param.ebs = rte_bswap64(mtr_t->ebs);
		mtr->metering_method = mtr_t->metering_method;
#ifdef PRINT_NEW_RULE_ENTRY
		print_mtr_val(mtr);
#endif  /* PRINT_NEW_RULE_ENTRY */
		break;
	}

	case SDF_RULE: {
		/**
		 * @brief Coverts zmq message into SDF Rules info
		 * ref.Doc : Message_sdn.docx
		 * section : Table No.14 SDF Table
		 */
		static uint8_t rule_id_t = 1;
		struct sdf_entry_t *sdf_t =
			&(zmqmsgbuf_rx->msg_union.sdf_entry_m);
		struct pkt_filter *sdf = &(rbuf->msg_union.pkt_filter_entry);

		rbuf->mtype = MSG_SDF_ADD;
		rbuf->dp_id.id = DPN_ID;

		sdf->pcc_rule_id = rule_id_t++;
		sdf->sel_rule_type = sdf_t->rule_type;

		switch (sdf->sel_rule_type) {
		case RULE_STRING:
			strncpy(sdf->u.rule_str,
					(char *)(&(sdf_t->rule_type) + 5),
					MAX_LEN);
			break;

		case FIVE_TUPLE:
			/*TODO: rule should be in struct five_tuple_rule
			 * This field is currently not used
			 */
			break;

		default:
			RTE_LOG_DP(ERR, DP, "UNKNOWN Rule Type: %d\n",
				sdf_t->rule_type);
			break;
		}
#ifdef PRINT_NEW_RULE_ENTRY
			print_sdf_val(sdf);
#endif  /* PRINT_NEW_RULE_ENTRY */
			break;
	}

	case DDN_ACK: {
		rbuf->mtype = MSG_DDN_ACK;
		rbuf->dp_id.id = DPN_ID;

		printf("ACK received from FPC..\n");
		break;
	}

	default:
		RTE_LOG_DP(ERR, DP, "UNKNOWN Message Type: %d\n", zmqmsgbuf_rx->type);
		break;

	}

	ret = process_comm_msg((void *)rbuf);
	if (ret < 0)
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_SYSTEM_FAILURE;
	else
		zmqmsgbuf_tx.msg_union.dpn_response.cause =
			GTPV2C_CAUSE_REQUEST_ACCEPTED;

	zmqmsgbuf_tx.type = DPN_RESPONSE;
	ret = do_zmq_mbuf_send(&zmqmsgbuf_tx);

	if (ret < 0)
		printf("do_zmq_mbuf_send failed for type: %"PRIu8"\n",
				zmqmsgbuf_rx->type);

	return ret;
}

static int
zmq_destroy(void)
{
	/*
	 * zmqsub destroy
	 */
	zmq_subsocket_destroy();
	return 0;
}

#endif		/* DP: SDN_ODL_BUILD */
#endif /* !CP_BUILD*/

#define IFACE_FILE "interface.cfg"

static void set_config_ip(struct in_addr *ip, const char *key,
                 struct rte_cfgfile *file, const char *section, const char *entry)
{
		entry = rte_cfgfile_get_entry(file, section, key);
		if (entry == NULL)
			rte_panic("%s not found in %s", key, IFACE_FILE);
		parse_arg_host(entry, ip);
}

#define SET_CONFIG_IP(ip, file, section, entry) \
	set_config_ip(&ip, #ip, file, section, entry)

static void set_config_port(uint16_t *port, const char *key,
                 struct rte_cfgfile *file, const char *section, const char *entry)
{
		entry = rte_cfgfile_get_entry(file, section, key);
		if (entry == NULL)
			rte_panic("%s not found in %s", key, IFACE_FILE);
		if (sscanf(entry, "%"SCNu16, port) != 1)
			rte_panic("Invalid %"PRIu16" in %s", *port, IFACE_FILE);
}

#define SET_CONFIG_PORT(port, file, section, entry) \
	set_config_port(&port, #port, file, section, entry)

static void read_interface_config(void)
{
	char iface_file[128] = {'\0'}; 
	sprintf(iface_file, "%s%s", config_update_base_folder, IFACE_FILE);
	struct rte_cfgfile *file = rte_cfgfile_load(iface_file, 0);
	char *file_entry = NULL;

	if (file == NULL)
		rte_exit(EXIT_FAILURE, "Cannot load configuration profile %s\n",
				iface_file);

#ifndef SDN_ODL_BUILD /* Communication over the UDP */
	SET_CONFIG_IP(dp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(dp_comm_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_comm_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_comm_port, file, "0", file_entry);

#ifdef ZMQ_COMM
	const char *zmq_proto = "tcp";

#if ZMQ_DIRECT
#if defined (CP_BUILD) && defined (MULTI_UPFS)
	/* init the upf list */
	TAILQ_INIT(&upf_list);
	RTE_SET_USED(zmq_proto);
	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);
#elif defined (MULTI_UPFS)
	RTE_SET_USED(zmq_proto);
	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);
	SET_CONFIG_IP(zmq_dp_ip, file, "0", file_entry);
	SET_CONFIG_IP(zmq_cp_ip, file, "0", file_entry);
#endif
	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(dp_comm_ip), dp_comm_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(cp_comm_ip), cp_comm_port);
#else
#ifdef CP_BUILD
	SET_CONFIG_IP(zmq_cp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_push_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_cp_pull_port, file, "0", file_entry);

#ifdef MULTI_UPFS
	/* init the upf list */
	RTE_SET_USED(zmq_proto);
	TAILQ_INIT(&upf_list);
	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);
#else
	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_cp_ip), zmq_cp_push_port);
#endif
#else
	SET_CONFIG_IP(zmq_dp_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_pull_port, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_dp_push_port, file, "0", file_entry);

	snprintf(zmq_pull_ifconnect, sizeof(zmq_pull_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_pull_port);

	snprintf(zmq_push_ifconnect, sizeof(zmq_push_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_dp_ip), zmq_dp_push_port);
#ifdef MULTI_UPFS
	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);
#endif
#endif

#endif  /* ZMQ_DIRECT */

#endif  /* ZMQ_COMM */
#else   /* Communication over the ZMQ */

	const char *zmq_proto = "tcp";
	struct in_addr zmq_sub_ip;
	struct in_addr zmq_pub_ip;
	uint16_t zmq_sub_port;
	uint16_t zmq_pub_port;

	SET_CONFIG_IP(fpc_ip, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_port, file, "0", file_entry);
	SET_CONFIG_PORT(fpc_topology_port, file, "0", file_entry);

	SET_CONFIG_IP(cp_nb_ip, file, "0", file_entry);
	SET_CONFIG_PORT(cp_nb_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_sub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_sub_port, file, "0", file_entry);

	SET_CONFIG_IP(zmq_pub_ip, file, "0", file_entry);
	SET_CONFIG_PORT(zmq_pub_port, file, "0", file_entry);

	snprintf(zmq_sub_ifconnect, sizeof(zmq_sub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_sub_ip), zmq_sub_port);
	snprintf(zmq_pub_ifconnect, sizeof(zmq_pub_ifconnect),
		"%s://%s:%u", zmq_proto, inet_ntoa(zmq_pub_ip), zmq_pub_port);

#endif

#ifdef SGX_CDR
	app.dealer_in_ip = rte_cfgfile_get_entry(file, "0",
			DEALERIN_IP);
	app.dealer_in_port = rte_cfgfile_get_entry(file, "0",
			DEALERIN_PORT);
	app.dealer_in_mrenclave = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRENCLAVE);
	app.dealer_in_mrsigner = rte_cfgfile_get_entry(file, "0",
			DEALERIN_MRSIGNER);
	app.dealer_in_isvsvn = rte_cfgfile_get_entry(file, "0",
			DEALERIN_ISVSVN);
	app.dp_cert_path = rte_cfgfile_get_entry(file, "0",
			DP_CERT_PATH);
	app.dp_pkey_path = rte_cfgfile_get_entry(file, "0",
			DP_PKEY_PATH);
#endif /* SGX_CDR */
}

/**
 * @brief Initialize iface message passing
 *
 * This function is not thread safe and should only be called once by DP.
 */
void iface_module_constructor(void)
{
	/* Read and store ip and port for socket communication between cp and
	 * dp*/
	read_interface_config();
#ifdef ZMQ_COMM
	char command[100];
#endif
	read_interface_config();

#ifdef ZMQ_COMM
#ifdef CP_BUILD
	snprintf(command, sizeof(command),
			        "%s %s%s%s%u%s", "timeout 1 bash -c", "'cat < /dev/null > /dev/tcp/", inet_ntoa(zmq_cp_ip), "/", zmq_cp_push_port, "' > /dev/null 2>&1");
#else
	snprintf(command, sizeof(command),
			        "%s %s%s%s%u%s", "timeout 1 bash -c", "'cat < /dev/null > /dev/tcp/", inet_ntoa(zmq_dp_ip), "/", zmq_dp_push_port, "' > /dev/null 2>&1");
#endif
#ifndef ZMQ_DIRECT
	if((system(command)) > 0) {
		rte_exit(EXIT_FAILURE, "ZMQ Streamer not running, Please start ZMQ Streamer service...\n");
	} else {
		printf("ZMQ Streamer running... CUPS connectivity opened....\n");
	}
#endif /* ZMQ_DIRECT */
#endif /* ZMQ_COMM */

#ifdef CP_BUILD
	printf("IFACE: CP Initialization\n");
#if defined SDN_ODL_BUILD
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				NULL,
				NULL);
	set_comm_type(COMM_SOCKET);
#else
#ifdef ZMQ_COMM
#ifdef MULTI_UPFS
	register_comm_msg_cb(COMM_ZMQ,
			zmq_cp_init_socket,
			zmq_cp_send_socket,
			zmq_cp_recv_socket,
			zmq_cp_destroy);
#else
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
#endif
	set_comm_type(COMM_ZMQ);
#else   /* ZMQ_COMM */
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_cp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
	set_comm_type(COMM_SOCKET);
#endif  /* ZMQ_COMM */
#endif  /* SDN_ODL_BUILD  */
#else   /* CP_BUILD */
#ifndef SDN_ODL_BUILD
	RTE_LOG_DP(NOTICE, DP, "IFACE: DP Initialization\n");
#ifdef ZMQ_COMM
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);

	set_comm_type(COMM_ZMQ);
#else   /* ZMQ_COMM */
	register_comm_msg_cb(COMM_SOCKET,
				udp_init_dp_socket,
				udp_send_socket,
				udp_recv_socket,
				NULL);
#endif  /* ZMQ_COMM */
#else
/* Code Rel. Jan 30, 2017
* Note: PCC, ADC, Session table initial creation on the DP sent over UDP by CP
* Needs to be from SDN controller as code & data models evolve
* For Jan 30, 2017 release, for flow updates over SDN controller
* register ZMQSUB socket after dp_session_table_create.
*/
	register_comm_msg_cb(COMM_ZMQ,
			zmq_init_socket,
			zmq_send_socket,
			zmq_recv_socket,
			zmq_destroy);
#endif  /* SDN_ODL_BUILD */
#endif  /* !CP_BUILD */
}

void sig_handler(int signo)
{
	if (signo == SIGINT) {
#ifdef SDN_ODL_BUILD
#ifdef CP_BUILD
		close_nb();
#else
		zmq_status_goodbye();
#endif
#endif

#ifdef CP_BUILD
#ifdef SYNC_STATS
		retrive_stats_entry();
		close_stats();
#endif /* SYNC_STATS */
#endif

#ifndef CP_BUILD
		close(route_sock);
		cdr_close();
#ifdef USE_AF_PACKET
		mnl_socket_close(mnl_sock);
#endif /* USE_AF_PACKET */
#endif /* CP_BUILD */
#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
		print_perf_statistics();
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
		rte_exit(EXIT_SUCCESS, "received SIGINT\n");
	}
	else if (signo == SIGSEGV)
		rte_panic("received SIGSEGV\n");
}
