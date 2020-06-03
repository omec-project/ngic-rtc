/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _ZMQPUB_H
#define _ZMQPUB_H

#define ZMQ_PUB_PORT
#define ZMQ_MSG_BUF_PARSE
#define ZMQ_DEV_ID "DPN1"

#include <zmq.h>

#include <assert.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>

#include "interface.h"

/* ZMQ_DIRECT enable the direct communication between CP-DP. */
#define ZMQ_DIRECT 1

struct zmqbuf;

/* s11 interface message type */
enum s11_msgtype {
	CREATE_SESSION = 1,
	MODIFY_BEARER = 2,
	DELETE_SESSION = 3,
	DPN_RESPONSE = 4,
	DDN = 5,
	ADC_RULE = 17,
	PCC_RULE = 18,
	METER_RULE = 19,
	SDF_RULE = 20,
};

#if defined (CP_BUILD) && defined (MULTI_UPFS)
int zmq_push_create(void);
int zmq_pull_create(void);
void zmq_push_pull_destroy(struct upf_context *upf);
int zmq_mbuf_push(struct upf_context *upf, void *mbuf, uint32_t zmqbufsz);
int zmq_mbuf_pull(struct upf_context *upf, void *mbuf, uint32_t zmqbufsz);
extern zmq_pollitem_t zmq_items[MAX_UPFS];
#else
/**
 * @brief
 * creates zmq server(PUSH) message socket
 * @return
 * 0 to indicate success, error otherwise
 */
int zmq_push_create(void);

/**
 * @brief
 * creates zmq server(PULL) message socket
 * @return
 * 0 to indicate success, error otherwise
 */
int zmq_pull_create(void);

/**
 * @brief
 * destroys zmq server/socket (PUSH/PULL) message socket
 */
void zmq_push_pull_destroy(void);

/**
 * @brief
 * callback to send zmq message buffer
 * @param mbuf
 * message buffer to send
 * @param zmqbufsz
 * size of message buffer to send
 * @return
 * 0 to indicate success, error otherwise
 */
int zmq_mbuf_push(void *mbuf, uint32_t zmqbufsz);

/**
 * @brief
 * receives zmq message from Control-Plane
 * @param mbuf
 * zmq message buffer recieved
 * @param zmqbufsz
 * maximum size of zmq message recieved
 * @return
 * size of zmq message recieved
 */
int zmq_mbuf_pull(void *mbuf, uint32_t zmqbufsz);
#endif /* MULTI_UPFS */
#endif
