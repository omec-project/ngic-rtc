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
#include "zmqsub.h"

struct zmqbuf;

/**
 * @brief
 * creates zmq publisher message socket
 * @return
 * 0 to indicate success, error otherwise
 */
int zmq_pubsocket_create(void);

/**
 * @brief
 * destroys zmq publisher message socket
 */
void zmq_pubsocket_destroy(void);


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
int zmq_mbuf_send(struct zmqbuf *mbuf, uint32_t zmqbufsz);

#endif

