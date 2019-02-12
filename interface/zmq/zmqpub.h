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

