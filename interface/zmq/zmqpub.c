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

#include <netinet/in.h>

#include "zmqpub.h"
#include "zmqsub.h"

void *zmqpub_sockctxt;
void *zmqpub_socket;

int zmq_pubsocket_create(void)
{
	/* Socket to talk to server */
	zmqpub_sockctxt = zmq_ctx_new();
	zmqpub_socket = zmq_socket(zmqpub_sockctxt, ZMQ_PUB);
	int rc = zmq_connect(zmqpub_socket, zmq_pub_ifconnect);

	assert(rc == 0);

	printf("Publisherer connected- server:\t%s\t\t; device:\t%s\n",
			zmq_pub_ifconnect, ZMQ_DEV_ID);
	return rc;
}

void zmq_pubsocket_destroy(void)
{
	zmq_close(zmqpub_socket);
	zmq_ctx_destroy(zmqpub_sockctxt);
}

int zmq_mbuf_send(struct zmqbuf *mbuf, uint32_t zmqbufsz)
{
	int rc = zmq_send(zmqpub_socket, mbuf, zmqbufsz, 0);

	PRINT_ZMQBUF(mbuf, zmqbufsz);

	return rc;
}

