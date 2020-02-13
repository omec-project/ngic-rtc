/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <netinet/in.h>

#include "zmq_push_pull.h"

void *zmqpull_sockctxt;
void *zmqpull_sockcet;
void *zmqpush_sockctxt;
void *zmqpush_sockcet;

int zmq_pull_create(void)
{
	/* Socket to talk to Client */
	zmqpull_sockctxt = zmq_ctx_new();
	zmqpull_sockcet = zmq_socket(zmqpull_sockctxt, ZMQ_PULL);

#ifdef CP_BUILD
#if ZMQ_DIRECT
	int rc = zmq_bind(zmqpull_sockcet, zmq_push_ifconnect);
	assert(rc == 0);

	printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
			zmq_push_ifconnect, ZMQ_DEV_ID);
#else
	int rc = zmq_connect(zmqpull_sockcet, zmq_pull_ifconnect);
	assert(rc == 0);

	printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
			zmq_pull_ifconnect, ZMQ_DEV_ID);
#endif /* ZMQ_DIRECT */
#else
#if ZMQ_DIRECT
	int rc = zmq_bind(zmqpull_sockcet, zmq_pull_ifconnect);
	assert(rc == 0);

	printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
			zmq_pull_ifconnect, ZMQ_DEV_ID);
#else
        int rc = zmq_connect(zmqpull_sockcet, zmq_pull_ifconnect);
	assert(rc == 0);

	printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
	zmq_pull_ifconnect, ZMQ_DEV_ID);
#endif /* ZMQ_DIRECT */
#endif	/* CP_BUILD */

	return rc;
}

int
zmq_push_create(void)
{
	/* Socket to talk to Server */
	zmqpush_sockctxt = zmq_ctx_new();
	zmqpush_sockcet = zmq_socket(zmqpush_sockctxt, ZMQ_PUSH);

#ifdef CP_BUILD
#if ZMQ_DIRECT
	int rc = zmq_connect(zmqpush_sockcet, zmq_pull_ifconnect);
	assert(rc == 0);

	printf("ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
			zmq_pull_ifconnect, ZMQ_DEV_ID);
#else
	int rc = zmq_connect(zmqpush_sockcet, zmq_push_ifconnect);
	assert(rc == 0);

	printf("ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
			zmq_push_ifconnect, ZMQ_DEV_ID);
#endif /* ZMQ_DIRECT */
#else
        int rc = zmq_connect(zmqpush_sockcet, zmq_push_ifconnect);
	assert(rc == 0);

	printf("ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
	                zmq_push_ifconnect, ZMQ_DEV_ID);
#endif  /* CP_BUILD */

	return rc;
}

void
zmq_push_pull_destroy(void)
{
	zmq_close(zmqpull_sockcet);
	zmq_close(zmqpush_sockcet);
	zmq_ctx_destroy(zmqpull_sockctxt);
	zmq_ctx_destroy(zmqpush_sockctxt);
}

int
zmq_mbuf_push(void *mbuf, uint32_t zmqbufsz)
{
	return zmq_send(zmqpush_sockcet, mbuf, zmqbufsz, 0);
}

int
zmq_mbuf_pull(void *buf, uint32_t zmqbufsz)
{
	return zmq_recv(zmqpull_sockcet, buf, zmqbufsz, 0);
}
