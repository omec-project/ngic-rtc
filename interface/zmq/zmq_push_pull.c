/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <netinet/in.h>

#include "zmq_push_pull.h"

#if defined (CP_BUILD) && defined (MULTI_UPFS)
/* assuming that we can only monitor MAX_UPFS number of UPFs at the moment */
zmq_pollitem_t zmq_items[MAX_UPFS] = {0};

int zmq_pull_create(void)
{
	struct upf_context *upf;
	int rc, i = 1;

	TAILQ_FOREACH(upf, &upf_list, entries) {
		/* Socket to talk to Client */
		upf->zmqpull_sockctxt = zmq_ctx_new();
		upf->zmqpull_sockcet = zmq_socket(upf->zmqpull_sockctxt, ZMQ_PULL);
#if ZMQ_DIRECT
		rc = zmq_bind(upf->zmqpull_sockcet, upf->zmq_push_ifconnect);
		assert(rc == 0);

		printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
		       upf->zmq_push_ifconnect, ZMQ_DEV_ID);
#else
		rc = zmq_connect(upf->zmqpull_sockcet, upf->zmq_pull_ifconnect);
		assert(rc == 0);

		printf("ZMQ Server connect to:\t%s\t\t; device:\t%s\n",
		       upf->zmq_pull_ifconnect, ZMQ_DEV_ID);
#endif
		zmq_items[i].socket = upf->zmqpull_sockcet;
		zmq_items[i].events = ZMQ_POLLIN;

		i++;
	}
	return rc;
}

int
zmq_push_create(void)
{
	struct upf_context *upf;
	int rc;

	TAILQ_FOREACH(upf, &upf_list, entries) {
		/* Socket to talk to Server */
		upf->zmqpush_sockctxt = zmq_ctx_new();
		upf->zmqpush_sockcet = zmq_socket(upf->zmqpush_sockctxt, ZMQ_PUSH);
#if ZMQ_DIRECT
		rc = zmq_connect(upf->zmqpush_sockcet, upf->zmq_pull_ifconnect);
		assert(rc == 0);

		printf("ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
		       upf->zmq_pull_ifconnect, ZMQ_DEV_ID);
#else
		rc = zmq_connect(upf->zmqpush_sockcet, upf->zmq_push_ifconnect);
		assert(rc == 0);

		printf("ZMQ Client connect to:\t%s\t\t; device:\t%s\n",
		       upf->zmq_push_ifconnect, ZMQ_DEV_ID);
#endif
	}
	return rc;
}

void
zmq_push_pull_destroy(struct upf_context *upf)
{
	zmq_close(upf->zmqpull_sockcet);
	zmq_close(upf->zmqpush_sockcet);
	zmq_ctx_destroy(upf->zmqpull_sockctxt);
	zmq_ctx_destroy(upf->zmqpush_sockctxt);
}

int
zmq_mbuf_push(struct upf_context *upf, void *mbuf, uint32_t zmqbufsz)
{
	return zmq_send(upf->zmqpush_sockcet, mbuf, zmqbufsz, 0);
}

int
zmq_mbuf_pull(struct upf_context *upf, void *buf, uint32_t zmqbufsz)
{
	return zmq_recv(upf->zmqpull_sockcet, buf, zmqbufsz, 0);
}

#else
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
#endif /* MULTI_UPFS */
