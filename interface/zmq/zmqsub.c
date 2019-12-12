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

#include <stdlib.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>

#include <rte_byteorder.h>
#include <rte_debug.h>

#include "zmqsub.h"
#include "zmqpub.h"
#include "up_main.h"

static void *zmqsub_sockctxt;
static void *zmqsub_socket;
char node_id[MAX_NODE_ID_SIZE];
static char network_id[MAX_NETWORK_ID_SIZE];
static uint8_t dpn_topic_id;
static uint8_t controller_topic_id;
static uint32_t source;

enum {
	INIT,			/* Initial State */
	ASSIGN_TOPIC_WAIT,	/* Awaiting Topic Assignment */
	STATUS_WAIT,		/* Awaiting Status ack */
	DPN_ALIVE,		/* Ready to rec messages from controller */
	DPN_DYING		/* Goodbye sent, awaiting ack receipt */
} dpn_lifecycle_state = INIT;

/** For use when dpn_lifecycle_state = ASSIGN_TOPIC_WAIT */
static time_t assign_topic_time;

extern struct app_params app;
#define ASSIGN_TOPIC_TIMEOUT 10

#if ZMQSUB_DEBUG
void
hex_dump(FILE *fileptr, void *base, void *data, size_t length, int indent) {
	uint8_t *c = (uint8_t *)data;
	uint32_t i = 0;
	uint32_t base_val = (base <= data ?
			(uint32_t)((uint8_t *)data - (uint8_t *)base) : 0);
	while (i < length) {
		/* 1         2         3         4         ~50
		 * 01234567890123456789012345678901234567890123456789
		 * 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f
		 */
		char bytes[50];
		char chars[18];

		do {
			if (i < length) {
				sprintf(bytes + 3 * (i % 16) +
						1 * (i % 16 > 7 ? 1 : 0),
						"%02x%s",
						c[i],
						(i % 16 == 7 ? "    " : " "));
				sprintf(chars + (i % 16) +
						1 * (i % 16 > 7 ? 1 : 0),
						"%c%s",
						isalnum(c[i]) ? c[i] : '.',
						(i % 16 == 7 ? "    " : " "));
			} else {
				i += 16 - i % 16;
				break;
			}
			++i;
		} while (i % 16);

		fprintf(fileptr, "%*s[%4.4x]  %-50.50s  %s\n", indent, "",
				i - i % 16 - 16 + base_val, bytes, chars);
	}
	fprintf(fileptr, "\n");
}

#define rte_bswap8(v) (v)
#define PRINT_MEMBER_WIDTH 17
#define PRINT_MEMBER(m, mem, size) \
		printf("\t%-*s: %"PRIu##size"\n", PRINT_MEMBER_WIDTH, \
			#mem, rte_bswap##size(m->mem))

void print_zmqbuf(struct zmqbuf *buf)
{
	switch (buf->type) {
	case CREATE_SESSION:
	{
		struct create_session_t *m = &buf->msg_union.create_session_msg;

		puts("\tCREATE_SESSION");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, imsi, 64);
		PRINT_MEMBER(m, default_ebi, 8);
		PRINT_MEMBER(m, ue_ipv4, 32);
		PRINT_MEMBER(m, s1u_sgw_teid, 32);
		PRINT_MEMBER(m, s1u_sgw_ipv4, 32);
		PRINT_MEMBER(m, session_id, 64);
		PRINT_MEMBER(m, controller_topic, 32);
		PRINT_MEMBER(m, client_id, 32);
		PRINT_MEMBER(m, op_id, 32);
		break;
	}
	case MODIFY_BEARER:
	{
		struct modify_bearer_t *m = &buf->msg_union.modify_bearer_msg;

		puts("\tMODIFY_BEARER");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, s1u_enodeb_ipv4, 32);
		PRINT_MEMBER(m, s1u_enodeb_teid, 32);
		PRINT_MEMBER(m, s1u_sgw_ipv4, 32);
		PRINT_MEMBER(m, session_id, 64);
		PRINT_MEMBER(m, controller_topic, 8);
		PRINT_MEMBER(m, client_id, 32);
		PRINT_MEMBER(m, op_id, 32);
		break;
	}
	case DELETE_SESSION:
	{
		struct delete_session_t *m = &buf->msg_union.delete_session_msg;

		puts("\tDELETE_SESSION");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, session_id, 64);
		PRINT_MEMBER(m, controller_topic, 32);
		PRINT_MEMBER(m, client_id, 32);
		PRINT_MEMBER(m, op_id, 32);
		break;
	}
	case DPN_RESPONSE:
	{
		struct dpn_response_t *m = &buf->msg_union.dpn_response;

		puts("\tDPN_RESPONSE");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, cause, 8);
		PRINT_MEMBER(m, client_id, 32);
		PRINT_MEMBER(m, op_id, 32);
		break;
	}
	case DDN:
	{
		struct ddn_t *m = &buf->msg_union.ddn;

		puts("\tDDN");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, session_id, 64);
		PRINT_MEMBER(m, client_id, 32);
		PRINT_MEMBER(m, op_id, 32);
		break;
	}
	case ASSIGN_TOPIC:
	{
		struct assign_topic_t *m = &buf->msg_union.assign_topic_msg;

		puts("\tASSIGN_TOPIC");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, topic_generated, 32);
		PRINT_MEMBER(m, source, 32);
		break;
	}
	case ASSIGN_CONFLICT:
	{
		struct assign_topic_t *m = &buf->msg_union.assign_topic_msg;

		puts("\tASSIGN_CONFLICT");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, topic_generated, 32);
		PRINT_MEMBER(m, source, 32);
		break;
	}
	case DPN_STATUS_INDICATION:
	{
		struct status_indication_t *m =
				&buf->msg_union.status_indication;

		puts("\tDPN_STATUS_INDICATION");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, source_topic_id, 8);
		PRINT_MEMBER(m, status, 8);
		PRINT_MEMBER(m, source, 32);

		break;
	}
	case CONTROLLER_STATUS_INDICATION:
	{
		struct status_indication_t *m =
				&buf->msg_union.status_indication;

		puts("\tCONTROLLER_STATUS_INDICATION");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, source_topic_id, 8);
		PRINT_MEMBER(m, status, 8);
		PRINT_MEMBER(m, source, 32);

		break;
	}
	case DPN_STATUS_ACK:
	{
		struct dpn_status_ack_t *m = &buf->msg_union.dpn_status_ack;

		puts("\tDPN_STATUS_ACK");
		PRINT_MEMBER(buf, topic_id, 8);
		PRINT_MEMBER(buf, type, 8);
		PRINT_MEMBER(m, controller_topic, 32);
		PRINT_MEMBER(m, source, 32);
		break;
	}
	}
}
#endif


uint8_t get_network_node_var_length(uint8_t *node_id_len_ptr)
{
	uint8_t *network_id_len_ptr = node_id_len_ptr +
			sizeof(uint8_t) + *node_id_len_ptr;

	return *node_id_len_ptr + sizeof(*node_id_len_ptr) +
			*network_id_len_ptr + sizeof(*network_id_len_ptr);
}

int
do_zmq_mbuf_send(struct zmqbuf *mbuf)
{
	size_t message_length = 0;

	switch (mbuf->type) {
	case ASSIGN_TOPIC:
	case ASSIGN_CONFLICT:
		message_length = sizeof(mbuf->topic_id) +
			sizeof(mbuf->type) +
			offsetof(struct assign_topic_t, node_network_id_buffer);
		message_length += get_network_node_var_length(
					mbuf->msg_union.assign_topic_msg.
					node_network_id_buffer);
		break;
	case DPN_STATUS_INDICATION:
		message_length = sizeof(mbuf->topic_id) +
			sizeof(mbuf->type) +
			offsetof(struct status_indication_t,
					node_network_id_buffer);
		message_length += get_network_node_var_length(
					mbuf->msg_union.status_indication.
					node_network_id_buffer);
		break;
	case DPN_RESPONSE:
		message_length = sizeof(mbuf->topic_id) +
			sizeof(mbuf->type) +
			sizeof(struct dpn_response_t);
		break;
	case DDN:
		message_length = sizeof(mbuf->topic_id) +
			sizeof(mbuf->type)  +
			offsetof(struct ddn_t, node_network_id_buffer);
		message_length += get_network_node_var_length(
					mbuf->msg_union.ddn.
					node_network_id_buffer);
		break;

	default:
	return -1;
	}

	return zmq_mbuf_send(mbuf, message_length);
}

/**
 * @brief
 * helper function to set network identifier and node identifier in zmq messages
 * @param node_id_len_ptr
 * beginning location to set network and node identifiers
 */
static void zmq_set_network_node_id(uint8_t *node_id_len_ptr)
{
	char *node_id_ptr = node_id_len_ptr + 1;
	*node_id_len_ptr = strlen(node_id);
	memcpy(node_id_ptr, node_id, *node_id_len_ptr);

	uint8_t *network_id_len_ptr = node_id_ptr + strlen(node_id);
	*network_id_len_ptr = strlen(network_id);
	char *network_id_ptr = network_id_len_ptr + 1;
	memcpy(network_id_ptr, network_id, *network_id_len_ptr);
}

/**
 * @brief
 * processes assign conflict messages and handles the case where another node
 * attempts to use provisioned topic identifier
 * @param mbuf
 * message containing assign conflict
 */
static void zmq_assign_conflict(struct zmqbuf *mbuf)
{
	/* ASSIGN_TOPIC and ASSIGN_CONFLICT message structures are same as of
	 * now, so reuse the current buffer and just change the fields
	 */
	mbuf->type = ASSIGN_CONFLICT;
	mbuf->msg_union.assign_topic_msg.source = source;
	zmq_set_network_node_id(
		mbuf->msg_union.assign_topic_msg.node_network_id_buffer);
	do_zmq_mbuf_send(mbuf);
}

/**
 * @brief
 * assings topic identifier to be used by zmq messaging for this data plane node
 */
static void zmq_assign_topic(void)
{
	/* TODO: seed random for topic number - not seeding yet for testing */
	dpn_topic_id = (rand() % (UINT8_MAX - 4)) + 4; /* Valid range (4-255) */

	snprintf(node_id, MAX_NODE_ID_SIZE, "node%"PRIu8, dpn_topic_id);
	snprintf(network_id, MAX_NETWORK_ID_SIZE,
			"network%"PRIu8, dpn_topic_id);

	assign_topic_time = time(NULL);

	struct zmqbuf assign_topic_time = {
			.topic_id = BROADCAST_ALL_TOPIC,
			.type = ASSIGN_TOPIC,
			.msg_union.assign_topic_msg = {
					.topic_generated = dpn_topic_id,
					.source = source,
			}
	};
	zmq_set_network_node_id(assign_topic_time.msg_union.
			assign_topic_msg.node_network_id_buffer);

	do_zmq_mbuf_send(&assign_topic_time);
}

static void zmq_status_hello(void)
{
	struct zmqbuf hello = {
			.topic_id = BROADCAST_CONTROLLERS,
			.type = DPN_STATUS_INDICATION,
			.msg_union.status_indication = {
					.source_topic_id = dpn_topic_id,
					.status = HELLO,
					.source = source,
					.dpn_type = app.spgw_cfg,
			},
	};


	zmq_set_network_node_id(hello.msg_union.
			status_indication.node_network_id_buffer);

	do_zmq_mbuf_send(&hello);
}

void zmq_status_goodbye(void)
{
	dpn_lifecycle_state = DPN_DYING;

	struct zmqbuf bye = {
			.topic_id = BROADCAST_CONTROLLERS,
			.type = DPN_STATUS_INDICATION,
			.msg_union.status_indication = {
					.source_topic_id = dpn_topic_id,
					.status = GOODBYE,
					.source = source,
			},
	};


	zmq_set_network_node_id(&bye.msg_union.
			status_indication.node_network_id_buffer[0]);

	do_zmq_mbuf_send(&bye);
}

void zmq_ddn(uint64_t sess_id, uint32_t client_id)
{
	struct zmqbuf buf = {
			.topic_id = controller_topic_id,
			.type = DDN,
			.msg_union.ddn = {
					.session_id = rte_bswap64(sess_id),
					.client_id = client_id,
					.op_id = rand(),
			},

	};

	zmq_set_network_node_id(&buf.msg_union.
			ddn.node_network_id_buffer[0]);

	do_zmq_mbuf_send(&buf);
}

int zmq_subsocket_create(void)
{
	/* Socket to talk to server */
	zmqsub_sockctxt = zmq_ctx_new();
	zmqsub_socket = zmq_socket(zmqsub_sockctxt, ZMQ_SUB);
	int rc = zmq_setsockopt(zmqsub_socket, ZMQ_SUBSCRIBE, "", 0);
	assert(rc == 0);

	rc = zmq_connect(zmqsub_socket, zmq_sub_ifconnect);
	assert(rc == 0);
	printf("Subscriber connected- server:\t%s\t\t; device:\t%s\n",
			zmq_sub_ifconnect, ZMQ_DEV_ID);
	srand((int)time(NULL));
	source = rand();

	sleep(2);
	rc = zmq_mbuf_send((struct zmqbuf *)ZMQ_DEV_SIG, strlen(ZMQ_DEV_SIG));

	dpn_lifecycle_state = ASSIGN_TOPIC_WAIT;
	zmq_assign_topic();

	return rc;
}

void zmq_subsocket_destroy(void)
{
	zmq_close(zmqsub_socket);
	zmq_ctx_destroy(zmqsub_sockctxt);
}

void check_topic_id_conflict(struct zmqbuf *mbuf)
{
	if (mbuf->msg_union.assign_topic_msg.topic_generated == dpn_topic_id &&
			mbuf->msg_union.assign_topic_msg.source != source) {
		printf("Got ASSIGN Topic with conflict\n");
		/* This topic id has already been assigned to this DPN.
		 * So send ASSIGN_CONFLICT
		 */
		zmq_assign_conflict(mbuf);
	}
}

void handle_controller_hello(struct zmqbuf *mbuf)
{
	if (mbuf->msg_union.status_indication.source != source &&
			mbuf->msg_union.status_indication.status == HELLO) {
		printf("Got STATUS Indication\n");
		/* HELLO has arrived from CONTROLLER, so send HELLO to
		 * controller. The DPN is still in STATUS_WAIT state
		 */
		zmq_status_hello();
		dpn_lifecycle_state = STATUS_WAIT;
	}
}

int zmq_mbuf_rcv(struct zmqbuf *buf, uint32_t zmqbufsz)
{
	int flag = (dpn_lifecycle_state == INIT ||
			dpn_lifecycle_state == ASSIGN_TOPIC_WAIT) ?
			ZMQ_DONTWAIT : 0;

	return zmq_recv(zmqsub_socket, buf, zmqbufsz, flag);
}

int dp_lifecycle_process(struct zmqbuf *mbuf, int rc)
{
	switch (mbuf->type) {
	case ASSIGN_TOPIC:
		check_topic_id_conflict(mbuf);
		PRINT_ZMQBUF_MESSAGE(mbuf, rc, "ASSIGN_TOPIC");
		return 0;
	case CONTROLLER_STATUS_INDICATION:
		handle_controller_hello(mbuf);
		PRINT_ZMQBUF_MESSAGE(mbuf, rc, "CONTROLLER_STATUS_INDICATION");
		return 0;
	case DPN_RESPONSE:
		PRINT_ZMQBUF_MESSAGE(mbuf, rc, "DPN_RESPONSE");
		return 0;
	}
	switch (dpn_lifecycle_state) {
	case ASSIGN_TOPIC_WAIT:
		if (rc == -1 && errno == EAGAIN) {
			time_t elapsed = time(NULL) - assign_topic_time;

			if (elapsed < ASSIGN_TOPIC_TIMEOUT)
				return 0;

			/* else ASSIGN_TOPIC_TIMEOUT'd */
			zmq_status_hello();
			dpn_lifecycle_state = STATUS_WAIT;
		} else if (mbuf->topic_id == BROADCAST_ALL_TOPIC &&
				mbuf->type == ASSIGN_CONFLICT) {
			PRINT_ZMQBUF_MESSAGE(mbuf, rc,
					"Topic-id Conflict");
			zmq_assign_topic();
		}
		break;
	case STATUS_WAIT:
		if (mbuf->topic_id == dpn_topic_id &&
				mbuf->type == DPN_STATUS_ACK) {
			PRINT_ZMQBUF_MESSAGE(mbuf, rc, "recv on hello");
			controller_topic_id =
				mbuf->msg_union.
				dpn_status_ack.controller_topic;
			dpn_lifecycle_state = DPN_ALIVE;
			printf("%s on %s initialized with topic_id %"
					PRIu8" talking to controller on"
					" topic_id %"PRIu8"\n.",
					node_id, network_id,
					dpn_topic_id,
					controller_topic_id);
			return 0;
		}
		PRINT_ZMQBUF(mbuf, rc);
		break;
	case DPN_ALIVE:
		/* DPN is ready to receive session create/update/delete
		 * messages. Process as usual.
		 */
		PRINT_ZMQBUF(mbuf, rc);
		if (mbuf->topic_id == dpn_topic_id)
			return rc;
		break;
	/* default: ignore message */

	}
	return -1;
}
