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
#define _GNU_SOURCE	/* To expose asprintf */
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <linux/tcp.h>
#include <fcntl.h>


#include <rte_common.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_hash_crc.h>
#include <rte_hash.h>

#include <curl/curl.h>
#include <json-c/json.h>

#include "nb.h"
#include "cp.h"
#include "interface.h"
#include "dp_ipc_api.h"
#include "cp_stats.h"
#include "packet_filters.h"
#include "cp_stats.h"


#define MESSAGE_BUFFER_SIZE (1 << 13)
#define OP_ID_HASH_SIZE     (1 << 15)


#define DO_CHECK_CURL_EASY_SETOPT(one, two, three) \
	do {\
		CURLcode res = curl_easy_setopt(one, two, three);\
		if (res != CURLE_OK) {\
			rte_panic("%s (%s:%d)\n", \
				curl_easy_strerror(res), \
				__func__, __LINE__);\
		} \
	} while (0)

/* #define DEBUG_NB */
#ifdef DEBUG_NB
#define DEBUG_PRINTF(...) DEBUG_PRINTF_(__VA_ARGS__, "dummy")
#define DEBUG_PRINTF_(format, ...) printf(format "%.0s", __VA_ARGS__)
#else
#define DEBUG_PRINTF(format, ...)
#endif

struct rte_hash *nb_op_id_hash;
uint64_t op_id;

char *client_id;
char *dpn_id;

fd_set fd_set_active;
fd_set fd_set_responded;
int request_fd = -1;
int server_fd = -1;
int response_fd = -1;
int notification_fd = -1;

int one = 1;

char message_buffer[MESSAGE_BUFFER_SIZE];

struct sse_handle_message_event_map {
	const char *event;
	void (*sse_handle_message_func)(json_object *d);
};


/**
 * @brief  : Sets the DPN for use on incoming session creation and management messages
 * @param  : dpn_id_from_json
 *           Data Plane Node Identifier string
 * @return : 0 on success, error otherwise
 */
static int
set_dpn_id(const char *dpn_id_from_json)
{
	if (dpn_id != NULL && dpn_id_from_json != NULL)
		return -1;
	if (dpn_id != NULL && dpn_id_from_json == NULL) {
		free(dpn_id);
		dpn_id = NULL;
		reset_cp_stats();
		return 0;
	}
	if (dpn_id == NULL && dpn_id_from_json == NULL)
		return 0;
	dpn_id = strdup(dpn_id_from_json);

	return 0;
}


/**
 * @brief  : Processes response from a get topology request made over HTTP with
 *           CURL calls - callback used by CURL
 * @param  : ptr
 *           data received
 * @param  : size
 *           size of data members received
 * @param  : nmemb
 *           number of members received
 * @param  : userdata
 * @return : number of bytes processed - 0 if partial message received
 */
static size_t
consume_topology_output(char *ptr, size_t size, size_t nmemb,
		__rte_unused void *userdata)
{
	json_bool ret;
	static char *object;
	int i;

	if (object == NULL) {
		object = calloc(1, (nmemb * size) + 1);
		strncpy(object, ptr, (size * nmemb));
	} else {
		char *tmp = object;
		object = calloc(1, strlen(tmp) + (size * nmemb) + 1);
		strcpy(object, tmp);
		strncat(object, ptr, (size * nmemb));
		free(tmp);
	}

	enum json_tokener_error error;
	json_object *jobj = json_tokener_parse_verbose(object, &error);
	if (jobj == NULL || error != json_tokener_success)
		return size * nmemb;

	clLog(clSystemLog, eCLSeverityDebug, "FPC Topology json obj:%s\n", \
			json_object_to_json_string_ext(jobj, \
				JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

	json_object *dpn_types_jobj;
	ret = json_object_object_get_ex(jobj, "dpn-types",
			&dpn_types_jobj);

	if (ret == FALSE || json_object_get_type(dpn_types_jobj) !=
			json_type_array) {
		free(object);
		object = NULL;
		json_object_put(jobj);
		return size * nmemb;
	}

	clLog(clSystemLog, eCLSeverityDebug, "Dpn-types json obj:%s\n", \
			json_object_to_json_string_ext(dpn_types_jobj, \
				JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

	int dpn_types_jobj_array_len = json_object_array_length(dpn_types_jobj);
	if (dpn_types_jobj_array_len > 0) {

		for (i = 0; i < dpn_types_jobj_array_len; ++i) {
			json_object *fpc_jobj =
					json_object_array_get_idx(dpn_types_jobj, i);

			json_object *dpns_jobj = NULL;
			ret = json_object_object_get_ex(fpc_jobj, "dpns", &dpns_jobj);
			if (json_object_get_type(dpns_jobj) != json_type_array) {
				free(object);
				object = NULL;
				json_object_put(jobj);
				return size * nmemb;
			}

			clLog(clSystemLog, eCLSeverityDebug, "Dpns List json obj:%s\n", \
					json_object_to_json_string_ext(dpns_jobj, \
						JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_PRETTY));

			int dpns_jobj_array_length = json_object_array_length(dpns_jobj);
			if (dpns_jobj_array_length > 0) {

				for (i = 0; i < dpns_jobj_array_length; ++i) {
					json_object *dpn_jobj =
							json_object_array_get_idx(dpns_jobj, i);

					/*Pickup first DP in list.
					 * Assumption:DPN list to be sorted by FPC based on load balancing etc*/
					json_object *dpn_id_jobj;
					ret = json_object_object_get_ex(dpn_jobj, "dpn-id",
							&dpn_id_jobj);
					if (ret == FALSE || json_object_get_type(dpn_id_jobj) !=
							json_type_string) {
						free(object);
						object = NULL;
						json_object_put(jobj);
						return size * nmemb;
					}

					if (dpn_id == NULL) {
						set_dpn_id(json_object_get_string(dpn_id_jobj));
						/* TODO: maintain list to allow multiple DPNs */
						break;
					}
				}
			}
		}
	}

	free(object);
	object = NULL;
	json_object_put(jobj);
	return size * nmemb;
}

/**
 * @brief  : Initalizes curl handle for get topology request
 * @param  : curl
 *           CURL handle to be used
 * @param  : list
 *           List of headers to be populated
 * @param  : request
 *           HTTP request method
 * @param  : uri_path
 *           URI of request
 * @param  : ip
 *           IP of server to handle request
 * @param  : port
 *           Port of server to handle request
 * @param  : write_callback
 *           Callback function to process response
 * @return : Returns nothing
 */
static void
init_curl(CURL **curl, struct curl_slist **list, const char *request,
		const char *uri_path, const struct in_addr ip,
		const uint16_t port, curl_write_callback write_callback) {
	char uri[256];

	clLog(clSystemLog, eCLSeverityDebug, "get-topology URI PATH:%s\n", uri_path);

	*curl = curl_easy_init();
	if (!*curl)
		rte_panic("curl_easy_init failed\n");

	curl_easy_reset(*curl);
	*list = curl_slist_append(*list, HTTP_HEADER_JSON);
	*list = curl_slist_append(*list, "Expect:");

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_USERPWD, UIDPWD);

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_CUSTOMREQUEST, request);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_HTTPHEADER, *list);
	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_WRITEFUNCTION, write_callback);

	snprintf(uri, sizeof(uri), "http://%s:%"PRIu16"%s", inet_ntoa(ip),
			port, uri_path);

	DO_CHECK_CURL_EASY_SETOPT(*curl, CURLOPT_URL, uri);
}


/**
 * @brief  : Function to request toplology from the FPC ODL plugin
 * @param  : No param
 * @return : Returns nothing
 */
static void
get_topology(void) {
	int ret;
	long res_code;
	CURL *curl_topology = NULL;
	struct curl_slist *topology_list = NULL;
	char URI_PATH[SDN_TOPOLOGY_URI_LEN] = SDN_TOPOLOGY_URI_PATH;

	curl_global_init(CURL_GLOBAL_ALL);

	switch(spgw_cfg) {
		case SGWC:
			init_curl(&curl_topology, &topology_list, HTTP_METHOD_GET,
					strcat(URI_PATH, "/dpn-types/sgwu"),
					fpc_ip, fpc_topology_port,
					&consume_topology_output);
			break;

		case PGWC:
			init_curl(&curl_topology, &topology_list, HTTP_METHOD_GET,
					strcat(URI_PATH, "/dpn-types/pgwu"),
					fpc_ip, fpc_topology_port,
					&consume_topology_output);
			break;

		case SAEGWC:
			init_curl(&curl_topology, &topology_list, HTTP_METHOD_GET,
					strcat(URI_PATH, "/dpn-types/spgw"),
					fpc_ip, fpc_topology_port,
					&consume_topology_output);
			break;

		default:
			rte_panic("ERROR : INVALID CP Type.\n");
	}

	ret = curl_easy_perform(curl_topology);
	if (ret != CURLE_OK) {
		clLog(clSystemLog, eCLSeverityCritical, "curl_easy_perform Error: %s\n",
				curl_easy_strerror(ret));
		return;
	}

	curl_easy_getinfo(curl_topology, CURLINFO_RESPONSE_CODE, &res_code);
	if (res_code != HTTP_CONTINUE &&
			res_code != HTTP_OK) {
		clLog(clSystemLog, eCLSeverityCritical, "CURL response %ld\n",
				res_code);
	}
}


/**
 * @brief  : Initializes the hash table used to account for NB messages by op_id
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_nb_op_id(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "nb_op_id_hash",
	    .entries = OP_ID_HASH_SIZE,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_hash_crc,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	nb_op_id_hash = rte_hash_create(&rte_hash_params);
	if (!nb_op_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

/**
 * @brief  : Adds the current op_id to the hash table used to account for NB Messages
 * @param  : No param
 * @return : Returns nothing
 */
static void
add_nb_op_id_hash(void)
{
	int ret;

	ret = rte_hash_add_key_data(nb_op_id_hash, (void *)&op_id, NULL);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "rte_hash_add_key_data failed for"
				" op_id %"PRIu64": %s (%u)\n",
				op_id, rte_strerror(abs(ret)), ret);
	} else {
		++cp_stats.nb_sent;
	}

	DEBUG_PRINTF("Added op_id; %"PRIu64"\n", op_id);

	++op_id;
}


/* Curretly we are simply accounting the config-result-notifications for
 * each message passed to the SDN Controller. In future, we will be
 * using this for retransmit original messages that the SDN Controller
 * does not respond to. Nothing is needed to be done for deleted
 * entries, but rather those that do not get deleted.
 */
/**
 * @brief  : Deletes the op_id from the hash table used to account for NB Messages
 * @param  : nb_op_id
 *           op_id received in a config-result-notification message to indicate message
 *           was received and processed by the FPC agent and DPN
 * @return : Returns nothing
 */
static void
del_nb_op_id(uint64_t nb_op_id)
{
	int ret = rte_hash_del_key(nb_op_id_hash, (void *)&nb_op_id);

	DEBUG_PRINTF("Deleting op_id; %"PRIu64"\n", nb_op_id);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "rte_hash_del_key failed for op_id %"PRIu64
				": %s (%u)\n",
				nb_op_id,
				rte_strerror(abs(ret)), ret);
	} else {
#ifdef SYNC_STATS
		update_stats_entry(nb_op_id, RESPONSE);
#endif /* SYNC_STATS */
		++cp_stats.nb_cnr;
	}
}


/**
 * @brief  : verifies that an op_id received within a response message on the NB
 *           was in fact used in the original request message on the NB interface
 * @param  : nb_op_id
 *           op_id received in a config-result-notification message to indicate message
 *           was received and processed by the FPC agent and DPN
 * @return : Returns nothing
 */
static void
check_nb_op_id(uint64_t nb_op_id)
{
	int ret = rte_hash_lookup(nb_op_id_hash, (void *)&nb_op_id);

	DEBUG_PRINTF("Checked op_id; %"PRIu64"\n", nb_op_id);

	if (ret == -ENOENT) {
		clLog(clSystemLog, eCLSeverityCritical, "rte_hash_lookup failed for op_id %"PRIu64
				": %s (%u)\n",
				nb_op_id,
				rte_strerror(abs(ret)), ret);
	} else {
#ifdef SYNC_STATS
		update_stats_entry(nb_op_id, ACK);
#endif /* SYNC_STATS */
		++cp_stats.nb_ok;
	}
}


/**
 * @brief  : creates a json_object for use in the notification stream request message
 * @param  : No param
 * @return : Returns created json object, NULL otherwise
 */
static json_object *
notification_stream_req_json(void)
{
	json_object *jobj;
	json_object *jstring;

	jobj = json_object_new_object();
	if (jobj == NULL)
		return NULL;

	jstring = json_object_new_string_len(client_id, strlen(client_id));
	if (jstring == NULL) {
		free(jobj);
		return NULL;
	}

	json_object_object_add(jobj, "client-id", jstring);
	return jobj;
}


/**
 * @brief  : creates a json_object for use in the response stream response message
 * @param  : No param
 * @return : Returns created json object, NULL otherwise
 */
static json_object *
response_stream_req_json(void)
{
	int ret;
	char *client_uri;
	json_object *jobj;
	json_object *jstring;

	ret = asprintf(&client_uri, "http://%s:%"PRIu16 REQUEST_PATH_STR,
			inet_ntoa(cp_nb_ip), cp_nb_port);
	if (ret < 0)
		return NULL;
	jobj = json_object_new_object();
	if (jobj == NULL) {
		free(client_uri);
		return NULL;
	}
	jstring = json_object_new_string_len(client_uri, strlen(client_uri));
	if (jstring == NULL) {
		free(client_uri);
		free(jobj);
		return NULL;
	}

	json_object_object_add(jobj, "client-uri", jstring);
	free(client_uri);
	return jobj;
}

/**
 * @brief  : sends a stream request message
 * @param  : fd, socket file descriptor used to send the request
 * @param  : path, URL path of request
 * @param  : jobj, json_object of the HTTP request message contents
 * @return : Returns nothing
 */
static void
request_stream(int fd, const char *path, json_object *jobj)
{
	int ret;
	const char *json_str;
	size_t buffer_len;
	int tx_bytes;

	if (jobj == NULL)
		rte_panic("%d\tJSON Object is NULL\n", fd);

	json_str = json_object_to_json_string(jobj);


	ret = snprintf(message_buffer, MESSAGE_BUFFER_SIZE,
			HTTP_METHOD_POST" %s "HTTP_V_1_1 CRLF
			"Host: %s:%"PRIu16 CRLF
			"Accept: */*" CRLF
			HTTP_HEADER_JSON CRLF
			HTTP_CONTENT_LENGTH "%zu" CRLF
			CRLF
			"%s",
			path,
			inet_ntoa(fpc_ip), fpc_port,
			strlen(json_str),
			json_str);

	if (ret < 0)
		rte_panic("%d\tStream request string allocation failed\n", fd);


	buffer_len = strlen(message_buffer);

	tx_bytes = send(fd, message_buffer, buffer_len, 0);

	if (tx_bytes < 0)
		clLog(clSystemLog, eCLSeverityCritical, "%d\tSending stream request failed: %s\n", fd,
				strerror(errno));


	if ((size_t)tx_bytes < buffer_len)
		clLog(clSystemLog, eCLSeverityCritical, "%d\tSending stream request error - "
				"sent less than expected: %s\n", fd,
				strerror(errno));


	DEBUG_PRINTF("\n\n%d\tSent stream request\n%s\n", fd, message_buffer);
}

/**
 * @brief  : handles the processing of a bind client response message
 * @param  : jobj, json_object contents from a bind client HTTP response
 * @return : Returns nothing
 */
static void
sse_handle_message_bind_client(json_object *jobj)
{
	int ret;
	json_object *output_jobj;
	json_object *client_id_jobj;
	json_object *notification_obj;

	ret = json_object_object_get_ex(jobj, "output", &output_jobj);
	if (ret == FALSE ||
			json_object_get_type(output_jobj) != json_type_object) {
		clLog(clSystemLog, eCLSeverityCritical, "Error parsing bind client response:\n%s\n",
				json_object_to_json_string(jobj));
		return;
	}

	ret = json_object_object_get_ex(output_jobj, "client-id",
			&client_id_jobj);
	if (ret == FALSE || json_object_get_type(client_id_jobj) !=
			json_type_string) {
		clLog(clSystemLog, eCLSeverityCritical, "Error parsing bind client response:\n%s\n",
				json_object_to_json_string(jobj));
		return;
	}

	if (client_id != NULL)
		free(client_id);

	client_id = strdup(json_object_get_string(client_id_jobj));
	if (client_id == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Error setting client id: %s\n",
				strerror(errno));
		return;
	}
	clLog(clSystemLog, eCLSeverityDebug,"Established client_id as '%s'\n", client_id);

	notification_obj = notification_stream_req_json();
	if (notification_obj == NULL)
		rte_panic("Error in creating notification json obj\n");

	request_stream(notification_fd, NOTIFICATION_PATH_STR,
			notification_obj);

	get_topology();

	json_object_put(notification_obj);
}

/**
 * @brief  : Creates and connects a socket to the FPC ODL plugin for use of a SSE stream
 * @param  : fd, file descriptor variable to be used for the socket to be created/connected
 * @return : Returns nothing
 */
static void
connect_stream(int *fd)
{
	int ret;
	struct sockaddr_in host;

	*fd = socket(AF_INET, SOCK_STREAM, 0);
	if (*fd == -1)
		rte_panic("%d\tResponse stream socket create failed\n",  *fd);

	host.sin_addr = fpc_ip;
	host.sin_family = AF_INET;
	host.sin_port = htons(fpc_port);

	ret = connect(*fd, (struct sockaddr *)&host, sizeof(host));


	if (ret < 0)
		rte_panic("%d\tConnect stream failed to %s:%"PRIu16" - %s\n",
				*fd, inet_ntoa(fpc_ip), fpc_port,
				strerror(errno));

	setsockopt(*fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));


	FD_SET(*fd, &fd_set_active);
}


/**
 * @brief  : creates the HTTP chunk containing an event_data pair message to be
 *           sent to the FPC ODL plugin
 * @param  : event, event string
 * @param  : data, data string
 * @return : A statically allocaed buffer containing the event/data pair encoded as a
 *           HTTP chuncked message
 */
static const char *
set_message_sse(const char *event, const char *data)
{
	char buffer[MESSAGE_BUFFER_SIZE];
	int ret;

	/* create HTTP chunk data contents */
	ret = snprintf(buffer, MESSAGE_BUFFER_SIZE,
			SSE_EVENT "%s" LF
			SSE_DATA  "%s" LF,
			event,
			data);

	if (ret < 0 || ret > MESSAGE_BUFFER_SIZE)
		return NULL;

	/* add chunk data HTTP chunk including chunk size and boundary */
	ret = snprintf(message_buffer, MESSAGE_BUFFER_SIZE,
			"%lx"CRLF "%s" CRLF,
			strlen(buffer), buffer);
	if (ret < 0 || ret > MESSAGE_BUFFER_SIZE)
		return NULL;

	return message_buffer;
}


/**
 * @brief  : sends a zero-sized HTTP chunk message to indicate the closing of a
 *           SSE connection
 * @param  : fd, file descriptor to send the message on
 * @return : 0 on success, error otherwise
 */
static int
close_sse(int fd)
{
	const char end_chunked_msg[] = "0" CRLF CRLF;
	size_t len = strlen(end_chunked_msg);
	int tx_bytes = send(fd, end_chunked_msg, len, 0);

	if (tx_bytes < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Sending of %s failed: %s\n",
				__func__, strerror(errno));
		return EXIT_FAILURE;
	}

	if ((size_t)tx_bytes < len) {
		clLog(clSystemLog, eCLSeverityCritical, "Sending of %s error - "
				"sent less than expected: %s\n",
				__func__, strerror(errno));
		return EXIT_FAILURE;
	}

	DEBUG_PRINTF("\n%d\tSent %d bytes of %zu\n", request_fd, tx_bytes, len);
	DEBUG_PRINTF("%*s", (int)len, buffer);

	return EXIT_SUCCESS;

}


/**
 * @brief  : wrapper to conduct error handling on sent SSE messages
 * @param  : fd, file descriptor to use for sending SSE message on NB interface
 * @param  : event, event string
 * @param  : data, data string
 * @param  : calling_func, function called - used to determine message type for debugging purposes
 * @return : 0 on success, error otherwise
 */
static int
send_sse(int fd, const char *event, const char *data, const char *calling_func)
{
	const char *buffer;
	int tx_bytes;
	size_t len;

	buffer = set_message_sse(event, data);
	if (buffer == NULL)
		return EXIT_FAILURE;


	len = strlen(buffer);
	tx_bytes = send(fd, buffer, len, 0);

	if (tx_bytes < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Sending of %s failed: %s\n",
				calling_func, strerror(errno));
		return EXIT_FAILURE;
	}

	if ((size_t)tx_bytes < len) {
		clLog(clSystemLog, eCLSeverityCritical, "Sending of %s error - "
				"sent less than expected: %s\n",
				calling_func, strerror(errno));
		return EXIT_FAILURE;
	}

	DEBUG_PRINTF("\n%d\tSent %d bytes of %zu\n", request_fd, tx_bytes, len);
	DEBUG_PRINTF("%*s", (int)len, buffer);

	return EXIT_SUCCESS;
}


/**
 * @brief  : sends bind client as an SSE message
 * @param  : No param
 * @return : 0 on success, error otherwise
 */
static int
bind_client_request(void)
{
	return send_sse(request_fd, SSE_BIND_CLIENT_EVENT,
			SSE_BIND_CLIENT_DATA, __func__);
}

/**
 * @brief  : sends HTTP response message indicating success - HTTP OK
 * @param  : fd, file descriptor to send the message on
 * @return : 0 on success, error otherwise
 */
static int
send_stream_response_ok(int fd)
{
	int tx_bytes;

	tx_bytes = send(fd, HTTP_REQUEST_STREAM_RESPONSE,
			strlen(HTTP_REQUEST_STREAM_RESPONSE), 0);
	if (tx_bytes < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\t%s send error: %s\n", fd, __func__,
				strerror(errno));
		FD_CLR(fd, &fd_set_active);
		close(fd);
		return EXIT_FAILURE;
	}
	DEBUG_PRINTF("%d\tSent:\n%s\n", fd, HTTP_REQUEST_STREAM_RESPONSE);

	return EXIT_SUCCESS;
}

/**
 * @brief  : sends HTTP response message some error condition
 * @param  : fd, file descriptor to send response
 * @param  : error, HTTP Error code  and description as a string
 * @param  : rx, message received causing the error
 * @return : Returns nothing
 */
static void
send_stream_response_error(int fd, const char *error, const char *rx)
{
	int tx_bytes;

	clLog(clSystemLog, eCLSeverityCritical, "\n\n%d\tUnexpected request: %s\n", fd, rx);

	tx_bytes = send(fd, error, strlen(error), 0);
	if (tx_bytes < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\t%s send error: %s\n", fd, __func__,
				strerror(errno));
		FD_CLR(fd, &fd_set_active);
		close(fd);
		return;
	}
	DEBUG_PRINTF("%d\tSent:\n%s\n", fd, HTTP_REQUEST_STREAM_RESPONSE);
}

/**
 * @brief  : server helper function to receive message and respond accordingly
 * @param  : fd, file descriptor to receive message
 * @return : 0 on success, error otherwise
 */
static int
serve_client_with_response(int fd)
{
	char buf[MESSAGE_BUFFER_SIZE] = {0};
	const char *request_path;
	const char *http_v;
	int ret;

	ret = recv(fd, buf, MESSAGE_BUFFER_SIZE - 1, 0);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\t%s recv error: %s\n", fd, __func__,
				strerror(errno));
		return ret;
	}

	if (ret == 0) {
		FD_CLR(fd, &fd_set_active);
		if (request_fd == fd) {
			request_fd = -1;
			clLog(clSystemLog, eCLSeverityCritical, "%d\tConnection to request stream "
					"closed by peer\n", fd);
		}
		close(fd);
		return EXIT_SUCCESS;
	}

	request_path = strchr(buf, '/');
	http_v = strstr(buf, HTTP);
	if (request_path == NULL || http_v == NULL) {
		send_stream_response_error(fd, HTTP_400 CRLF CRLF, buf);
		return EXIT_FAILURE;
	}

	if (strncmp(REQUEST_PATH_STR, request_path, strlen(REQUEST_PATH_STR))) {
		send_stream_response_error(fd, HTTP_404 CRLF CRLF, buf);
		return EXIT_FAILURE;
	}

	if (strncmp(HTTP_V_1_1, http_v, strlen(HTTP_V_1_1))) {
		send_stream_response_error(fd, HTTP_505 CRLF CRLF, buf);
		return EXIT_FAILURE;
	}

	if (request_fd != -1) {
		send_stream_response_error(fd, HTTP_429 CRLF CRLF, buf);
		return EXIT_FAILURE;
	}

	if (!strncmp(buf, HTTP_METHOD_HEAD, strlen(HTTP_METHOD_HEAD))) {
		send_stream_response_ok(fd);
		return EXIT_SUCCESS;
	}

	if (strncmp(buf, HTTP_METHOD_GET, strlen(HTTP_METHOD_GET))) {
		send_stream_response_error(fd, HTTP_405 CRLF CRLF, buf);
		return EXIT_FAILURE;
	}

	DEBUG_PRINTF("%d\tReceived:\n%*s\n", fd, rx_bytes, buf);

	ret = send_stream_response_ok(fd);
	if (ret)
		return ret;

	request_fd = fd;

	ret = bind_client_request();
	if (ret)
		return ret;

	FD_SET(fd, &fd_set_responded);

	return EXIT_SUCCESS;
}

/**
 * @brief  : server helper function to receive message and respond accordingly -
 *           as we do not expect any data on this connection, we log and discard it
 *           without response
 * @param  : fd, file descriptor to receive message
 * @return : 0 on success, error otherwise
 */
static int
serve_client(int fd)
{
	/* we shouldn't be receiving anything here - just log it */
	char rx_buffer[MESSAGE_BUFFER_SIZE] = {0};
	int ret = recv(fd, rx_buffer, MESSAGE_BUFFER_SIZE - 1, 0);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\tListener recv error: %s\n", fd,
				strerror(errno));
		FD_CLR(fd, &fd_set_active);
		return EXIT_FAILURE;
	}

	if (ret == 0) {
		FD_CLR(fd, &fd_set_active);
		if (request_fd == fd) {
			request_fd = -1;
			clLog(clSystemLog, eCLSeverityCritical, "%d\tConnection to request stream "
					"closed by peer\n", fd);
		}
		close(fd);
		return EXIT_SUCCESS;
	}

	clLog(clSystemLog, eCLSeverityCritical, "%d\tUnexpected request: %s\n", fd, rx_buffer);
	return EXIT_SUCCESS;
}

/**
 * @brief  : handler function to process 'configure' messages that are received on
 *           the response stream
 * @param  : jobj, the json object data contained within the response message
 * @return : Returns nothing
 */
static void
sse_handle_message_configure(json_object *jobj)
{
	json_object *output_jobj;
	json_object *op_id_jobj;
	int ret;

	ret = json_object_object_get_ex(jobj, "output",
			&output_jobj);
	if (ret == FALSE || output_jobj == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(no output object):\n%s\n",
			json_object_to_json_string(jobj));
		return;
	}
	if (!json_object_is_type(output_jobj, json_type_object)) {
		clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(output value not an object):\n%s\n",
			json_object_to_json_string(jobj));
		return;
	}


	ret = json_object_object_get_ex(output_jobj, "op-id",
			&op_id_jobj);
	if (ret == FALSE || op_id_jobj == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(no op_id object):\n%s\n",
			json_object_to_json_string(jobj));
		return;
	}

	if (!json_object_is_type(op_id_jobj, json_type_int)) {
		clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(op_id not int):\n%s\n",
			json_object_to_json_string(jobj));
		return;
	}

	check_nb_op_id(json_object_get_int64(op_id_jobj));
}


/**
 * @brief  : handler function to process  messages that are received on
 *           the notification stream
 * @param  : jobj
 *           complete json object data contained within the notification message
 * @param  : notify_jobj
 *           json sub-object data contained within the notification message containing the
 *           notification
 * @param  : message_type
 *           The value (to the notify key) that describes the notification *
 * @return : Returns nothing
 */
static void
nb_json_notify_parser(json_object *jobj,
		json_object *notify_jobj, const char *message_type)
{
	json_bool ret;
	if (!strcmp(message_type, "Dpn-Availability")) {
		json_object *dpn_status_jobj;
		ret = json_object_object_get_ex(notify_jobj,
				"dpn-status", &dpn_status_jobj);
		if (ret == FALSE ||  !json_object_is_type(dpn_status_jobj,
				json_type_string)) {
			clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
					"(no dpn-status):\n%s\n",
					json_object_to_json_string(jobj));
			return;
		}
		const char *dpn_status =
				json_object_get_string(dpn_status_jobj);
		if (!strcmp(dpn_status, "available")) {
			json_object *dpn_id_jobj;
			ret = json_object_object_get_ex(notify_jobj, "dpn-id",
					&dpn_id_jobj);
			if (ret == FALSE || !json_object_is_type(dpn_id_jobj,
					json_type_string)) {
				clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object"
					" (no dpn-id):\n%s\n",
					json_object_to_json_string(jobj));
				return;
			}
			if (!set_dpn_id(json_object_get_string(dpn_id_jobj))) {
				clLog(clSystemLog, eCLSeverityDebug,"dpn id set to %s\n",
					json_object_get_string(dpn_id_jobj));
			}
			return;
		} else if (!strcmp(dpn_status, "unavailable")) {
			json_object *dpn_id_jobj;
			ret = json_object_object_get_ex(notify_jobj, "dpn-id",
					&dpn_id_jobj);
			if (ret == FALSE || !json_object_is_type(dpn_id_jobj,
					json_type_string)) {
				clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object"
					" (no dpn-id):\n%s\n",
					json_object_to_json_string(jobj));
				return;
			}
			if (dpn_id != NULL && !strcmp(dpn_id,
					json_object_get_string(dpn_id_jobj))) {
				clLog(clSystemLog, eCLSeverityDebug,"dpn_id currently in use "
						"is no longer available:\n");
				DEBUG_PRINTF("%s\n",
					json_object_get_string(dpn_id_jobj));
				set_dpn_id(NULL);
				/* attempt to use different dpn */
				get_topology();
			}
			return;
		}
	} else if (!strcmp(message_type, "Downlink-Data-Notification")) {
		json_object *session_id_jobj;
		ret = json_object_object_get_ex(notify_jobj, "session-id",
					&session_id_jobj);
		if (ret == FALSE || !json_object_is_type(session_id_jobj,
				json_type_int)) {
			clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
					"(no session-id):\n%s\n",
					json_object_get_string(jobj));
			return;
		}

		uint64_t session_id = json_object_get_int64(session_id_jobj);

		ddn_by_session_id(session_id);
		return;
	}

	clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(unknown message-type):\n%s\n",
			json_object_get_string(jobj));
}

/**
 * @brief  : handles messages on the notification stream
 * @param  : jobj
 *           json object received in the data portion of the message-
 * @return : Returns nothing
 */
static void
sse_handle_message_notification(json_object *jobj)
{
	int ret;
	json_object *notify_jobj;
	ret = json_object_object_get_ex(jobj, "notify", &notify_jobj);
	if (ret == TRUE && json_object_get_type(notify_jobj) ==
			json_type_object) {

		json_object *message_type_jobj;
		ret = json_object_object_get_ex(notify_jobj, "message-type",
				&message_type_jobj);
		if (ret == FALSE || !json_object_is_type(message_type_jobj,
				json_type_string)) {
			clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
					"(no message-type):\n%s\n",
					json_object_get_string(jobj));
			return;
		}
		nb_json_notify_parser(jobj, notify_jobj,
				json_object_get_string(message_type_jobj));
		return;
	}

	json_object *config_result_notification_jobj;
	ret = json_object_object_get_ex(jobj, "config-result-notification",
			&config_result_notification_jobj);
	if (ret == TRUE && config_result_notification_jobj != NULL) {
		if (!json_object_is_type(config_result_notification_jobj,
				json_type_object)) {
			clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
					"(no config-result-notification "
					"object):\n%s\n",
					json_object_get_string(jobj));
			return;
		}
		json_object *op_id_jobj;
		ret = json_object_object_get_ex(config_result_notification_jobj,
					"op-id", &op_id_jobj);
		if (ret == FALSE || !json_object_is_type(op_id_jobj,
				json_type_int)) {
			clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object"
				" (no dpn-id):\n%s\n",
				json_object_to_json_string(jobj));
			return;
		}
		uint32_t op_id = json_object_get_int64(op_id_jobj);
		del_nb_op_id(op_id);
		return;
	}


	clLog(clSystemLog, eCLSeverityCritical, "Received unhandled JSON object "
			"(Unknown message):\n%s\n",
			json_object_get_string(jobj));
}


/**
 * @brief  : message hanlder for the sse messages received on the
 *           request or notification streams
 * @param  : msg
 *           message received
 * @param  : map
 *           used to map the message contents to a handler function
 * @return : Returns nothing
 */
static void
sse_handle_message(const char *msg,
		const struct sse_handle_message_event_map *map)
{
	unsigned i;
	const char *ptr = msg;
	enum json_tokener_error error;
	json_object *jobj;


	/* We could do something more elegant, but we are only
	 * checking for a couple of message types at the moment
	 */
	for (i = 0; map[i].event; ++i) {
		if (!strncmp(msg, map[i].event, strlen(map[i].event)))
			break;
	}

	if (map[i].event == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Unexpected Message: SSE Event:\n%s\n", msg);
		return;
	}

	ptr += strlen(map[i].event);

	if (strncmp(ptr, SSE_DATA, strlen(SSE_DATA))) {
		clLog(clSystemLog, eCLSeverityCritical, "Unexpected Message: Missing Data:\n%s\n", msg);
		return;
	}
	ptr += strlen(SSE_DATA);

	jobj = json_tokener_parse_verbose(ptr, &error);

	if (jobj == NULL || error != json_tokener_success) {
		clLog(clSystemLog, eCLSeverityCritical, "SSE Data JSON parsing error: %s\n",
				json_tokener_error_desc(error));
		return;
	}

	map[i].sse_handle_message_func(jobj);

	json_object_put(jobj);
}

/**
 * @brief  : parses a message expected to contain a HTTP header
 * @param  : fd
 *           file descriptor used to receive the message
 * @param  : rx_buffer
 *           message contents
 * @return : number of bytes processed
 */
static size_t
check_header(const int fd, const char *rx_buffer)
{
	int ret;
	int http_status = -1;
	const char *ptr;

	ret = sscanf(rx_buffer, HTTP_V_1_1" %d", &http_status);
	if (ret != 1)
		return 0;


	if (http_status != HTTP_OK)
		rte_panic("%d\tStream request HTTP Error %d:\n%s\n",
				fd, http_status, rx_buffer);


	ptr = strstr(rx_buffer, CRLF CRLF);

	if (ptr == NULL)
		return 0;
	DEBUG_PRINTF("\n\n%d\tRecieved\n%*s", fd,
			(int)(ptr - rx_buffer), rx_buffer);

	return ptr - rx_buffer + strlen(CRLF CRLF);
}

/**
 * @brief  : parses an expected  HTTP chunk message
 * @param  : fd
 *           file descriptor on the received message
 * @param  : rx_buffer
 *           message contents received
 * @param  : map
 *           used to map the message contents to a handler function
 * @return : Returns number of processes bytes
 */
static size_t
check_chunk(const int fd, const char *rx_buffer,
		const struct sse_handle_message_event_map *map)
{
	unsigned chunk_size;
	const char *ptr;
	int n;
	int ret;

	ret = sscanf(rx_buffer, "%x" CRLF "%n", &chunk_size, &n);
	if (ret != 1) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\tMissing chunk size:\n%s\n", fd, rx_buffer);
		return 0;
	}

	if (chunk_size == 0) {
		DEBUG_PRINTF("\n\n%d\tReceived empty chunk\n", fd);
		ptr = strstr(&rx_buffer[n], CRLF CRLF);
		if (ptr == NULL)
			return 0;
		return ptr - rx_buffer + strlen(CRLF CRLF);
	}


	ptr = strstr(&rx_buffer[n], CRLF);
	if (ptr == NULL)
		return 0;
	while (isspace(*ptr))
		++ptr;

	DEBUG_PRINTF("\n\n%d\tRecieved\n%*s", fd,
			(int)(ptr - rx_buffer), rx_buffer);
	sse_handle_message(&rx_buffer[n], map);

	return ptr - rx_buffer;
}


/**
 * @brief  : receives messages (and bufferes if partial message is received).
 *           Messages are expected to be HTTP chunked encoded SSE event-data pairs
 * @param  : fd
 *           file descriptor on the received message
 * @param  : active
 *           active buffer to be used on message receipt
 * @param  : inactive
 *           inactive buffer to be used if buffer swapping is required
 * @param  : buf_size
 *           buffer size remaining in active buffer
 * @param  : map
 *           used to map the message contents to a handler function
 * @return : number bytes received, or error if negative
 */
static inline int
rec_stream(int fd, char **active, char **inactive, size_t *buf_size,
		const struct sse_handle_message_event_map *map)
{
	int rx_bytes;
	size_t consumed_header = 0;
	size_t consumed_chunk = 0;
	size_t consumed = 0;

	rx_bytes = recv(fd, &(*active)[*buf_size],
			MESSAGE_BUFFER_SIZE - *buf_size - 1, 0);

	if (rx_bytes < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\%s recv error: %s\n", fd, __func__,
				strerror(errno));
		return rx_bytes;
	}

	if (rx_bytes == 0)
		return 0;

	*buf_size += rx_bytes;
	(*active)[*buf_size] = '\0';

	do {
		consumed_header = check_header(fd, &(*active)[consumed]);
		consumed += consumed_header;
		if (consumed >= *buf_size)
			break;
		consumed_chunk = check_chunk(fd, &(*active)[consumed], map);
		consumed += consumed_chunk;
	} while (consumed < *buf_size && (consumed_header || consumed_chunk));

	if (consumed == *buf_size) {
		*buf_size = 0;
	} else if (consumed > *buf_size) {
		DEBUG_PRINTF("Consumed more than alloted\n");
		*buf_size = 0;
	} else {
		*buf_size -= consumed;
		memcpy(*inactive, &(*active)[consumed], *buf_size);
		if ((*inactive)[0] == '\n' || (*inactive)[0] == '\r')
			clLog(clSystemLog, eCLSeverityDebug,"Error switching between inactive & active\n");
		char *swap = *active;
		*active = *inactive;
		*inactive = swap;
	}


	return rx_bytes;
}

/**
 * @brief  : wrapper function to receive a message on the response stream
 * @param  : No param
 * @return : Returns nothing
 */
static void
rec_response_stream(void)
{
	static char rx_buffer[2][MESSAGE_BUFFER_SIZE];
	static char *active = rx_buffer[0];
	static char *inactive = rx_buffer[1];
	static size_t buf_pos;
	size_t rx_bytes;

	static const struct sse_handle_message_event_map response_map[] = {
		{SSE_EVENT SSE_CONFIGURE_EVENT LF,
				sse_handle_message_configure},
		{SSE_EVENT SSE_BIND_CLIENT_EVENT LF,
				sse_handle_message_bind_client},
		{NULL, NULL}
	};

	rx_bytes = rec_stream(response_fd, &active, &inactive,
			&buf_pos, response_map);

	if (rx_bytes == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\tResponse stream closed.\n", response_fd);
		FD_CLR(response_fd, &fd_set_active);
		close(response_fd);

		connect_stream(&response_fd);
		DEBUG_PRINTF("%d\tConnected to response stream.\n",
				response_fd);
	}
}

/**
 * @brief  : wrapper function to receive a message on the notification stream
 * @param  : No param
 * @return : Returns nothing
 */
static void
rec_notification_stream(void)
{
	static char rx_buffer[2][MESSAGE_BUFFER_SIZE];
	static char *active = rx_buffer[0];
	static char *inactive = rx_buffer[1];
	static size_t buf_pos;
	size_t rx_bytes;


	static const struct sse_handle_message_event_map notification_map[] = {
		{SSE_EVENT SSE_NOTIFICATION_EVENT LF,
				sse_handle_message_notification},
		{NULL, NULL}
	};

	rx_bytes = rec_stream(notification_fd, &active, &inactive,
			&buf_pos, notification_map);

	if (rx_bytes == 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%d\tNotification stream closed.\n",
				notification_fd);
		FD_CLR(notification_fd, &fd_set_active);
		close(notification_fd);

		connect_stream(&notification_fd);
		DEBUG_PRINTF("%d\tConnected to response stream.\n",
				response_fd);
	}
}

void
server(void)
{
	int i;
	int ret;
	fd_set fd_set_read;
	fd_set fd_set_zero;

	puts("Starting server");

	FD_ZERO(&fd_set_zero);
	FD_ZERO(&fd_set_responded);

	switch (spgw_cfg) {
	case SGWC:
		if (s5s8_sgwc_fd != -1)
			FD_SET(s5s8_sgwc_fd, &fd_set_active);

	case SAEGWC:
		if (s11_fd != -1)
			FD_SET(s11_fd, &fd_set_active);
		if (s11_pcap_fd != -1)
			FD_SET(s11_pcap_fd, &fd_set_active);
		break;

	 case PGWC:
		if (s5s8_pgwc_fd != -1)
			FD_SET(s5s8_pgwc_fd, &fd_set_active);
		break;

	default:
		break;

	}

	while (memcmp(&fd_set_zero, &fd_set_active, sizeof(fd_set))) {
		fd_set_read = fd_set_active;
		ret = select(FD_SETSIZE, &fd_set_read, NULL, NULL, NULL);
		if (ret < 0) {
			/* If all fd's have been closed, exit server */
			if (!memcmp(&fd_set_zero, &fd_set_active,
					sizeof(fd_set)))
				return;
			rte_panic("Select error: %s", strerror(errno));
		}

		switch (spgw_cfg) {
			case SGWC:
				if (FD_ISSET(s5s8_sgwc_fd, &fd_set_read)) {
					FD_CLR(s5s8_sgwc_fd, &fd_set_read);
					control_plane();
				}

			case SAEGWC:
				if (FD_ISSET(s11_fd, &fd_set_read)) {
					FD_CLR(s11_fd, &fd_set_read);
					control_plane();
				}
				break;

			case PGWC:
				if (FD_ISSET(s5s8_pgwc_fd, &fd_set_read)) {
					FD_CLR(s5s8_pgwc_fd, &fd_set_read);
					control_plane();
				}
				break;

			default:
				rte_panic("ERROR: INVALID Control Plane type.\n");
		}

		if (FD_ISSET(response_fd, &fd_set_read)) {
			FD_CLR(response_fd, &fd_set_read);
			rec_response_stream();
		}

		if (FD_ISSET(notification_fd, &fd_set_read)) {
			FD_CLR(notification_fd, &fd_set_read);
			rec_notification_stream();
		}

		for (i = 0; i < FD_SETSIZE; ++i) {
			if (!FD_ISSET(i, &fd_set_read))
				continue;
			if (i == server_fd) {
				int new_fd = accept(server_fd, NULL, NULL);

				if (new_fd < 0) {
					rte_panic("Accept Error: %s\n",
							strerror(errno));
					continue;
				}

				DEBUG_PRINTF("%d\tAccepted new connection\n",
						new_fd);
				FD_SET(new_fd, &fd_set_active);
				FD_CLR(new_fd, &fd_set_responded);
			} else {
				if (FD_ISSET(i, &fd_set_responded)) {
					DEBUG_PRINTF("\n\n%d\tSelect on old "
							"connection\n", i);
					/* we shouldn't expect anything else to
					 * be received on this socket, but we
					 * will log it
					 */
					ret = serve_client(i);
				} else {
					DEBUG_PRINTF("\n\n%d\tSelect on "
							"new connection\n", i);
					ret = serve_client_with_response(i);
				}

				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
						"%d\tClosing connection", i);
					close(i);
					FD_CLR(i, &fd_set_active);
				}
			}
		}
	}

	puts("Exiting server");
}


/**
 * @brief  : server intialiation function
 * @param  : No param
 * @return : Returns nothing
 */
static void
init_server(void)
{
	int ret;

	struct linger so_linger = {
			.l_linger = 0,
			.l_onoff = 1,
	};

	server_fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	setsockopt(server_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

	ret = setsockopt(server_fd, SOL_SOCKET, SO_LINGER, &so_linger,
			sizeof(so_linger));

	if (ret)
		clLog(clSystemLog, eCLSeverityCritical, "Linger Error: %s\n", strerror(errno));

	struct sockaddr_in local_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(cp_nb_port),
			.sin_addr = cp_nb_ip,
			.sin_zero = {0},
	};

	if (bind(server_fd, (struct sockaddr *) &local_addr,
	    sizeof(local_addr)) < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
		    inet_ntoa(local_addr.sin_addr),
		    ntohs(local_addr.sin_port),
		    strerror(errno));
	}

	if (listen(server_fd, 24) < 0)
		rte_panic("Listen error: %s\n", strerror(errno));

	DEBUG_PRINTF("\n\n%d\tListening to %s:%"PRIu16"\n", server_fd,
			inet_ntoa(cp_nb_ip), cp_nb_port);

	FD_ZERO(&fd_set_active);
	FD_SET(server_fd, &fd_set_active);
}

int
init_nb(void)
{
	init_nb_op_id();

	init_server();

	connect_stream(&response_fd);
	DEBUG_PRINTF("\n\n%d\tConnected to response stream.\n", response_fd);

	connect_stream(&notification_fd);
	DEBUG_PRINTF("\n\n%d\tConnected to notification stream.\n",
			notification_fd);

	json_object *response_obj;

	puts("Starting NB Interface");

	response_obj = response_stream_req_json();
	request_stream(response_fd, RESPONSE_PATH_STR, response_obj);
	json_object_put(response_obj);

	return EXIT_SUCCESS;
}


int
send_nb_create_modify(const char *op_type, const char *instruction,
		uint64_t sess_id, uint32_t assigned_ip,
		uint32_t remote_address, uint32_t s5s8_address, uint32_t local_address,
		uint32_t remote_teid, uint32_t local_teid,
		uint64_t imsi, uint8_t ebi)
{
	static char json_buf[MESSAGE_BUFFER_SIZE];
	char assigned_address_string[INET_ADDRSTRLEN];
	char remote_address_string[INET_ADDRSTRLEN];
	char s5s8_address_string[INET_ADDRSTRLEN];
	char local_address_string[INET_ADDRSTRLEN];

	strcpy(assigned_address_string,
		inet_ntoa(*((struct in_addr *)&assigned_ip)));
	strcpy(remote_address_string,
		inet_ntoa(*((struct in_addr *)&remote_address)));
	strcpy(s5s8_address_string,
		inet_ntoa(*((struct in_addr *)&s5s8_address)));
	strcpy(local_address_string,
		inet_ntoa(*((struct in_addr *)&local_address)));

	if (dpn_id == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "NO DPN INSTALLED!!!!\n");
		return EXIT_FAILURE;
	}


	snprintf(json_buf, MESSAGE_BUFFER_SIZE,
			CREATE_MODIFY_JSON_FORMAT_STR,
			op_id,
			instruction,
			sess_id,
			assigned_address_string,
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			s5s8_address_string,		/* S5S8 IP Address*/
			local_teid,			/* SGW-S1U TEID */
			local_address_string,		/* SGW-S1U IP Address*/
			remote_address_string,		/* eNB-S1U IP Address*/
			s5s8_address_string,		/* S5S8 IP Address*/
			remote_teid,			/* eNB-S1U TEID */
			dpn_id,
			imsi,
			ebi,
			ebi,
			client_id,
			op_type);

	add_nb_op_id_hash();

	clLog(clSystemLog, eCLSeverityDebug, "SSE Json Stream :%s\n", json_buf);

#ifdef SYNC_STATS
	struct sync_stats info = {0};
	info.op_id = op_id;

	if((strcmp(op_type, "create")) == 0) {
		info.type = 1;
	} else {
		info.type = 2;
	}

	info.session_id = sess_id;
	add_stats_entry(&info);

#endif /* SYNC_STATS */

	return send_sse(request_fd, SSE_CONFIGURE_EVENT, json_buf, __func__);
}


int
send_nb_delete(uint64_t sess_id)
{
	static char json_buf[MESSAGE_BUFFER_SIZE];

	if (dpn_id == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "NO DPN INSTALLED!!!!");
		return EXIT_FAILURE;
	}

	snprintf(json_buf, MESSAGE_BUFFER_SIZE,
			DELETE_JSON_FORMAT_STR,
			op_id,
			sess_id,
			client_id,
			JSON_OBJ_OP_TYPE_DELETE);

	add_nb_op_id_hash();

#ifdef SYNC_STATS
	struct sync_stats info = {0};
	info.op_id = op_id;
	info.type = 3;
	info.session_id = sess_id;
	add_stats_entry(&info);

#endif /* SYNC_STATS */

	return send_sse(request_fd, SSE_CONFIGURE_EVENT, json_buf, __func__);
}

int
send_nb_ddn_ack(uint64_t dl_buffering_suggested_count,
		uint64_t dl_buffering_duration)
{
	static char json_buf[MESSAGE_BUFFER_SIZE];

	if (dpn_id == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "NO DPN INSTALLED!!!!");
		return EXIT_FAILURE;
	}

	snprintf(json_buf, MESSAGE_BUFFER_SIZE,
			DDN_ACK_JSON_FORMAT_STR,
			dpn_id,
			dl_buffering_suggested_count,
			client_id,
			op_id,
			JSON_OBJ_OP_TYPE_DDN_ACK,
			dl_buffering_duration);

	add_nb_op_id_hash();

	clLog(clSystemLog, eCLSeverityDebug, "DDN_ACK: SSE Json Stream :%s\n", json_buf);

	return send_sse(request_fd, SSE_DDN_ACK_EVENT, json_buf, __func__);
}

int
close_nb(void)
{
	char buffer[MESSAGE_BUFFER_SIZE];
	int ret;
	int i;
	fd_set fd_to_close = fd_set_active;

	FD_ZERO(&fd_set_active);
	ret = snprintf(buffer, MESSAGE_BUFFER_SIZE,
			SSE_UNBIND_CLIENT_DATA_FORMAT, client_id);
	if (ret < 0 || ret > MESSAGE_BUFFER_SIZE)
		clLog(clSystemLog, eCLSeverityCritical, "Error in generating unbind client message");
	else
		send_sse(request_fd, SSE_UNBIND_CLIENT_EVENT, buffer, __func__);

	close_sse(request_fd);

	sleep(2);

	for (i = 0; i < FD_SETSIZE; ++i) {
		if (!FD_ISSET(i, &fd_to_close))
			continue;

		close(i);
	}
	return EXIT_SUCCESS;
}

