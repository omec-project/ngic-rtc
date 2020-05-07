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
#ifndef __NB_SSE_CLIENT_H__
#define __NB_SSE_CLIENT_H__

#include <curl/curl.h>

#define LF "\n"
#define CRLF "\r\n"

#define REQUEST_PATH_STR      "/request"
#define RESPONSE_PATH_STR     "/response"
#define NOTIFICATION_PATH_STR "/notification"
#define SSE_EVENT "event:"
#define SSE_DATA  "data:"

#define SSE_APPLICATION_JSON "application/json"

#define SSE_EVENT_PATH_FPC      "/restconf/operations/fpc"
#define SSE_EVENT_PATH_FPCAGENT "/restconf/operations/ietf-dmm-fpcagent"

#define SSE_EVENT_FPC_REGISTER_CLIENT   "register_client"
#define SSE_EVENT_FPC_DEREGISTER_CLIENT "deregister_client"
#define SSE_EVENT_FPCAGENT_CONFIGURE    "configure"
#define SSE_EVENT_FPCAGENT_DDN_ACK    "downlink-data-notification"

#define SSE_DEFINE_EVENT(path, cmd) \
	SSE_APPLICATION_JSON ";" \
	path ":" cmd

#define SSE_BIND_CLIENT_EVENT \
	SSE_DEFINE_EVENT(SSE_EVENT_PATH_FPC, SSE_EVENT_FPC_REGISTER_CLIENT)
#define SSE_UNBIND_CLIENT_EVENT \
	SSE_DEFINE_EVENT(SSE_EVENT_PATH_FPC, SSE_EVENT_FPC_DEREGISTER_CLIENT)
#define SSE_CONFIGURE_EVENT \
	SSE_DEFINE_EVENT(SSE_EVENT_PATH_FPCAGENT, SSE_EVENT_FPCAGENT_CONFIGURE)

#define SSE_DDN_ACK_EVENT \
	SSE_DEFINE_EVENT(SSE_EVENT_PATH_FPCAGENT, SSE_EVENT_FPCAGENT_DDN_ACK)

#define SSE_NOTIFICATION_EVENT SSE_APPLICATION_JSON ";" NOTIFICATION_PATH_STR

#define SSE_BIND_CLIENT_DATA \
	"{\"input\":"\
	"{\"client-id\":\"1\","\
	"\"tenant-id\":\"default\","\
	"\"supported-features\":["\
	"\"urn:ietf:params:xml:ns:yang:fpcagent:fpc-bundles\","\
	"\"urn:ietf:params:xml:ns:yang:fpcagent:operation-ref-scope\","\
	"\"urn:ietf:params:xml:ns:yang:fpcagent:fpc-agent-assignments\","\
	"\"urn:ietf:params:xml:ns:yang:fpcagent:instruction-bitset\"]}}"


#define HTTP "HTTP"
#define HTTP_METHOD_GET  "GET"
#define HTTP_METHOD_POST "POST"
#define HTTP_METHOD_HEAD "HEAD"
#define HTTP_SCHEME_STR "http://"
#define HTTP_V_1_1  HTTP"/1.1"

#define HTTP_200_OK HTTP_V_1_1" 200 OK"
#define HTTP_400    HTTP_V_1_1" 400 Bad Request"
#define HTTP_404    HTTP_V_1_1" 404 Not Found"
#define HTTP_405    HTTP_V_1_1" 405 Method Not Allowed"
#define HTTP_429    HTTP_V_1_1" 429 Too Many Requests"
#define HTTP_505    HTTP_V_1_1" 505 HTTP Version Not Supported"


#define HTTP_HEADER_JSON    "Content-Type: "SSE_APPLICATION_JSON
#define HTTP_HEADER_SSE     "Content-Type: text/event-stream"
#define HTTP_HEADER_CHUNKED "Transfer-Encoding: chunked"
#define HTTP_CONTENT_LENGTH "Content-Length: "

#define HTTP_REQUEST_STREAM_RESPONSE \
		HTTP_200_OK CRLF \
		HTTP_HEADER_SSE CRLF \
		HTTP_HEADER_CHUNKED CRLF CRLF ""

#define HTTP_EXPECTED_REQUEST_STREAM(http_method) \
		http_method " " REQUEST_PATH_STR " " HTTP_V_1_1 CRLF



#define JSON_OBJ_INSTR_3GPP_MOB_KEY    "instr-3gpp-mob"
#define JSON_OBJ_INSTR_3GPP_MOB_CREATE "session uplink"
#define JSON_OBJ_INSTR_3GPP_MOB_MODIFY "downlink"

#define JSON_OBJ_TUNNEL_LOCAL_ADDRESS_KEY  "tunnel-local-address"
#define JSON_OBJ_TUNNEL_REMOTE_ADDRESS_KEY "tunnel-remote-address"
#define JSON_OBJ_TUNNEL_IDENTIFIER_KEY     "tunnel-identifier"

#define JSON_OBJ_OP_TYPE_CREATE "create"
#define JSON_OBJ_OP_TYPE_UPDATE "update"
#define JSON_OBJ_OP_TYPE_DELETE "delete"
#define JSON_OBJ_OP_TYPE_DDN_ACK "Downlink-Data-Notification-Ack"


#define PRI_OP_ID_FORMAT PRIu64
#define PRI_ODL_INSTRUCTION "s"
#define PRI_CONTEXT_SESS_ID PRIu64
#define PRI_UE_IP "s"
#define PRI_TEID PRIu32
#define PRI_CLIENT_ID "s"
#define PRI_DPN_ID "s"
#define PRI_FPC_IP "s"
#define PRI_FPC_PORT PRIu16

#define PRI_DL_FORMAT PRIu64

#define SSE_UNBIND_CLIENT_DATA_FORMAT \
	"{\"input\":{\"client-id\":\"%" PRI_CLIENT_ID "\"}}"

#define UIDPWD "admin:admin"
#define SDN_TOPOLOGY_URI_LEN 256
#define SDN_TOPOLOGY_URI_PATH \
	"/restconf/config/ietf-dmm-fpcagent:tenants/tenant/default/fpc-topology"

#define CREATE_MODIFY_JSON_FORMAT_STR \
"{" \
	"\"input\": {" \
	"\"op-id\": \"%"PRI_OP_ID_FORMAT"\"," \
	"\"contexts\": [" \
		"{" \
		"\"instructions\": {" \
			"\"instr-3gpp-mob\": \"%"PRI_ODL_INSTRUCTION"\"" \
		"}," \
		"\"context-id\": %"PRI_CONTEXT_SESS_ID"," \
		"\"dpn-group\": \"site1-l3\"," \
		"\"delegating-ip-prefixes\": [" \
			      "\"%"PRI_UE_IP"/32\"" \
		"]," \
		"\"ul\": {" \
			"\"tunnel-local-address\": \"%s\"," \
			"\"tunnel-remote-address\": \"%s\"," \
			"\"tunnel-s5s8-address\": \"%s\"," \
			"\"mobility-tunnel-parameters\": {" \
				"\"tunnel-type\": \"ietf-dmm-threegpp:gtpv1\","\
				"\"tunnel-identifier\": \"%"PRI_TEID"\"" \
			"}," \
			"\"dpn-parameters\": {}" \
		"}," \
		"\"dl\": {" \
			"\"tunnel-local-address\": \"%s\"," \
			"\"tunnel-remote-address\": \"%s\"," \
			"\"tunnel-s5s8-address\": \"%s\"," \
			"\"mobility-tunnel-parameters\": {" \
				"\"tunnel-type\": \"ietf-dmm-threegpp:gtpv1\","\
				"\"tunnel-identifier\": \"%"PRI_TEID"\"" \
			"}," \
			"\"dpn-parameters\": {}" \
		"}," \
		"\"dpns\": [" \
			"{" \
				"\"dpn-id\": \"%"PRI_DPN_ID"\"," \
				"\"direction\": \"uplink\"," \
				"\"dpn-parameters\": {}" \
			"}" \
			"]," \
		"\"imsi\": \"%"PRIu64"\"," \
		"\"ebi\": \"%"PRIu8"\"," \
		"\"lbi\": \"%"PRIu8"\"" \
		"}" \
		"]," \
	"\"client-id\": \"%"PRI_CLIENT_ID"\"," \
	"\"session-state\": \"complete\"," \
	"\"admin-state\": \"enabled\"," \
	"\"op-type\": \"%s\"," \
	"\"op-ref-scope\": \"none\"" \
	"}" \
"}"


#define DELETE_TARGET_PREFIX \
	"/ietf-dmm-fpcagent:tenants/tenant/default/fpc-mobility/contexts/"
#define DELETE_JSON_FORMAT_STR \
"{" \
	"\"input\": {" \
		"\"op-id\": \"%"PRI_OP_ID_FORMAT"\"," \
		"\"targets\": [ {" \
			"\"target\": \""DELETE_TARGET_PREFIX"%"PRIu64"\"" \
		"} ]," \
	"\"client-id\": \"%"PRI_CLIENT_ID"\"," \
	"\"session-state\": \"complete\"," \
	"\"admin-state\": \"enabled\"," \
	"\"op-type\": \"%s\"," \
	"\"op-ref-scope\": \"none\"" \
	"}" \
"}"

#define DDN_ACK_JSON_FORMAT_STR \
"{" \
	"\"notify\": {" \
		"\"downlink-data-notification\": [ {" \
			"\"dpn-id\": \"%"PRI_DPN_ID"\"," \
			"\"dl_buffering-suggested-count\": \"%"PRI_DL_FORMAT"\"," \
			"\"client-id\": \"%"PRI_CLIENT_ID"\"," \
			"\"op-id\": \"%"PRI_OP_ID_FORMAT"\"," \
			"\"message-type\": \"%s\"," \
			"\"dl-buffering-duration\": \"%"PRI_DL_FORMAT"\"," \
		"} ]," \
	"}" \
"}"
//#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

/* From rfc2616 */
/**
 * @brief  : Http error codes
 */
enum http_status {
	HTTP_CONTINUE = 100,
	HTTP_SWITCHING_PROTOCOLS = 101,
	HTTP_OK = 200,
	HTTP_CREATED = 201,
	HTTP_ACCEPTED = 202,
	HTTP_NON_AUTHORITATIVE_INFORMATION = 203,
	HTTP_NO_CONTENT = 204,
	HTTP_RESET_CONTENT = 205,
	HTTP_PARTIAL_CONTENT = 206,
	HTTP_MULTIPLE_CHOICES = 300,
	HTTP_MOVED_PERMANENTLY = 301,
	HTTP_FOUND = 302,
	HTTP_SEE_OTHER = 303,
	HTTP_NOT_MODIFIED = 304,
	HTTP_USE_PROXY = 305,
	HTTP_TEMPORARY_REDIRECT = 307,
	HTTP_BAD_REQUEST = 400,
	HTTP_UNAUTHORIZED = 401,
	HTTP_PAYMENT_REQUIRED = 402,
	HTTP_FORBIDDEN = 403,
	HTTP_NOT_FOUND = 404,
	HTTP_METHOD_NOT_ALLOWED = 405,
	HTTP_NOT_ACCEPTABLE = 406,
	HTTP_PROXY_AUTHENTICATION_REQUIRED = 407,
	HTTP_REQUEST_TIMEOUT = 408,
	HTTP_CONFLICT = 409,
	HTTP_GONE = 410,
	HTTP_LENGTH_REQUIRED = 411,
	HTTP_PRECONDITION_FAILED = 412,
	HTTP_REQUEST_ENTITY_TOO_LARGE = 413,
	HTTP_REQUEST_URI_TOO_LONG = 414,
	HTTP_UNSUPPORTED_MEDIA_TYPE = 415,
	HTTP_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	HTTP_EXPECTATION_FAILED = 417,
	HTTP_INTERNAL_SERVER_ERROR = 500,
	HTTP_NOT_IMPLEMENTED = 501,
	HTTP_BAD_GATEWAY = 502,
	HTTP_SERVICE_UNAVAILABLE = 503,
	HTTP_GATEWAY_TIMEOUT = 504,
	HTTP_VERSION_NOT_SUPPORTED = 505,
};

extern char *dpn_id;

/**
 * @brief  : Initalizes northbound interface
 * @param  : No param
 * @return : 0 on success, error otherwise
 */
int
init_nb(void);

/**
 * @brief  : closes the northbound interface connections
 * @param  : No param
 * @return : 0 on success, error otherwise
 */
int
close_nb(void);

/**
 * @brief  : used to send create session or modify bearer (updates) to the FPC ODL plugin.
 * @param  : op_type
 *           operation type - either JSON_OBJ_OP_TYPE_CREATE or JSON_OBJ_OP_TYPE_UPDATE
 * @param  : instruction
 *           either JSON_OBJ_INSTR_3GPP_MOB_CREATE or JSON_OBJ_INSTR_3GPP_MOB_MODIFY
 * @param  : sess_id
 *           session identifier
 * @param  : assigned_ip
 *           Assigned UE IP in network byte order
 * @param  : remote_address
 *           eNB IP - in network byte order
 * @param  : s5s8_address
 *           SGWU(in case of PGWC) or PGWU (in case of SGWC)address. Unused for SPGW.
 * @param  : local_address
 *           SGW IP - in network byte order
 * @param  : remote_teid
 *           eNB GTP Tunnel Endpoint Identifier - in network byte order
 * @param  : local_teid
 *           SGW GTP Tunnel Endpoint Identifier - in network byte order
 * @param  : imsi
 *           Subscriber identifier - Currently same as assigned_ip
 * @param  : ebi
 *           EPS Bearer Identifier *
 * @return :  0 on success, error otherwise
 */
int
send_nb_create_modify(const char *op_type, const char *instruction,
		uint64_t sess_id, uint32_t assigned_ip,
		uint32_t remote_address, uint32_t s5s8_address, uint32_t local_address,
		uint32_t remote_teid, uint32_t local_teid,
		uint64_t imsi, uint8_t ebi);

/**
 * @brief  : used to send ddn ack messages to the FPC OLD plugin
 * @param  : dl-buffering-suggested-count, dl-buffering-duration
 *           downlink_data_notification_ack_t downlink data notification
 *           information element
 * @return : 0 on success, error otherwise
 */
int
send_nb_ddn_ack(uint64_t buff_count, uint64_t buff_delay);

/**
 * @brief  : used to send delete session messages to the FPC OLD plugin
 * @param  : sess_id
 *           session identifier
 * @return : 0 on success, error otherwise
 */
int
send_nb_delete(uint64_t sess_id);

/**
 * @brief  : Acts as a server on incoming connection requests and manages handling
 *           of messages as they arrive on other established conenctions. These other
 *           connections include the S11 interface and notification & response SSE streams
 * @param  : No param
 * @return : Returns nothing
 */
void
server(void);

#endif /* __NB_SSE_CLIENT_H__ */

