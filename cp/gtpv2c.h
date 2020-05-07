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

#ifndef GTPV2C_H
#define GTPV2C_H

/**
 * @file
 *
 * GTPv2C definitions and helper macros.
 *
 * GTP Message type definition and GTP header definition according to 3GPP
 * TS 29.274; as well as IE parsing helper functions/macros, and message
 * processing function declarations.
 *
 */

#include "cp.h"
#include "ue.h"
#include "gtpv2c_ie.h"

#include <stddef.h>
#include <arpa/inet.h>
#include "../libgtpv2c/include/gtp_messages.h"
#define GTPC_UDP_PORT                                        (2123)
#define MAX_GTPV2C_UDP_LEN                                   (4096)


#define PDN_TYPE_IPV4	1
#define PDN_TYPE_IPV6	2
#define PDN_TYPE_IPV4_IPV6	3

#define GTP_VERSION_GTPV2C                                   (2)

/* GTP Message Type Values */
#define GTP_ECHO_REQ                                         (1)
#define GTP_ECHO_RSP                                         (2)
#define GTP_VERSION_NOT_SUPPORTED_IND                        (3)
#define GTP_CREATE_SESSION_REQ                               (32)
#define GTP_CREATE_SESSION_RSP                               (33)
#define GTP_MODIFY_BEARER_REQ                                (34)
#define GTP_MODIFY_BEARER_RSP                                (35)
#define GTP_DELETE_SESSION_REQ                               (36)
#define GTP_DELETE_SESSION_RSP                               (37)
#define GTP_MODIFY_BEARER_CMD                                (64)
#define GTP_MODIFY_BEARER_FAILURE_IND                        (65)
#define GTP_DELETE_BEARER_CMD                                (66)
#define GTP_DELETE_BEARER_FAILURE_IND                        (67)
#define GTP_BEARER_RESOURCE_CMD                              (68)
#define GTP_BEARER_RESOURCE_FAILURE_IND                      (69)
#define GTP_DOWNLINK_DATA_NOTIFICATION_FAILURE_IND           (70)
#define GTP_TRACE_SESSION_ACTIVATION                         (71)
#define GTP_TRACE_SESSION_DEACTIVATION                       (72)
#define GTP_STOP_PAGING_IND                                  (73)
#define GTP_CREATE_BEARER_REQ                                (95)
#define GTP_CREATE_BEARER_RSP                                (96)
#define GTP_UPDATE_BEARER_REQ                                (97)
#define GTP_UPDATE_BEARER_RSP                                (98)
#define GTP_DELETE_BEARER_REQ                                (99)
#define GTP_DELETE_BEARER_RSP                                (100)
#define GTP_DELETE_PDN_CONNECTION_SET_REQ                    (101)
#define GTP_DELETE_PDN_CONNECTION_SET_RSP                    (102)
#define GTP_IDENTIFICATION_REQ                               (128)
#define GTP_IDENTIFICATION_RSP                               (129)
#define GTP_CONTEXT_REQ                                      (130)
#define GTP_CONTEXT_RSP                                      (131)
#define GTP_CONTEXT_ACK                                      (132)
#define GTP_FORWARD_RELOCATION_REQ                           (133)
#define GTP_FORWARD_RELOCATION_RSP                           (134)
#define GTP_FORWARD_RELOCATION_COMPLETE_NTF                  (135)
#define GTP_FORWARD_RELOCATION_COMPLETE_ACK                  (136)
#define GTP_FORWARD_ACCESS_CONTEXT_NTF                       (137)
#define GTP_FORWARD_ACCESS_CONTEXT_ACK                       (138)
#define GTP_RELOCATION_CANCEL_REQ                            (139)
#define GTP_RELOCATION_CANCEL_RSP                            (140)
#define GTP_CONFIGURE_TRANSFER_TUNNEL                        (141)
#define GTP_DETACH_NTF                                       (149)
#define GTP_DETACH_ACK                                       (150)
#define GTP_CS_PAGING_INDICATION                             (151)
#define GTP_RAN_INFORMATION_RELAY                            (152)
#define GTP_ALERT_MME_NTF                                    (153)
#define GTP_ALERT_MME_ACK                                    (154)
#define GTP_UE_ACTIVITY_NTF                                  (155)
#define GTP_UE_ACTIVITY_ACK                                  (156)
#define GTP_CREATE_FORWARDING_TUNNEL_REQ                     (160)
#define GTP_CREATE_FORWARDING_TUNNEL_RSP                     (161)
#define GTP_SUSPEND_NTF                                      (162)
#define GTP_SUSPEND_ACK                                      (163)
#define GTP_RESUME_NTF                                       (164)
#define GTP_RESUME_ACK                                       (165)
#define GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ       (166)
#define GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_RSP       (167)
#define GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQ       (168)
#define GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_RSP       (169)
#define GTP_RELEASE_ACCESS_BEARERS_REQ                       (170)
#define GTP_RELEASE_ACCESS_BEARERS_RSP                       (171)
#define GTP_DOWNLINK_DATA_NOTIFICATION                       (176)
#define GTP_DOWNLINK_DATA_NOTIFICATION_ACK                   (177)
#define GTP_RESERVED                                         (178)
#define GTP_PGW_RESTART_NOTIFICATION                         (179)
#define GTP_PGW_RESTART_NOTIFICATION_ACK                     (180)
#define GTP_UPDATE_PDN_CONNECTION_SET_REQ                    (200)
#define GTP_UPDATE_PDN_CONNECTION_SET_RSP                    (201)
#define GTP_MBMS_SESSION_START_REQ                           (231)
#define GTP_MBMS_SESSION_START_RSP                           (232)
#define GTP_MBMS_SESSION_UPDATE_REQ                          (233)
#define GTP_MBMS_SESSION_UPDATE_RSP                          (234)
#define GTP_MBMS_SESSION_STOP_REQ                            (235)
#define GTP_MBMS_SESSION_STOP_RSP                            (236)
#define GTP_MSG_END                                          (255)

/**
 * @brief  : GTPv2c Interface coded values for use in F-TEID IE, as defined in 3GPP
 *           TS 29.274, clause 8.22. These values are a subset of those defined in the TS,
 *           and represent only those used by the Control Plane (in addition to a couple
 *           that are not currently used).
 */
enum gtpv2c_interfaces {
	GTPV2C_IFTYPE_S1U_ENODEB_GTPU = 0,
	GTPV2C_IFTYPE_S1U_SGW_GTPU = 1,
	GTPV2C_IFTYPE_S12_RNC_GTPU = 2,
	GTPV2C_IFTYPE_S12_SGW_GTPU = 3,
	GTPV2C_IFTYPE_S5S8_SGW_GTPU = 4,
	GTPV2C_IFTYPE_S5S8_PGW_GTPU = 5,
	GTPV2C_IFTYPE_S5S8_SGW_GTPC = 6,
	GTPV2C_IFTYPE_S5S8_PGW_GTPC = 7,
	GTPV2C_IFTYPE_S5S8_SGW_PIMPv6 = 8,
	GTPV2C_IFTYPE_S5S8_PGW_PIMPv6 = 9,
	GTPV2C_IFTYPE_S11_MME_GTPC = 10,
	GTPV2C_IFTYPE_S11S4_SGW_GTPC = 11,
	GTPV2C_IFTYPE_S11U_SGW_GTPU = 39
};

#pragma pack(1)

/**
 * TODO: REMOVE_DUPLICATE_USE_LIBGTPV2C
 * Remove following structure and use structure defined in
 * libgtpv2c header file.
 * Following structure has dependency on functionality
 * which can not to be tested now.
 */
/**
 * @brief  : Maintains information related to gtpv2c header
 */
typedef struct gtpv2c_header {
	struct gtpc_t {
		uint8_t spare :3;
		uint8_t teidFlg :1;
		uint8_t piggyback :1;
		uint8_t version :3;
		uint8_t type;
		uint16_t length;
	} gtpc;
	union teid_u_t {
		struct has_teid {
			uint32_t teid;
			uint32_t seq :24;
			uint32_t spare :8;
		} has_teid;
		struct no_teid {
			uint32_t seq :24;
			uint32_t spare :8;
		} no_teid;
	} teid_u;
} gtpv2c_header;

/**
 * @brief  : Maintains information parsed from release access bearer request
 */
typedef struct parse_release_access_bearer_request_t {
	gtpv2c_header_t header;
	ue_context *context;
	uint32_t seq;
} rel_acc_ber_req;

#pragma pack()

/* These IE functions/macros are 'safe' in that the ie's returned, if any, fall
 * within the memory range limit specified by either the gtpv2c header or
 * grouped ie length values */

/**
 * @brief  : Macro to provide address of first Information Element within message buffer
 *           containing GTP header. Address may be invalid and must be validated to ensure
 *           it does not exceed message buffer.
 * @param  : gtpv2c_h
 *           Pointer of address of message buffer containing GTP header.
 * @return : Pointer of address of first Information Element.
 */
#define IE_BEGIN(gtpv2c_h)                               \
	  ((gtpv2c_h)->gtpc.teid_flag                              \
	  ? (gtpv2c_ie *)((&(gtpv2c_h)->teid.has_teid)+1)      \
	  : (gtpv2c_ie *)((&(gtpv2c_h)->teid.no_teid)+1))

/**
 * @brief  : Macro to provide address of next Information Element within message buffer
 *           given previous information element. Address may be invalid and must be
 *           validated to ensure it does not exceed message buffer.
 * @param  : gtpv2c_ie_ptr
 *           Pointer of address of information element preceding desired IE..
 * @return : Pointer of address of following Information Element.
 */
#define NEXT_IE(gtpv2c_ie_ptr) \
	(gtpv2c_ie *)((uint8_t *)(gtpv2c_ie_ptr + 1) \
	+ ntohs(gtpv2c_ie_ptr->length))

/**
 * @brief  : Helper macro to calculate the address of some offset from some base address
 * @param  : base, base or starting address
 * @param  : offset, offset to be added to base for return value
 * @return : Cacluated address of Offset from some Base address
 */
#define IE_LIMIT(base, offset) \
	(gtpv2c_ie *)((uint8_t *)(base) + offset)

/**
 * @brief  : Helper macro to calculate the limit of a Gropued Information Element
 * @param  : gtpv2c_ie_ptr
 *           Pointer to address of a Grouped Information Element
 * @return : The limit (or exclusive end) of a grouped information element by its length field
 */
#define GROUPED_IE_LIMIT(gtpv2c_ie_ptr)\
	IE_LIMIT(gtpv2c_ie_ptr + 1, ntohs(gtpv2c_ie_ptr->length))

/**
 * @brief  : Helper macro to calculate the limit of a GTP message buffer given the GTP
 *           header (which contains its length)
 * @param  : gtpv2c_h
 *           Pointer to address message buffer containing a GTP Header
 * @return : The limit (or exclusive end) of a GTP message (and thus its IEs) given the
 *           message buffer containing a GTP header and its length field.
 */
#define GTPV2C_IE_LIMIT(gtpv2c_h)\
	IE_LIMIT(&gtpv2c_h->teid, ntohs(gtpv2c_h->gtpc.message_len))

/**
 * @brief  : Helper function to get the location, according to the buffer and gtp header
 *           located at '*gtpv2c_h', of the first information element according to
 *           3gppp 29.274 clause 5.6, & figure 5.6-1
 * @param  : gtpv2c_h
 *           header and buffer containing gtpv2c message
 * @return : - NULL \- No such information element exists due to address exceeding limit
 *           - pointer to address of first information element, if exists.
 */
gtpv2c_ie *
get_first_ie(gtpv2c_header_t * gtpv2c_h);

/**
 * @brief  : Helper macro to loop through GTPv2C Information Elements (IE)
 * @param  : gtpv2c_h
 *           Pointer to address message buffer containing a GTP Header
 * @param  : gtpv2c_ie_ptr
 *           Pointer to starting IE to loop from
 * @param  : gtpv2c_limit_ie_ptr
 *           Pointer to ending IE of the loop
 * @return : nothing
 *
 */
#define FOR_EACH_GTPV2C_IE(gtpv2c_h, gtpv2c_ie_ptr, gtpv2c_limit_ie_ptr) \
	for (gtpv2c_ie_ptr = get_first_ie(gtpv2c_h),                 \
		gtpv2c_limit_ie_ptr = GTPV2C_IE_LIMIT(gtpv2c_h);         \
		gtpv2c_ie_ptr;                                           \
		gtpv2c_ie_ptr = get_next_ie(gtpv2c_ie_ptr, gtpv2c_limit_ie_ptr))

/**
 * @brief  : Calculates address of Information Element which follows gtpv2c_ie_ptr
 *           according to its length field while considering the limit, which may be
 *           calculated according to the buffer allocated for the GTP message or length of
 *           a Information Element Group
 *
 * @param  : gtpv2c_ie_ptr
 *           Known information element preceding desired information element.
 * @param  : limit
 *           Memory limit for next information element, if one exists
 * @return : - NULL \- No such information element exists due to address exceeding limit
 *           - pointer to address of next available information element
 */
gtpv2c_ie *
get_next_ie(gtpv2c_ie *gtpv2c_ie_ptr, gtpv2c_ie *limit);

/**
 * @brief  : Helper macro to loop through GTPv2C Grouped Information Elements (IE)
 * @param  : parent_ie_ptr
 *           Pointer to address message buffer containing a parent GTPv2C IE
 * @param  : child_ie_ptr
 *           Pointer to starting child IE to loop from
 * @param  : gtpv2c_limit_ie_ptr
 *           Pointer to ending IE of the loop
 * @return : Nothing
 *
 */
#define FOR_EACH_GROUPED_IE(parent_ie_ptr, child_ie_ptr, gtpv2c_limit_ie_ptr) \
	for (gtpv2c_limit_ie_ptr = GROUPED_IE_LIMIT(parent_ie_ptr),           \
	       child_ie_ptr = parent_ie_ptr + 1;                              \
	       child_ie_ptr;                                                  \
	       child_ie_ptr = get_next_ie(child_ie_ptr, gtpv2c_limit_ie_ptr))

extern struct in_addr s11_mme_ip;
extern struct sockaddr_in s11_mme_sockaddr;

extern struct in_addr s11_sgw_ip;
extern in_port_t s11_port;
extern struct sockaddr_in s11_sgw_sockaddr;
extern uint8_t s11_rx_buf[MAX_GTPV2C_UDP_LEN];
extern uint8_t s11_tx_buf[MAX_GTPV2C_UDP_LEN];
extern uint8_t tx_buf[MAX_GTPV2C_UDP_LEN];

#ifdef USE_REST
//VS: ECHO BUFFERS
extern uint8_t echo_tx_buf[MAX_GTPV2C_UDP_LEN];
#endif /* USE_REST */

extern struct in_addr s5s8_sgwc_ip;
extern in_port_t s5s8_sgwc_port;
extern struct sockaddr_in s5s8_sgwc_sockaddr;

extern struct in_addr s5s8_pgwc_ip;
extern in_port_t s5s8_pgwc_port;
extern struct sockaddr_in s5s8_pgwc_sockaddr;
extern uint8_t pfcp_tx_buf[MAX_GTPV2C_UDP_LEN];
extern uint8_t s5s8_rx_buf[MAX_GTPV2C_UDP_LEN];
extern uint8_t s5s8_tx_buf[MAX_GTPV2C_UDP_LEN];

extern struct in_addr s1u_sgw_ip;
extern struct in_addr s5s8_sgwu_ip;
extern struct in_addr s5s8_pgwu_ip;

#ifdef CP_BUILD

/* SGWC S5S8 handlers:
 * static int parse_sgwc_s5s8_create_session_response(...)
 * int gen_sgwc_s5s8_create_session_request(...)
 * int process_sgwc_s5s8_create_session_response(...)
 *
 */

/**
 * @brief  : Table 7.2.1-1: Information Elements in a Create Session Response -
 *           incomplete list
 */
typedef struct parse_sgwc_s5s8_create_session_response_t {
	uint8_t *bearer_context_to_be_created_ebi;
	fteid_ie *pgw_s5s8_gtpc_fteid;
	gtpv2c_ie *pdn_addr_alloc_ie;
	gtpv2c_ie *apn_restriction_ie;
	gtpv2c_ie *bearer_qos_ie;
	gtpv2c_ie *bearer_tft_ie;
	gtpv2c_ie *s5s8_pgw_gtpu_fteid;
}sgwc_s5s8_create_session_response_t;

/**
 * @brief  : parses gtpv2c message and populates parse_sgwc_s5s8_create_session_response_t structure
 * @param  : gtpv2c_rx
 *           buffer containing create bearer response message
 * @param  : csr
 *           data structure to contain required information elements from create
 *           create session response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */

int
parse_sgwc_s5s8_create_session_response(gtpv2c_header_t *gtpv2c_rx,
		sgwc_s5s8_create_session_response_t *csr);

/**
 * @brief  : Handles processing of sgwc s5s8 create session response messages
 * @param  : gtpv2c_rx
 *           gtpc2c message reception  buffer containing the response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_sgwc_s5s8_create_session_response(gtpv2c_header_t *gtpv2c_rx);

/**
 * @brief  : Handles processing of create bearer request  messages
 * @param  : cb_req
 *           message reception  buffer containing the request message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_create_bearer_request(create_bearer_req_t *cb_req);

/**
 * @brief  : Handles processing of sgwc s11 create bearer response messages
 * @param  : gtpv2c_rx
 *           gtpc2c message reception  buffer containing the response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_delete_bearer_request(del_bearer_req_t *db_req , uint8_t flag);

int
process_delete_bearer_resp(del_bearer_rsp_t *db_rsp , uint8_t flag);

int
process_sgwc_s11_create_bearer_response(gtpv2c_header_t *gtpv2c_rx);

/**
 * @brief  : Writes packet at @tx_buf of length @payload_length to pcap file specified
 *           in @pcap_dumper (global)
 * @param  : payload_length, total length
 * @param  : tx_buf, buffer containg packets
 * @return : Returns nothing
 */
void
dump_pcap(uint16_t payload_length, uint8_t *tx_buf);
#endif /* CP_BUILD */

/**
 * @brief  : Helper function to set the gtp header for a gtp echo message.
 * @param  : gtpv2c_tx, buffer used to contain gtp message for transmission
 * @param  : teifFlg, Indicates if tied is available or not
 * @param  : type, gtp type according to 2gpp 29.274 table 6.1-1
 * @param  : has_teid, teid information
 * @param  : seq, sequence number as described by clause 7.6 3gpp 29.274
 * @return : Returns nothing
 */
void
set_gtpv2c_echo(gtpv2c_header_t *gtpv2c_tx,
				uint8_t teidFlg, uint8_t type,
				uint32_t has_teid, uint32_t seq);

/* gtpv2c message handlers as defined in gtpv2c_messages folder */

/**
 * @brief  : Handles the processing of bearer resource commands received by the
 *           control plane.
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing bearer resource command message
 * @param  : gtpv2c_tx
 *           gtpv2c message transmission buffer to contain any triggered message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_bearer_resource_command(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Handles the processing of create bearer response messages received by the
 *           control plane.
 *
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing create bearer response
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_create_bearer_response(gtpv2c_header_t *gtpv2c_rx);

/**
 * @brief  : Handles the processing of create session request messages received by the
 *           control plane
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing the create session request message
 * @param  : gtpv2c_s11_tx
 *           gtpc2c message transmission buffer to contain s11 response message
 * @param  : gtpv2c_s5s8_tx
 *           gtpc2c message transmission buffer to contain s5s8 response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_create_session_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_s11_tx, gtpv2c_header_t *gtpv2c_s5s8_tx);

/**
 * @brief  : from parameters, populates gtpv2c message 'create session response' and
 *           populates required information elements as defined by
 *           clause 7.2.2 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'create session response' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the session to be created
 * @param  : pdn
 *           PDN Connection data structure pertaining to the session to be created
 * @param  : bearer
 *           Default EPS Bearer corresponding to the PDN Connection to be created
 * @return : Nothing
 */
void
set_create_session_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * @brief  : Handles the processing of pgwc create session request messages
 *
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing the create session request message
 * @param  : upf_ipv4, upf id address
 * @param  : proc, procedure type
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_pgwc_s5s8_create_session_request(gtpv2c_header_t *gtpv2c_rx,
		struct in_addr *upf_ipv4, uint8_t proc);

/**
 * @brief  : Handles the generation of sgwc s5s8 create session request messages
 * @param  : gtpv2c_s11_rx
 *           gtpc2c message reception  buffer containing s11 request message
 * @param  : gtpv2c_s5s8_tx
 *           gtpc2c message transmission buffer to contain s5s8 response message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : pdn
 *           PDN Connection data structure pertaining to the session to be created
 * @param  : bearer
 *           Default EPS Bearer corresponding to the PDN Connection to be created
 * @param  : sgwu_fqdn
 *           SGWU fqdn to be sent to PGWC
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
gen_sgwc_s5s8_create_session_request(gtpv2c_header_t *gtpv2c_s11_rx,
		gtpv2c_header_t *gtpv2c_s5s8_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer, char *sgwu_fqdn);

/**
 * @brief  : Handles the processing of delete bearer response messages received by the
 *           control plane.
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing delete bearer response
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_delete_bearer_response(gtpv2c_header_t *gtpv2c_rx);

/**
 * @brief  : Handles the processing of delete session request messages received by the
 *           control plane.
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing delete session request message
 * @param  : gtpv2c_s11_tx
 *           gtpc2c message transmission buffer to contain s11 response message
 * @param  : gtpv2c_s5s8_tx
 *           gtpc2c message transmission buffer to contain s5s8 response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_delete_session_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_s11_tx, gtpv2c_header_t *gtpv2c_s5s8_tx);

/**
 * @brief  : Handles the processing of pgwc delete session request messages
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing delete session request message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
//int
//process_pgwc_s5s8_delete_session_request(gtpv2c_header_t *gtpv2c_rx,
//		uint8_t proc);

/**
 * @brief  : Handles the generation of sgwc s5s8 delete session request messages
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing delete session request message
 * @param  : gtpv2c_tx
 *           gtpv2c message buffer to contain delete session response message
 * @param  : pgw_gtpc_del_teid
 *           Default pgw_gtpc_del_teid to be deleted on PGW
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : del_ebi
 *           Id of EPS Bearer to be deleted
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
gen_sgwc_s5s8_delete_session_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx, uint32_t pgw_gtpc_del_teid,
		uint32_t sequence, uint8_t del_ebi);

/**
 * @brief  : Handles processing of sgwc s5s8 delete session response messages
 * @param  : gtpv2c_rx
 *           gtpc2c message reception  buffer containing the response message
 * @param  : gtpv2c_tx
 *           gtpc2c message transmission buffer to contain response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
//int
//process_sgwc_s5s8_delete_session_response(gtpv2c_header_t *gtpv2c_s5s8_rx,
//			gtpv2c_header_t *gtpv2c_s11_tx);

/**
 * @brief  : Handles the processing and reply of gtp echo requests received by the control plane
 * @param  : gtpv2c_rx
 *           gtpv2c buffer received by CP containing echo request
 * @param  : gtpv2c_tx
 *           gtpv2c buffer to transmit from CP containing echo response
 * @return : will return 0 to indicate success
 */
int
process_echo_request(gtpv2c_header_t *gtpv2c_rx, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Handles the processing of modify bearer request messages received by the
 *           control plane.
 * @param  : gtpv2c_rx
 *           gtpv2c message buffer containing the modify bearer request message
 * @param  : gtpv2c_tx
 *           gtpv2c message transmission buffer to response message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_modify_bearer_request(gtpv2c_header_t *gtpv2c_rx,
		gtpv2c_header_t *gtpv2c_tx);


/**
 * @brief  : Handles the processing of release access bearer request messages received by
 *           the control plane.
 * @param  : rel_acc_ber_req_t
 *           gtpv2c message buffer containing the modify bearer request message
 * @param  : proc, procedure type
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_release_access_bearer_request(rel_acc_ber_req *rel_acc_ber_req_t, uint8_t proc);

/**
 * @brief  : Processes a Downlink Data Notification Acknowledgement message
 *           (29.274 Section 7.2.11.2).  Populates the delay value @delay
 * @param  : downlink_data_notification_t
 *           Containing the Downlink Data Notification Acknowledgement
 * @param  : delay
 *           - 0 if no delay IE present
 *           - > 0 The delay value to be parsed and set as specified in 29.274
 *           Table 7.2.11.2-1
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
process_ddn_ack(downlink_data_notification_t ddn_ack, uint8_t *delay);

/**
 * @brief  : Creates a Downlink Data Notification message
 * @param  : context
 *           the UE context for the DDN
 * @param  : eps_bearer_id
 *           the eps bearer ID to be included in the DDN
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : gtpv2c_tx
 *           gtpv2c message buffer containing the Downlink Data Notification to
 *           transmit
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 */
int
create_downlink_data_notification(ue_context *context, uint8_t eps_bearer_id,
		uint32_t sequence, gtpv2c_header_t *gtpv2c_tx);


/**
 * @brief  : parses gtpv2c message and populates downlink_data_notification_ack_t
 *           structure
 * @param  : gtpv2c_rx
 *           buffer containing received downlink data notification ack message
 * @param  : ddn_ack
 *           structure to contain parsed information from message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
parse_downlink_data_notification_ack(gtpv2c_header_t *gtpv2c_rx,
			downlink_data_notification_t *ddn_ack);


/**
 * @brief  : parses gtpv2c message and populates parse_release_access_bearer_request_t
 *           structure
 * @param  : gtpv2c_rx
 *           buffer containing received release access bearer request message
 * @param  : release_access_bearer_request
 *           structure to contain parsed information from message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *           specified cause error value
 *           - < 0 for all other errors
 */
int
parse_release_access_bearer_request(gtpv2c_header_t *gtpv2c_rx,
		rel_acc_ber_req *rel_acc_ber_req_t);
/**
 * @brief  : Utility to send or dump gtpv2c messages
 * @param  : gtpv2c_tx, gtpv2c message transmission buffer to response message
 * @param  : gtpv2c_pyld_len, gtpv2c message length
 * @param  : dest_addr, ip address of destination
 * @param  : dest_addr_len, destination address length
 * @return : Returns nothing
 */
void
gtpv2c_send(int gtpv2c_if_id, uint8_t *gtpv2c_tx_buf,
			uint16_t gtpv2c_pyld_len, struct sockaddr *dest_addr,
			socklen_t dest_addr_len);
/**
 * @brief  : Util to send or dump gtpv2c messages
 * @param  : fd, interface indentifier
 * @param  : t_tx, buffer to store data for peer node
 * @return : Returns nothing
 */
void
timer_retry_send(int fd, peerData *t_tx);

/**
 * @brief  : Function to build GTP-U echo request
 * @param  : echo_pkt rte_mbuf pointer
 * @param  : gtpu_seqnb, sequence number
 * @return : Returns nothing
 */
void
build_gtpv2_echo_request(gtpv2c_header_t *echo_pkt, uint16_t gtpu_seqnb);

/**
 * @brief  : Set values in modify bearer request
 * @param  : gtpv2c_tx, gtpv2c message transmission buffer to response message
 * @param  : pdn, PDN Connection data structure pertaining to the session to be created
 * @param  : bearer, Default EPS Bearer corresponding to the PDN Connection to be created
 * @return : Returns nothing
 */
void
set_modify_bearer_request(gtpv2c_header_t *gtpv2c_tx, /*create_sess_req_t *csr,*/
		  pdn_connection *pdn, eps_bearer *bearer);

/**
 * @brief  : Process modify bearer response received on s5s8 interface at sgwc
 * @param  : mb_rsp, buffer containing response data
 * @param  : gtpv2c_tx, gtpv2c message transmission buffer to response message
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_modify_bearer_response(mod_bearer_rsp_t *mb_rsp, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Process delete request on sgwc for handover scenario
 * @param  : seid, session id
 * @param  : gtpv2c_tx, gtpv2c message transmission buffer to response message
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sgwc_delete_handover(uint64_t seid,
		    gtpv2c_header_t *gtpv2c_tx);


#endif /* GTPV2C_H */
