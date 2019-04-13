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

#include "gtpv2c_ie.h"
#include "ue.h"
#include "cp.h"

#include <stddef.h>
#include <arpa/inet.h>

#define GTPC_UDP_PORT                                        (2123)
#define MAX_GTPV2C_UDP_LEN                                   (4096)

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
 * GTPv2c Interface coded values for use in F-TEID IE, as defined in 3GPP
 * TS 29.274, clause 8.22. These values are a subset of those defined in the TS,
 * and represent only those used by the Control Plane (in addition to a couple
 * that are not currently used).
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


#pragma pack()

/* These IE functions/macros are 'safe' in that the ie's returned, if any, fall
 * within the memory range limit specified by either the gtpv2c header or
 * grouped ie length values */

/**
 * Macro to provide address of first Information Element within message buffer
 * containing GTP header. Address may be invalid and must be validated to ensure
 * it does not exceed message buffer.
 * @param gtpv2c_h
 *   Pointer of address of message buffer containing GTP header.
 * @return
 *   Pointer of address of first Information Element.
 */
#define IE_BEGIN(gtpv2c_h)                               \
	  ((gtpv2c_h)->gtpc.teidFlg                              \
	  ? (gtpv2c_ie *)((&(gtpv2c_h)->teid_u.has_teid)+1)      \
	  : (gtpv2c_ie *)((&(gtpv2c_h)->teid_u.no_teid)+1))

/**
 * Macro to provide address of next Information Element within message buffer
 * given previous information element. Address may be invalid and must be
 * validated to ensure it does not exceed message buffer.
 * @param gtpv2c_ie_ptr
 *   Pointer of address of information element preceding desired IE..
 * @return
 *   Pointer of address of following Information Element.
 */
#define NEXT_IE(gtpv2c_ie_ptr) \
	(gtpv2c_ie *)((uint8_t *)(gtpv2c_ie_ptr + 1) \
	+ ntohs(gtpv2c_ie_ptr->length))

/**
 * Helper macro to calculate the address of some offset from some base address
 * @param base
 *   base or starting address
 * @param offset
 *   offset to be added to base for return value
 * @return
 *   Cacluated address of Offset from some Base address
 */
#define IE_LIMIT(base, offset) \
	(gtpv2c_ie *)((uint8_t *)(base) + offset)

/**
 * Helper macro to calculate the limit of a Gropued Information Element
 * @param gtpv2c_ie_ptr
 *   Pointer to address of a Grouped Information Element
 * @return
 *   The limit (or exclusive end) of a grouped information element by its length
 *   field
 */
#define GROUPED_IE_LIMIT(gtpv2c_ie_ptr)\
	IE_LIMIT(gtpv2c_ie_ptr + 1, ntohs(gtpv2c_ie_ptr->length))

/**
 * Helper macro to calculate the limit of a GTP message buffer given the GTP
 * header (which contains its length)
 * @param gtpv2c_h
 *   Pointer to address message buffer containing a GTP Header
 * @return
 *   The limit (or exclusive end) of a GTP message (and thus its IEs) given the
 *   message buffer containing a GTP header and its length field.
 */
#define GTPV2C_IE_LIMIT(gtpv2c_h)\
	IE_LIMIT(&gtpv2c_h->teid_u, ntohs(gtpv2c_h->gtpc.length))

/**
 * Helper function to get the location, according to the buffer and gtp header
 * located at '*gtpv2c_h', of the first information element according to
 * 3gppp 29.274 clause 5.6, & figure 5.6-1
 * @param gtpv2c_h
 *   header and buffer containing gtpv2c message
 * @return
 *   \- NULL \- No such information element exists due to address exceeding
 *   limit
 *   \- pointer to address of first information element, if exists.
 */
gtpv2c_ie *
get_first_ie(gtpv2c_header * gtpv2c_h);

/**
 * Helper macro to loop through GTPv2C Information Elements (IE)
 * @param gtpv2c_h
 *   Pointer to address message buffer containing a GTP Header
 * @param gtpv2c_ie_ptr
 *   Pointer to starting IE to loop from
 * @param gtpv2c_limit_ie_ptr
 *   Pointer to ending IE of the loop
 * @return
 *
 */
#define FOR_EACH_GTPV2C_IE(gtpv2c_h, gtpv2c_ie_ptr, gtpv2c_limit_ie_ptr) \
	for (gtpv2c_ie_ptr = get_first_ie(gtpv2c_h),                 \
		gtpv2c_limit_ie_ptr = GTPV2C_IE_LIMIT(gtpv2c_h);         \
		gtpv2c_ie_ptr;                                           \
		gtpv2c_ie_ptr = get_next_ie(gtpv2c_ie_ptr, gtpv2c_limit_ie_ptr))

/**
 * Calculates address of Information Element which follows gtpv2c_ie_ptr
 * according to its length field while considering the limit, which may be
 * calculated according to the buffer allocated for the GTP message or length of
 * a Information Element Group
 *
 * @param gtpv2c_ie_ptr
 *   Known information element preceding desired information element.
 * @param limit
 *   Memory limit for next information element, if one exists
 * @return
 *   \- NULL \- No such information element exists due to address exceeding
 *   limit
 *   \- pointer to address of next available information element
 */
gtpv2c_ie *
get_next_ie(gtpv2c_ie *gtpv2c_ie_ptr, gtpv2c_ie *limit);

/**
 * Helper macro to loop through GTPv2C Grouped Information Elements (IE)
 * @param parent_ie_ptr
 *   Pointer to address message buffer containing a parent GTPv2C IE
 * @param child_ie_ptr
 *   Pointer to starting child IE to loop from
 * @param gtpv2c_limit_ie_ptr
 *   Pointer to ending IE of the loop
 * @return
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

/**
 * @brief
 * Writes packet at @tx_buf of length @payload_length to pcap file specified
 * in @pcap_dumper (global)
 */
void
dump_pcap(uint16_t payload_length, uint8_t *tx_buf);

/**
 * Helper function to set the gtp header for a gtpv2c message.
 * @param gtpv2c_tx
 *   buffer used to contain gtp message for transmission
 * @param type
 *   gtp type according to 2gpp 29.274 table 6.1-1
 * @param has_teid
 *   boolean to indicate if the message requires the TEID field within the
 *   gtp header
 * @param seq
 *   sequence number as described by clause 7.6 3gpp 29.274
 */
/**void
 *set_gtpv2c_header(gtpv2c_header *gtpv2c_tx, uint8_t type,
 *     uint8_t has_teid, uint32_t seq);
 */
/**
 * Helper function to set the gtp header for a gtpv2c message with the
 * TEID field.
 * @param gtpv2c_tx
 *   buffer used to contain gtp message for transmission
 * @param type
 *   gtp type according to 2gpp 29.274 table 6.1-1
 * @param teid
 *   GTP teid, or TEID-C, to be populated in the GTP header
 * @param seq
 *   sequence number as described by clause 7.6 3gpp 29.274
 */
/**void
 *set_gtpv2c_teid_header(gtpv2c_header *gtpv2c_tx, uint8_t type,
 *    uint32_t teid, uint32_t seq);
 */
/**
 * Helper function to set the gtp header for a gtp echo message.
 * @param gtpv2c_tx
 *   buffer used to contain gtp message for transmission
 * @param type
 *   gtp type according to 2gpp 29.274 table 6.1-1
 * @param seq
 *   sequence number as described by clause 7.6 3gpp 29.274
 */
void
set_gtpv2c_echo(gtpv2c_header *gtpv2c_tx,
				uint8_t teidFlg, uint8_t type,
				uint32_t has_teid, uint32_t seq);

/* gtpv2c message handlers as defined in gtpv2c_messages folder */

/**
 * Handles the processing of bearer resource commands received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing bearer resource command message
 * @param gtpv2c_tx
 *   gtpv2c message transmission buffer to contain any triggered message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_bearer_resource_command(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx);

/**
 * Handles the processing of create bearer response messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing create bearer response
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_create_bearer_response(gtpv2c_header *gtpv2c_rx);

/**
 * Handles the processing of create session request messages received by the
 * control plane
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the create session request message
 * @param gtpv2c_s11_tx
 *   gtpc2c message transmission buffer to contain s11 response message
 * @param gtpv2c_s5s8_tx
 *   gtpc2c message transmission buffer to contain s5s8 response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx);

/**
 * from parameters, populates gtpv2c message 'create session response' and
 * populates required information elements as defined by
 * clause 7.2.2 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'create session response' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the session to be created
 * @param pdn
 *   PDN Connection data structure pertaining to the session to be created
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be created
 */
void
set_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * Handles the processing of pgwc create session request messages
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the create session request message
 * @param gtpv2c_tx
 *   gtpc2c message transmission buffer to contain response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_pgwc_s5s8_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx);

/**
 * Handles the generation of sgwc s5s8 create session request messages
 *
 * @param gtpv2c_s11_rx
 *   gtpc2c message reception  buffer containing s11 request message
 * @param gtpv2c_s5s8_tx
 *   gtpc2c message transmission buffer to contain s5s8 response message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the session to be created
 * @param pdn
 *   PDN Connection data structure pertaining to the session to be created
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be created
  * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
gen_sgwc_s5s8_create_session_request(gtpv2c_header *gtpv2c_s11_rx,
		gtpv2c_header *gtpv2c_s5s8_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * Handles processing of sgwc s5s8 create session response messages
 *
 * @param gtpv2c_rx
 *   gtpc2c message reception  buffer containing the response message
 * @param gtpv2c_tx
 *   gtpc2c message transmission buffer to contain response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_sgwc_s5s8_create_session_response(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx);

/**
 * Handles the processing of delete bearer response messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete bearer response
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_delete_bearer_response(gtpv2c_header *gtpv2c_rx);

/**
 * Handles the processing of delete session request messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete session request message
 * @param gtpv2c_s11_tx
 *   gtpc2c message transmission buffer to contain s11 response message
 * @param gtpv2c_s5s8_tx
 *   gtpc2c message transmission buffer to contain s5s8 response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx);

/**
 * Handles the processing of pgwc delete session request messages
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete session request message
 * @param gtpv2c_tx
 *   gtpv2c message buffer to contain delete session response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_pgwc_s5s8_delete_session_request(gtpv2c_header *gtpv2c_rx,
	gtpv2c_header *gtpv2c_tx);

/**
 * Handles the generation of sgwc s5s8 delete session request messages
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete session request message
 * @param gtpv2c_tx
 *   gtpv2c message buffer to contain delete session response message
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be deleted
 * @param pgw_gtpc_del_teid
 *   Default pgw_gtpc_del_teid to be deleted on PGW
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
gen_sgwc_s5s8_delete_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx, uint32_t pgw_gtpc_del_teid,
		uint32_t sequence, uint8_t del_ebi);

/**
 * Handles processing of sgwc s5s8 delete session response messages
 *
 * @param gtpv2c_rx
 *   gtpc2c message reception  buffer containing the response message
 * @param gtpv2c_tx
 *   gtpc2c message transmission buffer to contain response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_sgwc_s5s8_delete_session_response(gtpv2c_header *gtpv2c_s5s8_rx,
			gtpv2c_header *gtpv2c_s11_tx);

/**
 * Handles the processing and reply of gtp echo requests received by the control
 * plane
 *
 * @param gtpv2c_rx
 *   gtpv2c buffer received by CP containing echo request
 * @param gtpv2c_tx
 *   gtpv2c buffer to transmit from CP containing echo response
 * @return
 *   will return 0 to indicate success
 */
int
process_echo_request(gtpv2c_header *gtpv2c_rx, gtpv2c_header *gtpv2c_tx);

/**
 * Handles the processing of modify bearer request messages received by the
 * control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the modify bearer request message
 * @param gtpv2c_tx
 *   gtpv2c message transmission buffer to response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_modify_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx);


/**
 * Handles the processing of release access bearer request messages received by
 * the control plane.
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the modify bearer request message
 * @param gtpv2c_tx
 *   gtpv2c message transmission buffer to response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_release_access_bearer_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx);


/**
 * Processes a Downlink Data Notification Acknowledgement message
 * (29.274 Section 7.2.11.2).  Populates the delay value @delay
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing the Downlink Data Notification
 *   Acknowledgement to parse
 * @param delay
 *   \- 0 if no delay IE present
 *   \- > 0 The delay value to be parsed and set as specified in 29.274
 *   Table 7.2.11.2-1
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_ddn_ack(gtpv2c_header *gtpv2c_rx, uint8_t *delay);

/**
 * Creates a Downlink Data Notification message
 *
 * @param context
 *   the UE context for the DDN
 * @param eps_bearer_id
 *   the eps bearer ID to be included in the DDN
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param gtpv2c_tx
 *   gtpv2c message buffer containing the Downlink Data Notification to
 *   transmit
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 */
int
create_downlink_data_notification(ue_context *context, uint8_t eps_bearer_id,
		uint32_t sequence, gtpv2c_header *gtpv2c_tx);

/**
 * @brief
 * Utility to send or dump gtpv2c messages
 */
void
gtpv2c_send(int gtpv2c_if_id, uint8_t *gtpv2c_tx_buf,
			uint16_t gtpv2c_pyld_len, struct sockaddr *dest_addr,
			socklen_t dest_addr_len);

void
build_gtpv2_echo_request(gtpv2c_header *echo_pkt);
#endif /* GTPV2C_H */
