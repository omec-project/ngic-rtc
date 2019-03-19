/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef GTPV2C_SET_IE_H
#define GTPV2C_SET_IE_H

/**
 * @file
 *
 * Helper functions to add Information Elements and their specific data to
 * a message buffer containing a GTP header.
 */

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "ue.h"

#define MAX_GTPV2C_LENGTH (MAX_GTPV2C_UDP_LEN-sizeof(struct gtpc_t))

/**
 * Structure for handling synchronus Create/Modify/delete session response
 * table.
 */
struct response_info {
	struct gtpv2c_header gtpv2c_tx_t;
	struct ue_context_t context_t;
	struct pdn_connection_t pdn_t;
	struct eps_bearer_t bearer_t;
	uint32_t s5s8_sgw_gtpc_del_teid_ptr;
	uint8_t msg_type;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * Copies existing information element to gtp message
 * within transmission buffer with the GTP header '*header'
 *
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param src_ie
 *   Existing Information element to copy into message
 * @return
 *   size of information element copied into message
 */
uint16_t
set_ie_copy(gtpv2c_header *header, gtpv2c_ie *src_ie);


void
set_ie_header(ie_header_t *header, uint8_t type,
		enum ie_instance instance, uint16_t length);

/**
 * Populates cause information element with accepted value
 *
 * @param cause ie
 *   cause ie
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   void
 */
void
set_cause_accepted(cause_ie_t *cause, enum ie_instance instance);

/**
 * Creates and populates cause information element with accepted value
 * within transmission buffer with the GTP header '*header'
 *
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   size of information element created in message
 */
uint16_t
set_cause_accepted_ie(gtpv2c_header *header,
	enum ie_instance instance);

/**
 * Creates and populates allocation/retention priority information element
 * with the GTP header '*header'
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains priority data
 * @return
 *   size of information element created in message
 */
uint16_t
set_ar_priority_ie(gtpv2c_header *header, enum ie_instance instance,
		eps_bearer *bearer);

/**
 * Populates F-TEID information element with ipv4 value
 *
 * @param fteid
 *   fully qualified teid
 * @param interface
 *   value indicating interface as defined by 3gpp 29.274 clause 8.22
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of interface
 * @param teid
 *   Tunnel End-point IDentifier of interface
 * @return
 *   void
 */
void
set_ipv4_fteid(fteid_ie_t *fteid,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid);

/**
 * Creates and populates F-TEID information element with ipv4 value
 * within transmission buffer with the GTP header '*header'
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param interface
 *   value indicating interface as defined by 3gpp 29.274 clause 8.22
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of interface
 * @param teid
 *   Tunnel End-point IDentifier of interface
 * @return
 *   size of information element created in message
 */
uint16_t
set_ipv4_fteid_ie(gtpv2c_header *header,
	enum gtpv2c_interfaces interface, enum ie_instance instance,
	struct in_addr ipv4, uint32_t teid);

/**
 * Populates 'PDN Address Allocation' information element with ipv4
 * address of User Equipment
 *
 * @param paa
 *   paa ie
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of user equipment
 * @return
 *   void
 */
void
set_ipv4_paa(paa_ie_t *paa, enum ie_instance instance,
	struct in_addr ipv4);

/**
 * Creates & populates 'PDN Address Allocation' information element with ipv4
 * address of User Equipment
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ipv4
 *   ipv4 address of user equipment
 * @return
 *   size of information element created in message
 */
uint16_t
set_ipv4_paa_ie(gtpv2c_header *header, enum ie_instance instance,
	struct in_addr ipv4);

/**
 * Returns ipv4 UE address from  'PDN Address Allocation' information element
 * address of User Equipment
 *
 * @param ie
 *   gtpv2c_ie information element
 * @return
 *   ipv4 address of user equipment
 */
struct in_addr
get_ipv4_paa_ipv4(gtpv2c_ie *ie);

/**
 * Creates & populates 'Access Point Name' restriction information element
 * according to 3gpp 29.274 clause 8.57
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param apn_restriction
 *   value indicating the restriction according to 3gpp 29.274 table 8.57-1
 * @return
 *   size of information element created in message
 */
uint16_t
set_apn_restriction_ie(gtpv2c_header *header,
		enum ie_instance instance, uint8_t apn_restriction);

/**
 * Populates 'Access Point Name' restriction information element
 * according to 3gpp 29.274 clause 8.57
 *
 * @param apn_restriction
 *   apn restriction ie
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param apn_restriction
 *   value indicating the restriction according to 3gpp 29.274 table 8.57-1
 * @return
 *   void
 */
void
set_apn_restriction(apn_restriction_ie_t *apn_restriction,
		enum ie_instance instance, uint8_t restriction_type);

/**
 * Populates 'Eps Bearer Identifier' information element
 *
 * @param ebi
 *   eps bearer id ie
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ebi
 *   value indicating the EBI according to 3gpp 29.274 clause 8.8
 * @return
 *   void
 */
void
set_ebi(eps_bearer_id_ie_t *ebi, enum ie_instance instance,
		uint8_t eps_bearer_id);

/**
 * Creates & populates 'Eps Bearer Identifier' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param ebi
 *   value indicating the EBI according to 3gpp 29.274 clause 8.8
 * @return
 *   size of information element created in message
 */
uint16_t
set_ebi_ie(gtpv2c_header *header, enum ie_instance instance,
	uint8_t ebi);

/**
 * Creates & populates 'Procedure Transaction ' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param pti
 *   Procedure transaction value from 3gpp 29.274 clause 8.35
 * @return
 *   size of information element created in message
 */
uint16_t
set_pti_ie(gtpv2c_header *header, enum ie_instance instance,
	uint8_t pti);

/**
 * Creates & populates 'Bearer Quality of Service' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains qos data
 * @return
 *   size of information element created in message
 */
uint16_t
set_bearer_qos_ie(gtpv2c_header *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * Creates & populates 'Traffic Flow Template' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param bearer
 *   eps bearer data structure that contains tft data
 * @return
 *   size of information element created in message
 */
uint16_t
set_bearer_tft_ie(gtpv2c_header *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * Creates & populates 'recovery/restart counter' information element
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   size of information element created in message
 */
uint16_t
set_recovery_ie(gtpv2c_header *header, enum ie_instance instance);


/* Group Information Element Setter & Builder Functions */

/**
 * Modifies group_ie information element's length field, adding the length
 * from grouped_ie_length
 *
 * @param group_ie
 *   group information element (such as bearer context)
 * @param grouped_ie_length
 *   grouped information element contained within 'group_ie' information
 *   element
 * @return
 *   size of information element created in message
 */
void
add_grouped_ie_length(gtpv2c_ie *group_ie, uint16_t grouped_ie_length);

void
set_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * from parameters, populates gtpv2c message 'modify bearer response' and
 * populates required information elements as defined by
 * clause 7.2.8 3gpp 29.274
 * @param gtpv2c_tx
 *  transmission buffer to contain 'modify bearer request' message
 * @param sequence
 *  sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *  UE Context data structure pertaining to the bearer to be modified
 * @param bearer
 *  bearer data structure to be modified
 */

void
set_modify_bearer_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer);

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
void
set_gtpv2c_header(gtpv2c_header *gtpv2c_tx,
				uint8_t teidFlg, uint8_t type,
				uint32_t teid, uint32_t seq);

/**
 * Helper function to set the gtp header for a gtpv2c message with the
 * TEID field.
 * @param gtpv2c_tx
 *    buffer used to contain gtp message for transmission
 * @param type
 *    gtp type according to 2gpp 29.274 table 6.1-1
 * @param teid
 *    GTP teid, or TEID-C, to be populated in the GTP header
 * @param seq
 *    sequence number as described by clause 7.6 3gpp 29.274
 */
void
set_gtpv2c_teid_header(gtpv2c_header *gtpv2c_tx, uint8_t type,
		uint32_t teid, uint32_t seq);

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
set_pgwc_s5s8_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * Creates & populates bearer context group information element within
 * transmission buffer at *header
 *
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   bearer context created in 'header'
 */
gtpv2c_ie *
create_bearer_context_ie(gtpv2c_header *header,
	enum ie_instance instance);

#endif /* GTPV2C_SET_IE_H */
