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

#ifndef GTPV2C_SET_IE_H
#define GTPV2C_SET_IE_H

/**
 * @file
 *
 * Helper functions to add Information Elements and their specific data to
 * a message buffer containing a GTP header.
 */
#include "ue.h"
#include "gtpv2c.h"
#include "gtp_ies.h"

#include "gtp_messages_decoder.h" // Added new
#include "gtp_messages_encoder.h" // Added new

#define MAX_GTPV2C_LENGTH (MAX_GTPV2C_UDP_LEN-sizeof(struct gtpc_t))

#ifdef USE_REST
uint8_t rstCnt;
#endif /* USE_REST */

/**
 * @brief  : Copies existing information element to gtp message
 *           within transmission buffer with the GTP header '*header'
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : src_ie
 *           Existing Information element to copy into message
 * @return :
 *           size of information element copied into message
 */
uint16_t
set_ie_copy(gtpv2c_header_t *header, gtpv2c_ie *src_ie);

/**
 * @brief  : Set values in ie header
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : type, ie type value
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : length, total ie length
 * @return : Returns nothing
 */
void
set_ie_header(ie_header_t *header, uint8_t type,
		enum ie_instance instance, uint16_t length);

/**
 * @brief  : Populates cause information element with error cause value
 * @param  : cause ie
 *           cause ie
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : cause value
 *           cause value that we want to set on cause IE
 * @param  : rsp_info
 *          rsp_info specifies offending ie.
 * @return : Returns nothing
 */
void
set_cause_error_value(gtp_cause_ie_t *cause, enum ie_instance instance, uint8_t cause_value);

/**
 * @brief  : Populates cause information element with accepted value
 * @param  : cause ie
 *           cause ie
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : Returns nothing
 */
void
set_cause_accepted(gtp_cause_ie_t *cause, enum ie_instance instance);

/**
 * @brief  : Creates and populates cause information element with accepted value
 *           within transmission buffer with the GTP header '*header'
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return :
 *           size of information element created in message
 */
uint16_t
set_cause_accepted_ie(gtpv2c_header_t *header,
	enum ie_instance instance);

/**
 * @brief  : Creates and populates allocation/retention priority information element
 *           with the GTP header '*header'
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : bearer
 *           eps bearer data structure that contains priority data
 * @return :
 *           size of information element created in message
 */
uint16_t
set_ar_priority_ie(gtpv2c_header_t *header, enum ie_instance instance,
		eps_bearer *bearer);

/**
 * @brief  : Populates F-TEID information element with ipv4 value
 * @param  : fteid
 *           fully qualified teid
 * @param  : interface
 *           value indicating interface as defined by 3gpp 29.274 clause 8.22
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ipv4
 *           ipv4 address of interface
 * @param  : teid
 *           Tunnel End-point IDentifier of interface
 * @return : Returns nothing
 */
void
set_ipv4_fteid(gtp_fully_qual_tunn_endpt_idnt_ie_t *fteid,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid);

/**
 * @brief  : Creates and populates F-TEID information element with ipv4 value
 *           within transmission buffer with the GTP header '*header'
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : interface
 *           value indicating interface as defined by 3gpp 29.274 clause 8.22
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ipv4
 *           ipv4 address of interface
 * @param  : teid
 *           Tunnel End-point IDentifier of interface
 * @return :
 *           size of information element created in message
 */
uint16_t
set_ipv4_fteid_ie(gtpv2c_header_t *header,
	enum gtpv2c_interfaces interface, enum ie_instance instance,
	struct in_addr ipv4, uint32_t teid);

/**
 * @brief  : Populates 'PDN Address Allocation' information element with ipv4
 *          address of User Equipment
 * @param  : paa
 *           paa ie
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ipv4
 *           ipv4 address of user equipment
 * @return : Returns nothing
 */
void
set_ipv4_paa(gtp_pdn_addr_alloc_ie_t *paa, enum ie_instance instance,
	struct in_addr ipv4);

/**
 * @brief  : Creates & populates 'PDN Address Allocation' information element with ipv4
 *           address of User Equipment
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ipv4
 *           ipv4 address of user equipment
 * @return :
 *           size of information element created in message
 */
uint16_t
set_ipv4_paa_ie(gtpv2c_header_t *header, enum ie_instance instance,
	struct in_addr ipv4);

/**
 * @brief  : Returns ipv4 UE address from  'PDN Address Allocation' information element
 *           address of User Equipment
 * @param  : ie
 *           gtpv2c_ie information element
 * @return :
 *           ipv4 address of user equipment
 */
struct in_addr
get_ipv4_paa_ipv4(gtpv2c_ie *ie);

/**
 * @brief  : Creates & populates 'Access Point Name' restriction information element
 *           according to 3gpp 29.274 clause 8.57
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : apn_restriction
 *           value indicating the restriction according to 3gpp 29.274 table 8.57-1
 * @return :
 *           size of information element created in message
 */
uint16_t
set_apn_restriction_ie(gtpv2c_header_t *header,
		enum ie_instance instance, uint8_t apn_restriction);

/**
 * @brief  : Populates 'Access Point Name' restriction information element
 *           according to 3gpp 29.274 clause 8.57
 * @param  : apn_restriction
 *           apn restriction ie
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : apn_restriction
 *           value indicating the restriction according to 3gpp 29.274 table 8.57-1
 * @return : Returns nothing
 */
void
set_apn_restriction(gtp_apn_restriction_ie_t *apn_restriction,
		enum ie_instance instance, uint8_t restriction_type);

/**
 * @brief  : Populates 'Eps Bearer Identifier' information element
 * @param  : ebi
 *           eps bearer id ie
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ebi
 *           value indicating the EBI according to 3gpp 29.274 clause 8.8
 * @return : Returns nothing
 */
void
set_ebi(gtp_eps_bearer_id_ie_t *ebi, enum ie_instance instance,
		uint8_t eps_bearer_id);

/**
 * @brief  : Populates 'Proc Trans Identifier' information element
 * @param  : pti
 *           Proc Trans Identifier
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : pti
 *           value indicating the pti according to 3gpp 29.274 clause 8.8
 * @return : Returns nothing
 */
void
set_pti(gtp_proc_trans_id_ie_t *pti, enum ie_instance instance,
		uint8_t proc_trans_id);

/**
 * @brief  : Creates & populates 'Eps Bearer Identifier' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : ebi
 *           value indicating the EBI according to 3gpp 29.274 clause 8.8
 * @return :
 *           size of information element created in message
 */
uint16_t
set_ebi_ie(gtpv2c_header_t *header, enum ie_instance instance,
	uint8_t ebi);

/**
 * @brief  : Creates & populates 'Procedure Transaction ' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : pti
 *           Procedure transaction value from 3gpp 29.274 clause 8.35
 * @return :
 *           size of information element created in message
 */
uint16_t
set_pti_ie(gtpv2c_header_t *header, enum ie_instance instance,
	uint8_t pti);

/**
 * @brief  : Creates & populates 'Charging ID' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : charging_id
 *           general value within an information element
 * @return :
 *           size of information element created in message
 */
uint16_t
set_charging_id_ie(gtpv2c_header_t *header, enum ie_instance instance, uint32_t charging_id);

/**
 * @brief  : Set values in 'Charging ID' information element
 * @param  : charging_id
 *           structure to be filled
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : charging_id
 *           Charging id value
 * @return : Returns nothing
 */
void
set_charging_id(gtp_charging_id_ie_t *charging_id, enum ie_instance instance, uint32_t chrgng_id_val);


/**
 * @brief  : Creates & populates 'Bearer Quality of Service' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : bearer
 *           eps bearer data structure that contains qos data
 * @return :
 *           size of information element created in message
 */
uint16_t
set_bearer_qos_ie(gtpv2c_header_t *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * @brief  : Set values in 'Bearer Quality of Service' information element
 * @param  : bqos
 *           Structure to be filled
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : bearer
 *           eps bearer data structure that contains qos data
 * @return : Returns nothing
 */
void
set_bearer_qos(gtp_bearer_qlty_of_svc_ie_t *bqos, enum ie_instance instance,
		eps_bearer *bearer);

/**
 * @brief  : Creates & populates 'Traffic Flow Template' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : bearer
 *           eps bearer data structure that contains tft data
 * @return :
 *           size of information element created in message
 */
uint16_t
set_bearer_tft_ie(gtpv2c_header_t *header, enum ie_instance instance,
	eps_bearer *bearer);

/**
 * @brief  : Set values in 'Traffic Flow Template' information element
 * @param  : tft,
 *           Structure to be filled
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : eps_bearer_lvl_tft
 *           eps bearer level tft value
 * @param  : bearer
 *           eps bearer data structure that contains tft data
 * @return :
 *           size of information element
 */
uint8_t
set_bearer_tft(gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *tft,
		enum ie_instance instance, uint8_t eps_bearer_lvl_tft,
		eps_bearer *bearer);

/**
 * @brief  : Creates & populates 'recovery/restart counter' information element
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return :
 *           size of information element created in message
 */
uint16_t
set_recovery_ie(gtpv2c_header_t *header, enum ie_instance instance);


/* Group Information Element Setter & Builder Functions */

/**
 * @brief  : Modifies group_ie information element's length field, adding the length
 *           from grouped_ie_length
 * @param  : group_ie
 *           group information element (such as bearer context)
 * @param  : grouped_ie_length
 *           grouped information element contained within 'group_ie' information element
 * @return : Returns nothing
 */
void
add_grouped_ie_length(gtpv2c_ie *group_ie, uint16_t grouped_ie_length);

/**
 * @brief  : from parameters, populates gtpv2c message 'create session response' and
 *           populates required information elements
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'create session request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : pdn
 *           pdn connection information
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
void
set_create_session_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * @brief  : from parameters, populates gtpv2c message 'modify bearer response' and
 *           populates required information elements as defined by
 *           clause 7.2.8 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
void
set_modify_bearer_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer);

/* @brief  : Function added to return Response in case of Handover
 *           It performs the same as the function set_modify_bearer_response
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
void
set_modify_bearer_response_handover(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer);
/**
 * @brief  : Helper function to set the gtp header for a gtpv2c message.
 * @param  : gtpv2c_tx
 *           buffer used to contain gtp message for transmission
 * @param  : type
 *           gtp type according to 2gpp 29.274 table 6.1-1
 * @param  : has_teid
 *           boolean to indicate if the message requires the TEID field within the
 *           gtp header
 * @param  : seq
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @return : Returns nothing
 */
void
set_gtpv2c_header(gtpv2c_header_t *gtpv2c_tx,
				uint8_t teidFlg, uint8_t type,
				uint32_t has_teid, uint32_t seq);

/**
 * @brief  : Helper function to set the gtp header for a gtpv2c message with the
 *         TEID field.
 * @param  : gtpv2c_tx
 *           buffer used to contain gtp message for transmission
 * @param  : type
 *           gtp type according to 2gpp 29.274 table 6.1-1
 * @param  : teid
 *           GTP teid, or TEID-C, to be populated in the GTP header
 * @param  : seq
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @return : Returns nothing
 */
void
set_gtpv2c_teid_header(gtpv2c_header_t *gtpv2c_tx, uint8_t type,
		uint32_t teid, uint32_t seq);

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
 * @return : Returns nothing
 */
void
set_pgwc_s5s8_create_session_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer);

/**
 * @brief  : Creates & populates bearer context group information element within
 *         transmission buffer at *header
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return :
 *           bearer context created in 'header'
 */
gtpv2c_ie *
create_bearer_context_ie(gtpv2c_header_t *header,
	enum ie_instance instance);

/**
 * @brief  : Set values in fqdn ie
 * @param  : header
 *           header pre-populated that contains transmission buffer for message
 * @param  : fqdn
 *           fqdn value
 * @return : Returns nothing
 */
void
set_fqdn_ie(gtpv2c_header_t *header, char *fqdn);

/**
 * @brief  : Set values in indication ie
 * @param  : indic
 *           Structure to be filled
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : Returns nothing
 */
void
set_indication(gtp_indication_ie_t *indic, enum ie_instance instance);

/**
 * @brief  : Set values in user location information ie
 * @param  : uli
 *           Structure to be filled
 * @param  : csr
 *           buffer which holds information from create session request
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : Returns nothing
 */
void
set_uli(gtp_user_loc_info_ie_t *uli, create_sess_req_t *csr,
		               enum ie_instance instance);

/**
 * @brief  : Set values in serving network ie
 * @param  : serving_nw
 *           Structure to be filled
 * @param  : csr
 *           buffer which holds information from create session request
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : Returns nothing
 */
void
set_serving_network(gtp_serving_network_ie_t *serving_nw,
		               create_sess_req_t  *csr, enum ie_instance instance);

/**
 * @brief  : Set values in ue timezone ie
 * @param  : ue_timezone
 *           Structure to be filled
 * @param  : csr
 *           buffer which holds information from create session request
 * @param  : instance
 *           Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : Returns nothing
 */
void
set_ue_timezone(gtp_ue_time_zone_ie_t *ue_timezone,
		               create_sess_req_t *csr, enum ie_instance instance);

/**
 * @brief  : from parameters, populates gtpv2c message 'release access bearer
 *           response' and populates required information elements as defined by
 *           clause 7.2.22 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'release access bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @return : Returns nothing
 */

/* TODO: Remove #if 0 before rollup */
void
set_release_access_bearer_response(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, uint32_t s11_mme_gtpc_teid);

/**
 * @brief  : Set values in mapped ue usage type ie
 * @param  : ie
 *           Structure to be filled
 * @return : Returns nothing
 */
void
set_mapped_ue_usage_type(gtp_mapped_ue_usage_type_ie_t *ie, uint16_t usage_type_value);

#ifdef CP_BUILD
/**
 * @brief  : Decodes incoming create session request and store it in structure
 * @param  : gtpv2c_rx
 *           transmission buffer to contain 'create session request' message
 * @param  : csr
 *           buffer to store decoded information from create session request
 * @return : Returns nothing
 */
int
decode_check_csr(gtpv2c_header_t *gtpv2c_rx,
		create_sess_req_t *csr);

#endif /*CP_BUILD*/
#endif /* GTPV2C_SET_IE_H */
