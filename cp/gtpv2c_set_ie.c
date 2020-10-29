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


#include "gtp_ies.h"
#include "sm_struct.h"
#include "gtpv2c_set_ie.h"
#include "packet_filters.h"
#include "gw_adapter.h"

extern int clSystemLog;
/**
 * @brief  : helper function to get the location of the next information element '*ie'
 *           that the buffer located at '*header' may be used, in the case that the size
 *           of the information element IS known ahead of time
 * @param  : header, header pre-populated that contains transmission buffer for message
 * @param  : type, information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param  : instance, Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : length, size of information element created in message
 * @return : information element to be populated
 */
static gtpv2c_ie *
set_next_ie(gtpv2c_header_t *header, uint8_t type,
		enum ie_instance instance, uint16_t length)
{
	gtpv2c_ie *ie = (gtpv2c_ie *) (((uint8_t *) &header->teid)
	    + ntohs(header->gtpc.message_len));

	if (ntohs(header->gtpc.message_len) + length
	    + sizeof(gtpv2c_ie) > MAX_GTPV2C_LENGTH) {
		rte_panic("Insufficient space in UDP buffer for IE\n");
	}

	header->gtpc.message_len = htons(
	    ntohs(header->gtpc.message_len) + length + sizeof(gtpv2c_ie));

	ie->type = type;
	ie->instance = instance;
	ie->length = htons(length);
	ie->spare = 0;

	return ie;
}

/**
 * @brief  : helper function to get the location of the next information element '*ie'
 *           that the buffer located at '*header' may be used, in the case that the size
 *           of the information element IS NOT known ahead of time
 * @param  : header, header pre-populated that contains transmission buffer for message
 * @param  : type, information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param  : instance, Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return : information element to be populated
 */
static gtpv2c_ie *
set_next_unsized_ie(gtpv2c_header_t *header, uint8_t type,
		enum ie_instance instance)
{
	gtpv2c_ie *ie = (gtpv2c_ie *) (((uint8_t *) &header->teid)
	    + ntohs(header->gtpc.message_len));

	ie->type = type;
	ie->instance = instance;
	ie->spare = 0;

	return ie;
}

/**
 * @brief  : helper function to update the size of a gtp message header field within the
 *           transmit buffer *header by the length of 'length' due to the length of the
 *           information element 'ie'
 * @param  : header, header pre-populated that contains transmission buffer for message
 * @param  : ie, information element to be added to gtp message buffer
 * @param  : length, size of information element created in message
 */
static void
set_ie_size(gtpv2c_header_t *header, gtpv2c_ie *ie, uint16_t length)
{
	if (ntohs(header->gtpc.message_len) + length
	    + sizeof(gtpv2c_ie) > MAX_GTPV2C_LENGTH) {
		rte_panic("Insufficient space in UDP buffer for IE\n");
	}
	ie->length = htons(length);
	header->gtpc.message_len = htons(
	    ntohs(header->gtpc.message_len) + length + sizeof(gtpv2c_ie));
}

/**
 * @brief  : helper function to get the information element length used to increment gtp
 *           header length field
 * @param  : ie, information element pointer
 * @return : size of information element created in message
 */
static inline uint16_t
get_ie_return(gtpv2c_ie *ie)
{
	return sizeof(gtpv2c_ie) + ntohs(ie->length);
}

/**
 * @brief  : helper function to set general value within an inforation element of size 1 byte
 * @param  : header, header pre-populated that contains transmission buffer for message
 * @param  : type, information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param  : instance, Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : value, value of information element
 * @return : size of information element(return value of get_ie_return)
 */
static uint16_t
set_uint8_ie(gtpv2c_header_t *header, uint8_t type,
		enum ie_instance instance, uint8_t value)
{
	gtpv2c_ie *ie = set_next_ie(header, type, instance, sizeof(uint8_t));
	uint8_t *value_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ie);

	*value_ptr = value;

	return get_ie_return(ie);
}

/**
 * @brief  : helper function to set general value within an information element of size 4 bytes
 * @param  : header, header pre-populated that contains transmission buffer for message
 * @param  : type, information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param  : instance, Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : value, value of information element
 * @return : size of information element(return value of get_ie_return)
 */
static uint16_t
set_uint32_ie(gtpv2c_header_t *header, uint8_t type,
		enum ie_instance instance, uint8_t value)
{
	gtpv2c_ie *ie = set_next_ie(header, type, instance, sizeof(uint32_t));
	uint32_t *value_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(uint32_t, ie);

	*value_ptr = value;

	return get_ie_return(ie);
}

uint16_t
set_ie_copy(gtpv2c_header_t *header, gtpv2c_ie *src_ie)
{
	uint16_t len = ntohs(src_ie->length);
	gtpv2c_ie *ie = set_next_ie(header, src_ie->type, src_ie->instance, len);
	memcpy(((uint8_t *)ie)+sizeof(gtpv2c_ie),((uint8_t *)src_ie)+sizeof(gtpv2c_ie),len);
	return get_ie_return(ie);
}

/**
 * @brief  : helper function to set ie header values
 * @param  : header, ie header
 * @param  : type, information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param  : instance, Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param  : length, size of information element created in message
 * @return : nothing
 */
void
set_ie_header(ie_header_t *header, uint8_t type,
		enum ie_instance instance, uint16_t length)
{
	header->type = type;
	header->instance = instance;
	header->len = length;
}

void
set_cause_error_value(gtp_cause_ie_t *cause,
		enum ie_instance instance, uint8_t cause_value, uint8_t cause_source)
{
	set_ie_header(&cause->header, GTP_IE_CAUSE, instance,
				sizeof(struct cause_ie_hdr_t));
	cause->cause_value = cause_value;
	cause->pce = 0;
	cause->bce = 0;
	cause->spareinstance = 0;
	cause->cs = cause_source;

}

void
set_cause_accepted(gtp_cause_ie_t *cause,
		enum ie_instance instance)
{
	set_ie_header(&cause->header, GTP_IE_CAUSE, instance,
	    sizeof(struct cause_ie_hdr_t));
	cause->cause_value = GTPV2C_CAUSE_REQUEST_ACCEPTED;
	cause->pce = 0;
	cause->bce = 0;
	cause->cs = 0;
	cause->spareinstance = 0;
}

void
set_csresp_cause(gtp_cause_ie_t *cause, uint8_t cause_value,
									enum ie_instance instance)
{
	set_ie_header(&cause->header, GTP_IE_CAUSE, instance,
	    sizeof(struct cause_ie_hdr_t));
	cause->cause_value = cause_value;
	cause->pce = 0;
	cause->bce = 0;
	cause->cs = 0;
	cause->spareinstance = 0;
}


uint16_t
set_ar_priority_ie(gtpv2c_header_t *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	gtpv2c_ie *ie = set_next_ie(header,
			GTP_IE_ALLOC_RETEN_PRIORITY, instance,
			sizeof(ar_priority_ie));
	ar_priority_ie *ar_priority_ie_ptr =
			IE_TYPE_PTR_FROM_GTPV2C_IE(ar_priority_ie, ie);

	ar_priority_ie_ptr->preemption_vulnerability =
			bearer->qos.arp.preemption_vulnerability;
	ar_priority_ie_ptr->spare1 = 0;
	ar_priority_ie_ptr->priority_level = bearer->qos.arp.priority_level;
	ar_priority_ie_ptr->preemption_capability =
			bearer->qos.arp.preemption_capability;
	ar_priority_ie_ptr->spare2 = 0;

	return get_ie_return(ie);
}


int
set_gtpc_fteid(gtp_fully_qual_tunn_endpt_idnt_ie_t *fteid,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		node_address_t node_value, uint32_t teid)
{
	int size = sizeof(uint8_t);
	fteid->interface_type = interface;

	fteid->teid_gre_key = teid;
	size += sizeof(uint32_t);

	if (node_value.ip_type == PDN_IP_TYPE_IPV4) {
		size += sizeof(struct in_addr);

		fteid->v4 = PRESENT;
		fteid->ipv4_address = node_value.ipv4_addr;

	} else if (node_value.ip_type == PDN_IP_TYPE_IPV6) {
		size += sizeof(struct in6_addr);

		fteid->v6 = PRESENT;
		memcpy(fteid->ipv6_address, node_value.ipv6_addr, IPV6_ADDRESS_LEN);

	} else if (node_value.ip_type == PDN_IP_TYPE_IPV4V6) {

		size += sizeof(struct in_addr);
		size += sizeof(struct in6_addr);

		fteid->v4 = PRESENT;
		fteid->v6 = PRESENT;

		fteid->ipv4_address = node_value.ipv4_addr;
		memcpy(fteid->ipv6_address, node_value.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	set_ie_header(&fteid->header, GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT, instance,
		size);
	return size + IE_HEADER_SIZE;
}

uint16_t
set_ipv4_fteid_ie(gtpv2c_header_t *header,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid)
{
	gtpv2c_ie *ie = set_next_ie(header, GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT, instance,
	    sizeof(struct fteid_ie_hdr_t) + sizeof(struct in_addr));
	fteid_ie *fteid_ie_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, ie);
	fteid_ie_ptr->fteid_ie_hdr.v4 = 1;
	fteid_ie_ptr->fteid_ie_hdr.v6 = 0;
	fteid_ie_ptr->fteid_ie_hdr.interface_type = interface;
	fteid_ie_ptr->fteid_ie_hdr.teid_or_gre = teid;
	fteid_ie_ptr->ip_u.ipv4 = ipv4;

	return get_ie_return(ie);
}

void
set_paa(gtp_pdn_addr_alloc_ie_t *paa, enum ie_instance instance,
		pdn_connection *pdn)
{
	int size = sizeof(uint8_t);
	paa->spare2 = 0;

	if (pdn->pdn_type.ipv4) {

		size += sizeof(struct in_addr);

		paa->pdn_type = PDN_IP_TYPE_IPV4;
		paa->pdn_addr_and_pfx = pdn->ipv4.s_addr;

	}

	if (pdn->pdn_type.ipv6) {

		size += sizeof(uint8_t) + sizeof(struct in6_addr);

		paa->pdn_type = PDN_IP_TYPE_IPV6;
		paa->ipv6_prefix_len = pdn->prefix_len;
		memcpy(paa->paa_ipv6, pdn->ipv6.s6_addr, IPV6_ADDRESS_LEN);
	}

	if (pdn->pdn_type.ipv4 && pdn->pdn_type.ipv6)
		paa->pdn_type = PDN_IP_TYPE_IPV4V6;

	set_ie_header(&paa->header, GTP_IE_PDN_ADDR_ALLOC, instance, size);

	return;
}

uint16_t
set_ipv4_paa_ie(gtpv2c_header_t *header, enum ie_instance instance,
		struct in_addr ipv4)
{
	gtpv2c_ie *ie = set_next_ie(header, GTP_IE_PDN_ADDR_ALLOC, instance,
	    sizeof(struct paa_ie_hdr_t) + sizeof(struct in_addr));
	paa_ie *paa_ie_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(paa_ie, ie);

	paa_ie_ptr->paa_ie_hdr.pdn_type = PDN_IP_TYPE_IPV4;
	paa_ie_ptr->paa_ie_hdr.spare = 0;
	paa_ie_ptr->ip_type_union.ipv4 = ipv4;

	return get_ie_return(ie);
}


struct in_addr
get_ipv4_paa_ipv4(gtpv2c_ie *ie)
{
	paa_ie *paa_ie_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(paa_ie, ie);
	paa_ie_ptr->paa_ie_hdr.pdn_type = PDN_IP_TYPE_IPV4;
	paa_ie_ptr->paa_ie_hdr.spare = 0;
	return(paa_ie_ptr->ip_type_union.ipv4);
}

void
set_apn_restriction(gtp_apn_restriction_ie_t *apn_restriction,
		enum ie_instance instance, uint8_t restriction_type)
{
	set_ie_header(&apn_restriction->header,	GTP_IE_APN_RESTRICTION,
		instance, sizeof(uint8_t));

	apn_restriction->rstrct_type_val = restriction_type;

	return;
}

void
set_change_reporting_action(gtp_chg_rptng_act_ie_t *chg_rptng_act,
		 enum ie_instance instance, uint8_t action)
{

	set_ie_header(&chg_rptng_act->header, GTP_IE_CHG_RPTNG_ACT,
		instance, sizeof(uint8_t));

	chg_rptng_act->action = action;

}

uint16_t
set_apn_restriction_ie(gtpv2c_header_t *header,
		enum ie_instance instance, uint8_t apn_restriction)
{
	return set_uint8_ie(header, GTP_IE_APN_RESTRICTION, instance,
			apn_restriction);
}

void
set_ebi(gtp_eps_bearer_id_ie_t *ebi, enum ie_instance instance,
		uint8_t eps_bearer_id)
{
	set_ie_header(&ebi->header, GTP_IE_EPS_BEARER_ID, instance, sizeof(uint8_t));

	ebi->ebi_ebi = eps_bearer_id;
	ebi->ebi_spare2 = 0;
}

void
set_ar_priority(gtp_alloc_reten_priority_ie_t *arp, enum ie_instance instance,
		eps_bearer *bearer)
{
	set_ie_header(&arp->header, GTP_IE_ALLOC_RETEN_PRIORITY, instance, sizeof(uint8_t));
	arp->spare2 = 0;
	arp->pci = bearer->qos.arp.preemption_capability;
	arp->pl = bearer->qos.arp.priority_level;
	arp->pvi = bearer->qos.arp.preemption_vulnerability;
	arp->spare3 = 0;
}

/**
 * @brief  : generate a packet filter identifier based on availabe for that bearer
 * @param  : bearer,
 *           to check the identifier availablity
 * @return  : identifier between 1 to 16 for sucess and -1 for failure
 */
static int
get_packet_filter_identifier(eps_bearer *bearer){

	for(uint8_t i = 1; i <= MAX_FILTERS_PER_UE; i++ ){
		if(bearer->packet_filter_map[i] == NOT_PRESENT){
			bearer->packet_filter_map[i] = PRESENT;
			return i;
		}
	}

	return -1;
}


uint8_t
set_bearer_tft(gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *tft,
		enum ie_instance instance, uint8_t tft_op_code,
		eps_bearer *bearer, char *rule_name)
{
	uint32_t mask;
	uint8_t i = 0;
	uint8_t length;
	uint8_t len_index = 0;
	uint8_t tft_op_code_index = 0;
	dynamic_rule_t *rule = NULL;
	uint8_t num_rule_filters = 0;
	uint8_t counter = 0;
	uint8_t num_dyn_rule = bearer->num_dynamic_filters;
	uint8_t num_prdef_rule = bearer->num_prdef_filters;

	num_rule_filters = num_dyn_rule + num_prdef_rule;

	tft_op_code_index = i;
	tft->eps_bearer_lvl_tft[i++] = tft_op_code;
	for(uint8_t iCnt = 0; iCnt < num_rule_filters; ++iCnt) {

		if(num_prdef_rule){
			counter = bearer->num_prdef_filters - num_prdef_rule;
			rule = bearer->prdef_rules[counter];
			num_prdef_rule--;
		}else if(num_dyn_rule){
			counter = bearer->num_dynamic_filters - num_dyn_rule;
			rule = bearer->dynamic_rules[counter];
			num_dyn_rule--;
		}else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT" No filters present in bearer \n", LOG_VALUE);
			return -1;
		}

		if(tft_op_code != TFT_CREATE_NEW &&
			(rule_name != NULL &&
			(strncmp(rule_name, rule->rule_name, RULE_NAME_LEN) != 0 ))){
			continue;
		}

		for(int flow_cnt = 0; flow_cnt < rule->num_flw_desc; flow_cnt++) {

			length = 0;
			tft->eps_bearer_lvl_tft[tft_op_code_index] += 1;
			/*Store packet filter identifier in rule*/
			if(rule->flow_desc[flow_cnt].sdf_flw_desc.direction &&
				tft_op_code != TFT_REMOVE_FILTER_EXISTING)
				rule->flow_desc[flow_cnt].pckt_fltr_identifier = get_packet_filter_identifier(bearer);

			if(tft_op_code == TFT_REMOVE_FILTER_EXISTING){
				tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].pckt_fltr_identifier;
				bearer->packet_filter_map[rule->flow_desc[flow_cnt].pckt_fltr_identifier] = NOT_PRESENT;
				continue;
			}

			if(TFT_DIRECTION_UPLINK_ONLY == rule->flow_desc[flow_cnt].sdf_flw_desc.direction) {
				tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].pckt_fltr_identifier + TFT_UPLINK;
			} else if(TFT_DIRECTION_DOWNLINK_ONLY ==
					rule->flow_desc[flow_cnt].sdf_flw_desc.direction) {
				tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].pckt_fltr_identifier + TFT_DOWNLINK;
			} else if(TFT_DIRECTION_BIDIRECTIONAL ==
					rule->flow_desc[flow_cnt].sdf_flw_desc.direction) {
				tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].pckt_fltr_identifier + TFT_BIDIRECTIONAL;
			} else {
				tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].pckt_fltr_identifier;
			}

			tft->eps_bearer_lvl_tft[i++] = rule->precedence; /* precedence */

			len_index = i++;

			tft->eps_bearer_lvl_tft[i++] = TFT_PROTO_IDENTIFIER_NEXT_HEADER_TYPE;
			tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.proto_id;
			length += 2;

			if(TFT_DIRECTION_DOWNLINK_ONLY == rule->flow_desc[flow_cnt].sdf_flw_desc.direction) {

				tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_REMOTE_PORT_TYPE;
				tft->eps_bearer_lvl_tft[i++] =
					(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low >> 8) & 0xff;
				tft->eps_bearer_lvl_tft[i++] =
					rule->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low & 0xff;
				length += 3;

				tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_SRC_PORT_TYPE;
				tft->eps_bearer_lvl_tft[i++] =
					(rule->flow_desc[flow_cnt].sdf_flw_desc.local_port_low >> 8) & 0xff;
				tft->eps_bearer_lvl_tft[i++] =
					rule->flow_desc[flow_cnt].sdf_flw_desc.local_port_low & 0xff;
				length += 3;

				if (rule->flow_desc[flow_cnt].sdf_flw_desc.v4) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_SRC_ADDR_TYPE;
					tft->eps_bearer_lvl_tft[i++] =
						rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 24) & 0xff;
					length += 5;

					mask = 0xffffffff << (32 - rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask);
					tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
					length += 4;
				} else if (rule->flow_desc[flow_cnt].sdf_flw_desc.v6)   {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV6_SRC_ADDR_PREFIX_LEN_TYPE;

					for (int cnt = 0; cnt < IPV6_ADDRESS_LEN; cnt++) {
						tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip6_addr.s6_addr[cnt];
					}

					length += IPV6_ADDRESS_LEN + 1;

					tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask;
					length += 1;

				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Invalid IP address family type is set",
							"Cannot set Traffic Flow Template\n",LOG_VALUE);
				}


				if (rule->flow_desc[flow_cnt].sdf_flw_desc.v4) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_REMOTE_ADDR_TYPE;
					tft->eps_bearer_lvl_tft[i++] =
						rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 24) & 0xff;
					length += 5;

					mask = 0xffffffff << (32 - rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask);
					tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
					length += 4;
				} else if (rule->flow_desc[flow_cnt].sdf_flw_desc.v6) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV6_REMOTE_ADDR_PREFIX_LEN_TYPE;

					for (int cnt = 0; cnt < IPV6_ADDRESS_LEN; cnt++) {
						tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip6_addr.s6_addr[cnt];
					}

					length += IPV6_ADDRESS_LEN + 1;

					tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask;
					length += 1;

				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Invalid IP address family type is set",
							"Cannot set Traffic Flow Template\n",LOG_VALUE);
				}

			} else {
				tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_REMOTE_PORT_TYPE;
				tft->eps_bearer_lvl_tft[i++] =
					(rule->flow_desc[flow_cnt].sdf_flw_desc.local_port_low >> 8) & 0xff;
				tft->eps_bearer_lvl_tft[i++] =
					rule->flow_desc[flow_cnt].sdf_flw_desc.local_port_low & 0xff;
				length += 3;

				tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_SRC_PORT_TYPE;
				tft->eps_bearer_lvl_tft[i++] =
					(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low >> 8) & 0xff;
				tft->eps_bearer_lvl_tft[i++] =
					rule->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low & 0xff;
				length += 3;

				if (rule->flow_desc[flow_cnt].sdf_flw_desc.v4) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_SRC_ADDR_TYPE;
					tft->eps_bearer_lvl_tft[i++] =
						rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 24) & 0xff;
					length += 5;

					mask = 0xffffffff << (32 - rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask);
					tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
					length += 4;

				} else if (rule->flow_desc[flow_cnt].sdf_flw_desc.v6) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV6_SRC_ADDR_PREFIX_LEN_TYPE;

					for (int cnt = 0; cnt < IPV6_ADDRESS_LEN; cnt++) {
						tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip6_addr.s6_addr[cnt];
					}

					length += IPV6_ADDRESS_LEN + 1;

					tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask;
					length += 1;

				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Invalid IP address family type is set",
							"Cannot set Traffic Flow Template\n",LOG_VALUE);
				}

				if (rule->flow_desc[flow_cnt].sdf_flw_desc.v4) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_REMOTE_ADDR_TYPE;
					tft->eps_bearer_lvl_tft[i++] =
						rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] =
						(rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 24) & 0xff;
					length += 5;

					mask = 0xffffffff << (32 - rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask);
					tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
					tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
					length += 4;

				} else if (rule->flow_desc[flow_cnt].sdf_flw_desc.v6) {

					tft->eps_bearer_lvl_tft[i++] = TFT_IPV6_REMOTE_ADDR_PREFIX_LEN_TYPE;

					for (int cnt = 0; cnt < IPV6_ADDRESS_LEN; cnt++) {
						tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip6_addr.s6_addr[cnt];
					}

					length += IPV6_ADDRESS_LEN + 1;

					tft->eps_bearer_lvl_tft[i++] = rule->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask;
					length += 1;

				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Invalid IP address family type is set",
							"Cannot set Traffic Flow Template\n",LOG_VALUE);
				}


			}

			tft->eps_bearer_lvl_tft[len_index] = length; /* length */
		}
	}

	set_ie_header(&tft->header, GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL, instance, i);

	return (i + IE_HEADER_SIZE);
}

void
set_pti(gtp_proc_trans_id_ie_t *pti, enum ie_instance instance,
		uint8_t proc_trans_id)
{
	set_ie_header(&pti->header, GTP_IE_PROC_TRANS_ID, instance, sizeof(uint8_t));

	pti->proc_trans_id = proc_trans_id;
}

uint16_t
set_ebi_ie(gtpv2c_header_t *header, enum ie_instance instance, uint8_t ebi)
{
	if (ebi & 0xF0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI used %"PRIu8"\n", LOG_VALUE, ebi);
	return set_uint8_ie(header, GTP_IE_EPS_BEARER_ID, instance, ebi);
}


uint16_t
set_pti_ie(gtpv2c_header_t *header, enum ie_instance instance, uint8_t pti)
{
	return set_uint8_ie(header, GTP_IE_PROC_TRANS_ID, instance, pti);
}

uint16_t
set_charging_id_ie(gtpv2c_header_t *header, enum ie_instance instance, uint32_t charging_id)
{
	return set_uint32_ie(header, GTP_IE_PROC_TRANS_ID, instance, charging_id);
}

void
set_charging_id(gtp_charging_id_ie_t *charging_id, enum ie_instance instance, uint32_t chrgng_id_val)
{
	set_ie_header(&charging_id->header, GTP_IE_CHARGING_ID, instance, sizeof(uint8_t));

	charging_id->chrgng_id_val = chrgng_id_val;
}

void
set_bearer_qos(gtp_bearer_qlty_of_svc_ie_t *bqos, enum ie_instance instance,
		eps_bearer *bearer)
{
	set_ie_header(&bqos->header, GTP_IE_BEARER_QLTY_OF_SVC,
			instance, (sizeof(gtp_bearer_qlty_of_svc_ie_t) - IE_HEADER_SIZE));

	bqos->spare2 = 0;
	bqos->pci = bearer->qos.arp.preemption_capability;
	bqos->pl = bearer->qos.arp.priority_level;;
	bqos->spare3 = 0;
	bqos->pvi = bearer->qos.arp.preemption_vulnerability;
	bqos->qci = bearer->qos.qci;
	bqos->max_bit_rate_uplnk = bearer->qos.ul_mbr;
	bqos->max_bit_rate_dnlnk = bearer->qos.dl_mbr;
	bqos->guarntd_bit_rate_uplnk = bearer->qos.ul_gbr;
	bqos->guarntd_bit_rate_dnlnk = bearer->qos.dl_gbr;
}

uint16_t
set_bearer_qos_ie(gtpv2c_header_t *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	/* subtract 12 from size as MBR, GBR for uplink and downlink are
	 * uint64_t but encoded in 5 bytes.
	 */
	gtpv2c_ie *ie = set_next_ie(header, GTP_IE_BEARER_QLTY_OF_SVC, instance,
	    sizeof(bearer_qos_ie) - 12);
	bearer_qos_ie *bqos = IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_qos_ie, ie);

	bqos->arp.preemption_vulnerability =
			bearer->qos.arp.preemption_vulnerability;
	bqos->arp.spare1 = 0;
	bqos->arp.priority_level = bearer->qos.arp.priority_level;
	bqos->arp.preemption_capability =
			bearer->qos.arp.preemption_capability;
	bqos->arp.spare2 = 0;

	/* VS: Need to remove following memcpy statement */
	/* subtract 12 from size as MBR, GBR for uplink and downlink are
	 * uint64_t but encoded in 5 bytes.
	 */
	/* memcpy(&bqos->qos, &bearer->qos.qos, sizeof(bqos->qos) - 12); */
	/**
	 * IE specific data segment for Quality of Service (QoS).
	 *
	 * Definition used by bearer_qos_ie and flow_qos_ie.
	 */
	bqos->qci = bearer->qos.qci;
	bqos->ul_mbr = bearer->qos.ul_mbr;
	bqos->dl_mbr = bearer->qos.dl_mbr;
	bqos->ul_gbr = bearer->qos.ul_gbr;
	bqos->dl_gbr = bearer->qos.dl_gbr;

	return get_ie_return(ie);
}


uint16_t
set_bearer_tft_ie(gtpv2c_header_t *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	gtpv2c_ie *ie = set_next_unsized_ie(header, GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL, instance);
	bearer_tft_ie *tft = IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_tft_ie, ie);
	create_pkt_filter *cpf = (create_pkt_filter *) &tft[1];
	uint8_t i;
	uint16_t ie_length = 0;

	tft->num_pkt_filters = 0;
	tft->tft_op_code = TFT_OP_CREATE_NEW;
	tft->parameter_list = 0;

	for (i = 0; i < MAX_FILTERS_PER_UE; ++i) {
		if (bearer->packet_filter_map[i] == -ENOENT)
			continue;

		++tft->num_pkt_filters;
		packet_filter *pf =
				get_packet_filter(bearer->packet_filter_map[i]);
		if (pf == NULL)
			continue;
		packet_filter_component *component =
				(packet_filter_component *) &cpf[1];
		cpf->pkt_filter_id = i;
		cpf->direction = pf->pkt_fltr.direction;
		cpf->spare = 0;
		/*TODO : This param is removed from SDF.
		/Handle it appropriatly here.*/
		/*cpf->precedence = pf->pkt_fltr.precedence;*/
		cpf->precedence = 0;
		cpf->pkt_filter_length = 0;

		if (pf->pkt_fltr.remote_ip_mask != 0) {
			component->type = IPV4_REMOTE_ADDRESS;
			component->type_union.ipv4.ipv4 =
					pf->pkt_fltr.remote_ip_addr;
			component->type_union.ipv4.mask.s_addr = UINT32_MAX
			    >> (32 - pf->pkt_fltr.remote_ip_mask);
			component =
			    (packet_filter_component *)
			    &component->type_union.ipv4.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.ipv4);
		}

		if (pf->pkt_fltr.local_ip_mask != 0) {
			component->type = IPV4_LOCAL_ADDRESS;
			component->type_union.ipv4.ipv4 =
					pf->pkt_fltr.local_ip_addr;
			component->type_union.ipv4.mask.s_addr =
				UINT32_MAX >> (32 - pf->pkt_fltr.local_ip_mask);
			component =
			    (packet_filter_component *)
			    &component->type_union.ipv4.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.ipv4);
		}

		if (pf->pkt_fltr.proto_mask != 0) {
			component->type = PROTOCOL_ID_NEXT_HEADER;
			component->type_union.proto.proto = pf->pkt_fltr.proto;
			component =
			    (packet_filter_component *)
			    &component->type_union.proto.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.proto);
		}

		if (pf->pkt_fltr.remote_port_low ==
			pf->pkt_fltr.remote_port_high) {
			component->type = SINGLE_REMOTE_PORT;
			component->type_union.port.port =
					pf->pkt_fltr.remote_port_low;
			component =
			    (packet_filter_component *)
			    &component->type_union.port.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.port);
		} else if (pf->pkt_fltr.remote_port_low != 0 ||
				pf->pkt_fltr.remote_port_high != UINT16_MAX) {
			component->type = REMOTE_PORT_RANGE;
			component->type_union.port_range.port_low =
					pf->pkt_fltr.remote_port_low;
			component->type_union.port_range.port_high =
					pf->pkt_fltr.remote_port_high;
			component =
			    (packet_filter_component *)
			    &component->type_union.port_range.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.port_range);
		}

		if (pf->pkt_fltr.local_port_low ==
			pf->pkt_fltr.local_port_high) {
			component->type = SINGLE_LOCAL_PORT;
			component->type_union.port.port =
					pf->pkt_fltr.local_port_low;
			component =
			    (packet_filter_component *)
			    &component->type_union.port.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.port);
		} else if (pf->pkt_fltr.local_port_low != 0 ||
				pf->pkt_fltr.local_port_high != UINT16_MAX) {
			component->type = LOCAL_PORT_RANGE;
			component->type_union.port_range.port_low =
					pf->pkt_fltr.local_port_low;
			component->type_union.port_range.port_high =
					pf->pkt_fltr.local_port_high;
			component =
			    (packet_filter_component *)
			    &component->type_union.port_range.next_component;
			cpf->pkt_filter_length +=
				sizeof(component->type_union.port_range);
		}

		ie_length += cpf->pkt_filter_length + sizeof(create_pkt_filter);
		cpf = (create_pkt_filter *) component;
	}

	set_ie_size(header, ie, sizeof(bearer_tft_ie) + ie_length);
	return get_ie_return(ie);
}


uint16_t
set_recovery_ie(gtpv2c_header_t *header, enum ie_instance instance)
{
	/** TODO: According to 3gpp TS 29.274 [7.1.1] and 23.007 [16.1.1
	 * Restoration Procedures] this value (currently using 0) *should*
	 * be obtained at SPGW startup, from a local non-volatile counter
	 * (modulo 256) which is denoted  as the 'local Restart Counter'.
	 * Instead we set this value as 0
	 */
#ifdef USE_REST
	/* Support for restart counter */
	return set_uint8_ie(header, GTP_IE_RECOVERY, instance, rstCnt);
#else
	return set_uint8_ie(header, GTP_IE_RECOVERY, instance, 0);
#endif /* USE_REST */
}


void
add_grouped_ie_length(gtpv2c_ie *group_ie, uint16_t grouped_ie_length)
{
	group_ie->length = htons(ntohs(group_ie->length) + grouped_ie_length);
}


gtpv2c_ie *
create_bearer_context_ie(gtpv2c_header_t *header,
		enum ie_instance instance)
{
	return set_next_ie(header, GTP_IE_BEARER_CONTEXT, instance, 0);
}

void
set_fqdn_ie(gtpv2c_header_t *header, char *fqdn)
{
	gtpv2c_ie *ie = set_next_ie(header, GTP_IE_FULLY_QUAL_DOMAIN_NAME, IE_INSTANCE_ZERO,
			    strnlen(fqdn, 256));
	fqdn_type_ie *fqdn_ie_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(fqdn_type_ie, ie);
	strncpy((char *)fqdn_ie_ptr->fqdn, fqdn, strnlen(fqdn, 255) + 1);
}

#ifdef CP_BUILD
pfcp_config_t config;

int
decode_check_csr(gtpv2c_header_t *gtpv2c_rx,
		create_sess_req_t *csr, uint8_t *cp_type)
{
	int ret = 0;
	ret = decode_create_sess_req((uint8_t *) gtpv2c_rx,
			csr);

	if (!ret){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Decoding for csr req failed", LOG_VALUE);
		return -1;
	}

	if (csr->indctn_flgs.header.len &&
			csr->indctn_flgs.indication_uimsi) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n", LOG_VALUE);
		return GTPV2C_CAUSE_IMSI_NOT_KNOWN;
	}

	/* Dynamically Set the gateway modes */
	if (csr->pgw_s5s8_addr_ctl_plane_or_pmip.header.len != 0) {

		if((config.s5s8_ip_type != PDN_IP_TYPE_IPV4V6) &&
		  ((csr->pgw_s5s8_addr_ctl_plane_or_pmip.v4 &&
			csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address != 0 &&
			config.s5s8_ip_type != PDN_IP_TYPE_IPV4) ||
			(csr->pgw_s5s8_addr_ctl_plane_or_pmip.v6 &&
			 *csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address != 0 &&
			config.s5s8_ip_type != PDN_IP_TYPE_IPV6))){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"SGW S5S8 interface not supported for"
															" Requested PGW IP type\n", LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}
		struct in6_addr temp = {0};
		if ((csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address != 0
				|| csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address != 0)
				&& (config.s5s8_ip.s_addr != 0
					|| *config.s5s8_ip_v6.s6_addr)) {
			/* Selection Criteria for Combined GW, SAEGWC */
			if((((csr->pgw_s5s8_addr_ctl_plane_or_pmip.v4)
							&& (csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address == config.s5s8_ip.s_addr))
						|| (csr->pgw_s5s8_addr_ctl_plane_or_pmip.v6
							&& (!memcmp(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address,
										temp.s6_addr, IPV6_ADDRESS_LEN)
								|| (memcmp(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address,
										config.s5s8_ip_v6.s6_addr, IPV6_ADDRESS_LEN) == 0))))
					|| (((csr->pgw_s5s8_addr_ctl_plane_or_pmip.v4)
							&& (csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address == config.s11_ip.s_addr))
						|| (csr->pgw_s5s8_addr_ctl_plane_or_pmip.v6
							&& memcmp(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address,
								config.s11_ip_v6.s6_addr, IPV6_ADDRESS_LEN) == 0))) {

				/* Condition to Allow GW run as a Combined GW */
				if (config.cp_type == SAEGWC) {
					*cp_type = SAEGWC;
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Not Valid CSR Request for configured GW, Gateway Mode:%s\n",
							LOG_VALUE, config.cp_type == SGWC ? "SGW-C" :
							config.cp_type == PGWC ? "PGW-C" :
							config.cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");
					return GTPV2C_CAUSE_REQUEST_REJECTED;
				}
			} else {
				/* Selection Criteria for SGWC */
				if ((config.cp_type != PGWC) &&
					((csr->pgw_s5s8_addr_ctl_plane_or_pmip.v4
						&& (csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address  != csr->sender_fteid_ctl_plane.ipv4_address))
						|| (csr->pgw_s5s8_addr_ctl_plane_or_pmip.v6
							&& memcmp(csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv6_address, csr->sender_fteid_ctl_plane.ipv6_address,
													IPV6_ADDRESS_LEN) != 0))) {
					*cp_type = SGWC;
				} else {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Not Valid CSR Request for configured GW, Gateway Mode:%s\n",
							LOG_VALUE, config.cp_type == SGWC ? "SGW-C" :
							config.cp_type == PGWC ? "PGW-C" :
							config.cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");
					return GTPV2C_CAUSE_REQUEST_REJECTED;
				}
			}
		} else {
			/* Condition to Allow GW run as a Combined GW */
			if (config.cp_type == SAEGWC) {
				*cp_type = SAEGWC;
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Not Valid CSR Request for configured GW, Gateway Mode:%s\n",
						LOG_VALUE, config.cp_type == SGWC ? "SGW-C" :
						config.cp_type == PGWC ? "PGW-C" :
						config.cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");
				return GTPV2C_CAUSE_REQUEST_REJECTED;
			}
		}
	} else if (csr->sender_fteid_ctl_plane.interface_type == S5_S8_SGW_GTP_C) {
		/* Selection Criteria for PGWC */
		if (config.cp_type != SGWC) {
			*cp_type = PGWC;
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Not Valid CSR Request for configured GW, Gateway Mode:%s\n",
					LOG_VALUE, config.cp_type == SGWC ? "SGW-C" :
					config.cp_type == PGWC ? "PGW-C" :
					config.cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}
	} else {
		if (config.cp_type == SAEGWC) {
			*cp_type = SAEGWC;
		} else {
			/* Not meet upto selection Criteria */
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to Select or Set Gateway Mode, Dropping packet\n",
					LOG_VALUE);
			return GTPV2C_CAUSE_REQUEST_REJECTED;
		}
	}

	if ((*cp_type == SGWC) &&
			(!csr->pgw_s5s8_addr_ctl_plane_or_pmip.header.len)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Mandatory IE missing. Dropping packet len:%u\n",
				LOG_VALUE,
				csr->pgw_s5s8_addr_ctl_plane_or_pmip.header.len);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (!csr->sender_fteid_ctl_plane.header.len
			|| !csr->imsi.header.len
			|| !csr->apn_ambr.header.len
			|| !csr->pdn_type.header.len
			|| !csr->rat_type.header.len
			|| !csr->apn.header.len) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Mandatory IE missing. Dropping packet\n",
				LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	for (uint8_t iCnt = 0; iCnt < csr->bearer_count; ++iCnt) {
		if (!csr->bearer_contexts_to_be_created[iCnt].header.len
			|| !csr->bearer_contexts_to_be_created[iCnt].bearer_lvl_qos.header.len) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Bearer Context IE missing. Dropping packet\n",
					LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}
	}

	return 0;
}

void
set_serving_network(gtp_serving_network_ie_t *serving_nw, create_sess_req_t *csr,  enum ie_instance instance)
{
	set_ie_header(&serving_nw->header, GTP_IE_SERVING_NETWORK, instance,
			sizeof(uint8_t)*3);
	serving_nw->mcc_digit_2 =  csr->serving_network.mcc_digit_2;
	serving_nw->mcc_digit_1 =  csr->serving_network.mcc_digit_1;
	serving_nw->mnc_digit_3 =  csr->serving_network.mnc_digit_3;
	serving_nw->mcc_digit_3 =  csr->serving_network.mcc_digit_3;
	serving_nw->mnc_digit_2 =  csr->serving_network.mnc_digit_2;
	serving_nw->mnc_digit_1 =  csr->serving_network.mnc_digit_1;
}

void
set_ue_timezone(gtp_ue_time_zone_ie_t *ue_timezone, create_sess_req_t *csr,  enum ie_instance instance)
{
	set_ie_header(&ue_timezone->header, GTP_IE_UE_TIME_ZONE, instance,
			sizeof(uint8_t)*2);
	ue_timezone->time_zone = csr->ue_time_zone.time_zone;
	ue_timezone->spare2 = csr->ue_time_zone.spare2;
	ue_timezone->daylt_svng_time = csr->ue_time_zone.daylt_svng_time;
}


void
set_mapped_ue_usage_type(gtp_mapped_ue_usage_type_ie_t *ie, uint16_t usage_type_value)
{
	set_ie_header(&ie->header, GTP_IE_MAPPED_UE_USAGE_TYPE, 0,
			sizeof(uint16_t));
	ie->mapped_ue_usage_type = usage_type_value;
}


void
set_presence_reporting_area_action_ie(gtp_pres_rptng_area_act_ie_t *ie, ue_context *context){

	uint8_t size = 0;
	ie->action = context->pre_rptng_area_act.action;
	size += sizeof(uint8_t);
	ie->pres_rptng_area_idnt = context->pre_rptng_area_act.pres_rptng_area_idnt;
	size += 3*sizeof(uint8_t);
	ie->number_of_tai = context->pre_rptng_area_act.number_of_tai;
	ie->number_of_rai = context->pre_rptng_area_act.number_of_rai;
	size += sizeof(uint8_t);
	ie->nbr_of_macro_enb = context->pre_rptng_area_act.nbr_of_macro_enb;
	size += sizeof(uint8_t);
	ie->nbr_of_home_enb = context->pre_rptng_area_act.nbr_of_home_enb;
	size += sizeof(uint8_t);
	ie->number_of_ecgi = context->pre_rptng_area_act.number_of_ecgi;
	size += sizeof(uint8_t);
	ie->number_of_sai = context->pre_rptng_area_act.number_of_sai;
	size += sizeof(uint8_t);
	ie->number_of_cgi = context->pre_rptng_area_act.number_of_cgi;
	size += sizeof(uint8_t);
	ie->nbr_of_extnded_macro_enb = context->pre_rptng_area_act.nbr_of_extnded_macro_enb;
	size += sizeof(uint8_t);

	uint32_t cpy_size = 0;

	if(ie->number_of_tai){
		cpy_size = ie->number_of_tai * sizeof(tai_field_t);
		memcpy(&ie->tais, &context->pre_rptng_area_act.tais, cpy_size);
		size += sizeof(tai_field_t);
	}

	if(ie->number_of_rai){
		cpy_size = ie->number_of_rai * sizeof(rai_field_t);
		memcpy(&ie->rais, &context->pre_rptng_area_act.rais, cpy_size);
		size += sizeof(rai_field_t);
	}

	if(ie->nbr_of_macro_enb){
		cpy_size = ie->nbr_of_macro_enb * sizeof(macro_enb_id_fld_t);
		memcpy(&ie->macro_enb_ids, &context->pre_rptng_area_act.macro_enodeb_ids,
																		cpy_size);
		size += sizeof(macro_enb_id_fld_t);
	}

	if(ie->nbr_of_home_enb){
		cpy_size = ie->nbr_of_home_enb * sizeof(home_enb_id_fld_t);
		memcpy(&ie->home_enb_ids, &context->pre_rptng_area_act.home_enb_ids,
																	cpy_size);
		size += sizeof(home_enb_id_fld_t);
	}

	if(ie->number_of_ecgi){
		cpy_size = ie->number_of_ecgi * sizeof(ecgi_field_t);
		memcpy(&ie->ecgis, &context->pre_rptng_area_act.ecgis, cpy_size);
		size += sizeof(ecgi_field_t);
	}

	if(ie->number_of_sai){
		cpy_size = ie->number_of_sai * sizeof(sai_field_t);
		memcpy(&ie->sais, &context->pre_rptng_area_act.sais, cpy_size);
		size += sizeof(sai_field_t);
	}

	if(ie->number_of_cgi){
		cpy_size = ie->number_of_cgi * sizeof(cgi_field_t);
		memcpy(&ie->cgis, &context->pre_rptng_area_act.cgis, cpy_size);
		size += sizeof(cgi_field_t);
	}

	if(ie->nbr_of_extnded_macro_enb){
		cpy_size = ie->nbr_of_extnded_macro_enb * sizeof(extnded_macro_enb_id_fld_t);
		memcpy(&ie->extnded_macro_enb_ids,
			&context->pre_rptng_area_act.extended_macro_enodeb_ids,
															cpy_size);
		size += sizeof(extnded_macro_enb_id_fld_t);

	}

	set_ie_header(&ie->header, GTP_IE_PRES_RPTNG_AREA_ACT, 0, size);
	return;

}

void
set_presence_reporting_area_info_ie(gtp_pres_rptng_area_info_ie_t *ie, ue_context *context){

	int size = 0;
	ie->pra_identifier = context->pre_rptng_area_info.pra_identifier;
	size += 3*sizeof(uint8_t);

	ie->inapra = context->pre_rptng_area_info.inapra;
	ie->opra = context->pre_rptng_area_info.opra;
	ie->ipra = context->pre_rptng_area_info.ipra;
	size += sizeof(uint8_t);

	set_ie_header(&ie->header, GTP_IE_PRES_RPTNG_AREA_INFO, 0, size);
	return;
}

#endif /* CP_BUILD */
