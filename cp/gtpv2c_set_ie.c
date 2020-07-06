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
#include "gtpv2c_set_ie.h"
#include "packet_filters.h"
#include "clogger.h"

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
		enum ie_instance instance, uint8_t cause_value)
{
	set_ie_header(&cause->header, GTP_IE_CAUSE, instance,
				sizeof(struct cause_ie_hdr_t));
	cause->cause_value = cause_value;
	cause->pce = 0;
	cause->bce = 0;
	cause->spareinstance = 0;
	if(spgw_cfg != SGWC)
	   cause->cs = 1;
	else
	   cause->cs = 0;

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

uint16_t
set_cause_accepted_ie(gtpv2c_header_t *header,
		enum ie_instance instance)
{
	gtpv2c_ie *ie = set_next_ie(header, GTP_IE_CAUSE, instance,
	    sizeof(struct cause_ie_hdr_t));
	cause_ie *cause_ie_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie, ie);

	cause_ie_ptr->cause_ie_hdr.cause_value = GTPV2C_CAUSE_REQUEST_ACCEPTED;
	cause_ie_ptr->cause_ie_hdr.pdn_connection_error = 0;
	cause_ie_ptr->cause_ie_hdr.bearer_context_error = 0;
	cause_ie_ptr->cause_ie_hdr.cause_source = 0;
	cause_ie_ptr->spare_1 = 0;

	return get_ie_return(ie);
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


void
set_ipv4_fteid(gtp_fully_qual_tunn_endpt_idnt_ie_t *fteid,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid)
{
	set_ie_header(&fteid->header, GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT, instance,
		sizeof(struct fteid_ie_hdr_t) + sizeof(struct in_addr));
	fteid->v4 = 1;
	fteid->v6 = 0;
	fteid->interface_type = interface;
	fteid->teid_gre_key = teid;
	fteid->ipv4_address = ipv4.s_addr;

	return;
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
set_ipv4_paa(gtp_pdn_addr_alloc_ie_t *paa, enum ie_instance instance,
		struct in_addr ipv4)
{
	uint32_t temp_ipv4 = ipv4.s_addr;
	set_ie_header(&paa->header, GTP_IE_PDN_ADDR_ALLOC, instance,
			sizeof(uint8_t) + sizeof(struct in_addr));

	paa->pdn_type = PDN_IP_TYPE_IPV4;
	paa->spare2 = 0;
	memcpy(paa->pdn_addr_and_pfx, &temp_ipv4, sizeof(uint32_t));

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

uint8_t
set_bearer_tft(gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *tft,
		enum ie_instance instance, uint8_t eps_bearer_lvl_tft,
		eps_bearer *bearer)
{
    uint32_t mask;
    uint8_t i = 0;
    uint8_t length;
    uint8_t len_index = 0;
    uint8_t num_pkt_filters = 0;
    tft->eps_bearer_lvl_tft[i++] = eps_bearer_lvl_tft + TFT_CREATE_NEW;
    for(uint8_t iCnt = 0; iCnt < bearer->num_dynamic_filters; ++iCnt) {
        // flow_cnt is for flow information counter
        for(int flow_cnt = 0; flow_cnt < bearer->dynamic_rules[iCnt]->num_flw_desc; flow_cnt++) {

            length = 0;
            ++num_pkt_filters;

            if(TFT_DIRECTION_UPLINK_ONLY == bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.direction) {
                tft->eps_bearer_lvl_tft[i++] = num_pkt_filters + TFT_UPLINK;
            } else if(TFT_DIRECTION_DOWNLINK_ONLY ==
                bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.direction) {
                tft->eps_bearer_lvl_tft[i++] = num_pkt_filters + TFT_DOWNLINK;
            } else if(TFT_DIRECTION_BIDIRECTIONAL ==
                bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.direction) {
                tft->eps_bearer_lvl_tft[i++] = num_pkt_filters + TFT_BIDIRECTIONAL;
            } else {
                tft->eps_bearer_lvl_tft[i++] = num_pkt_filters;
            }

            tft->eps_bearer_lvl_tft[i++] = bearer->dynamic_rules[iCnt]->precedence; /* precedence */

            len_index = i++;

            tft->eps_bearer_lvl_tft[i++] = TFT_PROTO_IDENTIFIER_NEXT_HEADER_TYPE;
            tft->eps_bearer_lvl_tft[i++] = bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.proto_id;
            length += 2;

        if(TFT_DIRECTION_DOWNLINK_ONLY == bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.direction) {

                tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_REMOTE_PORT_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low & 0xff;
                length += 3;

                tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_SRC_PORT_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_port_low >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_port_low & 0xff;
                length += 3;

                tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_SRC_ADDR_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 24) & 0xff;
                length += 5;

                mask = 0xffffffff << (32 - bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask);
                tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
                length += 4;

                tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_REMOTE_ADDR_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr & 0xff;
				                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 24) & 0xff;
                length += 5;

                mask = 0xffffffff << (32 - bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask);
                tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
                length += 4;

            } else {
                tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_REMOTE_PORT_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_port_low >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_port_low & 0xff;
                length += 3;

                tft->eps_bearer_lvl_tft[i++] = TFT_SINGLE_SRC_PORT_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_port_low & 0xff;
                length += 3;

                tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_SRC_ADDR_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_addr.s_addr >> 24) & 0xff;
                length += 5;

                mask = 0xffffffff << (32 - bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.remote_ip_mask);
                tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
                length += 4;

                tft->eps_bearer_lvl_tft[i++] = TFT_IPV4_REMOTE_ADDR_TYPE;
                tft->eps_bearer_lvl_tft[i++] =
                    bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] =
                    (bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_addr.s_addr >> 24) & 0xff;
                length += 5;

                mask = 0xffffffff << (32 - bearer->dynamic_rules[iCnt]->flow_desc[flow_cnt].sdf_flw_desc.local_ip_mask);
                tft->eps_bearer_lvl_tft[i++] = (mask >> 24) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 16) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = (mask >> 8) & 0xff;
                tft->eps_bearer_lvl_tft[i++] = mask & 0xff;
                length += 4;

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
		clLog(clSystemLog, eCLSeverityCritical, "Invalid EBI used %"PRIu8"\n", ebi);
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
pfcp_config_t pfcp_config;

int
decode_check_csr(gtpv2c_header_t *gtpv2c_rx,
		create_sess_req_t *csr)
{
	int ret = 0;
	ret = decode_create_sess_req((uint8_t *) gtpv2c_rx,
			csr);

	if (!ret){
		clLog(clSystemLog, eCLSeverityCritical, "Decoding for csr req failed");
		return -1;
	}

	if (csr->indctn_flgs.header.len &&
			csr->indctn_flgs.indication_uimsi) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%d Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n", __file__, __func__, __LINE__);
		return GTPV2C_CAUSE_IMSI_NOT_KNOWN;
	}

	if ((pfcp_config.cp_type == SGWC) &&
			(!csr->pgw_s5s8_addr_ctl_plane_or_pmip.header.len)) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%d Mandatory IE missing. Dropping packet len:%u\n",
				__file__, __func__, __LINE__,
				csr->pgw_s5s8_addr_ctl_plane_or_pmip.header.len);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (/*!csr->max_apn_rstrct.header.len
			||*/ !csr->bearer_contexts_to_be_created.header.len
			|| !csr->sender_fteid_ctl_plane.header.len
			|| !csr->imsi.header.len
			|| !csr->apn_ambr.header.len
			|| !csr->pdn_type.header.len
			|| !csr->bearer_contexts_to_be_created.bearer_lvl_qos.header.len
			|| !csr->rat_type.header.len
			|| !(csr->pdn_type.pdn_type_pdn_type == PDN_IP_TYPE_IPV4) ) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%d Mandatory IE missing. Dropping packet\n",
				__file__, __func__, __LINE__);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (csr->pdn_type.pdn_type_pdn_type == PDN_IP_TYPE_IPV6 ||
			csr->pdn_type.pdn_type_pdn_type == PDN_IP_TYPE_IPV4V6) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%d IPv6 Not Yet Implemented - Dropping packet\n",
				__file__, __func__, __LINE__);
		return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
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
#endif /* CP_BUILD */
