/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include <rte_debug.h>

#include "ie.h"
#include "gtpv2c_set_ie.h"
#include "packet_filters.h"

/**
 * helper function to get the location of the next information element '*ie'
 * that the buffer located at '*header' may be used, in the case that the size
 * of the information element IS known ahead of time
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param type
 *   information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param length
 *   size of information element created in message
 * @return
 *   information element to be populated
 */
static gtpv2c_ie *
set_next_ie(gtpv2c_header *header, uint8_t type,
		enum ie_instance instance, uint16_t length)
{
	gtpv2c_ie *ie = (gtpv2c_ie *) (((uint8_t *) &header->teid_u)
	    + ntohs(header->gtpc.length));

	if (ntohs(header->gtpc.length) + length
	    + sizeof(gtpv2c_ie) > MAX_GTPV2C_LENGTH) {
		rte_panic("Insufficient space in UDP buffer for IE\n");
	}

	header->gtpc.length = htons(
	    ntohs(header->gtpc.length) + length + sizeof(gtpv2c_ie));

	ie->type = type;
	ie->instance = instance;
	ie->length = htons(length);
	ie->spare = 0;

	return ie;
}

/**
 * helper function to get the location of the next information element '*ie'
 * that the buffer located at '*header' may be used, in the case that the size
 * of the information element IS NOT known ahead of time
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param type
 *   information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @return
 *   information element to be populated
 */
static gtpv2c_ie *
set_next_unsized_ie(gtpv2c_header *header, uint8_t type,
		enum ie_instance instance)
{
	gtpv2c_ie *ie = (gtpv2c_ie *) (((uint8_t *) &header->teid_u)
	    + ntohs(header->gtpc.length));

	ie->type = type;
	ie->instance = instance;
	ie->spare = 0;

	return ie;
}

/**
 * helper function to update the size of a gtp message header field within the
 * transmit buffer *header by the length of 'length' due to the length of the
 * information element 'ie'
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param ie
 *   information element to be added to gtp message buffer
 * @param length
 *   size of information element created in message
 */
static void
set_ie_size(gtpv2c_header *header, gtpv2c_ie *ie, uint16_t length)
{
	if (ntohs(header->gtpc.length) + length
	    + sizeof(gtpv2c_ie) > MAX_GTPV2C_LENGTH) {
		rte_panic("Insufficient space in UDP buffer for IE\n");
	}
	ie->length = htons(length);
	header->gtpc.length = htons(
	    ntohs(header->gtpc.length) + length + sizeof(gtpv2c_ie));
}

/**
 * helper function to get the information element length used to increment gtp
 * header length field
 * @param ie
 *   information element pointer
 * @return
 *   size of information element created in message
 */
static inline uint16_t
get_ie_return(gtpv2c_ie *ie)
{
	return sizeof(gtpv2c_ie) + ntohs(ie->length);
}

/**
 * helper function to set general value within an inforation element of size
 * 1 byte
 * @param header
 *   header pre-populated that contains transmission buffer for message
 * @param type
 *   information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param value
 *   value of information element
 * @return
 */
static uint16_t
set_uint8_ie(gtpv2c_header *header, uint8_t type,
		enum ie_instance instance, uint8_t value)
{
	gtpv2c_ie *ie = set_next_ie(header, type, instance, sizeof(uint8_t));
	uint8_t *value_ptr = IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ie);

	*value_ptr = value;

	return get_ie_return(ie);
}

uint16_t
set_ie_copy(gtpv2c_header *header, gtpv2c_ie *src_ie)
{
	uint16_t len = ntohs(src_ie->length);
	gtpv2c_ie *ie = set_next_ie(header, src_ie->type, src_ie->instance, len);
	memcpy(((uint8_t *)ie)+sizeof(gtpv2c_ie),((uint8_t *)src_ie)+sizeof(gtpv2c_ie),len);
	return get_ie_return(ie);
}

/**
 * helper function to set ie header values
 * @param header
 *   ie header
 * @param type
 *   information element type value as defined in 3gpp 29.274 table 8.1-1
 * @param instance
 *   Information element instance as specified by 3gpp 29.274 clause 6.1.3
 * @param length
 *   size of information element created in message
 * @return
 *   void
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
set_cause_accepted(cause_ie_t *cause,
		enum ie_instance instance)
{
	set_ie_header(&cause->header, IE_CAUSE, instance,
	    sizeof(struct cause_ie_hdr_t));
	cause->cause_value = GTPV2C_CAUSE_REQUEST_ACCEPTED;
	cause->pdn_connection_error = 0;
	cause->bearer_context_error = 0;
	cause->cause_source = 0;
	cause->spare_1 = 0;
}

uint16_t
set_cause_accepted_ie(gtpv2c_header *header,
		enum ie_instance instance)
{
	gtpv2c_ie *ie = set_next_ie(header, IE_CAUSE, instance,
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
set_ar_priority_ie(gtpv2c_header *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	gtpv2c_ie *ie = set_next_ie(header,
			IE_ALLOCATION_RETENTION_PRIORITY, instance,
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
set_ipv4_fteid(fteid_ie_t *fteid,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid)
{
	set_ie_header(&fteid->header, IE_FTEID, instance,
		sizeof(struct fteid_ie_hdr_t) + sizeof(struct in_addr));
	fteid->v4 = 1;
	fteid->v6 = 0;
	fteid->iface_type = interface;
	fteid->teid_gre = teid;
	fteid->ip.ipv4 = ipv4;

	return;
}

uint16_t
set_ipv4_fteid_ie(gtpv2c_header *header,
		enum gtpv2c_interfaces interface, enum ie_instance instance,
		struct in_addr ipv4, uint32_t teid)
{
	gtpv2c_ie *ie = set_next_ie(header, IE_FTEID, instance,
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
set_ipv4_paa(paa_ie_t *paa, enum ie_instance instance,
		struct in_addr ipv4)
{
	set_ie_header(&paa->header, IE_PAA, instance,
		sizeof(uint8_t) + sizeof(struct in_addr));

	paa->pdn_type = PDN_IP_TYPE_IPV4;
	paa->spare = 0;
	paa->ip_type.ipv4 = ipv4;

	return;
}

uint16_t
set_ipv4_paa_ie(gtpv2c_header *header, enum ie_instance instance,
		struct in_addr ipv4)
{
	gtpv2c_ie *ie = set_next_ie(header, IE_PAA, instance,
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
set_apn_restriction(apn_restriction_ie_t *apn_restriction,
		enum ie_instance instance, uint8_t restriction_type)
{
	set_ie_header(&apn_restriction->header,	IE_APN_RESTRICTION,
		instance, sizeof(uint8_t));

	apn_restriction->restriction_type = restriction_type;

	return;
}

uint16_t
set_apn_restriction_ie(gtpv2c_header *header,
		enum ie_instance instance, uint8_t apn_restriction)
{
	return set_uint8_ie(header, IE_APN_RESTRICTION, instance,
			apn_restriction);
}

void
set_ebi(eps_bearer_id_ie_t *ebi, enum ie_instance instance,
		uint8_t eps_bearer_id)
{
	set_ie_header(&ebi->header, IE_EBI, instance, sizeof(uint8_t));

	ebi->eps_bearer_id = eps_bearer_id;
	ebi->spare = 0;
}

uint16_t
set_ebi_ie(gtpv2c_header *header, enum ie_instance instance, uint8_t ebi)
{
	if (ebi & 0xF0)
		fprintf(stderr, "Invalid EBI used %"PRIu8"\n", ebi);
	return set_uint8_ie(header, IE_EBI, instance, ebi);
}


uint16_t
set_pti_ie(gtpv2c_header *header, enum ie_instance instance, uint8_t pti)
{
	return set_uint8_ie(header, IE_PROCEDURE_TRANSACTION_ID, instance, pti);
}


uint16_t
set_bearer_qos_ie(gtpv2c_header *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	gtpv2c_ie *ie = set_next_ie(header, IE_BEARER_QOS, instance,
	    sizeof(bearer_qos_ie));
	bearer_qos_ie *bqos = IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_qos_ie, ie);

	bqos->arp.preemption_vulnerability =
			bearer->qos.arp.preemption_vulnerability;
	bqos->arp.spare1 = 0;
	bqos->arp.priority_level = bearer->qos.arp.priority_level;
	bqos->arp.preemption_capability =
			bearer->qos.arp.preemption_capability;
	bqos->arp.spare2 = 0;

	memcpy(&bqos->qos, &bearer->qos.qos, sizeof(bqos->qos));

	return get_ie_return(ie);
}


uint16_t
set_bearer_tft_ie(gtpv2c_header *header, enum ie_instance instance,
		eps_bearer *bearer)
{
	gtpv2c_ie *ie = set_next_unsized_ie(header, IE_BEARER_TFT, instance);
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
set_recovery_ie(gtpv2c_header *header, enum ie_instance instance)
{
	/** TODO: According to 3gpp TS 29.274 [7.1.1] and 23.007 [16.1.1
	 * Restoration Procedures] this value (currently using 0) *should*
	 * be obtained at SPGW startup, from a local non-volatile counter
	 * (modulo 256) which is denoted  as the 'local Restart Counter'.
	 * Instead we set this value as 0
	 */
	return set_uint8_ie(header, IE_RECOVERY, instance, 0);
}


void
add_grouped_ie_length(gtpv2c_ie *group_ie, uint16_t grouped_ie_length)
{
	group_ie->length = htons(ntohs(group_ie->length) + grouped_ie_length);
}


gtpv2c_ie *
create_bearer_context_ie(gtpv2c_header *header,
		enum ie_instance instance)
{
	return set_next_ie(header, IE_BEARER_CONTEXT, instance, 0);
}


