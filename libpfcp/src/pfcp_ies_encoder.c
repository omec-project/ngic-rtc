/*
 * Copyright (c) 2019 Sprint
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

#include "../include/pfcp_ies_encoder.h"

#include "../include/enc_dec_bits.h"



/**
 * Encodes pfcp ie header to buffer.
 * @param value
 *     ie header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_ie_header_t(pfcp_ie_header_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_bits(value->type, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->len, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	//return encoded/CHAR_SIZE;
	return encoded;
}

/**
 * Encodes gtpc to buffer.
 * @param value
 *     gtpc
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_header_t(pfcp_header_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
//	encoded += encode_bits(value->s, 1, buf + (encoded/8), encoded % CHAR_SIZE);
//	encoded += encode_bits(value->mp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
//	encoded += encode_bits(value->spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
//	encoded += encode_bits(value->version, 3, buf + (encoded/8), encoded % CHAR_SIZE);

	encoded += encode_bits(value->version, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->s, 1, buf + (encoded/8), encoded % CHAR_SIZE);




	encoded += encode_bits(value->message_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->message_len, 16, buf + (encoded/8), encoded % CHAR_SIZE);

	if (value->s == 1) {
		encoded += encode_bits(value->seid_seqno.has_seid.seid, 64, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.seq_no, 24, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.message_prio, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	} else {
		encoded += encode_bits(value->seid_seqno.no_seid.seq_no, 24, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.no_seid.spare, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	}

	return encoded/CHAR_SIZE;
}

/**
 * Encodes node id ie to buffer.
 * @param value
 *     node id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_node_id_ie_t(node_id_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->node_id_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/8), &value->node_id_value, value->node_id_value_len);
	encoded +=  value->node_id_value_len * CHAR_SIZE;
	return encoded/CHAR_SIZE;
}

/**
 * Encodes recoveryime stamp ie to buffer.
 * @param value
 *     recoveryime stamp ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_recovery_time_stamp_ie_t(recovery_time_stamp_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->recovery_time_stamp_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes up function features ie to buffer.
 * @param value
 *     up function features ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_up_function_features_ie_t(up_function_features_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->supported_features, 16, buf + (encoded/CHAR_SIZE), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}

/**
 * Encodes cp function features ie to buffer.
 * @param value
 *     cp function features ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_cp_function_features_ie_t(cp_function_features_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->supported_features, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes cause ie to buffer.
 * @param value
 *     cause ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_cause_ie_t(pfcp_cause_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->cause_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes f seid ie to buffer.
 * @param value
 *     f seid ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_f_seid_ie_t(f_seid_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->seid, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->v4 == 1){
		memcpy(buf + (encoded/8), &value->ipv4_address, 4);
		encoded +=  4 * CHAR_SIZE;
	}
	else {
		memcpy(buf + (encoded/8), &value->ipv6_address, 16);
		encoded +=  16 * CHAR_SIZE;
	}
	return encoded/CHAR_SIZE;
}

/**
 * Encodes bar id ie to buffer.
 * @param value
 *     bar id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_bar_id_ie_t(bar_id_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->bar_id_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes downlink data notification delay ie to buffer.
 * @param value
 *     downlink data notification delay ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_downlink_data_notification_delay_ie_t(downlink_data_notification_delay_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->delay_value_in_integer_multiples_of_50_millisecs_or_zero, 8,
			buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded ;
}

/**
 * Encodes suggested buffering packets count ie to buffer.
 * @param value
 *     suggested buffering packets count ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_suggested_buffering_packets_count_ie_t(suggested_buffering_packets_count_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->packet_count_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes create bar to buffer.
 * @param c_bar
 *     create bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_create_bar_ie_t(create_bar_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if(value->bar_id.header.len)
	encoded += encode_bar_id_ie_t(&value->bar_id, buf + (encoded/CHAR_SIZE));

	if(value->downlink_data_notification_delay.header.len)
	encoded += encode_downlink_data_notification_delay_ie_t(&value->downlink_data_notification_delay,
			buf +(encoded/CHAR_SIZE));

	if(value->suggested_buffering_packets_count.header.len)
	encoded += encode_suggested_buffering_packets_count_ie_t(&(value->suggested_buffering_packets_count),
			buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}

/**
 * Encodes far id to buffer.
 * @param value
 *     far id
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_far_id_ie_t(far_id_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->far_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes precedence to buffer.
 * @param value
 *     precedence
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_precedence_ie_t(precedence_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->precedence_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes source interface to buffer.
 * @param value
 *     source interface
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_source_interface_ie_t(source_interface_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->interface_value, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}
/**
 * Encodes pdi ie to buffer.
 * @param value
 *     pdi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pdi_ie_t(pdi_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->source_interface.header.len)
		encoded += encode_source_interface_ie_t(&(value->source_interface), buf + (encoded/CHAR_SIZE));

	if (value->local_fteid.header.len)
		encoded += encode_f_teid_ie_t(&(value->local_fteid), buf + (encoded/CHAR_SIZE));

	if (value->network_instance.header.len)
		encoded += encode_network_instance_ie_t(&(value->network_instance), buf + (encoded/CHAR_SIZE));

	if (value->ue_ip_address.header.len)
		encoded += encode_ue_ip_address_ie_t(&(value->ue_ip_address), buf + (encoded/CHAR_SIZE));

	if (value->traffic_endpoint_id.header.len)
		encoded += encode_traffic_endpoint_id_ie_t(&(value->traffic_endpoint_id), buf + (encoded/CHAR_SIZE));

	if (value->application_id.header.len)
		encoded += encode_application_id_ie_t(&(value->application_id), buf + (encoded/CHAR_SIZE));

	if (value->ethernet_pdu_session_information.header.len)
		encoded += encode_ethernet_pdu_session_information_ie_t(&(value->ethernet_pdu_session_information), buf + (encoded/CHAR_SIZE));

	if (value->framedrouting.header.len)
		encoded += encode_framed_routing_ie_t(&(value->framedrouting), buf + (encoded/CHAR_SIZE));

	return encoded;
}

/**
 * Encodes outer header removal to buffer.
 * @param value
 *     outer header removal
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_outer_header_removal_ie_t(outer_header_removal_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->outer_header_removal_description, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes activate predefined rules to buffer.
 * @param value
 *     activate predefined rules
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */					 
int encode_activate_predefined_rules_ie_t(activate_predefined_rules_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	for(int i =0;i < 8 ;i++)
	 encoded += encode_bits(value->predefined_rules_name[i], 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}
/**
 * Encodes create pdr ie to buffer.
 * @param value
 *     create pdr ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_create_pdr_ie_t(create_pdr_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->pdr_id.header.len)
		encoded += encode_pdr_id_ie_t(&(value->pdr_id), buf + (encoded/CHAR_SIZE));

	if (value->precedence.header.len)
		encoded += encode_precedence_ie_t(&(value->precedence), buf + (encoded/CHAR_SIZE));

	if (value->pdi.header.len)
		encoded += encode_pdi_ie_t(&(value->pdi), buf + (encoded/CHAR_SIZE));

	if (value->outer_header_removal.header.len)
		encoded += encode_outer_header_removal_ie_t(&(value->outer_header_removal), buf + (encoded/CHAR_SIZE));

	if (value->far_id.header.len)
		encoded += encode_far_id_ie_t(&(value->far_id), buf + (encoded/CHAR_SIZE));

	if (value->urr_id.header.len)
		encoded += encode_urr_id_ie_t(&(value->urr_id), buf + (encoded/CHAR_SIZE));

	if (value->qer_id.header.len)
		encoded += encode_qer_id_ie_t(&(value->qer_id), buf + (encoded/CHAR_SIZE));

	if (value->activate_predefined_rules.header.len)
		encoded += encode_activate_predefined_rules_ie_t(&(value->activate_predefined_rules), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}

/**
 * Encodes fq csid ie to buffer.
 * @param value
 *     fq csid ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_fq_csid_ie_t(fq_csid_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->fq_csid_node_id_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->number_of_csids, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->fq_csid_node_id_type == 0){
		memcpy(buf + (encoded/8), &value->node_address.ipv4_address, 4);
		encoded +=  4 * CHAR_SIZE;
	}
	//encoded += encode_bits(value->node_address, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	//memcpy(buf + (encoded/CHAR_SIZE), &value->pdn_connection_set_identifier, PDN_CONNECTION_SET_IDENTIFIER_LEN);
	for(int i =0;i < value->number_of_csids ;i++)
		encoded += encode_bits(value->pdn_connection_set_identifier[i], 16, buf + (encoded/8), encoded % CHAR_SIZE);
#if 0
	memcpy(buf + (encoded/CHAR_SIZE), &value->pdn_connection_set_identifier, 2 * (value->number_of_csids));
	encoded +=  2 * (value->number_of_csids) * CHAR_SIZE;
#endif
	//encoded +=  PDN_CONNECTION_SET_IDENTIFIER_LEN * CHAR_SIZE;
	return encoded/CHAR_SIZE;
}

/**
 * Encodes user plane inactivityimer ie to buffer.
 * @param value
 *     user plane inactivityimer ie
 * @param buf
 *   buffer to store encoded values
 * @return
 *   number of encoded bytes
 */
int encode_user_plane_inactivity_timer_ie_t(user_plane_inactivity_timer_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->user_plane_inactivity_timer, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes user id ie to buffer.
 * @param value
 *     user id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_user_id_ie_t(user_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->naif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->msisdnf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->imeif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->imsif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->imsif == 1){
		encoded += encode_bits(value->length_of_imsi, 8, buf + (encoded/8), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/CHAR_SIZE), &value->imsi, value->length_of_imsi);
		encoded +=  value->length_of_imsi * CHAR_SIZE;
	}
	if(value->imeif == 1){
		encoded += encode_bits(value->length_of_imei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/CHAR_SIZE), &value->imei, value->length_of_imei);
		encoded +=  value->length_of_imei * CHAR_SIZE;
	}
	if(value->msisdnf == 1){
		encoded += encode_bits(value->length_of_msisdn, 8, buf + (encoded/8), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/CHAR_SIZE), &value->msisdn, value->length_of_msisdn);
		encoded +=  value->length_of_msisdn * CHAR_SIZE;
	}

	if(value->naif == 1){
		encoded += encode_bits(value->length_of_nai, 8, buf + (encoded/8), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/CHAR_SIZE), &value->nai, value->length_of_nai);
		encoded +=  value->length_of_nai * CHAR_SIZE;
	}
	return encoded/CHAR_SIZE;
}

/**
 * Encodes trace information ie to buffer.
 * @param value
 *     trace information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_trace_information_ie_t(trace_information_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->trace_id, 24, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	encoded += encode_bits(value->length_of_triggering_events, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->triggering_events, value->length_of_triggering_events);
	encoded +=  value->length_of_triggering_events * CHAR_SIZE;

	encoded += encode_bits(value->session_trace_depth, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	encoded += encode_bits(value->length_of_list_of_interfaces, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->list_of_interfaces,value->length_of_list_of_interfaces );
	encoded +=  value->length_of_list_of_interfaces * CHAR_SIZE;

	encoded += encode_bits(value->length_of_ip_address_of_trace_collection_entity, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->ip_address_of_trace_collection_entity,4* (value->length_of_ip_address_of_trace_collection_entity));
	encoded += 4* (value->length_of_ip_address_of_trace_collection_entity) * CHAR_SIZE;

	return encoded/CHAR_SIZE;
}

/**
 * Encodes pdnype ie to buffer.
 * @param value
 *     pdnype ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pdn_type_ie_t(pfcp_pdn_type_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdn_type, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes offending ie ie to buffer.
 * @param value
 *     offending ie ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_offending_ie_ie_t(offending_ie_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->type_of_the_offending_ie, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}


/**
 * Encodes failed rule id ie to buffer.
 * @param value
 *     failed rule id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_failed_rule_id_ie_t(failed_rule_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rule_id_type, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->rule_id_type == RULE_ID_TYPE_PDR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 2);
		encoded +=  2* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_QER) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_URR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_BAR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 1);
		encoded +=  1* CHAR_SIZE;
	}else {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	}//FAR is by default 3gpp 29.244 15.03 (8.2.80)

	return encoded/CHAR_SIZE;
}


/**
 * Encodes load control information to buffer.
 *   @param lc_inf
 * load control information
 *   @param buf
 * buffer to store encoded values.
 *   @return
 *  number of encoded bytes.
 **/
int encode_load_control_information_ie_t(load_control_information_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	if (value->load_control_sequence_number.header.len)
		encoded += encode_sequence_number_ie_t(&(value->load_control_sequence_number),buf+(encoded/CHAR_SIZE));
	if (value->load_metric.header.len)
		encoded += encode_metric_ie_t(&(value->load_metric), buf+(encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}
#if 0
int encode_load_control_information_ie_t(load_control_information_ie_t *lc_inf,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&lc_inf->header, msg);

	if (lc_inf->load_control_sequence_number.header.len)
		enc_len += encode_sequence_number_ie_t(&(lc_inf->load_control_sequence_number), msg);

	if (lc_inf->load_metric.header.len)
		enc_len += encode_metric_ie_t(&(lc_inf->load_metric), msg);

	return enc_len;
}
#endif
/**
 * Encodes overload control information to buffer.
 * @param oc_inf
 *     overload control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
#if 0
int encode_overload_control_information_ie_t(overload_control_information_ie_t *oc_inf,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&oc_inf->header, msg);

	if (oc_inf->overload_control_sequence_number.header.len)
		enc_len += encode_sequence_number_ie_t(&(oc_inf->overload_control_sequence_number), msg);

	if (oc_inf->overload_reduction_metric.header.len)
		enc_len += encode_metric_ie_t(&(oc_inf->overload_reduction_metric), msg);

	if (oc_inf->period_of_validity.header.len)
		enc_len += encode_timer_ie_t(&(oc_inf->period_of_validity), msg);
	if (oc_inf->overload_control_information_flags.header.len)
		enc_len += encode_oci_flags_ie_t(&(oc_inf->overload_control_information_flags), msg);

	return enc_len;
}
#endif
int encode_overload_control_information_ie_t(overload_control_information_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	if (value->overload_control_sequence_number.header.len)
		encoded += encode_sequence_number_ie_t(&(value->overload_control_sequence_number),buf+(encoded/CHAR_SIZE));
	if (value->overload_reduction_metric.header.len)
		encoded += encode_metric_ie_t(&(value->overload_reduction_metric), buf+(encoded/CHAR_SIZE));
	if (value->period_of_validity.header.len)
		encoded += encode_timer_ie_t(&(value->period_of_validity), buf+(encoded/CHAR_SIZE));
	if (value->overload_control_information_flags.header.len)
		encoded += encode_oci_flags_ie_t(&(value->overload_control_information_flags), buf+(encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}

/**
 * Encodes sequence number ie to buffer.
 * @param value
 *     sequence number ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_sequence_number_ie_t(sequence_number_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->sequence_number, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes metric ie to buffer.
 * @param value
 *     metric ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_metric_ie_t(metric_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->metric, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes timer ie to buffer.
 * @param value
 *     timer ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_timer_ie_t(timer_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	//return encoded/CHAR_SIZE;
	return encoded;
}
/**
 * Encodes oci flags ie to buffer.
 * @param value
 *     oci flags ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_oci_flags_ie_t(oci_flags_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->aoci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}



/**
 * Encodes cause ie to buffer.
 * @param value
 *     cause ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_cause_ie_t(pfcp_cause_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->cause_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}


/**
 * Encodes remove bar to buffer.
 * @param r_bar
 *     remove bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_remove_bar_ie_t(remove_bar_ie_t *value,
		uint8_t *buf)
{

	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	if(value->bar_id.header.len)
	encoded += encode_bar_id_ie_t(&value->bar_id, buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}

/**
 * Encodes removeraffic endpoint to buffer.
 * @param rt_end
 *     removeraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_remove_traffic_endpoint_ie_t(remove_traffic_endpoint_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	if (value->traffic_endpoint_id.header.len)
		encoded += encode_traffic_endpoint_id_ie_t(&(value->traffic_endpoint_id), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}

/**
 * Encodes traffic endpoint id ie to buffer.
 * @param value
 *     traffic endpoint id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_traffic_endpoint_id_ie_t(traffic_endpoint_id_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->traffic_endpoint_id_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes feid ie to buffer.
 * @param value
 *     feid ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_f_teid_ie_t(f_teid_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->chid, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ch, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	if (value->v4 == 1){
		memcpy(buf + (encoded/8), &value->ipv4_address, 4);
		encoded +=  4 * CHAR_SIZE;
	}else {
		memcpy(buf + (encoded/8), &value->ipv6_address, 16);
		encoded +=  16 * CHAR_SIZE;
	}
	if(value->chid == 1)
		encoded += encode_bits(value->choose_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes network instance ie to buffer.
 * @param value
 *     network instance ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_network_instance_ie_t(network_instance_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->network_instance, NETWORK_INSTANCE_LEN);
	encoded +=  NETWORK_INSTANCE_LEN * CHAR_SIZE;
	return encoded;
}

/**
 * Encodes ue ip address ie to buffer.
 * @param value
 *     ue ip address ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ue_ip_address_ie_t(ue_ip_address_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ipv6d, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sd, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->v4 == 1) {
		memcpy(buf + (encoded/8), &value->ipv4_address, 4);
		encoded +=  4 * CHAR_SIZE;
		//encoded += encode_bits(value->ipv4_address, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	} else {
		//encoded += encode_bits(value->ipv6_address, 64, buf + (encoded/8), encoded % CHAR_SIZE);
		memcpy(buf + (encoded/8), &value->ipv6_address,16);
		encoded +=  16 * CHAR_SIZE;
		encoded += encode_bits(value->ipv6_prefix_delegation_bits, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	}
	return encoded;
}

/**
 * Encodes ethernet pdu session information ie to buffer.
 * @param value
 *     ethernet pdu session information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ethernet_pdu_session_information_ie_t(ethernet_pdu_session_information_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ethi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes framed routing ie to buffer.
 * @param value
 *     framed routing ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_framed_routing_ie_t(framed_routing_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	memcpy(buf + (encoded/CHAR_SIZE), &value->framed_routing, FRAMED_ROUTING_LEN);
	encoded +=  FRAMED_ROUTING_LEN * CHAR_SIZE;
	return encoded;
}

/**
 * Encodes createraffic endpoint to buffer.
 * @param value
 *     createraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_create_traffic_endpoint_ie_t(create_traffic_endpoint_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->traffic_endpoint_id.header.len)
		encoded += encode_traffic_endpoint_id_ie_t(&(value->traffic_endpoint_id), buf + (encoded/CHAR_SIZE));

	if (value->local_fteid.header.len)
		encoded += encode_f_teid_ie_t(&(value->local_fteid), buf + (encoded/CHAR_SIZE));

	if (value->network_instance.header.len)
		encoded += encode_network_instance_ie_t(&(value->network_instance), buf + (encoded/CHAR_SIZE));

	if (value->ue_ip_address.header.len)
		encoded += encode_ue_ip_address_ie_t(&(value->ue_ip_address), buf + (encoded/CHAR_SIZE));

	if (value->ethernet_pdu_session_information.header.len)
		encoded += encode_ethernet_pdu_session_information_ie_t(&(value->ethernet_pdu_session_information), buf + (encoded/CHAR_SIZE));

	if (value->framedrouting.header.len)
		encoded += encode_framed_routing_ie_t(&(value->framedrouting), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}


/**
 * Encodes qer id ie to buffer.
 * @param value
 *     qer id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_qer_id_ie_t(qer_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->qer_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes qer correlation id ie to buffer.
 * @param value
 *     qer correlation id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_qer_correlation_id_ie_t(qer_correlation_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->qer_correlation_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes gate status ie to buffer.
 * @param value
 *     gate status ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_gate_status_ie_t(gate_status_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ul_gate, 2, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dl_gate, 2, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

int
encode_mbr_bits(uint64_t *val, uint8_t *buf)
{
	uint8_t tmp[MBR_BUF_SIZE];
	tmp[0] = (*val >> 32) & 0xff;
	tmp[1] = (*val >> 24) & 0xff;
	tmp[2] = (*val >> 16) & 0xff;
	tmp[3] = (*val >> 8) & 0Xff;
	tmp[4] = (*val & 0Xff);

	memcpy(buf, tmp, MBR_BUF_SIZE);

	return MBR_BUF_SIZE * CHAR_SIZE;
}
/**
 * Encodes mbr ie to buffer.
 * @param value
 *     mbr ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_mbr_ie_t(mbr_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	//encoded += encode_bits(value->ul_mbr, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	//encoded += encode_bits(value->dl_mbr, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_mbr_bits(&value->ul_mbr, buf + (encoded/8));
	encoded += encode_mbr_bits(&value->dl_mbr, buf + (encoded/8));
	return encoded;
}
 
/**
 * Encodes gbr ie to buffer.
 * @param value
 *     gbr ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_gbr_ie_t(gbr_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	//encoded += encode_bits(value->ul_gbr, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	//encoded += encode_bits(value->dl_gbr, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_mbr_bits(&value->ul_gbr, buf + (encoded/8));
	encoded += encode_mbr_bits(&value->dl_gbr, buf + (encoded/8));
	return encoded;
}


/**
 * Encodes packet rate ie to buffer.
 * @param value
 *     packet rate ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_packet_rate_ie_t(packet_rate_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dlpr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ulpr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->uplink_time_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->maximum_uplink_packet_rate, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare3, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->downlink_time_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->maximum_downlink_packet_rate, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes dl flow level marking ie to buffer.
 * @param value
 *     dl flow level marking ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_dl_flow_level_marking_ie_t(dl_flow_level_marking_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ttc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->tostraffic_class, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->service_class_indicator, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes qfi ie to buffer.
 * @param value
 *     qfi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_qfi_ie_t(qfi_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->qfi_value, 6, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes rqi ie to buffer.
 * @param value
 *     rqi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_rqi_ie_t(rqi_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rqi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}


/**
 * Encodes update qer to buffer.
 * @param value
 *     update qer
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_update_qer_ie_t(update_qer_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->qer_id.header.len)
		encoded += encode_qer_id_ie_t(&(value->qer_id), buf + (encoded/CHAR_SIZE));

	if (value->qer_correlation_id.header.len)
		encoded += encode_qer_correlation_id_ie_t(&(value->qer_correlation_id), buf + (encoded/CHAR_SIZE));

	if (value->gate_status.header.len)
		encoded += encode_gate_status_ie_t(&(value->gate_status), buf + (encoded/CHAR_SIZE));

	if (value->maximum_bitrate.header.len)
		encoded += encode_mbr_ie_t(&(value->maximum_bitrate), buf + (encoded/CHAR_SIZE));

	if (value->guaranteed_bitrate.header.len)
		encoded += encode_gbr_ie_t(&(value->guaranteed_bitrate), buf + (encoded/CHAR_SIZE));

	if (value->packet_rate.header.len)
		encoded += encode_packet_rate_ie_t(&(value->packet_rate), buf + (encoded/CHAR_SIZE));

	if (value->dl_flow_level_marking.header.len)
		encoded += encode_dl_flow_level_marking_ie_t(&(value->dl_flow_level_marking), buf + (encoded/CHAR_SIZE));

	if (value->qos_flow_identifier.header.len)
		encoded += encode_qfi_ie_t(&(value->qos_flow_identifier), buf + (encoded/CHAR_SIZE));

	if (value->reflective_qos.header.len)
		encoded += encode_rqi_ie_t(&(value->reflective_qos), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}
/**
 * Encodes update bar to buffer.
 * @param value
 *     update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_update_bar_ie_t(update_bar_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->bar_id.header.len)
		encoded += encode_bar_id_ie_t(&(value->bar_id), buf + (encoded/CHAR_SIZE));

	if (value->downlink_data_notification_delay.header.len)
		encoded += encode_downlink_data_notification_delay_ie_t(&(value->downlink_data_notification_delay), buf + (encoded/CHAR_SIZE));

	if (value->suggested_buffering_packets_count.header.len)
		encoded += encode_suggested_buffering_packets_count_ie_t(&(value->suggested_buffering_packets_count), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}


/**
 * Encodes updateraffic endpoint to buffer.
 * @param value
 *     updateraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_update_traffic_endpoint_ie_t(update_traffic_endpoint_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->traffic_endpoint_id.header.len)
		encoded += encode_traffic_endpoint_id_ie_t(&(value->traffic_endpoint_id), buf + (encoded/CHAR_SIZE));

	if (value->local_fteid.header.len)
		encoded += encode_f_teid_ie_t(&(value->local_fteid), buf + (encoded/CHAR_SIZE));

	if (value->network_instance.header.len)
		encoded += encode_network_instance_ie_t(&(value->network_instance), buf + (encoded/CHAR_SIZE));

	if (value->ue_ip_address.header.len)
		encoded += encode_ue_ip_address_ie_t(&(value->ue_ip_address), buf + (encoded/CHAR_SIZE));

	if (value->framedrouting.header.len)
		encoded += encode_framed_routing_ie_t(&(value->framedrouting), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}


/**
 * Encodes query urr reference ie to buffer.
 * @param value
 *     query urr reference ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_query_urr_reference_ie_t(query_urr_reference_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->query_urr_reference_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes pfcpsmreq flags ie to buffer.
 * @param value
 *     pfcpsmreq flags ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcpsmreq_flags_ie_t(pfcpsmreq_flags_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->drobu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sndem, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->qaurr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes pdr id ie to buffer.
 * @param value
 *     pdr id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pdr_id_ie_t(pdr_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rule_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded;
}

/**
 * Encodes created pdr to buffer.
 * @param value
 *     created pdr
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_created_pdr_ie_t(created_pdr_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->pdr_id.header.len)
		encoded += encode_pdr_id_ie_t(&(value->pdr_id), buf + (encoded/CHAR_SIZE));

	if (value->local_fteid.header.len)
		encoded += encode_f_teid_ie_t(&(value->local_fteid), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}


/**
 * Encodes additional usage reports information ie to buffer.
 * @param value
 *     additional usage reports information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_additional_usage_reports_information_ie_t(additional_usage_reports_information_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->auri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->number_of_additional_usage_reports_value, 15, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes createdraffic endpoint to buffer.
 * @param value
 *     createdraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_created_traffic_endpoint_ie_t(created_traffic_endpoint_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	if (value->traffic_endpoint_id.header.len)
		encoded += encode_traffic_endpoint_id_ie_t(&(value->traffic_endpoint_id), buf + (encoded/CHAR_SIZE));

	if (value->local_fteid.header.len)
		encoded += encode_f_teid_ie_t(&(value->local_fteid), buf + (encoded/CHAR_SIZE));

	return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp association release request ie to buffer.
 * @param value
 *     pfcp association release request ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_release_request_ie_t(pfcp_association_release_request_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sarr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}


/**
 * Encodes graceful release period ie to buffer.
 * @param value
 *     graceful release period ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_graceful_release_period_ie_t(graceful_release_period_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}

/**
 * Encodes node reportype ie to buffer.
 * @param value
 *     node reportype ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_node_report_type_ie_t(node_report_type_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->upfr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded/CHAR_SIZE;
}

/**
 * Encodes remote gtp u peer ie to buffer.
 * @param value
 *     remote gtp u peer ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_remote_gtpu_peer_ie_t(remote_gtp_u_peer_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->ipv4_address, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->ipv6_address, 128, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}


/**
 * Encodes user plane path failure report to buffer.
 * @param uppf_rep
 *     user plane path failure report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_user_plane_path_failure_report_ie_t(user_plane_path_failure_report_ie_t *value,
        uint8_t *buf)
{
	uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	if (value->remote_gtpu_peer.header.len)	
		encoded += encode_remote_gtpu_peer_ie_t(&(value->remote_gtpu_peer),buf+(encoded/CHAR_SIZE));
        return encoded/CHAR_SIZE;
}
/**
 * Encodes reportype ie to buffer.
 * @param value
 *     reportype ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_report_type_ie_t(report_type_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->upir, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->erir, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->usar, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->dldr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded/CHAR_SIZE;
}

/**
 * Encodes downlink data service information ie to buffer.
 * @param value
 *     downlink data service information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_downlink_data_service_information_ie_t(downlink_data_service_information_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->qfii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->ppi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare3, 2, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->paging_policy_indication_value, 6, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare4, 2, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes downlink data report to buffer.
 * @param dd_rep
 *     downlink data report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_downlink_data_report_ie_t(downlink_data_report_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;

        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->downlink_data_service_information.header.len)
                encoded += encode_downlink_data_service_information_ie_t(&(value->downlink_data_service_information), buf + (encoded/CHAR_SIZE));

        return encoded/CHAR_SIZE;
}

/**
 * Encodes urr id ie to buffer.
 * @param value
 *     urr id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_urr_id_ie_t(urr_id_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->urr_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes ur seqn ie to buffer.
 * @param value
 *     ur seqn ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ur_seqn_ie_t(ur_seqn_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->ur_seqn, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes usage reportrigger ie to buffer.
 * @param value
 *     usage reportrigger ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_usage_report_trigger_ie_t(usage_report_trigger_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->immer, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->droth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->stopt, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->start, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->quhti, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->timth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->volth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->perio, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->eveth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->macar, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->envcl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->monit, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->termr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->liusa, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->timqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->volqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes startime ie to buffer.
 * @param value
 *     startime ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_start_time_ie_t(start_time_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->start_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes endime ie to buffer.
 * @param value
 *     endime ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_end_time_ie_t(end_time_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->end_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}


/**
 * Encodes volume measurement ie to buffer.
 * @param value
 *     volume measurement ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_volume_measurement_ie_t(volume_measurement_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->total_volume, 64, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->uplink_volume, 64, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->downlink_volume, 64, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}


/**
 * Encodes duration measurement ie to buffer.
 * @param value
 *     duration measurement ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_duration_measurement_ie_t(duration_measurement_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->duration_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes application id ie to buffer.
 * @param value
 *     application id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_application_id_ie_t(application_id_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        memcpy(buf + (encoded/CHAR_SIZE), &value->application_identifier, APPLICATION_IDENTIFIER_LEN);
        encoded +=  APPLICATION_IDENTIFIER_LEN * CHAR_SIZE;
        return encoded;
}

/**
 * Encodes application instance id ie to buffer.
 * @param value
 *     application instance id ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_application_instance_id_ie_t(application_instance_id_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        memcpy(buf + (encoded/CHAR_SIZE), &value->application_instance_identifier, APPLICATION_INSTANCE_IDENTIFIER_LEN);
        encoded +=  APPLICATION_INSTANCE_IDENTIFIER_LEN * CHAR_SIZE;
        return encoded;
}


/**
 * Encodes flow information ie to buffer.
 * @param value
 *     flow information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_flow_information_ie_t(flow_information_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->flow_direction, 3, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->length_of_flow_description, 16, buf + (encoded/8), encoded % CHAR_SIZE);
        memcpy(buf + (encoded/CHAR_SIZE), &value->flow_description, FLOW_DESCRIPTION_LEN);
        encoded +=  FLOW_DESCRIPTION_LEN * CHAR_SIZE;
        return encoded;
}

/**
 * Encodes application detection information to buffer.
 * @param ad_inf
 *     application detection information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_application_detection_information_ie_t(application_detection_information_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;

        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->application_id.header.len)
                encoded += encode_application_id_ie_t(&(value->application_id),buf + (encoded/CHAR_SIZE));

        if (value->application_instance_id.header.len)
                encoded += encode_application_instance_id_ie_t(&(value->application_instance_id), buf + (encoded/CHAR_SIZE));

        if (value->flow_information.header.len)
                encoded += encode_flow_information_ie_t(&(value->flow_information), buf + (encoded/CHAR_SIZE));
        return encoded;
}
/**
 * Encodes time of first packet ie to buffer.
 * @param value
 *     time of first packet ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_time_of_first_packet_ie_t(time_of_first_packet_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->time_of_first_packet, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}


/**
 * Encodes time of last packet ie to buffer.
 * @param value
 *     time of last packet ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_time_of_last_packet_ie_t(time_of_last_packet_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->time_of_last_packet, 32, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}


/**
 * Encodes usage information ie to buffer.
 * @param value
 *     usage information ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_usage_information_ie_t(usage_information_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->ube, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->uae, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->aft, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->bef, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}
/**
 * Encodes mac addresses detected ie to buffer.
 * @param value
 *     mac addresses detected ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_mac_addresses_detected_ie_t(mac_addresses_detected_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->number_of_mac_addresses, 8, buf + (encoded/8), encoded % CHAR_SIZE);
        memcpy(buf + (encoded/CHAR_SIZE), &value->mac_address_value_1, MAC_ADDRESS_VALUE_1_LEN);
        encoded +=  MAC_ADDRESS_VALUE_1_LEN * CHAR_SIZE;
        return encoded;
}

/**
 * Encodes mac addresses removed ie to buffer.
 * @param value
 *     mac addresses removed ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_mac_addresses_removed_ie_t(mac_addresses_removed_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->number_of_mac_addresses, 8, buf + (encoded/8), encoded % CHAR_SIZE);
        memcpy(buf + (encoded/CHAR_SIZE), &value->mac_address_value_1, MAC_ADDRESS_VALUE_1_LEN);
        encoded +=  MAC_ADDRESS_VALUE_1_LEN * CHAR_SIZE;
        return encoded;
}

/**
 * Encodes ethernetraffic information to buffer.
 * @param et_inf
 *     ethernetraffic information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ethernet_traffic_information_ie_t(ethernet_traffic_information_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->mac_addresses_detected.header.len)
                encoded += encode_mac_addresses_detected_ie_t(&(value->mac_addresses_detected), buf + (encoded/CHAR_SIZE));

        if (value->mac_addresses_removed.header.len)
                encoded += encode_mac_addresses_removed_ie_t(&(value->mac_addresses_removed), buf + (encoded/CHAR_SIZE));

        return encoded;
}

/**
 * Encodes session report usage report to buffer.
 * @param value
 *     session report usage report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_session_report_usage_report_ie_t(session_report_usage_report_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;

        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->urr_id.header.len)
                encoded += encode_urr_id_ie_t(&(value->urr_id), buf + (encoded/CHAR_SIZE));

        if (value->urseqn.header.len)
                encoded += encode_ur_seqn_ie_t(&(value->urseqn), buf + (encoded/CHAR_SIZE));

        if (value->usage_report_trigger.header.len)
                encoded += encode_usage_report_trigger_ie_t(&(value->usage_report_trigger), buf + (encoded/CHAR_SIZE));

        if (value->start_time.header.len)
                encoded += encode_start_time_ie_t(&(value->start_time), buf + (encoded/CHAR_SIZE));
				
	if (value->end_time.header.len)
                encoded += encode_end_time_ie_t(&(value->end_time), buf + (encoded/CHAR_SIZE));

        if (value->volume_measurement.header.len)
                encoded += encode_volume_measurement_ie_t(&(value->volume_measurement), buf + (encoded/CHAR_SIZE));

        if (value->duration_measurement.header.len)
                encoded += encode_duration_measurement_ie_t(&(value->duration_measurement), buf + (encoded/CHAR_SIZE));

        if (value->application_detection_information.header.len)
                encoded += encode_application_detection_information_ie_t(&(value->application_detection_information), buf + (encoded/CHAR_SIZE));

        if (value->ue_ip_address.header.len)
                encoded += encode_ue_ip_address_ie_t(&(value->ue_ip_address), buf + (encoded/CHAR_SIZE));

        if (value->network_instance.header.len)
                encoded += encode_network_instance_ie_t(&(value->network_instance), buf + (encoded/CHAR_SIZE));

        if (value->time_of_first_packet.header.len)
                encoded += encode_time_of_first_packet_ie_t(&(value->time_of_first_packet), buf + (encoded/CHAR_SIZE));

        if (value->time_of_last_packet.header.len)
                encoded += encode_time_of_last_packet_ie_t(&(value->time_of_last_packet), buf + (encoded/CHAR_SIZE));

        if (value->usage_information.header.len)
                encoded += encode_usage_information_ie_t(&(value->usage_information), buf + (encoded/CHAR_SIZE));
				
	if (value->query_urr_reference.header.len)
                encoded += encode_query_urr_reference_ie_t(&(value->query_urr_reference), buf + (encoded/CHAR_SIZE));

        if (value->ethernet_traffic_information.header.len)
                encoded += encode_ethernet_traffic_information_ie_t(&(value->ethernet_traffic_information), buf + (encoded/CHAR_SIZE));
        return encoded/CHAR_SIZE;
}


/**
 * Encodes error indication report to buffer.
 * @param ei_rep
 *     error indication report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_error_indication_report_ie_t(error_indication_report_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;

        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->remote_fteid.header.len)
                encoded += encode_f_teid_ie_t(&(value->remote_fteid),buf + (encoded/CHAR_SIZE));

        return encoded/CHAR_SIZE;
}

/**
 * Encodes pfcpsrrsp flags ie to buffer.
 * @param value
 *     pfcpsrrsp flags ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcpsrrsp_flags_ie_t(pfcpsrrsp_flags_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spare7, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->drobu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded/CHAR_SIZE;
}

/**
 * Encodes dl buffering suggested packet count ie to buffer.
 * @param value
 *     dl buffering suggested packet count ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_dl_buffering_suggested_packet_count_ie_t(dl_buffering_suggested_packet_count_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        memcpy(buf + (encoded/CHAR_SIZE), &value->packet_count_value, PACKET_COUNT_VALUE_LEN);
        encoded +=  PACKET_COUNT_VALUE_LEN * CHAR_SIZE;
        return encoded;
}

/**
 * Encodes dl buffering duration ie to buffer.
 * @param value
 *     dl buffering duration ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_dl_buffering_duration_ie_t(dl_buffering_duration_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
        encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);
        return encoded;
}

/**
 * Encodes session report response update bar to buffer.
 * @param value
 *     session report response update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_session_report_response_update_bar_ie_t(session_report_response_update_bar_ie_t *value,
        uint8_t *buf)
{
        uint16_t encoded = 0;

        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

        if (value->bar_id.header.len)
                encoded += encode_bar_id_ie_t(&(value->bar_id), buf + (encoded/CHAR_SIZE));

        if (value->downlink_data_notification_delay.header.len)
                encoded += encode_downlink_data_notification_delay_ie_t(&(value->downlink_data_notification_delay), buf + (encoded/CHAR_SIZE));

        if (value->dl_buffering_duration.header.len)
                encoded += encode_dl_buffering_duration_ie_t(&(value->dl_buffering_duration), buf + (encoded/CHAR_SIZE));

        if (value->dl_buffering_suggested_packet_count.header.len)
                encoded += encode_dl_buffering_suggested_packet_count_ie_t(&(value->dl_buffering_suggested_packet_count), buf + (encoded/CHAR_SIZE)); 
				
        if (value->suggested_buffering_packets_count.header.len)
                encoded += encode_suggested_buffering_packets_count_ie_t(&(value->suggested_buffering_packets_count), buf + (encoded/CHAR_SIZE));

        return encoded/CHAR_SIZE;
}

/**
 * Encodes user plane ip resource information to buffer.
 * @param value
 *     user plane ip resource information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_user_plane_ip_resource_information_ie_t(user_plane_ip_resource_information_ie_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;
        encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->assosi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->assoni, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teidri, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->teidri != 0)
		encoded += encode_bits(value->teid_range, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->v4 == 1){
		memcpy(buf + (encoded/8), &value->ipv4_address, 4);
		encoded +=  4 * CHAR_SIZE;
	}
	else {
		memcpy(buf + (encoded/8), &value->ipv6_address, 16);
		encoded +=  16 * CHAR_SIZE;
	}
	if(value->assoni == 1)
		encoded += encode_bits(value->network_instance, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	if(value->assosi == 1)
		encoded += encode_bits(value->source_interface, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	return encoded/CHAR_SIZE;
}
