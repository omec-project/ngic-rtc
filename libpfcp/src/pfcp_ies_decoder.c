/*
 * Copyright (c) 2003-2018, Great Software Laboratory Pvt. Ltd.
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

#include "../include/pfcp_ies_decoder.h"

#include "../include/enc_dec_bits.h"


/**
 * Decode pfcp buffer.
 * @param value
 *     gtpc
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int decode_pfcp_header_t(uint8_t *buf, pfcp_header_t *value)
{

	uint16_t total_decoded = 0;
	uint16_t decoded = 0;

//	value->s = decode_bits(buf, total_decoded, 1, &decoded);
//	total_decoded += decoded;
//	value->mp = decode_bits(buf, total_decoded, 1, &decoded);
//	total_decoded += decoded;
//	value->spare = decode_bits(buf, total_decoded, 3, &decoded);
//	total_decoded += decoded;
//	value->version = decode_bits(buf, total_decoded, 3, &decoded);
//	total_decoded += decoded;

	value->version = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->mp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->s = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;


	value->message_type = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->message_len = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;

	if (value->s == 1) {

		value->seid_seqno.has_seid.seid = decode_bits(buf, total_decoded, 64, &decoded);
		total_decoded += decoded;

		value->seid_seqno.has_seid.seq_no = decode_bits(buf, total_decoded, 24, &decoded);
		total_decoded += decoded;

		value->seid_seqno.has_seid.spare = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;

		value->seid_seqno.has_seid.message_prio = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;

	} else {
		value->seid_seqno.no_seid.seq_no = decode_bits(buf, total_decoded, 24, &decoded);
		total_decoded += decoded;

		value->seid_seqno.no_seid.spare = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;

	}

	return total_decoded/CHAR_SIZE;
}



/**
 * decodes ie header to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ie header
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_ie_header_t(uint8_t *buf,
	pfcp_ie_header_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
	value->type = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->len = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	//return total_decoded/CHAR_SIZE;
	return total_decoded;
}

/**
 * decodes node id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     node id ie
 * @return
 *   number of decoded bytes.
 */
int decode_node_id_ie_t(uint8_t *buf,
	node_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->node_id_type = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	memcpy(&value->node_id_value, buf + (total_decoded/CHAR_SIZE), value->header.len - 1);
	total_decoded +=  (value->header.len - 1) * CHAR_SIZE;

	return total_decoded/CHAR_SIZE;
}

/**
 * decodes recoveryime stamp ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     recoveryime stamp ie
 * @return
 *   number of decoded bytes.
 */
int decode_recovery_time_stamp_ie_t(uint8_t *buf,
	recovery_time_stamp_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->recovery_time_stamp_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}


/**
 * decodes up function features ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     up function features ie
 * @return
 *   number of decoded bytes.
 */
int decode_up_function_features_ie_t(uint8_t *buf,
	up_function_features_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->supported_features = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes cause id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     cause ie
 * @return
 *   number of decoded bytes.
 */
int decode_cause_id_ie_t(uint8_t *buf,
	pfcp_cause_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->cause_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes cp function features ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     cp function features ie
 * @return
 *   number of decoded bytes.
 */
int decode_cp_function_features_ie_t(uint8_t *buf,
	cp_function_features_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->supported_features = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}



/**
 * decodes f seid ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     f seid ie
 * @return
 *   number of decoded bytes.
 */
int decode_f_seid_ie_t(uint8_t *buf,
		f_seid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->seid = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	if(value->v4 == 1){
		value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}
	else {
		value->ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
		total_decoded += decoded;
	}
	return total_decoded/CHAR_SIZE;
}


/**
 * Decodes load control information to buffer.
 * @param lc_inf
 *     load control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_load_control_information_ie_t(uint8_t *buf,
		load_control_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	total_decoded += decode_sequence_number_ie_t(buf +(total_decoded/CHAR_SIZE), &value->load_control_sequence_number);
	total_decoded += decode_metric_ie_t(buf +(total_decoded/CHAR_SIZE), &value->load_metric);

	return total_decoded/CHAR_SIZE;
}
#if 0
int decode_load_control_information_ie_t(uint8_t *msg,
		load_control_information_ie_t *lc_inf)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_ie_header_t(msg + count, &lc_inf->header);

	if (lc_inf->header.s)
		msg_len = lc_inf->header.message_len - 8;
	else
		msg_len = lc_inf->header.message_len - 4;

	msg = msg + count;
	count = 0;
	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_SEQUENCE_NUMBER) {
			count += decode_sequence_number_ie_t(msg + count, &lc_inf->load_control_sequence_number);
		} else if (ie_type == IE_METRIC ) {
			count += decode_metric_ie_t(msg + count, &lc_inf->load_metric);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}
#endif
/**
 * Decodes overload control information to buffer.
 * @param oc_inf
 *     overload control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_overload_control_information_ie_t(uint8_t *buf,
		overload_control_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	total_decoded += decode_sequence_number_ie_t(buf +(total_decoded/CHAR_SIZE), &value->overload_control_sequence_number);
	total_decoded += decode_metric_ie_t(buf +(total_decoded/CHAR_SIZE), &value->overload_reduction_metric);
	total_decoded += decode_timer_ie_t(buf +(total_decoded/CHAR_SIZE), &value->period_of_validity);
	total_decoded += decode_oci_flags_ie_t(buf +(total_decoded/CHAR_SIZE), &value->overload_control_information_flags);

	return total_decoded/CHAR_SIZE;
}
#if 0
int decode_overload_control_information_ie_t(uint8_t *msg,
		overload_control_information_ie_t *oc_inf)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &oc_inf->header);

	if (oc_inf->header.s)
		msg_len = oc_inf->header.message_len - 12;
	else
		msg_len = oc_inf->header.message_len - 4;

	msg = msg + count;
	count = 0;
	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_SEQUENCE_NUMBER) {
			count += decode_sequence_number_ie_t(msg + count, &oc_inf->overload_control_sequence_number);
		} else if (ie_type == IE_METRIC) {
			count += decode_metric_ie_t(msg + count, &oc_inf->overload_reduction_metric);
		} else if (ie_type == IE_TIMER) {
			count += decode_timer_ie_t(msg + count, &oc_inf->period_of_validity);
		} else if (ie_type == IE_OCI_FLAGS) {
			count += decode_oci_flags_ie_t(msg + count, &oc_inf->overload_control_information_flags);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}
#endif

/**
 * decodes offending ie ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     offending ie ie
 * @return
 *   number of decoded bytes.
 */
int decode_offending_ie_t(uint8_t *buf,
		offending_ie_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->type_of_the_offending_ie = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}


/**
 * decodes fq csid ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     fq csid ie
 * @return
 *   number of decoded bytes.
 */
int decode_fq_csid_ie_t(uint8_t *buf,
		fq_csid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->fq_csid_node_id_type = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->number_of_csids = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if (value->fq_csid_node_id_type ==0 ){
		value->node_address.ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}else if (value->fq_csid_node_id_type == 1 ){
		value->node_address.ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
		total_decoded += decoded;
	}else {
		value->node_address.mcc = decode_bits(buf, total_decoded, 20, &decoded);
		total_decoded += decoded;
		value->node_address.mnc = decode_bits(buf, total_decoded, 12, &decoded);
		total_decoded += decoded;
	}

	memcpy(&value->pdn_connection_set_identifier, buf + (total_decoded/CHAR_SIZE), 2*(value->number_of_csids));
	total_decoded +=  2*(value->number_of_csids) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes failed rule id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     failed rule id ie
 * @return
 *   number of decoded bytes.
 */
int decode_failed_rule_id_ie_t(uint8_t *buf,
		failed_rule_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->rule_id_type = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	if(value->rule_id_type == RULE_ID_TYPE_PDR) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 2);
		total_decoded +=  2 * CHAR_SIZE;
	}else if(value->rule_id_type == RULE_ID_TYPE_QER) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}else if(value->rule_id_type == RULE_ID_TYPE_URR) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}else if(value->rule_id_type == RULE_ID_TYPE_BAR) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 1);
		total_decoded +=  1 * CHAR_SIZE;
	}else{
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}//FAR is by default 3gpp 29.244 15.03 (8.2.80)
	return total_decoded/CHAR_SIZE;
}


/**
 * decodes sequence number ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     sequence number ie
 * @return
 *   number of decoded bytes.
 */
int decode_sequence_number_ie_t(uint8_t *buf,
		sequence_number_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->sequence_number = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes metric ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     metric ie
 * @return
 *   number of decoded bytes.
 */
int decode_metric_ie_t(uint8_t *buf,
		metric_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->metric = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes timer ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     timer ie
 * @return
 *   number of decoded bytes.
 */
int decode_timer_ie_t(uint8_t *buf,
		timer_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	return total_decoded;
}
/**
 * decodes oci flags ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     oci flags ie
 * @return
 *   number of decoded bytes.
 */
int decode_oci_flags_ie_t(uint8_t *buf,
		oci_flags_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->aoci = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes pdnype ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pdnype ie
 * @return
 *   number of decoded bytes.
 */
int decode_pdn_type_ie_t(uint8_t *buf,
		pfcp_pdn_type_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->pdn_type = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

	int
decode_bar_id_ie_t(uint8_t *buf ,bar_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->bar_id_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	//return total_decoded/CHAR_SIZE;
	return total_decoded;
}



int
decode_dl_data_notification_delay_ie_t(uint8_t *buf ,downlink_data_notification_delay_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->delay_value_in_integer_multiples_of_50_millisecs_or_zero = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	//return total_decoded/CHAR_SIZE;
	return total_decoded;
}



int
decode_suggested_buff_packet_count_ie_t(uint8_t *buf , suggested_buffering_packets_count_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->packet_count_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	//return total_decoded/CHAR_SIZE;
	return total_decoded;
}

/**
 * Decodes create bar to buffer.
 * @param c_bar
 *     create bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_create_bar_ie_t(uint8_t *buf,
		create_bar_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	total_decoded += decode_bar_id_ie_t(buf + (total_decoded/CHAR_SIZE),&value->bar_id);
	total_decoded += decode_dl_data_notification_delay_ie_t(buf + (total_decoded/CHAR_SIZE),&value->downlink_data_notification_delay);
	total_decoded += decode_suggested_buff_packet_count_ie_t(buf + (total_decoded/CHAR_SIZE),&value->suggested_buffering_packets_count);

	return total_decoded/CHAR_SIZE;
}

/**
 * decodes trace information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     trace information ie
 * @return
 *   number of decoded bytes.
 */
int decode_trace_information_ie_t(uint8_t *buf,
		trace_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->trace_id = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;
	value->spare = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->length_of_triggering_events = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->triggering_events, buf + (total_decoded/CHAR_SIZE),value->length_of_triggering_events);
	total_decoded +=  value->length_of_triggering_events * CHAR_SIZE;
	value->session_trace_depth = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	value->length_of_list_of_interfaces = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->list_of_interfaces, buf + (total_decoded/CHAR_SIZE), value->length_of_list_of_interfaces);
	total_decoded +=  value->length_of_list_of_interfaces * CHAR_SIZE;
	value->length_of_ip_address_of_trace_collection_entity = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->ip_address_of_trace_collection_entity, buf + (total_decoded/CHAR_SIZE),4*(value->length_of_ip_address_of_trace_collection_entity));
	total_decoded += 4*( value->length_of_ip_address_of_trace_collection_entity) * CHAR_SIZE;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes user plane inactivityimer ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     user plane inactivityimer ie
 * @return
 *   number of decoded bytes.
 */
int decode_user_plane_inactivity_timer_ie_t(uint8_t *buf,
		user_plane_inactivity_timer_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->user_plane_inactivity_timer = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes user id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     user id ie
 * @return
 *   number of decoded bytes.
 */
int decode_user_id_ie_t(uint8_t *buf,
		user_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->naif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->msisdnf = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->imeif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->imsif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->imsif == 1){
		value->length_of_imsi = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->imsi), buf + (total_decoded/CHAR_SIZE),value->length_of_imsi );
		total_decoded +=  value->length_of_imsi * CHAR_SIZE;
	}
	if(value->imeif == 1){
		value->length_of_imei = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->imei), buf + (total_decoded/CHAR_SIZE), value->length_of_imei);
		total_decoded +=  value->length_of_imei * CHAR_SIZE;
	}
	if(value->msisdnf ==1){
		value->length_of_msisdn = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->msisdn), buf + (total_decoded/CHAR_SIZE), value->length_of_msisdn);
		total_decoded +=  value->length_of_msisdn * CHAR_SIZE;
	}
	if(value->naif == 1){
		value->length_of_nai = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&value->nai, buf + (total_decoded/CHAR_SIZE), value->length_of_nai);
		total_decoded +=  value->length_of_nai * CHAR_SIZE;
	}
	return total_decoded/CHAR_SIZE;
}


/**
 * Decodes remove bar to buffer.
 * @param r_bar
 *     remove bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_remove_bar_ie_t(uint8_t *buf,
		remove_bar_ie_t *r_bar)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(r_bar->header));
	total_decoded += decode_bar_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(r_bar->bar_id));


	return total_decoded/CHAR_SIZE ;
}


/**
 * Decodes removeraffic endpoint to buffer.
 * @param rt_end
 *     removeraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_remove_traffic_endpoint_ie_t(uint8_t *buf,
		remove_traffic_endpoint_ie_t *rt_end)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(rt_end->header));
	total_decoded += decode_traffic_endpoint_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(rt_end->traffic_endpoint_id));

	return total_decoded/CHAR_SIZE ;

}


/**
 * Decodes createraffic endpoint to buffer.
 * @param ct_end
 *     createraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_create_traffic_endpoint_ie_t(uint8_t *buf,
		create_traffic_endpoint_ie_t *ct_end)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->header));

	total_decoded += decode_traffic_endpoint_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->traffic_endpoint_id));
	total_decoded += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->local_fteid));
	total_decoded += decode_network_instance_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->network_instance));
	total_decoded += decode_ue_ip_address_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->ue_ip_address));
	total_decoded += decode_ethernet_pdu_session_information_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->ethernet_pdu_session_information));
	total_decoded += decode_framed_routing_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->framedrouting));

	return total_decoded/CHAR_SIZE ;
}

/**
 * Decodes update qer to buffer.
 * @param u_qer
 *     update qer
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_update_qer_ie_t(uint8_t *buf,
	update_qer_ie_t *u_qer)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->header));
	total_decoded += decode_qer_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->qer_id));
	total_decoded += decode_qer_correlation_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->qer_correlation_id));
	total_decoded += decode_gate_status_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->gate_status));
	total_decoded += decode_mbr_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->maximum_bitrate));
	total_decoded += decode_gbr_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->guaranteed_bitrate));
	total_decoded += decode_packet_rate_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->packet_rate));
	total_decoded += decode_dl_flow_level_marking_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->dl_flow_level_marking));
	total_decoded += decode_qfi_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->qos_flow_identifier));
	total_decoded += decode_rqi_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_qer->reflective_qos));



	return total_decoded/CHAR_SIZE ;
}

/**
 * decodes traffic endpoint id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     traffic endpoint id ie
 * @return
 *   number of decoded bytes.
 */
int decode_traffic_endpoint_id_ie_t(uint8_t *buf,
		traffic_endpoint_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->traffic_endpoint_id_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes feid ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     feid ie
 * @return
 *   number of decoded bytes.
 */
int decode_f_teid_ie_t(uint8_t *buf,
		f_teid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->chid = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ch = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->teid = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	if(value->v4 == 1) {
		value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}else {
		value->ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
		total_decoded += decoded;
	}
	if(value->chid == 1) {
		value->choose_id = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	return total_decoded;
}

/**
 * Decodes update bar to buffer.
 * @param u_bar
 *     update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_update_bar_ie_t(uint8_t *buf,
	update_bar_ie_t *u_bar)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(u_bar->header));

	total_decoded += decode_bar_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_bar->bar_id));
	total_decoded += decode_dl_data_notification_delay_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_bar->downlink_data_notification_delay));
	total_decoded += decode_suggested_buff_packet_count_ie_t(buf + (total_decoded/CHAR_SIZE),&(u_bar->suggested_buffering_packets_count));

	return total_decoded/CHAR_SIZE;

}


/**
 * Decodes updateraffic endpoint to buffer.
 * @param ut_end
 *     updateraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_update_traffic_endpoint_ie_t(uint8_t *buf,
	update_traffic_endpoint_ie_t *ut_end)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->header));

	total_decoded += decode_traffic_endpoint_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->traffic_endpoint_id));
	total_decoded += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->local_fteid));
	total_decoded += decode_network_instance_ie_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->network_instance));
	total_decoded += decode_ue_ip_address_ie_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->ue_ip_address));
	total_decoded += decode_framed_routing_ie_t(buf + (total_decoded/CHAR_SIZE),&(ut_end->framedrouting));

	return total_decoded/CHAR_SIZE;

}

/**
 * decodes pfcpsmreq flags ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pfcpsmreq flags ie
 * @return
 *   number of decoded bytes.
 */
int decode_pfcpsmreq_flags_ie_t(uint8_t *buf,
	pfcpsmreq_flags_ie_t *value)
{

	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&(value->header));

	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->qaurr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->sndem = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->drobu = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	return total_decoded/CHAR_SIZE;

}

/**
 * decodes query urr reference ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     query urr reference ie
 * @return
 *   number of decoded bytes.
 */
int decode_query_urr_reference_ie_t(uint8_t *buf,
		query_urr_reference_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->query_urr_reference_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}


/**
 * decodes network instance ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     network instance ie
 * @return
 *   number of decoded bytes.
 */
int decode_network_instance_ie_t(uint8_t *buf,
		network_instance_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	memcpy(&value->network_instance, buf + (total_decoded/CHAR_SIZE), NETWORK_INSTANCE_LEN);
	total_decoded +=  NETWORK_INSTANCE_LEN * CHAR_SIZE;
	return total_decoded;
}


/**
 * decodes ue ip address ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ue ip address ie
 * @return
 *   number of decoded bytes.
 */
int decode_ue_ip_address_ie_t(uint8_t *buf,
		ue_ip_address_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->ipv6d = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->sd = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->v4 == 1) {
		value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}
	if(value->v6 == 1){
		value->ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
		total_decoded += decoded;
		value->ipv6_prefix_delegation_bits = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	} 
	return total_decoded;
}

/**
 * decodes ethernet pdu session information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ethernet pdu session information ie
 * @return
 *   number of decoded bytes.
 */

int decode_ethernet_pdu_session_information_ie_t(uint8_t *buf,
		ethernet_pdu_session_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->ethi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}



/**
 * decodes framed routing ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     framed routing ie
 * @return
 *   number of decoded bytes.
 */
int decode_framed_routing_ie_t(uint8_t *buf,
		framed_routing_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	memcpy(&value->framed_routing, buf + (total_decoded/CHAR_SIZE), FRAMED_ROUTING_LEN);
	total_decoded +=  FRAMED_ROUTING_LEN * CHAR_SIZE;
	return total_decoded;

}

/**
 * decodes qer id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     qer id ie
 * @return
 *   number of decoded bytes.
 */
int decode_qer_id_ie_t(uint8_t *buf,
		qer_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->qer_id_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes qer correlation id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     qer correlation id ie
 * @return
 *   number of decoded bytes.
 */

int decode_qer_correlation_id_ie_t(uint8_t *buf,
		qer_correlation_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->qer_correlation_id_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes gate status ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     gate status ie
 * @return
 *   number of decoded bytes.
 */

int decode_gate_status_ie_t(uint8_t *buf,
		gate_status_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->ul_gate = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->dl_gate = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;

	return total_decoded;
}


/**
 * decodes buffer to mbr value.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   mbr value
 * @return
 *   number of decoded bytes.
 */
int
decode_mbr_bits(uint8_t *buf, uint64_t *val)
{
        *val = (uint64_t)(buf[4]) | (uint64_t)(buf[3]) << 8  |
                   (uint64_t)(buf[2]) << 16 | (uint64_t)(buf[1]) << 24 |
                   (uint64_t)(buf[0]) << 32;

        return 5 * CHAR_SIZE;
}

/**
 * decodes mbr ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     mbr ie
 * @return
 *   number of decoded bytes.
 */

int decode_mbr_ie_t(uint8_t *buf,
		mbr_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	total_decoded += decode_mbr_bits(buf+(total_decoded/CHAR_SIZE),&value->ul_mbr);
	total_decoded += decode_mbr_bits(buf+(total_decoded/CHAR_SIZE),&value->dl_mbr);
	return total_decoded;
}


/**
 * decodes gbr ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     gbr ie
 * @return
 *   number of decoded bytes.
 */
int decode_gbr_ie_t(uint8_t *buf,
		gbr_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	total_decoded += decode_mbr_bits(buf+(total_decoded/CHAR_SIZE),&value->ul_gbr);
	total_decoded += decode_mbr_bits(buf+(total_decoded/CHAR_SIZE),&value->dl_gbr);
	return total_decoded;
}


/**
 * decodes packet rate ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     packet rate ie
 * @return
 *   number of decoded bytes.
 */
int decode_packet_rate_ie_t(uint8_t *buf,
		packet_rate_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->dlpr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ulpr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->uplink_time_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->maximum_uplink_packet_rate = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->downlink_time_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->maximum_downlink_packet_rate = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded;

}


/**
 * decodes dl flow level marking ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     dl flow level marking ie
 * @return
 *   number of decoded bytes.
 */

int decode_dl_flow_level_marking_ie_t(uint8_t *buf,
		dl_flow_level_marking_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->sci = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ttc = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->tostraffic_class = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	value->service_class_indicator = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes qfi ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     qfi ie
 * @return
 *   number of decoded bytes.
 */
int decode_qfi_ie_t(uint8_t *buf,
		qfi_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->qfi_value = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes rqi ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     rqi ie
 * @return
 *   number of decoded bytes.
 */

int decode_rqi_ie_t(uint8_t *buf,
		rqi_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->rqi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}



/**
 * Decodes created pdr to buffer.
 * @param c_pdr
 *     created pdr
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_created_pdr_ie_t(uint8_t *buf,
		created_pdr_ie_t *c_pdr)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&c_pdr->header);
	total_decoded += decode_pdr_id_ie_t(buf + (total_decoded/CHAR_SIZE),&c_pdr->pdr_id);
	total_decoded += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE),&c_pdr->local_fteid);

	return total_decoded/CHAR_SIZE;
}


/**
 * decodes pdr id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pdr id ie
 * @return
 *   number of decoded bytes.
 */

int decode_pdr_id_ie_t(uint8_t *buf,
		pdr_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->rule_id = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes additional usage reports information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     additional usage reports information ie
 * @return
 *   number of decoded bytes.
 */

int decode_additional_usage_reports_information_ie_t(uint8_t *buf,
		additional_usage_reports_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->auri = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->number_of_additional_usage_reports_value = decode_bits(buf, total_decoded, 15, &decoded);
	total_decoded += decoded;

	return total_decoded;
}



/**
 * Decodes createdraffic endpoint to buffer.
 * @param ct_end
 *     createdraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_created_traffic_endpoint_ie_t(uint8_t *buf,
	created_traffic_endpoint_ie_t *ct_end)
{

	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&ct_end->header);
	total_decoded += decode_traffic_endpoint_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->traffic_endpoint_id));
	total_decoded += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE),&(ct_end->local_fteid));

	return total_decoded/CHAR_SIZE;

}


/**
 * decodes pfcp association release request ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pfcp association release request ie
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_association_release_request_ie_t(uint8_t *buf,
		pfcp_association_release_request_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->sarr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}


/**
 * decodes graceful release period ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     graceful release period ie
 * @return
 *   number of decoded bytes.
 */
int decode_graceful_release_period_ie_t(uint8_t *buf,
		graceful_release_period_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}


/**
 * Decodes user plane path failure report to buffer.
 * @param uppf_rep
 *     user plane path failure report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_user_plane_path_failure_report_ie_t(uint8_t *buf,
    user_plane_path_failure_report_ie_t *uppf_rep)
{
        uint16_t total_decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&uppf_rep->header);
	total_decoded += decode_remote_gtp_u_peer_ie_t(buf + (total_decoded/CHAR_SIZE),&uppf_rep->remote_gtpu_peer);
	return total_decoded/CHAR_SIZE;

}


/**
 * decodes remote gtp u peer ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     remote gtp u peer ie
 * @return
 *   number of decoded bytes.
 */

int decode_remote_gtp_u_peer_ie_t(uint8_t *buf,
		remote_gtp_u_peer_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	value->ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes node reportype ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     node reportype ie
 * @return
 *   number of decoded bytes.
 */
int decode_node_report_type_ie_t(uint8_t *buf,
		node_report_type_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 7, &decoded);
	total_decoded += decoded;
	value->upfr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}



/**
 * decodes reportype ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     reportype ie
 * @return
 *   number of decoded bytes.
 */

int decode_report_type_ie_t(uint8_t *buf,
		report_type_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->upir = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->erir = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->usar = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->dldr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}



/**
 * Decodes session report usage report to buffer.
 * @param s_repu_rep
 *     session report usage report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_session_report_usage_report_ie_t(uint8_t *buf,
		session_report_usage_report_ie_t *s_repu_rep)
{

	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->header);
	//uint16_t decoded = 0;
	total_decoded += decode_urr_id_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->urr_id);
	total_decoded += decode_ur_seqn_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->urseqn);
	total_decoded += decode_usage_report_trigger_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->usage_report_trigger);
	total_decoded += decode_start_time_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->start_time);
	total_decoded += decode_end_time_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->end_time);
	total_decoded += decode_volume_measurement_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->volume_measurement);
	total_decoded += decode_duration_measurement_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->duration_measurement);
	total_decoded += decode_application_detection_information_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->application_detection_information);
	total_decoded += decode_ue_ip_address_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->ue_ip_address);
	total_decoded += decode_network_instance_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->network_instance);
	total_decoded += decode_time_of_first_packet_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->time_of_first_packet);
	total_decoded += decode_time_of_last_packet_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->time_of_last_packet);
	total_decoded += decode_usage_information_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->usage_information);
	total_decoded += decode_query_urr_reference_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->query_urr_reference);
	total_decoded += decode_ethernet_traffic_information_ie_t(buf + (total_decoded/CHAR_SIZE), &s_repu_rep->ethernet_traffic_information);

	return total_decoded/CHAR_SIZE;
}

/**
 * Decodes error indication report to buffer.
 * @param ei_rep
 *     error indication report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_error_indication_report_ie_t(uint8_t *buf,
		error_indication_report_ie_t *ei_rep)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&ei_rep->header);
	total_decoded  += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE), &ei_rep->remote_fteid);

	return total_decoded/CHAR_SIZE;
}


/**
 * Decodes downlink data report to buffer.
 * @param dd_rep
 *     downlink data report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_downlink_data_report_ie_t(uint8_t *buf,
		downlink_data_report_ie_t *dd_rep)
{
	uint16_t total_decoded = 0;

	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &dd_rep->header);
	total_decoded += decode_downlink_data_service_information_ie_t(buf + (total_decoded/CHAR_SIZE), &dd_rep->downlink_data_service_information);

	return total_decoded/CHAR_SIZE;
}


/**
 * decodes urr id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     urr id ie
 * @return
 *   number of decoded bytes.
 */
int decode_urr_id_ie_t(uint8_t *buf,
		urr_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->urr_id_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes usage reportrigger ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     usage reportrigger ie
 * @return
 *   number of decoded bytes.
 */

int decode_usage_report_trigger_ie_t(uint8_t *buf,
		usage_report_trigger_ie_t *value)
{
	uint16_t decoded = 0;
	uint16_t total_decoded = 0;
	value->immer = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->droth = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->stopt = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->start = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->quhti = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->timth = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->volth = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->perio = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->eveth = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->macar = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->envcl = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->monit = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->termr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->liusa = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->timqu = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->volqu = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	return total_decoded;
}


/**
 * decodes volume measurement ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     volume measurement ie
 * @return
 *   number of decoded bytes.
 */
int decode_volume_measurement_ie_t(uint8_t *buf,
		volume_measurement_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->total_volume = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	value->uplink_volume = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	value->downlink_volume = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;

	return total_decoded;
}

/**
 * decodes duration measurement ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     duration measurement ie
 * @return
 *   number of decoded bytes.
 */
int decode_duration_measurement_ie_t(uint8_t *buf,
		duration_measurement_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->duration_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes time of first packet ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     time of first packet ie
 * @return
 *   number of decoded bytes.
 */
int decode_time_of_first_packet_ie_t(uint8_t *buf,
		time_of_first_packet_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->time_of_first_packet = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes time of last packet ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     time of last packet ie
 * @return
 *   number of decoded bytes.
 */
int decode_time_of_last_packet_ie_t(uint8_t *buf,
		time_of_last_packet_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->time_of_last_packet = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes usage information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     usage information ie
 * @return
 *   number of decoded bytes.
 */
int decode_usage_information_ie_t(uint8_t *buf,
		usage_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->ube = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->uae = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->aft = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->bef = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes downlink data service information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     downlink data service information ie
 * @return
 *   number of decoded bytes.
 */
int decode_downlink_data_service_information_ie_t(uint8_t *buf,
		downlink_data_service_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->qfii = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ppi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	value->paging_policy_indication_value = decode_bits(buf, total_decoded, 6, &decoded);
	total_decoded += decoded;
	value->spare4 = decode_bits(buf, total_decoded, 2, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes ur seqn ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ur seqn ie
 * @return
 *   number of decoded bytes.
 */
int decode_ur_seqn_ie_t(uint8_t *buf,
		ur_seqn_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->ur_seqn = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes startime ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     startime ie
 * @return
 *   number of decoded bytes.
 */
int decode_start_time_ie_t(uint8_t *buf,
		start_time_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->start_time = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
 * decodes endime ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     endime ie
 * @return
 *   number of decoded bytes.
 */
int decode_end_time_ie_t(uint8_t *buf,
		end_time_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->end_time = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}



/**
 * Decodes application detection information to buffer.
 * @param ad_inf
 *     application detection information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_application_detection_information_ie_t(uint8_t *buf,
		application_detection_information_ie_t *ad_inf)
{
	uint16_t total_decoded = 0;

	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &ad_inf->header);
	total_decoded += decode_application_id_ie_t(buf + (total_decoded/CHAR_SIZE), &ad_inf->application_id);
	total_decoded += decode_application_instance_id_ie_t(buf + (total_decoded/CHAR_SIZE), &ad_inf->application_instance_id);
	total_decoded += decode_flow_information_ie_t(buf + (total_decoded/CHAR_SIZE), &ad_inf->flow_information);

	return total_decoded;
}

/**
 * decodes application id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     application id ie
 * @return
 *   number of decoded bytes.
 */
int decode_application_id_ie_t(uint8_t *buf,
		application_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	memcpy(&value->application_identifier, buf + (total_decoded/CHAR_SIZE), APPLICATION_IDENTIFIER_LEN);
	total_decoded +=  APPLICATION_IDENTIFIER_LEN * CHAR_SIZE;
	return total_decoded;
}


/**
 * decodes application instance id ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     application instance id ie
 * @return
 *   number of decoded bytes.
 */
int decode_application_instance_id_ie_t(uint8_t *buf,
		application_instance_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	memcpy(&value->application_instance_identifier, buf + (total_decoded/CHAR_SIZE), APPLICATION_INSTANCE_IDENTIFIER_LEN);
	total_decoded +=  APPLICATION_INSTANCE_IDENTIFIER_LEN * CHAR_SIZE;
	return total_decoded;
}


/**
 * decodes flow information ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     flow information ie
 * @return
 *   number of decoded bytes.
 */
int decode_flow_information_ie_t(uint8_t *buf,
		flow_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	value->flow_direction = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->length_of_flow_description = decode_bits(buf, total_decoded, 16, &decoded);
	total_decoded += decoded;
	memcpy(&value->flow_description, buf + (total_decoded/CHAR_SIZE), FLOW_DESCRIPTION_LEN);
	total_decoded +=  FLOW_DESCRIPTION_LEN * CHAR_SIZE;
	return total_decoded;
}





/**
 * Decodes ethernetraffic information to buffer.
 * @param et_inf
 *     ethernetraffic information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_ethernet_traffic_information_ie_t(uint8_t *buf,
		ethernet_traffic_information_ie_t *et_inf)
{
	uint16_t total_decoded = 0;

	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &et_inf->header);
	total_decoded += decode_mac_addresses_detected_ie_t(buf + (total_decoded/CHAR_SIZE), &et_inf->mac_addresses_detected);
	total_decoded += decode_mac_addresses_removed_ie_t(buf + (total_decoded/CHAR_SIZE),  &et_inf->mac_addresses_removed);

	return total_decoded;

}


/**
 * decodes mac addresses detected ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     mac addresses detected ie
 * @return
 *   number of decoded bytes.
 */
int decode_mac_addresses_detected_ie_t(uint8_t *buf,
		mac_addresses_detected_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->number_of_mac_addresses = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->mac_address_value_1, buf + (total_decoded/CHAR_SIZE), MAC_ADDRESS_VALUE_1_LEN);
	total_decoded +=  MAC_ADDRESS_VALUE_1_LEN * CHAR_SIZE;

	return total_decoded;
}


/**
 * decodes mac addresses removed ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     mac addresses removed ie
 * @return
 *   number of decoded bytes.
 */
int decode_mac_addresses_removed_ie_t(uint8_t *buf,
		mac_addresses_removed_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->number_of_mac_addresses = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	memcpy(&value->mac_address_value_1, buf + (total_decoded/CHAR_SIZE), MAC_ADDRESS_VALUE_1_LEN);
	total_decoded +=  MAC_ADDRESS_VALUE_1_LEN * CHAR_SIZE;
	return total_decoded;
}


/**
 * Decodes session report response update bar to buffer.
 * @param srru_bar
 *     session report response update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_session_report_response_update_bar_ie_t(uint8_t *buf,
		session_report_response_update_bar_ie_t *srru_bar)
{

	uint16_t total_decoded = 0;

	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->header);
	total_decoded += decode_bar_id_ie_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->bar_id);
	total_decoded += decode_downlink_data_notification_delay_ie_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->downlink_data_notification_delay);
	total_decoded += decode_dl_buffering_duration_ie_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->dl_buffering_duration);
	total_decoded += decode_dl_buffering_suggested_packet_count_ie_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->dl_buffering_suggested_packet_count);
	total_decoded += decode_suggested_buffering_packets_count_ie_t(buf + (total_decoded/CHAR_SIZE), &srru_bar->suggested_buffering_packets_count);

	return total_decoded;
}


/**
 * decodes downlink data notification delay ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     downlink data notification delay ie
 * @return
 *   number of decoded bytes.
 */
int decode_downlink_data_notification_delay_ie_t(uint8_t *buf,
		downlink_data_notification_delay_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->delay_value_in_integer_multiples_of_50_millisecs_or_zero = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes dl buffering duration ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     dl buffering duration ie
 * @return
 *   number of decoded bytes.
 */
int decode_dl_buffering_duration_ie_t(uint8_t *buf,
		dl_buffering_duration_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes dl buffering suggested packet count ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     dl buffering suggested packet count ie
 * @return
 *   number of decoded bytes.
 */
int decode_dl_buffering_suggested_packet_count_ie_t(uint8_t *buf,
		dl_buffering_suggested_packet_count_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	memcpy(&value->packet_count_value, buf + (total_decoded/CHAR_SIZE), PACKET_COUNT_VALUE_LEN);
	total_decoded +=  PACKET_COUNT_VALUE_LEN * CHAR_SIZE;
	return total_decoded;
}



/**
 * decodes suggested buffering packets count ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     suggested buffering packets count ie
 * @return
 *   number of decoded bytes.
 */
int decode_suggested_buffering_packets_count_ie_t(uint8_t *buf,
		suggested_buffering_packets_count_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->packet_count_value = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded;
}


/**
 * decodes pfcpsrrsp flags ie to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pfcpsrrsp flags ie
 * @return
 *   number of decoded bytes.
 */
int decode_pfcpsrrsp_flags_ie_t(uint8_t *buf,
		pfcpsrrsp_flags_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	uint16_t decoded = 0;
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->spare7 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->drobu = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * Decodes create pdr ie to buffer.
 * @param cpi
 *     create pdr ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_create_pdr_ie_t(uint8_t *buf,
	create_pdr_ie_t *cpi)
{
       	uint16_t total_decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&cpi->header);
	total_decoded += decode_pdr_id_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->pdr_id);

        total_decoded += decode_precedence_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->precedence);
        total_decoded += decode_pdi_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->pdi);
        total_decoded += decode_outer_header_removal_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->outer_header_removal);
        total_decoded += decode_far_id_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->far_id);
        total_decoded += decode_urr_id_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->urr_id);

        total_decoded += decode_qer_id_ie_t(buf + (total_decoded/CHAR_SIZE),&(cpi->qer_id));
        total_decoded += decode_activate_predefined_rules_ie_t(buf + (total_decoded/CHAR_SIZE),&cpi->activate_predefined_rules);

        return total_decoded/CHAR_SIZE;

}


/**
 * decodes outer header removal to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     outer header removal
 * @return
 *   number of decoded bytes.
 */
int decode_outer_header_removal_ie_t(uint8_t *buf,
	outer_header_removal_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	value->outer_header_removal_description = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;
	return total_decoded; //CHAR_SIZE;
}


/**
 * decodes far id to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     far id
 * @return
 *   number of decoded bytes.
 */

int decode_far_id_ie_t(uint8_t *buf,
	far_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	value->far_id_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded; //CHAR_SIZE;
}


/**
 * decodes precedence to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     precedence
 * @return
 *   number of decoded bytes.
 */
int decode_precedence_ie_t(uint8_t *buf,
	precedence_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	value->precedence_value = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded; //CHAR_SIZE;
}



/**
 * Decodes pdi ie to buffer.
 * @param pi
 *     pdi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pdi_ie_t(uint8_t *buf,
	pdi_ie_t *pi)
{

	uint16_t total_decoded = 0;
        total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&pi->header);
        total_decoded += decode_source_interface_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->source_interface);
        total_decoded += decode_f_teid_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->local_fteid);
        total_decoded += decode_network_instance_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->network_instance);
        total_decoded += decode_ue_ip_address_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->ue_ip_address);
        total_decoded += decode_traffic_endpoint_id_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->traffic_endpoint_id);
        total_decoded += decode_application_id_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->application_id);
        total_decoded += decode_ethernet_pdu_session_information_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->ethernet_pdu_session_information);
        total_decoded += decode_framed_routing_ie_t(buf + (total_decoded/CHAR_SIZE),&pi->framedrouting);
	
        return total_decoded; //CHAR_SIZE;
}



/**
 * decodes source interface to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     source interface
 * @return
 *   number of decoded bytes.
 */
int decode_source_interface_ie_t(uint8_t *buf,
	source_interface_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	value->spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->interface_value = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	return total_decoded;
}

/**
 * decodes activate predefined rules to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     activate predefined rules
 * @return
 *   number of decoded bytes.
 */
int decode_activate_predefined_rules_ie_t(uint8_t *buf,
	activate_predefined_rules_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);

	memcpy(&value->predefined_rules_name, buf + (total_decoded/CHAR_SIZE), 8);

//	memcpy(value->predefined_rules_name = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded + (8 * CHAR_SIZE);
	return total_decoded;
}

/**
 * decodes user plane ip resource information to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     user plane ip resource information
 * @return
 *   number of decoded bytes.
 */
int decode_user_plane_ip_resource_information_ie_t(uint8_t *buf,
	user_plane_ip_resource_information_ie_t *value)
{
	uint16_t total_decoded = 0;
	uint16_t decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE),&value->header);
	value->spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->assosi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->assoni = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->teidri = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	if(value->teidri == 1) {
		value->teid_range = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	if(value->v4 == 1){
		value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
		total_decoded += decoded;
	}
	else {
		value->ipv6_address = decode_bits(buf, total_decoded, 128, &decoded);
		total_decoded += decoded;
	}
	if(value->assoni == 1) {
		value->network_instance = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}
	value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	if(value->assosi == 1) {
		value->source_interface = decode_bits(buf, total_decoded, 4, &decoded);
		total_decoded += decoded;
	}
	return total_decoded/CHAR_SIZE;
}
