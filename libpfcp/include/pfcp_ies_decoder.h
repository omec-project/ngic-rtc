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

#include "pfcp_ies.h"



int decode_pfcp_header_t(uint8_t *buf, pfcp_header_t *value);


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
	pfcp_ie_header_t *value);

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
	node_id_ie_t *value);

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
		    pfcp_cause_ie_t *value);
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
	recovery_time_stamp_ie_t *value);


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
	up_function_features_ie_t *value);


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
	cp_function_features_ie_t *value);
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
f_seid_ie_t *value);

/**
 * Decodes load control information to buffer.
 * @param lc_inf
 *     load control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_load_control_information_ie_t(uint8_t *msg,
load_control_information_ie_t *lc_inf);

/**
 * Decodes overload control information to buffer.
 * @param oc_inf
 *     overload control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_overload_control_information_ie_t(uint8_t *msg,
overload_control_information_ie_t *oc_inf);

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
offending_ie_ie_t *value);

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
fq_csid_ie_t *value);

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
failed_rule_id_ie_t *value);
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
    sequence_number_ie_t *value);

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
    metric_ie_t *value);

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
    timer_ie_t *value);

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
	oci_flags_ie_t *value);

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
	f_seid_ie_t *value);

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
	pfcp_pdn_type_ie_t *value);


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
	fq_csid_ie_t *value);


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
	user_plane_inactivity_timer_ie_t *value);


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
	user_id_ie_t *value);


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
	trace_information_ie_t *value);

int decode_create_bar_ie_t(uint8_t *buf,
		    create_bar_ie_t *value);
int
decode_suggested_buff_packet_count_ie_t(uint8_t *buf , suggested_buffering_packets_count_ie_t *value);

int
decode_dl_data_notification_delay_ie_t(uint8_t *buf ,downlink_data_notification_delay_ie_t *value);

int
decode_bar_id_ie_t(uint8_t *buf ,bar_id_ie_t *value);


int decode_create_traffic_endpoint_ie_t(uint8_t *msg,
	create_traffic_endpoint_ie_t *ct_end);

int decode_remove_bar_ie_t(uint8_t *msg,
	remove_bar_ie_t *r_bar);

int decode_remove_traffic_endpoint_ie_t(uint8_t *buf,
	remove_traffic_endpoint_ie_t *rt_end);

int decode_traffic_endpoint_id_ie_t(uint8_t *buf,
	traffic_endpoint_id_ie_t *value);

int decode_remove_bar_ie_t(uint8_t *buf,
	remove_bar_ie_t *r_bar);


int decode_f_teid_ie_t(uint8_t *buf,
	f_teid_ie_t *value);

int decode_network_instance_ie_t(uint8_t *buf,
	network_instance_ie_t *value);


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
	ue_ip_address_ie_t *value);


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
	ethernet_pdu_session_information_ie_t *value);

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
	framed_routing_ie_t *value);

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
	qer_id_ie_t *value);

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
	qer_correlation_id_ie_t *value);


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
	update_qer_ie_t *u_qer);



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
	gate_status_ie_t *value);



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
	mbr_ie_t *value);


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
	gbr_ie_t *value);


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
	packet_rate_ie_t *value);


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
	dl_flow_level_marking_ie_t *value);


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
	qfi_ie_t *value);


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
	rqi_ie_t *value);


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
	update_bar_ie_t *u_bar);


/**
 * Decodes updateraffic endpoint to buffer.
 * @param ut_end
 *     updateraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_update_traffic_endpoint_ie_t(uint8_t *msg,
	update_traffic_endpoint_ie_t *ut_end);



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
	pfcpsmreq_flags_ie_t *value);


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
	query_urr_reference_ie_t *value);

/**
 * Decodes created pdr to buffer.
 * @param c_pdr
 *     created pdr
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_created_pdr_ie_t(uint8_t *msg,
	created_pdr_ie_t *c_pdr);


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
	pdr_id_ie_t *value);

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
	additional_usage_reports_information_ie_t *value);


/**
 * Decodes createdraffic endpoint to buffer.
 * @param ct_end
 *     createdraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_created_traffic_endpoint_ie_(uint8_t *msg,
	created_traffic_endpoint_ie_t *ct_end);


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
	pfcp_association_release_request_ie_t *value);

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
	graceful_release_period_ie_t *value);

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
    remote_gtp_u_peer_ie_t *value);


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
    node_report_type_ie_t *value);


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
    user_plane_path_failure_report_ie_t *uppf_rep);


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
	node_report_type_ie_t *value);
	
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
                report_type_ie_t *value);

				
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
                session_report_usage_report_ie_t *s_repu_rep);
				
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
                error_indication_report_ie_t *ei_rep);
				
/**
 * Decodes downlink data report to buffer.
 * @param dd_rep
 *     downlink data report
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_downlink_data_report(uint8_t *buf,
                downlink_data_report_ie_t *dd_rep);


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
    urr_id_ie_t *value);
	
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
    usage_report_trigger_ie_t *value);

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
    volume_measurement_ie_t *value);
	

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
    duration_measurement_ie_t *value);

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
    time_of_first_packet_ie_t *value);


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
    time_of_last_packet_ie_t *value);

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
    usage_information_ie_t *value);


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
    downlink_data_service_information_ie_t *value);


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
    ur_seqn_ie_t *value);


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
    start_time_ie_t *value);


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
    end_time_ie_t *value);


/**
 * Decodes application detection information to buffer.
 * @param ad_inf
 *     application detection information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_application_detection_information_ie_t(uint8_t *msg,
    application_detection_information_ie_t *ad_inf);



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
		application_instance_id_ie_t *value);


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
		application_id_ie_t *value);




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
    	flow_information_ie_t *value);



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
            ethernet_traffic_information_ie_t *et_inf);


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
                mac_addresses_detected_ie_t *value);
				

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
                mac_addresses_removed_ie_t *value);



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
		downlink_data_report_ie_t *dd_rep);


/**
 * Decodes session report response update bar to buffer.
 * @param srru_bar
 *     session report response update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_session_report_response_update_bar_ie_t(uint8_t *msg,
		session_report_response_update_bar_ie_t *srru_bar);


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
		downlink_data_notification_delay_ie_t *value);




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
		dl_buffering_duration_ie_t *value);



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
		dl_buffering_suggested_packet_count_ie_t *value);


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
		suggested_buffering_packets_count_ie_t *value);


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
                pfcpsrrsp_flags_ie_t *value);

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
decode_mbr_bits(uint8_t *buf, uint64_t *val);


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
	outer_header_removal_ie_t *value);

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
	far_id_ie_t *value);


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
	precedence_ie_t *value);


int decode_create_pdr_ie_t(uint8_t *buf,
        create_pdr_ie_t *cpi);

/**
 * Decodes pdi ie to buffer.
 * @param pi
 *     pdi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_pdi_ie_t(uint8_t *msg,
        pdi_ie_t *pi);

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
        source_interface_ie_t *value);

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
	activate_predefined_rules_ie_t *value);


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
	user_plane_ip_resource_information_ie_t *value);
