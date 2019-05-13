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

#include "pfcp_ies.h"

#define MBR_BUF_SIZE 5
/**
 * Encodes ie header to buffer.
 * @param value
 *     ie header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_ie_header_t(pfcp_ie_header_t *value,
	uint8_t *buf);

/*
* encode cause ie to buffer.
 * @param value
 *     cause ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
	*/
int encode_cause_ie_t(pfcp_cause_ie_t *value,
		uint8_t *buf);

/*
*Encodes pfcp_header_t header to buffer.
 * @param value
 *     pfcp_header_t header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_header_t(pfcp_header_t *value,
	uint8_t *buf);


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
	uint8_t *buf);

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
	uint8_t *buf);

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
	uint8_t *buf);

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
	uint8_t *buf);

/**
 * Encodes pfcp_cause_ie_t ie to buffer.
 * @param value
 *     cause ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_cause_ie_t(pfcp_cause_ie_t *value,
	uint8_t *buf);

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
	uint8_t *buf);

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
	uint8_t *buf);


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
	uint8_t *buf);

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
	uint8_t *buf);


/**
 * Encodes create bar to buffer.
 * @param c_bar
 *     create bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_create_bar_ie_t(create_bar_ie_t *c_bar,
	uint8_t *msg);


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
		uint8_t *buf);

/**
 * Encodes user plane inactivityimer ie to buffer.
 * @param value
 *     user plane inactivityimer ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_user_plane_inactivity_timer_ie_t(user_plane_inactivity_timer_ie_t *value,
		uint8_t *buf);


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
		uint8_t *buf);


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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);


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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);


/**
 * Encodes overload control information to buffer.
 * @param oc_inf
 *     overload control information
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_overload_control_information_ie_t(overload_control_information_ie_t *oc_inf,
		uint8_t *msg);

/**
 * Encodes load control information to buffer.
 * @param lc_inf
 * 		load control information
 * @param buf
 *     buffer to store encoded values.
 *  @return
 *     number of encoded bytes.
 */
int encode_load_control_information_ie_t(load_control_information_ie_t *lc_inf,
		uint8_t *msg);

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
		uint8_t *buf);
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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);

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
		uint8_t *buf);


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
		uint8_t *buf);

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
		uint8_t *buf);
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
		uint8_t *buf);

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
		uint8_t *buf);

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
        uint8_t *buf);

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
        uint8_t *buf);
		
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
        uint8_t *buf);

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
        uint8_t *buf);


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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);
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
        uint8_t *buf);

int
encode_mbr_bits(uint64_t *val, uint8_t *buf);

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
	uint8_t *buf);

/**
 * Encodes far id to buffer.
 * @param value
 *     far id
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_far_id_t(far_id_ie_t *value,
	uint8_t *buf);

/**
 * Encodes precedence to buffer.
 * @param value
 *     precedence
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_precedence_t(precedence_ie_t *value,
	uint8_t *buf);

/**
 * Encodes pdi ie to buffer.
 * @param value
 *     pdi ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pdi_ie(pdi_ie_t *value,
	uint8_t *buf);
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
	uint8_t *buf);
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
	uint8_t *buf);
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
	uint8_t *buf);

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
		uint8_t *buf);
