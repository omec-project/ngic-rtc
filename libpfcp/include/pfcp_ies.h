/*
 * Copyright (c) 2003_2018, Great Software Laboratory Pvt. Ltd.
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE_2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef PFCP_IES_H
#define PFCP_IES_H

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>


#define CHAR_SIZE 8

//IE TYPE

//#define IE_PFCP_IMSI                               (01)
#define IE_CREATED_PDR                             (8)
#define IE_CREATE_PDR                             (1)
#define IE_CAUSE_ID                                (19)
#define IE_OFFENDING_IE                            (40)
#define IE_UP_FUNCTION_FEATURES                    (43)
#define IE_DOWNLINK_DATA_NOTIFICATION_DELAY        (46)
#define IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT     (48)
#define IE_LOAD_CONTROL_INFORMATION                (51)
#define IE_SEQUENCE_NUMBER                         (52)
#define IE_METRIC                                  (53)
#define IE_OVERLOAD_CONTROL_INFORMATION            (54)
#define IE_TIMER                                   (55)
#define IE_F_SEID                                  (57)
#define IE_NODE_ID                                 (60)
#define IE_PFCP_FQ_CSID                            (65)
#define IE_PFCP_IMEI                               (75)
#define IE_PFCP_MSISDN                             (76)
#define IE_CREATE_BAR                              (85)
#define IE_UPDATE_BAR                              (86)
#define IE_REMOVE_BAR                              (87)
#define IE_BAR_ID                                  (88)
#define IE_CP_FUNCTION_FEATURES                    (89)
#define IE_RECOVERY_TIME_STAMP                     (96)
#define IE_OCI_FLAGS                               (110)
#define IE_PFCP_PDN_TYPE                           (113)
#define IE_FAILED_RULE_ID                          (114)
#define IE_USER_PLANE_INACTIVITY_TIMER             (117)
#define IE_USER_ID                                 (141)
#define IE_PFCP_TRACE_INFORMATION                  (152)
#define IE_TRAFFIC_ENDPOINT_ID                     (131)
#define IE_REMOVE_TRAFFIC_ENDPOINT                 (130)
#define IE_CREATE_TRAFFIC_ENDPOINT                 (127)
#define IE_UPDATE_TRAFFIC_ENDPOINT                 (129)
#define IE_FRAMED_ROUTING                          (154)
#define IE_RQI                                     (123)
#define IE_QFI                                     (124)
#define IE_QER_ID                                  (109)
#define IE_DL_FLOW_LEVEL_MARKING                   (97)
#define IE_UE_IP_ADDRESS                           (93)
#define IE_PFCPSMREQ_FLAGS                         (49)
#define IE_MBR                                     (26)
#define IE_GBR                                     (27)
#define IE_UPDATE_QER                              (14)
#define IE_QER_CORRELATION_ID                      (28)
#define IE_F_TEID                                  (21)
#define IE_NETWORK_INSTANCE                        (22)
#define IE_PDR_ID                                  (56)
#define IE_USAGE_REPORT_TRIGGER                    (63)
#define IE_ETHERNET_PDU_SESSION_INFORMATION        (142)
#define IE_GATE_STATUS                             (25)
#define IE_PACKET_RATE                             (94)
#define IE_QUERY_URR_REFERENCE                     (125)
#define IE_ADDITIONAL_USAGE_REPORTS_INFORMATION    (126)
#define IE_PFCP_ASSOCIATION_RELEASE_REQUEST        (111)
#define IE_GRACEFUL_RELEASE_PERIOD                 (112)
#define IE_NODE_REPORT_TYPE                        (101)
#define IE_USER_PLANE_PATH_FAILURE_REPORT          (102)
#define IE_REMOTE_GTP_U_PEER                       (103)
#define IE_DOWNLINK_DATA_REPORT			   (83)
#define IE_SESSION_REPORT_USAGE_REPORT             (80)
#define IE_ERROR_INDICATION_REPORT                 (99)
#define IE_REPORT_TYPE				   (39)
#define IE_PFCPSRRSP_FLAGS		           (50)
#define IE_SESSION_REPORT_RESPONSE_UPDATE_BAR      (12)
#define IE_PRECEDENCE	(29)
#define IE_PDI   (2)
#define IE_OUTER_HEADER_REMOVAL	(95)
#define IE_FAR_ID	(108)
#define IE_URR_ID	(81)
#define IE_ACTIVATE_PREDEFINED_RULES	(106)
#define IE_SOURCE_INTERFACE	(20)
#define IE_APPLICATION_ID	(24)
#define IE_ETHERNET_PDU_SESSION_INFORMATION	(142)
#define IE_ETHERNET_FILTER_PROPERTIES	(139)
#define IE_UP_IP_RESOURCE_INFORMATION (116)
//IE LENGTH
#define NODE_ID_VALUE_LEN                           (256)
#define IP_ADDRESS_OF_TRACE_COLLECTION_ENTITY_LEN   (8)
#define LIST_OF_INTERFACES_LEN                      (8)
#define TRIGGERING_EVENTS_LEN                       (8)
#define IMSI_LEN                                    (8)
#define IMEI_LEN                                    (8)
#define MSISDN_LEN                                  (8)
#define NAI_LEN                                     (8)
#define PDN_CONNECTION_SET_IDENTIFIER_LEN           (8)
#define RULE_ID_VALUE_LEN                           (8)
#define NETWORK_INSTANCE_LEN                        (8)
#define FRAMED_ROUTING_LEN                          (8)
#define MAC_ADDRESS_VALUE_1_LEN                     (8)
#define APPLICATION_INSTANCE_IDENTIFIER_LEN         (8)
#define FLOW_DESCRIPTION_LEN                        (8)
#define APPLICATION_IDENTIFIER_LEN                  (8)

#define MAC_ADDRESS_VALUE_1_LEN                     (8)
#define APPLICATION_INSTANCE_IDENTIFIER_LEN         (8)
#define FLOW_DESCRIPTION_LEN                        (8)
#define PACKET_COUNT_VALUE_LEN                      (8)
#define PREDEFINED_RULES_NAME_LEN          	    (8)
//UP_FUNCTION_FEATURES
#define UP_BUCP  0x01 /*0b0000000000000001 DL Data Buffering in CPF is supported by the UP function*/
#define UP_DDND  0x02 /*0b0000000000000010 The buffering parameter 'DL Data Notification Delay'is supported by the UPF*/
#define UP_DLBD  0x03 /*0b0000000000000100 The buffering parameter 'DL Buffering Duration' is supported by the UPF */
#define UP_TRST  0x04 /*0b0000000000001000 Traffic Steering is supported by the UPF*/
#define UP_FTUP  0x05 /*0b0000000000010000 F-TEID allocation/release in the UPF is supported by the UPF*/
#define UP_PFDM  0x06 /*0b0000000000100000 The PFD Management procedure is supported by the UPF*/
#define UP_HEEU  0x07 /*0b0000000001000000 Header Enrichment of UL traffic is supported by the UPF*/
#define UP_TREU  0x08 /*0b0000000010000000 Traffic Redirection Enforcement in the UPF is supported by the UPF*/
#define UP_EMPU  0x09 /*0b0000000100000000 Sending of End Marker packets supported by the UPF*/
#define UP_PDIU  0x0A /*0b0000001000000000 Support of PDI optimised signalling in UPF*/
#define UP_UDBC  0x0B /*0b0000010000000000 Support of UL/DL Buffering Control*/
#define UP_QUOAC 0x0C /*0b0000100000000000 UPF supports being provisioned with the Quota Action to apply when reaching quotas*/
#define UP_TRACE 0x0D /*0b0001000000000000 UPF supports trace*/
#define UP_FRRT  0x0E /*0b0010000000000000 The UPFsupports Framed Routing*/

//CP_FUNCTION_FEATURES
#define CP_LOAD  0x01 /*0b00000001 Load Control is supported by the CPF*/
#define CP_OVRL  0x02 /*0b00000010 Overload control is supported by the CPF*/

//IE SIZE FOR CAUSE CHECK

#define NODE_ID_IPV4_LEN		5
#define NODE_ID_IPV6_LEN             	9
#define RECOV_TIMESTAMP_LEN          	4
#define CP_FUNC_FEATURES_LEN         	1
#define CP_FSEID_LEN                 	13
#define PGWC_FQCSID_LEN              	7
#define SGWC_FQCSID_LEN  		7
#define MME_FQCSID_LEN   		7
#define EPDG_FQCSID_LEN  		7
#define TWAN_FQCSID_LEN  		7
#define REMOVE_TRAFFIC_ENDPOINT_LEN  	5
#define CREATE_TRAFFIC_ENDPOINT_LEN  	57
#define UPDATE_TRAFFIC_ENDPOINT_LEN  	52
#define CREATE_BAR_LEN  		15
#define UPDATE_QER_LEN  		79  
#define UPDATE_BAR_LEN  		15
#define PFCP_SEMREQ_FLAG_LEN  		1
#define QUERY_URR_REFERENCE_LEN  	4
#define USER_PLANE_INACTIV_TIMER_LEN 	4
#define DELETE_SESSION_HEADER_LEN 	12

enum cause_values {
	CAUSE_VALUES_RESERVED =0,
	CAUSE_VALUES_REQUESTACCEPTEDSUCCESS =1,
	CAUSE_VALUES_REQUESTREJECTEDREASONNOTSPECIFIED = 64,
	CAUSE_VALUES_SESSIONCONTEXTNOTFOUND =65,
	CAUSE_VALUES_MANDATORYIEMISSING =66,
	CAUSE_VALUES_CONDITIONALIEMISSING =67,
	CAUSE_VALUES_INVALIDLENGTH =68,
	CAUSE_VALUES_MANDATORYIEINCORRECT =69,
	CAUSE_VALUES_INVALIDFORWARDINGPOLICY =70,
	CAUSE_VALUES_INVALIDF_TEIDALLOCATIONOPTION =71,
	CAUSE_VALUES_NOESTABLISHEDPFCPASSOCIATION =72,
	CAUSE_VALUES_RULECREATIONMODIFICATIONFAILURE =73,
	CAUSE_VALUES_PFCPENTITYINCONGESTION =74,
	CAUSE_VALUES_NORESOURCESAVAILABLE =75,
	CAUSE_VALUES_SERVICENOTSUPPORTED =76,
	CAUSE_VALUES_SYSTEMFAILURE =77,
};

enum node_id_type {
	NODE_ID_TYPE_IPV4ADDRESS =0,
	NODE_ID_TYPE_IPV6ADDRESS =1,
	NODE_ID_TYPE_FQDN =2,
};

enum fq_csid_node_id_type{
	IPV4_GLOBAL_UNICAST =0,
	IPV6_GLOBAL_UNICAST =1,
	MCC_MNC =2,

};

enum pdn_type {
	PFCP_PDN_TYPE_IPV4 =1,
	PFCP_PDN_TYPE_IPV6 =2,
	PFCP_PDN_TYPE_IPV4V6 =3,
	PFCP_PDN_TYPE_NON_IP =4,
	PFCP_PDN_TYPE_ETHERNET =5,
};

#pragma pack(1)

typedef struct pfcp_ie_header_t {
	uint16_t type;
	uint16_t len;
} pfcp_ie_header_t;


typedef struct pfcp_header_t {
	uint8_t s :1;
	uint8_t mp :1;
	uint8_t spare :3;
	uint8_t version :3;
	uint8_t message_type;
	uint16_t message_len;

	union seid_seqno {
		struct has_seid {
			uint64_t seid;
			uint32_t seq_no :24;
			uint8_t message_prio :4;
			uint8_t spare :4;
		} has_seid;
		struct no_seid {
			uint32_t seq_no :24;
			uint8_t spare :8;
		} no_seid;
	} seid_seqno;

} pfcp_header_t;

typedef struct node_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t node_id_type :4;
	uint8_t node_id_value_len;
	uint8_t node_id_value[NODE_ID_VALUE_LEN];
} node_id_ie_t;

typedef struct recovery_time_stamp_ie_t {
	pfcp_ie_header_t header;
	uint32_t recovery_time_stamp_value;
} recovery_time_stamp_ie_t;

typedef struct up_function_features_ie_t {
	pfcp_ie_header_t header;
	uint16_t supported_features;
} up_function_features_ie_t;

typedef struct cp_function_features_ie_t {
	pfcp_ie_header_t header;
	uint8_t supported_features;
} cp_function_features_ie_t;

typedef struct pfcp_cause_ie_t {
	pfcp_ie_header_t header;
	uint8_t cause_value;
} pfcp_cause_ie_t;


typedef struct f_seid_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :1;
	uint8_t spare2 :1;
	uint8_t spare3 :1;
	uint8_t spare4 :1;
	uint8_t spare5 :1;
	uint8_t spare6 :1;
	uint8_t v4 :1;
	uint8_t v6 :1;
	uint64_t seid;
	uint32_t ipv4_address;
	uint64_t ipv6_address;
} f_seid_ie_t;


typedef struct bar_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t bar_id_value;
} bar_id_ie_t;


typedef struct downlink_data_notification_delay_ie_t {
	pfcp_ie_header_t header;
	uint8_t delay_value_in_integer_multiples_of_50_millisecs_or_zero;
} downlink_data_notification_delay_ie_t;

typedef struct suggested_buffering_packets_count_ie_t {
	pfcp_ie_header_t header;
	uint8_t packet_count_value;
} suggested_buffering_packets_count_ie_t;

typedef struct create_bar_ie_t {
	pfcp_ie_header_t header;
	bar_id_ie_t bar_id;
	downlink_data_notification_delay_ie_t downlink_data_notification_delay;
	suggested_buffering_packets_count_ie_t suggested_buffering_packets_count;
} create_bar_ie_t;

typedef union node_adddress_ie_t {
	uint32_t ipv4_address;
	uint64_t ipv6_address;
	uint32_t mcc:20;
	uint32_t mnc:12;

}node_address_ie_t;

typedef struct fq_csid_ie_t {
	pfcp_ie_header_t header;
	uint8_t fq_csid_node_id_type :4;
	uint8_t number_of_csids :4;
	node_address_ie_t  node_address;
	uint16_t pdn_connection_set_identifier[PDN_CONNECTION_SET_IDENTIFIER_LEN];
} fq_csid_ie_t;


typedef struct user_plane_inactivity_timer_ie_t {
	pfcp_ie_header_t header;
	uint32_t user_plane_inactivity_timer;
} user_plane_inactivity_timer_ie_t;

#if 0
typedef struct pfcp_imsi_ie_t{
	pfcp_ie_header_t header;
	uint8_t value[IMSI_LEN];
}pfcp_imsi_ie_t;

typedef struct pfcp_imei_ie_t{
	pfcp_ie_header_t header;
	uint8_t value[IMEI_LEN];
}pfcp_imei_ie_t;

typedef struct pfcp_msisdn_ie_t{
	pfcp_ie_header_t header;
	uint8_t value[MSISDN_LEN];
}pfcp_msisdn_ie_t;

#endif
typedef struct user_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t naif :1;
	uint8_t msisdnf :1;
	uint8_t imeif :1;
	uint8_t imsif :1;
	uint8_t length_of_imsi;
	uint8_t imsi[IMSI_LEN];
	//pfcp_imsi_ie_t imsi;
	uint8_t length_of_imei;
	uint8_t imei[IMEI_LEN];
	//pfcp_imei_ie_t imei;
	uint8_t length_of_msisdn;
	uint8_t msisdn[MSISDN_LEN];
	//pfcp_msisdn_ie_t msisdn;
	uint8_t length_of_nai;
	uint8_t nai[NAI_LEN];
} user_id_ie_t;

typedef struct trace_information_ie_t {
	pfcp_ie_header_t header;
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint32_t trace_id:24;
	uint32_t spare:8;
	uint8_t length_of_triggering_events;
	uint8_t triggering_events[TRIGGERING_EVENTS_LEN];
	uint8_t session_trace_depth;
	uint8_t length_of_list_of_interfaces;
	uint8_t list_of_interfaces[LIST_OF_INTERFACES_LEN];
	uint8_t length_of_ip_address_of_trace_collection_entity;
	uint32_t ip_address_of_trace_collection_entity[IP_ADDRESS_OF_TRACE_COLLECTION_ENTITY_LEN];
} trace_information_ie_t;

typedef struct pfcp_pdn_type_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :5;
	uint8_t pdn_type :3;
} pfcp_pdn_type_ie_t;

typedef struct offending_ie_ie_t {
	pfcp_ie_header_t header;
	uint16_t type_of_the_offending_ie;
} offending_ie_ie_t;

typedef struct failed_rule_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :3;
	uint8_t rule_id_type :5;
	uint8_t rule_id_value[RULE_ID_VALUE_LEN];
} failed_rule_id_ie_t;


typedef struct sequence_number_ie_t {
	pfcp_ie_header_t header;
	uint32_t sequence_number;
} sequence_number_ie_t;


enum rule_id_type {
	RULE_ID_TYPE_PDR =0,
	RULE_ID_TYPE_FAR =1,
	RULE_ID_TYPE_QER =2,
	RULE_ID_TYPE_URR =3,
	RULE_ID_TYPE_BAR =4,
};

typedef struct metric_ie_t {
	pfcp_ie_header_t header;
	uint8_t metric;
} metric_ie_t;


typedef struct timer_ie_t {
	pfcp_ie_header_t header;
	uint8_t timer_unit :3;
	uint8_t timer_value :5;
} timer_ie_t;


enum timer_information_element {
	TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS =0,
	TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_MINUTE =1,
	TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_MINUTES =2,
	TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR =3,
	TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_HOURS =4,
	TIMER_INFORMATIONLEMENT_VALUE_INDICATES_THAT_THE_TIMER_IS_INFINITE =7,
};

typedef struct oci_flags_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :7;
	uint8_t aoci :1;
} oci_flags_ie_t;


typedef struct load_control_information_ie_t {
	pfcp_ie_header_t header;
	sequence_number_ie_t load_control_sequence_number;
	metric_ie_t load_metric;
} load_control_information_ie_t;

typedef struct overload_control_information_ie_t {
	pfcp_ie_header_t header;
	sequence_number_ie_t overload_control_sequence_number;
	metric_ie_t overload_reduction_metric;
	timer_ie_t period_of_validity;
	oci_flags_ie_t overload_control_information_flags;
} overload_control_information_ie_t;

typedef struct remove_bar_ie_t {
	pfcp_ie_header_t header;
	bar_id_ie_t bar_id;
} remove_bar_ie_t;

typedef struct traffic_endpoint_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t traffic_endpoint_id_value;
} traffic_endpoint_id_ie_t;

typedef struct remove_traffic_endpoint_ie_t {
	pfcp_ie_header_t header;
	traffic_endpoint_id_ie_t traffic_endpoint_id;
} remove_traffic_endpoint_ie_t;

typedef struct f_teid_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t chid :1;
	uint8_t ch :1;
	uint8_t v6 :1;
	uint8_t v4 :1;
	uint32_t teid;
	uint32_t ipv4_address;
	uint64_t ipv6_address;
	uint8_t choose_id;
} f_teid_ie_t;

typedef struct network_instance_ie_t {
	pfcp_ie_header_t header;
	uint8_t network_instance[NETWORK_INSTANCE_LEN];
} network_instance_ie_t;

typedef struct ue_ip_address_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t ipv6d :1;
	uint8_t sd :1;
	uint8_t v4 :1;
	uint8_t v6 :1;
	uint32_t ipv4_address;
	uint64_t ipv6_address;
	uint8_t ipv6_prefix_delegation_bits;
} ue_ip_address_ie_t;

typedef struct ethernet_pdu_session_information_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :7;
	uint8_t ethi :1;
} ethernet_pdu_session_information_ie_t;

typedef struct framed_routing_ie_t {
	pfcp_ie_header_t header;
	uint8_t framed_routing[FRAMED_ROUTING_LEN];
} framed_routing_ie_t;


typedef struct qer_id_ie_t {
	pfcp_ie_header_t header;
	uint32_t qer_id_value;
} qer_id_ie_t;

typedef struct qer_correlation_id_ie_t {
	pfcp_ie_header_t header;
	uint32_t qer_correlation_id_value;
} qer_correlation_id_ie_t;


typedef struct gate_status_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t ul_gate :2;
	uint8_t dl_gate :2;
} gate_status_ie_t;


enum ul_gate {
	UL_GATE_OPEN =0,
	UL_GATE_CLOSED =1,
};

enum dl_gate {
	DL_GATE_OPEN =0,
	DL_GATE_CLOSED =1,
};

typedef struct mbr_ie_t {
	pfcp_ie_header_t header;
	uint64_t ul_mbr;
	uint64_t dl_mbr;
} mbr_ie_t;

typedef struct gbr_ie_t {
	pfcp_ie_header_t header;
	uint64_t ul_gbr;
	uint64_t dl_gbr;
} gbr_ie_t;


typedef struct packet_rate_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :6;
	uint8_t dlpr :1;
	uint8_t ulpr :1;
	uint8_t spare2 :5;
	uint8_t uplink_time_unit :3;
	uint16_t maximum_uplink_packet_rate;
	uint8_t spare3 :5;
	uint8_t downlink_time_unit :3;
	uint16_t maximum_downlink_packet_rate;
} packet_rate_ie_t;

enum uplinkdownlink_time_unit {
	UPLINKDOWNLINK_TIME_UNIT_MINUTE =0,
	UPLINKDOWNLINK_TIME_UNIT_6_MINUTES =1,
	UPLINKDOWNLINK_TIME_UNIT_HOUR =2,
	UPLINKDOWNLINK_TIME_UNIT_DAY =3,
	UPLINKDOWNLINK_TIME_UNIT_WEEK =4,
};

typedef struct dl_flow_level_marking_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :6;
	uint8_t sci :1;
	uint8_t ttc :1;
	uint16_t tostraffic_class;
	uint16_t service_class_indicator;
} dl_flow_level_marking_ie_t;

typedef struct rqi_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :7;
	uint8_t rqi :1;
} rqi_ie_t;

typedef struct qfi_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :2;
	uint8_t qfi_value :6;
} qfi_ie_t;



typedef struct pfcpsmreq_flags_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :1;
	uint8_t spare2 :1;
	uint8_t spare3 :1;
	uint8_t spare4 :1;
	uint8_t spare5 :1;
	uint8_t qaurr :1;
	uint8_t sndem :1;
	uint8_t drobu :1;
} pfcpsmreq_flags_ie_t;

typedef struct query_urr_reference_ie_t {
	pfcp_ie_header_t header;
	uint32_t query_urr_reference_value;
} query_urr_reference_ie_t;

typedef struct update_qer_ie_t {
	pfcp_ie_header_t header;
	qer_id_ie_t qer_id;
	qer_correlation_id_ie_t qer_correlation_id;
	gate_status_ie_t gate_status;
	mbr_ie_t maximum_bitrate;
	gbr_ie_t guaranteed_bitrate;
	packet_rate_ie_t packet_rate;
	dl_flow_level_marking_ie_t dl_flow_level_marking;
	qfi_ie_t qos_flow_identifier;
	rqi_ie_t reflective_qos;
} update_qer_ie_t;

typedef struct update_bar_ie_t {
	pfcp_ie_header_t header;
	bar_id_ie_t bar_id;
	downlink_data_notification_delay_ie_t downlink_data_notification_delay;
	suggested_buffering_packets_count_ie_t suggested_buffering_packets_count;
} update_bar_ie_t;

typedef struct update_traffic_endpoint_ie_t {
	pfcp_ie_header_t header;
	traffic_endpoint_id_ie_t traffic_endpoint_id;
	f_teid_ie_t local_fteid;
	network_instance_ie_t network_instance;
	ue_ip_address_ie_t ue_ip_address;
	framed_routing_ie_t framedrouting;
} update_traffic_endpoint_ie_t;

typedef struct create_traffic_endpoint_ie_t {
	pfcp_ie_header_t header;
	traffic_endpoint_id_ie_t traffic_endpoint_id;
	f_teid_ie_t local_fteid;
	network_instance_ie_t network_instance;
	ue_ip_address_ie_t ue_ip_address;
	ethernet_pdu_session_information_ie_t ethernet_pdu_session_information;
	framed_routing_ie_t framedrouting;
} create_traffic_endpoint_ie_t;


typedef struct pdr_id_ie_t {
	pfcp_ie_header_t header;
	uint16_t rule_id;
} pdr_id_ie_t;

typedef struct additional_usage_reports_information_ie_t {
	pfcp_ie_header_t header;
	uint16_t auri :1;
	uint16_t number_of_additional_usage_reports_value :15;
} additional_usage_reports_information_ie_t;

typedef struct created_traffic_endpoint_ie_t {
	pfcp_ie_header_t header;
	traffic_endpoint_id_ie_t traffic_endpoint_id;
	f_teid_ie_t local_fteid;
} created_traffic_endpoint_ie_t;

typedef struct created_pdr_ie_t {
	pfcp_ie_header_t header;
	pdr_id_ie_t pdr_id;
	f_teid_ie_t local_fteid;
} created_pdr_ie_t;

typedef struct pfcp_association_release_request_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :7;
	uint8_t sarr :1;
} pfcp_association_release_request_ie_t;

typedef struct graceful_release_period_ie_t {
	pfcp_ie_header_t header;
	uint8_t timer_unit :3;
	uint8_t timer_value :5;
} graceful_release_period_ie_t;

enum graceful_release_period_information_element {
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS =0,
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_MINUTE =1,
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_MINUTES =2,
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_1_HOUR =3,
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_10_HOURS =4,
	GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_INDICATES_THAT_THE_TIMER_IS_INFINITE =7,
};


typedef struct remote_gtp_u_peer_ie_t {
        pfcp_ie_header_t header;
        uint8_t spare :6;
        uint8_t v4 :1;
        uint8_t v6 :1;
        uint32_t ipv4_address;
        uint64_t ipv6_address;
} remote_gtp_u_peer_ie_t;

typedef struct node_report_type_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :7;
	uint8_t upfr :1;
} node_report_type_ie_t;

typedef struct user_plane_path_failure_report_ie_t {
        pfcp_ie_header_t header;
        remote_gtp_u_peer_ie_t remote_gtpu_peer;
} user_plane_path_failure_report_ie_t;



typedef struct volume_measurement_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t spare :5;
   	uint8_t dlvol :1;
    	uint8_t ulvol :1;
    	uint8_t tovol :1;
    	uint64_t total_volume;
    	uint64_t uplink_volume;
    	uint64_t downlink_volume;
} volume_measurement_ie_t;

typedef struct duration_measurement_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t duration_value;
} duration_measurement_ie_t;

typedef struct urr_id_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t urr_id_value;
} urr_id_ie_t;

typedef struct ur_seqn_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t ur_seqn;
} ur_seqn_ie_t;

typedef struct usage_report_trigger_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t immer :1;
    	uint8_t droth :1;
    	uint8_t stopt :1;
    	uint8_t start :1;
    	uint8_t quhti :1;
    	uint8_t timth :1;
    	uint8_t volth :1;
    	uint8_t perio :1;
    	uint8_t eveth :1;
    	uint8_t macar :1;
    	uint8_t envcl :1;
    	uint8_t monit :1;
    	uint8_t termr :1;
	uint8_t liusa :1;
	uint8_t timqu :1;
    	uint8_t volqu :1;
} usage_report_trigger_ie_t;



typedef struct start_time_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t start_time;
} start_time_ie_t;

typedef struct end_time_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t end_time;
} end_time_ie_t;

typedef struct time_of_first_packet_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t time_of_first_packet;
} time_of_first_packet_ie_t;

typedef struct time_of_last_packet_ie_t {
    	pfcp_ie_header_t header;
    	uint32_t time_of_last_packet;
} time_of_last_packet_ie_t;

typedef struct usage_information_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t spare :5;
    	uint8_t ube :1;
    	uint8_t uae :1;
    	uint8_t aft :1;
    	uint8_t bef :1;
} usage_information_ie_t;

typedef struct mac_addresses_detected_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t number_of_mac_addresses;
    	uint64_t mac_address_value_1[MAC_ADDRESS_VALUE_1_LEN];
} mac_addresses_detected_ie_t;

typedef struct mac_addresses_removed_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t number_of_mac_addresses;
    	uint64_t mac_address_value_1[MAC_ADDRESS_VALUE_1_LEN];
} mac_addresses_removed_ie_t;


typedef struct application_id_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t application_identifier[APPLICATION_IDENTIFIER_LEN];
} application_id_ie_t;

typedef struct application_instance_id_ie_t {
    	pfcp_ie_header_t header;
    	uint8_t application_instance_identifier[APPLICATION_INSTANCE_IDENTIFIER_LEN];
} application_instance_id_ie_t;

typedef struct flow_information_ie_t {
        pfcp_ie_header_t header;
        uint8_t spare :5;
        uint8_t flow_direction :3;
        uint16_t length_of_flow_description;
        uint8_t flow_description[FLOW_DESCRIPTION_LEN];
} flow_information_ie_t;


typedef struct ethernet_traffic_information_ie_t {
    	pfcp_ie_header_t header;
    	mac_addresses_detected_ie_t mac_addresses_detected;
   	mac_addresses_removed_ie_t mac_addresses_removed;
} ethernet_traffic_information_ie_t;

typedef struct application_detection_information_ie_t {
    	pfcp_ie_header_t header;
    	application_id_ie_t application_id;
    	application_instance_id_ie_t application_instance_id;
    	flow_information_ie_t flow_information;
} application_detection_information_ie_t;


typedef struct report_type_ie_t {
    pfcp_ie_header_t header;
    uint8_t spare :4;
    uint8_t upir :1;
    uint8_t erir :1;
    uint8_t usar :1;
    uint8_t dldr :1;
} report_type_ie_t;


typedef struct session_report_usage_report_ie_t {
    pfcp_ie_header_t header;
    urr_id_ie_t urr_id;
    ur_seqn_ie_t urseqn;
    usage_report_trigger_ie_t usage_report_trigger;
    start_time_ie_t start_time;
    end_time_ie_t end_time;
    volume_measurement_ie_t volume_measurement;
    duration_measurement_ie_t duration_measurement;
    application_detection_information_ie_t application_detection_information;
    ue_ip_address_ie_t ue_ip_address;
    network_instance_ie_t network_instance;
    time_of_first_packet_ie_t time_of_first_packet;
    time_of_last_packet_ie_t time_of_last_packet;
    usage_information_ie_t usage_information;
    query_urr_reference_ie_t query_urr_reference;
    ethernet_traffic_information_ie_t ethernet_traffic_information;
} session_report_usage_report_ie_t;

typedef struct downlink_data_service_information_ie_t {
    pfcp_ie_header_t header;
    uint8_t spare2 :6;
    uint8_t qfii :1;
    uint8_t ppi :1;
    uint8_t spare3 :2;
    uint8_t paging_policy_indication_value :6;
    uint8_t spare4 :2;
} downlink_data_service_information_ie_t;

typedef struct dl_buffering_suggested_packet_count_ie_t {
    pfcp_ie_header_t header;
    uint8_t packet_count_value[PACKET_COUNT_VALUE_LEN];
} dl_buffering_suggested_packet_count_ie_t;



typedef struct downlink_data_report_ie_t {
    pfcp_ie_header_t header;
    downlink_data_service_information_ie_t downlink_data_service_information;
} downlink_data_report_ie_t;


typedef struct error_indication_report_ie_t {
    pfcp_ie_header_t header;
    f_teid_ie_t remote_fteid;
} error_indication_report_ie_t;


typedef struct dl_buffering_duration_ie_t {
    pfcp_ie_header_t header;
    uint8_t timer_unit :3;
    uint8_t timer_value :5;
} dl_buffering_duration_ie_t;


typedef struct session_report_response_update_bar_ie_t {
    pfcp_ie_header_t header;
    bar_id_ie_t bar_id;
    downlink_data_notification_delay_ie_t downlink_data_notification_delay;
    dl_buffering_duration_ie_t dl_buffering_duration;
    dl_buffering_suggested_packet_count_ie_t dl_buffering_suggested_packet_count;
    suggested_buffering_packets_count_ie_t suggested_buffering_packets_count;
} session_report_response_update_bar_ie_t;

typedef struct pfcpsrrsp_flags_ie_t {
    pfcp_ie_header_t header;
    uint8_t spare :1;
    uint8_t spare2 :1;
    uint8_t spare3 :1;
    uint8_t spare4 :1;
    uint8_t spare5 :1;
    uint8_t spare6 :1;
    uint8_t spare7 :1;
    uint8_t drobu :1;
} pfcpsrrsp_flags_ie_t;

typedef struct precedence_ie_t {
	pfcp_ie_header_t header;
	uint32_t precedence_value;
} precedence_ie_t;

typedef struct source_interface_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :4;
	uint8_t interface_value :4;
} source_interface_ie_t;

enum source_interface_value { 
	SOURCE_INTERFACE_VALUE_ACCESS =0,
	SOURCE_INTERFACE_VALUE_CORE =1,
	SOURCE_INTERFACE_VALUE_SGI_LAN_N6_LAN =2,
	SOURCE_INTERFACE_VALUE_CP_FUNCTION =3,
};

typedef struct pdi_ie_t {
	pfcp_ie_header_t header;
	source_interface_ie_t source_interface;
	f_teid_ie_t local_fteid;
	network_instance_ie_t network_instance;
	ue_ip_address_ie_t ue_ip_address;
	traffic_endpoint_id_ie_t traffic_endpoint_id;
	application_id_ie_t application_id;
	ethernet_pdu_session_information_ie_t ethernet_pdu_session_information;
	framed_routing_ie_t framedrouting;
} pdi_ie_t;

typedef struct outer_header_removal_ie_t {
	pfcp_ie_header_t header;
	uint8_t outer_header_removal_description;
} outer_header_removal_ie_t;

enum outer_header_removal_description { 
	OUTER_HEADER_REMOVAL_DESCRIPTION_GTP_U_UDP_IPV4 =0,
	OUTER_HEADER_REMOVAL_DESCRIPTION_GTP_U_UDP_IPV6 =1,
	OUTER_HEADER_REMOVAL_DESCRIPTION_UDP_IPV4 =2,
	OUTER_HEADER_REMOVAL_DESCRIPTION_UDP_IPV6 =3,
};

typedef struct far_id_ie_t {
	pfcp_ie_header_t header;
	uint32_t far_id_value;
} far_id_ie_t;

typedef struct activate_predefined_rules_ie_t {
	pfcp_ie_header_t header;
	uint8_t predefined_rules_name[PREDEFINED_RULES_NAME_LEN];
} activate_predefined_rules_ie_t;

typedef struct create_pdr_ie_t {
	pfcp_ie_header_t header;
	pdr_id_ie_t pdr_id;
	precedence_ie_t precedence;
	pdi_ie_t pdi;
	outer_header_removal_ie_t outer_header_removal;
	far_id_ie_t far_id;
	urr_id_ie_t urr_id;
	qer_id_ie_t qer_id;	
	activate_predefined_rules_ie_t activate_predefined_rules;
} create_pdr_ie_t;

typedef struct user_plane_ip_resource_information_ie_t {
	pfcp_ie_header_t header;
	uint8_t spare :1;
	uint8_t assosi :1;
	uint8_t assoni :1;
	uint8_t teidri :3;
	uint8_t v6 :1;
	uint8_t v4 :1;
	uint8_t teid_range;
	uint32_t ipv4_address;
	uint64_t ipv6_address;
	uint8_t network_instance;
	uint8_t spare2 :4;
	uint8_t source_interface :4;
} user_plane_ip_resource_information_ie_t;
#pragma pack()

#endif
