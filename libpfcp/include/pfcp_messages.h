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

#ifndef PFCP_GTPV2C_MESSAGE_H
#define PFCP_GTPV2C_MESSAGE_H

#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>



#include "pfcp_ies.h"

#define CHAR_SIZE 8

#pragma pack(1)

typedef struct pfcp_association_setup_request_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	recovery_time_stamp_ie_t recovery_time_stamp;
	up_function_features_ie_t up_function_features;
	cp_function_features_ie_t cp_function_features;
} pfcp_association_setup_request_t;

typedef struct pfcp_association_setup_response_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	pfcp_cause_ie_t cause;
	recovery_time_stamp_ie_t recovery_time_stamp;
	up_function_features_ie_t up_function_features;
	cp_function_features_ie_t cp_function_features;
	user_plane_ip_resource_information_ie_t up_ip_resource_info;
} pfcp_association_setup_response_t;

typedef struct pfcp_association_update_request_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	up_function_features_ie_t up_function_features;
	cp_function_features_ie_t cp_function_features;
	pfcp_association_release_request_ie_t pfcp_association_release_request;
	graceful_release_period_ie_t graceful_release_period;
} pfcp_association_update_request_t;

typedef struct pfcp_association_update_response_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	pfcp_cause_ie_t cause;
	up_function_features_ie_t up_function_features;
	cp_function_features_ie_t cp_function_features;
} pfcp_association_update_response_t;

typedef struct pfcp_session_establishment_request_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	f_seid_ie_t cp_fseid;
	create_pdr_ie_t create_pdr;	
	create_bar_ie_t create_bar;
	pfcp_pdn_type_ie_t pdn_type;
	fq_csid_ie_t sgwc_fqcsid;
	fq_csid_ie_t mme_fqcsid;
	fq_csid_ie_t pgwc_fqcsid;
	fq_csid_ie_t epdg_fqcsid;
	fq_csid_ie_t twan_fqcsid;
	user_plane_inactivity_timer_ie_t user_plane_inactivity_timer;
	user_id_ie_t user_id;
	trace_information_ie_t trace_information;
} pfcp_session_establishment_request_t;

typedef struct pfcp_session_establishment_response_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	pfcp_cause_ie_t cause;
	offending_ie_ie_t offending_ie;
	f_seid_ie_t up_fseid;
	created_pdr_ie_t created_pdr;
	load_control_information_ie_t load_control_information;
	overload_control_information_ie_t overload_control_information;
	fq_csid_ie_t sgwu_fqcsid;
	fq_csid_ie_t pgwu_fqcsid;
	failed_rule_id_ie_t failed_rule_id;
} pfcp_session_establishment_response_t;


typedef struct pfcp_session_modification_request_t {
	pfcp_header_t header;
	f_seid_ie_t cp_fseid;
	remove_bar_ie_t remove_bar;
	remove_traffic_endpoint_ie_t remove_traffic_endpoint;
	create_pdr_ie_t create_pdr;
	create_bar_ie_t create_bar;
	create_traffic_endpoint_ie_t create_traffic_endpoint;
	update_qer_ie_t update_qer;
	update_bar_ie_t update_bar;
	update_traffic_endpoint_ie_t update_traffic_endpoint;
	pfcpsmreq_flags_ie_t pfcpsmreqflags;
	fq_csid_ie_t pgwc_fqcsid;
	fq_csid_ie_t sgwc_fqcsid;
	fq_csid_ie_t mme_fqcsid;
	fq_csid_ie_t epdg_fqcsid;
	fq_csid_ie_t twan_fqcsid;
	user_plane_inactivity_timer_ie_t user_plane_inactivity_timer;
	query_urr_reference_ie_t query_urr_reference;
	trace_information_ie_t trace_information;
} pfcp_session_modification_request_t;

typedef struct pfcp_session_modification_response_t {
	pfcp_header_t header;
	pfcp_cause_ie_t cause;
	offending_ie_ie_t offending_ie;
	created_pdr_ie_t created_pdr;
	load_control_information_ie_t load_control_information;
	overload_control_information_ie_t overload_control_information;
	failed_rule_id_ie_t failed_rule_id;
	additional_usage_reports_information_ie_t additional_usage_reports_information;
	created_traffic_endpoint_ie_t createdupdated_traffic_endpoint;
} pfcp_session_modification_response_t;

typedef struct pfcp_session_set_deletion_request_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	fq_csid_ie_t sgwc_fqcsid;
	fq_csid_ie_t pgwc_fqcsid;
	fq_csid_ie_t sgwu_fqcsid;
	fq_csid_ie_t pgwu_fqcsid;
	fq_csid_ie_t twan_fqcsid;
	fq_csid_ie_t epdg_fqcsid;
	fq_csid_ie_t mme_fqcsid;
} pfcp_session_set_deletion_request_t;

typedef struct pfcp_session_set_deletion_response_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	pfcp_cause_ie_t cause;
	offending_ie_ie_t offending_ie;
} pfcp_session_set_deletion_response_t;

typedef struct pfcp_session_deletion_request_t {
	pfcp_header_t header;
} pfcp_session_deletion_request_t;

typedef struct pfcp_session_deletion_response_t {
	pfcp_header_t header;
	pfcp_cause_ie_t cause;
	offending_ie_ie_t offending_ie;
	load_control_information_ie_t load_control_information;
	overload_control_information_ie_t overload_control_information;
} pfcp_session_deletion_response_t;

typedef struct pfcp_association_release_request_t {
        pfcp_header_t header;
        node_id_ie_t node_id;
} pfcp_association_release_request_t;

typedef struct pfcp_association_release_response_t {
        pfcp_header_t header;
        node_id_ie_t node_id;
        pfcp_cause_ie_t cause;
} pfcp_association_release_response_t;

typedef struct pfcp_node_report_request_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	node_report_type_ie_t node_report_type;
	user_plane_path_failure_report_ie_t user_plane_path_failure_report;
} pfcp_node_report_request_t;

typedef struct pfcp_node_report_response_t {
	pfcp_header_t header;
	node_id_ie_t node_id;
	pfcp_cause_ie_t cause;
	offending_ie_ie_t offending_ie;
} pfcp_node_report_response_t;

typedef struct pfcp_heartbeat_request_t {
        pfcp_header_t header;
        recovery_time_stamp_ie_t recovery_time_stamp;
} pfcp_heartbeat_request_t;

typedef struct pfcp_heartbeat_response_t {
        pfcp_header_t header;
        recovery_time_stamp_ie_t recovery_time_stamp;
} pfcp_heartbeat_response_t;

typedef struct pfcp_session_report_request_t {
   	pfcp_header_t header;
    	report_type_ie_t report_type;
    	downlink_data_report_ie_t downlink_data_report;
    	session_report_usage_report_ie_t usage_report;
    	error_indication_report_ie_t error_indication_report;
	load_control_information_ie_t load_control_information;
    	overload_control_information_ie_t overload_control_information;
    	additional_usage_reports_information_ie_t additional_usage_reports_information;
} pfcp_session_report_request_t;


typedef struct pfcp_session_report_response_t {
    	pfcp_header_t header;
    	pfcp_cause_ie_t cause;
    	offending_ie_ie_t offending_ie;
    	session_report_response_update_bar_ie_t update_bar;
    	pfcpsrrsp_flags_ie_t sxsrrspflags;
} pfcp_session_report_response_t;



#pragma pack()

#endif
