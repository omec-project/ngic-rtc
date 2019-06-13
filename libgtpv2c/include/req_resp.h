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

#ifndef __LIBGTPV2C_REQ_RESP_H_
#define __LIBGTPV2C_REQ_RESP_H_

#include "ie.h"

#pragma pack(1)

typedef struct create_session_request_t {
	gtpv2c_header_t header;
	imsi_ie_t imsi;
	msisdn_ie_t msisdn;
	mei_ie_t mei;
	uli_ie_t uli;
	serving_network_ie_t serving_nw;
	rat_type_ie_t rat_type;
	indication_ie_t indication;
	fteid_ie_t sender_ftied;
	fteid_ie_t s5s8pgw_pmip;
	apn_ie_t apn;
	ambr_ie_t ambr;
	selection_mode_ie_t seletion_mode;
	pdn_type_ie_t pdn_type;
	paa_ie_t paa;
	apn_restriction_ie_t apn_restriction;
	charging_char_ie_t charging_characteristics;

	/* TODO: Add multiple context.
	 * As per 3GPP TS 29.274, clause 7.2.1
	 * Bearer Contexts to be created IE can be multiple IEs
	 * with same type.
	 */
	bearer_context_to_be_created_ie_t bearer_context;
	recovery_ie_t recovery;
	ue_timezone_ie_t ue_timezone;
	mapped_ue_usage_type_ie_t ue_usage_type;
	fqdn_ie_t sgwu_nodename;
} create_session_request_t;

typedef struct create_session_response_t {
	gtpv2c_header_t header;
	cause_ie_t cause;
	fteid_ie_t s11_ftied;
	fteid_ie_t pgws5s8_pmip;
	paa_ie_t paa;
	apn_restriction_ie_t apn_restriction;
	bearer_context_created_ie_t bearer_context;
} create_session_response_t;

typedef struct modify_bearer_request_t {
	gtpv2c_header_t header;
	indication_ie_t indication;
	fteid_ie_t s11_mme_fteid;
	bearer_context_to_be_modified_ie_t bearer_context;
} modify_bearer_request_t;

typedef struct modify_bearer_response_t {
	gtpv2c_header_t header;
	cause_ie_t cause;
	bearer_context_modified_ie_t bearer_context;
} modify_bearer_response_t;

typedef struct delete_session_request_t {
	gtpv2c_header_t header;
	eps_bearer_id_ie_t linked_ebi;
	indication_ie_t indication_flags;
} delete_session_request_t;

typedef struct delete_session_response_t {
	gtpv2c_header_t header;
	cause_ie_t cause;
} delete_session_response_t;

typedef struct echo_request_t {
	gtpv2c_header_t header;
	recovery_ie_t recovery;
} echo_request_t;

#pragma pack()

#endif /* __LIBGTPV2C_REQ_RESP_H_ */
