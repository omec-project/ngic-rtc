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

#ifndef _LIBGTPV2C_IE_H_
#define _LIBGTPV2C_IE_H_

#include <arpa/inet.h>
#include <unistd.h>

#define GTPV2C_HEADER_LEN 12

#define IE_HEADER_SIZE sizeof(ie_header_t)

#define MNC_MCC_BUF_SIZE 3
#define MBR_BUF_SIZE 5
#define BINARY_IMSI_LEN	8
#define BINARY_MSISDN_LEN	8
#define BINARY_MEI_LEN	8
#define APN_LEN	128

#define PDN_TYPE_IPV4	1
#define PDN_TYPE_IPV6	2
#define PDN_TYPE_IPV4_IPV6	3

#define HOSTNAME_LEN 256

/* Information Element type values according to 3GPP TS 29.274 Table 8.1-1 */
#define IE_RESERVED (0)
#define IE_IMSI (1)
#define IE_CAUSE (2)
#define IE_RECOVERY (3)
#define IE_APN (71)
#define IE_AMBR (72)
#define IE_EBI (73)
#define IE_IP_ADDRESS (74)
#define IE_MEI (75)
#define IE_MSISDN (76)
#define IE_INDICATION (77)
#define IE_PCO (78)
#define IE_PAA (79)
#define IE_BEARER_QOS (80)
#define IE_FLOW_QOS (81)
#define IE_RAT_TYPE (82)
#define IE_SERVING_NETWORK (83)
#define IE_BEARER_TFT (84)
#define IE_TAD (85)
#define IE_ULI (86)
#define IE_FTEID (87)
#define IE_TMSI (88)
#define IE_GLOBAL_CN_ID (89)
#define IE_S103PDF (90)
#define IE_S1UDF (91)
#define IE_DELAY_VALUE (92)
#define IE_BEARER_CONTEXT (93)
#define IE_CHARGING_ID (94)
#define IE_CHARGING_CHARACTERISTICS (95)
#define IE_TRACE_INFORMATION (96)
#define IE_BEARER_FLAGS (97)
#define IE_PDN_TYPE (99)
#define IE_PROCEDURE_TRANSACTION_ID (100)
#define IE_DRX_PARAMETER (101)
#define IE_UE_NETWORK_CAPABILITY (102)
#define IE_PDN_CONNECTION (109)
#define IE_PDU_NUMBERS (110)
#define IE_PTMSI (111)
#define IE_PTMSI_SIGNATURE (112)
#define IE_HIP_COUNTER (113)
#define IE_UE_TIME_ZONE (114)
#define IE_TRACE_REFERENCE (115)
#define IE_COMPLETE_REQUEST_MESSAGE (116)
#define IE_GUTI (117)
#define IE_F_CONTAINER (118)
#define IE_F_CAUSE (119)
#define IE_SELECTED_PLMN_ID (120)
#define IE_TARGET_IDENTIFICATION (121)
#define IE_PACKET_FLOW_ID (123)
#define IE_RAB_CONTEXT (124)
#define IE_SOURCE_RNC_PDCP_CONTEXT_INFO (125)
#define IE_UDP_SOURCE_PORT_NUMBER (126)
#define IE_APN_RESTRICTION (127)
#define IE_SELECTION_MODE (128)
#define IE_SOURCE_IDENTIFICATION (129)
#define IE_CHANGE_REPORTING_ACTION (131)
#define IE_FQ_CSID (132)
#define IE_CHANNEL_NEEDED (133)
#define IE_EMLPP_PRIORITY (134)
#define IE_NODE_TYPE (135)
#define IE_FQDN (136)
#define IE_TI (137)
#define IE_MBMS_SESSION_DURATION (138)
#define IE_MBMS_SERIVCE_AREA (139)
#define IE_MBMS_SESSION_IDENTIFIER (140)
#define IE_MBMS_FLOW_IDENTIFIER (141)
#define IE_MBMS_IP_MULTICAST_DISTRIBUTION (142)
#define IE_MBMS_IP_DISTRIBUTION_ACK (143)
#define IE_RFSP_INDEX (144)
#define IE_UCI (145)
#define IE_CSG_INFORMATION_REPORTING_ACTION (146)
#define IE_CSG_ID (147)
#define IE_CSG_MEMBERSHIP_INDICATION (148)
#define IE_SERVICE_INDICATOR (149)
#define IE_ALLOCATION_RETENTION_PRIORITY (155)
#define IE_MAPPED_UE_USAGE_TYPE (200)
#define IE_PRIVATE_EXTENSION (255)

/**
* Partial list of acceptable instance values to use for the instance field
* with the gtpv2c_ie structure.
*/
enum ie_instance {
	IE_INSTANCE_ZERO = 0,
	IE_INSTANCE_ONE = 1,
	IE_INSTANCE_TWO = 2,
	IE_INSTANCE_THREE = 3,
	IE_INSTANCE_FOUR = 4,
	IE_INSTANCE_FIVE = 5,
	IE_INSTANCE_SIX = 6
};

#pragma pack(1)

typedef struct gtpv2c_header_t {
	struct gtpc {
		uint8_t spare :3;
		uint8_t teid_flag :1;
		uint8_t piggyback :1;
		uint8_t version :3;
		uint8_t message_type;
		uint16_t message_len;
	} gtpc;
	union teid {
		struct has_teid_t {
			uint32_t teid;
			uint32_t seq :24;
			uint32_t spare :8;
		} has_teid;
		struct no_teid_t {
			uint32_t seq :24;
			uint32_t spare :8;
		} no_teid;
	} teid;
} gtpv2c_header_t;

typedef struct ie_header_t {
	uint8_t type;
	uint16_t len;
	uint8_t instance;
} ie_header_t;

typedef struct imsi_ie_t {
	ie_header_t header;
	uint8_t imsi[BINARY_IMSI_LEN];
} imsi_ie_t;

typedef struct msisdn_ie_t {
	ie_header_t header;
	uint8_t msisdn[BINARY_MSISDN_LEN];
} msisdn_ie_t;

typedef struct mei_ie_t {
	ie_header_t header;
	uint8_t mei[BINARY_MEI_LEN];
} mei_ie_t;

typedef struct mcc_mnc_t {
	uint8_t mcc_digit_1 :4;
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t mnc_digit_2 :4;
} mcc_mnc_t;

typedef struct uli_flags_t {
	uint8_t cgi :1;
	uint8_t sai :1;
	uint8_t rai :1;
	uint8_t tai :1;
	uint8_t ecgi :1;
	uint8_t lai :1;
	uint8_t spare :2;
} uli_flags_t;

typedef struct lai_t {
	uint16_t location_area_code;
} lai_t;

typedef struct ecgi_t {
	mcc_mnc_t mcc_mnc;
	uint32_t spare :4;
	uint32_t eci :28;
} ecgi_t;

typedef struct tai_t {
	mcc_mnc_t mcc_mnc;
	uint16_t tac;
} tai_t;

typedef struct rai_t {
	mcc_mnc_t mcc_mnc;
	uint16_t lac;
	uint16_t rac;
} rai_t;

typedef struct sai_t {
	mcc_mnc_t mcc_mnc;
	uint16_t lac;
	uint16_t sac;
} sai_t;

typedef struct cgi_t {
	mcc_mnc_t mcc_mnc;
	uint16_t lac;
	uint16_t ci;
} cgi_t;

typedef struct uli_ie_t {
	ie_header_t header;
	uli_flags_t flags;
	/*cgi_t cgi;
	sai_t sai;
	rai_t rai;*/
	tai_t tai;
	ecgi_t ecgi;
	/*lai_t lai; */
} uli_ie_t;


typedef struct serving_network_ie_t {
	ie_header_t header;
	mcc_mnc_t mcc_mnc;
} serving_network_ie_t;

typedef enum e_rat_type {
	RAT_TYPE_RESERVED = 0,
	RAT_TYPE_UTRAN = 1,
	RAT_TYPE_GERAN = 2,
	RAT_TYPE_WLAN = 3,
	RAT_TYPE_GAN = 4,
	RAT_TYPE_HSPA_EVOLUTION = 5,
	RAT_TYPE_EUTRAN = 6,
	RAT_TYPE_VIRTUAL = 7,
} e_rat_type;

typedef struct rat_type_ie_t {
	ie_header_t header;
	uint8_t rat_type;
} rat_type_ie_t;


typedef struct indication_t {
	uint8_t sgwci :1;
	uint8_t israi :1;
	uint8_t isrsi :1;
	uint8_t oi :1;
	uint8_t dfi :1;
	uint8_t hi :1;
	uint8_t dtf :1;
	uint8_t daf :1;

	uint8_t msv :1;
	uint8_t si :1;
	uint8_t pt :1;
	uint8_t p :1;
	uint8_t crsi :1;
	uint8_t cfsi :1;
	uint8_t uimsi :1;
	uint8_t sqci :1;

	uint8_t ccrsi :1;
	uint8_t israu :1;
	uint8_t mbmdt :1;
	uint8_t s4af :1;
	uint8_t s6af :1;
	uint8_t srni :1;
	uint8_t pbic :1;
	uint8_t retloc :1;

	uint8_t cpsr :1;
	uint8_t clii :1;
	uint8_t csfbi :1;
	uint8_t ppsi :1;
	uint8_t ppon_ppei :1;
	uint8_t ppof :1;
	uint8_t arrl :1;
	uint8_t cprai :1;

	uint8_t aopi :1;
	uint8_t aosi :1;
	uint8_t spare :6;

	uint8_t spare1;
} indication_t;

typedef struct indication_ie_t {
	ie_header_t header;
	indication_t indication_value;
} indication_ie_t;

typedef struct fteid_ie_t {
	ie_header_t header;
	uint8_t iface_type :6;
	uint8_t v6 :1;
	uint8_t v4 :1;
	uint32_t teid_gre;
    union ftied_ip {
			struct in_addr ipv4;
			struct in6_addr ipv6;
			struct ipv4v6_t {
					struct in_addr ipv4;
					struct in6_addr ipv6;
			} ipv4v6;
	} ip;
} fteid_ie_t;

typedef struct apn_ie_t {
	ie_header_t header;
	uint8_t apn[APN_LEN];
} apn_ie_t;

typedef struct ambr_ie_t {
	ie_header_t header;
	uint32_t apn_ambr_ul;
	uint32_t apn_ambr_dl;
} ambr_ie_t;

typedef struct charging_char_ie_t {
	ie_header_t header;
	uint16_t value;
} charging_char_ie_t;

typedef struct selection_mode_ie_t {
	ie_header_t header;
	uint8_t selec_mode :2;
	uint8_t spare :6;
} selection_mode_ie_t;

typedef struct pdn_type_ie_t {
	ie_header_t header;
	uint8_t pdn_type :3;
	uint8_t spare :5;
} pdn_type_ie_t;

typedef struct paa_ie_t {
	ie_header_t header;
	uint8_t pdn_type :3;
	uint8_t spare :5;
	union ip_type {
		struct in_addr ipv4;
		struct ipv6_t {
				uint8_t prefix_length;
				struct in6_addr ipv6;
		} ipv6;
		struct paa_ipv4v6_t {
				uint8_t prefix_length;
				struct in6_addr ipv6;
				struct in_addr ipv4;
		} paa_ipv4v6;
	} ip_type;
} paa_ie_t;

typedef struct apn_restriction_ie_t {
	ie_header_t header;
	uint8_t restriction_type;
} apn_restriction_ie_t;

typedef struct recovery_ie_t {
	ie_header_t header;
	uint8_t restart_counter;
} recovery_ie_t;

typedef struct ue_timezone_ie_t {
	ie_header_t header;
	uint8_t timezone;
	uint8_t spare1 :6;
	uint8_t ds_time :2;
} ue_timezone_ie_t;

typedef struct eps_bearer_id_ie_t {
	ie_header_t header;
	uint8_t eps_bearer_id :4;
	uint8_t spare :4;
} eps_bearer_id_ie_t;

typedef struct pci_pl_pvi_t {
	uint8_t pvi :1;
	uint8_t spare2 :1;
	uint8_t pl :4;
	uint8_t pci :1;
	uint8_t spare1 :1;
} pci_pl_pvi_t;

typedef struct bearer_qos_ie_t {
	ie_header_t header;
	pci_pl_pvi_t pci_pl_pvi;
	uint8_t label_qci;
	uint64_t maximum_bit_rate_for_uplink;
	uint64_t maximum_bit_rate_for_downlink;
	uint64_t guaranteed_bit_rate_for_uplink;
	uint64_t guaranteed_bit_rate_for_downlink;
} bearer_qos_ie_t;

/**
 * Bearer Context to be created IE specific for Create Session Request
 * as defined by 3GPP TS 29.274, clause 7.2.1 for the
 * IE type value 93.
 */
typedef struct bearer_context_to_be_created_ie_t {
	ie_header_t header;
	eps_bearer_id_ie_t ebi;
	bearer_qos_ie_t bearer_qos;
	fteid_ie_t s5s8_sgwu_fteid;
} bearer_context_to_be_created_ie_t;

/**
 * Bearer Context to be removed IE specific for Create Session Request
 * as defined by 3GPP TS 29.274, clause 7.2.1 for the
 * IE type value 93.
 */
typedef struct bearer_context_to_be_removed_ie_t {
	ie_header_t header;
	eps_bearer_id_ie_t ebi;
} bearer_context_to_be_removed_ie_t;

/**
 * IE specific data for Cause as defined by 3GPP TS 29.274, clause 8.4 for the
 * IE type value 2.
 */
typedef struct cause_ie_t {
	ie_header_t header;
	uint8_t cause_value;
	uint8_t cause_source :1;
	uint8_t bearer_context_error :1;
	uint8_t pdn_connection_error :1;
	uint8_t spare_0 :5;

	uint8_t offending_ie_type;
	uint16_t offending_ie_length;
	uint8_t instance :4;
	uint8_t spare_1 :4;
} cause_ie_t;

/**
 * Bearer Context Created IE specific for Create Session Response
 * as defined by 3GPP TS 29.274, clause 7.2.2-2 for the
 * IE type value 93.
 */
typedef struct bearer_context_created_ie_t {
	ie_header_t header;
	eps_bearer_id_ie_t ebi;
	cause_ie_t cause;
	fteid_ie_t s1u_sgw_ftied;
	fteid_ie_t s5s8_pgw;
} bearer_context_created_ie_t;

/**
 * Bearer Context marked for removal IE specific for Create Session Response
 * as defined by 3GPP TS 29.274, clause 7.2.2-3 for the
 * IE type value 93.
 */
typedef struct bearer_context_marked_for_removal_ie_t {
	ie_header_t header;
	eps_bearer_id_ie_t ebi;
	cause_ie_t cause;
} bearer_context_marked_for_removal_ie_t;


/**
 * Bearer Context within Modify Bearer Request
 * as defined by 3GPP TS 29.274, clause 7.2.7 for the
 * IE type value 93.
 */
typedef struct bearer_context_to_be_modified_ie_t {
	ie_header_t header;
	eps_bearer_id_ie_t ebi;
	fteid_ie_t s1u_enodeb_ftied;
} bearer_context_to_be_modified_ie_t;

/**
 * Bearer Context modified within Modify Bearer Response
 * as defined by 3GPP TS 29.274, clause 7.2.8 for the
 * IE type value 93.
 */
typedef struct bearer_context_modified_ie_t {
	ie_header_t header;
	cause_ie_t cause;
	eps_bearer_id_ie_t ebi;
	fteid_ie_t s1u_sgw_ftied;
} bearer_context_modified_ie_t;

/**
 * Mapped UE Usage Type
 * as defined by 3GPP TS 29.274, clause 8.131 for the
 * IE type value 200.
 */
typedef struct mapped_ue_usage_type_ie_t {
	ie_header_t header;
	uint16_t mapped_ue_usage_type;
} mapped_ue_usage_type_ie_t;

typedef struct fqdn_ie_t {
	ie_header_t header;
	uint8_t fqdn[HOSTNAME_LEN];
} fqdn_ie_t;

#pragma pack()

#endif /* _LIBGTPV2C_IE_H_ */
