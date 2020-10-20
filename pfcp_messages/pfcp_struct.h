/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#ifndef PFCP_STRUCT_H
#define PFCP_STRUCT_H

#define MAX_LIST_SIZE	    16
#define MAX_FLOW_DESC_LEN   256
#define RULE_NAME_LEN   	(256)

#define NONE_PDN_TYPE		0
#define PDN_TYPE_IPV4		1
#define PDN_TYPE_IPV6		2
#define PDN_TYPE_IPV4_IPV6	3

#include "pfcp_ies.h"

#define MAX_FRWD_PLCY_IDENTIFIER_LEN		255
/**
 * li max entries per imsi. id is different per imsi
 */
#define MAX_LI_ENTRIES_PER_UE						16
#define URR_PER_PDR         1

enum urr_measur_method {
	VOL_BASED,
	TIME_BASED,
	VOL_TIME_BASED
};

/**
 * @brief  : Maintains Source Interface details
 */
typedef struct source_intfc_info_t {
	uint8_t interface_value;
} src_intfc_t;

/**
 * @brief  : Maintains fteid details
 */
typedef struct fteid_info_t {
	uint8_t chid;
	uint8_t ch;
	uint8_t v6;
	uint8_t v4;
	uint32_t teid;
	uint32_t ipv4_address;
	uint8_t ipv6_address[IPV6_ADDRESS_LEN];
	uint8_t choose_id;
}fteid_ie_t;

/**
 * @brief  : Maintains node address type and address value
 */
struct node_address_t
{
	/* Setting IP Address type either IPv4:1 or IPv6:2 */
	uint8_t ip_type;

	/*Node Address*/
	uint32_t ipv4_addr;
	uint8_t ipv6_addr[IPV6_ADDRESS_LEN];
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

typedef struct node_address_t  node_address_t;

/**
 * @brief  : Maintains ue ip address details
 */
typedef struct ue_ip_address_info_t {
	uint8_t ipv6d;
	uint8_t sd;
	uint8_t v4;
	uint8_t v6;
	uint32_t ipv4_address;
	uint8_t ipv6_address[IPV6_ADDRESS_LEN];
	uint8_t ipv6_pfx_dlgtn_bits;
} ue_ip_addr_t;

/**
 * @brief  : Maintains sdf filter details
 */
typedef struct sdf_filter_info_t {
	uint8_t bid;
	uint8_t fl;
	uint8_t spi;
	uint8_t ttc;
	uint8_t fd;
	/* TODO: Need to think on flow desc*/
	uint8_t flow_desc[MAX_FLOW_DESC_LEN];
	uint16_t len_of_flow_desc;
	uint16_t tos_traffic_cls;
	uint32_t secur_parm_idx;
	uint32_t flow_label;
	uint32_t sdf_filter_id;
} sdf_filter_t;

/**
 * @brief  : Maintains Network Instance value
 */
typedef struct network_inst_t {
	/* TODO: Revisit this */
	uint8_t ntwk_inst[PFCP_NTWK_INST_LEN];
} ntwk_inst_t;

/**
 * @brief  : Maintains Application ID value
 */
typedef struct application_id_info_t {
  /* TODO: Revisit this for change */
  uint8_t app_ident[PFCP_APPLICATION_ID_LEN];
} app_id_t;

/**
 * @brief  : Maintains pdi information
 */
typedef struct pdi_info_t {
	uint8_t sdf_filter_cnt;
	src_intfc_t src_intfc;
	ue_ip_addr_t ue_addr;
	ntwk_inst_t ntwk_inst;
	fteid_ie_t local_fteid;
	sdf_filter_t sdf_filter[MAX_LIST_SIZE];
	app_id_t application_id;
}pdi_t;

/**
 * @brief  : Maintains Outer Header Removal
 */
typedef struct outer_hdr_removal_info_t {
  uint8_t outer_hdr_removal_desc;
/* TODO: Revisit this for change */
//	uint8_t gtpu_ext_hdr_del;
} outer_hdr_removal_t;

/**
 * @brief  : Maintains urr id value
 */
typedef struct urr_id_t {
	uint32_t urr_id;		/* URR ID */
}urr;

/**
 * @brief  : Maintains qer id value
 */
typedef struct qer_id_t {
	uint32_t qer_id;		/* QER ID */
}qer;

/**
 * @brief  : Maintains activating predefined rule name
 */
typedef struct actvt_predef_rules_t {
	uint8_t predef_rules_nm[RULE_NAME_LEN];
}actvt_predef_rules;

/**
 * @brief  : Maintains Destination Interface value
 */
typedef struct destination_intfc_t {
	uint8_t interface_value;
} dst_intfc_t;

/**
 * @brief  : Maintains Outer Header Creation information
 */
typedef struct outer_hdr_creation_info_t{
	uint8_t  ip_type;
	uint16_t outer_hdr_creation_desc;
	uint32_t teid;
	uint32_t ipv4_address;
	uint8_t ipv6_address[IPV6_ADDRESS_LEN];
	uint16_t port_number;
	uint32_t ctag;
	uint32_t stag;
}outer_hdr_creation_t;

/**
 * @brief  : Maintains Transport Level Marking
 */
typedef struct transport_lvl_marking_info_t {
	uint16_t tostraffic_cls;
} trnspt_lvl_marking_t;

/**
 * @brief  : Maintains Header Enrichment info
 */
typedef struct hdr_enrchmt_info_t {
	uint8_t header_type;
	uint8_t len_of_hdr_fld_nm;
	uint8_t hdr_fld_nm;
	uint8_t len_of_hdr_fld_val;
	uint8_t hdr_fld_val;
} hdr_enrchmt_t;

/**
 * @brief  : Maintains Redirect Information
 */
typedef struct redirect_info_t {
	uint8_t redir_addr_type;
	uint8_t redir_svr_addr_len;
	uint8_t redir_svr_addr;
} redir_info_t;

/**
 * @brief  : Maintains Forwarding Policy info
 */
typedef struct forwardng_plcy_t {
	uint8_t frwdng_plcy_ident_len;
	uint8_t frwdng_plcy_ident[MAX_FRWD_PLCY_IDENTIFIER_LEN];
} frwdng_plcy_t;

/**
 * @brief  : Maintains Traffic Endpoint ID
 */
typedef struct traffic_endpoint_id_t {
	uint8_t traffic_endpt_id_val;
} traffic_endpt_id_t;

/**
 * @brief  : Maintains proxying info
 */
typedef struct proxying_inf_t {
	uint8_t ins;
	uint8_t arp;
} proxying_t;

/**
 * @brief  : Maintains Apply Action details
 */
typedef struct apply_action_t {
	uint8_t dupl;
	uint8_t nocp;
	uint8_t buff;
	uint8_t forw;
	uint8_t drop;
} apply_action;

/**
 * @brief  : Maintains gate status
 */
typedef struct gate_status_info_t {
	uint8_t ul_gate;
	uint8_t dl_gate;
} gate_status_t;

/**
 * @brief  : Maintains mbr info
 */
typedef struct mbr_info_t {
	uint64_t ul_mbr;
	uint64_t dl_mbr;
} mbr_t;

/**
 * @brief  : Maintains gbr info
 */
typedef struct gbr_info_t {
	uint64_t ul_gbr;
	uint64_t dl_gbr;
} gbr_t;

/**
 * @brief  : Maintains Packet Rate info
 */
typedef struct packet_rate_info_t {
	uint8_t dlpr;
	uint8_t ulpr;
	uint8_t uplnk_time_unit;
	uint16_t max_uplnk_pckt_rate;
	uint8_t dnlnk_time_unit;
	uint16_t max_dnlnk_pckt_rate;
} packet_rate_t;

/**
 * @brief  : Maintains DL Flow Level Marking
 */
typedef struct dl_flow_level_marking_t {
	uint8_t sci;
	uint8_t ttc;
	uint16_t tostraffic_cls;
	uint16_t svc_cls_indctr;
} dl_flow_lvl_marking_t;

/**
 * @brief  : Maintains qfi value
 */
typedef struct qfi_info_t {
	uint8_t qfi_value;
} qfi_t;

/**
 * @brief  : Maintains rqi value
 */
typedef struct rqi_info_t {
	uint8_t rqi;
} rqi_t;

/**
 * @brief  : Maintains Paging Policy Indicator value
 */
typedef struct paging_policy_indctr_t {
	uint8_t ppi_value;
} paging_plcy_indctr_t;

/**
 * @brief  : Maintains Averaging Window
 */
typedef struct avgng_window_t {
	uint32_t avgng_wnd;
} avgng_wnd_t;

/**
 * @brief  : Maintains Downlink Data Notification Delay
 */
typedef struct downlink_data_notif_delay_t {
	/* Note: delay_val_in_integer_multiples_of_50_millisecs_or_zero */
	uint8_t delay;
} dnlnk_data_notif_delay_t;

/**
 * @brief  : Maintains Suggested Buffering Packets Count
 */
typedef struct suggested_buf_packets_cnt_t {
	uint8_t pckt_cnt_val;
} suggstd_buf_pckts_cnt_t;

/**
 * @brief  : Maintains DL Buffering Suggested Packets Count
 */
typedef struct dl_buffering_suggested_packets_cnt_t {
	uint16_t pckt_cnt_val;
} dl_buffering_suggested_packets_cnt_t;

/**
 * @brief : Maintains measurement methods in urr
 */
typedef struct measurement_method_t {

	uint8_t event;
	uint8_t volum;
	uint8_t durat;

}measurement_method;

/**
 * @brief : Maintains reporting trigger in urr
 */
typedef struct reporting_trigger_t {

	uint8_t timth;
	uint8_t volth;
	uint8_t eveth;

}reporting_trigger;

/**
 * @brief : Maintains volume threshold in urr
 */
typedef struct volume_threshold_t {

	uint64_t total_volume;
	uint64_t uplink_volume;
	uint64_t downlink_volume;

}volume_threshold;


/**
 * @brief : Maintains time threshold in urr
 */
typedef struct time_threshold_t {

	uint32_t time_threshold;

}time_threshold;

/**
 * @brief  : Maintains far information
 */
typedef struct far_cp_info_t {
	uint8_t bar_id_value;						/* BAR ID */
	uint32_t far_id_value;						/* FAR ID */
	uint64_t session_id;						/* Session ID */
	ntwk_inst_t ntwk_inst;						/* Network Instance */
	dst_intfc_t dst_intfc;						/* Destination Interface */
	outer_hdr_creation_t outer_hdr_creation;	/* Outer Header Creation */
	trnspt_lvl_marking_t trnspt_lvl_marking;	/* Transport Level Marking */
	frwdng_plcy_t frwdng_plcy;					/* Forwarding policy */
	hdr_enrchmt_t hdr_enrchmt;					/* Container for header enrichment */
	apply_action actions;						/* Apply Action parameters*/
}far_t;

/**
 * @brief  : Maintains qer information
 */
typedef struct qer_cp_info_t {
	uint32_t qer_id;							/* QER ID */
	uint32_t qer_corr_id_val;					/* QER Correlation ID */
	uint64_t session_id;						/* Session ID */
	gate_status_t gate_status;					/* Gate Status UL/DL */
	mbr_t max_bitrate;							/* Maximum Bitrate */
	gbr_t guaranteed_bitrate;					/* Guaranteed Bitrate */
	packet_rate_t packet_rate;					/* Packet Rate */
	dl_flow_lvl_marking_t dl_flow_lvl_marking;	/* Downlink Flow Level Marking */
	qfi_t qos_flow_ident;						/* QOS Flow Ident */
	rqi_t reflective_qos;						/* RQI */
	paging_plcy_indctr_t paging_plcy_indctr;	/* Paging policy */
	avgng_wnd_t avgng_wnd;						/* Averaging Window */
}qer_t;

/**
 * @brief  : Maintains urr information
 */
typedef struct urr_cp_info_t {

	uint32_t urr_id_value;
	uint64_t session_id;
	measurement_method mea_mt;
	reporting_trigger rept_trigg;
	volume_threshold vol_th;
	time_threshold time_th;

}urr_t;


/**
 * @brief  : Maintains pdr information for CP
 */
typedef struct pdr_cp_info_t {
	uint8_t urr_id_count;						/* Number of URR */
	uint8_t qer_id_count;						/* Number of QER */
	uint8_t actvt_predef_rules_count;			/* Number of predefine rules */
	uint16_t rule_id;							/* PDR ID*/
	uint32_t prcdnc_val;						/* Precedence Value*/
	uint64_t session_id;						/* Session ID */
	pdi_t pdi;									/* Packet Detection Information */
	far_t far;									/* FAR structure info */
	qer_t qer;
	urr_t urr;
	outer_hdr_removal_t outer_hdr_removal;		/* Outer Header Removal */
	urr urr_id[MAX_LIST_SIZE];					/* Collection of URR IDs */
	qer qer_id[MAX_LIST_SIZE];					/* Collection of QER IDs */
	actvt_predef_rules rules[MAX_LIST_SIZE];	/* Collection of active predefined rules */
	char rule_name[RULE_NAME_LEN];			/* Rule name for which the PDR is created */
	uint8_t create_far;
	uint8_t create_urr;

}pdr_t;


/**
 * @brief  : Maintains bar information
 */
typedef struct bar_cp_info_t {
	uint8_t bar_id;				/* BAR ID */
	dnlnk_data_notif_delay_t ddn_delay;
	suggstd_buf_pckts_cnt_t suggstd_buf_pckts_cnt;
	dl_buffering_suggested_packets_cnt_t dl_buf_suggstd_pckts_cnt;
}bar_t;

#endif /* PFCP_STRUCT_H */
