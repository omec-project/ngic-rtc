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

#ifndef UE_H
#define UE_H

/**
 * @file
 *
 * Contains all data structures required by 3GPP TS 23.401 Tables 5.7.3-1 and
 * 5.7.4-1 (that are nessecary for current implementaiton) to describe the
 * Connections, state, bearers, etc as well as functions to manage and/or
 * obtain value for their fields.
 *
 */

#include <stdint.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_jhash.h>

#include "gtpv2c_ie.h"
#include "interface.h"
#include "packet_filters.h"
#include "pfcp_struct.h"
#include "ngic_timer.h"

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

/* li parameter */
#define LI_DF_CSV_IMSI_COLUMN			0
#define LI_DF_CSV_LI_DEBUG_COLUMN		1
#define LI_DF_CSV_EVENT_CC_COLUMN		2
#define LI_DF_CSV_DDF2_IP_COLUMN		3
#define LI_DF_CSV_DDF2_PORT_COLUMN		4
#define LI_DF_CSV_DDF3_IP_COLUMN		5
#define LI_DF_CSV_DDF3_PORT_COLUMN		6

#define LI_LDB_ENTRIES_DEFAULT						1024

#define SDF_FILTER_TABLE "sdf_filter_table"
#define ADC_TABLE "adc_rule_table"
#define PCC_TABLE "pcc_table"
#define SESSION_TABLE "session_table"
#define METER_PROFILE_SDF_TABLE "meter_profile_sdf_table"
#define METER_PROFILE_APN_TABLE "meter_profile_apn_table"

#define SDF_FILTER_TABLE_SIZE        (1024)
#define ADC_TABLE_SIZE               (1024)
#define PCC_TABLE_SIZE               (1025)
#define METER_PROFILE_SDF_TABLE_SIZE (2048)

#define DPN_ID                       (12345)

#define MAX_BEARERS                  (14)
#define MAX_FILTERS_PER_UE           (16)

#define MAX_NETCAP_LEN               (64)
#define MAX_APN_LEN                  (64)
#define MAX_SDF_DESC_LEN             (512)
#define RULE_CNT                     (16)
#define PROC_LEN					 (64)

#define GET_UE_IP(ip_pool, ip_pool_mask, ue_index) \
			(((ip_pool.s_addr | (~ip_pool_mask.s_addr)) \
			  - htonl(ue_index)) - 0x01000000)

#define INTERFACE \
			( (SAEGWC == config.cp_type) ? Sxa_Sxb : ( (PGWC != config.cp_type) ? Sxa : Sxb ) )

#ifndef CP_BUILD
#define FQDN_LEN 256
#endif

#define NUMBER_OF_PDR_PER_RULE 2
#define NUMBER_OF_QER_PER_RULE 2
#define MAX_RULE_PER_BEARER 16
#define NUMBER_OF_PDR_PER_BEARER 32
#define NUMBER_OF_QER_PER_BEARER 32

#define QER_INDEX_FOR_ACCESS_INTERFACE 0
#define QER_INDEX_FOR_CORE_INTERFACE 1


#define CSR_SEQUENCE(x) (\
	(x->header.gtpc.teid_flag == 1)? x->header.teid.has_teid.seq : x->header.teid.no_teid.seq \
	)
#define LEN                                 12
#define DEFAULT_RULE_COUNT                  1
#define QCI_VALUE                           6
#define GX_PRIORITY_LEVEL                   1
#define PREEMPTION_CAPABILITY_DISABLED      1
#define PREEMPTION_VALNERABILITY_ENABLED    0
#define GX_ENABLE                           2
#define PRECEDENCE                          2
#define SERVICE_INDENTIFIRE                 11
#define RATING_GROUP                        1
#define REQUESTED_BANDWIDTH_UL              16500
#define REQUESTED_BANDWIDTH_DL              16500
#define GURATEED_BITRATE_UL                 0
#define GURATEED_BITRATE_DL                 0
#define RULE_NAME                           "default rule"
#define RULE_LENGTH                         strnlen(RULE_NAME, LEN)
#define PROTO_ID                            0
#define LOCAL_IP_MASK                       0
#define LOCAL_IP_ADDR                       0
#define PORT_LOW                            0
#define PORT_HIGH                           65535
#define REMOTE_IP_MASK                      0
#define REMOTE_IP_ADDR                      0
#define LOCAL_IPV6_MASK                     4
#define REMOTE_IPV6_MASK                    4
#define GX_FLOW_COUNT                       1
#define MAX_UINT8_T_VAL						255

#pragma pack(1)

struct eps_bearer_t;
struct pdn_connection_t;

/**
 * @brief  : Maintains CGI (Cell Global Identifier) data from user location information
 */
typedef struct cgi_t {
	uint8_t cgi_mcc_digit_2 :4;
	uint8_t cgi_mcc_digit_1 :4;
	uint8_t cgi_mnc_digit_3 :4;
	uint8_t cgi_mcc_digit_3 :4;
	uint8_t cgi_mnc_digit_2 :4;
	uint8_t cgi_mnc_digit_1 :4;
	uint16_t cgi_lac;
	uint16_t cgi_ci;
} cgi_t;

/**
 * @brief  : Maintains SAI (Service Area Identifier) data from user location information
 */
typedef struct sai_t {
	uint8_t sai_mcc_digit_2 :4;
	uint8_t sai_mcc_digit_1 :4;
	uint8_t sai_mnc_digit_3 :4;
	uint8_t sai_mcc_digit_3 :4;
	uint8_t sai_mnc_digit_2 :4;
	uint8_t sai_mnc_digit_1 :4;
	uint16_t sai_lac;
	uint16_t sai_sac;
}sai_t;

/**
 * @brief  : Maintains RAI (Routing Area Identity) data from user location information
 */
typedef struct rai_t {
	uint8_t ria_mcc_digit_2 :4;
	uint8_t ria_mcc_digit_1 :4;
	uint8_t ria_mnc_digit_3 :4;
	uint8_t ria_mcc_digit_3 :4;
	uint8_t ria_mnc_digit_2 :4;
	uint8_t ria_mnc_digit_1 :4;
	uint16_t ria_lac;
	uint16_t ria_rac;
} rai_t;

/**
 * @brief  : Maintains TAI (Tracking Area Identity) data from user location information
 */
typedef struct tai_t {
	uint8_t tai_mcc_digit_2 :4;
	uint8_t tai_mcc_digit_1 :4;
	uint8_t tai_mnc_digit_3 :4;
	uint8_t tai_mcc_digit_3 :4;
	uint8_t tai_mnc_digit_2 :4;
	uint8_t tai_mnc_digit_1 :4;
	uint16_t tai_tac;
} tai_t;

/**
 * @brief  : Maintains LAI (Location Area Identifier) data from user location information
 */
typedef struct lai_t {
	uint8_t lai_mcc_digit_2 :4;
	uint8_t lai_mcc_digit_1 :4;
	uint8_t lai_mnc_digit_3 :4;
	uint8_t lai_mcc_digit_3 :4;
	uint8_t lai_mnc_digit_2 :4;
	uint8_t lai_mnc_digit_1 :4;
	uint16_t lai_lac;
} lai_t;

/**
 * @brief  : Maintains ECGI (E-UTRAN Cell Global Identifier) data from user location information
 */
typedef struct ecgi_t {
	uint8_t ecgi_mcc_digit_2 :4;
	uint8_t ecgi_mcc_digit_1 :4;
	uint8_t ecgi_mnc_digit_3 :4;
	uint8_t ecgi_mcc_digit_3 :4;
	uint8_t ecgi_mnc_digit_2 :4;
	uint8_t ecgi_mnc_digit_1 :4;
	uint8_t ecgi_spare :4;
	uint32_t eci :28;
} ecgi_t;

/**
 * @brief  : Maintains Macro eNodeB ID data from user location information
 */
typedef struct macro_enb_id_t {
	uint8_t menbid_mcc_digit_2 :4;
	uint8_t menbid_mcc_digit_1 :4;
	uint8_t menbid_mnc_digit_3 :4;
	uint8_t menbid_mcc_digit_3 :4;
	uint8_t menbid_mnc_digit_2 :4;
	uint8_t menbid_mnc_digit_1 :4;
	uint8_t menbid_spare :4;
	uint8_t menbid_macro_enodeb_id :4;
	uint16_t menbid_macro_enb_id2;
} macro_enb_id_t;

typedef struct home_enb_id_t {
	uint8_t henbid_mcc_digit_2 :4;
	uint8_t henbid_mcc_digit_1 :4;
	uint8_t henbid_mnc_digit_3 :4;
	uint8_t henbid_mcc_digit_3 :4;
	uint8_t henbid_mnc_digit_2 :4;
	uint8_t henbid_mnc_digit_1 :4;
	uint8_t henbid_spare :4;
	uint8_t henbid_home_enodeb_id :4;
	uint32_t henbid_home_enb_id2 :24;
} home_enb_id_t;

/**
 * @brief  : Maintains Extended Macro eNodeB ID data from user location information
 */
typedef struct  extnded_macro_enb_id_t {
	uint8_t emenbid_mcc_digit_2 :4;
	uint8_t emenbid_mcc_digit_1 :4;
	uint8_t emenbid_mnc_digit_3 :4;
	uint8_t emenbid_mcc_digit_3 :4;
	uint8_t emenbid_mnc_digit_2 :4;
	uint8_t emenbid_mnc_digit_1 :4;
	uint8_t emenbid_smenb :1;
	uint8_t emenbid_spare :2;
	uint8_t emenbid_extnded_macro_enb_id :5;
	uint16_t emenbid_extnded_macro_enb_id2;
} extnded_macro_enb_id_t;

/**
 * @brief  : Maintains user location information data
 */
typedef struct user_loc_info_t {
	uint8_t lai;
	uint8_t tai;
	uint8_t rai;
	uint8_t sai;
	uint8_t cgi;
	uint8_t ecgi;
	uint8_t macro_enodeb_id;
	uint8_t extnded_macro_enb_id;
	cgi_t cgi2;
	sai_t sai2;
	rai_t rai2;
	tai_t tai2;
	lai_t lai2;
	ecgi_t ecgi2;
	macro_enb_id_t macro_enodeb_id2;
	extnded_macro_enb_id_t extended_macro_enodeb_id2;
} user_loc_info_t;


typedef struct presence_reproting_area_action_t {
	uint8_t action;
	uint32_t pres_rptng_area_idnt;
	uint8_t number_of_tai;
	uint8_t number_of_rai;
	uint8_t nbr_of_macro_enb;
	uint8_t nbr_of_home_enb;
	uint8_t number_of_ecgi;
	uint8_t number_of_sai;
	uint8_t number_of_cgi;
	uint8_t nbr_of_extnded_macro_enb;
	cgi_t cgis[MAX_CGIS];
	sai_t sais[MAX_SAIS];
	rai_t rais[MAX_RAIS];
	tai_t tais[MAX_TAIS];
	ecgi_t ecgis[MAX_ECGIS];
	macro_enb_id_t macro_enodeb_ids[MAX_MACRO_ENB_IDS];
	home_enb_id_t home_enb_ids[MAX_HOME_ENB_IDS];
	extnded_macro_enb_id_t extended_macro_enodeb_ids[MAX_EX_MACRO_ENB_IDS];
} presence_reproting_area_action_t;

typedef struct presence_reproting_area_info_t {
	uint32_t pra_identifier;
	uint8_t inapra;
	uint8_t opra;
	uint8_t ipra;
} presence_reproting_area_info_t;

/**
 * @brief  : Maintains serving network mcc and mnc information
 */
typedef struct serving_nwrk_t {
	uint8_t mcc_digit_2;
	uint8_t mcc_digit_1;
	uint8_t mnc_digit_3;
	uint8_t mcc_digit_3;
	uint8_t mnc_digit_2;
	uint8_t mnc_digit_1;
} serving_nwrk_t;

/**
 * @brief  : Maintains rat type information
 */
typedef struct rat_type_t {
	uint8_t rat_type;
	uint16_t len;
}rat_type_t;

/**
 * @brief  : Maintains apn related information
 */
typedef struct apn_t {
	char *apn_name_label;
	int apn_usage_type;
	char apn_net_cap[MAX_NETCAP_LEN];
	int trigger_type;
	int uplink_volume_th;
	int downlink_volume_th;
	int time_th;
	size_t apn_name_length;
	int8_t apn_idx;
	struct in_addr ip_pool_ip;
	struct in_addr ip_pool_mask;
	struct in6_addr ipv6_network_id;
	uint8_t ipv6_prefix_len;
} apn;

/**
 * @brief  : Maintains secondary rat related information
 */
typedef struct secondary_rat_t {
	uint8_t spare2:6;
	uint8_t irsgw :1;
	uint8_t irpgw :1;
	uint8_t rat_type;
	uint8_t eps_id:4;
	uint8_t spare3:4;
	uint32_t start_timestamp;
	uint32_t end_timestamp;
	uint64_t usage_data_dl;
	uint64_t usage_data_ul;
} secondary_rat_t;
extern int total_apn_cnt;

/**
 * @brief  : Maintains eps bearer id
 */
typedef struct ebi_id_t {
	uint64_t ebi_id;
}ebi_id;

/**
 * @brief  : Maintains sdf packet filter information
 */
typedef struct sdf_pkt_fltr_t {
	uint8_t proto_id;
	uint8_t v4;
	uint8_t v6;
	uint8_t proto_mask;
	uint8_t direction;
	uint8_t action;
	uint8_t local_ip_mask;
	uint8_t remote_ip_mask;
	uint16_t local_port_low;
	uint16_t local_port_high;
	uint16_t remote_port_low;
	uint16_t remote_port_high;
	struct in_addr local_ip_addr;
	struct in_addr remote_ip_addr;
	struct in6_addr local_ip6_addr;
	struct in6_addr remote_ip6_addr;
} sdf_pkt_fltr;

/**
 * @brief  : Maintains flow description data
 */
typedef struct flow_description {
	uint8_t pckt_fltr_identifier;
	int32_t flow_direction;
	sdf_pkt_fltr sdf_flw_desc;
	char sdf_flow_description[MAX_SDF_DESC_LEN];
	uint16_t flow_desc_len;
}flow_desc_t;

/**
 * @brief  : Maintains information about dynamic rule
 */
typedef struct dynamic_rule{
	int32_t online;
	int32_t offline;
	int32_t flow_status;
	int32_t reporting_level;
	uint32_t precedence;
	uint32_t service_id;
	uint32_t rating_group;
	uint32_t def_bearer_indication;
	char rule_name[RULE_NAME_LEN];
	char af_charging_id_string[256];
	bool predefined_rule;
	bearer_qos_ie qos;
	/* Need to think on it */
	uint8_t num_flw_desc;
	flow_desc_t flow_desc[32];
	pdr_t *pdr[NUMBER_OF_PDR_PER_RULE];
}dynamic_rule_t;

enum rule_action_t {
	RULE_ACTION_INVALID,
	RULE_ACTION_ADD = 1,
	RULE_ACTION_MODIFY = 2,
	RULE_ACTION_MODIFY_ADD_RULE = 3,
	RULE_ACTION_MODIFY_REMOVE_RULE = 4,
	RULE_ACTION_DELETE = 5,
	RULE_ACTION_MAX
};

/**
 * @brief  : Maintains information about pcc rule
 */
typedef struct pcc_rule{
	enum rule_action_t action;
	bool predefined_rule;
	dynamic_rule_t dyn_rule;
	/* maintain the predefined rule info */
	dynamic_rule_t pdef_rule;
}pcc_rule_t;

/**
 * @brief  : Currently policy from PCRF can be two thing
 * 1. Default bearer QOS
 * 2. PCC Rule
 * Default bearer QOS can be modified
 * PCC Rules can be Added, Modified or Deleted
 * These policy shoulbe be applied to the PDN or eps_bearer
 * data strutures only after sucess from access side
 */
typedef struct policy{
	bool default_bearer_qos_valid;
	uint8_t count;
	uint8_t num_charg_rule_install;
	uint8_t num_charg_rule_modify;
	uint8_t num_charg_rule_delete;
	bearer_qos_ie default_bearer_qos;
	pcc_rule_t pcc_rule[32];
}policy_t;

/**
 * @brief  : Maintains selection mode info
 */
typedef struct selection_mode{
	uint8_t spare2:6;
	uint8_t selec_mode:2;
}selection_mode;

/**
 * @brief  : Maintains indication flag oi value
 */
typedef struct indication_flag_t {

	uint8_t oi:1;     /* Operation Indication */
	uint8_t ltempi:1; /* LTE-M RAT Type reporting to PGW Indication */
	uint8_t crsi:1;   /* Change Reporting support indication */
	uint8_t sgwci:1;  /* SGW Change Indication */
	uint8_t hi:1;     /* Handover Indication */
	uint8_t ccrsi:1;  /* CSG Change Reporting support indication */
	uint8_t cprai:1;  /* Change of Presence Reporting Area information Indication */
	uint8_t clii:1;   /* Change of Location Information Indication */
	uint8_t dfi:1;    /* Direct Forwarding Indication */
	uint8_t arrl:1;   /* Abnormal Release of Radio Link */
	uint8_t daf:1; 	/*Dual Address Bearer Flag*/
	uint8_t cfsi:1;   /* Change F-TEID support indication */
	uint8_t pt:1;     /*(S5/S8 Protocol Type */
	uint8_t s11tf:1;  /* S11-u teid Indication*/
}indication_flag_t;

/**
 * @brief  : Maintains Time zone information
 */
typedef struct ue_tz_t{
	uint8_t tz;
	uint8_t dst;
}ue_tz;

/**
 * @brief  : Maintains user CSG information
 */
typedef struct user_csg_i_t {
	uint8_t mcc_digit_2 :4;
	uint8_t mcc_digit_1 :4;
	uint8_t mnc_digit_3 :4;
	uint8_t mcc_digit_3 :4;
	uint8_t mnc_digit_2 :4;
	uint8_t mnc_digit_1 :4;
	uint8_t spare2 :5;
	uint32_t csg_id :3;
	uint32_t csg_id2 :24;
	uint8_t access_mode :2;
	uint8_t spare3 :4;
	uint8_t lcsg :1;
	uint8_t cmi :1;
} user_csg_i;

/**
 * @brief  : Maintains timestamp and counter information
 */
typedef struct counter_t{
	uint32_t timestamp_value;
	uint8_t counter_value;
}counter;

/**
 * @brief  : Maintains li configurations
 */
typedef struct li_data {
	uint64_t id;
	uint8_t s11;
	uint8_t sgw_s5s8c;
	uint8_t pgw_s5s8c;
	uint8_t sxa;
	uint8_t sxb;
	uint8_t sxa_sxb;
	uint8_t forward;
} li_data_t;

/**
 * @brief  : Maintains imsi to li mapping
 */
typedef struct imsi_id_hash {
	uint8_t cntr;
	uint64_t ids[MAX_LI_ENTRIES_PER_UE];
} imsi_id_hash_t;

/**
 * @brief  : Status of mbr processing
 */
enum mbr_status_t {
	MBR_PROCESS_DONE = 0,
	MBR_IN_PROGRESS = 1
};

/**
 * @brief  : Status of dsr processing
 */
enum dsr_status_t {
	DSR_PROCESS_DONE = 0,
	DSR_IN_PROGRESS = 1
};

/**
 * @brief  : Status of cbr processing
 */
enum cbr_status_t {
	CBR_PROCESS_DONE = 0,
	CBR_IN_PROGRESS = 1
};

/**
 * @brief  : Maintains status of current MBR in progress
 */
typedef struct mbr_req_info {
	uint32_t seq;
	enum mbr_status_t status;
}mbr_req_info_t;

/**
 * @brief: Status of MABR processing
 */
enum mabr_status_t {
	MABR_PROCESS_DONE = 0,
	MABR_IN_PROGRESS = 1
};
/**
 * @brief  : Maintains status of current Modify Acccess Bearer
 * Request in progress
 */
typedef struct mabr_req_info {
	uint32_t seq;
	enum mabr_status_t status;
}mabr_req_info_t;

/**
 * @brief  : Maintains status of current DSR in progress
 */
typedef struct dsr_req_info {
	uint32_t seq;
	enum dsr_status_t status;
}dsr_req_info_t;

/**
 * @brief  : Maintains status of current CBR in progress
 */
typedef struct cbr_req_info {
	uint32_t seq;
	enum cbr_status_t status;
} cbr_req_info_t;

/*
 * @brief : Used to store rule status received in CCA
 *          send provision ack message to PCRF*/

typedef struct pro_ack_rule_status {
    char rule_name[RULE_NAME_LEN];
    uint8_t rule_status;
}pro_ack_rule_status_t;

typedef struct pro_ack_rule_array {
    uint8_t rule_cnt;
    pro_ack_rule_status_t rule[MAX_RULE_PER_BEARER];
}pro_ack_rule_array_t;


/**
 * @brief  : Maintains ue related information
 */
typedef struct ue_context_t {
	bool cp_mode_flag;
	uint8_t cp_mode;
	uint64_t imsi;
	uint8_t imsi_len;
	uint8_t unathenticated_imsi;
	uint64_t mei;
	uint64_t msisdn;
	uint8_t msisdn_len;

	/* MBR sequence number and status for identifying
	 * retransmitted MBR req.
	 */

	mbr_req_info_t mbr_info;
	/*DSR sequence number and status for identifying
	 * retransmitted DSR req.
	 */
	dsr_req_info_t dsr_info;

	/*CBR sequence number and status for identifying
	 * retransmitted CBR req.
	 */
	cbr_req_info_t cbr_info;

	/* MABR sequence number and status for identifying
	 * retransmitted MABR req.
	 */
	mabr_req_info_t mabr_info;

	uint8_t proc_trans_id;
	uint32_t ue_initiated_seq_no;
	uint8_t mbc_cleanup_status;
	ambr_ie mn_ambr;
	bool sgwu_changed;

	uint8_t uli_flag;
	user_loc_info_t uli;
	user_loc_info_t old_uli;

	ue_tz old_ue_tz;
	bool old_ue_tz_valid;

	bool eci_changed;
	bool ltem_rat_type_flag;
	bool serving_nw_flag;
	serving_nwrk_t serving_nw;
	bool rat_type_flag;
	rat_type_t rat_type;
	rat_type_t old_rat_type;
	bool old_rat_valid;

	uint8_t is_sent_bearer_rsc_failure_indc;

	secondary_rat_t second_rat[MAX_BEARERS];
	bool second_rat_flag;
	uint8_t second_rat_count;
	uint8_t change_report_action;
	bool change_report;
	bool piggyback;

	indication_flag_t indication_flag;
	bool ue_time_zone_flag;
	ue_tz tz;
	bool uci_flag;
	user_csg_i uci;
	bool mo_exception_flag;
	bool mme_changed_flag;
	counter mo_exception_data_counter;
	uint8_t bearer_count;

#ifdef USE_CSID
	/* Temp cyclic linking of the MME and SGW FQ-CSID */
	sess_fqcsid_t *mme_fqcsid;
	sess_fqcsid_t *sgw_fqcsid;
	sess_fqcsid_t *pgw_fqcsid;
	sess_fqcsid_t *up_fqcsid;
#endif /* USE_CSID */

	uint32_t sequence;
	uint8_t pfcp_sess_count;
	uint8_t selection_flag;
	selection_mode select_mode;

	uint8_t up_selection_flag;
	uint8_t promotion_flag;
	uint8_t dcnr_flag;

	uint32_t s11_sgw_gtpc_teid;
	node_address_t s11_sgw_gtpc_ip;

	uint32_t s11_mme_gtpc_teid;
	node_address_t s11_mme_gtpc_ip;

	uint16_t bearer_bitmap;
	uint16_t teid_bitmap;
	uint8_t num_pdns;

	struct pdn_connection_t *pdns[MAX_BEARERS];

	/*VS: TODO: Move bearer information in pdn structure and remove from UE context */
	struct eps_bearer_t *eps_bearers[MAX_BEARERS*2]; /* index by ebi - 1 */

	/* temporary bearer to be used during resource bearer cmd -
	 * create/deletee bearer req - rsp */
	struct eps_bearer_t *ded_bearer;
	uint64_t event_trigger;
	uint8_t procedure;
	uint8_t upd_pdn_set_ebi_index;

	/* User Level Packet Copying Configurations */
	uint8_t dupl;
	uint8_t li_data_cntr;
	li_data_t li_data[MAX_LI_ENTRIES_PER_UE];

	struct indirect_tunnel_t *indirect_tunnel;    /* maintains bearers and sessions for indirect tunnel */
	uint8_t indirect_tunnel_flag;                 /* indication for presence indirect tunnel */

	/* S1 HO Flag to forward MBR Req to PGWC */
	uint8_t update_sgw_fteid;
	/* Flag to indicate report response already sent or not*/
	uint8_t pfcp_rept_resp_sent_flag;

	uint8_t pra_flag;
	presence_reproting_area_action_t pre_rptng_area_act;
	presence_reproting_area_info_t pre_rptng_area_info;
} ue_context;

/**
 * @brief  : Maintains pdn connection information
 */
typedef struct pdn_connection_t {
	uint8_t proc;
	uint8_t state;
	uint8_t bearer_control_mode;
	/* Call ID ref. to session id of CCR */
	uint32_t call_id;

	bool flag_fqcsid_modified;
#ifdef USE_CSID
	fqcsid_t mme_csid;
	fqcsid_t sgw_csid;
	fqcsid_t pgw_csid;
	fqcsid_t up_csid;
#endif /* USE_CSID */


	apn *apn_in_use;
	ambr_ie apn_ambr;
	uint32_t apn_restriction;

	ambr_ie session_ambr;
	ambr_ie session_gbr;

	node_address_t upf_ip;

	uint64_t seid;
	uint64_t dp_seid;

	struct in_addr ipv4;
	uint8_t prefix_len;
	struct in6_addr ipv6;

	/* Need to Discuss teid and IP should be part of UE context */
	uint32_t s5s8_sgw_gtpc_teid;
	node_address_t s5s8_sgw_gtpc_ip;

	bool old_sgw_addr_valid;
	node_address_t old_sgw_addr;

	uint32_t s5s8_pgw_gtpc_teid;
	node_address_t s5s8_pgw_gtpc_ip;

	uint8_t ue_time_zone_flag;
	ue_tz ue_tz;
	ue_tz old_ue_tz;
	bool old_ue_tz_valid;

	uint8_t rat_type;
	uint8_t old_ret_type;
	bool old_rat_type_valid;

	int16_t mapped_ue_usage_type;

	uint8_t requested_pdn_type;

	pdn_type_ie pdn_type;
	/* See  3GPP TS 32.298 5.1.2.2.7 for Charging Characteristics fields*/
	charging_characteristics_ie charging_characteristics;

	uint8_t default_bearer_id;
	/* Need to think on it */
	uint8_t num_bearer;

	/* Create a cyclic linking to access the data structures of UE */
	ue_context *context;

	uint8_t fqdn[FQDN_LEN];
	struct eps_bearer_t *eps_bearers[MAX_BEARERS*2]; /* index by ebi - 1 */

	struct eps_bearer_t *packet_filter_map[MAX_FILTERS_PER_UE];

	char gx_sess_id[MAX_LEN];

	/*Structure used to store rule status for sending
	 * provision ack */
	pro_ack_rule_array_t pro_ack_rule_array;

	/* need to maintain reqs ptr for RAA*/
	unsigned long rqst_ptr;
	policy_t policy;

	/* timer entry data for stop timer session */
	peerData *timer_entry;

	/* CSR sequence number for identify CSR retransmission req. */
	uint32_t csr_sequence;
	/* need to maintain DNS query Domain type */
	uint8_t dns_query_domain;

	void *node_sel;
	uint8_t enb_query_flag;
	uint8_t generate_cdr;

	uint8_t num_ddn_sent_count;    /*number of ddn request sent per session*/

	/* As per spec at most one bar per session */
	bar_t bar;

	/* Need to send default DL Buffering Suggested Packet Count in first Report Response */
	uint8_t is_default_dl_sugg_pkt_cnt_sent;

} pdn_connection;

/**
 * @brief  : Maintains eps bearer related information
 */
typedef struct eps_bearer_t {
	uint8_t eps_bearer_id;
	/* Packet Detection identifier/Rule_ID */
	uint8_t pdr_count;
	pdr_t *pdrs[NUMBER_OF_PDR_PER_BEARER];

	/* As per discussion der will be only one qer per bearer */
	uint8_t qer_count;
	qer qer_id[NUMBER_OF_QER_PER_BEARER];

	bearer_qos_ie qos;

	/* To store seq number of incoming req for bearer*/
	uint32_t sequence;

	/*VSD: Fill the ID in intial attach */
	/* Generate ID while creating default bearer */
	uint32_t charging_id;

	/*seq no for each bearer used as CDR field*/
	uint32_t cdr_seq_no;


	node_address_t s1u_sgw_gtpu_ip;
	uint32_t s1u_sgw_gtpu_teid;

	node_address_t s5s8_sgw_gtpu_ip;
	uint32_t s5s8_sgw_gtpu_teid;

	node_address_t s5s8_pgw_gtpu_ip;
	uint32_t s5s8_pgw_gtpu_teid;

	node_address_t s1u_enb_gtpu_ip;
	uint32_t s1u_enb_gtpu_teid;

	node_address_t s11u_mme_gtpu_ip;
	uint32_t s11u_mme_gtpu_teid;

	node_address_t s11u_sgw_gtpu_ip;
	uint32_t s11u_sgw_gtpu_teid;

	struct pdn_connection_t *pdn;

	uint8_t num_packet_filters;
	int packet_filter_map[MAX_FILTERS_PER_UE];
	int flow_desc_check;
	int qos_bearer_check;
	int arp_bearer_check;
	uint8_t num_dynamic_filters;
	dynamic_rule_t *dynamic_rules[MAX_RULE_PER_BEARER];

	/* Predefined rule support */
	uint8_t num_prdef_filters;
	dynamic_rule_t *prdef_rules[MAX_RULE_PER_BEARER];
	enum rule_action_t action;

} eps_bearer;

/**
 * @brief : Stores data TEID and Msg_type as data for the use of error handling.
 */
typedef struct teid_value_t
{
	uint32_t teid;
	uint8_t msg_type;
} teid_value_t;

/**
 * @brief : Rule Name is key for Mapping of Rules and Bearer table.
 */
typedef struct teid_seq_map_key {
	/** Rule Name */
	char teid_key[RULE_NAME_LEN];
}teid_key_t;


/**
 *  @brief  : Maintains sessions and bearers created
 * for indirect tunnel data transmission.
 * */
struct indirect_tunnel_t {
	pdn_connection *pdn;
	uint8_t anchor_gateway_flag;
	/*This bearer is UE context default bearer id */
	uint8_t eps_bearer_id;
};

/*@brief: maintains pdr array for ddn requests */
typedef struct pdr_ids_t{
	uint8_t pdr_count;              /* pdr id count*/
	uint16_t pdr_id[MAX_LIST_SIZE]; /* rule ids array*/
}pdr_ids;

/*@brief: maintains pdr array for ddn requests */
typedef struct sess_info_t{
	uint64_t sess_id;                   /*session id*/
	uint8_t pdr_count;                 /* pdr id  count */
	uint16_t pdr_id[MAX_LIST_SIZE];   /* rule ids array*/
	struct sess_info_t *next;
}sess_info;

#pragma pack()

extern struct rte_hash *ue_context_by_imsi_hash;
extern struct rte_hash *ue_context_by_fteid_hash;
extern struct rte_hash *ue_context_by_sender_teid_hash;

extern apn apn_list[MAX_NB_DPN];
extern int apnidx;

/**
 * @brief  : Initializes UE hash table
 * @param  : No param
 * @return : Returns nothing
 */
void
create_ue_hash(void);

/**
 * @brief  : creates an UE Context (if needed), and pdn connection with a default bearer
 *           given the UE IMSI, and EBI
 * @param  : imsi
 *           value of information element of the imsi
 * @param  : imsi_len
 *           length of information element of the imsi
 * @param  : ebi
 *           Eps Bearer Identifier of default bearer
 * @param  : context
 *           UE context to be created
 * @param  : cp_mode
 *           [SGWC/SAEGWC/PGWC]
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to
 *           3gpp specified cause error value
 *           - < 0 for all other errors
 */
int
create_ue_context(uint64_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, apn *apn_requested,
		uint32_t sequence, uint8_t *check_ue_hash,
		uint8_t cp_mode);

/**
 * Create the ue eps Bearer context by PDN (if needed), and key is sgwc s5s8 teid.
 * @param fteid_key
 *    value of information element of the sgwc s5s8 teid
 * @param bearer
 *  Eps Bearer context
 * @return
 *    \- 0 if successful
 *    \- > if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 *   \- < 0 for all other errors
*/
int
add_bearer_entry_by_sgw_s5s8_tied(uint32_t fteid_key, struct eps_bearer_t **bearer);


/**
 * @brief  : This function takes the c-string argstr describing a apn by url, for example
 *           label1.label2.label3 and populates the apn structure according 3gpp 23.003
 *           clause 9.1
 * @param  : an_apn
 *           apn to be initialized
 * @param  : argstr
 *           c-string containing the apn label
 * @return : Returns nothing
 */
void
set_apn_name(apn *an_apn, char *argstr);


/**
 * @brief  : returns the apn strucutre of the apn referenced by create session message
 * @param  : apn_label
 *           apn_label within a create session message
 * @param  : apn_length
 *           the length as recorded by the apn information element
 * @return : the apn label configured for the CP
 */
apn *
get_apn(char *apn_label, uint16_t apn_length);

/**
 * @brief  : returns the apn strucutre for default apn(Forwarding Gateway-S1 HO)
 * @param  : void
 * @return : the apn label configured for the CP
 */
apn *
set_default_apn(void);

/**
 * @brief  : Simple ip-pool
 * @param  : ip_pool, IP subnet ID
 * @param  : ip_pool_mask, Mask to be used
 * @param  : ipv4
 *           ip address to be used for a new UE connection
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to
 *           3gpp specified cause error value
 */
uint32_t
acquire_ip(struct in_addr ip_pool,	struct in_addr ip_pool_mask,
											struct in_addr *ipv4);

/**
 * @brief  : Simple ip-pool for ipv6
 * @param  : ipv6_network_id, Prefix for IPv6 creation
 * @param  : prefix_len, bearer_id that need to be used for IPv6 allocation
 * @param  : ipv6
 *           ip address to be used for a new UE connection
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to
 *           3gpp specified cause error value
 */
uint32_t
acquire_ipv6(struct in6_addr ipv6_network_id, uint8_t prefix_len,
											struct in6_addr *ipv6);

/* debug */

/**
 * @brief  : print (with a column header) either context by the context and/or
 *           iterating over hash
 * @param  : h
 *           pointer to rte_hash containing ue hash table
 * @param  : context
 *           denotes if some context is to be indicated by '*' character
 * @return : Returns nothing
 */
void
print_ue_context_by(struct rte_hash *h, ue_context *context);

/**
 * @brief  : Initializes LI-DF IMSI hash table
 * @param  : No param
 * @return : Returns nothing
 */
void
create_li_info_hash(void);

/**
 * @brief  : fill and send pfcp session modification with drop flag set
 * @param  : context, ue context
 * @return : Returns 0 on success and -1 on error
 */
int
send_pfcp_sess_mod_with_drop(ue_context *context);
#endif /* UE_H */
