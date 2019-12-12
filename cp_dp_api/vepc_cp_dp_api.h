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
/***************************CP-DP-Structures**************************/

#ifndef _CP_DP_API_H_
#define _CP_DP_API_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes to describe CP DP APIs.
 */
#include <time.h>
#include "pfcp_ies.h"
#include <rte_ether.h>
/**
 * IPv6 address length
 */
#define IPV6_ADDR_LEN 16

/**
 * Maximum CDR services.
 */
#define MAX_SERVICE 1
/**
 * Maximum PCC rules per session.
 */
#define MAX_PCC_RULES 12
/**
 * Maximum PCC rules per session.
 */
#define MAX_ADC_RULES 16


/**
 * Maximum number of SDF indices that can be referred in PCC rule.
 * Max length of the sdf rules string that will be recieved as part of add
 * pcc entry from FPC. String is list of SDF indices.
 * TODO: Revisit this count
 */
#define MAX_SDF_IDX_COUNT 16
#define MAX_SDF_STR_LEN 4096

/**
 * Maximum buffer/name length
 */
#define MAX_LEN 128
/**
 * @brief  : Defines number of entries in local database.
 *
 * Recommended local table size to remain within L2 cache: 64000 entries.
 * See README for detailed calculations.
 */
#define LDB_ENTRIES_DEFAULT (1024 * 1024 * 4)

#define DEFAULT_DN_NUM 512

/**
 * Gate closed
 */
#define CLOSE 1
/**
 * Gate opened
 */
#define OPEN 0

/**
 * Maximum rating groups per bearer session.
 */
#define MAX_RATING_GRP 6

/**
 * Get pdn from context and bearer id.
 */
#define GET_PDN(x, i) (x->eps_bearers[i]->pdn)
/**
 * default bearer session.
 */
#define DEFAULT_BEARER 5

/**
 * get UE session id
 */
#define UE_SESS_ID(x) ((x & 0xffffffff) >> 4)

/**
 * get bearer id
 */
#define UE_BEAR_ID(x) (x & 0xf)
/**
 * set session id from the combination of
 * unique UE id and Bearer id
 */
#define SESS_ID(ue_id, br_id) (((uint64_t)(ue_id) << 4) | (0xf & (br_id)))

/**
 * MAX DNS Sponsor ID name lenth
 */
#define MAX_DNS_SPON_ID_LEN 16
/**
 * @brief  : Select IPv4 or IPv6.
 */
enum iptype {
	IPTYPE_IPV4 = 0,     /* IPv4. */
	IPTYPE_IPV6,        /* IPv6. */
};

/**
 * @brief  : SDF Rule type field.
 */
enum rule_type {
	RULE_STRING = 0,
	FIVE_TUPLE,
};

/**
 * @brief  : Packet action  field.
 */
enum sess_pkt_action {
	ACTION_NONE = 0,
	ACTION_DROP,
	ACTION_FORWARD,
	ACTION_BUFFER,
	ACTION_NOTIFY_CP,
	ACTION_DUPLICATE,
};

/**
 * @brief  : IPv4 or IPv6 address configuration structure.
 */
struct ip_addr {
	enum iptype iptype;			/* IP type: IPv4 or IPv6. */
	union {
		uint32_t ipv4_addr;		/* IPv4 address*/
		uint8_t  ipv6_addr[IPV6_ADDR_LEN]; /* IPv6 address*/
	} u;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : IPv4 5 tuple rule configuration structure.
 */
struct ipv4_5tuple_rule {
	uint32_t ip_src;	/* Src IP address*/
	uint32_t ip_dst;	/* Dst IP address*/
	uint32_t src_mask;	/* Src Mask*/
	uint32_t dst_mask;	/* Dst Mask*/
	uint16_t sport_s;	/* Range start Src Port */
	uint16_t sport_e;	/* Range end Src Port */
	uint16_t dport_s;	/* Range start Dst Port */
	uint16_t dport_e;	/* Range end Dst Port */
	uint8_t  proto_s;	/* Range start Protocol*/
	uint8_t  proto_e;	/* Range end Protocol*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : IPv6 5 tuple rule configuration structure.
 */
struct ipv6_5tuple_rule {
	uint8_t  ip_src[IPV6_ADDR_LEN];	/* Src IP address*/
	uint8_t  ip_dst[IPV6_ADDR_LEN];	/* Dst IP address*/
	uint32_t src_mask;	/* Src Mask*/
	uint32_t dst_mask;	/* Dst Mask*/
	uint16_t sport_s;	/* Range start Src Port */
	uint16_t sport_e;	/* Range end Src Port */
	uint16_t dport_s;	/* Range start Dst Port */
	uint16_t dport_e;	/* Range end Dst Port */
	uint8_t  proto_s;	/* Range start Protocol*/
	uint8_t  proto_e;	/* Range end Protocol*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : 5 tuple rule configuration structure.
 */
struct  five_tuple_rule {
	enum iptype iptype; /* IP type: IPv4 or IPv6. */
	union {
		struct ipv4_5tuple_rule ipv4;
		struct ipv6_5tuple_rule ipv6;
	} u;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Packet filter configuration structure.
 */
struct service_data_list {
	uint32_t	service[MAX_SERVICE];	/* list of service id*/
	/* TODO: add other members*/
} ;

/**
 * @brief  : SDF Packet filter configuration structure.
 */
struct pkt_filter {
	uint32_t pcc_rule_id;				/* PCC rule id*/
	union {
		char rule_str[MAX_LEN];		/* string of rule, please refer
						 * cp/main.c for example
						 * TODO: rule should be in struct five_tuple_rule*/
		struct five_tuple_rule rule_5tp;	/* 5 Tuple rule.
							 * This field is currently not used*/
	} u;
	enum rule_type sel_rule_type;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  :  DNS selector type.
 */
enum selector_type {
	DOMAIN_NAME = 0,		/* Domain name. */
	DOMAIN_IP_ADDR,			/* Domain IP address */
	DOMAIN_IP_ADDR_PREFIX,	/* Domain IP prefix */
	DOMAIN_NONE
};

/**
 * @brief  : IPv4 or IPv6 address configuration structure.
 */
struct ip_prefix {
	struct ip_addr ip_addr;	/* IP address*/
	uint16_t prefix;		/* Prefix*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Redirect configuration structure.
 */
struct  redirect_info {
	uint32_t info;
};

/**
 * @brief  : QoS parameters structure for DP
 */
struct qos_info {
	uint16_t ul_mtr_profile_index; /* index 0 to skip */
	uint16_t dl_mtr_profile_index; /* index 0 to skip */
	uint16_t ul_gbr_profile_index; /* index 0 to skip */
	uint16_t dl_gbr_profile_index; /* index 0 to skip */
	uint8_t qci;    /*QoS Class Identifier*/
	uint8_t arp;    /*Allocation and Retention Priority*/
};

/**
 * @brief  : Application Detection and Control Rule Filter config structure.
 */
struct adc_rules {
	enum selector_type sel_type;	/* domain name, IP addr
					 * or IP addr prefix*/
	union {
		char domain_name[MAX_LEN];	/* Domain name. */
		struct ip_addr domain_ip;	/* Domain IP address */
		struct ip_prefix domain_prefix;	/* Domain IP prefix */
	} u;
	uint32_t rule_id;				/* Rule ID*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));


/**
 * @brief  : Metering Methods.
 */
enum mtr_mthds {
	SRTCM_COLOR_BLIND = 0,	/* Single Rate Three Color Marker - Color blind*/
	SRTCM_COLOR_AWARE,     /* Single Rate Three Color Marker - Color aware*/
	TRTCM_COLOR_BLIND,	/* Two Rate Three Color Marker - Color blind*/
	TRTCM_COLOR_AWARE,	/* Two Rate Three Color Marker - Color aware*/
};

/**
 * @brief  : Meter profile parameters
 */
struct mtr_params {
	/* Committed Information Rate (CIR). Measured in bytes per second.*/
	uint64_t cir;
	/* Committed Burst Size (CBS).  Measured in bytes.*/
	uint64_t cbs;
	/* Excess Burst Size (EBS).  Measured in bytes.*/
	uint64_t ebs;
	/* TODO: add TRTCM params */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Meter Profile entry config structure.
 */
struct mtr_entry {
	uint16_t mtr_profile_index;	/* Meter profile index*/
	struct mtr_params mtr_param;	/* Meter params*/
	uint8_t  metering_method;	/* Metering Methods
								 * -fwd, srtcm, trtcm*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Direction on which the session is applicable.
 */
enum sess_direction {
	SESS_UPLINK = 0,/* rule applicable for Uplink. */
	SESS_DOWNLINK,	/* rule applicable for Downlink*/
};

/**
 * @brief  : UpLink S1u interface config structure.
 */
struct ul_s1_info {
	uint32_t sgw_teid;		/* SGW teid*/
	uint32_t s5s8_pgw_teid; 	/* PGW teid */
	struct ip_addr enb_addr;	/* eNodeB address*/
	struct ip_addr sgw_addr;	/* Serving Gateway address*/
	struct ip_addr s5s8_pgwu_addr;	/* S5S8_PGWU address*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : DownLink S1u interface config structure.
 */
struct dl_s1_info {
	uint32_t enb_teid;		/* eNodeB teid*/
	struct ip_addr enb_addr;	/* eNodeB address*/
	struct ip_addr sgw_addr;	/* Serving Gateway address*/
	struct ip_addr s5s8_sgwu_addr;	/* S5S8_SGWU address*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Policy and Charging Control structure for DP
 */
struct pcc_rules {
	uint32_t rule_id;			/* Rule ID*/
	char rule_name[MAX_LEN];		/* Rule Name*/
	uint32_t rating_group;			/* Group rating*/
	uint32_t service_id;			/* identifier for the service or the service component
						 * the service data flow relates to.*/
	uint8_t rule_status;			/* Rule Status*/
	uint8_t  gate_status;			/* gate status indicates whether the service data flow,
						 * detected by the service data flow filter(s),
						 * may pass or shall be discarded*/
	uint8_t  session_cont;			/* Total Session Count*/
	uint8_t  report_level;			/* Level of report*/
	uint32_t  monitoring_key;		/* key to identify monitor control instance that shall
						 * be used for usage monitoring control of the service
						 * data flows controlled*/
	char sponsor_id[MAX_LEN];		/* to identify the 3rd party organization (the
						 * sponsor) willing to pay for the operator's charge*/
	struct  redirect_info redirect_info;	/* Redirect  info*/
	uint32_t precedence;			/* Precedence*/
	uint64_t drop_pkt_count;		/* Drop count*/
	uint32_t adc_idx; //GCC_Security flag
	uint32_t sdf_idx_cnt;
	uint32_t sdf_idx[MAX_SDF_IDX_COUNT];
	struct qos_info qos;			/* QoS Parameters*/
	uint8_t  charging_mode;			/* online and offline charging*/
	uint8_t  metering_method;		/* Metering Methods
						 * -fwd, srtcm, trtcm*/
	uint8_t  mute_notify;			/* Mute on/off*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Maintains cdr details
 */
struct cdr {
	uint64_t bytes;
	uint64_t pkt_count;
};
/**
 * @brief  : Volume based Charging
 */
struct chrg_data_vol {
	struct cdr ul_cdr;		/* Uplink cdr*/
	struct cdr dl_cdr;		/* Downlink cdr*/
	struct cdr ul_drop;		/* Uplink dropped cdr*/
	struct cdr dl_drop;		/* Downlink dropped cdr*/
};

/**
 * @brief  : Rating group index mapping Data structure.
 */
struct rating_group_index_map {
	uint32_t rg_val;				/* Rating group*/
	uint8_t rg_idx;					/* Rating group index*/
};

/**
 * @brief  : IP-CAN Bearer Charging Data Records
 */
struct ipcan_dp_bearer_cdr {
	uint32_t charging_id;			/* Bearer Charging id*/
	uint32_t pdn_conn_charging_id;		/* PDN connection charging id*/
	struct tm record_open_time;		/* Record time*/
	uint64_t duration_time;			/* duration (sec)*/
	uint8_t	record_closure_cause;		/* Record closure cause*/
	uint64_t record_seq_number;		/* Sequence no.*/
	uint8_t charging_behavior_index; 	/* Charging index*/
	uint32_t service_id;			/* to identify the service
						 * or the service component
						 * the bearer relates to*/
	char sponsor_id[MAX_DNS_SPON_ID_LEN];	/* to identify the 3rd party organization (the
						 * sponsor) willing to pay for the operator's charge*/
	struct service_data_list service_data_list; /* List of service*/
	uint32_t rating_group;			/* rating group of this bearer*/
	uint64_t vol_threshold;			/* volume threshold in MBytes*/
	struct chrg_data_vol data_vol;		/* charing per UE by volume*/
	uint32_t charging_rule_id;			/* Charging Rule ID*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));


/**
 * @brief  : Bearer Session information structure
 */
struct session_info {
	struct ip_addr ue_addr;						/* UE ip address*/
	struct ul_s1_info ul_s1_info;					/* UpLink S1u info*/
	struct dl_s1_info dl_s1_info;					/* DownLink S1u info*/
	uint8_t bearer_id;						/* Bearer ID*/

	/* PCC rules related params*/
	uint32_t num_ul_pcc_rules;					/* No. of UL PCC rule*/
	uint32_t ul_pcc_rule_id[MAX_PCC_RULES]; 			/* PCC rule id supported in UL*/
	uint32_t num_dl_pcc_rules;					/* No. of PCC rule*/
	uint32_t dl_pcc_rule_id[MAX_PCC_RULES];				/* PCC rule id*/

	/* ADC rules related params*/
	uint32_t num_adc_rules;					/* No. of ADC rule*/
	uint32_t adc_rule_id[MAX_ADC_RULES]; 			/* List of ADC rule id*/

	/* Charging Data Records*/
	struct ipcan_dp_bearer_cdr ipcan_dp_bearer_cdr;			/* Charging Data Records*/
	uint32_t client_id;

	uint64_t sess_id;						/* session id of this bearer
									 * last 4 bits of sess_id
									 * maps to bearer id*/
	uint64_t cp_sess_id;
	uint32_t service_id;						/* Type of service given
									 * given to this session like
									 * Internet, Management, CIPA etc
									 */
	uint32_t ul_apn_mtr_idx;		/* UL APN meter profile index*/
	uint32_t dl_apn_mtr_idx;		/* DL APN meter profile index*/
	enum sess_pkt_action action;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));


/**
 * @brief  : DataPlane identifier information structure.
 */
struct dp_id {
	uint64_t id;			/* table identifier.*/
	char name[MAX_LEN];		/* name string of identifier*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Type of CDR record to be flushed.
 */
enum cdr_type {
    CDR_TYPE_BEARER,
    CDR_TYPE_ADC,
    CDR_TYPE_FLOW,
    CDR_TYPE_RG,
    CDR_TYPE_ALL
};
/**
 * @brief  : Structure to flush different types of UE CDRs into file.
 */
struct msg_ue_cdr {
    uint64_t session_id;    /* session id of the bearer, this field
							 * should have same value as set in sess_id
							 * in struct session_info during session create.*/
    enum cdr_type type;     /* type of cdrs to flush. It can be
							 * either Bearer, ADC, FLOW, Rating group
							 * or all. Please refer enum cdr_type for values*/
    uint8_t action;         /* 0 to append and 1 to clear old logs and
							 * write new logs into cdr log file.*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

#ifdef DP_BUILD
/**
 * @brief  : SDF Packet filter configuration structure.
 */
struct sdf_pkt_filter {
	uint32_t precedence;				/* Precedence */
	union {
		char rule_str[MAX_LEN];		/* string of rule, please refer
						 * cp/main.c for example
						 * TODO: rule should be in struct five_tuple_rule*/
		struct five_tuple_rule rule_5tp;	/* 5 Tuple rule.
							 * This field is currently not used*/
	} u;
	enum rule_type sel_rule_type;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Structure to downlink data notification ack information struct.
 */
struct downlink_data_notification_ack_t {

	/* todo! more to implement... see table 7.2.11.2-1
	 * 'recovery: this ie shall be included if contacting the peer
	 * for the first time'
	 */
	/* */
	uint64_t dl_buff_cnt;
	uint64_t dl_buff_duration;
};

/*
 * @brief  : Structure to store information for sending End Marker
 */
struct sess_info_endmark {
	uint32_t teid;
	uint32_t dst_ip;
	uint32_t src_ip;
	uint8_t dst_port;
	uint8_t src_port;
	struct ether_addr source_MAC;
	struct ether_addr destination_MAC;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Create and send endmarker packet
 * @param  : edmk, holds information to fill in packet
 * @return : Returns nothing
 */
void
build_endmarker_and_send(struct sess_info_endmark *edmk);

#endif 	/* DP_BUILD */

#define MAX_NB_DPN	8  /* Note: MAX_NB_DPN <= 8 */

/********************* SDF Pkt filter table ****************/
/**
 * @brief  : Function to create Service Data Flow (SDF) filter
 *           table. This table is used to detect SDFs that each packet belongs to.
 *           It allows to configure 5 tuple rules to classify
 *           incomming traffic.
 * @param  : dp_id
 *           table identifier.
 * @param  : max_elements
 *           max number of rules that can be configured
 *           in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
sdf_filter_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * @brief  : Delete SDF filter table. For deleting this table,
 *           make sure dp_id match with the one used when table created.
 * @param  : dp_id
 *           table identifier.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
sdf_filter_table_delete(struct dp_id dp_id);

/**
 * @brief  : Add SDF filter entry. This api allows to configure SDF filter.
 *           Each filters are 5 tuple based and should be configured with unique pcc_rule_id
 *           and precedence.
 *           Please refer test/simu_cp/simu_cp.c for an example.
 * @param  : dp_id
 *           table identifier.
 * @param  : pkt_filter_entry
 *           sdf packet filter entry structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
sdf_filter_entry_add(struct dp_id dp_id, struct pkt_filter pkt_filter_entry);

/**
 * @brief  : Delete SDF filter entry. For deleting an entry,
 *            only pcc_rule_id is necessary. All other field can be left NULL.
 * @param  : dp_id
 *           table identifier.
 * @param  : pkt_filter_entry
 *           sdf packet filter entry structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
sdf_filter_entry_delete(struct dp_id dp_id, struct pkt_filter pkt_filter_entry);

/********************* ADC Rule Table ****************/
/**
 * @brief  : Function to create Application Detection and
 *           Control (ADC) table.
 *           This table allow to configure ADC rules. Each rules
 *           will have unique ADC id.
 * @param  : dp_id
 *           table identifier.
 * @param  : max_elements
 *           max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int adc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * @brief  : Destroy ADC table. For deleting this table,
 *           make sure dp_id match with the one used when table created.
 * @param  : dp_id
 *           table identifier.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int adc_table_delete(struct dp_id dp_id);

/**
 * @brief  : Add entry in Application Detection and Control (ADC) table.
 *           This API allows to add an ADC rule. Each entry should have unique ADC rule_id.
 *           Please refer "struct adc_rules" for detailed information about the
 *           variabled that can be configured.
 * @param  : dp_id
 *           table identifier.
 * @param  : entry
 *           element to be added in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int adc_entry_add(struct dp_id dp_id, struct adc_rules entry);

/**
 * @brief  : Delete entry in ADC table. For deleting an entry,
 *            only ADC id is necessary. All other field can be left NULL.
 * @param  : dp_id
 *           table identifier.
 * @param  : entry
 *           element to be deleted in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int adc_entry_delete(struct dp_id dp_id, struct adc_rules entry);

/********************* PCC Table ****************/
/**
 * @brief  : Function to create Policy and Charging Control
 *           (PCC) table. This table allow to configure PCC rules.
 *           Each rules must have unique PCC id.
 * @param  : dp_id
 *           table identifier.
 * @param  : max_elements
 *           max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int pcc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * @brief  : Delete PCC table. For deleting this table,
 *           make sure dp_id match with the one used when table created.
 * @param  : dp_id
 *           table identifier.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int pcc_table_delete(struct dp_id dp_id);

/**
 * @brief  : Add entry in Policy and Charging Control
 *           (PCC) table. Each entry should have unique PCC ruleid.
 *           The purpose of the PCC rule is to identify the service the Service
 *           Data Flow (SDF) contributes to, provide applicable charging parameters
 *           for the SDF and provide policy control for the SDF.
 * @param  : dp_id
 *           table identifier.
 * @param  : entry
 *           element to be added in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
pcc_entry_add(struct dp_id dp_id, struct pcc_rules entry);

/**
 * @brief  : Delete entry in PCC table. For deleting an entry,
 *           only PCC id is necessary. All other field can be left NULL.
 * @param  : dp_id
 *           table identifier.
 * @param  : entry
 *           element to be deleted in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
pcc_entry_delete(struct dp_id dp_id, struct pcc_rules entry);

/********************* Bearer Session ****************/
/**
 * @brief  : Function to create Bearer Session table.
 *           This table allow to configure Bearer Sessions per UEs.
 *           Please refer "struct session_info" for the
 *           configurable parameters.
 * @param  : dp_id
 *           table identifier.
 * @param  : max_element
 *           max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int session_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * @brief  : Destroy Bearer Session table. For deleting this table,
 *            make sure dp_id match with the one used when table created.
 * @param  : dp_id
 *           table identifier.
 * @param  : max_element
 *           max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int session_table_delete(struct dp_id dp_id);

/**
 * @brief  : Create UE Session.
 *           This API allows to create Bearer sessions of UEs.
 *           Bearer session can be either per UE or per Bearer per UE based.
 *           In case of per bearer per UE, the last 3 bits of sess_id
 *           maps to bearer id.
 *           To update downlink related params please refer session_modify().
 * @param  : dp_id
 *           table identifier.
 * @param  : session
 *           Session information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
session_create(struct dp_id dp_id, struct session_info session);

/**
 * @brief  : Modify Bearer Session per user.
 *           This API allows to modify Bearer sessions of UEs.
 *           The information regarding uplink and downlink should
 *           be updated when passing session.
 *           If there is mismatch in ul_s1_info this API overwrites
 *           the old rules which were set by session_create().
 * @param  : dp_id
 *           table identifier.
 * @param  : session
 *           Session information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
session_modify(struct dp_id dp_id, struct session_info session);

#ifdef DP_BUILD
/**
 * @brief  : Downlink data notification ack information. The information
 *            regarding downlink should be updated bearer info.
 * @param  : dp_id
 *           table identifier.
 * @param  : ddn_ack
 *           Downlink data notification ack information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
send_ddn_ack(struct dp_id dp_id,
		struct downlink_data_notification_ack_t ddn_ack);


#endif 	/* DP_BUILD */

/**
 * @brief  : To Delete Bearer Session of user. For deleting session,
 *           sess_id must be updated and all other fields can be left NULL.
 * @param  : dp_id
 *           table identifier.
 * @param  : session
 *           Session information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
session_delete(struct dp_id dp_id, struct session_info session);

/********************* Meter Table ****************/
/**
 * @brief  : Create Meter profile table.
 *           This API allows to create a standard meter profile table,
 *           The entries in this table can be used to configure metering
 *           across all UEs.
 * @param  : dp_id
 *           dp_id - table identifier.
 * @param  : max_element
 *           max_element - max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * @brief  : Delete Meter profile table. For deleting this table,
 *            make sure dp_id match with the one used when table created.
 * @param  : dp_id
 *           table identifier.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
meter_profile_table_delete(struct dp_id dp_id);

/**
 * @brief  : Add Meter profile entry. Each entry should be configured
 *           with unique id i.e. mtr_profile_index and with configurable mtr_params.
 *           This meter profile index can be used for PCC metering and APN metering.
 *           When creating PCC rule, the mtr_profile_index has
 *           to be set as per requirement. And when creating Bearer Session
 *           with APN metering, apn_mtr_idx has to be set as per requirement.
 * @param  : dp_id
 *           table identifier.
 * @param  : mtr_entry
 *           meter entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry mtr_entry);

/**
 * @brief  : Delete Meter profile entry. For deleting an entry,
 *            only meter id is necessary. All other field can be left NULL.
 * @param  : dp_id
 *           table identifier.
 * @param  : mtr_entry
 *           meter entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry mtr_entry);

/**
 * @brief  : Function to flush UE CDR records into file.
 *           The cdrs will be dumped on request without resetting
 *           counters in DP.
 *           cdr file is located at "/var/log/dpn/session_cdr.csv".
 * @param  : dp_id
 *           table identifier.
 * @param  : ue_cdr
 *           structre to flush UE CDR. This structure include
 *           session id of the bearer, cdr_type to get the type
 *           of records (cdr_type can be bearer, adc, flow,
 *           rating group or all) and action field to append or
 *           replace the logs. .
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
ue_cdr_flush(struct dp_id dp_id, struct msg_ue_cdr ue_cdr);

#endif /* _CP_DP_API_H_ */
