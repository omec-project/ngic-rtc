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
#include "restoration_timer.h"

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

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

#define MAX_BEARERS                  (15)
#define MAX_FILTERS_PER_UE           (16)

#define MAX_NETCAP_LEN               (64)

#define MAX_APN_LEN               (64)


#define GET_UE_IP(ue_index) \
			(((pfcp_config.ip_pool_ip.s_addr | (~pfcp_config.ip_pool_mask.s_addr)) \
			  - htonl(ue_index)) - 0x01000000)

#ifndef CP_BUILD
#define FQDN_LEN 256
#endif

/* Need to handle case of multiple charging rule for signle bearer
 * this count will change once added handling
 * */
#define NUMBER_OF_PDR_PER_BEARER 2
#define NUMBER_OF_QER_PER_BEARER 2

#define QER_INDEX_FOR_ACCESS_INTERFACE 0
#define QER_INDEX_FOR_CORE_INTERFACE 1


#define CSR_SEQUENCE(x) (\
	(x->header.gtpc.teid_flag == 1)? x->header.teid.has_teid.seq : x->header.teid.no_teid.seq \
	)
struct eps_bearer_t;
struct pdn_connection_t;

/**
 * @brief  : Maintains CGI (Cell Global Identifier) data from user location information
 */
typedef struct cgi_t {
	uint8_t cgi_mcc_digit_2;
	uint8_t cgi_mcc_digit_1;
	uint8_t cgi_mnc_digit_3;
	uint8_t cgi_mcc_digit_3;
	uint8_t cgi_mnc_digit_2;
	uint8_t cgi_mnc_digit_1;
	uint16_t cgi_lac;
	uint16_t cgi_ci;
} cgi_t;

/**
 * @brief  : Maintains SAI (Service Area Identifier) data from user location information
 */
typedef struct sai_t {
	uint8_t sai_mcc_digit_2;
	uint8_t sai_mcc_digit_1;
	uint8_t sai_mnc_digit_3;
	uint8_t sai_mcc_digit_3;
	uint8_t sai_mnc_digit_2;
	uint8_t sai_mnc_digit_1;
	uint16_t sai_lac;
	uint16_t sai_sac;
}sai_t;

/**
 * @brief  : Maintains RAI (Routing Area Identity) data from user location information
 */
typedef struct rai_t {
	uint8_t ria_mcc_digit_2;
	uint8_t ria_mcc_digit_1;
	uint8_t ria_mnc_digit_3;
	uint8_t ria_mcc_digit_3;
	uint8_t ria_mnc_digit_2;
	uint8_t ria_mnc_digit_1;
	uint16_t ria_lac;
	uint16_t ria_rac;
} rai_t;

/**
 * @brief  : Maintains TAI (Tracking Area Identity) data from user location information
 */
typedef struct tai_t {
	uint8_t tai_mcc_digit_2;
	uint8_t tai_mcc_digit_1;
	uint8_t tai_mnc_digit_3;
	uint8_t tai_mcc_digit_3;
	uint8_t tai_mnc_digit_2;
	uint8_t tai_mnc_digit_1;
	uint16_t tai_tac;
} tai_t;

/**
 * @brief  : Maintains LAI (Location Area Identifier) data from user location information
 */
typedef struct lai_t {
	uint8_t lai_mcc_digit_2;
	uint8_t lai_mcc_digit_1;
	uint8_t lai_mnc_digit_3;
	uint8_t lai_mcc_digit_3;
	uint8_t lai_mnc_digit_2;
	uint8_t lai_mnc_digit_1;
	uint16_t lai_lac;
} lai_t;

/**
 * @brief  : Maintains ECGI (E-UTRAN Cell Global Identifier) data from user location information
 */
typedef struct ecgi_t {
	uint8_t ecgi_mcc_digit_2;
	uint8_t ecgi_mcc_digit_1;
	uint8_t ecgi_mnc_digit_3;
	uint8_t ecgi_mcc_digit_3;
	uint8_t ecgi_mnc_digit_2;
	uint8_t ecgi_mnc_digit_1;
	uint8_t ecgi_spare;
	uint32_t eci;
} ecgi_t;

/**
 * @brief  : Maintains Macro eNodeB ID data from user location information
 */
typedef struct macro_enb_id_t {
	uint8_t menbid_mcc_digit_2;
	uint8_t menbid_mcc_digit_1;
	uint8_t menbid_mnc_digit_3;
	uint8_t menbid_mcc_digit_3;
	uint8_t menbid_mnc_digit_2;
	uint8_t menbid_mnc_digit_1;
	uint8_t menbid_spare;
	uint8_t menbid_macro_enodeb_id;
	uint16_t menbid_macro_enb_id2;
} macro_enb_id_t;

/**
 * @brief  : Maintains Extended Macro eNodeB ID data from user location information
 */
typedef struct  extnded_macro_enb_id_t {
	uint8_t emenbid_mcc_digit_2;
	uint8_t emenbid_mcc_digit_1;
	uint8_t emenbid_mnc_digit_3;
	uint8_t emenbid_mcc_digit_3;
	uint8_t emenbid_mnc_digit_2;
	uint8_t emenbid_mnc_digit_1;
	uint8_t emenbid_smenb;
	uint8_t emenbid_spare;
	uint8_t emenbid_extnded_macro_enb_id;
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
	size_t apn_name_length;
	uint8_t apn_idx;
} apn;

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
} sdf_pkt_fltr;

/**
 * @brief  : Maintains flow description data
 */
typedef struct flow_description {
	int32_t flow_direction;
	sdf_pkt_fltr sdf_flw_desc;
	char sdf_flow_description[512];
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
	char rule_name[256];
	char af_charging_id_string[256];
	bearer_qos_ie qos;
	/* Need to think on it */
	uint8_t num_flw_desc;
	flow_desc_t flow_desc[32];
	pdr_t *pdr[2];
}dynamic_rule_t;

enum rule_action_t {
	RULE_ACTION_INVALID,
	RULE_ACTION_ADD = 1,
	RULE_ACTION_MODIFY = 2,
	RULE_ACTION_DELETE = 3,
	RULE_ACTION_MAX
};

typedef struct pcc_rule{
	enum rule_action_t action;
	dynamic_rule_t dyn_rule;
}pcc_rule_t;
/* Currently policy from PCRF can be two thing
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
	uint8_t oi:1;
}indication_flag_t;

/**
 * @brief  : Maintains ue related information
 */
typedef struct ue_context_t {
	uint64_t imsi;
	uint8_t imsi_len;
	uint8_t unathenticated_imsi;
	uint64_t mei;
	uint64_t msisdn;
	uint8_t msisdn_len;

	ambr_ie mn_ambr;
	/*TODO: Move below 3 lines into PDN*/
	user_loc_info_t uli;
	user_loc_info_t old_uli;
	bool old_uli_valid;

	serving_nwrk_t serving_nw;
	rat_type_t rat_type;
	indication_flag_t indication_flag;

#ifdef USE_CSID
	/* Temp cyclic linking of the MME and SGW FQ-CSID */
	fqcsid_t *mme_fqcsid;
	fqcsid_t *sgw_fqcsid;
	fqcsid_t *pgw_fqcsid;
	fqcsid_t *up_fqcsid;
#endif /* USE_CSID */

	int16_t mapped_ue_usage_type;
	uint32_t sequence;

	uint8_t selection_flag;
	selection_mode select_mode;

	uint32_t s11_sgw_gtpc_teid;
	struct in_addr s11_sgw_gtpc_ipv4;
	uint32_t s11_mme_gtpc_teid;
	struct in_addr s11_mme_gtpc_ipv4;

	uint16_t bearer_bitmap;
	uint16_t teid_bitmap;
	uint8_t num_pdns;

	struct pdn_connection_t *pdns[MAX_BEARERS];

	/*VS: TODO: Move bearer information in pdn structure and remove from UE context */
	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 5 */

	/* temporary bearer to be used during resource bearer cmd -
	 * create/deletee bearer req - rsp */
	struct eps_bearer_t *ded_bearer;
	uint64_t event_trigger;

} ue_context;

typedef struct ue_tz_t
{
	uint8_t tz;
	uint8_t dst;
}ue_tz;

/**
 * @brief  : Maintains pdn connection information
 */
typedef struct pdn_connection_t {
	uint8_t proc;
	uint8_t state;
	uint8_t bearer_control_mode;

	/*VS : Call ID ref. to session id of CCR */
	uint32_t call_id;

	apn *apn_in_use;
	ambr_ie apn_ambr;
	uint32_t apn_restriction;

	ambr_ie session_ambr;
	ambr_ie session_gbr;

	struct in_addr upf_ipv4;
	uint64_t seid;
	uint64_t dp_seid;

	struct in_addr ipv4;
	struct in6_addr ipv6;

	/* VS: Need to Discuss teid and IP should be part of UE context */
	uint32_t s5s8_sgw_gtpc_teid;
	struct in_addr s5s8_sgw_gtpc_ipv4;

	bool old_sgw_addr_valid;
	struct in_addr old_sgw_addr;

	uint32_t s5s8_pgw_gtpc_teid;
	struct in_addr s5s8_pgw_gtpc_ipv4;

	uint8_t ue_time_zone_flag;
	ue_tz ue_tz;
	ue_tz old_ue_tz;
	bool old_ue_tz_valid;

	uint8_t rat_type;
	uint8_t old_ret_type;
	bool old_rat_type_valid;


	/* VS: Support partial failure functionality of FQ-CSID */
#ifdef USE_CSID
	/*TODO: Need to think on it */
	uint8_t peer_cnt;
	/* Need to think on index can we use the ebi as index*/
	csid_key *peer_info[MAX_BEARERS];
	/* Collection of the associated peer node CSIDs*/
	fq_csids *csids[MAX_BEARERS];
#endif /* USE_CSID */

	pdn_type_ie pdn_type;
	/* See  3GPP TS 32.298 5.1.2.2.7 for Charging Characteristics fields*/
	charging_characteristics_ie charging_characteristics;

	uint8_t default_bearer_id;
	/* VS: Need to think on it */
	uint8_t num_bearer;

	/* VS: Create a cyclic linking to access the data structures of UE */
	ue_context *context;

	uint8_t fqdn[FQDN_LEN];
	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 1 */

	struct eps_bearer_t *packet_filter_map[MAX_FILTERS_PER_UE];

	char gx_sess_id[MAX_LEN];
	dynamic_rule_t *dynamic_rules[16];

	/* need to maintain reqs ptr for RAA*/
	unsigned long rqst_ptr;
	policy_t policy;

	/* timer entry data for stop timer session */
	peerData *timer_entry;

	/* CSR sequence number for identify CSR retransmission req. */
	uint32_t csr_sequence;

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

	/*VSD: Fill the ID in intial attach */
	/* Generate ID while creating default bearer */
	uint32_t charging_id;

	struct in_addr s1u_sgw_gtpu_ipv4;
	uint32_t s1u_sgw_gtpu_teid;
	struct in_addr s5s8_sgw_gtpu_ipv4;
	uint32_t s5s8_sgw_gtpu_teid;
	struct in_addr s5s8_pgw_gtpu_ipv4;
	uint32_t s5s8_pgw_gtpu_teid;
	struct in_addr s1u_enb_gtpu_ipv4;
	uint32_t s1u_enb_gtpu_teid;

	struct in_addr s11u_mme_gtpu_ipv4;
	uint32_t s11u_mme_gtpu_teid;

	struct pdn_connection_t *pdn;

	uint8_t num_packet_filters;
	int packet_filter_map[MAX_FILTERS_PER_UE];

	uint8_t num_dynamic_filters;
	dynamic_rule_t *dynamic_rules[16];

} eps_bearer;

extern struct rte_hash *ue_context_by_imsi_hash;
extern struct rte_hash *ue_context_by_fteid_hash;
extern struct rte_hash *pdn_by_fteid_hash;

extern apn apn_list[MAX_NB_DPN];
extern int apnidx;

/**
 * @brief  : sets base teid value given range by DP
 * @param  : val
 *           teid range assigned by DP
 * @return : Returns nothing
 */
void
set_base_teid(uint8_t val);

/**
 * @brief  : sets the s1u_sgw gtpu teid given the bearer
 * @param  : bearer
 *           bearer whose tied is to be set
 * @param  : context
 *           ue context of bearer, whose teid is to be set
 * @return : Returns nothing
 */
void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);


/**
 * @brief  : sets the s5s8_sgw gtpu teid given the bearer
 * @param  : bearer
 *           bearer whose tied is to be set
 * @param  : context
 *           ue context of bearer, whose teid is to be set
 * @return : Returns nothing
 */
void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);


/**
 * @brief  : sets the s5s8_pgw gtpc teid given the pdn_connection
 * @param  : pdn
 *           pdn_connection whose s5s8 tied is to be set
 * @return : Returns nothing
 */
void
set_s5s8_pgw_gtpc_teid(pdn_connection *pdn);

/**
 * @brief  : Initializes UE hash table
 * @param  : No param
 * @return : Returns nothing
 */
void
create_ue_hash(void);

/**
 * @brief  : sets the s5s8_pgw gtpu teid given the bearer
 * @param  : bearer
 *           bearer whose tied is to be set
 * @param  : context
 *           ue context of bearer, whose teid is to be set
 * @return : Returns nothing
 */
void
set_s5s8_pgw_gtpu_teid_using_pdn(eps_bearer *bearer, pdn_connection *pdn);

/**
 * @brief  : sets the s5s8_pgw gtpu teid given the bearer
 * @param  : bearer
 *           bearer whose tied is to be set
 * @param  : context
 *           ue context of bearer, whose teid is to be set
 * @return : Returns nothing
 */
void
set_s5s8_pgw_gtpu_teid(eps_bearer *bearer, ue_context *context);

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
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to
 *           3gpp specified cause error value
 *           - < 0 for all other errors
 */
int
create_ue_context(uint64_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context, apn *apn_requested,
		uint32_t sequence);

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
 * @brief  : assigns the ip pool variable from parsed c-string
 * @param  : ip_str
 *           ip address c-string from command line
 * @return : Returns nothing
 */
void
set_ip_pool_ip(const char *ip_str);


/**
 * @brief  : assigns the ip pool mask variable from parsed c-string
 * @param  : ip_str
 *           ip address c-string from command line
 * @return : Returns nothing
 */
void
set_ip_pool_mask(const char *ip_str);


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
 * @brief  : Simple ip-pool
 * @param  : ipv4
 *           ip address to be used for a new UE connection
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to
 *           3gpp specified cause error value
 */
uint32_t
acquire_ip(struct in_addr *ipv4);

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

#endif /* UE_H */
