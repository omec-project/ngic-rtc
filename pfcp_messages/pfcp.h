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

#ifndef PFCP_H
#define PFCP_H

#ifdef CP_BUILD
#include "cp.h"
#include "gx_app/include/gx_struct.h"
#include "pfcp_struct.h"
#include "pfcp_session.h"


struct rte_hash *pdr_entry_hash;
struct rte_hash *qer_entry_hash;
struct rte_hash *pdn_conn_hash;
struct rte_hash *rule_name_bearer_id_map_hash;
struct rte_hash *ds_seq_key_with_teid;

/**
 * @file
 *
 * PFCP definitions and helper macros.
 *
 * GTP Message type definition and GTP header definition according to 3GPP
 * TS 29.274; as well as IE parsing helper functions/macros, and message
 * processing function declarations.
 *
 */
extern peer_addr_t s11_mme_sockaddr;

extern in_port_t s11_port;
extern peer_addr_t s11_sockaddr;

extern struct in_addr s5s8_ip;
extern in_port_t s5s8_port;
extern peer_addr_t s5s8_sockaddr;

extern peer_addr_t s5s8_recv_sockaddr;

extern in_port_t pfcp_port;
extern peer_addr_t pfcp_sockaddr;

extern in_port_t upf_pfcp_port;
extern peer_addr_t upf_pfcp_sockaddr;

#define PFCP_BUFF_SIZE 1024
#define PFCP_RX_BUFF_SIZE 2048
#define ADD_RULE_TO_ALLOW  1
#define ADD_RULE_TO_DENY   2
#define DEFAULT_SDF_RULE_IPV4  "permit out ip from 0.0.0.0/0 0-65535 to 0.0.0.0/0 0-65535"
#define DEFAULT_SDF_RULE_IPV6  "permit out ip from f000:0:0:0:0:0:0:0/4 0-65535 to f000:0:0:0:0:0:0:0/4 0-65535"
#define DEFAULT_FLOW_STATUS_FL_ENABLED  2
#define DEFAULT_FLOW_STATUS_FL_DISABLED 3
#define DEFAULT_PRECEDENCE  10
#define DEFAULT_NUM_SDF_RULE 2
#define DEFAULT_NUM_SDF_RULE_v4_v6  4
#define DEFAULT_RULE_NAME "default_rule_name"

/**
 * @brief : Rule Name is key for Mapping of Rules and Bearer table.
 */
typedef struct rule_name_bearer_id_map_key {
	/** Rule Name */
	char rule_name[RULE_NAME_LEN];
}rule_name_key_t;

/**
 * @brief  : Maintains information for hash key for rule
 */
typedef struct rule_key_t {
	uint64_t cp_seid;
	uint32_t id;
}rule_key_t;

/**
 * @brief : Bearer identifier information
 */
typedef struct bearer_identifier_t {
	/* Bearer identifier */
	uint8_t bearer_id;
}bearer_id_t;


/**
 * @brief : PFCP context information for PDR, QER, BAR and FAR.
 */
struct pfcp_cntxt {
	/* TODO: THIS STRUCTURE STORED CSR INFORMATION UNTIL NOT GETTING CCA FROM GX*/
	/* Number of PDRs */
//	uint8_t create_pdr_count;
//	/* Number of FARs*/
//	uint8_t create_far_count;
//	/* Collection of PDRs */
//	pdr_t pdr[MAX_LIST_SIZE];
//	/* Collection of FARs */
//	far_t far[MAX_LIST_SIZE];

}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * @brief  : Create a  hash table to maintain the PDR, QER, FAR and BAR information.
 * @param  : void
 * @return : Does not return anything
 */
void
init_pfcp_tables(void);

/**
 * @brief  : Initializes the pfcp context hash table used to account for PDR, QER, BAR and FAR rules information.
 * @param  : void
 * @return : Does not return anything
 */
void
init_hash_tables(void);

/**
 * @brief  : Add PDN Connection information in the table.
 * @param  : call_id
 * @param  : pdn connection details
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
add_pdn_conn_entry(uint32_t call_id, pdn_connection *pdn);

/**
 * @brief  : Add Rule name and bearer information in the table.
 * @param  : rule_key
 * @param  : bearer
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
add_rule_name_entry(const rule_name_key_t rule_key, bearer_id_t *bearer);

/**
 * @brief  : Add pfcp context information in the table.
 * @param  : session_id
 * @param  : resp, pfcp context details
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
add_pfcp_cntxt_entry(uint64_t session_id, struct pfcp_cntxt *resp);

/**
 * @brief  : Add PDR information in the table.
 * @param  : rule id
 * @param  : pdr context
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
add_pdr_entry(uint16_t rule_id, pdr_t *cntxt, uint64_t cp_seid);

/**
 * @brief  : Add QER information in the table.
 * @param  : qer id
 * @param  : qer context
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
add_qer_entry(uint32_t qer_id, qer_t *cntxt, uint64_t cp_seid);

/**
 * @brief  : Retrive PDN connection entry.
 * @param  : call id
 * @return : Returns pointer to pdn entry on success , NULL otherwise
 */
pdn_connection *get_pdn_conn_entry(uint32_t call_id);

/**
 * @brief  : Retrive Rule Name entry.
 * @param  : rule_key
 * @return : Return bearer id on success , -1 otherwise
 */
int8_t
get_rule_name_entry(const rule_name_key_t rule_key);

/**
 * @brief  : Retrive pfcp context entry.
 * @param  : session id
 * @return : Returns pointer to pfcp context, NULL otherwise
 */
struct pfcp_cntxt *
get_pfcp_cntxt_entry(uint64_t session_id);

/**
 * @brief  : Retrive PDR entry.
 * @param  : rule id
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns pointer to pdr context, NULL otherwise
 */
pdr_t *get_pdr_entry(uint16_t rule_id, uint64_t cp_seid);

/**
 * @brief  : Update PDR entry.
 * @param  : bearer context to be updated
 * @param  : teid to be updated
 * @param  : node_address_t ; IP_address for updation
 * @param  : iface, interface type ACCESS or CORE
 * @return : Returns 0 on success , -1 otherwise
 */
int
update_pdr_teid(eps_bearer *bearer, uint32_t teid, node_address_t addr, uint8_t iface);

/**
 * @brief  : Retrive QER entry.
 * @param  : qer_id
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns pointer to qer context on success , NULL otherwise
 */
qer_t *get_qer_entry(uint32_t qer_id, uint64_t cp_seid);


/**
 * @brief  : Delete PDN connection entry from PDN conn table.
 * @param  : call_id
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
del_pdn_conn_entry(uint32_t call_id);

/**
 * @brief  : Delete Rule Name entry from Rule and Bearer Map table.
 * @param  : rule key
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
del_rule_name_entry(const rule_name_key_t rule_key);

/**
 * @brief  : Delete context entry from pfcp context table.
 * @param  : session id
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
del_pfcp_cntxt_entry(uint64_t session_id);

/**
 * @brief  : Delete PDR entry from QER table.
 * @param  : pdr id
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
del_pdr_entry(uint16_t pdr_id, uint64_t cp_seid);

/**
 * @brief  : Delete QER entry from QER table.
 * @param  : qer id
 * @param  : cp_seid, CP session ID for that UE
 * @return : Returns 0 on success , -1 otherwise
 */
uint8_t
del_qer_entry(uint32_t qer_id, uint64_t cp_seid);

/**
 * @brief  : Generate the PDR ID [RULE ID]
 * @param  : pdr_rule_id_offset, PDR ID offset value
 * @return : Returns pdr id  on success , 0 otherwise
 */
uint16_t
generate_pdr_id(uint16_t *pdr_rule_id_offset);

/**
 * @brief  : Generate the BAR ID
 * @param  : bar_rule_id_offset, BAR ID offset value
 * @return : Returns bar id  on success , 0 otherwise
 */
uint8_t
generate_bar_id(uint8_t *bar_rule_id_offset);

/**
 * @brief  : Generate the FAR ID
 * @param  : far_rule_id_offset, FAR ID offset value
 * @return : Returns far id  on success , 0 otherwise
 */
uint32_t
generate_far_id(uint32_t *far_rule_id_offset);

/**
 * @brief  : Generate the URR ID
 * @param  : urr_rule_id_offset, URR ID offset value
 * @return : Returns far id  on success , 0 otherwise
 */
uint32_t
generate_urr_id(uint32_t *urr_rule_id_offset);

/*
 * @brief  : Generate the QER ID
 * @param  : qer_rule_id_offset, QER ID offset value
 * @return : Returns qer id  on success , 0 otherwise
 */
uint32_t
generate_qer_id(uint32_t *qer_rule_id_offset);

/**
 * @brief  : Generate the CALL ID
 * @param  : void
 * @return : Returns call id  on success , 0 otherwise
 */
uint32_t
generate_call_id(void);

/**
 * @brief  : Generates sequence numbers for sgwc generated
 *           gtpv2c messages for mme
 * @param  : void
 * @return : Returns sequence number on success , 0 otherwise
 */
uint32_t
generate_seq_number(void);

/**
 * @brief  : Retrieve Call ID from CCR Session ID
 * @param  : str represents CCR session ID
 * @param  : call_id , variable to store retrived call id
 * @return : Returns 0  on success , 0 otherwise
 */
int
retrieve_call_id(char *str, uint32_t *call_id);

/**
 * @brief  : Generate the SESSION ID
 * @param  : cp session id
 * @return : Returns dp session id  on success , 0 otherwise
 */
uint64_t
generate_dp_sess_id(uint64_t cp_sess_id);

/**
 * @brief  : Generate the CCR Session ID with combination of timestamp and call id.
 * @param  : sess id
 * @param  : call id
 * @return : Returns 0 on success
 */
int8_t
gen_sess_id_for_ccr(char *sess_id, uint32_t call_id);

void store_presence_reporting_area_info(pdn_connection *pdn_cntxt,
						GxPresenceReportingAreaInformation *pres_rprtng_area_info);

/**
 * @brief  : Parse GX CCA message and fill ue context
 * @param  : cca holds data from gx cca message
 * @param  : _context , ue context to be filled
 * @return : Returns 0 on success, -1 otherwise
 */
int8_t
parse_gx_cca_msg(GxCCA *cca, pdn_connection **_pdn);

/**
 * @brief  : Create a new bearer
 * @param  : pdn, pdn connection details
 * @return : Returns 0 on success, -1 otherwise
 */
int
gx_create_bearer_req(pdn_connection *pdn);

/**
 * @brief  : Delete already existing bearer
 * @param  : pdn, pdn connection details
 * @return : Returns 0 on success, -1 otherwise
 */
int
gx_delete_bearer_req(pdn_connection *pdn);

/**
 * @brief  : Updates the already existing bearer
 * @param  : pdn, pdn connection details
 * @return : Returns 0 on success, -1 otherwise
 */
int
gx_update_bearer_req(pdn_connection *pdn);

/**
 * @brief  : Parse GX RAR message.
 * @param  : rar, rar holds data from gx rar message
 * @param  : pdn_cntxt, pointer structure for pdn information
 * @return : Returns 0 on success, -1 otherwise
 */
int16_t
parse_gx_rar_msg(GxRAR *rar, pdn_connection *pdn_cntxt);

/**
 * @brief  : Get details of charging rule
 * @param  : pdn, pdn connection details
 * @param  : lbi
 * @param  : ded_ebi
 * @param  : ber_cnt
 * @return : Return nothing
 */
void
get_charging_rule_remove_bearer_info(pdn_connection *pdn,
	uint8_t *lbi, uint8_t *ded_ebi, uint8_t *ber_cnt);

/**
 * @brief  : Convert the decimal value into the string
 * @param  : buf , string to store output value
 * @param  : val, value to be converted.
 * @return : Returns length of new string
 */
int
int_to_str(char *buf , uint32_t val);

/**
 * @brief  : Compare default bearer qos
 * @param  : default_bearer_qos
 * @param  : rule_qos
 * @return : Returns 0 on success, -1 otherwise
 */
int8_t
compare_default_bearer_qos(bearer_qos_ie *default_bearer_qos,
		bearer_qos_ie *rule_qos);

/**
 * @brief  : to check whether flow description is changed or not
 * @param  : dyn_rule, old dynamic_rule
 * @param  : dyn_rule, new dynamic_rule
 * @return : Returns 1 if found changed, 0 otherwise
 */
uint8_t
compare_flow_description(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule);

/**
 * @brief  : to check whether bearer qos is changed or not
 * @param  : dyn_rule, old dynamic_rule
 * @param  : dyn_rule, new dynamic_rule
 * @return : Returns 1 if found changed, 0 otherwise
 */
uint8_t
compare_bearer_qos(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule);

/**
 * @brief  : to check whether bearer arp is changed or not
 * @param  : dyn_rule, old dynamic_rule
 * @param  : dyn_rule, new dynamic_rule
 * @return : Returns 1 if found changed, 0 otherwise
 */
uint8_t
compare_bearer_arp(dynamic_rule_t *old_dyn_rule, dynamic_rule_t *new_dyn_rule);

/**
 * @brief  : to change arp values for all the bearers
 * @param  : pdn, pdn
 * @param  : qos, Bearer Qos structure
 * @return : nothing
 */
void
change_arp_for_ded_bearer(pdn_connection *pdn, bearer_qos_ie *qos);

/**
 * Add seg number on tied.
 * @param teid_key : sequence number and proc as a key
 * @param teid_info : structure containing value of TEID and msg_type
 * return 0 or -1
 */
int8_t
add_seq_number_for_teid(const teid_key_t teid_key, struct teid_value_t *teid_value);

/**
 * Add seg number on tied.
 *
 * @param teid_key : sequence number and proc as a key
 * return teid_value structure in case of success otherwise null
 */
teid_value_t *get_teid_for_seq_number(const teid_key_t teid_key);

/**
 * Delete teid entry for seg number.
 * @param teid_key : sequence number and proc as a key
 * return 0 or -1
 */
int8_t
delete_teid_entry_for_seq(const teid_key_t teid_key);
/**
 * @brief  : Fill qos information for bearer form Dynamic rule
 * @param  : bearer , eps bearer to be modified
 * @return : Returns nothing
 */
void
update_bearer_qos(eps_bearer *bearer);

/**
 * @brief  : Store rule name & status for pro ack msg
 * @param  : policy , contains rule & rule action received in CCA-U
 * @param  : pro_ack_rule_array,global var to store rule name & their status
 * @return : Returns 0 on success, else -1
 */
int
store_rule_status_for_pro_ack(policy_t *policy,
		         pro_ack_rule_array_t  *pro_ack_rule_array);

#endif /* CP_BUILD */
#endif /* PFCP_H */
