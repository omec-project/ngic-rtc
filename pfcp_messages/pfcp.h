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

#ifndef PFCP_H
#define PFCP_H

#ifdef CP_BUILD
#include "cp.h"
#include "gx_app/include/gx_struct.h"
#include "pfcp_struct.h"


struct rte_hash *pfcp_cntxt_hash;
struct rte_hash *pdr_entry_hash;
struct rte_hash *qer_entry_hash;
struct rte_hash *urr_entry_hash;
struct rte_hash *pdn_conn_hash;
struct rte_hash *rule_name_bearer_id_map_hash;

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
extern struct in_addr s11_mme_ip;
extern struct sockaddr_in s11_mme_sockaddr;

extern in_port_t s11_port;
extern struct sockaddr_in s11_sockaddr;

extern struct in_addr s5s8_ip;
extern in_port_t s5s8_port;
extern struct sockaddr_in s5s8_sockaddr;

extern struct sockaddr_in s5s8_recv_sockaddr;

extern in_port_t pfcp_port;
extern struct sockaddr_in pfcp_sockaddr;

extern in_port_t upf_pfcp_port;
extern struct sockaddr_in upf_pfcp_sockaddr;

/** Rule Name is key for Mapping of Rules and Bearer table. */
typedef struct rule_name_bearer_id_map_key {
	/** Rule Name */
	char rule_name[255];
}rule_name_key_t;

/** Bearer identifier information */
typedef struct bearer_identifier_t {
	/* Bearer identifier */
	uint8_t bearer_id;
}bearer_id_t;

/*
 * PFCP context information for PDR, QER, BAR and FAR.
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

/* Create a  hash table to maintain the PDR, QER, FAR and BAR information.*/
void
init_pfcp_tables(void);

/**
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information.
 */
void
init_hash_tables(void);

/**
 * Add PDN Connection information in the table.
 */
uint8_t
add_pdn_conn_entry(uint32_t call_id, pdn_connection *pdn);

/**
 * Add Rule name and bearer information in the table.
 */
uint8_t
add_rule_name_entry(const rule_name_key_t rule_key, bearer_id_t *bearer);

/**
 * Add pfcp context information in the table.
 */
uint8_t
add_pfcp_cntxt_entry(uint64_t session_id, struct pfcp_cntxt *resp);

/**
 * Add PDR information in the table.
 */
uint8_t
add_pdr_entry(uint16_t rule_id, pdr_t *cntxt);

/**
 * Add QER information in the table.
 */
uint8_t
add_qer_entry(uint32_t qer_id, qer_t *cntxt);

/**
 * Add URR information in the table.
 */
uint8_t
add_urr_entry(uint32_t urr_id, urr_t *cntxt);

/**
 * Retrive PDN connection entry.
 */
pdn_connection *get_pdn_conn_entry(uint32_t call_id);

/**
 * Retrive Rule Name entry.
 */
int8_t
get_rule_name_entry(const rule_name_key_t rule_key);

/**
 * Retrive pfcp context entry.
 */
struct pfcp_cntxt *
get_pfcp_cntxt_entry(uint64_t session_id);

/**
 * Retrive PDR entry.
 */
pdr_t *get_pdr_entry(uint16_t rule_id);

/**
 * Update PDR entry.
 */
int
update_pdr_teid(eps_bearer *bearer, uint32_t teid, uint32_t ip, uint8_t iface);

/**
 * Retrive QER entry.
 */
qer_t *get_qer_entry(uint32_t qer_id);

/**
 * Retrive URR entry.
 */
urr_t *get_urr_entry(uint32_t urr_id);

/**
 * Delete PDN connection entry from PDN conn table.
 */
uint8_t
del_pdn_conn_entry(uint32_t call_id);

/**
 * Delete Rule Name entry from Rule and Bearer Map table.
 */
uint8_t
del_rule_name_entry(const rule_name_key_t rule_key);

/**
 * Delete context entry from pfcp context table.
 */
uint8_t
del_pfcp_cntxt_entry(uint64_t session_id);

/**
 * Delete PDR entry from QER table.
 */
uint8_t
del_pdr_entry(uint16_t pdr_id);

/**
 * Delete QER entry from QER table.
 */
uint8_t
del_qer_entry(uint32_t qer_id);

/**
 * Delete URR entry from URR table.
 */
uint8_t
del_urr_entry(uint32_t urr_id);

/**
 * Generate the PDR ID [RULE ID]
 */
uint16_t
generate_pdr_id(void);

/**
 * Generate the BAR ID
 */
uint8_t
generate_bar_id(void);

/**
 * Generate the FAR ID
 */
uint32_t
generate_far_id(void);

/*
 * Generate the QER ID
 */
uint32_t
generate_qer_id(void);

/**
 * Generate the CALL ID
 */
uint32_t
generate_call_id(void);

/**
 * Generate the Sequence
 */
uint32_t
generate_rar_seq(void);

/**
 * Retrieve Call ID form CCR Session ID
 */
int
retrieve_call_id(char *str, uint32_t *call_id);

/**
 * Generate the SESSION ID
 */
uint64_t
generate_dp_sess_id(uint64_t cp_sess_id);

/**
 * Generate the CCR Session ID with combination of timestamp and call id.
 */
int8_t
gen_sess_id_for_ccr(char *sess_id, uint32_t call_id);

#ifdef GX_BUILD
/**
 * Parse GX CCA message.
 */

int8_t
parse_gx_cca_msg(GxCCA *cca, ue_context **_context);

/**
 * Parse GX RAR message.
 */
int8_t
parse_gx_rar_msg(GxRAR *rar);

int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt);

#endif /* GX_BUILD */
int
int_to_str(char *buf , uint32_t val);
#endif /* CP_BUILD */
#endif /* PFCP_H */
