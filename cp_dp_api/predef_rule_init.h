
/*
 * Copyright (c) 2020 Sprint
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

#ifndef _PREDEF_RULE_INIT_H
#define _PREDEF_RULE_INIT_H

#include "dp_ipc_api.h"
#ifdef CP_BUILD
#include "packet_filters.h"
#endif
#include "vepc_cp_dp_api.h"

#ifdef CP_BUILD
#include "main.h"
#else
#include "up_main.h"
#endif /* CP_BUILD */

/* Defined the hash table name */
#define PCC_HASH 1
#define SDF_HASH 2
#define MTR_HASH 3
#define ADC_HASH 4
#define RULE_HASH 5

/* Operation Modes of the rules */
#define ADD_RULE 1
#define GET_RULE 2
#define SND_RULE 3
#define DEL_RULE 4

/* PCC Rule name length */
#define MAX_RULE_LEN 256

/* Defined the tables to stored/maintain predefined rules and there
 * associated info.
 */

/**
 * @brief  : rte hash table to maintain the collection of PCC, SDF, MTR, and ADC rules.
 * hash key: ip_addr, Data: struct rules_struct
 */
struct rte_hash *rules_by_ip_addr_hash;

/**
 * @brief  : rte hash table to maintain the pcc rules by rule name.
 * hash key: rule_name, Data: struct pcc_rules
 */
struct rte_hash *pcc_by_rule_name_hash;

/**
 * @brief  : rte hash table to maintain the sdf rules by rule index.
 * hash key: rule_indx, Data: struct sdf_pkt_filter
 */
struct rte_hash *sdf_by_inx_hash;

/**
 * @brief  : rte hash table to maintain the mtr rules by rule index.
 * hash key: rule_indx, Data: struct mtr_entry
 */
struct rte_hash *mtr_by_inx_hash;

/**
 * @brief  : rte hash table to maintain the adc rules by rule index.
 * hash key: rule_indx, Data: struct adc_rules
 */
struct rte_hash *adc_by_inx_hash;

typedef struct pcc_rule_name_key {
	/* pcc rule name*/
	char rname[MAX_RULE_LEN];
}pcc_rule_name;

typedef struct rules_struct_t {
	uint16_t rule_cnt;
	pcc_rule_name rule_name;

	/* LL to contain the list of pcc rules */
	struct rules_struct_t *next;
}rules_struct;

/**
 * @brief  : Function to add rule entry in collection hash table.
 * @param  : head, new_node.
 * @retrun : 0: Success, -1: Failure
 */
int8_t
insert_rule_name_node(rules_struct *head, rules_struct *new_node);

/**
 * @brief  : Function to add/get/update rule entry in collection hash table.
 * @param  : cp_pfcp_ip key.
 * @param  : is_mod, Operation modes.
 * @retrun : Success: rules_struct, Failure: NULL
 */
rules_struct *
get_map_rule_entry(uint32_t cp_pfcp_ip, uint8_t is_mod);

/**
 * @brief  : Function to delete rule entry in collection hash table.
 * @param  : cp_pfcp_ip key.
 * @retrun : 0: Success, -1: Failure
 */
int8_t
del_map_rule_entry(uint32_t cp_pfcp_ip);

/**
 * @brief  : Function to add/get/update rule entry of SDF,MTR,ADC in hash table.
 * @param  : rule_indx, SDF, MTR, and ADC rule index value.
 * @param  : hash_type, Selection of table, Ex. SDF_TABLE, ADC_TABLE etc.
 * @param  : is_mod, Operation modes, Ex. ADD_RULE, UPDATE_RULE etc
 * @param  : data, return SDF, MTR, and ADC rule.
 * @retrun : 0: Success, -1: Failure
 */
int8_t
get_predef_rule_entry(uint16_t rule_indx, uint8_t hash_type,
		uint8_t is_mod, void **data);

/**
 * @brief  : Function to delete rule entry of SDF,MTR,ADC in hash table.
 * @param  : rule_indx, SDF, MTR, and ADC rule index value.
 * @param  : hash_type, Selection of table, Ex. SDF_TABLE, ADC_TABLE etc.
 * @retrun : 0: Success, -1: Failure
 */
int8_t
del_predef_rule_entry(uint16_t rule_indx, uint8_t hash_type);

/**
 * @brief  : Function to add/get/update rule entry of pcc in hash table.
 * @param  : rule_name, pcc rule name.
 * @param  : is_mod, Operation modes, Ex. ADD_RULE, UPDATE_RULE etc
 * @retrun : Success: struct pcc_rules, Failure: NULL
 */
struct pcc_rules *
get_predef_pcc_rule_entry(const pcc_rule_name *rule_name, uint8_t is_mod);

/**
 * @brief  : Function to delete rule entry of SDF,MTR,ADC in hash table.
 * @param  : rule_name, pcc rule name.
 * @retrun : 0: Success, -1: Failure
 */
int8_t
del_predef_pcc_rule_entry(const pcc_rule_name *rule_name);

/* Create and initialize the tables to maintain the predefined rules info*/
void
init_predef_rule_hash_tables(void);

/**
 * @brief  : Pack the message which has to be sent to DataPlane.
 * @param  : mtype
 *           mtype - Message type.
 * @param  : param
 *           param - parameter to be parsed based on msg type.
 * @param  : msg_payload
 *           msg_payload - message payload to be sent.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
build_rules_up_msg(enum dp_msg_type mtype, void *param, struct msgbuf *msg_payload);
#endif /* _PREDEF_RULE_INIT_H */
