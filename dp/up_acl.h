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

#ifndef _UP_ACL_H_
#define _UP_ACL_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of Access Control List.
 */
#include <rte_acl.h>
#include <rte_ip.h>
#include <acl.h>

#include "pfcp_up_struct.h"
#include "vepc_cp_dp_api.h"

#define MAX_ACL_TABLES		1000
#define MAX_SDF_RULE_NUM	32

/**
 * Max pkt filter precedence.
 */
#define MAX_FILTER_PRECE 0x1fffffff

/**
 * DNS filter rule precedence.
 */
#define DNS_FILTER_PRECE MAX_FILTER_PRECE

/**
 * Default SDF Rule ID to DROP (initialization)
 */
#define SDF_DEFAULT_DROP_RULE_ID  (MAX_SDF_RULE_NUM - 1)

/**
 * Default SDF Rule ID
 */
#define SDF_DEFAULT_RULE_ID  1

uint64_t acl_rule_stats[MAX_SDF_RULE_NUM];

/**
 * Function for SDF lookup.
 *
 * @param m
 *	pointer to pkts.
 * @param nb_rx
 *	num. of pkts.
 *
 * @return
 *	array containing search results for each input buf
 */
uint32_t *
sdf_lookup(struct rte_mbuf **m, int nb_rx, uint32_t indx);


/******************** UP SDF functions **********************/

/**
 * Get ACL Table index for SDF entry
 *
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
get_acl_table_indx(struct sdf_pkt_filter *pkt_filter);

/**
 *  Add SDF rules
 *
 * @param  pkt_filter
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_entry_add(uint32_t indx, struct sdf_pkt_filter *pkt_filter);

/**
 *  Create the ACL table and add SDF rules
 *
 *
 * @return
 *    ACL Table index
 */
int
default_up_filter_entry_add(uint32_t precedence, uint8_t direction);

/**
 * Delete SDF rules.
 *
 * @param  ACL Table Index
 *
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_entry_delete(uint32_t indx,
		struct sdf_pkt_filter *pkt_filter_entry);


/**
 * Delete SDF ACL table.
 *
 * @param  ACL Table Index
 *
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_table_delete(uint32_t indx);

/**
 * Add default SDF entry
 *
 * @param Index
 *      ACL Table index
 *
 * @param precedence
 *     PDR precedence
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_default_entry_add(uint32_t indx, uint32_t precedence, uint8_t direction);

/**
 * Modify default SDF entry action
 *
 * @param rule_id
 *      sdf rule_id
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
//int
//up_sdf_default_entry_action_modify(uint32_t rule_id);


//int
//cb_sdf_filter_entry_add(struct msgbuf *msg_payload);

void
qer_gating(pdr_info_t **pdr, uint32_t n, uint64_t *pkts_mask,
			uint64_t *pkts_queue_mask, uint8_t direction);


/* swap the src and dst address for DL traffic.*/
void swap_src_dst_ip(char *str);
#endif /* _UP_ACL_H_ */

