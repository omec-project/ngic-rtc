/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _ACL_DP_H_
#define _ACL_DP_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of Access Control List.
 */
#include <rte_acl.h>
#include <rte_ip.h>

#include "vepc_cp_dp_api.h"

#define MAX_ACL_RULE_NUM	100000
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
#define SDF_DEFAULT_DROP_RULE_ID  (MAX_ACL_RULE_NUM - 1)

/**
 * Default SDF Rule ID
 */
#define SDF_DEFAULT_RULE_ID  1

/**
 * Default ADC Rule ID
 */
#define ADC_DEFAULT_RULE_ID  (MAX_ACL_RULE_NUM - 1)

uint64_t acl_rule_stats[MAX_ACL_RULE_NUM];

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
sdf_lookup(struct rte_mbuf **m, int nb_rx);

/**
 * Function for ADC table lookup for Upsstream traffic.
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
adc_ul_lookup(struct rte_mbuf **m, int nb_rx);
/**
 * Function for ADC table lookup for Downsstream traffic.
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
adc_dl_lookup(struct rte_mbuf **m, int nb_rx);

/**
 * Get SDF ACL table base address.
 *
 * @return
 *	void
 */
void get_sdf_table_base(void **ba, void **as);

/**
 * Get ADC ACL table base address.
 * @param ba
 *	base address of acl config.
 * @param as
 *	base address of acl search struct.
 *
 */
void get_adc_table_base(void **ba, void **as);

/******************** DP SDF functions **********************/
/**
 *  Create SDF rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_table_create(struct dp_id dp_id, uint32_t max_elements);
/**
 *  Delete SDF rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_table_delete(struct dp_id dp_id);

/**
 *  Add SDF rules
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter);

/**
 * Delete SDF rules.
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_filter_entry_delete(struct dp_id dp_id,
				struct pkt_filter *pkt_filter_entry);

/******************** DP ADC functions **********************/
/**
 *  Create ADC rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 *  Delete ADC rules table
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_table_delete(struct dp_id dp_id);

/**
 *  Add ADC rules
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter);

/**
 * Delete ADC rules.
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 * @param  pkt_filter_entry
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_entry_delete(struct dp_id dp_id,
				struct pkt_filter *pkt_filter_entry);

/**
 * Add default SDF entry
 *
 * @param dp_id
 *	dp_id structure
 * @param rule_id
 *      sdf rule_id
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_default_entry_add(struct dp_id dp_id, uint32_t rule_id);

/**
 * Modify default SDF entry action
 *
 * @param dp_id
 *	dp_id structure
 * @param rule_id
 *      sdf rule_id
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_sdf_default_entry_action_modify(struct dp_id dp_id, uint32_t rule_id);

/**
 *  Add default ADC rule
 *
 * @param dp_id
 *	identifier which is unique across DataPlanes.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
dp_adc_filter_default_entry_add(struct dp_id dp_id);

#endif /* _ACL_H_ */
