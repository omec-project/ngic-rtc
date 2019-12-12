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

#include <rte_mbuf.h>

#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl_dp.h"
#include "meter.h"
#include "interface.h"
#include "structs.h"

struct rte_hash *rte_pcc_hash;
extern struct rte_hash *rte_sdf_pcc_hash;
extern struct rte_hash *rte_adc_pcc_hash;
/**
 * @brief  : Called by DP to lookup key-value in PCC table.
 *           This function is thread safe (Read Only).
 * @param  : key32, key
 * @param  : value, Structure to fill result of lookup
 * @return : Returns 0 in case of success , -1 otherwise
 */
int iface_lookup_pcc_data(const uint32_t key32,
					struct dp_pcc_rules **value)
{
	return rte_hash_lookup_data(rte_pcc_hash, &key32, (void **)value);
}

int
dp_pcc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	if (rte_pcc_hash) {
		clLog(clSystemLog, eCLSeverityInfo, "PCC table: \"%s\" exist\n", dp_id.name);
		return 0;
	}

	return hash_create(dp_id.name, &rte_pcc_hash, max_elements * 4,
				   sizeof(uint32_t));
}

int
dp_pcc_table_delete(struct dp_id dp_id)
{
	RTE_SET_USED(dp_id);
	rte_hash_free(rte_pcc_hash);
	return 0;
}

int
dp_pcc_entry_add(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;

	pcc = rte_zmalloc("data", sizeof(struct dp_pcc_rules),
			   RTE_CACHE_LINE_SIZE);
	if (pcc == NULL)
		return -1;
	memcpy(pcc, entry, sizeof(struct pcc_rules));

	key32 = entry->rule_id;
	ret = rte_hash_add_key_data(rte_pcc_hash, &key32,
				  pcc);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Failed to add entry in hash table");
		return -1;
	}

	clLog(clSystemLog, eCLSeverityInfo, "PCC_TBL ADD: rule_id:%u, addr:0x%"PRIx64
			", ul_mtr_idx:%u, dl_mtr_idx:%u, sdf_cnt=%d, adc_idx=%d\n",
			pcc->rule_id, (uint64_t)pcc,
			pcc->qos.ul_mtr_profile_index,
			pcc->qos.dl_mtr_profile_index, pcc->sdf_idx_cnt, pcc->adc_idx);

	/*If there are no SDF indices send(count <0) then ADC parameters are passed.
	 * Either ADC or SDF will be passed.*/
	if (entry->sdf_idx_cnt > 0)
		filter_pcc_entry_add(FILTER_SDF, key32, entry->precedence,
				entry->gate_status, entry->sdf_idx_cnt, entry->sdf_idx);
	else
		filter_pcc_entry_add(FILTER_ADC, key32, entry->precedence,
				entry->gate_status, 1, &entry->adc_idx);
	return 0;
}

int
dp_pcc_entry_delete(struct dp_id dp_id, struct pcc_rules *entry)
{
	struct dp_pcc_rules *pcc;
	uint32_t key32;
	int ret;
	key32 = entry->rule_id;
	ret = rte_hash_lookup_data(rte_pcc_hash, &key32,
				  (void **)&pcc);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Failed to del\n"
			"pcc key 0x%x to hash table\n",
			 key32);
		return -1;
	}
	ret = rte_hash_del_key(rte_pcc_hash, &key32);
	if (ret < 0)
		return -1;

	rte_free(pcc);
	return 0;
}

/******************** Call back functions **********************/
/**
 * @brief  : Call back to parse msg to create pcc rules table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_pcc_table_create(struct msgbuf *msg_payload)
{
	return pcc_table_create(msg_payload->dp_id,
				msg_payload->msg_union.msg_table.max_elements);
}

/**
 * @brief  : Call back to parse msg to delete table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_pcc_table_delete(struct msgbuf *msg_payload)
{
	return pcc_table_delete(msg_payload->dp_id);
}

//static
int cb_pcc_entry_add(struct msgbuf *msg_payload)
{
	return pcc_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * @brief  : Call back to delete pcc rules.
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_pcc_entry_delete(struct msgbuf *msg_payload)
{
	return pcc_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.pcc_entry);
}

/**
 * Initialization of PCC Table Callback functions.
 */
void app_pcc_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_PCC_TBL_CRE, cb_pcc_table_create);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DES, cb_pcc_table_delete);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_ADD, cb_pcc_entry_add);
	iface_ipc_register_msg_cb(MSG_PCC_TBL_DEL, cb_pcc_entry_delete);
}

/**
 * @brief  : Returns insertion position in sorted array, after moving elements.
 *           Capacity of pcc should be n+1
 * @param  : pcc
 *           Pointer to pcc_id_precedence structure
 * @param  : n
 *           no of entries in pcc
 * @param  : precedence
 *           Comparison is based on precedence.
 * @return : Insert position for new element.
 */
static uint32_t
get_insert_position(struct pcc_id_precedence *pcc, uint32_t n,
		uint32_t precedence)
{
	int i;
	for(i = n-1; (i >= 0 && pcc[i].precedence <= precedence); i--)
		pcc[i+1] = pcc[i];
	return i+1;
}

/* --> GCC_security flag */
#if 0
/**
 * @brief  : Returns delete position in sorted array, after moving elements.
 *           Capacity of pcc should be n-1
 * @param  : pcc
 *           Pointer to pcc_id_precedence structure
 * @param  : n
 *           no of entries in pcc
 * @param  : precedence
 *           Comparison is based on precedence.
 * @return : Insert position for new element.
 */
static uint32_t
get_delete_position(struct pcc_id_precedence *pcc, uint32_t n,
		uint32_t pcc_id)
{
	int i;
	for(i = n-1; (i >= 0 && pcc[i].pcc_id == pcc_id); i--)
		return i;
	return -1;
}
#endif
 /* <-- GCC_security flag */

/**
 * @brief  : Add entry into SDF-PCC or ADC-PCC association hash.
 * @param  : type, Type of hash table, SDF/ADC.
 * @param  : pcc_id, PCC rule id to be added.
 * @param  : precedence, PCC rule precedence.
 * @param  : gate_status, PCC rule gate status.
 * @param  : n, Number of SDF/ADC rules.
 * @param  : rule_ids,  Pointer to SDF/ADC rule ids.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
filter_pcc_entry_add(enum filter_pcc_type type, uint32_t pcc_id,
		uint32_t precedence, uint8_t gate_status, uint32_t n,
		uint32_t rule_ids[])
{
	int ret;
	uint32_t i;
	struct filter_pcc_data *pinfo = NULL;
	struct rte_hash *hash = NULL;

	if (type == FILTER_SDF)
		hash = rte_sdf_pcc_hash;
	else if (type == FILTER_ADC)
		hash = rte_adc_pcc_hash;
	else
		return -1;

	for (i = 0; i < n; i++) {
		ret = rte_hash_lookup_data(hash, &rule_ids[i], (void **)&pinfo);

		if (ret < 0 || pinfo == NULL) {
			/* No data found for sdf id, insert new entry*/

			struct pcc_id_precedence *pcc = rte_zmalloc("pcc_id_preced",
					sizeof(struct pcc_id_precedence), RTE_CACHE_LINE_SIZE);
			if (pcc == NULL)
				rte_panic("Failed to allocate memory for pcc_id_precedence");

			pcc->pcc_id = pcc_id;
			pcc->precedence = precedence;
			pcc->gate_status = gate_status;

			struct filter_pcc_data *data = rte_zmalloc("filter_pcc_data",
					sizeof(struct filter_pcc_data), RTE_CACHE_LINE_SIZE);

			if (data == NULL) {
				rte_free(pcc);
				rte_panic("Failed to allocate memory for filter_pcc_data");
			}

			data->entries = 1;
			data->pcc_info = pcc;

			ret = rte_hash_add_key_data(hash, &rule_ids[i], data);

			if (ret < 0) {
				rte_free(pcc);
				rte_free(data);
				clLog(clSystemLog, eCLSeverityDebug, "Failed to add entry in rte_sdf_pcc hash.\n");
				continue;
			}
		} else {
			struct pcc_id_precedence *pcc = rte_zmalloc("pcc_id_precedence",
					(pinfo->entries + 1) * sizeof(struct pcc_id_precedence),
					RTE_CACHE_LINE_SIZE);

			if (pcc == NULL)
				rte_panic("Failed to allocate memory for pcc_id_precedence");

			rte_memcpy(pcc, pinfo->pcc_info,
					(pinfo->entries) * sizeof(struct pcc_id_precedence));
			uint32_t insert_pos = get_insert_position(pcc, pinfo->entries,
									precedence);
			pcc[insert_pos].pcc_id = pcc_id;
			pcc[insert_pos].precedence = precedence;
			pcc[insert_pos].gate_status = gate_status;

			struct filter_pcc_data *data = rte_zmalloc("filter_pcc_data",
					sizeof(struct filter_pcc_data), RTE_CACHE_LINE_SIZE);

			if (data == NULL)
				rte_panic("Failed to allocate memory for filter_pcc_data");

			data->entries = pinfo->entries + 1;
			data->pcc_info = pcc;

			ret = rte_hash_del_key(hash, &rule_ids[i]);
			if (ret < 0) {
				rte_free(pcc);
				rte_free(data);
				clLog(clSystemLog, eCLSeverityDebug, "Failed to delete from rte_sdf_pcc hash\n");
				continue;
			}

			rte_free(pinfo->pcc_info);
			rte_free(pinfo);
			pinfo = NULL;

			ret = rte_hash_add_key_data(hash,
					&rule_ids[i], data);
			if (ret < 0) {
				rte_free(pcc);
				rte_free(data);
				clLog(clSystemLog, eCLSeverityDebug,
						"Failed to add entry in sdf_pcc hash table\n");
				continue;
			}
		}
	}
	return 0;
}

/**
 * @brief  : Search SDF-PCC or ADC-PCC association hash for SDF/ADC ruleid as a key
 * @param  : type, Type of hash table, SDF/ADC.
 * @param  : pcc_id, SDF/ADC rule ids to be used for searching.
 * @param  : n, Number of SDF/ADC rules.
 * @param  : pcc_info, Pointer to matched PCC info.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
filter_pcc_entry_lookup(enum filter_pcc_type type, uint32_t* rule_ids,
		uint32_t n, struct pcc_id_precedence *pcc_ids)
{
	int ret = 0;
	uint32_t i;
	struct filter_pcc_data *pinfo = NULL;
	struct rte_hash *hash = NULL;

	if (type == FILTER_SDF)
		hash = rte_sdf_pcc_hash;
	else if (type == FILTER_ADC)
		hash = rte_adc_pcc_hash;
	else {
		clLog(clSystemLog, eCLSeverityInfo, "filter_pcc_entry_lookup hash type mistmatch");
		return -1;
	}

	for (i = 0; i < n; i++) {
		ret = rte_hash_lookup_data(hash, &rule_ids[i], (void **)&pinfo);

		if (ret < 0 || pinfo == NULL) {
			/* TODO : If there is no matching pcc rule, what should be
			 *        values of pcc? Currently hardcoding to 1 with
			 *        gate-status 1 (pass traffic) : Default policy in pcc
			 */
			pcc_ids[i].pcc_id = 1;
			pcc_ids[i].precedence = 255;
			pcc_ids[i].gate_status = 1;
		} else {
			pcc_ids[i] = pinfo->pcc_info[pinfo->entries - 1];
		}
	}
	return 0;
}
