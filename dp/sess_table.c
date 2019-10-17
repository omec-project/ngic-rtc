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

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include <search.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_cfgfile.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>


#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl_dp.h"
#include "interface.h"
#include "cdr.h"
#include "session_cdr.h"
#include "meter.h"

#define SESS_CREATE 0
#define SESS_MODIFY 1
#define SESS_DEL 2

extern struct rte_hash *rte_sess_hash;
extern struct rte_hash *rte_ue_hash;
extern struct rte_hash *rte_uplink_hash;
extern struct rte_hash *rte_downlink_hash;
extern struct rte_hash *rte_adc_hash;
extern struct rte_hash *rte_adc_ue_hash;

#define DEBUG_SESS_TABLE 0

#if DEBUG_SESS_TABLE
#define WIDTH 40
#define PRINT_SESSION_INFO(entry) \
do {\
	puts(__FUNCTION__);\
	printf("\t%*s:0x%"PRIx64"\n", WIDTH, "entry->sess_id", \
			entry->sess_id);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "ue_addr.u.ipv4_addr", \
			entry->ue_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "ul_s1_info.enb_addr.u.ipv4_addr",\
			entry->ul_s1_info.enb_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "ul_s1_info.sgw_addr.u.ipv4_addr",\
			entry->ul_s1_info.sgw_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr",\
			entry->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr",\
			entry->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "ul_s1_info.sgw_teid", \
			entry->ul_s1_info.sgw_teid);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "dl_s1_info.enb_addr.u.ipv4_addr",\
			entry->dl_s1_info.enb_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "dl_s1_info.sgw_addr.u.ipv4_addr",\
			entry->dl_s1_info.sgw_addr.u.ipv4_addr);\
	printf("\t%*s:0x%"PRIx32"\n", WIDTH, "dl_s1_info.enb_teid", \
			entry->dl_s1_info.enb_teid);\
} while (0)
#else
#define PRINT_SESSION_INFO(entry) do {} while (0)
#endif

/** Function used to compare keys */
typedef int (*rte_hash_cmp_eq_t) (const void *key1, const void *key2,
		size_t key_len);
/** Structure storing both primary and secondary hashes */
struct rte_hash_signatures {
	union {
		struct {
			hash_sig_t current;
			hash_sig_t alt;
		};
		uint64_t sig;
	};
};

#define RTE_HASH_BUCKET_ENTRIES         4
/** Bucket structure */
struct rte_hash_bucket {
	struct rte_hash_signatures signatures[RTE_HASH_BUCKET_ENTRIES];
	/** Includes dummy key index that always contains index 0 */
	uint32_t key_idx[RTE_HASH_BUCKET_ENTRIES + 1];
	uint8_t flag[RTE_HASH_BUCKET_ENTRIES];
} __rte_cache_aligned;

/** A hash table structure. */
struct rte_hash {
	char name[RTE_HASH_NAMESIZE];
	/** Total table entries. */
	uint32_t entries;
	/** Number of buckets in table. */
	uint32_t num_buckets;
	/** Length of hash key. */
	uint32_t key_len;
	/** Function used to calculate hash. */
	rte_hash_function hash_func;
	/** Init value used by hash_func. */
	uint32_t hash_func_init_val;
	/** Function used to compare keys. */
	rte_hash_cmp_eq_t rte_hash_cmp_eq;
	/** Bitmask for getting bucket index from hash signature */
	uint32_t bucket_bitmask;
	/** Size of each key entry. */
	uint32_t key_entry_size;
	/** Ring that stores all indexes of the free slots in the key table*/
	struct rte_ring *free_slots;
	/** Table storing all keys and data */
	void *key_store;
	/** Table with buckets storing all the hash values and key indexes
	 * to the key table
	 */
	struct rte_hash_bucket *buckets;
} __rte_cache_aligned;

int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value)
{
	return rte_hash_lookup_data(rte_uplink_hash, key, value);
}

int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	return rte_hash_lookup_bulk_data(rte_uplink_hash, key, n, hit_mask, value);
}

int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value)
{
	return rte_hash_lookup_data(rte_downlink_hash, key, value);
}

int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	return rte_hash_lookup_bulk_data(rte_downlink_hash, key, n, hit_mask, value);
}

int
iface_lookup_adc_ue_data(struct dl_bm_key *key,
		void **value)
{
	return rte_hash_lookup_data(rte_adc_ue_hash, key, value);
}

/******************** DP- ADC, PCC funcitons **********************/
int iface_lookup_adc_data(const uint32_t key32,
		void **value)
{
	return rte_hash_lookup_data(rte_adc_hash, &key32, (void **)value);
}

int iface_lookup_adc_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	return rte_hash_lookup_bulk_data(rte_adc_hash, key, n, hit_mask, value);
}
struct rte_hash_bucket *bucket_ul_addr(uint64_t key)
{
	uint32_t bucket_idx;
	hash_sig_t sig = rte_hash_hash(rte_uplink_hash, &key);

	bucket_idx = sig & rte_uplink_hash->bucket_bitmask;
	return &rte_uplink_hash->buckets[bucket_idx];
}

struct rte_hash_bucket *bucket_dl_addr(uint64_t key)
{
	uint32_t bucket_idx;
	hash_sig_t sig = rte_hash_hash(rte_downlink_hash, &key);

	bucket_idx = sig & rte_downlink_hash->bucket_bitmask;
	return &rte_downlink_hash->buckets[bucket_idx];
}

int
add_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map)
{
	uint32_t i;

	for (i = 0; i < MAX_RATING_GRP; i++) {

		if ((rg_idx_map+i)->rg_val == rg_val)
			return 0;

		if ((rg_idx_map+i)->rg_val == 0) {
			(rg_idx_map+i)->rg_val = rg_val;
			return 0;
		}
	}
	return -1;
}

/********************* PCC rules update functions ***********************/
/**
 * @brief Function to add UL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
add_ul_pcc_entry_key_with_idx(struct dp_session_info *old,
			struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct ul_bm_key ul_key;
	struct dp_pcc_rules *pcc_info = NULL;
	uint32_t pcc_id;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	pcc_id = data->ul_pcc_rule_id[idx];
	if (pcc_id == 0)
		return;

	/* get pcc rule info address*/
	ret = iface_lookup_pcc_data(pcc_id, &pcc_info);
	if(ret == ENOENT || ret == EINVAL)
               printf("Error in add_ul_pcc_entry_key_with_idx\n\n");

	old->ul_pcc_rule_id[idx] = pcc_id;

	/* update rating group idx*/
	if (old->ue_info_ptr != NULL) {
		ret = add_rg_idx(pcc_info->rating_group, old->ue_info_ptr->rg_idx_map);
		if (ret)
			rte_panic("Failed to add rating group to index map");
	}

	/* alloc memory for per sdf per bearer info structure*/
	psdf = rte_zmalloc("sdf per bearer", sizeof(struct dp_sdf_per_bearer_info),
			RTE_CACHE_LINE_SIZE);
	if (NULL == psdf) {
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory for sdf per bearer info");
		return ;
	}
	psdf->pcc_info = *pcc_info;
	psdf->bear_sess_info = old;

#ifdef SDF_MTR
	mtr_cfg_entry(pcc_info->qos.ul_mtr_profile_index, &psdf->sdf_mtr_obj);
	RTE_LOG_DP(DEBUG, DP, "SDF MTR ADD:UL pcc %d, mtr_idx %d\n",
			pcc_info->rule_id, pcc_info->qos.ul_mtr_profile_index);
#endif	/* SDF_MTR */

	ul_key.s1u_sgw_teid = data->ul_s1_info.sgw_teid;
	ul_key.rid = pcc_id;

	RTE_LOG_DP(DEBUG, DP, "SDF ADD:UL_KEY: teid:0x%X, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);

	ret = rte_hash_add_key_data(rte_uplink_hash,
			&ul_key, psdf);

	if (ret < 0)
		rte_panic("Failed to add entry in hash table");
}

/**
 * @brief Function to del UL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
del_ul_pcc_entry_key_with_idx(struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct ul_bm_key ul_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	ul_key.s1u_sgw_teid = data->ul_s1_info.sgw_teid;
	ul_key.rid = data->ul_pcc_rule_id[idx];

	RTE_LOG_DP(DEBUG, DP, "BEAR_SESS DEL:UL_KEY: teid:0x%X, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);

	if (ul_key.rid == 0)
		return;

	/* Get the sdf per bearer info */
	ret = iface_lookup_uplink_data(&ul_key, (void **)&psdf);
	if (ret < 0) {
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS DEL FAIL:UL_KEY: teid:0x%X, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);
		return ;
	}

	ret = rte_hash_del_key(rte_uplink_hash,
			&ul_key);
	if (ret == -ENOENT)
		RTE_LOG_DP(DEBUG, DP, "key is not found\n");
	if (ret == -EINVAL)
		RTE_LOG_DP(DEBUG, DP, "Invalid Params: Failed to del from hash table");
	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

	rte_free(psdf);
}

/**
 * @brief Function to add DL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
add_dl_pcc_entry_key_with_idx(struct dp_session_info *old,
			struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key dl_key;
	struct dp_pcc_rules *pcc_info = NULL;
	uint32_t pcc_id;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	pcc_id = data->dl_pcc_rule_id[idx];
	if (pcc_id == 0)
		return;

	/* get pcc rule info address*/
	iface_lookup_pcc_data(pcc_id, &pcc_info);
	if (pcc_info == NULL)
		return;
	old->dl_pcc_rule_id[idx] = pcc_id;

	/* update rating group idx*/
	if (old->ue_info_ptr != NULL) {
		ret = add_rg_idx(pcc_info->rating_group, old->ue_info_ptr->rg_idx_map);
		if (ret)
			rte_panic("Failed to add rating group to index map");
	}

	/* alloc memory for per sdf per bearer info */
	psdf = rte_zmalloc("sdf per bearer", sizeof(struct dp_sdf_per_bearer_info),
			RTE_CACHE_LINE_SIZE);
	if (psdf == NULL) {
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory for sdf per bearer info");
		return ;
	}
	psdf->pcc_info = *pcc_info;
	psdf->bear_sess_info = old;

#ifdef SDF_MTR
	mtr_cfg_entry(pcc_info->qos.dl_mtr_profile_index, &psdf->sdf_mtr_obj);
	RTE_LOG_DP(DEBUG, DP, "SDF MTR ADD:DL pcc %d, mtr_idx %d\n",
			pcc_info->rule_id, pcc_info->qos.dl_mtr_profile_index);
#endif	/* SDF_MTR */

	dl_key.ue_ipv4 = old->ue_addr.u.ipv4_addr;
	dl_key.rid = pcc_id;

	RTE_LOG_DP(DEBUG, DP, "SDF ADD:DL_KEY: ue_addr:"IPV4_ADDR ", rid: %d\n",
			IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4), pcc_id);

	ret = rte_hash_add_key_data(rte_downlink_hash,
			&dl_key, psdf);


	if (ret < 0)
		rte_panic("Failed to add entry in hash table");
}

#ifdef SDF_MTR
static void
flush_sdf_mtr(struct dp_sdf_per_bearer_info *psdf, char *s)
{
	export_mtr(psdf->bear_sess_info, s, psdf->pcc_info.rule_id,
					psdf->sdf_mtr_drops);
}
#endif /* SDF_MTR*/
#ifdef APN_MTR
static void
flush_apn_mtr(struct dp_sdf_per_bearer_info *psdf)
{
	export_mtr(psdf->bear_sess_info, "UL-APN",
			psdf->bear_sess_info->ue_info_ptr->ul_apn_mtr_idx,
			psdf->bear_sess_info->ue_info_ptr->ul_apn_mtr_drops);
	export_mtr(psdf->bear_sess_info, "DL-APN",
			psdf->bear_sess_info->ue_info_ptr->dl_apn_mtr_idx,
			psdf->bear_sess_info->ue_info_ptr->dl_apn_mtr_drops);
}
#endif /* APN_MTR*/

/**
 * @brief Function to del DL pcc entry with key and
 * update pcc address and rating group.
 *
 */
static void
del_dl_pcc_entry_key_with_idx(struct dp_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	dl_key.ue_ipv4 = data->ue_addr.u.ipv4_addr;
	dl_key.rid = data->dl_pcc_rule_id[idx];

	if (dl_key.rid == 0)
		return;

	RTE_LOG_DP(DEBUG, DP, "BEAR_SESS DEL:DL_KEY: pcc_id: %d, ue_addr:"
		IPV4_ADDR "\n",
		dl_key.rid, IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4));

	/* Get the sdf per bearer info */
	ret = iface_lookup_downlink_data(&dl_key, (void **)&psdf);
	if (ret < 0) {
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS DEL FAIL:DL_KEY: ue_addr:"IPV4_ADDR ",",
			IPV4_ADDR_HOST_FORMAT(dl_key.ue_ipv4));
		return ;
	}

	ret = rte_hash_del_key(rte_downlink_hash,
			&dl_key);
	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

#ifdef SDF_MTR
	flush_sdf_mtr(psdf, "DL-SDF");
#endif

	rte_free(psdf);
}

/**
 * @brief Check for change in PCC rule.
 */
static void
update_pcc_rules(struct dp_session_info *old,
			struct dp_session_info *new)
{
	uint32_t i;
	uint32_t *p1;
	uint32_t *p2;
	uint32_t n1;
	uint32_t n2;
	uint32_t n;

	/* Modify UL PCC rule keys*/
	p1 = old->ul_pcc_rule_id;
	p2 = new->ul_pcc_rule_id;
	n1 = old->num_ul_pcc_rules;
	n2 = new->num_ul_pcc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_ul_pcc_entry_key_with_idx(old, i);
			add_ul_pcc_entry_key_with_idx(old, new, i);
		}

	if (n1 > n2)
		while (i < n1) {
			del_ul_pcc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_ul_pcc_entry_key_with_idx(old, new, i);
			i++;
		}

	old->num_ul_pcc_rules = n2;

	/* Modify DL PCC rule keys*/
	p1 = old->dl_pcc_rule_id;
	p2 = new->dl_pcc_rule_id;
	n1 = old->num_dl_pcc_rules;
	n2 = new->num_dl_pcc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_dl_pcc_entry_key_with_idx(old, i);
			add_dl_pcc_entry_key_with_idx(old, new, i);
		}
	if (n1 > n2)
		while (i < n1) {
			del_dl_pcc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_dl_pcc_entry_key_with_idx(old, new, i);
			i++;
		}
	old->num_dl_pcc_rules = n2;
}

/******************** ADC rules update functions **************/
/**
 * @brief Function to copy fields from struct adc_rules to
 * struct dp_adc_rules. *
 */

static void
copy_dp_adc_rules(struct dp_adc_rules *dst,
		struct adc_rules *src)
{
	dst->rule_id = src->rule_id;
}

/**
 * @brief Function to add adc entry with key and
 * update adc address and rating group.
 *
 */
static void
add_adc_entry_key_with_idx(struct ue_session_info *old,
			struct ue_session_info *new, uint32_t idx)
{
	int ret;
	struct dl_bm_key key;
	struct adc_rules *adc_info;
	uint32_t adc_id;
	uint64_t pkts_mask = 1;
	struct dp_adc_ue_info *padc_ue;
	void *data = NULL;

	adc_id = new->adc_rule_id[idx];
	if (adc_id == 0)
		return;
	key.ue_ipv4 = old->ue_addr.u.ipv4_addr;
	key.rid = adc_id;

	ret = rte_hash_lookup_data(rte_adc_ue_hash, &key, &data);
	if (data)
		return;

	/* get adc rule info address*/
	adc_rule_info_get(&adc_id, 1, &pkts_mask, (void **)&adc_info);
	old->adc_rule_id[idx] = adc_id;

	/* alloc memory for per ADC per UE info structure*/
	padc_ue = rte_zmalloc("adc ue info", sizeof(struct dp_adc_ue_info),
			RTE_CACHE_LINE_SIZE);
	if (padc_ue == NULL) {
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory for adc ue info");
		return ;
	}
	copy_dp_adc_rules(&padc_ue->adc_info, adc_info);

	RTE_LOG_DP(DEBUG, DP, "ADC UE INFO ADD: ue_addr:"IPV4_ADDR ",",
					IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));
	RTE_LOG_DP(DEBUG, DP, "adc_id:%u\n",
					old->adc_rule_id[idx]);
	ret = rte_hash_add_key_data(rte_adc_ue_hash,
					&key, padc_ue);
	if (ret < 0)
			rte_panic("Failed to add entry in hash table");

#ifdef SDF_MTR
	mtr_cfg_entry(padc_ue->adc_info.mtr_profile_index, &padc_ue->mtr_obj);
#endif  /* SDF_MTR */
}

/**
 * @brief Function to del adc entry with key and
 * update adc address and rating group.
 *
 */
static void
del_adc_entry_key_with_idx(struct ue_session_info *data, uint32_t idx)
{
	int ret;
	struct dl_bm_key key;
	struct dp_adc_ue_info *padc_ue;

	key.ue_ipv4 = data->ue_addr.u.ipv4_addr;
	key.rid = data->adc_rule_id[idx];

	if (key.rid == 0)
		return;

	RTE_LOG_DP(DEBUG, DP, "ADC UE DEL:key: adc_id: %d, ue_addr:"IPV4_ADDR ",",
		key.rid, IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));

	/* Get per ADC per UE info structure */
	ret = iface_lookup_adc_ue_data(&key, (void **)&padc_ue);
	if (ret < 0) {
	RTE_LOG_DP(DEBUG, DP, "ADC UE DEL Fail !!:key: adc_id: %d, ue_addr:"IPV4_ADDR ",",
		key.rid, IPV4_ADDR_HOST_FORMAT(key.ue_ipv4));
		return ;
	}

	ret = rte_hash_del_key(rte_adc_ue_hash,
			&key);

	if (ret < 0)
		rte_panic("Failed to del entry from hash table");

	/* free the memory*/
	rte_free(padc_ue);
}

/**
 * @brief Check for change in adc rule.
 */
static void
update_adc_rules(struct ue_session_info *old,
			struct ue_session_info *new)
{
	uint32_t i;
	uint32_t *p1;
	uint32_t *p2;
	uint32_t n1;
	uint32_t n2;
	uint32_t n;

	/* Modify adc rule keys*/
	p1 = old->adc_rule_id;
	p2 = new->adc_rule_id;
	n1 = old->num_adc_rules;
	n2 = new->num_adc_rules;
	n = (n1 > n2) ? (n2) : (n1);
	for (i = 0; i < n; i++)
		if (p1[i] != p2[i]) {
			del_adc_entry_key_with_idx(old, i);
			add_adc_entry_key_with_idx(old, new, i);
		}

	if (n1 > n2)
		while (i < n1) {
			del_adc_entry_key_with_idx(old, i);
			i++;
		}
	else if (n1 < n2)
		while (i < n2) {
			add_adc_entry_key_with_idx(old, new, i);
			i++;
		}

	old->num_adc_rules = n2;
}

/******************** ADC SponsDNS Table **********************/
void print_adc_hash(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;


	while (rte_hash_iterate(rte_adc_hash, &next_key, &next_data, &iter) >= 0) {

		struct in_addr tmp_ip_key;

		memcpy(&tmp_ip_key, next_key, sizeof(struct in_addr));

	}
	puts("<\\ >\n");
}

int
adc_dns_entry_add(struct msg_adc *data)
{
	struct msg_adc *adc;
	uint32_t key32 = 0;
	int32_t ret;
	adc = rte_malloc("data", sizeof(struct msg_adc),
			RTE_CACHE_LINE_SIZE);
	if (adc == NULL){
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory");
		return -1;
	}
	*adc = *data;

	key32 = adc->ipv4;
	ret = rte_hash_add_key_data(rte_adc_hash, &key32,
			adc);
	if (ret < 0){
		RTE_LOG_DP(ERR, DP, "Failed to add entry in hash table");
		return -1;
	}
	return 0;
}

int adc_dns_entry_delete(struct msg_adc *data)
{
	struct msg_adc *adc;
	uint32_t key32 = 0;
	int32_t ret;
	key32 = data->ipv4;
	ret = rte_hash_lookup_data(rte_adc_hash, &key32,
			(void **)&adc);
	if (ret < 0) {
		RTE_LOG_DP(ERR, DP, "Failed to del\n"
				"adc key 0x%X to hash table\n",
				data->ipv4);
		return -1;
	}
	ret = rte_hash_del_key(rte_adc_hash, &key32);
	if (ret < 0){
		RTE_LOG_DP(ERR, DP, "Failed to del entry in hash table");
		return -1;
	}
	rte_free(adc);
	return 0;
}

/******************** Session functions **********************/
/**
 * @brief Function to return session info entry address.
 *	if entry not found, allocate the memory & add entry.
 *
 */

struct dp_session_info *
get_session_data(uint64_t sess_id, uint32_t is_mod)
{
	struct dp_session_info *data = NULL;
	int ret;
	/* check if session exists*/
	if (unlikely(rte_sess_hash == NULL))
	{
		static int show_message_once;
		if (show_message_once == 0) {
			RTE_LOG_DP(NOTICE, DP, "Sess Hash Table not yet setup\n");
			show_message_once = 1;
		}
		return NULL;
	}

	rte_hash_lookup_data(rte_sess_hash, &sess_id, (void **)&data);

	if (data != NULL)
		return data;

	/* allocate memory only if request is from session create*/
	if (is_mod != SESS_CREATE)
		return NULL;

	/* allocate memory for session info*/
	data = rte_zmalloc("data", sizeof(struct dp_session_info),
			RTE_CACHE_LINE_SIZE);
	if (data == NULL){
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory for session info\n");
		return NULL;
	}

	/* add entry*/
	ret = rte_hash_add_key_data(rte_sess_hash, &sess_id, data);
	if (ret < 0){
		RTE_LOG_DP(ERR, DP, "Failed to add entry in hash table\n");
		rte_free(data);
		return NULL;
	}

	return data;
}

int
dp_session_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	RTE_SET_USED(dp_id);
	int rc;
	if (rte_sess_hash) {
		RTE_LOG_DP(INFO, DP, "PCC table: \"%s\" exist\n", dp_id.name);
		return 0;
	}
	rc = hash_create(dp_id.name, &rte_sess_hash, max_elements * 4,
			sizeof(uint64_t));
	return rc;
}

int
dp_session_table_delete(struct dp_id dp_id)
{
	RTE_SET_USED(dp_id);
	rte_hash_free(rte_sess_hash);
	return 0;
}

static void
copy_session_info(struct dp_session_info *dst,
		struct session_info *src)
{
	int i;
	/*No ue_addr in case of MBR*/
	if(src->ue_addr.u.ipv4_addr){
		dst->ue_addr = src->ue_addr;
	}
	dst->ul_s1_info = src->ul_s1_info;
	dst->dl_s1_info = src->dl_s1_info;
	dst->num_ul_pcc_rules = src->num_ul_pcc_rules;
	for (i = 0; i < dst->num_ul_pcc_rules; i++)
		dst->ul_pcc_rule_id[i] = src->ul_pcc_rule_id[i];
	dst->num_dl_pcc_rules = src->num_dl_pcc_rules;
	for (i = 0; i < dst->num_dl_pcc_rules; i++)
		dst->dl_pcc_rule_id[i] = src->dl_pcc_rule_id[i];
	dst->ipcan_dp_bearer_cdr = src->ipcan_dp_bearer_cdr;
	dst->sess_id = src->sess_id;
	dst->client_id = src->client_id;
	dst->service_id = src->service_id;
}

int
dp_session_create(struct dp_id dp_id,
		struct session_info *entry)
{
	PRINT_SESSION_INFO(entry);
	int ret;
	int i;
	struct dp_session_info *data;
	struct dp_session_info new;
	struct ue_session_info *ue_data = NULL;
	uint32_t ue_sess_id = UE_SESS_ID(entry->sess_id);
	uint32_t bear_id = UE_BEAR_ID(entry->sess_id);

	RTE_SET_USED(dp_id);
	RTE_LOG_DP(DEBUG, DP, "BEAR_SESS ADD:sess_id:%u, bear_id:%u, ue_addr:"
			IPV4_ADDR "\n",
			ue_sess_id, bear_id,
			IPV4_ADDR_HOST_FORMAT(entry->ue_addr.u.ipv4_addr));

	if ((entry->num_ul_pcc_rules > MAX_PCC_RULES)
			|| (entry->num_dl_pcc_rules > MAX_PCC_RULES)) {
		RTE_LOG_DP(ERR, DP, "Number of PCC rule exceeds max limit %d\n",
				MAX_PCC_RULES);
		return -1;
	}

	if (entry->num_adc_rules > MAX_ADC_RULES) {
		RTE_LOG_DP(ERR, DP, "Number of ADC rule exceeds max limit %d\n",
				MAX_ADC_RULES);
		return -1;
	}

	data = get_session_data(entry->sess_id, SESS_CREATE);
	if (data == NULL) {
		RTE_LOG_DP(ERR, DP, "Failed to allocate memory");
		return -1;
	}

	copy_session_info(data, entry);

	data->num_ul_pcc_rules = 0;
	data->num_dl_pcc_rules = 0;

	copy_session_info(&new, entry);

	ret = rte_hash_lookup_data(rte_ue_hash, &ue_sess_id, (void **)&ue_data);
	if ((ue_data == NULL) || (ret == -ENOENT)) {
		/* return if this is not a default bearer and ue_data not created.
		 * only default bearer can create ue_data.*/
		if (bear_id != DEFAULT_BEARER) {
			/* create req for dedicated bearer, but ue_data not created,
			 * this means default bearer is not created for this UE. Hence
			 * return error and free memory allocated for dedicated bearer.
			 */
			RTE_LOG_DP(ERR, DP, "BEAR_SESS ADD Fail: Default bearer not found for sess_id:%u, bear_id:%u\n",
						ue_sess_id, bear_id);
			rte_hash_del_key(rte_sess_hash, &entry->sess_id);
			rte_free(data);
			return 0;
		}
		/* add UE data*/
		ue_data = rte_zmalloc("ue sess info", sizeof(struct ue_session_info),
				RTE_CACHE_LINE_SIZE);
		if (ue_data == NULL)
			rte_panic("Failed to alloc mem for ue session");
		ret = rte_hash_add_key_data(rte_ue_hash, &ue_sess_id, ue_data);
		if (ret < 0) {
			rte_panic("Failed to add entry in hash table");
			return -1;
		}

		ue_data->ue_addr = data->ue_addr;
		ue_data->ul_apn_mtr_idx = entry->ul_apn_mtr_idx;
		ue_data->dl_apn_mtr_idx = entry->dl_apn_mtr_idx;
		ue_data->bearer_count = 1;

#ifdef APN_MTR
		mtr_cfg_entry(ue_data->ul_apn_mtr_idx,
				&ue_data->ul_apn_mtr_obj);
		RTE_LOG_DP(DEBUG, DP, "UL-APN MTR ADD: apn_mtr_id: %u, "
				"apn_obj:0x%"PRIx64"\n",
				ue_data->ul_apn_mtr_idx,
				(uint64_t)&ue_data->ul_apn_mtr_obj);

		mtr_cfg_entry(ue_data->dl_apn_mtr_idx,
				&ue_data->dl_apn_mtr_obj);
		RTE_LOG_DP(DEBUG, DP, "DL-APN MTR ADD: apn_mtr_id: %u, "
				"apn_obj:0x%"PRIx64"\n",
				ue_data->dl_apn_mtr_idx,
				(uint64_t)&ue_data->dl_apn_mtr_obj);
#endif	/* APN_MTR */
	} else {
		/* update UE data*/
		ue_data->bearer_count += 1;
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS ADD:bear_id:%u, bear_count:%u,\n",
				bear_id, ue_data->bearer_count);
	}

	/* Update UE session info ptr */
	data->ue_info_ptr = ue_data;
	data->sess_state = IN_PROGRESS;

#ifdef USE_REST
	if (app.spgw_cfg == PGWU) {
		/* VS: Add SGW-U peer node information in connection table */
		if (data->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr != 0 ) {
			if ((add_node_conn_entry(ntohl(data->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr),
							entry->sess_id, S1U_PORT_ID)) < 0) {
				RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGW-U");
			}
		}
	}
#endif  /* USE_REST */

	/* Update adc rules */
	if (entry->num_adc_rules) {
		struct ue_session_info new_ue_data;
		new_ue_data.num_adc_rules = entry->num_adc_rules;
		for (i = 0; i < new_ue_data.num_adc_rules; i++)
			new_ue_data.adc_rule_id[i] = entry->adc_rule_id[i];
		/* Update ADC rules addr*/
		update_adc_rules(ue_data, &new_ue_data);
	}
	/* Update PCC rules addr*/
	update_pcc_rules(data, &new);


	data->client_id = entry->client_id;
	new.client_id = entry->client_id;

	return 0;
}

int
update_uplink_hash( uint32_t s1u_teid, uint32_t ul_pcc_rid, uint32_t s5s8_pgwu_addr)
{
	int ret;
	struct ul_bm_key ul_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	ul_key.s1u_sgw_teid = s1u_teid;
	ul_key.rid = ul_pcc_rid;

	RTE_LOG_DP(DEBUG, DP, "BEAR_SESS UPDATE:UL_KEY: teid:0x%X, rid:%u\n",
			ul_key.s1u_sgw_teid, ul_key.rid);

	if (ul_key.rid == 0)
		return -1;

	/* Get the sdf per bearer info */
		ret = iface_lookup_uplink_data(&ul_key, (void **)&psdf);
	if (ret < 0) {
		RTE_LOG_DP(DEBUG, DP, "BEAR_SESS UPDATE FAIL:UL_KEY: teid:0x%X, rid:%u\n",
				ul_key.s1u_sgw_teid, ul_key.rid);
		return -1;
	}
	psdf->bear_sess_info->ul_s1_info.s5s8_pgwu_addr.iptype  = IPTYPE_IPV4;
	psdf->bear_sess_info->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr = s5s8_pgwu_addr;

	return 0;
}

int
dp_session_modify(struct dp_id dp_id,
		struct session_info *entry)
{
	PRINT_SESSION_INFO(entry);
	struct dp_session_info *data;
	struct dp_session_info mod_data;
	uint32_t ue_sess_id = UE_SESS_ID(entry->sess_id);
	uint32_t bear_id = UE_BEAR_ID(entry->sess_id);
	int i;
	RTE_SET_USED(dp_id);

	RTE_LOG_DP(DEBUG, DP, "BEAR_SESS MOD:sess_id:%u, bear_id:%u, ue_addr:"
		IPV4_ADDR "\n",
		ue_sess_id, bear_id,
		IPV4_ADDR_HOST_FORMAT(entry->ue_addr.u.ipv4_addr));

	if ((entry->num_ul_pcc_rules > MAX_PCC_RULES)
			|| (entry->num_dl_pcc_rules > MAX_PCC_RULES)) {
		RTE_LOG_DP(ERR, DP, "Number of PCC rule exceeds max limit %d\n",
				MAX_PCC_RULES);
		return -1;
	}

	if (entry->num_adc_rules > MAX_ADC_RULES) {
		RTE_LOG_DP(ERR, DP, "Number of ADC rule exceeds max limit %d\n",
				MAX_ADC_RULES);
		return -1;
	}

	data = get_session_data(entry->sess_id, SESS_MODIFY);
	if (data == NULL) {
		RTE_LOG_DP(ERR, DP, "Session id 0x%"PRIx64" not found\n",
					entry->sess_id);
		fprintf(stderr, "DP:Session id 0x%"PRIx64" not found\n",
					entry->sess_id);
		return -1;
	}


	copy_session_info(&mod_data, entry);
	/* Update adc rules */
	if (entry->num_adc_rules) {
		struct ue_session_info new_ue_data;
		new_ue_data.num_adc_rules = entry->num_adc_rules;
		for (i = 0; i < new_ue_data.num_adc_rules; i++)
			new_ue_data.adc_rule_id[i] = entry->adc_rule_id[i];
		/* Update ADC rules addr*/
		update_adc_rules(data->ue_info_ptr, &new_ue_data);
	}

	/* Update PCC rules addr*/
	//TODO PFCP TRY
	if (entry->num_dl_pcc_rules || entry->num_ul_pcc_rules) {
		update_pcc_rules(data, &mod_data);
	}
	/* Copy dl information */
	struct dl_s1_info *dl_info;
	dl_info = &data->dl_s1_info;
	*dl_info = mod_data.dl_s1_info;

	if (!dl_info->enb_teid) {
		if (data->sess_state == CONNECTED)
			data->sess_state = IDLE;
	} else {
		switch (data->sess_state) {
		case IDLE:
			{
				data->sess_state = CONNECTED;
			}
		break;

		case IN_PROGRESS:
			{
/**VS: Resolved queued pkts by dl core and enqueue pkts into notification ring */
#ifdef NGCORE_SHRINK
			{
				struct rte_mbuf *buf_pkt =
					rte_ctrlmbuf_alloc(notify_msg_pool);
				uint64_t *sess =
					rte_pktmbuf_mtod(buf_pkt, uint64_t *);

				*sess = entry->sess_id;
				rte_ring_enqueue(notify_ring,
					buf_pkt);
			}
#else
			//GCC_Security flag
			struct ue_session_info *ue_data = NULL;
			int ret;
			uint32_t hash;
			uint32_t ue_sess_id = UE_SESS_ID(entry->sess_id);

			ret = rte_hash_lookup_data(rte_ue_hash, &ue_sess_id,
					(void **)&ue_data);
			hash = rte_hash_crc_4byte(ue_data->ue_addr.u.ipv4_addr,
					PRIME_VALUE);
			int wk_id = hash % (epc_app.num_workers);

			{
				struct rte_mbuf *buf_pkt =
					rte_ctrlmbuf_alloc(
					epc_app.worker[wk_id].notify_msg_pool);
				uint64_t *sess =
					rte_pktmbuf_mtod(buf_pkt, uint64_t *);

				*sess = entry->sess_id;
				rte_ring_enqueue(
					epc_app.worker[wk_id].notify_ring,
					buf_pkt);
			}

#endif	/* NGCORE_SHRINK */
			}
		break;
		default:
			RTE_LOG_DP(DEBUG, DP, "No state change");
		}
	}

	entry->ul_s1_info.sgw_teid = data->ul_s1_info.sgw_teid; /*S1u TEID*/
	entry->ul_s1_info.sgw_addr.u.ipv4_addr = data->ul_s1_info.sgw_addr.u.ipv4_addr;
	if (app.spgw_cfg == SGWU) {
		int ret ;
		if( entry->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr != 0 )
		{
			ret = update_uplink_hash(entry->ul_s1_info.sgw_teid,
					entry->ul_pcc_rule_id[0],
					entry->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr);
			if( ret < 0 )
				RTE_LOG_DP(DEBUG, DP, "Update UL hash fail\n");
		}
	}

#ifdef USE_REST
	if (entry->dl_s1_info.enb_addr.u.ipv4_addr != 0 ) {
		/* VS: Add eNB peer node information in connection table */
		if ((add_node_conn_entry(ntohl(entry->dl_s1_info.enb_addr.u.ipv4_addr), entry->sess_id, S1U_PORT_ID)) < 0) {
			RTE_LOG_DP(ERR, DP, "Failed to add connection entry for eNB");
		}
	}

	if (app.spgw_cfg == SGWU) {
		/* VS: Add PGW-U peer node information in connection table */
		if (entry->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr != 0 ) {
			if ((add_node_conn_entry(ntohl(entry->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr),
							entry->sess_id, SGI_PORT_ID)) < 0) {
				RTE_LOG_DP(ERR, DP, "Failed to add connection entry for PGW-U");
			}
		}
	}
#endif /* USE_REST */
	return 0;
}

/**
 * Flush CDR records of all the PCC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */
static void
flush_session_pcc_records(struct dp_session_info *session)
{
	uint32_t i, j;
	struct ul_bm_key ul_key;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	/* list of pcc rules for all all ul and dl */
	uint32_t ul_dl_pcc_rules[MAX_PCC_RULES + MAX_PCC_RULES];
	uint32_t num_ul_dl_pcc_rules = session->num_dl_pcc_rules;

	/* add all dl pcc rules to list */
	for (i = 0; i < session->num_dl_pcc_rules; ++i)
		ul_dl_pcc_rules[i] = session->dl_pcc_rule_id[i];
	/* add all ul pcc rules to list if not added previously */
	for (i = 0; i < session->num_ul_pcc_rules; i++) {
		for (j = 0; j < session->num_dl_pcc_rules; ++j) {
			if (session->ul_pcc_rule_id[i] ==
					session->dl_pcc_rule_id[j])
				break;
		}
		if (j == session->num_dl_pcc_rules) {
			ul_dl_pcc_rules[num_ul_dl_pcc_rules] =
					session->ul_pcc_rule_id[i];
			++num_ul_dl_pcc_rules;
		}
	}

	dl_key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	ul_key.s1u_sgw_teid = session->ul_s1_info.sgw_teid;
	for (i = 0; i < num_ul_dl_pcc_rules; ++i) {
		dl_key.rid = ul_dl_pcc_rules[i];
		ul_key.rid = ul_dl_pcc_rules[i];

		rte_hash_lookup_data(rte_downlink_hash, &dl_key,
				(void **)&psdf);

		if (psdf == NULL)
			rte_hash_lookup_data(rte_uplink_hash, &ul_key,
					(void **)&psdf);

		if (psdf == NULL) {
			RTE_LOG_DP(ERR, DP, "CDR read error for session id 0x%"
					PRIx64", PCC %d, "IPV4_ADDR"\n",
					session->sess_id, dl_key.rid,
					IPV4_ADDR_HOST_FORMAT(
						session->ue_addr.u.ipv4_addr));
			continue;
		}

		export_session_pcc_record(&psdf->pcc_info, &psdf->sdf_cdr, session);
	}
}

/**
 * Flush CDR records of all the PCC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */
static void
flush_session_records(struct dp_session_info *session)
{
	uint32_t i;
	struct ul_bm_key ul_key;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;
	struct dp_pcc_rules *pcc_info = NULL;

	dl_key.ue_ipv4 = session->ue_addr.u.ipv4_addr;

	for (i = 0; i < session->num_dl_pcc_rules; i++) {

		dl_key.rid = session->dl_pcc_rule_id[i];
		rte_hash_lookup_data(rte_downlink_hash, &dl_key, (void **)&psdf);

		if (psdf == NULL) {
			continue;
		}

		iface_lookup_pcc_data(psdf->sdf_cdr.charging_rule_id, &pcc_info);

		if (pcc_info != NULL)
			export_session_pcc_record(pcc_info, &psdf->sdf_cdr, session);
	}

	ul_key.s1u_sgw_teid = session->ul_s1_info.sgw_teid;
	for (i = 0; i < session->num_ul_pcc_rules; i++) {
		ul_key.rid = session->ul_pcc_rule_id[i];
		rte_hash_lookup_data(rte_uplink_hash, &ul_key, (void **)&psdf);

		if (psdf == NULL) {
			continue;
		}

		iface_lookup_pcc_data(psdf->sdf_cdr.charging_rule_id, &pcc_info);

		if (pcc_info != NULL)
			export_session_pcc_record(pcc_info, &psdf->sdf_cdr, session);
	}

}

/**
 * Flush CDR records of all the ADC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */

static void
flush_session_adc_records(struct dp_session_info *session)
{
	uint32_t i;
	uint64_t m;
	uint32_t adc_id;
	struct adc_rules *adc_info;
	struct dl_bm_key key;
	struct dp_adc_ue_info *adc_ue_info;

	RTE_LOG_DP(DEBUG, DP, "Flushing CDRs for session id 0x%"PRIx64": ebi %d @ "IPV4_ADDR"\n",
			session->sess_id, (uint8_t)UE_BEAR_ID(session->sess_id),
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));

	key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	for (i = 0; i < session->ue_info_ptr->num_adc_rules; i++) {
		adc_id = session->ue_info_ptr->adc_rule_id[i];
		m = 1;
		adc_rule_info_get(&adc_id, 1, &m, (void **)&adc_info);

		key.rid = adc_id;
		if ((rte_hash_lookup_data(rte_adc_ue_hash, &key, (void **)&adc_ue_info)) < 0)
			continue;
		export_session_adc_record(adc_info, &adc_ue_info->adc_cdr, session);
	}
}

/**
 * Flush CDR records of all the PCC rules for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *      dp bearer session.
 *
 * @return
 * Void
 */
#ifdef APN_MTR
static void
flush_apn_records(struct dp_session_info *session)
{
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	RTE_LOG_DP(DEBUG, DP, "Flushing APN CDRs for session id 0x%"PRIx64
			": ebi %d @ "IPV4_ADDR"\n",
			session->sess_id, (uint8_t)UE_BEAR_ID(session->sess_id),
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));
	dl_key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	dl_key.rid = session->dl_pcc_rule_id[0];
	if ((rte_hash_lookup_data(rte_downlink_hash, &dl_key,
			(void **)&psdf)) < 0)
		return;
	flush_apn_mtr(psdf);
}
#endif /* APN_MTR */

/**
 * Flush Bearer CDR records
 * into cvs file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */
static void
export_bearer_cdr_record(struct dp_session_info *session)
{
	export_cdr_record(session, "BEARER",
				UE_BEAR_ID(session->sess_id), &session->ipcan_dp_bearer_cdr);
}

/**
 * Flush CDR records of all the ADC rules of the given Bearer session,
 * into cvs file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */

static void
export_adc_cdr_record(struct dp_session_info *session)
{
	uint32_t i;
	struct dl_bm_key key;
	struct dp_adc_ue_info *adc_ue_info = NULL;

	key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	for (i = 0; i < session->ue_info_ptr->num_adc_rules; i++) {
		key.rid = session->ue_info_ptr->adc_rule_id[i];
		if ((rte_hash_lookup_data(rte_adc_ue_hash, &key, (void **)&adc_ue_info)) < 0) {
			RTE_LOG_DP(ERR, DP, "CDR read error for session id 0x%"PRIx64", ADC %d, "IPV4_ADDR"\n",
			session->sess_id, key.rid,
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));
			continue;
		}

		export_cdr_record(session, "ADC", key.rid, &adc_ue_info->adc_cdr);
	}
}
/**
 * Flush CDR records of all the PCC rules of the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */
static void
export_flow_cdr_record(struct dp_session_info *session)
{
	uint32_t i, j;
	struct ul_bm_key ul_key;
	struct dl_bm_key dl_key;
	struct dp_sdf_per_bearer_info *psdf = NULL;

	/* list of pcc rules for all all ul and dl */
	uint32_t ul_dl_pcc_rules[MAX_PCC_RULES + MAX_PCC_RULES];
	uint32_t num_ul_dl_pcc_rules = session->num_dl_pcc_rules;

	/* add all dl pcc rules to list */
	for (i = 0; i < session->num_dl_pcc_rules; ++i)
		ul_dl_pcc_rules[i] = session->dl_pcc_rule_id[i];
	/* add all ul pcc rules to list if not added previously */
	for (i = 0; i < session->num_ul_pcc_rules; i++) {
		for (j = 0; j < session->num_dl_pcc_rules; ++j) {
			if (session->ul_pcc_rule_id[i] ==
					session->dl_pcc_rule_id[j])
				break;
		}
		if (j == session->num_dl_pcc_rules) {
			ul_dl_pcc_rules[num_ul_dl_pcc_rules] =
					session->ul_pcc_rule_id[i];
			++num_ul_dl_pcc_rules;
		}
	}

	dl_key.ue_ipv4 = session->ue_addr.u.ipv4_addr;
	ul_key.s1u_sgw_teid = session->ul_s1_info.sgw_teid;
	for (i = 0; i < num_ul_dl_pcc_rules; ++i) {
		dl_key.rid = ul_dl_pcc_rules[i];
		ul_key.rid = ul_dl_pcc_rules[i];

		rte_hash_lookup_data(rte_downlink_hash, &dl_key,
				(void **)&psdf);

		if (psdf == NULL)
			rte_hash_lookup_data(rte_uplink_hash, &ul_key,
					(void **)&psdf);

		if (psdf == NULL) {
			RTE_LOG_DP(ERR, DP, "CDR read error for session id 0x%"
					PRIx64", PCC %d, "IPV4_ADDR"\n",
					session->sess_id, dl_key.rid,
					IPV4_ADDR_HOST_FORMAT(
						session->ue_addr.u.ipv4_addr));
			continue;
		}

		export_cdr_record(session, "PCC", ul_dl_pcc_rules[i],
				&psdf->sdf_cdr);
	}
}

int
dp_session_delete(struct dp_id dp_id,
		struct session_info *entry)
{
	PRINT_SESSION_INFO(entry);
	struct dp_session_info *data;
	RTE_SET_USED(dp_id);
	data = get_session_data(entry->sess_id, SESS_MODIFY);
	if (data == NULL) {
		printf("Session id 0x%"PRIx64" not found\n", entry->sess_id);
		return -1;
	}
	if (data->dl_ring != NULL) {
		uint32_t worker_core_id;
		uint32_t ue_ipv4_hash;
		set_ue_ipv4_hash(&ue_ipv4_hash, &data->ue_addr.u.ipv4_addr);
		set_worker_core_id(&worker_core_id, &ue_ipv4_hash);

#ifndef NGCORE_SHRINK

		struct epc_worker_params *wk_params =
				&epc_app.worker[worker_core_id];
#endif	/* NGCORE_SHRINK */

		struct rte_ring *ring = data->dl_ring;

		data->dl_ring = NULL;
		/* This is going to be nasty. We could potentially have a race
		 * condition if modify bearer occurs directly before a delete
		 * session, causing scan_notify_ring_func to work on the same
		 * ring as this function. For our current tests, we *should* be
		 * okay. For now.
		 */

		struct rte_mbuf *m[MAX_BURST_SZ];
		int ret = 0;
		int i;
		int count = 0;

		do {

/* VS: Adding handling for support dpdk-18.02 and dpdk-16.11.04 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)m, MAX_BURST_SZ);
#elif (RTE_VER_YEAR >= 18) && (RTE_VER_MONTH >= 02)
			unsigned int *ring_entry = NULL;

			/* VS: Adding handling for support dpdk-18.02 */
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)m, MAX_BURST_SZ, ring_entry);
#endif

			for (i = 0; i < ret; ++i)
				rte_pktmbuf_free(m[i]);
			count += ret;
		} while (ret);

#ifdef NGCORE_SHRINK

		if (rte_ring_enqueue(dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "Can't put ring back, so free it - "
					"dropped %d pkts\n", count);
			rte_ring_free(ring);
		}

#else

		if (rte_ring_enqueue(wk_params->dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "Can't put ring back, so free it - "
					"dropped %d pkts\n", count);
			rte_ring_free(ring);
		}
#endif	/* NGCORE_SHRINK */
	}

#ifdef USE_REST
	/* VS: Delete session id from connection table */
	if (data->dl_s1_info.enb_addr.u.ipv4_addr != 0)
		dp_flush_session(ntohl(data->dl_s1_info.enb_addr.u.ipv4_addr),
						entry->sess_id);
	if (data->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr != 0)
		dp_flush_session(ntohl(data->dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr),
						entry->sess_id);
	if (data->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr != 0)
		dp_flush_session(ntohl(data->ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr),
						entry->sess_id);
#endif /* USE_REST */

	flush_session_adc_records(data);
	/*flush_session_pcc_records(data);*/
	flush_session_records(data);

#ifdef APN_MTR
	flush_apn_records(data);

#endif /* APN_MTR */

	/*added for debugging*/
	export_bearer_cdr_record(data);
	export_adc_cdr_record(data);
	export_flow_cdr_record(data);


	struct dp_session_info new;

	memset(&new, 0, sizeof(struct dp_session_info));
	/* Update PCC rules addr*/
	update_pcc_rules(data, &new);
	/* Update adc rules */
	if (data->ue_info_ptr->num_adc_rules) {
		struct ue_session_info new_ue_data = {0};
		/* Update ADC rules addr*/
		update_adc_rules(data->ue_info_ptr, &new_ue_data);
	}

	/* remove entry from session hash table*/
	if (rte_hash_del_key(rte_sess_hash, &entry->sess_id) < 0)
		return -1;
	rte_free(data);
	return 0;
}

/**
 * Flush Rating Group CDR records for the given Bearer session,
 * into cdr cvs record file.
 * @param session
 *	dp bearer session.
 *
 * @return
 * Void
 */
#ifdef RATING_GRP_CDR
static void
export_rg_cdr_record(struct dp_session_info *session)
{
	uint32_t i;

	for (i = 0; i < MAX_RATING_GRP; i++) {
		if (session->ue_info_ptr->rg_idx_map[i].rg_val)
			export_cdr_record(session, "Rating_Group",
					session->ue_info_ptr->rg_idx_map[i].rg_val,
					&session->ue_info_ptr->rating_grp[i]);
	}
}
#endif /* RATING_GRP_CDR */
int
dp_ue_cdr_flush(struct dp_id dp_id, struct msg_ue_cdr *ue_cdr)
{
	struct dp_session_info *session;
	uint64_t sess_id = ue_cdr->session_id;
	enum cdr_type type = ue_cdr->type;
	RTE_SET_USED(dp_id);
	session = get_session_data(sess_id, SESS_MODIFY);
	if (session == NULL) {
		RTE_LOG_DP(ERR, DP, "CDR flush fail, Session id 0x%"PRIx64" not found\n", sess_id);
		return -1;
	}

	RTE_LOG_DP(INFO, DP, "Flushing CDRs type %d for session id 0x%"PRIx64": ebi %d @ "IPV4_ADDR"\n",
			type, session->sess_id, (uint8_t)UE_BEAR_ID(session->sess_id),
			IPV4_ADDR_HOST_FORMAT(session->ue_addr.u.ipv4_addr));

	if (ue_cdr->action)
		sess_cdr_reset();

	switch (type) {
	case CDR_TYPE_BEARER:
		export_bearer_cdr_record(session);
		break;
	case CDR_TYPE_ADC:
		export_adc_cdr_record(session);
		break;
	case CDR_TYPE_FLOW:
		export_flow_cdr_record(session);
		break;
	case CDR_TYPE_RG:
#ifdef RATING_GRP_CDR
		export_rg_cdr_record(session);
#else
		RTE_LOG_DP(ERR, DP, "Rating Group cdr not enabled\n");
#endif
		break;
	case CDR_TYPE_ALL:
		export_bearer_cdr_record(session);
		export_adc_cdr_record(session);
		export_flow_cdr_record(session);
#ifdef RATING_GRP_CDR
		export_rg_cdr_record(session);
#endif
		break;
	default:
		RTE_LOG_DP(ERR, DP, "Invalid cdr type request\n");
		break;
	}
	return 0;
}

/**
 *  Call back to parse msg to flush cdr to file.
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_ue_cdr_flush(struct msgbuf *msg_payload)
{
	return ue_cdr_flush(msg_payload->dp_id,
			msg_payload->msg_union.ue_cdr);
}
/******************** Call back functions for Bearer Session ******************/
/**
 *  Call back to parse msg to create bearer session table
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_table_create(struct msgbuf *msg_payload)
{
	return session_table_create(msg_payload->dp_id,
			msg_payload->msg_union.msg_table.max_elements);
}

/**
 *  Call back to parse msg to delete table
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_table_delete(struct msgbuf *msg_payload)
{
	return session_table_delete(msg_payload->dp_id);
}

/**
 *  Call back to parse msg to add bearer session
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_create(struct msgbuf *msg_payload)
{
	return session_create(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 *  Call back to parse msg to add bearer session
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_modify(struct msgbuf *msg_payload)
{
	return session_modify(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 * Call back to delete bearer session.
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_session_delete(struct msgbuf *msg_payload)
{
	return session_delete(msg_payload->dp_id,
			msg_payload->msg_union.sess_entry);
}

/**
 *  Call back to parse msg to handle downlink data notification ack.
 *
 * @param
 *	msg_payload - payload from CP
 * @return
 *	- 0 Success.
 *	- -1 Failure.
 */
static int
cb_ddn_ack(struct msgbuf *msg_payload)
{
	return send_ddn_ack(msg_payload->dp_id,
			msg_payload->msg_union.dl_ddn);
}

/**
 * Initialization of Session Table Callback functions.
 */
void
app_sess_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_SESS_TBL_CRE, cb_session_table_create);
	iface_ipc_register_msg_cb(MSG_SESS_TBL_DES, cb_session_table_delete);
	iface_ipc_register_msg_cb(MSG_SESS_CRE, cb_session_create);
	iface_ipc_register_msg_cb(MSG_SESS_MOD, cb_session_modify);
	iface_ipc_register_msg_cb(MSG_SESS_DEL, cb_session_delete);
	/* Export CDR to file */
	iface_ipc_register_msg_cb(MSG_EXP_CDR, cb_ue_cdr_flush);

	/* VS: Register DDN ACK messgae handler */
	iface_ipc_register_msg_cb(MSG_DDN_ACK, cb_ddn_ack);
}

