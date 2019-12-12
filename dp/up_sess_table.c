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

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include "util.h"
#include "up_acl.h"

extern struct rte_hash *sess_ctx_by_sessid_hash;
extern struct rte_hash *sess_by_teid_hash;
extern struct rte_hash *sess_by_ueip_hash;
extern struct rte_hash *pdr_by_id_hash;
extern struct rte_hash *far_by_id_hash;
extern struct rte_hash *qer_by_id_hash;
extern struct rte_hash *urr_by_id_hash;


/* Retrive the Session information based on teid */
int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value)
{
	return rte_hash_lookup_data(sess_by_teid_hash, key, value);
}

/* Retrive the Session information based on teid */
int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	return rte_hash_lookup_bulk_data(sess_by_teid_hash, key, n, hit_mask, value);
}

/* Retrive the Session information based on UE IP */
int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value)
{
	return rte_hash_lookup_data(sess_by_ueip_hash, key, value);
}

/* Retrive the Session information based on UE IP */
int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value)
{
	return rte_hash_lookup_bulk_data(sess_by_ueip_hash, key, n, hit_mask, value);
}


