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

#include <stdio.h>
#include <rte_hash_crc.h>

#include "cp.h"
#include "pfcp.h"

#define PFCP_CNTXT_HASH_SIZE (1 << 18)

const uint8_t bar_base_rule_id = 0xFF;
static uint8_t bar_rule_id_offset;
const uint16_t pdr_base_rule_id = 0xFFFF;
static uint16_t pdr_rule_id_offset;
const uint32_t far_base_rule_id = 0xFFFFFFFF;
static uint32_t far_rule_id_offset;
const uint32_t qer_base_rule_id = 0xFFFFFFFF;
static uint32_t qer_rule_id_offset;

/*
 * Add context entry in pfcp context hash table.
 *
 * @param rule_id
 * key.
 * @param pfcp_cntxt Resp
 * return 0 or 1.
 *
 */
	uint8_t
add_pfcp_cntxt_entry(uint16_t rule_id, struct pfcp_cntxt *cntxt)
{
	int ret = 0;
	struct pfcp_cntxt *tmp = NULL;

	/* Lookup for pfcp context entry. */
	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
			&rule_id, (void **)&tmp);

	if ( ret < 0) {
		/* pfcp context Entry not present. Add pfcp context Entry */
		ret = rte_hash_add_key_data(pfcp_cntxt_hash,
				&rule_id, cntxt);
		if (ret) {
			fprintf(stderr, "%s: Failed to add entry for rule_id = %u"
					"\n\tError= %s\n",
					__func__, rule_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(struct pfcp_cntxt));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: PFCP context entry add for Rule_Id:%u",
			__func__, rule_id);
	return 0;
}

	uint8_t
get_pfcp_cntxt_entry(uint16_t rule_id, struct pfcp_cntxt **cntxt)
{
	int ret = 0;
	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
			&rule_id, (void **)cntxt);

	if ( ret < 0) {
		fprintf(stderr, "Entry not found for rule_id:%u...\n", rule_id);
		return -1;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: Rule_Id:%u",
			__func__, rule_id);
	return 0;

}

	uint8_t
del_pfcp_cntxt_entry(uint16_t rule_id)
{
	int ret = 0;
	struct pfcp_cntxt *cntxt = NULL;

	/* Check Session Entry is present or Not */
	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
			&rule_id, (void **)&cntxt);
	if (ret) {
		/* Session Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(pfcp_cntxt_hash, &rule_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:Entry not found for rule_id:%u...\n",
					__func__, rule_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(cntxt);

	RTE_LOG_DP(DEBUG, CP, "%s: Rule_Id:%u",
			__func__, rule_id);

	return 0;
}

/*
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information.
 */
	void
init_pfcp_cntxt_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "pfcp_cntxt_hash",
		.entries = PFCP_CNTXT_HASH_SIZE,
		.key_len = sizeof(uint16_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	pfcp_cntxt_hash = rte_hash_create(&rte_hash_params);
	if (!pfcp_cntxt_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}
}

	uint8_t
generate_bar_id(void)
{
	uint8_t id = 0;

	id = bar_base_rule_id + (++bar_rule_id_offset);

	return id;
}

	uint16_t
generate_pdr_id(void)
{
	uint16_t id = 0;

	id = pdr_base_rule_id + (++pdr_rule_id_offset);

	return id;
}

	uint32_t
generate_far_id(void)
{
	uint32_t id = 0;

	id = far_base_rule_id + (++far_rule_id_offset);

	return id;
}

	uint32_t
generate_qer_id(void)
{
	uint32_t id = 0;

	id = qer_base_rule_id + (++qer_rule_id_offset);

	return id;
}

uint32_t
generate_far_id_mbr(void)
{
	uint32_t id = 0;

	id = far_base_rule_id + (far_rule_id_offset);

	return id;
}
