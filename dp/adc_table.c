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

#include "vepc_cp_dp_api.h"
#include "main.h"
#include "util.h"
#include "acl_dp.h"
#include "interface.h"
#include "meter.h"
#include <sponsdn.h>

#define IS_MAX_REACHED(table) \
	((table.num_entries == table.max_entries) ? 1 : 0)

struct table adc_table;

/**
 * @brief  : Compare ADC Rule entries.
 * @param  : r1p, rule entry to compare
 * @param  : r2p, rule entry to compare
 * @return : Returns 0 if same rule id, -1 if first rule id is less than second, 1 otherwise
 */
static int adc_rule_id_compare(const void *r1p, const void *r2p)
{
	const struct adc_rules *r1, *r2;

	r1 = (const struct adc_rules *) r1p;
	r2 = (const struct adc_rules *) r2p;

	/* compare rule_ids */
	if (r1->rule_id < r2->rule_id)
		return -1;
	else if (r1->rule_id == r2->rule_id)
		return 0;
	else
		return 1;

}

/**
 * @brief  : Print the ADC Rule entry.
 * @param  : nodep, holds adc rule info
 * @param  : which, type of tsearch
 * @param  : depth, depth of entry
 * @return : Returns nothing
 */
static void adc_print_rule(const void *nodep, const VISIT which, const int depth)
{
	struct adc_rules *r;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct adc_rules **) nodep;
#pragma GCC diagnostic pop   /* require GCC 4.6 */

	switch (which) {
	case leaf:
	case postorder:
		clLog(clSystemLog, eCLSeverityDebug,"Depth: %d, Rule ID: %d\n",
				depth, r->rule_id);
		break;
	default:
		break;
	}
}

/**
 * @brief  : Dump the table entries.
 * @param  : table, table pointer whose entries to dumb.
 * @return : Returns nothing
 */
__rte_unused static void dump_table(struct table *t)
{
	twalk(t->root, t->print_entry);
}


/**
 * @brief  : Create ADC filter table.
 * @param  : dp_id
 *           identifier which is unique across DataPlanes.
 * @param  : max_element
 *           max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dp_adc_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	if (adc_table.root != NULL) {
		clLog(clSystemLog, eCLSeverityInfo, "ADC filter table: \"%s\" exist\n", dp_id.name);
		return -1;
	}
	adc_table.num_entries = 0;
	adc_table.max_entries = max_elements;
	strncpy(adc_table.name, dp_id.name, MAX_LEN);
	adc_table.active = 1;
	adc_table.compare = adc_rule_id_compare;
	adc_table.print_entry = adc_print_rule;
	clLog(clSystemLog, eCLSeverityInfo, "ADC filter table: \"%s\" created\n", dp_id.name);
	return 0;
}

/**
 * @brief  : Free the memory allocated for node.
 * @param  : p, void pointer to be free.
 * @return : Returns nothing
 */
static void free_node(void *p)
{
	rte_free(p);
}

/**
 * @brief  : Delete ADC filter table.
 * @param  : dp_id
 *           identifier which is unique across DataPlanes.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dp_adc_table_delete(struct dp_id dp_id)
{
	tdestroy(&adc_table.root, free_node);
	memset(&adc_table, 0, sizeof(struct table));
	clLog(clSystemLog, eCLSeverityInfo, "ADC filter table: \"%s\" destroyed\n", dp_id.name);
	return 0;
}

/**
 * @brief  : Add ADC filter entry.
 * @param  : dp_id, identifier which is unique across DataPlanes.
 * @param  : adc_filter_entry, element to be added in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dp_adc_entry_add(struct dp_id dp_id, struct adc_rules *adc_filter_entry)
{
	if (IS_MAX_REACHED(adc_table)) {
		clLog(clSystemLog, eCLSeverityInfo, "Reached max ADC filter entries\n");
		return -1;
	}

	struct adc_rules *new = rte_malloc("adc_filter", sizeof(struct adc_rules),
			RTE_CACHE_LINE_SIZE);
	if (new == NULL) {
		clLog(clSystemLog, eCLSeverityInfo, "ADC: Failed to allocate memory\n");
		return -1;
	}
	*new = *adc_filter_entry;
	/* put node into the tree */
	if (tsearch(new, &adc_table.root, adc_table.compare) == 0) {
		clLog(clSystemLog, eCLSeverityInfo, "Fail to add adc rule_id %d\n",
				adc_filter_entry->rule_id);
		return -1;
	}

	adc_table.num_entries++;

	/* add entry in adc acl table */
	if (adc_filter_entry->sel_type == DOMAIN_IP_ADDR) {
		struct pkt_filter msg_payload;
		uint32_t ipv4 = adc_filter_entry->u.domain_ip.u.ipv4_addr;

		msg_payload.pcc_rule_id = adc_filter_entry->rule_id;
		//msg_payload.precedence = adc_filter_entry->precedence;
		sprintf(msg_payload.u.rule_str, "0.0.0.0/0 "IPV4_ADDR"/32 0 : 65535 0 : 65535 0x0/0x0 \n",
				IPV4_ADDR_HOST_FORMAT(ipv4));
		dp_adc_filter_entry_add(dp_id, &msg_payload);
		sprintf(msg_payload.u.rule_str, ""IPV4_ADDR"/32 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0 \n",
				IPV4_ADDR_HOST_FORMAT(ipv4));
		dp_adc_filter_entry_add(dp_id, &msg_payload);

		clLog(clSystemLog, eCLSeverityInfo, "ADC_TBL ADD: rule_id:%d, domain_ip:"\
				IPV4_ADDR"\n", adc_filter_entry->rule_id,
				IPV4_ADDR_HOST_FORMAT(\
					adc_filter_entry->u.domain_ip.u.ipv4_addr));

	} else if (adc_filter_entry->sel_type == DOMAIN_IP_ADDR_PREFIX) {
		struct pkt_filter msg_payload;
		uint32_t ipv4 = adc_filter_entry->u.domain_prefix.ip_addr.u.ipv4_addr;
		uint32_t prefix = adc_filter_entry->u.domain_prefix.prefix;

		msg_payload.pcc_rule_id = adc_filter_entry->rule_id;
		//msg_payload.precedence = adc_filter_entry->precedence;
		sprintf(msg_payload.u.rule_str, "0.0.0.0/0 "IPV4_ADDR"/%u 0 : 65535 0 : 65535 0x0/0x0 \n",
				IPV4_ADDR_HOST_FORMAT(ipv4), prefix);
		dp_adc_filter_entry_add(dp_id, &msg_payload);
		sprintf(msg_payload.u.rule_str, ""IPV4_ADDR"/%u 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0 \n",
				IPV4_ADDR_HOST_FORMAT(ipv4), prefix);
		dp_adc_filter_entry_add(dp_id, &msg_payload);

		clLog(clSystemLog, eCLSeverityInfo, "ADC_TBL ADD: rule_id:%d, domain_ip:"\
				IPV4_ADDR"\n",
				adc_filter_entry->rule_id,
				IPV4_ADDR_HOST_FORMAT(\
					adc_filter_entry->u.domain_prefix.ip_addr.u.ipv4_addr));

	} else if (adc_filter_entry->sel_type == DOMAIN_NAME) {
		int ret;

		ret = epc_sponsdn_dn_add_single(adc_filter_entry->u.domain_name, adc_filter_entry->rule_id);
		if (ret)
			clLog(clSystemLog, eCLSeverityDebug, "failed to add DN error code %d\n", ret);
		clLog(clSystemLog, eCLSeverityInfo, "Spons DN ADD: rule_id:%d, domain_name:%s\n",
				adc_filter_entry->rule_id, adc_filter_entry->u.domain_name);
	}
	return 0;
}

/**
 * @brief  : Delete ADC filter entry.
 * @param  : dp_id, identifier which is unique across DataPlanes.
 * @param  : adc_filter_entry, element to be added in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dp_adc_entry_delete(struct dp_id dp_id, struct adc_rules *adc_filter_entry)
{
	void **p;
	RTE_SET_USED(dp_id);
	/* delete node from the tree */
	p = tdelete(adc_filter_entry, &adc_table.root, adc_rule_id_compare);
	if (p == NULL) {
		clLog(clSystemLog, eCLSeverityInfo, "Fail to delete rule_id %d\n",
						adc_filter_entry->rule_id);
		return -1;
	}
	rte_free(*p);
	adc_table.num_entries--;
	clLog(clSystemLog, eCLSeverityInfo, "ADC filter entry with rule_id %d deleted\n",
					adc_filter_entry->rule_id);
	return 0;
}

int
adc_rule_info_get(uint32_t *rid, uint32_t n, uint64_t *pkts_mask, void **adc_info)
{
	struct adc_rules new;
	uint32_t i;
	void **p;

	for (i = 0; i < n; i++) {
		new.rule_id = rid[i];
		/* skip adc process*/
		if (new.rule_id == 0) {
			adc_info[i] = NULL;
			continue;
		}

		/* put node into the tree */
		p = tfind(&new, &adc_table.root, adc_table.compare);
		if (p == NULL) {
			/* adc rule not found, drop the pkt*/
			RESET_BIT(*pkts_mask, i);
			adc_info[i] = NULL;
			clLog(clSystemLog, eCLSeverityDebug, "ADC rule not found for id %u\n", rid[i]);
		} else
			adc_info[i] = *p;
	}
	return 0;
}

/**
 * @brief  : Gate ADC filter entry.
 * @param  : rid, ADC rule id.
 * @param  : adc_info, ADC information.
 * @param  : n, num. of rule ids.
 * @param  : adc_pkts_mask, set the adc pkt mask only if adc gate is open.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @return : Returns nothing
 */
void
adc_gating(uint32_t *rid, void **adc_ue_info, uint32_t n,
			uint64_t *adc_pkts_mask, uint64_t *pkts_mask)
{
	struct dp_adc_ue_info *adc_ue;
	uint32_t i;

	for (i = 0; i < n; i++) {
		/* skip gating*/
		if (rid[i] == 0)
			continue;
		adc_ue = (struct dp_adc_ue_info *)adc_ue_info[i];
		if (adc_ue == NULL)
			continue;
		if (adc_ue->adc_info.gate_status == CLOSE)
			RESET_BIT(*pkts_mask, i);
		else
			SET_BIT(*adc_pkts_mask, i);
	}
}

/******************** Callback functions **********************/
/**
 * @brief  : Callback to parse msg to create adc rules table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_adc_table_create(struct msgbuf *msg_payload)
{
	return adc_table_create(msg_payload->dp_id,
					msg_payload->msg_union.msg_table.max_elements);
}

/**
 * @brief  : Callback to parse msg to delete table
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_adc_table_delete(struct msgbuf *msg_payload)
{
	return adc_table_delete(msg_payload->dp_id);
}

/**
 * @brief  : Callback to parse msg to add adc rules
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
//static
int cb_adc_entry_add(struct msgbuf *msg_payload)
{
	return adc_entry_add(msg_payload->dp_id,
					msg_payload->msg_union.adc_filter_entry);
}

/**
 * @brief  : Delete adc rules.
 * @param  : msg_payload, payload from CP
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
cb_adc_entry_delete(struct msgbuf *msg_payload)
{
	return adc_entry_delete(msg_payload->dp_id,
					msg_payload->msg_union.adc_filter_entry);
}

/**
 * @brief  : Initialization of ADC Table Callback functions.
 * @param  : No param
 * @return : Returns nothing
 */
void app_adc_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_ADC_TBL_CRE, cb_adc_table_create);
	iface_ipc_register_msg_cb(MSG_ADC_TBL_DES, cb_adc_table_delete);
	iface_ipc_register_msg_cb(MSG_ADC_TBL_ADD, cb_adc_entry_add);
	iface_ipc_register_msg_cb(MSG_ADC_TBL_DEL, cb_adc_entry_delete);
}
