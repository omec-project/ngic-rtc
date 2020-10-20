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

#include <stdio.h>
#include <time.h>
#include <rte_hash_crc.h>

#include "cp.h"
#include "pfcp.h"
#include "gw_adapter.h"

/*VS:TODO: Need to revist this for hash size */
#define PFCP_CNTXT_HASH_SIZE (1 << 15)

#define TIMESTAMP_LEN 14
#define NUM_OF_TABLES 4
#define NUM_INIT_TABLES 3

#define MAX_HASH_SIZE (1 << 15)
#define MAX_SEQ_ENTRIES_HASH_SIZE (1 << 10)
#define MAX_PDN_HASH_SIZE (1 << 12)

const uint8_t bar_base_rule_id = 0x00;
static uint8_t bar_rule_id_offset;
const uint16_t pdr_base_rule_id = 0x0000;
static uint16_t pdr_rule_id_offset;
const uint32_t far_base_rule_id = 0x00000000;
const uint32_t urr_base_rule_id = 0x00000000;
static uint32_t far_rule_id_offset;
static uint32_t urr_rule_id_offset;
const uint32_t qer_base_rule_id = 0x00000000;
static uint32_t qer_rule_id_offset;
/* VS: Need to decide the base value of call id */
/* const uint32_t call_id_base_value = 0xFFFFFFFF; */
const uint32_t call_id_base_value = 0x00000000;
static uint32_t call_id_offset;
static uint64_t dp_sess_id_offset;
const uint32_t rar_base_rule_id = 0x00000000;

const uint32_t base_seq_number = 0x00000000;
static uint32_t seq_number_offset;
extern int clSystemLog;

/**
 * Add PDN Connection entry in PDN hash table.
 *
 * @param CALL ID
 * key.
 * @param pdn_connection pdn
 * return 0 or 1.
 *
 */
uint8_t
add_pdn_conn_entry(uint32_t call_id, pdn_connection *pdn)
{
	int ret = 0;
	pdn_connection *tmp = NULL;

	/* Lookup for PDN Connection entry. */
	ret = rte_hash_lookup_data(pdn_conn_hash,
				&call_id, (void **)&tmp);

	if ( ret < 0) {
		/* PDN Connection Entry if not present */
		ret = rte_hash_add_key_data(pdn_conn_hash,
						&call_id, pdn);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add pdn "
				"connection for CALL_ID = %u"
				"\n\tError= %s\n", LOG_VALUE, call_id,
				rte_strerror(abs(ret)));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	} else {
		memcpy(tmp, pdn, sizeof(pdn_connection));
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" PDN Connection entry add for CALL_ID:%u",
		LOG_VALUE, call_id);
	return 0;
}

/**
 * Get PDN Connection entry from PDN hash table.
 *
 * @param CALL ID
 * key.
 * return pdn_connection pdn or NULL
 *
 */
pdn_connection *get_pdn_conn_entry(uint32_t call_id)
{
	int ret = 0;
	pdn_connection *pdn = NULL;

	/* Check PDN Conn entry is present or Not */
	ret = rte_hash_lookup_data(pdn_conn_hash,
				&call_id, (void **)&pdn);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for CALL_ID:%u "
			"while extrating PDN entry\n", LOG_VALUE, call_id);
		return NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CALL_ID for PDN connection entry:%u", LOG_VALUE, call_id);
	return pdn;

}

/**
 * Delete PDN Connection entry from PDN hash table.
 *
 * @param CALL ID
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_pdn_conn_entry(uint32_t call_id)
{
	int ret = 0;
	pdn_connection *pdn = NULL;

	/* Check PDN Conn entry is present or Not */
	ret = rte_hash_lookup_data(pdn_conn_hash,
					&call_id, (void **)&pdn);
	if (ret >= 0) {
		/* PDN Conn Entry is present. Delete PDN Conn Entry */
		ret = rte_hash_del_key(pdn_conn_hash, &call_id);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for CALL_ID :%u while deleting PDN connection entry\n", LOG_VALUE, call_id);
			return -1;
		}
	}

	/* Free data from hash */
	if (pdn != NULL) {
		rte_free(pdn);
		pdn = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CALL_ID for PDN connection entry:%u", LOG_VALUE, call_id);

	return 0;
}
/**
 * Add Rule name entry with bearer identifier in Rule and bearer map hash table.
 *
 * @param Rule_Name
 * key.
 * @param uint8_t bearer id
 * return 0 or 1.
 *
 */
uint8_t
add_rule_name_entry(const rule_name_key_t rule_key, bearer_id_t *bearer)
{
	int ret = 0;
	bearer_id_t *tmp = NULL;

	/* Lookup for Rule entry. */
	ret = rte_hash_lookup_data(rule_name_bearer_id_map_hash,
				&rule_key, (void **)&tmp);

	if ( ret < 0) {
		/* Rule Entry if not present */
		ret = rte_hash_add_key_data(rule_name_bearer_id_map_hash,
						&rule_key, bearer);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add rule "
				"entry for Rule_Name = %s"
				"\n\tError= %s\n", LOG_VALUE, rule_key.rule_name,
				rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, bearer, sizeof(bearer_id_t));
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Rule Name entry add for "
		"Rule_Name:%s, Bearer_id:%u\n",
		LOG_VALUE, rule_key.rule_name, bearer->bearer_id);
	return 0;
}

/**
 * Get Rule Name entry from Rule and Bearer Map table.
 *
 * @param Rule_Name
 * key.
 * return Bearer ID or NULL
 *
 */
int8_t
get_rule_name_entry(const rule_name_key_t rule_key)
{
	int ret = 0;
	bearer_id_t *bearer = NULL;

	/* Check Rule Name entry is present or Not */
	ret = rte_hash_lookup_data(rule_name_bearer_id_map_hash,
				&rule_key, (void **)&bearer);
	if ( ret < 0) {
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": Rule_Name:%s, Bearer_ID:%u\n",
		LOG_VALUE, rule_key.rule_name, bearer->bearer_id);
	return bearer->bearer_id;
}

int8_t
add_seq_number_for_teid(const teid_key_t teid_key, struct teid_value_t *teid_value)
{
	int ret = 0;
	struct teid_value_t *tmp = NULL;

	ret = rte_hash_lookup_data(ds_seq_key_with_teid,
				&teid_key, (void **)&tmp);
	if(ret < 0) {
		ret = rte_hash_add_key_data(ds_seq_key_with_teid,
						&teid_key, teid_value);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add TEID "
				"entry for key = %s"
				"\n\tError= %s\n", LOG_VALUE, teid_key.teid_key,
				rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, &teid_value, sizeof(struct teid_value_t));
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":TEID entry added for "
		"key :%s, TEID : %u\n",
		LOG_VALUE, teid_key.teid_key, teid_value->teid);
	return 0;
}

teid_value_t *get_teid_for_seq_number(const teid_key_t teid_key)
{
	int ret = 0;
	teid_value_t *teid_value = NULL;

	/* lookup the entry based on the sequence number */
	ret = rte_hash_lookup_data(ds_seq_key_with_teid,
				&teid_key, (void **)&teid_value);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get teid value "
			"for key : %s\n", LOG_VALUE, teid_key.teid_key);
		return NULL;
	}
	//memcpy(teid_t, teid, sizeof(uint32_t));
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Found entry for Key:%s, TEID:%u\n",
			LOG_VALUE, teid_key.teid_key, teid_value->teid);

	return teid_value;
}

int8_t
delete_teid_entry_for_seq(const teid_key_t teid_key)
{
	int ret = 0;
	struct teid_value_t *teid_value = NULL;

	ret = rte_hash_lookup_data(ds_seq_key_with_teid,
				&teid_key, (void **)&teid_value);
	if(ret >= 0) {

		ret = rte_hash_del_key(ds_seq_key_with_teid, &teid_key);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to "
				"delete TEID entry for key = %s\n\tError= %s\n", LOG_VALUE,
				teid_key.teid_key, rte_strerror(abs(ret)));
			return -1;
		}
	}

	/* Free data from hash */
	if (teid_value != NULL) {
		rte_free(teid_value);
		teid_value = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"TEID entry deleted for "
		"teid key :%s\n", LOG_VALUE, teid_key.teid_key);
	return 0;
}

/**
 * Delete Rule Name entry from Rule and Bearer Map hash table.
 *
 * @param Rule_Name
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_rule_name_entry(const rule_name_key_t rule_key)
{
	int ret = 0;
	bearer_id_t *bearer = NULL;

	/* Check Rule Name entry is present or Not */
	ret = rte_hash_lookup_data(rule_name_bearer_id_map_hash,
					&rule_key, (void **)bearer);
	if (ret >= 0) {
		/* Rule Name Entry is present. Delete Rule Name Entry */
		ret = rte_hash_del_key(rule_name_bearer_id_map_hash, &rule_key);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Entry not found for Rule_Name:%s...\n",
						LOG_VALUE, rule_key.rule_name);
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Rule_Name:%s is found \n",
				LOG_VALUE, rule_key.rule_name);
	} else {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Rule_Name:%s is not "
			"found \n", LOG_VALUE, rule_key.rule_name);
	}

	/* Free data from hash */
	if (bearer != NULL) {
		free(bearer);
		bearer = NULL;
	}

	return 0;
}


/**
 * Add PDR entry in PDR hash table.
 *
 * @param rule_id/PDR_ID
 * key.
 * @param pdr_t cntxt
 * return 0 or 1.
 *
 */
uint8_t
add_pdr_entry(uint16_t rule_id, pdr_t *cntxt)
{
	int ret = 0;
	pdr_t *tmp = NULL;

	/* Lookup for PDR entry. */
	ret = rte_hash_lookup_data(pdr_entry_hash,
				&rule_id, (void **)&tmp);

	if ( ret < 0) {
		/* PDR Entry not present. Add PDR Entry */
		ret = rte_hash_add_key_data(pdr_entry_hash,
						&rule_id, cntxt);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add entry for PDR_ID = %u"
				"\n\tError= %s\n", LOG_VALUE, rule_id, rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(pdr_t));
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": PDR entry added for PDR_ID:%u\n",
		LOG_VALUE, rule_id);
	return 0;
}

/**
 * Get PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * return pdr_t cntxt or NULL
 *
 */
pdr_t *get_pdr_entry(uint16_t rule_id)
{
	int ret = 0;
	pdr_t *cntxt = NULL;

	ret = rte_hash_lookup_data(pdr_entry_hash,
				&rule_id, (void **)&cntxt);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for PDR_ID:%u...\n",
			LOG_VALUE, rule_id);
		return NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": PDR_ID:%u\n",
		LOG_VALUE, rule_id);
	return cntxt;

}

int
update_pdr_teid(eps_bearer *bearer, uint32_t teid, node_address_t addr, uint8_t iface){
	int ret = -1;

	for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
		if(bearer->pdrs[itr] == NULL)
			continue;

		if(bearer->pdrs[itr]->pdi.src_intfc.interface_value == iface){
			bearer->pdrs[itr]->pdi.local_fteid.teid = teid;

			if(addr.ip_type == PDN_IP_TYPE_IPV4)  {
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address = addr.ipv4_addr;
				bearer->pdrs[itr]->pdi.local_fteid.v4 = PRESENT;
			}

			if(addr.ip_type == PDN_IP_TYPE_IPV6) {
				memcpy(bearer->pdrs[itr]->pdi.local_fteid.ipv6_address,
					addr.ipv6_addr, IPV6_ADDRESS_LEN);
				bearer->pdrs[itr]->pdi.local_fteid.v6 = PRESENT;
			}

			if(addr.ip_type == PDN_IP_TYPE_IPV4V6) {
				bearer->pdrs[itr]->pdi.local_fteid.ipv4_address = addr.ipv4_addr;
				memcpy(bearer->pdrs[itr]->pdi.local_fteid.ipv6_address,
					addr.ipv6_addr, IPV6_ADDRESS_LEN);
				bearer->pdrs[itr]->pdi.local_fteid.v4 = PRESENT;
				bearer->pdrs[itr]->pdi.local_fteid.v6 = PRESENT;
			}
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Updated pdr entry Successfully for PDR_ID:%u\n",
				LOG_VALUE, bearer->pdrs[itr]->rule_id);
			ret = 0;
			break;
		}
	}
	return ret;
}

/**
 * Delete PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_pdr_entry(uint16_t rule_id)
{
	int ret = 0;
	pdr_t *cntxt = NULL;

	/* Check PDR entry is present or Not */
	ret = rte_hash_lookup_data(pdr_entry_hash,
					&rule_id, (void **)cntxt);
	if (ret >= 0) {
		/* PDR Entry is present. Delete PDR Entry */
		ret = rte_hash_del_key(pdr_entry_hash, &rule_id);

	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
			"for PDR_ID:%u\n", LOG_VALUE, rule_id);
		return -1;
	}

	/* Free data from hash */
	if (cntxt != NULL) {
		rte_free(cntxt);
		cntxt = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PDR_ID:%u\n",LOG_VALUE, rule_id);

	return 0;
}

/**
 * Add QER entry in QER hash table.
 *
 * @param qer_id
 * key.
 * @param qer_t context
 * return 0 or 1.
 *
 */
uint8_t
add_qer_entry(uint32_t qer_id, qer_t *cntxt)
{
	int ret = 0;
	qer_t *tmp = NULL;

	/* Lookup for QER entry. */
	ret = rte_hash_lookup_data(qer_entry_hash,
				&qer_id, (void **)&tmp);

	if ( ret < 0) {
		/* QER Entry not present. Add QER Entry in table */
		ret = rte_hash_add_key_data(qer_entry_hash,
						&qer_id, cntxt);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add QER entry for QER_ID = %u"
				"\n\tError= %s\n", LOG_VALUE, qer_id, rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(qer_t));
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" QER entry add for QER_ID:%u\n", LOG_VALUE, qer_id);
	return 0;
}

/**
 * Get QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return qer_t cntxt or NULL
 *
 */
qer_t *get_qer_entry(uint32_t qer_id)
{
	int ret = 0;
	qer_t *cntxt = NULL;

	/* Retireve QER entry */
	ret = rte_hash_lookup_data(qer_entry_hash,
				&qer_id, (void **)&cntxt);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for QER_ID:%u "
			"while extrating QER\n", LOG_VALUE, qer_id);
		return NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": QER_ID:%u\n", LOG_VALUE, qer_id);
	return cntxt;

}

/**
 * Delete QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_qer_entry(uint32_t qer_id)
{
	int ret = 0;
	qer_t *cntxt = NULL;

	/* Check QER entry is present or Not */
	ret = rte_hash_lookup_data(qer_entry_hash,
					&qer_id, (void **)cntxt);
	if (ret >= 0) {
		/* QER Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(qer_entry_hash, &qer_id);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for QER_ID:%u while deleting QER\n", LOG_VALUE, qer_id);
			return -1;
		}
	}

	/* Free data from hash */
	if (cntxt != NULL) {
		rte_free(cntxt);
		cntxt = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"QER_ID:%u\n", LOG_VALUE, qer_id);

	return 0;
}

/**
 * Generate the BAR ID
 */
uint8_t
generate_bar_id(void)
{
	uint8_t id = 0;

	id = bar_base_rule_id + (++bar_rule_id_offset);

	return id;
}

/**
 * Generate the PDR ID
 */
uint16_t
generate_pdr_id(void)
{
	uint16_t id = 0;

	id = pdr_base_rule_id + (++pdr_rule_id_offset);

	return id;
}

/**
 * Generate the FAR ID
 */
uint32_t
generate_far_id(void)
{
	uint32_t id = 0;

	id = far_base_rule_id + (++far_rule_id_offset);

	return id;
}

/**
 * NK:Generate the URR ID
 */
uint32_t
generate_urr_id(void)
{
	uint32_t id = 0;

	id = urr_base_rule_id + (++urr_rule_id_offset);

	return id;
}

/**
 * Generate the QER ID
 */
uint32_t
generate_qer_id(void)
{
	uint32_t id = 0;

	id = qer_base_rule_id + (++qer_rule_id_offset);

	return id;
}

/**
 * Generates sequence numbers for sgwc generated
 * gtpv2c messages for mme
 */
uint32_t
generate_seq_number(void)
{
	uint32_t id = 0;

	id = base_seq_number + (++seq_number_offset);

	return id;
}


/**
 * Convert the decimal value into the string.
 */
int
int_to_str(char *buf , uint32_t val)
{
	uint8_t tmp_buf[10] = {0};
	uint32_t cnt = 0, num = 0;
	uint8_t idx = 0;

	while(val)
	{
		num = val%10;
		tmp_buf[cnt] = (uint8_t)(num + 48);
		val/=10;
		++cnt;
	}

	tmp_buf[cnt] = '\0';
	--cnt;

	for(; tmp_buf[idx]; ++idx)
	{

		buf[idx] = tmp_buf[cnt];
		--cnt;
	}

	buf[idx] = '\0';
	return idx;

}

/**
 * @brief  : Get the system current timestamp.
 * @param  : timestamp is used for storing system current timestamp
 * @return : Returns 0 in case of success
 */
static uint8_t
get_timestamp(char *timestamp)
{

	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	strftime(timestamp, MAX_LEN, "%Y%m%d%H%M%S", tmp);
	return 0;
}

/**
 * @brief  : Generate CCR session id with the combination of timestamp and call id
 * @param  : str_buf is used to store generated session id
 * @param  : timestamp is used to pass timestamp
 * @param  : value is used to pas call id
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
gen_sess_id_string(char *str_buf, char *timestamp , uint32_t value)
{
	char buf[MAX_LEN] = {0};
	int len = 0;

	if (timestamp == NULL)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Time stamp is NULL "
			"while generating session ID\n", LOG_VALUE);
		return -1;
	}

	/* itoa(value, buf, 10);  10 Means base value, i.e. indicate decimal value */
	len = int_to_str(buf, value);

	if(buf[0] == 0)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed in coversion of "
			"integer to string, len:%d \n", LOG_VALUE, len);
		return -1;
	}

	snprintf(str_buf, MAX_LEN,"%s%s", timestamp, buf);
	return 0;
}

/**
 * Generate the CALL ID
 */
uint32_t
generate_call_id(void)
{
	uint32_t call_id = 0;
	call_id = call_id_base_value + (++call_id_offset);

	return call_id;
}

/**
 * Retrieve the call id from the CCR session id.
 */
int
retrieve_call_id(char *str, uint32_t *call_id)
{
	uint8_t idx = 0, index = 0;
	char buf[MAX_LEN] = {0};

	if(str == NULL)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"String is NULL \n", LOG_VALUE);
		return -1;
	}

	idx = TIMESTAMP_LEN; /* TIMESTAMP STANDARD BYTE SIZE */
	for(;str[idx] != '\0'; ++idx)
	{
		buf[index] = str[idx];
		++index;
	}

	*call_id = atoi(buf);
	if (*call_id == 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Call ID not found\n", LOG_VALUE);
		return -1;
	}
	return 0;
}

/**
 * Return the CCR session id.
 */
int8_t
gen_sess_id_for_ccr(char *sess_id, uint32_t call_id)
{
	char timestamp[MAX_LEN] = {0};

	get_timestamp(timestamp);

	if((gen_sess_id_string(sess_id, timestamp, call_id)) < 0)
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to generate "
			"session id for CCR\n", LOG_VALUE);
		return -1;
	}
	return 0;
}

/**
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information.
 */
void
init_hash_tables(void)
{
	struct rte_hash_parameters
		pfcp_hash_params[NUM_OF_TABLES] = {
		{	.name = "PDR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint16_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "QER_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "URR_ENTRY_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "PDN_CONN_HASH",
			//.entries = MAX_PDN_HASH_SIZE,
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		}
	};

	pdr_entry_hash = rte_hash_create(&pfcp_hash_params[0]);
	if (!pdr_entry_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[0].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	qer_entry_hash = rte_hash_create(&pfcp_hash_params[1]);
	if (!qer_entry_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[1].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	urr_entry_hash = rte_hash_create(&pfcp_hash_params[2]);
	if (!urr_entry_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[2].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	pdn_conn_hash = rte_hash_create(&pfcp_hash_params[3]);
	if (!pdn_conn_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[3].name,
		    rte_strerror(rte_errno), rte_errno);
	}

}


/**
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information in control plane.
 */
void
init_pfcp_tables(void)
{

	struct rte_hash_parameters
		pfcp_hash_params[NUM_INIT_TABLES] = {
		{	.name = "PFCP_CNTXT_HASH",
			.entries = PFCP_CNTXT_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "RULE_NAME_BEARER_ID_HASH",
			.entries = MAX_PDN_HASH_SIZE,
			.key_len = sizeof(rule_name_key_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "DS_SEQ_TEID_HASH",
			.entries = MAX_HASH_SIZE,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		}
	};

	pfcp_cntxt_hash = rte_hash_create(&pfcp_hash_params[0]);
	if (!pfcp_cntxt_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[0].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	rule_name_bearer_id_map_hash = rte_hash_create(&pfcp_hash_params[1]);
	if (!rule_name_bearer_id_map_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[1].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	ds_seq_key_with_teid = rte_hash_create(&pfcp_hash_params[2]);
	if (!ds_seq_key_with_teid) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				pfcp_hash_params[2].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	init_hash_tables();

}

/**
 * Generate the SESSION ID
 */
uint64_t
generate_dp_sess_id(uint64_t cp_sess_id)
{
	uint64_t dp_sess_id = 0;

	dp_sess_id = ((++dp_sess_id_offset << 32) | cp_sess_id);

	return dp_sess_id;
}

