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
#include <time.h>
#include <rte_hash_crc.h>

#include "cp.h"
#include "pfcp.h"

/*VS:TODO: Need to revist this for hash size */
#define PFCP_CNTXT_HASH_SIZE (1 << 15)

#define TIMESTAMP_LEN 14
#define NUM_OF_TABLES 4

#define MAX_HASH_SIZE (1 << 15)
#define MAX_PDN_HASH_SIZE (1 << 4)

const uint8_t bar_base_rule_id = 0xFF;
static uint8_t bar_rule_id_offset;
const uint16_t pdr_base_rule_id = 0x0000;
static uint16_t pdr_rule_id_offset;
const uint32_t far_base_rule_id = 0x00000000;
static uint32_t far_rule_id_offset;
const uint32_t qer_base_rule_id = 0x00000000;
static uint32_t qer_rule_id_offset;
/* VS: Need to decide the base value of call id */
/* const uint32_t call_id_base_value = 0xFFFFFFFF; */
const uint32_t call_id_base_value = 0x00000000;
static uint32_t call_id_offset;
static uint64_t dp_sess_id_offset;
const uint32_t rar_base_rule_id = 0x00000000;
static uint32_t rar_rule_id_offset;



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
			fprintf(stderr, "%s:%d Failed to add pdn connection for CALL_ID = %u"
					"\n\tError= %s\n",
					__func__, __LINE__, call_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, pdn, sizeof(pdn_connection));
	}

	RTE_LOG_DP(DEBUG, CP, "%s:%d PDN Connection entry add for CALL_ID:%u",
			__func__, __LINE__, call_id);
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
		fprintf(stderr, "%s:%d Entry not found for CALL_ID:%u...\n",
				__func__, __LINE__, call_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, CP, "%s:%d CALL_ID:%u",
			__func__, __LINE__, call_id);
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
	if (ret) {
		/* PDN Conn Entry is present. Delete PDN Conn Entry */
		ret = rte_hash_del_key(pdn_conn_hash, &call_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for CALL_ID:%u...\n",
						__func__, __LINE__, call_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(pdn);

	RTE_LOG_DP(DEBUG, CP, "%s: CALL_ID:%u",
			__func__, call_id);

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
			fprintf(stderr, "%s:%d Failed to add rule entry for Rule_Name = %s"
					"\n\tError= %s\n",
					__func__, __LINE__, rule_key.rule_name,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, bearer, sizeof(bearer_id_t));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: Rule Name entry add for Rule_Name:%s, Bearer_id:%u\n",
			__func__, rule_key.rule_name, bearer->bearer_id);
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
		fprintf(stderr, "%s:%d Entry not found for Rule_Name:%s...\n",
				__func__, __LINE__, rule_key.rule_name);
		return -1;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: Rule_Name:%s, Bearer_ID:%u\n",
			__func__, rule_key.rule_name, bearer->bearer_id);
	return bearer->bearer_id;

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
					&rule_key, (void **)&bearer);
	if (ret) {
		/* Rule Name Entry is present. Delete Rule Name Entry */
		ret = rte_hash_del_key(rule_name_bearer_id_map_hash, &rule_key);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for Rule_Name:%s...\n",
						__func__, __LINE__, rule_key.rule_name);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(bearer);

	RTE_LOG_DP(DEBUG, CP, "%s: Rule_Name:%s\n",
			__func__, rule_key.rule_name);

	return 0;
}

/**
 * Add context entry in pfcp context hash table.
 *
 * @param sess_id
 * key.
 * @param pfcp_cntxt cntxt
 * return 0 or 1.
 *
 */
uint8_t
add_pfcp_cntxt_entry(uint64_t sess_id, struct pfcp_cntxt *cntxt)
{
	int ret = 0;
	struct pfcp_cntxt *tmp = NULL;

	/* Lookup for pfcp context entry. */
	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
				&sess_id, (void **)&tmp);

	if ( ret < 0) {
		/* pfcp context Entry not present. Add pfcp context Entry */
		ret = rte_hash_add_key_data(pfcp_cntxt_hash,
						&sess_id, cntxt);
		if (ret) {
			fprintf(stderr, "%s:%d Failed to add entry for Sess_id = %lu"
					"\n\tError= %s\n",
					__func__, __LINE__, sess_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(struct pfcp_cntxt));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: PFCP context entry add for Sess_Id:%lu\n",
			__func__, sess_id);
	return 0;
}

/**
 * Get PFCP Context entry from pfcp context table.
 *
 * @param SESS ID
 * key.
 * return pfcp_cntxt cntxt or NULL
 *
 */

struct pfcp_cntxt *
get_pfcp_cntxt_entry(uint64_t sess_id)
{
	int ret = 0;
	struct pfcp_cntxt *cntxt = NULL;

	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
				&sess_id, (void **)&cntxt);

	if ( ret < 0) {
		fprintf(stderr, "%s:%d Entry not found for Sess_Id:%lu...\n",
				__func__, __LINE__, sess_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: Sess_Id:%lu\n",
			__func__, sess_id);
	return cntxt;

}

/**
 * Delete PFCP context entry from PFCP Context hash table.
 *
 * @param SESS ID
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_pfcp_cntxt_entry(uint64_t sess_id)
{
	int ret = 0;
	struct pfcp_cntxt *cntxt = NULL;

	/* Check pfcp context entry is present or Not */
	ret = rte_hash_lookup_data(pfcp_cntxt_hash,
					&sess_id, (void **)&cntxt);
	if (ret) {
		/* pfcp context Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(pfcp_cntxt_hash, &sess_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for Sess_Id:%lu...\n",
						__func__, __LINE__, sess_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(cntxt);

	RTE_LOG_DP(DEBUG, CP, "%s: Sess_Id:%lu\n",
			__func__, sess_id);

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
			fprintf(stderr, "%s:%d Failed to add entry for PDR_ID = %u"
					"\n\tError= %s\n",
					__func__, __LINE__, rule_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(struct pfcp_cntxt));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: PDR entry add for PDR_ID:%u\n",
			__func__, rule_id);
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
		fprintf(stderr, "%s:%d Entry not found for PDR_ID:%u...\n",
				__func__, __LINE__, rule_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: PDR_ID:%u\n",
			__func__, rule_id);
	return cntxt;

}

/**
 * Get PDR entry from PDR hash table.
 * update entry
 */
int
update_pdr_teid(eps_bearer *bearer, uint32_t teid, uint32_t ip, uint8_t iface){
	int ret = -1;

	for(uint8_t itr = 0; itr < bearer->pdr_count ; itr++) {
		if(bearer->pdrs[itr]->pdi.src_intfc.interface_value == iface){
			bearer->pdrs[itr]->pdi.local_fteid.teid = teid;
			bearer->pdrs[itr]->pdi.local_fteid.ipv4_address = htonl(ip);
			RTE_LOG_DP(DEBUG, CP, "%s: Updated pdr entry Successfully for PDR_ID:%u\n",
					__func__, bearer->pdrs[itr]->rule_id);
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
					&rule_id, (void **)&cntxt);
	if (ret) {
		/* PDR Entry is present. Delete PDR Entry */
		ret = rte_hash_del_key(pdr_entry_hash, &rule_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for PDR_ID:%u...\n",
						__func__, __LINE__, rule_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(cntxt);
	cntxt = NULL;

	RTE_LOG_DP(DEBUG, CP, "%s: PDR_ID:%u\n",
			__func__, rule_id);

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
			fprintf(stderr, "%s:%d Failed to add QER entry for QER_ID = %u"
					"\n\tError= %s\n",
					__func__, __LINE__, qer_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(qer_t));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: QER entry add for QER_ID:%u\n",
			__func__, qer_id);
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
		fprintf(stderr, "%s:%d Entry not found for QER_ID:%u...\n",
				__func__, __LINE__, qer_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: QER_ID:%u\n",
			__func__, qer_id);
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
					&qer_id, (void **)&cntxt);
	if (ret) {
		/* QER Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(qer_entry_hash, &qer_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for QER_ID:%u...\n",
						__func__, __LINE__, qer_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(cntxt);

	RTE_LOG_DP(DEBUG, CP, "%s: QER_ID:%u\n",
			__func__, qer_id);

	return 0;
}

/**
 * Add URR entry in URR hash table.
 *
 * @param urr_id
 * key.
 * @param urr_t context
 * return 0 or 1.
 *
 */
uint8_t
add_urr_entry(uint32_t urr_id, urr_t *cntxt)
{
	int ret = 0;
	urr_t *tmp = NULL;

	/* Lookup for URR entry. */
	ret = rte_hash_lookup_data(urr_entry_hash,
				&urr_id, (void **)&tmp);

	if ( ret < 0) {
		/* URR Entry not present. Add URR Entry in table */
		ret = rte_hash_add_key_data(urr_entry_hash,
						&urr_id, cntxt);
		if (ret) {
			fprintf(stderr, "%s:%d Failed to add URR entry for URR_ID = %u"
					"\n\tError= %s\n",
					__func__, __LINE__, urr_id,
					rte_strerror(abs(ret)));
			return -1;
		}
	} else {
		memcpy(tmp, cntxt, sizeof(urr_t));
	}

	RTE_LOG_DP(DEBUG, CP, "%s: URR entry add for URR_ID:%u\n",
			__func__, urr_id);
	return 0;
}

/**
 * Get URR entry from urr hash table.
 *
 * @param URR ID
 * key.
 * return urr_t cntxt or NULL
 *
 */
urr_t *get_urr_entry(uint32_t urr_id)
{
	int ret = 0;
	urr_t *cntxt = NULL;

	/* Retireve URR entry */
	ret = rte_hash_lookup_data(urr_entry_hash,
				&urr_id, (void **)&cntxt);

	if ( ret < 0) {
		fprintf(stderr, "%s:%d Entry not found for URR_ID:%u...\n",
				__func__, __LINE__, urr_id);
		return NULL;
	}

	RTE_LOG_DP(DEBUG, CP, "%s: URR_ID:%u\n",
			__func__, urr_id);
	return cntxt;

}

/**
 * Delete URR entry from URR hash table.
 *
 * @param URR ID
 * key.
 * return 0 or 1.
 *
 */
uint8_t
del_urr_entry(uint32_t urr_id)
{
	int ret = 0;
	urr_t *cntxt = NULL;

	/* Check URR entry is present or Not */
	ret = rte_hash_lookup_data(urr_entry_hash,
					&urr_id, (void **)&cntxt);
	if (ret) {
		/* URR Entry is present. Delete Session Entry */
		ret = rte_hash_del_key(urr_entry_hash, &urr_id);

		if ( ret < 0) {
			fprintf(stderr, "%s:%d Entry not found for URR_ID:%u...\n",
						__func__, __LINE__, urr_id);
			return -1;
		}
	}

	/* Free data from hash */
	rte_free(cntxt);

	RTE_LOG_DP(DEBUG, CP, "%s: URR_ID:%u\n",
			__func__, urr_id);

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
 * Generate the Sequence
 */
uint32_t
generate_rar_seq(void)
{
	uint32_t id = 0;

	id = rar_base_rule_id + (++rar_rule_id_offset);

	return id;
}


/**
 * Convert the decimal value into the string.
 */
//static int
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
 * Get the system current timestamp.
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
 * Generate CCR session id with the combination of timestamp and call id
 */
static int
gen_sess_id_string(char *str_buf, char *timestamp , uint32_t value)
{
	char buf[MAX_LEN] = {0};
	int len = 0;

	if (timestamp == NULL)
	{
		fprintf(stderr, "%s:%d Time stamp is NULL \n",
				__func__, __LINE__);
		return -1;
	}

	/* itoa(value, buf, 10);  10 Means base value, i.e. indicate decimal value */
	len = int_to_str(buf, value);

	if(buf[0] == 0)
	{
		fprintf(stderr, "%s:%d Failed coversion of integer to string, len:%d \n",
			__func__, __LINE__, len);
		return -1;
	}

	sprintf(str_buf, "%s%s", timestamp, buf);
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
		fprintf(stderr, "%s:%d String is NULL\n",
				__func__, __LINE__);
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
		fprintf(stderr, "%s:%d Call ID not found\n",
				__func__, __LINE__);
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
		fprintf(stderr, "%s:%d Failed to generate session id for CCR\n",
				__func__, __LINE__);
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
		pfcp_hash_params[2] = {
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

