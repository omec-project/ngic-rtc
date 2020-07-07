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

#include <rte_hash_crc.h>

#include "clogger.h"
#include "predef_rule_init.h"

/* Create the Tables to mantain sdf, mtr, adc and pcc rules */
#define PREDEF_NUM_OF_TABLES 5

/* Defined the table index */
#define ZERO  0
#define ONE   1
#define TWO   2
#define THREE 3
#define FOUR  4

/* Maximum collection of rules stored into the hash table */
#define MAX_RULES_ENTRIES_COLLECTION 10

/* Maximum predefined rules stored into the hash table */
#define MAX_RULES_HASH_SIZE 255

extern struct rte_hash *sdf_by_inx_hash;
extern struct rte_hash *mtr_by_inx_hash;
extern struct rte_hash *adc_by_inx_hash;
extern struct rte_hash *pcc_by_rule_name_hash;
extern struct rte_hash *rules_by_ip_addr_hash;

/* Return the selected hash table pointer */
static struct rte_hash *
select_predef_rule_hash_table(uint8_t hash_type)
{
	if (hash_type == SDF_HASH) {
		return sdf_by_inx_hash;
	} else if (hash_type == MTR_HASH) {
		return mtr_by_inx_hash;
	} else if (hash_type == ADC_HASH) {
		return adc_by_inx_hash;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Wrong/not defined hash type, hash_type:%u\n",
				LOG_VALUE, hash_type);
		return NULL;
	}
}

int8_t
insert_rule_name_node(rules_struct *head, rules_struct *new_node)
{
	rules_struct *tmp =  NULL;
	if(new_node == NULL)
	    return -1;

	new_node->next = NULL;
	/* Check linked list is empty or not */
	if (head == NULL) {
	    head = new_node;
		head->rule_cnt++;
	} else {
	    tmp = head;

	    /* Traverse the linked list until tmp is the last node */
	    while(tmp->next != NULL) {
	        tmp = tmp->next;
	    }
	    tmp->next = new_node;
		tmp->rule_cnt = head->rule_cnt;
		head->rule_cnt++;
	}
	return 0;
}

rules_struct *
get_map_rule_entry(uint32_t cp_pfcp_ip, uint8_t is_mod)
{
	int ret = 0;
	uint16_t size = 0;
	rules_struct *data = NULL;
	struct rte_hash *hash = rules_by_ip_addr_hash;
	/* Validate if hash is created or not */
	if (hash == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Collection rules hash not found!\n",
				LOG_VALUE);
		return NULL;
	}

	ret = rte_hash_lookup_data(hash, &cp_pfcp_ip, (void **)&data);
	if ( ret < 0) {
		/* allocate memory only if request for add new rule entry */
		if (is_mod != ADD_RULE) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Entry not found for IP_Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
			return NULL;
		}

		/* Calculate the memory size to allocate */
		size = sizeof(rules_struct);

		/* allocate memory for rule entry*/
		data = rte_zmalloc("Rules_Infos", size, RTE_CACHE_LINE_SIZE);
		if (data == NULL) {
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for rule entry.\n",
					LOG_VALUE);
		    return NULL;
		}

		/* Rule Entry not present. Add new rule entry */
		ret = rte_hash_add_key_data(hash, &cp_pfcp_ip, data);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for IP_Address: "IPV4_ADDR""
					"\n\tError= %s\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip),
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(data);
			data = NULL;
			return NULL;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Successfully added rule entry for IP_Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
		return data;
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Rule entry found for IP_Address: "IPV4_ADDR"\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
	return data;
}

int8_t
del_map_rule_entry(uint32_t cp_pfcp_ip)
{
	int ret = 0;
	rules_struct *data = NULL;
	struct rte_hash *hash = rules_by_ip_addr_hash;

	ret = rte_hash_lookup_data(hash, &cp_pfcp_ip, (void **)&data);
	if (ret >= 0) {
		/* Rule Entry is present. Delete rule Entry */
		ret = rte_hash_del_key(hash, &cp_pfcp_ip);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found"
				"for IP_Address: "IPV4_ADDR"\n", LOG_VALUE,
				IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
			return -1;
		}
		if (data != NULL) {
			rte_free(data);
			data = NULL;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Rule entry deleted for IP_Address: "IPV4_ADDR"\n", LOG_VALUE,
				IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
		return 0;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Rule entry not found for IP_Address: "IPV4_ADDR"\n", LOG_VALUE,
			IPV4_ADDR_HOST_FORMAT(cp_pfcp_ip));
	return -1;
}

struct pcc_rules *
get_predef_pcc_rule_entry(const pcc_rule_name *rule_name, uint8_t is_mod)
{
	int ret = 0;
	uint16_t size = 0;
	struct pcc_rules *data = NULL;
	struct rte_hash *hash = pcc_by_rule_name_hash;
	/* Validate if hash is created or not */
	if (hash == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Predef pcc hash not found!\n",
				LOG_VALUE);
		return NULL;
	}

	ret = rte_hash_lookup_data(hash, &rule_name->rname, (void **)&data);
	if ( ret < 0) {
		/* allocate memory only if request for add new rule entry */
		if (is_mod != ADD_RULE) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Entry not found for Rule_Name: %s\n",
					LOG_VALUE, rule_name->rname);
			return NULL;
		}

		/* Calculate the memory size to allocate */
		size = sizeof(struct pcc_rules);

		/* allocate memory for rule entry*/
		data = rte_zmalloc("PCC_Rules_Info", size, RTE_CACHE_LINE_SIZE);
		if (data == NULL) {
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for rule entry.\n",
					LOG_VALUE);
		    return NULL;
		}

		/* Rule Entry not present. Add new rule entry */
		ret = rte_hash_add_key_data(hash, &rule_name->rname, data);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for Rule_Name: %s"
					"\n\tError= %s\n", LOG_VALUE, rule_name->rname,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(data);
			data = NULL;
			return NULL;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Successfully added pcc rule entry for Rule_Name: %s\n",
				LOG_VALUE, rule_name->rname);
		return data;
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"PCC Rule entry found for Rule_Name: %s\n",
			LOG_VALUE, rule_name->rname);
	return data;
}

int8_t
del_predef_pcc_rule_entry(const pcc_rule_name *rule_name)
{
	int ret = 0;
	struct pcc_rules *data = NULL;
	struct rte_hash *hash = pcc_by_rule_name_hash;

	ret = rte_hash_lookup_data(hash, &rule_name->rname, (void **)&data);
	if (ret >= 0) {
		/* PCC Rule Entry is present. Delete PCC rule Entry */
		ret = rte_hash_del_key(hash, &rule_name->rname);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for PCC_Rule_Name: %s\n", LOG_VALUE, rule_name->rname);
			return -1;
		}
		if (data != NULL) {
			rte_free(data);
			data = NULL;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"PCC Rule entry deleted for Rule_Name: %s\n", LOG_VALUE,
				rule_name->rname);
		return 0;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"PCC Rule entry not found for Rule_Name: %s\n", LOG_VALUE,
			rule_name->rname);
	return -1;
}

int8_t
get_predef_rule_entry(uint16_t rule_indx, uint8_t hash_type,
		uint8_t is_mod, void **rule_info)
{
	int ret = 0;
	uint16_t size = 0;
	void *data = NULL;
	const char *hash_name = NULL;
	struct rte_hash *hash = NULL;
	hash = select_predef_rule_hash_table(hash_type);
	/* Caluate the size for memory allocation */
	if (hash_type == SDF_HASH) {
#ifdef CP_BUILD
		size = sizeof(pkt_fltr);
#else
		size = sizeof(struct pkt_filter);
#endif
		hash_name = "SDF";
	} else if (hash_type == MTR_HASH) {
		size = sizeof(struct mtr_entry);
		hash_name = "MTR";
	} else if (hash_type == ADC_HASH) {
		size = sizeof(struct adc_rules);
		hash_name = "ADC";
	}

	/* Validate if hash is created or not */
	if (hash == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Predef %s hash not found!\n",
				LOG_VALUE, hash_name);
		return -1;
	}


	ret = rte_hash_lookup_data(hash, &rule_indx, (void **)&data);
	if ( ret < 0) {
		/* allocate memory only if request for add new rule entry */
		if (is_mod != ADD_RULE) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Entry not found for %s Rule_Index: %u...\n",
					LOG_VALUE, hash_name, rule_indx);
			return -1;
		}

		/* allocate memory for rule entry*/
		data = rte_zmalloc("Rules_Info", size, RTE_CACHE_LINE_SIZE);
		if (data == NULL){
		    clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate memory for %s rule entry.\n",
					LOG_VALUE, hash_name);
		    return -1;
		}

		/* Copy rule info into allocated memory */
#ifdef CP_BUILD
		memcpy(data, &(*rule_info), size);
#else
		memcpy(data, *rule_info, size);
#endif /* CP_BUILD */

		/* Rule Entry not present. Add new rule entry */
		ret = rte_hash_add_key_data(hash, &rule_indx, data);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add entry for %s Rule_Index: %u"
					"\n\tError= %s\n", LOG_VALUE, hash_name, rule_indx,
					rte_strerror(abs(ret)));

			/* free allocated memory */
			rte_free(data);
			data = NULL;
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Successfully added rule entry for %s Rule_Index:%u\n",
				LOG_VALUE, hash_name, rule_indx);
		return 0;
	}

	*rule_info = data;
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"%s Rule entry found for Rule_Index:%u\n",
			LOG_VALUE, hash_name, rule_indx);
	return 0;
}

int8_t
del_predef_rule_entry(uint16_t rule_indx, uint8_t hash_type)
{
	int ret = 0;
	void *data = NULL;
	const char *hash_name = NULL;
	struct rte_hash *hash = NULL;
	/* Set the hash name */
	if (hash_type == SDF_HASH) {
		hash_name = "SDF";
	} else if (hash_type == MTR_HASH) {
		hash_name = "MTR";
	} else if (hash_type == ADC_HASH) {
		hash_name = "ADC";
	}

	hash = select_predef_rule_hash_table(hash_type);
	/* Validate if hash is created or not */
	if (hash == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Predef %s hash not found!\n",
				LOG_VALUE, hash_name);
		return -1;
	}

	ret = rte_hash_lookup_data(hash, &rule_indx, (void **)&data);
	if (ret >= 0) {
		/* Rule Entry is present. Delete Rule Entry */
		ret = rte_hash_del_key(hash, &rule_indx);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found "
				"for %s Rule_Index: %u\n", LOG_VALUE, hash_name, rule_indx);
			return -1;
		}
		if (data != NULL) {
			rte_free(data);
			data = NULL;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Rule entry delted for %s Rule_Index: %u\n", LOG_VALUE,
				hash_name, rule_indx);
		return 0;
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Rule entry not found for %s Rule_Index: %u\n", LOG_VALUE,
			hash_name, rule_indx);
	return -1;
}

/* Create and initialize the tables to maintain the predefined rules info*/
void
init_predef_rule_hash_tables(void)
{
	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Table Creation Started\n", LOG_VALUE);

	struct rte_hash_parameters
		predef_hash_params[PREDEF_NUM_OF_TABLES] = {
		{	.name = "SDF_ENTRY_HASH",
			.entries = MAX_RULES_HASH_SIZE,
			.key_len = sizeof(uint16_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "MTR_ENTRY_HASH",
			.entries = MAX_RULES_HASH_SIZE,
			.key_len = sizeof(uint16_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "ADC_ENTRY_HASH",
			.entries = MAX_RULES_HASH_SIZE,
			.key_len = sizeof(uint16_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "PCC_ENTRY_HASH",
			.entries = MAX_RULES_HASH_SIZE,
			.key_len = sizeof(pcc_rule_name),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		},
		{	.name = "RULES_ENTRY_HASH",
			.entries = MAX_RULES_ENTRIES_COLLECTION,
			.key_len = sizeof(uint32_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id()
		}
	};

	sdf_by_inx_hash = rte_hash_create(&predef_hash_params[ZERO]);
	if (!sdf_by_inx_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				predef_hash_params[ZERO].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	mtr_by_inx_hash = rte_hash_create(&predef_hash_params[ONE]);
	if (!mtr_by_inx_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				predef_hash_params[ONE].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	adc_by_inx_hash = rte_hash_create(&predef_hash_params[TWO]);
	if (!adc_by_inx_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				predef_hash_params[TWO].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	pcc_by_rule_name_hash = rte_hash_create(&predef_hash_params[THREE]);
	if (!pcc_by_rule_name_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				predef_hash_params[THREE].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	rules_by_ip_addr_hash = rte_hash_create(&predef_hash_params[FOUR]);
	if (!rules_by_ip_addr_hash) {
		rte_panic("%s: hash create failed: %s (%u)\n",
				predef_hash_params[FOUR].name,
		    rte_strerror(rte_errno), rte_errno);
	}

	clLog(clSystemLog, eCLSeverityInfo,
			LOG_FORMAT"SDF, PCC, MTR, and ADC hash tables successfully created.\n", LOG_VALUE);
}
#ifdef CP_BUILD
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
build_rules_up_msg(enum dp_msg_type mtype,
		void *param, struct msgbuf *msg_payload)
{
	msg_payload->mtype = mtype;
	/* Not Supporting dp_id */
	struct dp_id dp_id = { .id = DPN_ID };
	msg_payload->dp_id = dp_id;

	switch (mtype) {
		case MSG_SDF_CRE:
		case MSG_ADC_TBL_CRE:
		case MSG_PCC_TBL_CRE:
		case MSG_SESS_TBL_CRE:
		case MSG_MTR_CRE:
			msg_payload->msg_union.msg_table.max_elements =
							*(uint32_t *)param;
			break;
		case MSG_EXP_CDR:
			msg_payload->msg_union.ue_cdr =
					*(struct msg_ue_cdr *)param;
			break;
		case MSG_SDF_DES:
		case MSG_ADC_TBL_DES:
		case MSG_PCC_TBL_DES:
		case MSG_SESS_TBL_DES:
		case MSG_MTR_DES:
			break;
		case MSG_SDF_ADD:
		case MSG_SDF_DEL:
			msg_payload->msg_union.pkt_filter_entry =
						*(struct pkt_filter *)param;
			break;
		case MSG_ADC_TBL_ADD:
		case MSG_ADC_TBL_DEL:
			msg_payload->msg_union.adc_filter_entry =
						*(struct adc_rules *)param;
			break;
		case MSG_PCC_TBL_ADD:
		case MSG_PCC_TBL_DEL:
			msg_payload->msg_union.pcc_entry =
						*(struct pcc_rules *)param;
			break;
		case MSG_SESS_CRE:
		case MSG_SESS_MOD:
		case MSG_SESS_DEL:
			msg_payload->msg_union.sess_entry =
					*(struct session_info *)param;
			break;
		case MSG_MTR_ADD:
		case MSG_MTR_DEL:
			msg_payload->msg_union.mtr_entry =
					*(struct mtr_entry *)param;
			break;
		case MSG_DDN_ACK:
			msg_payload->msg_union.dl_ddn =
					*(struct downlink_data_notification *)param;
			break;
		default:
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Invalid msg type\n", LOG_VALUE);
			return -1;
	}
	return 0;
}
#endif
