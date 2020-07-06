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

#include "li_config.h"
#include "clogger.h"
#include "pfcp_session.h"

uint8_t
del_li_imsi_entry(uint64_t uiImsi)
{
	int ret = 0;
	struct li_df_config_t *li_df_config = NULL;

	ret = rte_hash_lookup_data(li_df_by_imsi_hash,
					&uiImsi, (void **)&li_df_config);
	if (ret >= 0) {

		/* Set li action to delete */
		li_df_config->uiAction = CC_EVENT_DELETE;

		/* Send pfcp session modification request to user plane */
		send_pfcp_sess_mod_req_for_li(li_df_config);

		ret = rte_hash_del_key(li_df_by_imsi_hash, &uiImsi);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%d Entry not found for IMSI:%lu...\n",
						__func__, __LINE__, uiImsi);
			return -1;
		}

		/* Free data from hash */
		if(li_df_config != NULL){
			rte_free(li_df_config);
			li_df_config = NULL;
		}

		return 0;
	}

	return -1;
}

int8_t
fillup_li_df_hash(struct li_df_config_t *li_df_config_data, uint16_t uiCntr) {
	int8_t ret;

	for (uint16_t uiCnt = 0; uiCnt < uiCntr; uiCnt++) {
		struct li_df_config_t *li_df_config = NULL;

		ret = rte_hash_lookup_data(li_df_by_imsi_hash,
				&li_df_config_data[uiCnt].uiImsi, (void **)&li_df_config);
		if (ret < 0) {
			li_df_config = rte_zmalloc_socket(NULL,
					sizeof(struct li_df_config_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (NULL == li_df_config) {
				clLog(clSystemLog, eCLSeverityCritical,
						"Failure to allocate PDN structure: %s (%s:%d)\n",
						rte_strerror(rte_errno), __FILE__,__LINE__);

				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}

			li_df_config->uiImsi = li_df_config_data[uiCnt].uiImsi;
			li_df_config->uiOperation = li_df_config_data[uiCnt].uiOperation;
			li_df_config->uiAction = li_df_config_data[uiCnt].uiAction;
			li_df_config->ddf2_ip.s_addr = li_df_config_data[uiCnt].ddf2_ip.s_addr;
			li_df_config->uiDDf2Port = li_df_config_data[uiCnt].uiDDf2Port;
			li_df_config->ddf3_ip.s_addr = li_df_config_data[uiCnt].ddf3_ip.s_addr;
			li_df_config->uiDDf3Port = li_df_config_data[uiCnt].uiDDf3Port;
			li_df_config->uiTimerValue = li_df_config_data[uiCnt].uiTimerValue;

			ret = rte_hash_add_key_data(li_df_by_imsi_hash,
			    (const void *) &li_df_config->uiImsi,
			    (void *) li_df_config);

			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
					"%s - Error on li_df_by_imsi_hash add\n",
					strerror(ret));
				rte_hash_del_key(li_df_by_imsi_hash,
				    (const void *) &li_df_config->uiImsi);
				if (ret < 0) {
					rte_panic("%s - Error on "
						"li_df_by_imsi_hash del\n", strerror(ret));
				}
				if(li_df_config != NULL){
					rte_free(li_df_config);
					li_df_config = NULL;
				}
				return GTPV2C_CAUSE_SYSTEM_FAILURE;
			}
		} else {
			if (li_df_config_data[uiCnt].uiOperation != MAX_UINT16_T) {
				li_df_config->uiOperation =
					li_df_config_data[uiCnt].uiOperation;
			}

			if (li_df_config_data[uiCnt].uiAction != MAX_UINT16_T) {
				li_df_config->uiAction = li_df_config_data[uiCnt].uiAction;
			}

			if (li_df_config_data[uiCnt].ddf2_ip.s_addr != 0) {
				li_df_config->ddf2_ip.s_addr = li_df_config_data[uiCnt].ddf2_ip.s_addr;
			}

			if (li_df_config_data[uiCnt].uiDDf2Port != 0) {
				li_df_config->uiDDf2Port = li_df_config_data[uiCnt].uiDDf2Port;
			}

			if (li_df_config_data[uiCnt].ddf3_ip.s_addr != 0) {
				li_df_config->ddf3_ip.s_addr = li_df_config_data[uiCnt].ddf3_ip.s_addr;
			}

			if (li_df_config_data[uiCnt].uiDDf3Port != 0) {
				li_df_config->uiDDf3Port = li_df_config_data[uiCnt].uiDDf3Port;
			}

			if (li_df_config_data[uiCnt].uiTimerValue != 0) {
				li_df_config->uiTimerValue =
					li_df_config_data[uiCnt].uiTimerValue;
			}

		}

		send_pfcp_sess_mod_req_for_li(li_df_config);
	}

	return 0;
}

int
get_li_config(uint64_t uiImsi, struct li_df_config_t **li_config)
{
	int ret = 0;
	ret = rte_hash_lookup_data(li_df_by_imsi_hash,
				&uiImsi, (void **)li_config);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				"%s:Entry not found for Imsi:%lu...\n", __func__, uiImsi);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, "%s: Imsi:%lu\n",
			__func__, uiImsi);
	return 0;

}


