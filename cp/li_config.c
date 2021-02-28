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
del_li_entry(uint64_t *uiId, uint16_t uiCntr)
{
	int ret = 0;
	uint64_t imsi = 0;
	imsi_id_hash_t *imsi_id_config = NULL;
	struct li_df_config_t *li_df_config = NULL;

	for (uint16_t uiCnt = 0; uiCnt < uiCntr; uiCnt++) {

		li_df_config = NULL;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Delete ue entry from hash"
				" :%lu\n", LOG_VALUE, uiId[uiCnt]);

		ret = rte_hash_lookup_data(li_info_by_id_hash, &uiId[uiCnt], (void **)&li_df_config);
		if ((ret >= 0) && (NULL != li_df_config)) {

			imsi = li_df_config->uiImsi;

			ret = rte_hash_del_key(li_info_by_id_hash, &uiId[uiCnt]);
			if ( ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for LI Id %lu\n",
						LOG_VALUE, uiId[uiCnt]);
				return -1;
			}

			/* Free data from hash */
			rte_free(li_df_config);
			li_df_config = NULL;

			imsi_id_config = NULL;

			/* get user level packet copying token or id using imsi */
			ret = get_id_using_imsi(imsi, &imsi_id_config);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Not applicable for li\n",
						LOG_VALUE);

				return -1;
			}

			if ((NULL != imsi_id_config) && (imsi_id_config->cntr > 0)) {

				int i = 0;
				for (int8_t cnt = 0; cnt < imsi_id_config->cntr; cnt++) {

					if (imsi_id_config->ids[cnt] == uiId[uiCnt]) {

						continue;
					}

					imsi_id_config->ids[i] = imsi_id_config->ids[cnt];
					i++;
				}

				imsi_id_config->cntr--;
			}

			if ((NULL != imsi_id_config) && (imsi_id_config->cntr == NOT_PRESENT)) {

				ret = rte_hash_del_key(li_id_by_imsi_hash, &imsi);
				if ( ret < 0) {

					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for LI Id %lu\n",
							LOG_VALUE, imsi);
					return -1;
				}

				/* Free data from hash */
				rte_free(imsi_id_config);
				imsi_id_config = NULL;
			}

			/* Send pfcp session modification request to user plane */
			send_pfcp_sess_mod_req_for_li(imsi);
		}
	}

	return 0;
}

int8_t
fillup_li_df_hash(struct li_df_config_t *li_df_config_data, uint16_t uiCntr) {

	int ret = 0;

	for (uint16_t uiCnt = 0; uiCnt < uiCntr; uiCnt++) {

		struct li_df_config_t *li_df_config = NULL;

		ret = rte_hash_lookup_data(li_info_by_id_hash, &li_df_config_data[uiCnt].uiId,
				(void **)&li_df_config);
		if (ret < 0) {

			li_df_config = rte_zmalloc_socket(NULL, sizeof(struct li_df_config_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (NULL == li_df_config) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to "
					"allocate PDN structure: %s \n", LOG_VALUE,
					rte_strerror(rte_errno));

				return -1;
			}

			li_df_config->uiId = li_df_config_data[uiCnt].uiId;
			li_df_config->uiImsi = li_df_config_data[uiCnt].uiImsi;
			li_df_config->uiS11 = li_df_config_data[uiCnt].uiS11;
			li_df_config->uiSgwS5s8C = li_df_config_data[uiCnt].uiSgwS5s8C;
			li_df_config->uiPgwS5s8C = li_df_config_data[uiCnt].uiPgwS5s8C;
			li_df_config->uiSxa = li_df_config_data[uiCnt].uiSxa;
			li_df_config->uiSxb = li_df_config_data[uiCnt].uiSxb;
			li_df_config->uiSxaSxb = li_df_config_data[uiCnt].uiSxaSxb;
			li_df_config->uiS1uContent = li_df_config_data[uiCnt].uiS1uContent;
			li_df_config->uiSgwS5s8UContent =
				li_df_config_data[uiCnt].uiSgwS5s8UContent;
			li_df_config->uiPgwS5s8UContent =
				li_df_config_data[uiCnt].uiPgwS5s8UContent;
			li_df_config->uiSgiContent = li_df_config_data[uiCnt].uiSgiContent;
			li_df_config->uiS1u = li_df_config_data[uiCnt].uiS1u;
			li_df_config->uiSgwS5s8U = li_df_config_data[uiCnt].uiSgwS5s8U;
			li_df_config->uiPgwS5s8U = li_df_config_data[uiCnt].uiPgwS5s8U;
			li_df_config->uiSgi = li_df_config_data[uiCnt].uiSgi;
			li_df_config->uiForward = li_df_config_data[uiCnt].uiForward;

			ret = rte_hash_add_key_data(li_info_by_id_hash, (const void *) &li_df_config->uiId,
				    (void *) li_df_config);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"- Error on li_info_by_id_hash"
					" add\n", LOG_VALUE, strerror(ret));

				rte_hash_del_key(li_info_by_id_hash, (const void *) &li_df_config->uiId);
				if (ret < 0) {

					rte_panic("%s - Error on li_info_by_id_hash del\n", strerror(ret));
				}

				rte_free(li_df_config);
				return -1;
			}

			ret = add_id_in_imsi_hash(li_df_config->uiId, li_df_config->uiImsi);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"add id in imsi hash failed"
						" with return value (%d).", LOG_VALUE, ret);
				return -1;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"send pfcp modification request if ue is already attach."
				" Action (%u)\n", LOG_VALUE, ADD_LI_ENTRY);
		} else {

			if (li_df_config_data[uiCnt].uiS11 != 0) {
				li_df_config->uiS11 = li_df_config_data[uiCnt].uiS11;
			}

			if (li_df_config_data[uiCnt].uiSgwS5s8C != 0) {
				li_df_config->uiSgwS5s8C = li_df_config_data[uiCnt].uiSgwS5s8C;
			}

			if (li_df_config_data[uiCnt].uiPgwS5s8C != 0) {
				li_df_config->uiPgwS5s8C = li_df_config_data[uiCnt].uiPgwS5s8C;
			}

			if (li_df_config_data[uiCnt].uiSxa != 0) {
				li_df_config->uiSxa = li_df_config_data[uiCnt].uiSxa;
			} else {
				li_df_config->uiSxa = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiSxb != 0) {
				li_df_config->uiSxb = li_df_config_data[uiCnt].uiSxb;
			} else {
				li_df_config->uiSxb = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiSxaSxb != 0) {
				li_df_config->uiSxaSxb = li_df_config_data[uiCnt].uiSxaSxb;
			} else {
				li_df_config->uiSxaSxb = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiS1uContent != 0) {
				li_df_config->uiS1uContent =
					li_df_config_data[uiCnt].uiS1uContent;
			}

			if (li_df_config_data[uiCnt].uiSgwS5s8UContent != 0) {
				li_df_config->uiSgwS5s8UContent =
					li_df_config_data[uiCnt].uiSgwS5s8UContent;
			}

			if (li_df_config_data[uiCnt].uiPgwS5s8UContent != 0) {
				li_df_config->uiPgwS5s8UContent =
					li_df_config_data[uiCnt].uiPgwS5s8UContent;
			}

			if (li_df_config_data[uiCnt].uiSgiContent != 0) {
				li_df_config->uiSgiContent =
					li_df_config_data[uiCnt].uiSgiContent;
			}

			if (li_df_config_data[uiCnt].uiS1u != 0) {
				li_df_config->uiS1u = li_df_config_data[uiCnt].uiS1u;
			} else {
				li_df_config->uiS1u = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiSgwS5s8U != 0) {
				li_df_config->uiSgwS5s8U = li_df_config_data[uiCnt].uiSgwS5s8U;
			} else {
				li_df_config->uiSgwS5s8U = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiPgwS5s8U != 0) {
				li_df_config->uiPgwS5s8U = li_df_config_data[uiCnt].uiPgwS5s8U;
			} else {
				li_df_config->uiPgwS5s8U = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiSgi != 0) {
				li_df_config->uiSgi = li_df_config_data[uiCnt].uiSgi;
			} else {
				li_df_config->uiSgi = NOT_PRESENT;
			}

			if (li_df_config_data[uiCnt].uiForward != 0) {
				li_df_config->uiForward = li_df_config_data[uiCnt].uiForward;
			}

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"send pfcp modification request if ue is already attach."
				" Action (%u)\n", LOG_VALUE, UPDATE_LI_ENTRY);
		}

		send_pfcp_sess_mod_req_for_li(li_df_config->uiImsi);
	}

	return 0;
}

int
get_li_config(uint64_t uiId, struct li_df_config_t **li_config)
{
	int ret = 0;

	ret = rte_hash_lookup_data(li_info_by_id_hash, &uiId, (void **)li_config);
	if (ret < 0) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Entry not found for "
			"Id : %lu.\n", LOG_VALUE, uiId);

		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": LI Id : %lu\n", LOG_VALUE, uiId);

	return 0;
}

int8_t
add_id_in_imsi_hash(uint64_t uiId, uint64_t uiImsi) {

	int ret = 0;
	imsi_id_hash_t *imsi_id_hash = NULL;

	ret = rte_hash_lookup_data(li_id_by_imsi_hash, &uiImsi, (void **)&imsi_id_hash);
	if (ret < 0) {

		imsi_id_hash = rte_zmalloc_socket(NULL,	sizeof(imsi_id_hash_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (NULL == imsi_id_hash) {

			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
				"Failure to allocate id_by_imsi structure: %s \n",
				LOG_VALUE, rte_strerror(rte_errno));

			return -1;
		}

		/* initialize structure contents */
		imsi_id_hash->cntr = 0;
		for (uint8_t i = 0; i < MAX_LI_ENTRIES_PER_UE; i++) {
			imsi_id_hash->ids[i] = 0;
		}

		imsi_id_hash->ids[imsi_id_hash->cntr++] = uiId;

		ret = rte_hash_add_key_data(li_id_by_imsi_hash, (const void *) &uiImsi,
				(void *) imsi_id_hash);
		if (ret < 0) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" - Error on"
					" li_id_by_imsi_hash add\n",LOG_VALUE, strerror(ret));

			rte_hash_del_key(li_id_by_imsi_hash, (const void *) &uiImsi);
			if (ret < 0) {
				rte_panic("%s - Error on li_id_by_imsi_hash del\n", strerror(ret));
			}

			rte_free(imsi_id_hash);
			return -1;
		}
	} else {

		imsi_id_hash->ids[imsi_id_hash->cntr++] = uiId;
	}

	return 0;
}

int
get_id_using_imsi(uint64_t uiImsi, imsi_id_hash_t **imsi_id_hash)
{
	int ret = 0;

	ret = rte_hash_lookup_data(li_id_by_imsi_hash, &uiImsi, (void **)imsi_id_hash);
	if (ret < 0) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":Entry not found for imsi :"
				"%lu\n", LOG_VALUE, uiImsi);

		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": imsi :%lu\n", LOG_VALUE, uiImsi);

	return 0;
}

int
fill_li_config_in_context(ue_context *context, imsi_id_hash_t *imsi_id_hash) {

	int ret = 0;

	context->li_data_cntr = 0;
	memset(context->li_data, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_data_t));

	for (uint8_t i = 0; i < imsi_id_hash->cntr; i++) {

		struct li_df_config_t *li_config = NULL;

		ret = get_li_config(imsi_id_hash->ids[i], &li_config);
		if (ret < 0) {

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Entry not found "
					"for li identifier %lu", LOG_VALUE, imsi_id_hash->ids[i]);

			continue;
		}

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"fillup LI configurations in"
				" context. IMSI (%lu)", LOG_VALUE, context->imsi);

		context->li_data[context->li_data_cntr].id = imsi_id_hash->ids[i];

		if (COPY_SIG_MSG_ON == li_config->uiS11) {
			context->li_data[context->li_data_cntr].s11 = PRESENT;
		}

		if (COPY_SIG_MSG_ON == li_config->uiSgwS5s8C) {
			context->li_data[context->li_data_cntr].sgw_s5s8c = PRESENT;
		}

		if (COPY_SIG_MSG_ON == li_config->uiPgwS5s8C) {
			context->li_data[context->li_data_cntr].pgw_s5s8c = PRESENT;
		}

		if ((SX_COPY_CP_MSG == li_config->uiSxa) ||
				(SX_COPY_CP_DP_MSG == li_config->uiSxa)) {
			context->li_data[context->li_data_cntr].sxa = PRESENT;
		}

		if ((SX_COPY_CP_MSG == li_config->uiSxb) ||
				(SX_COPY_CP_DP_MSG == li_config->uiSxb)) {
			context->li_data[context->li_data_cntr].sxb = PRESENT;
		}

		if ((SX_COPY_CP_MSG == li_config->uiSxaSxb) ||
				(SX_COPY_CP_DP_MSG == li_config->uiSxaSxb)) {
			context->li_data[context->li_data_cntr].sxa_sxb = PRESENT;
		}

		context->li_data[context->li_data_cntr].forward = li_config->uiForward;

		context->dupl = PRESENT;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"LI configurations : IMSI (%lu) s11(%u) sgw-s5s8c(%u)"
			"pgw_s5s8c (%u) sxa(%u) sxb(%u) sxa_sxb(%u) forward(%u) dupl(%u)",
			LOG_VALUE, context->imsi, context->li_data[context->li_data_cntr].s11,
			context->li_data[context->li_data_cntr].sgw_s5s8c,
			context->li_data[context->li_data_cntr].pgw_s5s8c,
			context->li_data[context->li_data_cntr].sxa,
			context->li_data[context->li_data_cntr].sxb,
			context->li_data[context->li_data_cntr].sxa_sxb,
			context->li_data[context->li_data_cntr].forward, context->dupl);

		context->li_data_cntr++;
	}

	return 0;
}
