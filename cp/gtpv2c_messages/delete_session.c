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

#include <rte_debug.h>

#include "gtp_messages.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include "gtpv2c_set_ie.h"
#include "sm_struct.h"
#include "cp_config.h"
#include "cp_stats.h"
#include "gtpc_session.h"

extern pfcp_config_t config;
extern int clSystemLog;


int
delete_context(gtp_eps_bearer_id_ie_t lbi, uint32_t teid,
				ue_context **_context, pdn_connection **_pdn)
{
	int ret = 0;
	ue_context *context = NULL;

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &context);

	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to get UE context for teid: %d\n", LOG_VALUE, ue_context_by_fteid_hash);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}


	if (!lbi.header.len) {
		/* TODO: should be responding with response indicating error
		 * in request */
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Received Delete Session Request without ebi!\n",LOG_VALUE);
		return GTPV2C_CAUSE_INVALID_MESSAGE_FORMAT;
	}

	int ebi_index = GET_EBI_INDEX(lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
		    "Received Delete Session Request on non-existent EBI - "
		    "Dropping packet\n", LOG_VALUE);
		return GTPV2C_CAUSE_INVALID_MESSAGE_FORMAT;
	}

	pdn_connection *pdn = GET_PDN(context, ebi_index);
	if (!pdn) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (pdn->default_bearer_id != lbi.ebi_ebi) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
		    "Received Delete Session  Request referencing incorrect "
		    "default bearer ebi", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
			"Received Delete Session Request on non-existent default EBI\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	*_context = context;
	*_pdn = pdn;
	return 0;
}
