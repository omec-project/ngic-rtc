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

#include "gtpv2c.h"
#include "sm_pcnd.h"
#include "cp_stats.h"
#include "debug_str.h"
#include "pfcp_util.h"
#include "pfcp.h"
#include "gtp_messages_decoder.h"

#ifdef C3PO_OSS
#include "cp_config.h"
#endif /* C3PO_OSS */

pfcp_config_t pfcp_config;
extern struct cp_stats_t cp_stats;

uint8_t
gx_pcnd_check(gx_msg *gx_rx, msg_info *msg)
{
	int ret = 0;
	uint32_t call_id = 0;
	gx_context_t *gx_context = NULL;
	pdn_connection *pdn_cntxt = NULL;


	msg->msg_type = gx_rx->msg_type;

	switch(msg->msg_type) {
		case GX_CCA_MSG: {
			if (gx_cca_unpack((unsigned char *)gx_rx + sizeof(gx_rx->msg_type),
						&msg->gx_msg.cca) <= 0) {
			    return -1;
			}

			/* Retrive Gx_context based on Sess ID. */
			ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
					(const void*)(msg->gx_msg.cca.session_id.val),
					(void **)&gx_context);
			if (ret < 0) {
			    RTE_LOG_DP(ERR, CP, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
						msg->gx_msg.cca.session_id.val);
			    return -1;
			}

			if(msg->gx_msg.cca.presence.result_code &&
					msg->gx_msg.cca.result_code != 2001){
				RTE_LOG_DP(ERR, CP, "%s:Received CCA without DIAMETER Success [%d]\n", __func__,
						msg->gx_msg.cca.result_code);
				return -1;
			}

			/* Extract the call id from session id */
			ret = retrieve_call_id((char *)msg->gx_msg.cca.session_id.val, &call_id);
			if (ret < 0) {
			        fprintf(stderr, "%s:No Call Id found from session id:%s\n", __func__,
			                        msg->gx_msg.cca.session_id.val);
			        return -1;
			}

			/* Retrieve PDN context based on call id */
			pdn_cntxt = get_pdn_conn_entry(call_id);
			if (pdn_cntxt == NULL)
			{
			      fprintf(stderr, "%s:No valid pdn cntxt found for CALL_ID:%u\n",
			                          __func__, call_id);
			      return -1;
			}

			/* Retrive the Session state and set the event */
			msg->state = gx_context->state;
			msg->event = CCA_RCVD_EVNT;
			msg->proc = gx_context->proc;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Session Id:%s, "
					"State:%s, Event:%s\n",
					__func__, gx_type_str(msg->msg_type), msg->msg_type,
					msg->gx_msg.cca.session_id.val,
					get_state_string(msg->state), get_event_string(msg->event));
			break;
		}
		case GX_RAR_MSG: {

			uint32_t buflen ;

			if (gx_rar_unpack((unsigned char *)gx_rx + sizeof(gx_rx->msg_type),
						&msg->gx_msg.rar) <= 0) {
			    return -1;
			}

			/* Retrive Gx_context based on Sess ID. */
			ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
					(const void*)(msg->gx_msg.rar.session_id.val),
					(void **)&gx_context);
			if (ret < 0) {
			    RTE_LOG_DP(ERR, CP, "%s: NO ENTRY FOUND IN Gx HASH [%s]\n", __func__,
						msg->gx_msg.rar.session_id.val);
			    return -1;
			}

			/* Reteive the rqst ptr for RAA */
			buflen = gx_rar_calc_length (&msg->gx_msg.rar);
			//gx_context->rqst_ptr = (uint64_t *)(((unsigned char *)gx_rx + sizeof(gx_rx->msg_type) + buflen));
			memcpy( &gx_context->rqst_ptr ,((unsigned char *)gx_rx + sizeof(gx_rx->msg_type) + buflen),
					sizeof(unsigned long));


			/* Retrive the Session state and set the event */
			msg->state = CONNECTED_STATE;
			msg->event = RE_AUTH_REQ_RCVD_EVNT;
			msg->proc = DED_BER_ACTIVATION_PROC;

			clLog(sxlogger, eCLSeverityDebug, "%s: Callback called for"
					"Msg_Type:%s[%u], Session Id:%s, "
					"State:%s, Event:%s\n",
					__func__, gx_type_str(msg->msg_type), msg->msg_type,
					msg->gx_msg.cca.session_id.val,
					get_state_string(msg->state), get_event_string(msg->event));
			break;
		}
	default:
				fprintf(stderr, "%s::process_msgs-"
					"\n\tcase: SAEGWC::spgw_cfg= %d;"
					"\n\tReceived Gx Message : "
					"%d not supported... Discarding\n", __func__,
					spgw_cfg, gx_rx->msg_type);
			return -1;
	}

	return 0;
}
