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

#include "ue.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "sm_struct.h"
#include "pfcp_util.h"
#include "debug_str.h"
#include "dp_ipc_api.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"
#include"cp_config.h"

extern int pfcp_fd;
extern struct cp_stats_t cp_stats;

/* TODO remove if not necessary later */
/*struct downlink_data_notification_t {
	ue_context *context;

	gtpv2c_ie *bearer_context_to_be_created_ebi;
	gtpv2c_ie *arp;
};
*/

/**
 * @brief  : Maintains downlink data notification acknowledgement information
 */
struct downlink_data_notification_ack_t {
	ue_context *context;

	gtpv2c_ie *cause_ie;
	uint8_t *delay;
	/* TODO! More to implement... See table 7.2.11.2-1
	 * 'Recovery: This IE shall be included if contacting the peer
	 * for the first time'
	 */
};

/**
 * @brief  : callback to handle downlink data notification messages from the
 *           data plane
 * @param  : msg_payload
 *           message payload received by control plane from the data plane
 * @return : 0 inicates success, error otherwise
 */
int
cb_ddn(struct msgbuf *msg_payload)
{
	int ret = ddn_by_session_id(msg_payload->msg_union.sess_entry.sess_id);

	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error on DDN Handling %s: (%d) %s\n", LOG_VALUE,
				gtp_type_str(ret), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
	}
	return ret;
}

/**
 * @brief  : creates and sends downlink data notification according to session
 *           identifier
 * @param  : session_id - session identifier pertaining to downlink data packets
 *           arrived at data plane
 * @return : 0 - indicates success, failure otherwise
 */
int
ddn_by_session_id(uint64_t session_id)
{
	uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *) tx_buf;
	uint32_t sgw_s11_gtpc_teid = UE_SESS_ID(session_id);
	ue_context *context = NULL;
	static uint32_t ddn_sequence = 1;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"sgw_s11_gtpc_teid:%u\n",
			LOG_VALUE, sgw_s11_gtpc_teid);

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &sgw_s11_gtpc_teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ret = create_downlink_data_notification(context,
			UE_BEAR_ID(session_id),
			ddn_sequence,
			gtpv2c_tx);

	if (ret)
		return ret;

	struct sockaddr_in mme_s11_sockaddr_in = {
		.sin_family = AF_INET,
		.sin_port = htons(GTPC_UDP_PORT),
		.sin_addr.s_addr = htonl(context->s11_mme_gtpc_ipv4.s_addr),
		.sin_zero = {0},
	};


	uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

	if (pcap_dumper) {
		dump_pcap(payload_length, tx_buf);
	} else {
		uint32_t bytes_tx = sendto(s11_fd, tx_buf, payload_length, 0,
		    (struct sockaddr *) &mme_s11_sockaddr_in,
		    sizeof(mme_s11_sockaddr_in));

		if (bytes_tx != (int) payload_length) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Transmitted Incomplete GTPv2c Message:"
					"%u of %u tx bytes\n", LOG_VALUE,
					payload_length, bytes_tx);
		}
	}
	ddn_sequence += 2;
	++cp_stats.ddn;


	update_cli_stats(mme_s11_sockaddr_in.sin_addr.s_addr,
					gtpv2c_tx->gtpc.message_type,SENT,S11);

	return 0;
}

/**
 * @brief  : parses gtpv2c message and populates downlink_data_notification_ack_t
 *           structure
 * @param  : gtpv2c_rx
 *           buffer containing received downlink data notification ack message
 * @param  : ddn_ack
 *           structure to contain parsed information from message
 * @return : - 0 if successful
 *           - > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *             specified cause error value
 *           - < 0 for all other errors
 */
int
parse_downlink_data_notification_ack(gtpv2c_header_t *gtpv2c_rx,
			downlink_data_notification_t *ddn_ack)
{

	gtpv2c_ie *current_ie;
	gtpv2c_ie *limit_ie;

	uint32_t teid = ntohl(gtpv2c_rx->teid.has_teid.teid);
	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &ddn_ack->context);

	if (ret < 0 || !ddn_ack->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	/** TODO: we should fully verify mandatory fields within received
	 * message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == GTP_IE_CAUSE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			ddn_ack->cause_ie = current_ie;
		} else if (current_ie->type == GTP_IE_DELAY_VALUE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			ddn_ack->delay =
					&IE_TYPE_PTR_FROM_GTPV2C_IE(delay_ie,
					current_ie)->delay_value;
		}
		/* TODO implement conditional IE "Recovery" */
	}

	/* Verify that cause is accepted */
	if (IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie,
			ddn_ack->cause_ie)->cause_ie_hdr.cause_value
	    != GTPV2C_CAUSE_REQUEST_ACCEPTED) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Cause not accepted for DDNAck\n", LOG_VALUE);
		return IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie,
				ddn_ack->cause_ie)->cause_ie_hdr.cause_value;
	}
	return 0;
}

/**
 * @brief  : from parameters, populates gtpv2c message 'downlink data notification' and
 *           populates required information elements as defined by
 *           clause 7.2.11 3gpp 29.274
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : sequence
 *           sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context
 *           UE Context data structure pertaining to the bearer to be modified
 * @param  : bearer
 *           bearer data structure to be modified
 * @return : Returns nothing
 */
static void
set_downlink_data_notification(gtpv2c_header_t *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer)
{
	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DOWNLINK_DATA_NOTIFICATION,
			htonl(context->s11_mme_gtpc_teid), sequence, 0);
	set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO, bearer->eps_bearer_id);
	set_ar_priority_ie(gtpv2c_tx, IE_INSTANCE_ZERO, bearer);
}


int
create_downlink_data_notification(ue_context *context, uint8_t eps_bearer_id,
		uint32_t sequence, gtpv2c_header_t *gtpv2c_tx)
{
	int ebi_index = GET_EBI_INDEX(eps_bearer_id);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}
	struct eps_bearer_t *bearer = context->eps_bearers[ebi_index];
	if (bearer == NULL)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	set_downlink_data_notification(gtpv2c_tx, sequence, context, bearer);

	return 0;
}

int
process_ddn_ack(downlink_data_notification_t ddn_ack, uint8_t *delay)
{
	int ret = 0;
	struct resp_info *resp = NULL;
	struct eps_bearer_t *bearer = NULL;

	/* Lookup entry in hash table on the basis of session id*/
	int ebi_index = 0;
	uint64_t seid =0;
	for (uint32_t idx=0; idx <MAX_BEARERS; idx++) {
			bearer = ddn_ack.context->eps_bearers[idx];
		if (bearer != NULL) {
			seid = (bearer->pdn)->seid;
			ebi_index = GET_EBI_INDEX(bearer->eps_bearer_id);
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"DDN ACK: SEID:%lu, ebi:%u\n",
					LOG_VALUE, seid, ebi_index);
			break;
		}
	}

	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return -1;
	}

	if (get_sess_entry(seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, seid);
			return -1;
	}


	/* VS: Update the session state */
	resp->msg_type = GTP_DOWNLINK_DATA_NOTIFICATION_ACK;
	resp->state = DDN_ACK_RCVD_STATE;

	/* check for conditional delay value, set if necessary,
	 * or indicate no delay */
	if (ddn_ack.delay != NULL)
		*delay = *ddn_ack.delay;
	else
		*delay = 0;

	/* Update the UE State */
	ret = update_ue_state(ddn_ack.context, DDN_ACK_RCVD_STATE, ebi_index);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to update UE "
			"State for ebi_index\n", LOG_VALUE, ebi_index);
	}
	return 0;

}

