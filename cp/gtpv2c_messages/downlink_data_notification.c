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
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

/* TODO remove if not necessary later */
/*struct downlink_data_notification_t {
	ue_context *context;

	gtpv2c_ie *bearer_context_to_be_created_ebi;
	gtpv2c_ie *arp;
};
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
 * parses gtpv2c message and populates downlink_data_notification_ack_t
 *   structure
 * @param gtpv2c_rx
 *   buffer containing received downlink data notification ack message
 * @param ddn_ack
 *   structure to contain parsed information from message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
parse_downlink_data_notification_ack(gtpv2c_header *gtpv2c_rx,
			struct downlink_data_notification *ddn_ack)
{

	gtpv2c_ie *current_ie;
	gtpv2c_ie *limit_ie;

	uint32_t teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);
	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &teid,
	    (void **) &ddn_ack->context);

	if (ret < 0 || !ddn_ack->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;


	/** TODO: we should fully verify mandatory fields within received
	 * message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_CAUSE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			ddn_ack->cause_ie = current_ie;
		} else if (current_ie->type == IE_DELAY_VALUE &&
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
		fprintf(stderr, "Cause not accepted for DDNAck\n");
		return IE_TYPE_PTR_FROM_GTPV2C_IE(cause_ie,
				ddn_ack->cause_ie)->cause_ie_hdr.cause_value;
	}
	return 0;
}

/**
 * from parameters, populates gtpv2c message 'downlink data notification' and
 * populates required information elements as defined by
 * clause 7.2.11 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'modify bearer request' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the bearer to be modified
 * @param bearer
 *   bearer data structure to be modified
 *
 */
static void
set_downlink_data_notification(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, ue_context *context, eps_bearer *bearer)
{
	set_gtpv2c_teid_header(gtpv2c_tx, GTP_DOWNLINK_DATA_NOTIFICATION,
			htonl(context->s11_mme_gtpc_teid), sequence);
	set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO, bearer->eps_bearer_id);
	set_ar_priority_ie(gtpv2c_tx, IE_INSTANCE_ZERO, bearer);
}


int
create_downlink_data_notification(ue_context *context, uint8_t eps_bearer_id,
		uint32_t sequence, gtpv2c_header *gtpv2c_tx)
{
	struct eps_bearer_t *bearer = context->eps_bearers[eps_bearer_id - 5];
	if (bearer == NULL)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	set_downlink_data_notification(gtpv2c_tx, sequence, context, bearer);

	return 0;
}

int
process_ddn_ack(gtpv2c_header *gtpv2c_rx, uint8_t *delay)
{

	struct downlink_data_notification
			downlink_data_notification_ack = { 0 };

	int ret = parse_downlink_data_notification_ack(gtpv2c_rx,
			&downlink_data_notification_ack);
	if (ret)
		return ret;

	/* check for conditional delay value, set if necessary,
	 * or indicate no delay */
	if (downlink_data_notification_ack.delay != NULL)
		*delay = *downlink_data_notification_ack.delay;
	else
		*delay = 0;

	struct dp_id dp_id = { .id = DPN_ID };

	if (send_ddn_ack(dp_id, downlink_data_notification_ack) < 0)
		rte_exit(EXIT_FAILURE, "Downlink data notification ack fail !!!");
	return 0;

}

