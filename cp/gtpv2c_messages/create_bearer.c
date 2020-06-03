/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "gtpv2c.h"
#include "ue.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

struct parse_create_bearer_rsp_t {
	ue_context *context;
	eps_bearer *ded_bearer;

	gtpv2c_ie *cause_ie;
	gtpv2c_ie *bearer_contexts_ie;
	gtpv2c_ie *ebi_ie;
	gtpv2c_ie *s1u_enb_gtpu_fteid_ie;
	gtpv2c_ie *s1u_sgw_gtpu_fteid_ie;
};
extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];

/**
 * parses gtpv2c message and populates parse_create_bearer_rsp structure
 * @param gtpv2c_rx
 *   buffer containing create bearer response message
 * @param cbr
 *   data structure to contain required information elements from parsed
 *   create bearer response
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
static int
parse_create_bearer_rsp(gtpv2c_header *gtpv2c_rx,
	struct parse_create_bearer_rsp_t *cbr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_rx->teid_u.has_teid.teid,
	    (void **) &cbr->context);

	if (ret < 0 || !cbr->context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	cbr->ded_bearer = cbr->context->ded_bearer;
	if (cbr->ded_bearer == NULL) {
		fprintf(stderr, "Received unexpected Create "
				"Bearer Response!\n");
		return -EPERM;
	}
	cbr->context->ded_bearer = NULL;

	/** TODO: we should fully verify mandatory fields within
	 * received message */
	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			cbr->bearer_contexts_ie = current_ie;
			FOR_EACH_GROUPED_IE(
					current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == IE_EBI &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					cbr->ebi_ie = current_group_ie;
				} else if (current_group_ie->type == IE_FTEID &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					cbr->s1u_enb_gtpu_fteid_ie =
							current_group_ie;
				} else if (current_group_ie->type == IE_FTEID &&
						current_group_ie->instance ==
							IE_INSTANCE_ONE) {
					cbr->s1u_sgw_gtpu_fteid_ie =
							current_group_ie;
				}
			}
		} else if (current_ie->type == IE_CAUSE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			cbr->cause_ie = current_ie;
		}
	}

	if (cbr->ebi_ie == NULL || cbr->s1u_enb_gtpu_fteid_ie == NULL
	    || cbr->s1u_sgw_gtpu_fteid_ie == NULL) {
		fprintf(stderr, "Received Create Bearer "
				"response without expected IEs");
		return -EPERM;
	}

	cbr->ded_bearer->eps_bearer_id =
		IE_TYPE_PTR_FROM_GTPV2C_IE(eps_bearer_id_ie, cbr->ebi_ie)->ebi;
	cbr->ded_bearer->s1u_enb_gtpu_ipv4 =
		IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
				cbr->s1u_enb_gtpu_fteid_ie)->ip_u.ipv4;
	cbr->ded_bearer->s1u_enb_gtpu_teid =
		IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
			cbr->s1u_enb_gtpu_fteid_ie)->fteid_ie_hdr.teid_or_gre;

	return 0;
}

int
process_create_bearer_response(gtpv2c_header *gtpv2c_rx)
{
	struct parse_create_bearer_rsp_t create_bearer_rsp = {0};
	uint8_t i;
	int ret = parse_create_bearer_rsp(gtpv2c_rx, &create_bearer_rsp);

	if (ret)
		return ret;

	uint8_t ebi_index = create_bearer_rsp.ded_bearer->eps_bearer_id - 5;

	if (create_bearer_rsp.context->eps_bearers[ebi_index]) {
		/* TODO: Investigate correct behavior when new bearers are
		 * created with an ID of existing bearer
		 */
		rte_free(create_bearer_rsp.context->eps_bearers[ebi_index]);
	}

	create_bearer_rsp.context->eps_bearers[ebi_index] =
	    create_bearer_rsp.ded_bearer;
	create_bearer_rsp.context->bearer_bitmap |= (1 << ebi_index);

	create_bearer_rsp.ded_bearer->pdn->eps_bearers[ebi_index] =
	    create_bearer_rsp.ded_bearer;
	create_bearer_rsp.context->eps_bearers[ebi_index] =
	    create_bearer_rsp.ded_bearer;

	struct dp_id dp_id = { .id = create_bearer_rsp.context->dpId };
	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));

	session.ue_addr.iptype = IPTYPE_IPV4;
	session.ue_addr.u.ipv4_addr =
		htonl(create_bearer_rsp.ded_bearer->pdn->ipv4.s_addr);
	session.ul_s1_info.sgw_teid =
		htonl(create_bearer_rsp.ded_bearer->s1u_sgw_gtpu_teid),
	session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.sgw_addr.u.ipv4_addr =
		htonl(create_bearer_rsp.ded_bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.enb_addr.u.ipv4_addr =
		htonl(create_bearer_rsp.ded_bearer->s1u_enb_gtpu_ipv4.s_addr);
	session.dl_s1_info.enb_teid =
		htonl(create_bearer_rsp.ded_bearer->s1u_enb_gtpu_teid);
	session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.enb_addr.u.ipv4_addr =
		htonl(create_bearer_rsp.ded_bearer->s1u_enb_gtpu_ipv4.s_addr);
	session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4,
	session.dl_s1_info.sgw_addr.u.ipv4_addr =
		htonl(create_bearer_rsp.ded_bearer->s1u_sgw_gtpu_ipv4.s_addr),
	session.ul_apn_mtr_idx = ulambr_idx;
	session.dl_apn_mtr_idx = dlambr_idx;

	for (i = 0; i < create_bearer_rsp.ded_bearer->num_packet_filters; ++i) {
		uint8_t packet_filter_direction = get_packet_filter_direction(
		    create_bearer_rsp.ded_bearer->packet_filter_map[i]);
		if (packet_filter_direction & TFT_DIRECTION_DOWNLINK_ONLY) {
			session.dl_pcc_rule_id[session.num_dl_pcc_rules++] =
			    create_bearer_rsp.ded_bearer->packet_filter_map[i];
		}
		if (packet_filter_direction & TFT_DIRECTION_UPLINK_ONLY) {
			session.ul_pcc_rule_id[session.num_ul_pcc_rules++] =
					FIRST_FILTER_ID;
		}
	}
	session.num_adc_rules = num_adc_rules;
	for (i = 0; i < num_adc_rules; ++i)
		session.adc_rule_id[i] = adc_rule_id[i];
	/* using ue ipv4 addr as unique identifier for an UE.
	 * and sess_id is combination of ue addr and bearer id.
	 * formula to set sess_id = (ue_ipv4_addr << 4) | bearer_id
	 */
	session.sess_id = SESS_ID(create_bearer_rsp.context->s11_sgw_gtpc_teid,
				create_bearer_rsp.ded_bearer->eps_bearer_id);

	/* TODO : new bearer should be created on the same DP. Pull the dpId from user context and 
	* then send the bearer create to the same dp id. 	
	*/
	if (session_create(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");

	if (session_modify(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session modify fail !!!");
	return 0;
}
