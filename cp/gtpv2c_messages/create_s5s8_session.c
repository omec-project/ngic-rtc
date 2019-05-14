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

#include <errno.h>

#include "packet_filters.h"
#include "gtpv2c_set_ie.h"
#include "../cp_dp_api/vepc_cp_dp_api.h"

#include "pfcp_messages.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_util.h"
#include "pfcp_session.h"

#include "../cp_stats.h"

extern pfcp_config_t pfcp_config;
extern pfcp_context_t pfcp_ctxt;
extern int pfcp_sgwc_fd_arr[MAX_NUM_PGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];
extern struct sockaddr_in pfcp_sgwu_sockaddr_arr[MAX_NUM_PGWU];
extern struct sockaddr_in pfcp_pgwu_sockaddr_arr[MAX_NUM_PGWU];


#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

/* PGWC S5S8 handlers:
 * static int parse_pgwc_s5s8_create_session_request(...)
 * int process_pgwc_s5s8_create_session_request(...)
 * static void set_pgwc_s5s8_create_session_response(...)
 *
 */

/** Table 7.2.1-1: Information Elements in a Create Session Request -
 *  incomplete list */
struct parse_pgwc_s5s8_create_session_request_t {
	uint8_t *bearer_context_to_be_created_ebi;
	fteid_ie *s5s8_sgw_gtpc_fteid;
	gtpv2c_ie *apn_ie;
	gtpv2c_ie *apn_restriction_ie;
	gtpv2c_ie *imsi_ie;
	gtpv2c_ie *msisdn_ie;
	gtpv2c_ie *apn_ambr_ie;
	gtpv2c_ie *pdn_type_ie;
	gtpv2c_ie *charging_characteristics_ie;
	gtpv2c_ie *bearer_qos_ie;
	gtpv2c_ie *bearer_tft_ie;
	gtpv2c_ie *s5s8_sgw_gtpu_fteid;
};

extern uint32_t num_adc_rules;
extern uint32_t adc_rule_id[];
extern struct response_info resp_t;

/**
 * parses gtpv2c message and populates parse_pgwc_s5s8_create_session_request_t structure
 * @param gtpv2c_rx
 *   buffer containing create bearer response message
 * @param csr
 *   data structure to contain required information elements from create
 *   create session response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */

static int
parse_pgwc_s5s8_create_session_request(gtpv2c_header *gtpv2c_rx,
		struct parse_pgwc_s5s8_create_session_request_t *csr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == IE_EBI &&
					current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_context_to_be_created_ebi =
					    IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
							    current_group_ie);
				} else if (current_group_ie->type ==
						IE_BEARER_QOS &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_qos_ie = current_group_ie;
				} else if (current_group_ie->type == IE_BEARER_TFT &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_tft_ie = current_group_ie;
				} else if (current_group_ie->type == IE_FTEID &&
						current_group_ie->instance ==
						IE_INSTANCE_TWO) {
					csr->s5s8_sgw_gtpu_fteid = current_group_ie;
				}
			}

		} else if (current_ie->type == IE_FTEID &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->s5s8_sgw_gtpc_fteid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, current_ie);
		} else if (current_ie->type == IE_APN &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_ie = current_ie;
		} else if (current_ie->type == IE_APN_RESTRICTION &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_restriction_ie = current_ie;
		} else if (current_ie->type == IE_IMSI &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->imsi_ie = current_ie;
		} else if (current_ie->type == IE_AMBR &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_ambr_ie = current_ie;
		} else if (current_ie->type == IE_PDN_TYPE &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->pdn_type_ie = current_ie;
		} else if (current_ie->type == IE_CHARGING_CHARACTERISTICS &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->charging_characteristics_ie = current_ie;
		} else if (current_ie->type == IE_MSISDN &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->msisdn_ie = current_ie;
		}
	}

	if (!csr->apn_ie
		|| !csr->apn_restriction_ie
		|| !csr->bearer_context_to_be_created_ebi
		|| !csr->s5s8_sgw_gtpc_fteid
		|| !csr->imsi_ie
		|| !csr->apn_ambr_ie
		|| !csr->pdn_type_ie
		|| !csr->bearer_qos_ie
		|| !csr->msisdn_ie
		|| !IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie,
				csr->pdn_type_ie)->ipv4) {
		fprintf(stderr, "Dropping packet\n");
		return -EPERM;
	}
	if (IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie, csr->pdn_type_ie)->ipv6) {
		fprintf(stderr, "IPv6 Not Yet Implemented - Dropping packet\n");
		return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}
	return 0;
}

/**
 * from parameters, populates gtpv2c message 'create session response' and
 * populates required information elements as defined by
 * clause 7.2.2 3gpp 29.274
 * @param gtpv2c_tx
 *   transmission buffer to contain 'create session response' message
 * @param sequence
 *   sequence number as described by clause 7.6 3gpp 29.274
 * @param context
 *   UE Context data structure pertaining to the session to be created
 * @param pdn
 *   PDN Connection data structure pertaining to the session to be created
 * @param bearer
 *   Default EPS Bearer corresponding to the PDN Connection to be created
 */
void
set_pgwc_s5s8_create_session_response(gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer)
{

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_CREATE_SESSION_RSP,
	    pdn->s5s8_sgw_gtpc_teid, sequence);

	set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO);
	set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPC,
			IE_INSTANCE_ONE,
			pdn->s5s8_pgw_gtpc_ipv4, pdn->s5s8_pgw_gtpc_teid);
	set_ipv4_paa_ie(gtpv2c_tx, IE_INSTANCE_ZERO, pdn->ipv4);
	set_apn_restriction_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			pdn->apn_restriction);
	{
		gtpv2c_ie *bearer_context_group =
				create_bearer_context_ie(gtpv2c_tx,
		    IE_INSTANCE_ZERO);
		add_grouped_ie_length(bearer_context_group,
		    set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				    bearer->eps_bearer_id));
		add_grouped_ie_length(bearer_context_group,
		    set_cause_accepted_ie(gtpv2c_tx, IE_INSTANCE_ZERO));

		add_grouped_ie_length(bearer_context_group,
	    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_PGW_GTPU,
			    IE_INSTANCE_ZERO, bearer->s5s8_pgw_gtpu_ipv4,
			    bearer->s5s8_pgw_gtpu_teid));
	}
}

int
process_pgwc_s5s8_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s5s8_tx)
{
	struct parse_pgwc_s5s8_create_session_request_t create_s5s8_session_request = { 0 };
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	struct in_addr ue_ip;
	int ret;

	ret = parse_pgwc_s5s8_create_session_request(gtpv2c_rx,
			&create_s5s8_session_request);
	if (ret)
		return ret;

	apn *apn_requested = get_apn(
	    APN_PTR_FROM_APN_IE(create_s5s8_session_request.apn_ie),
	    ntohs(create_s5s8_session_request.apn_ie->length));

	if (!apn_requested)
		return GTPV2C_CAUSE_MISSING_UNKNOWN_APN;

	uint8_t ebi_index =
		*create_s5s8_session_request.bearer_context_to_be_created_ebi - 5;

	ret = acquire_ip(&ue_ip);
	if (ret)
		return GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_OCCUPIED;

	/* Overload s11_sgw_gtpc_teid
	 * set s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
	 * key->ue_context_by_fteid_hash */
	uint8_t *imsi_val = (uint8_t *)IE_TYPE_PTR_FROM_GTPV2C_IE(uint64_t,
			create_s5s8_session_request.imsi_ie);
	ret = create_ue_context(imsi_val,
			ntohs(create_s5s8_session_request.imsi_ie->length),
			*create_s5s8_session_request.bearer_context_to_be_created_ebi, &context);
	if (ret)
		return ret;

	if (create_s5s8_session_request.msisdn_ie) {
		memcpy(&context->msisdn,
		    IE_TYPE_PTR_FROM_GTPV2C_IE(uint64_t,
				    create_s5s8_session_request.msisdn_ie),
		    ntohs(create_s5s8_session_request.msisdn_ie->length));
	}

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_in_use = apn_requested;
		pdn->apn_ambr = *IE_TYPE_PTR_FROM_GTPV2C_IE(ambr_ie,
		    create_s5s8_session_request.apn_ambr_ie);
		pdn->apn_restriction = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
		    create_s5s8_session_request.apn_restriction_ie);
		pdn->ipv4 = ue_ip;
		pdn->pdn_type = *IE_TYPE_PTR_FROM_GTPV2C_IE(pdn_type_ie,
		    create_s5s8_session_request.pdn_type_ie);
		if (create_s5s8_session_request.charging_characteristics_ie) {
			pdn->charging_characteristics =
				*IE_TYPE_PTR_FROM_GTPV2C_IE(
						charging_characteristics_ie,
						create_s5s8_session_request.
						charging_characteristics_ie);
		}

		pdn->s5s8_sgw_gtpc_ipv4 =
			create_s5s8_session_request.
			s5s8_sgw_gtpc_fteid->ip_u.ipv4;
		pdn->s5s8_sgw_gtpc_teid =
			create_s5s8_session_request.
			s5s8_sgw_gtpc_fteid->fteid_ie_hdr.teid_or_gre;
#ifdef PFCP_COMM
	        pdn->s5s8_pgw_gtpc_ipv4 = pfcp_config.pgwc_s5s8_ip[0];
#else
		pdn->s5s8_pgw_gtpc_ipv4 = s5s8_pgwc_ip;
#endif
		/* Note: s5s8_pgw_gtpc_teid generated from
		 * s5s8_pgw_gtpc_base_teid and incremented
		 * for each pdn connection, similar to
		 * s11_sgw_gtpc_teid
		 */
		set_s5s8_pgw_gtpc_teid(pdn);
	}
	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		if (create_s5s8_session_request.bearer_tft_ie) {
		}
		*/
		bearer->qos = *IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_qos_ie,
		    create_s5s8_session_request.bearer_qos_ie);

		bearer->s5s8_sgw_gtpu_ipv4 =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
						create_s5s8_session_request.s5s8_sgw_gtpu_fteid)->
							ip_u.ipv4;
		bearer->s5s8_sgw_gtpu_teid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
						create_s5s8_session_request.s5s8_sgw_gtpu_fteid)->
							fteid_ie_hdr.teid_or_gre;
#ifdef PFCP_COMM
		bearer->s5s8_pgw_gtpu_ipv4.s_addr = htonl(pfcp_ctxt.s5s8_pgwu_ip);
#else
		bearer->s5s8_pgw_gtpu_ipv4 = s5s8_pgwu_ip;
#endif
		/* Note: s5s8_pgw_gtpu_teid = s5s8_pgw_gtpc_teid */
		bearer->s5s8_pgw_gtpu_teid = pdn->s5s8_pgw_gtpc_teid;
		bearer->pdn = pdn;
	}

#ifndef ZMQ_COMM
	set_pgwc_s5s8_create_session_response(gtpv2c_s5s8_tx,
			gtpv2c_rx->teid_u.has_teid.seq, pdn, bearer);

#else
	/* Set create session response */
	resp_t.gtpv2c_tx_t = *gtpv2c_s5s8_tx;
	resp_t.context_t = *context;
	resp_t.pdn_t = *pdn;
	resp_t.bearer_t = *bearer;
	resp_t.gtpv2c_tx_t.teid_u.has_teid.seq = gtpv2c_rx->teid_u.has_teid.seq;
	resp_t.msg_type = GTP_CREATE_SESSION_REQ;
	/* resp_t.msg_type = gtpv2c_rx->gtpc.type;
	 * TODO:Revisit this for to handle type received from message */
#endif


#ifdef PFCP_COMM

	pfcp_session_establishment_request_t pfcp_sess_est_req = {0};

	//fill_pfcp_sess_est_s5s8_req(&pfcp_sess_est_req, &create_s5s8_session_request);

	/* Below Passing 3rd Argumt. as NULL to reuse the fill_pfcp_sess_estab*/
	context->seid = SESS_ID(pdn->s5s8_sgw_gtpc_teid, bearer->eps_bearer_id);
	fill_pfcp_sess_est_req(&pfcp_sess_est_req, NULL, context, bearer, pdn);

	/*Filling sequence number */
	pfcp_sess_est_req.header.seid_seqno.has_seid.seq_no  = htonl(gtpv2c_rx->teid_u.has_teid.seq);

	/* Filling PDN structure*/

	pfcp_sess_est_req.pdn_type.header.type = IE_PFCP_PDN_TYPE;
	pfcp_sess_est_req.pdn_type.header.len = UINT8_SIZE;
	pfcp_sess_est_req.pdn_type.spare = 0;
	pfcp_sess_est_req.pdn_type.pdn_type =  PFCP_PDN_TYPE_IPV4; // create_s5s8_session_request.pdn_type_ie->type ;

	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_session_establishment_request(&pfcp_sess_est_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	/*Send the packet to PGWU*/

	//if(pfcp_ctxt.flag_ava_ip == true)
	{
		for(uint32_t i=0;i < pfcp_config.num_pgwu; i++) {
			if ( pfcp_send(pfcp_pgwc_fd_arr[i], pfcp_msg, encoded, &pfcp_pgwu_sockaddr_arr[i]) < 0 )
				printf("Error sending: %i\n",errno);
		}
	}
	return 0;

#endif

	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));

	session.ue_addr.iptype = IPTYPE_IPV4;
	session.ue_addr.u.ipv4_addr = htonl(pdn->ipv4.s_addr);
	session.ul_s1_info.sgw_teid = htonl(bearer->s1u_sgw_gtpu_teid);
	session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);

	if (bearer->s11u_mme_gtpu_teid) {
		/* If CIOT: [enb_addr,enb_teid] =
		 * s11u[mme_gtpu_addr, mme_gtpu_teid]
		 */
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid = htonl(bearer->s11u_mme_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
	} else {
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid = htonl(bearer->s1u_enb_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
	}

	/* Pass SGWU IP addr to PGWU */
	session.dl_s1_info.s5s8_sgwu_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.s5s8_sgwu_addr.u.ipv4_addr =
			htonl(bearer->s5s8_sgw_gtpu_ipv4.s_addr);

	session.dl_s1_info.enb_teid = htonl(bearer->s5s8_sgw_gtpu_teid);

#ifdef SDN_ODL_BUILD
	/* Pass SGWU teid to PGWU */
	session.ul_s1_info.sgw_teid = htonl(bearer->s5s8_sgw_gtpu_teid);
#endif /*SDN_ODL_BUILD*/

	session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.ul_apn_mtr_idx = ulambr_idx;
	session.dl_apn_mtr_idx = dlambr_idx;
	session.num_ul_pcc_rules = 1;
	session.num_dl_pcc_rules = 1;
	session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	/* using ue ipv4 addr as unique identifier for an UE.
	 * and sess_id is combination of ue addr and bearer id.
	 * formula to set sess_id = (ue_ipv4_addr << 4) | bearer_id
	 */
	session.sess_id = SESS_ID(context->s11_sgw_gtpc_teid,
						bearer->eps_bearer_id);

	struct dp_id dp_id = { .id = DPN_ID };

	if (session_create(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");
	return 0;
}

/* SGWC S5S8 handlers:
 * static int parse_sgwc_s5s8_create_session_response(...)
 * int gen_sgwc_s5s8_create_session_request(...)
 * int process_sgwc_s5s8_create_session_response(...)
 *
 */

/** Table 7.2.1-1: Information Elements in a Create Session Response -
 *  incomplete list */
struct parse_sgwc_s5s8_create_session_response_t {
	uint8_t *bearer_context_to_be_created_ebi;
	fteid_ie *pgw_s5s8_gtpc_fteid;
	gtpv2c_ie *pdn_addr_alloc_ie;
	gtpv2c_ie *apn_restriction_ie;
	gtpv2c_ie *bearer_qos_ie;
	gtpv2c_ie *bearer_tft_ie;
	gtpv2c_ie *s5s8_pgw_gtpu_fteid;
};

/**
 * parses gtpv2c message and populates parse_sgwc_s5s8_create_session_response_t structure
 * @param gtpv2c_rx
 *   buffer containing create bearer response message
 * @param csr
 *   data structure to contain required information elements from create
 *   create session response message
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */

static int
parse_sgwc_s5s8_create_session_response(gtpv2c_header *gtpv2c_rx,
		struct parse_sgwc_s5s8_create_session_response_t *csr)
{
	gtpv2c_ie *current_ie;
	gtpv2c_ie *current_group_ie;
	gtpv2c_ie *limit_ie;
	gtpv2c_ie *limit_group_ie;

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_ie, limit_ie)
	{
		if (current_ie->type == IE_BEARER_CONTEXT &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			FOR_EACH_GROUPED_IE(current_ie, current_group_ie,
					limit_group_ie)
			{
				if (current_group_ie->type == IE_EBI &&
					current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_context_to_be_created_ebi =
					    IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
							    current_group_ie);
				} else if (current_group_ie->type ==
						IE_BEARER_QOS &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_qos_ie = current_group_ie;
				} else if (current_group_ie->type == IE_BEARER_TFT &&
						current_group_ie->instance ==
							IE_INSTANCE_ZERO) {
					csr->bearer_tft_ie = current_group_ie;
				} else if (current_group_ie->type == IE_FTEID &&
						current_group_ie->instance ==
						IE_INSTANCE_ZERO) {
					csr->s5s8_pgw_gtpu_fteid = current_group_ie;
				}
			}

		} else if (current_ie->type == IE_FTEID &&
				current_ie->instance == IE_INSTANCE_ONE) {
			csr->pgw_s5s8_gtpc_fteid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie, current_ie);
		} else if (current_ie->type == IE_PAA &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->pdn_addr_alloc_ie = current_ie;
		} else if (current_ie->type == IE_APN_RESTRICTION &&
				current_ie->instance == IE_INSTANCE_ZERO) {
			csr->apn_restriction_ie = current_ie;
		}
	}

	if (!csr->apn_restriction_ie
		|| !csr->bearer_context_to_be_created_ebi
		|| !csr->pgw_s5s8_gtpc_fteid) {
		fprintf(stderr, "Dropping packet\n");
		return -EPERM;
	}
	return 0;
}

int
gen_sgwc_s5s8_create_session_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_tx,
		uint32_t sequence, pdn_connection *pdn,
		eps_bearer *bearer, char *sgwu_fqdn)
{

	gtpv2c_ie *current_rx_ie;
	gtpv2c_ie *limit_rx_ie;

	set_gtpv2c_teid_header(gtpv2c_tx, GTP_CREATE_SESSION_REQ,
		    0, sequence);

	FOR_EACH_GTPV2C_IE(gtpv2c_rx, current_rx_ie, limit_rx_ie)
	{
		if (current_rx_ie->type == IE_BEARER_CONTEXT &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			gtpv2c_ie *bearer_context_group =
				create_bearer_context_ie(gtpv2c_tx,
			    IE_INSTANCE_ZERO);
			add_grouped_ie_length(bearer_context_group,
			    set_ebi_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
			    bearer->eps_bearer_id));
			add_grouped_ie_length(bearer_context_group,
				set_bearer_qos_ie(gtpv2c_tx, IE_INSTANCE_ZERO,
				bearer));
			add_grouped_ie_length(bearer_context_group,
			    set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_SGW_GTPU,
			    IE_INSTANCE_TWO, bearer->s5s8_sgw_gtpu_ipv4,
			    bearer->s5s8_sgw_gtpu_teid));
		} else if (current_rx_ie->type == IE_FTEID &&
				current_rx_ie->instance == IE_INSTANCE_ONE) {
			continue;
		} else if (current_rx_ie->type == IE_FTEID &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ipv4_fteid_ie(gtpv2c_tx, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
				IE_INSTANCE_ZERO,
				pdn->s5s8_sgw_gtpc_ipv4, pdn->s5s8_sgw_gtpc_teid);
		} else if (current_rx_ie->type == IE_APN &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_APN_RESTRICTION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_IMSI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_AMBR &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_PDN_TYPE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_CHARGING_CHARACTERISTICS &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_INDICATION &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			continue;
		} else if (current_rx_ie->type == IE_MEI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			continue;
		} else if (current_rx_ie->type == IE_MSISDN &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_ULI &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_SERVING_NETWORK &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_RAT_TYPE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_SELECTION_MODE &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_PAA &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		} else if (current_rx_ie->type == IE_PCO &&
				current_rx_ie->instance == IE_INSTANCE_ZERO) {
			set_ie_copy(gtpv2c_tx, current_rx_ie);
		}
	}

	set_fqdn_ie(gtpv2c_tx, sgwu_fqdn);

	return 0;
}

int
process_sgwc_s5s8_create_session_response(gtpv2c_header *gtpv2c_s5s8_rx,
			gtpv2c_header *gtpv2c_s11_tx)
{
	pfcp_session_modification_request_t pfcp_sess_mod_req = {0};
	struct parse_sgwc_s5s8_create_session_response_t create_s5s8_session_response = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	int ret;
	static uint32_t process_sgwc_s5s8_cs_rsp_cnt;
	static uint32_t process_spgwc_s11_cs_res_cnt;

	ret = parse_sgwc_s5s8_create_session_response(gtpv2c_s5s8_rx,
			&create_s5s8_session_response);
	if (ret)
		return ret;

	uint8_t ebi_index =
		*create_s5s8_session_response.bearer_context_to_be_created_ebi - 5;

	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * key->ue_context_by_fteid_hash */
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
	    (const void *) &gtpv2c_s5s8_rx->teid_u.has_teid.teid,
	    (void **) &context);
	RTE_LOG_DP(DEBUG, CP, "NGIC- create_s5s8_session.c::"
			"\n\tprocess_sgwc_s5s8_create_session_response"
			"\n\tprocess_sgwc_s5s8_cs_rsp_cnt= %u;"
			"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X\n",
			process_sgwc_s5s8_cs_rsp_cnt,
			gtpv2c_s5s8_rx->teid_u.has_teid.teid);
	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	pdn = context->pdns[ebi_index];
	{
		pdn->apn_restriction = *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t,
		    create_s5s8_session_response.apn_restriction_ie);

		struct in_addr ip;
		ip = get_ipv4_paa_ipv4(
					create_s5s8_session_response.pdn_addr_alloc_ie);

		pdn->ipv4.s_addr = htonl(ip.s_addr);

		pdn->s5s8_pgw_gtpc_ipv4.s_addr =
				htonl(create_s5s8_session_response.
				pgw_s5s8_gtpc_fteid->ip_u.ipv4.s_addr);
		/* Note: s5s8_pgw_gtpc_teid updated by
		 * create_s5s8_session_response.pgw_s5s8_gtpc_fteid...
		 */
		pdn->s5s8_pgw_gtpc_teid =
				htonl(create_s5s8_session_response.
				pgw_s5s8_gtpc_fteid->fteid_ie_hdr.teid_or_gre);
	}
	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		if (create_s5s8_session_response.bearer_tft_ie) {
		}
		*/
		/* TODO: Implement PGWC S5S8 bearer QoS */
		if (create_s5s8_session_response.bearer_qos_ie) {
			bearer->qos = *IE_TYPE_PTR_FROM_GTPV2C_IE(bearer_qos_ie,
				create_s5s8_session_response.bearer_qos_ie);
		}
		bearer->s5s8_pgw_gtpu_ipv4.s_addr =
				htonl(IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
						create_s5s8_session_response.s5s8_pgw_gtpu_fteid)->
							ip_u.ipv4.s_addr);
		bearer->s5s8_pgw_gtpu_teid =
				IE_TYPE_PTR_FROM_GTPV2C_IE(fteid_ie,
						create_s5s8_session_response.s5s8_pgw_gtpu_fteid)->
							fteid_ie_hdr.teid_or_gre;

		bearer->pdn = pdn;
	}
#ifndef ZMQ_COMM
	set_create_session_response(
			gtpv2c_s11_tx, gtpv2c_s5s8_rx->teid_u.has_teid.seq,
			context, pdn, bearer);

#else
		/* Set create session response */
		resp_t.gtpv2c_tx_t = *gtpv2c_s11_tx;
		resp_t.context_t = *context;
		resp_t.pdn_t = *pdn;
		resp_t.bearer_t = *bearer;
		resp_t.gtpv2c_tx_t.teid_u.has_teid.seq = gtpv2c_s5s8_rx->teid_u.has_teid.seq;
		resp_t.msg_type = GTP_CREATE_SESSION_REQ;
		/*resp_t.msg_type = gtpv2c_s5s8_rx->gtpc.type;
		 * TODO:Revisit this for to handle type received from message */
#endif

	RTE_LOG_DP(DEBUG, CP, "NGIC- create_s5s8_session.c::"
			"\n\tprocess_sgwc_s5s8_cs_rsp_cnt= %u;"
			"\n\tprocess_spgwc_s11_cs_res_cnt= %u;"
			"\n\tue_ip= pdn->ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
			"\n\tbearer->s5s8_sgw_gtpu_ipv4= %s;"
			"\n\tbearer->s5s8_sgw_gtpu_teid= %X;"
			"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
			"\n\tbearer->s5s8_pgw_gtpu_ipv4= %s;"
			"\n\tbearer->s5s8_pgw_gtpu_teid= %X\n",
			process_sgwc_s5s8_cs_rsp_cnt++,
			process_spgwc_s11_cs_res_cnt++,
			inet_ntoa(pdn->ipv4),
			inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
			pdn->s5s8_sgw_gtpc_teid,
			inet_ntoa(bearer->s5s8_sgw_gtpu_ipv4),
			bearer->s5s8_sgw_gtpu_teid,
			inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
			pdn->s5s8_pgw_gtpc_teid,
			inet_ntoa(bearer->s5s8_pgw_gtpu_ipv4),
			bearer->s5s8_pgw_gtpu_teid);

#ifdef PFCP_COMM

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, NULL, context, bearer, pdn);
	pfcp_sess_mod_req.create_pdr[0].pdi.local_fteid.teid = htonl(bearer->s5s8_pgw_gtpu_teid) ;
	pfcp_sess_mod_req.create_pdr[0].pdi.local_fteid.ipv4_address = htonl(bearer->s5s8_pgw_gtpu_ipv4.s_addr) ;
	pfcp_sess_mod_req.create_pdr[0].pdi.ue_ip_address.ipv4_address = htonl(pdn->ipv4.s_addr);
	pfcp_sess_mod_req.create_pdr[0].pdi.source_interface.interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
	pfcp_sess_mod_req.header.seid_seqno.has_seid.seq_no = gtpv2c_s5s8_rx->teid_u.has_teid.seq ;

	/*pfcp_sess_mod_req.pdn_type.header.type = IE_PFCP_PDN_TYPE;
	pfcp_sess_mod_req.pdn_type.header.len = UINT8_SIZE;
	pfcp_sess_mod_req.pdn_type.spare = 0;
	pfcp_sess_mod_req.pdn_type.pdn_type = PFCP_PDN_TYPE_IPV4;*/

	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_session_modification_request(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	for(uint32_t i=0; i < pfcp_config.num_sgwu; i++ ) {
		if ( pfcp_send(pfcp_sgwc_fd_arr[i], pfcp_msg, encoded,
					&pfcp_sgwu_sockaddr_arr[i]) < 0 )

		printf("Error sending: %i\n",errno);
	}



#else
	/* using the s1u_sgw_gtpu_teid as unique identifier to the session */
	struct session_info session;
	memset(&session, 0, sizeof(session));

	session.ue_addr.iptype = IPTYPE_IPV4;
	session.ue_addr.u.ipv4_addr = pdn->ipv4.s_addr;
	session.ul_s1_info.sgw_teid = htonl(bearer->s1u_sgw_gtpu_teid);
	session.ul_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);

	if (bearer->s11u_mme_gtpu_teid) {
		/* If CIOT: [enb_addr,enb_teid] =
		 * s11u[mme_gtpu_addr, mme_gtpu_teid]
		 */
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid = htonl(bearer->s11u_mme_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s11u_mme_gtpu_ipv4.s_addr);
	} else {
		session.ul_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.ul_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
		session.dl_s1_info.enb_teid = htonl(bearer->s1u_enb_gtpu_teid);
		session.dl_s1_info.enb_addr.iptype = IPTYPE_IPV4;
		session.dl_s1_info.enb_addr.u.ipv4_addr =
				htonl(bearer->s1u_enb_gtpu_ipv4.s_addr);
	}

	/* Pass PGWU IP addr to SGWU */
	session.ul_s1_info.s5s8_pgwu_addr.iptype = IPTYPE_IPV4;
	session.ul_s1_info.s5s8_pgwu_addr.u.ipv4_addr =
			bearer->s5s8_pgw_gtpu_ipv4.s_addr;
	session.dl_s1_info.sgw_addr.iptype = IPTYPE_IPV4;
	session.dl_s1_info.sgw_addr.u.ipv4_addr =
			htonl(bearer->s1u_sgw_gtpu_ipv4.s_addr);
	session.ul_apn_mtr_idx = ulambr_idx;
	session.dl_apn_mtr_idx = dlambr_idx;
	session.num_ul_pcc_rules = 1;
	session.num_dl_pcc_rules = 1;
	session.ul_pcc_rule_id[0] = FIRST_FILTER_ID;
	session.dl_pcc_rule_id[0] = FIRST_FILTER_ID;

	/* using ue ipv4 addr as unique identifier for an UE.
	 * and sess_id is combination of ue addr and bearer id.
	 * formula to set sess_id = (ue_ipv4_addr << 4) | bearer_id
	 */
	session.sess_id = SESS_ID(context->s11_sgw_gtpc_teid,
						bearer->eps_bearer_id);

	struct dp_id dp_id = { .id = DPN_ID };

	if (session_create(dp_id, session) < 0)
		rte_exit(EXIT_FAILURE,"Bearer Session create fail !!!");
#endif
	return 0;
}

