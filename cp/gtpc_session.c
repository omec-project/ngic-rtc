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

#include "gtpc_session.h"
#include "gtpv2c_error_rsp.h"
#include "cp_timer.h"
#include "clogger.h"
#include "main.h"

extern int pfcp_fd;
extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

int
fill_cs_request(create_sess_req_t *cs_req, struct ue_context_t *context,
		uint8_t ebi_index)
{
	int len = 0 ;
	set_gtpv2c_header(&cs_req->header, 1, GTP_CREATE_SESSION_REQ,
			0, context->sequence);

	cs_req->imsi.imsi_number_digits = context->imsi;
	set_ie_header(&cs_req->imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
			sizeof(cs_req->imsi.imsi_number_digits));

	set_ie_header(&cs_req->msisdn.header, GTP_IE_MSISDN, IE_INSTANCE_ZERO, BINARY_MSISDN_LEN);
	cs_req->msisdn.msisdn_number_digits = context->msisdn;

	if (context->uli.lai) {
		cs_req->uli.lai = context->uli.lai;
		cs_req->uli.lai2.lai_mcc_digit_2 = context->uli.lai2.lai_mcc_digit_2;
		cs_req->uli.lai2.lai_mcc_digit_1 = context->uli.lai2.lai_mcc_digit_1;
		cs_req->uli.lai2.lai_mnc_digit_3 = context->uli.lai2.lai_mnc_digit_3;
		cs_req->uli.lai2.lai_mcc_digit_3 = context->uli.lai2.lai_mcc_digit_3;
		cs_req->uli.lai2.lai_mnc_digit_2 = context->uli.lai2.lai_mnc_digit_2;
		cs_req->uli.lai2.lai_mnc_digit_1 = context->uli.lai2.lai_mnc_digit_1;
		cs_req->uli.lai2.lai_lac = context->uli.lai2.lai_lac;

		len += sizeof(cs_req->uli.lai2);
	}
	if (context->uli.tai) {
		cs_req->uli.tai = context->uli.tai;
		cs_req->uli.tai2.tai_mcc_digit_2 = context->uli.tai2.tai_mcc_digit_2;
		cs_req->uli.tai2.tai_mcc_digit_1 = context->uli.tai2.tai_mcc_digit_1;
		cs_req->uli.tai2.tai_mnc_digit_3 = context->uli.tai2.tai_mnc_digit_3;
		cs_req->uli.tai2.tai_mcc_digit_3 = context->uli.tai2.tai_mcc_digit_3;
		cs_req->uli.tai2.tai_mnc_digit_2 = context->uli.tai2.tai_mnc_digit_2;
		cs_req->uli.tai2.tai_mnc_digit_1 = context->uli.tai2.tai_mnc_digit_1;
		cs_req->uli.tai2.tai_tac = context->uli.tai2.tai_tac;
		len += sizeof(cs_req->uli.tai2);
	}
	if (context->uli.rai) {
		cs_req->uli.rai = context->uli.rai;
		cs_req->uli.rai2.ria_mcc_digit_2 = context->uli.rai2.ria_mcc_digit_2;
		cs_req->uli.rai2.ria_mcc_digit_1 = context->uli.rai2.ria_mcc_digit_1;
		cs_req->uli.rai2.ria_mnc_digit_3 = context->uli.rai2.ria_mnc_digit_3;
		cs_req->uli.rai2.ria_mcc_digit_3 = context->uli.rai2.ria_mcc_digit_3;
		cs_req->uli.rai2.ria_mnc_digit_2 = context->uli.rai2.ria_mnc_digit_2;
		cs_req->uli.rai2.ria_mnc_digit_1 = context->uli.rai2.ria_mnc_digit_1;
		cs_req->uli.rai2.ria_lac = context->uli.rai2.ria_lac;
		cs_req->uli.rai2.ria_rac = context->uli.rai2.ria_rac;
		len += sizeof(cs_req->uli.rai2);
	}
	if (context->uli.sai) {
		cs_req->uli.sai = context->uli.sai;
		cs_req->uli.sai2.sai_mcc_digit_2 = context->uli.sai2.sai_mcc_digit_2;
		cs_req->uli.sai2.sai_mcc_digit_1 = context->uli.sai2.sai_mcc_digit_1;
		cs_req->uli.sai2.sai_mnc_digit_3 = context->uli.sai2.sai_mnc_digit_3;
		cs_req->uli.sai2.sai_mcc_digit_3 = context->uli.sai2.sai_mcc_digit_3;
		cs_req->uli.sai2.sai_mnc_digit_2 = context->uli.sai2.sai_mnc_digit_2;
		cs_req->uli.sai2.sai_mnc_digit_1 = context->uli.sai2.sai_mnc_digit_1;
		cs_req->uli.sai2.sai_lac = context->uli.sai2.sai_lac;
		cs_req->uli.sai2.sai_sac = context->uli.sai2.sai_sac;
		len += sizeof(cs_req->uli.sai2);
	}
	if (context->uli.cgi) {
		cs_req->uli.cgi = context->uli.cgi;
		cs_req->uli.cgi2.cgi_mcc_digit_2 = context->uli.cgi2.cgi_mcc_digit_2;
		cs_req->uli.cgi2.cgi_mcc_digit_1 = context->uli.cgi2.cgi_mcc_digit_1;
		cs_req->uli.cgi2.cgi_mnc_digit_3 = context->uli.cgi2.cgi_mnc_digit_3;
		cs_req->uli.cgi2.cgi_mcc_digit_3 = context->uli.cgi2.cgi_mcc_digit_3;
		cs_req->uli.cgi2.cgi_mnc_digit_2 = context->uli.cgi2.cgi_mnc_digit_2;
		cs_req->uli.cgi2.cgi_mnc_digit_1 = context->uli.cgi2.cgi_mnc_digit_1;
		cs_req->uli.cgi2.cgi_lac = context->uli.cgi2.cgi_lac;
	    cs_req->uli.cgi2.cgi_ci = context->uli.cgi2.cgi_ci;
		len += sizeof(cs_req->uli.cgi2);
	}
	if (context->uli.ecgi) {
		cs_req->uli.ecgi = context->uli.ecgi;
		cs_req->uli.ecgi2.ecgi_mcc_digit_2 = context->uli.ecgi2.ecgi_mcc_digit_2;
		cs_req->uli.ecgi2.ecgi_mcc_digit_1 = context->uli.ecgi2.ecgi_mcc_digit_1;
		cs_req->uli.ecgi2.ecgi_mnc_digit_3 = context->uli.ecgi2.ecgi_mnc_digit_3;
		cs_req->uli.ecgi2.ecgi_mcc_digit_3 = context->uli.ecgi2.ecgi_mcc_digit_3;
		cs_req->uli.ecgi2.ecgi_mnc_digit_2 = context->uli.ecgi2.ecgi_mnc_digit_2;
		cs_req->uli.ecgi2.ecgi_mnc_digit_1 = context->uli.ecgi2.ecgi_mnc_digit_1;
		cs_req->uli.ecgi2.ecgi_spare = context->uli.ecgi2.ecgi_spare;
	    cs_req->uli.ecgi2.eci = context->uli.ecgi2.eci;
		len += sizeof(cs_req->uli.ecgi2);
	}
	if (context->uli.macro_enodeb_id) {
		cs_req->uli.macro_enodeb_id = context->uli.macro_enodeb_id;
		cs_req->uli.macro_enodeb_id2.menbid_mcc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_2;
		cs_req->uli.macro_enodeb_id2.menbid_mcc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_1;
		cs_req->uli.macro_enodeb_id2.menbid_mnc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_3;
		cs_req->uli.macro_enodeb_id2.menbid_mcc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_3;
		cs_req->uli.macro_enodeb_id2.menbid_mnc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_2;
		cs_req->uli.macro_enodeb_id2.menbid_mnc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_1;
		cs_req->uli.macro_enodeb_id2.menbid_spare =
			context->uli.macro_enodeb_id2.menbid_spare;
		cs_req->uli.macro_enodeb_id2.menbid_macro_enodeb_id =
			context->uli.macro_enodeb_id2.menbid_macro_enodeb_id;
		cs_req->uli.macro_enodeb_id2.menbid_macro_enb_id2 =
			context->uli.macro_enodeb_id2.menbid_macro_enb_id2;
		len += sizeof(cs_req->uli.macro_enodeb_id2);
	}
	if (context->uli.extnded_macro_enb_id) {
		cs_req->uli.extnded_macro_enb_id = context->uli.extnded_macro_enb_id;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_smenb =
			context->uli.extended_macro_enodeb_id2.emenbid_smenb;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_spare =
			context->uli.extended_macro_enodeb_id2.emenbid_spare;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
		cs_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
		len += sizeof(cs_req->uli.extended_macro_enodeb_id2);
	}
	len += 1;
	set_ie_header(&cs_req->uli.header, GTP_IE_USER_LOC_INFO, IE_INSTANCE_ZERO, len);


	set_ie_header(&cs_req->serving_network.header, GTP_IE_SERVING_NETWORK, IE_INSTANCE_ZERO,
		sizeof(gtp_serving_network_ie_t) - sizeof(ie_header_t));
	cs_req->serving_network.mnc_digit_1 = context->serving_nw.mnc_digit_1;
	cs_req->serving_network.mnc_digit_2 = context->serving_nw.mnc_digit_2;
	cs_req->serving_network.mnc_digit_3 = context->serving_nw.mnc_digit_3;
	cs_req->serving_network.mcc_digit_1 = context->serving_nw.mcc_digit_1;
	cs_req->serving_network.mcc_digit_2 = context->serving_nw.mcc_digit_2;
	cs_req->serving_network.mcc_digit_3 = context->serving_nw.mcc_digit_3;

	set_ie_header(&cs_req->rat_type.header, GTP_IE_RAT_TYPE, IE_INSTANCE_ZERO,
			 sizeof(gtp_rat_type_ie_t) - sizeof(ie_header_t));
	cs_req->rat_type.rat_type = context->rat_type.rat_type;

	set_ipv4_fteid(&cs_req->sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
				IE_INSTANCE_ZERO, context->pdns[ebi_index]->s5s8_sgw_gtpc_ipv4,
				context->pdns[ebi_index]->s5s8_sgw_gtpc_teid);

	set_ie_header(&cs_req->apn.header, GTP_IE_ACC_PT_NAME, IE_INSTANCE_ZERO,
		             context->pdns[ebi_index]->apn_in_use->apn_name_length);
	memcpy(cs_req->apn.apn, &(context->pdns[ebi_index]->apn_in_use->apn_name_label[0]),
			context->pdns[ebi_index]->apn_in_use->apn_name_length);

	if (context->selection_flag) {
		cs_req->selection_mode.spare2 = context->select_mode.spare2;
		cs_req->selection_mode.selec_mode = context->select_mode.selec_mode;
	}

	set_ie_header(&cs_req->selection_mode.header, GTP_IE_SELECTION_MODE, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	if (context->pdns[ebi_index]->ue_time_zone_flag == TRUE) {
		cs_req->ue_time_zone.time_zone = context->pdns[ebi_index]->ue_tz.tz;
		cs_req->ue_time_zone.daylt_svng_time = context->pdns[ebi_index]->ue_tz.dst;
		cs_req->ue_time_zone.spare2 = 0;

		set_ie_header(&cs_req->ue_time_zone.header, GTP_IE_UE_TIME_ZONE, IE_INSTANCE_ZERO,
				sizeof(gtp_ue_time_zone_ie_t) - sizeof(ie_header_t));
		cs_req->header.gtpc.message_len = cs_req->ue_time_zone.header.len + sizeof(ie_header_t);
		//context->pdns[ebi_index]->ue_time_zone_flag = FALSE;
	}

	if (context->pdns[ebi_index]->pdn_type.ipv4)
		cs_req->pdn_type.pdn_type_pdn_type = PDN_TYPE_TYPE_IPV4;

	if (context->pdns[ebi_index]->pdn_type.ipv6)
		cs_req->pdn_type.pdn_type_pdn_type = PDN_TYPE_TYPE_IPV6;

	cs_req->pdn_type.pdn_type_spare2 = context->pdns[ebi_index]->pdn_type.spare;
	set_ie_header(&cs_req->pdn_type.header, GTP_IE_PDN_TYPE, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	set_ipv4_paa(&cs_req->paa, IE_INSTANCE_ZERO,
			context->pdns[ebi_index]->ipv4);
	uint32_t temp;
	temp = htonl(context->pdns[ebi_index]->ipv4.s_addr);
	memcpy(cs_req->paa.pdn_addr_and_pfx, &temp, sizeof(uint32_t));

	cs_req->max_apn_rstrct.rstrct_type_val = context->pdns[ebi_index]->apn_restriction;
	set_ie_header(&cs_req->max_apn_rstrct.header, GTP_IE_APN_RESTRICTION, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	cs_req->apn_ambr.apn_ambr_uplnk = context->pdns[ebi_index]->apn_ambr.ambr_uplink;
	cs_req->apn_ambr.apn_ambr_dnlnk = context->pdns[ebi_index]->apn_ambr.ambr_downlink;
	set_ie_header(&cs_req->apn_ambr.header, GTP_IE_AGG_MAX_BIT_RATE, IE_INSTANCE_ZERO,
			sizeof(uint64_t));

	set_ebi(&cs_req->bearer_contexts_to_be_created.eps_bearer_id, IE_INSTANCE_ZERO,
				context->eps_bearers[ebi_index]->eps_bearer_id);
	set_ie_header(&cs_req->bearer_contexts_to_be_created.eps_bearer_id.header,
			GTP_IE_EPS_BEARER_ID, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	set_ie_header(&cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.header,
			GTP_IE_BEARER_QLTY_OF_SVC, IE_INSTANCE_ZERO, sizeof(gtp_bearer_qlty_of_svc_ie_t) - sizeof(ie_header_t));
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.pvi =
			context->eps_bearers[ebi_index]->qos.arp.preemption_vulnerability;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.spare2 = 0;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.pl =
		context->eps_bearers[ebi_index]->qos.arp.priority_level;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.pci =
		context->eps_bearers[ebi_index]->qos.arp.preemption_capability;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.spare3 = 0;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.qci =
		context->eps_bearers[ebi_index]->qos.qci;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_mbr;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.max_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_mbr;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_gbr;
	cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.guarntd_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_gbr;

	set_ipv4_fteid(&cs_req->bearer_contexts_to_be_created.s5s8_u_sgw_fteid,
			GTPV2C_IFTYPE_S5S8_SGW_GTPU,
			IE_INSTANCE_TWO, context->eps_bearers[ebi_index]->s5s8_sgw_gtpu_ipv4,
			context->eps_bearers[ebi_index]->s5s8_sgw_gtpu_teid);
	cs_req->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.ipv4_address =
		htonl(cs_req->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.ipv4_address);
	set_ie_header(&cs_req->bearer_contexts_to_be_created.header,
			GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO,
		cs_req->bearer_contexts_to_be_created.eps_bearer_id.header.len
		+ sizeof(ie_header_t)
		+ cs_req->bearer_contexts_to_be_created.bearer_lvl_qos.header.len
		+ sizeof(ie_header_t)
		+ cs_req->bearer_contexts_to_be_created.s5s8_u_sgw_fteid.header.len
		+ sizeof(ie_header_t));
	/*fill fqdn string */
	set_ie_header(&cs_req->sgw_u_node_name.header, GTP_IE_FULLY_QUAL_DOMAIN_NAME, IE_INSTANCE_ZERO,
			    strlen((char *)context->pdns[ebi_index]->fqdn));
	strncpy((char *)&cs_req->sgw_u_node_name.fqdn, (char *)context->pdns[ebi_index]->fqdn, strlen((char *)context->pdns[ebi_index]->fqdn));

	if (context->mapped_ue_usage_type >= 0)
		set_mapped_ue_usage_type(&cs_req->mapped_ue_usage_type, context->mapped_ue_usage_type);

	cs_req->header.gtpc.message_len +=
			cs_req->imsi.header.len + cs_req->msisdn.header.len
			+ sizeof(ie_header_t)
			+ sizeof(ie_header_t)
			+ cs_req->uli.header.len + cs_req->rat_type.header.len
			+ sizeof(ie_header_t)
			+ sizeof(ie_header_t)
			+ cs_req->serving_network.header.len
			+ sizeof(ie_header_t)
			+ cs_req->sender_fteid_ctl_plane.header.len
			+ sizeof(ie_header_t)
			+ cs_req->apn.header.len
			+ sizeof(ie_header_t)
			+ cs_req->selection_mode.header.len
			+ sizeof(ie_header_t)
			+ cs_req->pdn_type.header.len
			+ sizeof(ie_header_t)
			+ cs_req->paa.header.len
			+ sizeof(ie_header_t)
			+ cs_req->max_apn_rstrct.header.len
			+ sizeof(ie_header_t)
			+ cs_req->apn_ambr.header.len
			+ sizeof(ie_header_t)
			+ cs_req->bearer_contexts_to_be_created.header.len
			+ sizeof(ie_header_t)
			+ sizeof(gtpv2c_header_t);

	if (context->mapped_ue_usage_type >= 0)
			cs_req->header.gtpc.message_len +=
				cs_req->mapped_ue_usage_type.header.len
				+ sizeof(ie_header_t);

	return 0;
}

void
fill_pgwc_create_session_response(create_sess_rsp_t *cs_resp,
		uint32_t sequence, struct ue_context_t *context, uint8_t ebi_index)
{

	set_gtpv2c_header(&cs_resp->header, 1, GTP_CREATE_SESSION_RSP,
			context->pdns[ebi_index]->s5s8_sgw_gtpc_teid, sequence);

	set_cause_accepted(&cs_resp->cause, IE_INSTANCE_ZERO);

	set_ipv4_fteid(
			&cs_resp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc,
			GTPV2C_IFTYPE_S5S8_PGW_GTPC, IE_INSTANCE_ONE,
			context->pdns[ebi_index]->s5s8_pgw_gtpc_ipv4,
			context->pdns[ebi_index]->s5s8_pgw_gtpc_teid);

	/* TODO: Added Temp Fix for the UE IP*/
	struct in_addr ipv4 = {0};
	context->pdns[ebi_index]->ipv4.s_addr = htonl(context->pdns[ebi_index]->ipv4.s_addr);
	ipv4.s_addr = context->pdns[ebi_index]->ipv4.s_addr;
	set_ipv4_paa(&cs_resp->paa, IE_INSTANCE_ZERO, ipv4);
			//context->pdns[ebi_index]->ipv4);

	set_apn_restriction(&cs_resp->apn_restriction, IE_INSTANCE_ZERO,
			context->pdns[ebi_index]->apn_restriction);

	set_ebi(&cs_resp->bearer_contexts_created.eps_bearer_id,
			IE_INSTANCE_ZERO,
			context->eps_bearers[ebi_index]->eps_bearer_id);
	set_cause_accepted(&cs_resp->bearer_contexts_created.cause,
			IE_INSTANCE_ZERO);
	set_ie_header(&cs_resp->bearer_contexts_created.bearer_lvl_qos.header,
			GTP_IE_BEARER_QLTY_OF_SVC, IE_INSTANCE_ZERO,
			sizeof(gtp_bearer_qlty_of_svc_ie_t) - sizeof(ie_header_t));
	cs_resp->bearer_contexts_created.bearer_lvl_qos.pvi =
		context->eps_bearers[ebi_index]->qos.arp.preemption_vulnerability;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.spare2 = 0;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.pl =
		context->eps_bearers[ebi_index]->qos.arp.priority_level;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.pci =
		context->eps_bearers[ebi_index]->qos.arp.preemption_capability;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.spare3 = 0;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.qci =
		context->eps_bearers[ebi_index]->qos.qci;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.max_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_mbr;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.max_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_mbr;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.guarntd_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_gbr;
	cs_resp->bearer_contexts_created.bearer_lvl_qos.guarntd_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_gbr;

	context->eps_bearers[ebi_index]->s5s8_pgw_gtpu_ipv4.s_addr =
		        htonl(context->eps_bearers[ebi_index]->s5s8_pgw_gtpu_ipv4.s_addr);
	set_ipv4_fteid(&cs_resp->bearer_contexts_created.s5s8_u_pgw_fteid,
			GTPV2C_IFTYPE_S5S8_PGW_GTPU, IE_INSTANCE_TWO,
			context->eps_bearers[ebi_index]->s5s8_pgw_gtpu_ipv4,
			context->eps_bearers[ebi_index]->s5s8_pgw_gtpu_teid);

	set_ie_header(&cs_resp->bearer_contexts_created.header,
			GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO,
			(cs_resp->bearer_contexts_created.eps_bearer_id.header.len
			 + sizeof(ie_header_t)
			 + cs_resp->bearer_contexts_created.cause.header.len
			 + sizeof(ie_header_t)
			 + cs_resp->bearer_contexts_created.s5s8_u_pgw_fteid.header.len
			 + sizeof(ie_header_t))
			 + cs_resp->bearer_contexts_created.bearer_lvl_qos.header.len
			 + sizeof(ie_header_t));
}

void
fill_ds_request(del_sess_req_t *ds_req, struct ue_context_t *context,
		 uint8_t ebi_index)
{
	int len = 0;
	set_gtpv2c_header(&ds_req->header, 1,
			GTP_DELETE_SESSION_REQ, context->pdns[ebi_index]->s5s8_pgw_gtpc_teid,
			context->sequence);

	set_ie_header(&ds_req->lbi.header, GTP_IE_EPS_BEARER_ID,
			IE_INSTANCE_ZERO, sizeof(uint8_t));

	set_ebi(&ds_req->lbi, IE_INSTANCE_ZERO,
			context->eps_bearers[ebi_index]->eps_bearer_id);

	if (context->uli.lai) {
		ds_req->uli.lai = context->uli.lai;
		ds_req->uli.lai2.lai_mcc_digit_2 = context->uli.lai2.lai_mcc_digit_2;
		ds_req->uli.lai2.lai_mcc_digit_1 = context->uli.lai2.lai_mcc_digit_1;
		ds_req->uli.lai2.lai_mnc_digit_3 = context->uli.lai2.lai_mnc_digit_3;
		ds_req->uli.lai2.lai_mcc_digit_3 = context->uli.lai2.lai_mcc_digit_3;
		ds_req->uli.lai2.lai_mnc_digit_2 = context->uli.lai2.lai_mnc_digit_2;
		ds_req->uli.lai2.lai_mnc_digit_1 = context->uli.lai2.lai_mnc_digit_1;
		ds_req->uli.lai2.lai_lac = context->uli.lai2.lai_lac;
		len += sizeof(ds_req->uli.lai2);
	}
	if (context->uli.tai) {
		ds_req->uli.tai = context->uli.tai;
		ds_req->uli.tai2.tai_mcc_digit_2 = context->uli.tai2.tai_mcc_digit_2;
		ds_req->uli.tai2.tai_mcc_digit_1 = context->uli.tai2.tai_mcc_digit_1;
		ds_req->uli.tai2.tai_mnc_digit_3 = context->uli.tai2.tai_mnc_digit_3;
		ds_req->uli.tai2.tai_mcc_digit_3 = context->uli.tai2.tai_mcc_digit_3;
		ds_req->uli.tai2.tai_mnc_digit_2 = context->uli.tai2.tai_mnc_digit_2;
		ds_req->uli.tai2.tai_mnc_digit_1 = context->uli.tai2.tai_mnc_digit_1;
		ds_req->uli.tai2.tai_tac = context->uli.tai2.tai_tac;
		len += sizeof(ds_req->uli.tai2);
	}
	if (context->uli.rai) {
		ds_req->uli.rai = context->uli.rai;
		ds_req->uli.rai2.ria_mcc_digit_2 = context->uli.rai2.ria_mcc_digit_2;
		ds_req->uli.rai2.ria_mcc_digit_1 = context->uli.rai2.ria_mcc_digit_1;
		ds_req->uli.rai2.ria_mnc_digit_3 = context->uli.rai2.ria_mnc_digit_3;
		ds_req->uli.rai2.ria_mcc_digit_3 = context->uli.rai2.ria_mcc_digit_3;
		ds_req->uli.rai2.ria_mnc_digit_2 = context->uli.rai2.ria_mnc_digit_2;
		ds_req->uli.rai2.ria_mnc_digit_1 = context->uli.rai2.ria_mnc_digit_1;
		ds_req->uli.rai2.ria_lac = context->uli.rai2.ria_lac;
		ds_req->uli.rai2.ria_rac = context->uli.rai2.ria_rac;
		len += sizeof(ds_req->uli.rai2);
	}
	if (context->uli.sai) {
		ds_req->uli.sai = context->uli.sai;
		ds_req->uli.sai2.sai_mcc_digit_2 = context->uli.sai2.sai_mcc_digit_2;
		ds_req->uli.sai2.sai_mcc_digit_1 = context->uli.sai2.sai_mcc_digit_1;
		ds_req->uli.sai2.sai_mnc_digit_3 = context->uli.sai2.sai_mnc_digit_3;
		ds_req->uli.sai2.sai_mcc_digit_3 = context->uli.sai2.sai_mcc_digit_3;
		ds_req->uli.sai2.sai_mnc_digit_2 = context->uli.sai2.sai_mnc_digit_2;
		ds_req->uli.sai2.sai_mnc_digit_1 = context->uli.sai2.sai_mnc_digit_1;
		ds_req->uli.sai2.sai_lac = context->uli.sai2.sai_lac;
		ds_req->uli.sai2.sai_sac = context->uli.sai2.sai_sac;
		len += sizeof(ds_req->uli.sai2);
	}
	if (context->uli.cgi) {
		ds_req->uli.cgi = context->uli.cgi;
		ds_req->uli.cgi2.cgi_mcc_digit_2 = context->uli.cgi2.cgi_mcc_digit_2;
		ds_req->uli.cgi2.cgi_mcc_digit_1 = context->uli.cgi2.cgi_mcc_digit_1;
		ds_req->uli.cgi2.cgi_mnc_digit_3 = context->uli.cgi2.cgi_mnc_digit_3;
		ds_req->uli.cgi2.cgi_mcc_digit_3 = context->uli.cgi2.cgi_mcc_digit_3;
		ds_req->uli.cgi2.cgi_mnc_digit_2 = context->uli.cgi2.cgi_mnc_digit_2;
		ds_req->uli.cgi2.cgi_mnc_digit_1 = context->uli.cgi2.cgi_mnc_digit_1;
		ds_req->uli.cgi2.cgi_lac = context->uli.cgi2.cgi_lac;
	    ds_req->uli.cgi2.cgi_ci = context->uli.cgi2.cgi_ci;
		len += sizeof(ds_req->uli.cgi2);
	}
	if (context->uli.ecgi) {
		ds_req->uli.ecgi = context->uli.ecgi;
		ds_req->uli.ecgi2.ecgi_mcc_digit_2 = context->uli.ecgi2.ecgi_mcc_digit_2;
		ds_req->uli.ecgi2.ecgi_mcc_digit_1 = context->uli.ecgi2.ecgi_mcc_digit_1;
		ds_req->uli.ecgi2.ecgi_mnc_digit_3 = context->uli.ecgi2.ecgi_mnc_digit_3;
		ds_req->uli.ecgi2.ecgi_mcc_digit_3 = context->uli.ecgi2.ecgi_mcc_digit_3;
		ds_req->uli.ecgi2.ecgi_mnc_digit_2 = context->uli.ecgi2.ecgi_mnc_digit_2;
		ds_req->uli.ecgi2.ecgi_mnc_digit_1 = context->uli.ecgi2.ecgi_mnc_digit_1;
		ds_req->uli.ecgi2.ecgi_spare = context->uli.ecgi2.ecgi_spare;
	    ds_req->uli.ecgi2.eci = context->uli.ecgi2.eci;
		len += sizeof(ds_req->uli.ecgi2);
	}
	if (context->uli.macro_enodeb_id) {
		ds_req->uli.macro_enodeb_id = context->uli.macro_enodeb_id;
		ds_req->uli.macro_enodeb_id2.menbid_mcc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_2;
		ds_req->uli.macro_enodeb_id2.menbid_mcc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_1;
		ds_req->uli.macro_enodeb_id2.menbid_mnc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_3;
		ds_req->uli.macro_enodeb_id2.menbid_mcc_digit_3 =
			context->uli.macro_enodeb_id2.menbid_mcc_digit_3;
		ds_req->uli.macro_enodeb_id2.menbid_mnc_digit_2 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_2;
		ds_req->uli.macro_enodeb_id2.menbid_mnc_digit_1 =
			context->uli.macro_enodeb_id2.menbid_mnc_digit_1;
		ds_req->uli.macro_enodeb_id2.menbid_spare =
			context->uli.macro_enodeb_id2.menbid_spare;
		ds_req->uli.macro_enodeb_id2.menbid_macro_enodeb_id =
			context->uli.macro_enodeb_id2.menbid_macro_enodeb_id;
		ds_req->uli.macro_enodeb_id2.menbid_macro_enb_id2 =
			context->uli.macro_enodeb_id2.menbid_macro_enb_id2;
		len += sizeof(ds_req->uli.macro_enodeb_id2);
	}
	if (context->uli.extnded_macro_enb_id) {
		ds_req->uli.extnded_macro_enb_id = context->uli.extnded_macro_enb_id;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
			context->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
			context->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_smenb =
			context->uli.extended_macro_enodeb_id2.emenbid_smenb;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_spare =
			context->uli.extended_macro_enodeb_id2.emenbid_spare;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
		ds_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
			context->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
		len += sizeof(ds_req->uli.extended_macro_enodeb_id2);
	}
	len += 1;
	set_ie_header(&ds_req->uli.header, GTP_IE_USER_LOC_INFO, IE_INSTANCE_ZERO,
		len);
}

int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp)
{
	int ret = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	eps_bearer *bearer = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};


#ifdef USE_REST
	/*CLI logic : add PGWC entry when CSResponse received*/
	if ((add_node_conn_entry(ntohl(cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address),
			S5S8_SGWC_PORT_ID)) != 0) {
		clLog(clSystemLog, eCLSeverityDebug, "Fail to add connection entry for PGWC");
	}
#endif

	uint8_t ebi_index = cs_rsp->bearer_contexts_created.eps_bearer_id.ebi_ebi - 5;

	/*ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &cs_rsp->header.teid.has_teid.teid,
			(void **) &context);*/
	ret = get_ue_context_by_sgw_s5s8_teid(cs_rsp->header.teid.has_teid.teid,
						&context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	pdn = context->eps_bearers[ebi_index]->pdn;
	{
		struct in_addr ip = {0};
		pdn->apn_restriction = cs_rsp->apn_restriction.rstrct_type_val;

		ip = *(struct in_addr *)cs_rsp->paa.pdn_addr_and_pfx;

		pdn->ipv4.s_addr = htonl(ip.s_addr);
		pdn->s5s8_pgw_gtpc_ipv4.s_addr =
			cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address;
		pdn->s5s8_pgw_gtpc_teid =
			cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.teid_gre_key;
	}

	bearer = context->eps_bearers[ebi_index];
	{
		/* TODO: Implement TFTs on default bearers
		 *          if (create_s5s8_session_response.bearer_tft_ie) {
		 *                     }
		 *                            */
		/* TODO: Implement PGWC S5S8 bearer QoS */
		if (cs_rsp->bearer_contexts_created.bearer_lvl_qos.header.len) {
			bearer->qos.qci = cs_rsp->bearer_contexts_created.bearer_lvl_qos.qci;
			bearer->qos.ul_mbr =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.max_bit_rate_uplnk;
			bearer->qos.dl_mbr =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.max_bit_rate_dnlnk;
			bearer->qos.ul_gbr =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.guarntd_bit_rate_uplnk;
			bearer->qos.dl_gbr =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.guarntd_bit_rate_dnlnk;
			bearer->qos.arp.preemption_vulnerability =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.pvi;
			bearer->qos.arp.spare1 =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.spare2;
			bearer->qos.arp.priority_level =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.pl;
			bearer->qos.arp.preemption_capability =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.pci;
			bearer->qos.arp.spare2 =
				cs_rsp->bearer_contexts_created.bearer_lvl_qos.spare3;
		}

		bearer->s5s8_pgw_gtpu_ipv4.s_addr =
			cs_rsp->bearer_contexts_created.s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid =
			cs_rsp->bearer_contexts_created.s5s8_u_pgw_fteid.teid_gre_key;
		bearer->pdn = pdn;
	}

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req.update_far_count = 0;
	pfcp_sess_mod_req.update_far_count++;
	for(int itr=0 ; itr < pfcp_sess_mod_req.update_far_count; itr++){
		update_far[itr].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_pgw_gtpu_teid;
		update_far[itr].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_pgw_gtpu_ipv4.s_addr;
		update_far[itr].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(cs_rsp->bearer_contexts_created.s5s8_u_pgw_fteid.interface_type);
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, NULL,
			bearer, pdn, update_far, 0);

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	/* PGW FQ-CSID */
	if (cs_rsp->pgw_fqcsid.header.len) {
		/* Stored the PGW CSID by PGW Node address */
		//tmp = get_peer_addr_csids_entry(ntohl(cs_rsp->pgw_fqcsid.node_address),
		tmp = get_peer_addr_csids_entry(cs_rsp->pgw_fqcsid.node_address,
				ADD);

		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = ntohl(cs_rsp->pgw_fqcsid.node_address);

		for(uint8_t itr = 0; itr < cs_rsp->pgw_fqcsid.number_of_csids; itr++) {
			uint8_t match = 0;
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] == cs_rsp->pgw_fqcsid.pdn_csid[itr])
					match = 1;
			}

			if (!match) {
				tmp->local_csid[tmp->num_csid++] =
					cs_rsp->pgw_fqcsid.pdn_csid[itr];
			}
		}
		memcpy(context->pgw_fqcsid, tmp, sizeof(fqcsid_t));
	} else {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		memcpy(context->pgw_fqcsid, tmp, sizeof(fqcsid_t));
	}

	/* Link local CSID with PGW CSID */
	if ((context->pgw_fqcsid)->num_csid) {
		csid_t *tmp1 = NULL;
		tmp1 = get_peer_csid_entry(
				&(context->pgw_fqcsid)->local_csid[(context->pgw_fqcsid)->num_csid - 1],
				S5S8_SGWC_PORT_ID);
		if (tmp1 == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		/* Link local csid with MME CSID */
		if (tmp1->local_csid == 0) {
			tmp1->local_csid = (context->sgw_fqcsid)->local_csid[(context->sgw_fqcsid)->num_csid - 1];
		} else if (tmp1->local_csid != local_csid){
			/* TODO: handle condition like single MME CSID link with multiple local CSID  */
		}

		/* Update the Node Addr */
		tmp1->node_addr = (context->sgw_fqcsid)->node_addr;
	}

	/* Set PGW FQ-CSID */
	if ((context->pgw_fqcsid)->num_csid) {
		set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, context->pgw_fqcsid);
	}

#endif /* USE_CSID */

	if(pfcp_sess_mod_req.create_pdr_count){
		for(int itr = 0; itr < pfcp_sess_mod_req.create_pdr_count; itr++) {
			pfcp_sess_mod_req.create_pdr[itr].pdi.ue_ip_address.ipv4_address =
				(pdn->ipv4.s_addr);
			pfcp_sess_mod_req.create_pdr[itr].pdi.src_intfc.interface_value =
				SOURCE_INTERFACE_VALUE_ACCESS;
		}
	}

	uint8_t pfcp_msg[512] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *)pfcp_msg;
	header->message_len = htons(encoded - 4);


	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0)
		clLog(clSystemLog, eCLSeverityCritical, "Error in sending MBR to SGW-U. err_no: %i\n", errno);
	else
	{
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Lookup Stored the session information. */
	if (get_sess_entry(context->pdns[ebi_index]->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Failed to add response in entry in SM_HASH\n", __file__
				,__func__, __LINE__);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set create session response */
	//resp->sequence = cs_rsp->header.teid.has_teid.seq;
	resp->eps_bearer_id = cs_rsp->bearer_contexts_created.eps_bearer_id.ebi_ebi;
	//resp->s11_sgw_gtpc_teid = context->s11_sgw_gtpc_teid;
	//resp->context = context;
	resp->msg_type = GTP_CREATE_SESSION_RSP;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

int
process_sgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp)
{
	int ret;
	uint8_t ebi_index;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context(cb_rsp->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi - 5;

	bearer = context->eps_bearers[ebi_index];
	bearer->eps_bearer_id = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi;
	if(bearer == NULL)
	{
		/* TODO:
		 * This mean ebi we allocated and received doesnt match
		 * In correct design match the bearer in transtient struct from sgw-u teid
		 * */
		return -1;
	}

	bearer->s1u_enb_gtpu_ipv4.s_addr = cb_rsp->bearer_contexts.s1u_enb_fteid.ipv4_address;
	bearer->s1u_enb_gtpu_teid = cb_rsp->bearer_contexts.s1u_enb_fteid.teid_gre_key;
	bearer->s1u_sgw_gtpu_ipv4.s_addr = cb_rsp->bearer_contexts.s1u_sgw_fteid.ipv4_address;
	bearer->s1u_sgw_gtpu_teid = cb_rsp->bearer_contexts.s1u_sgw_fteid.teid_gre_key;

	/* Update the next hop IP address */
	s11_mme_sockaddr.sin_addr.s_addr = ntohl(context->s11_mme_gtpc_ipv4.s_addr);

	uint32_t  seq_no = 0;
	seq_no = bswap_32(cb_rsp->header.teid.has_teid.seq) ;
	seq_no = seq_no >> 8;

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];

	pfcp_sess_mod_req.create_pdr_count = 0;
	pfcp_sess_mod_req.update_far_count = 0;

	if (cb_rsp->bearer_contexts.s1u_enb_fteid.header.len  != 0) {
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s1u_enb_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s1u_enb_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(cb_rsp->bearer_contexts.s1u_enb_fteid.interface_type);
		update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		pfcp_sess_mod_req.update_far_count++;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cb_rsp->header, bearer, bearer->pdn, update_far, 0);

	uint8_t pfcp_msg[512]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);


	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0)
		clLog(clSystemLog, eCLSeverityCritical, "Error in sending MBR to SGW-U. err_no: %i\n", errno);
	else
	{

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(cb_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	bearer->pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	if (get_sess_entry(bearer->pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Failed to add response in entry in SM_HASH\n");
		return -1;
	}

	resp->eps_bearer_id = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_CREATE_BEARER_RSP;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

/**
 * @brief  : Delete pgwc context
 * @param  : ds_req, hold information from delete session request
 * @param  : context, ue context data
 * @param  : resp, response structure to be filled
 * @return : Returns 0 in case of success , different error codes otherwise
 */
static int
delete_pgwc_context(del_sess_req_t *ds_req, ue_context **_context,
		struct gw_info *resp)
{
	int ret = 0, i = 0;
	uint8_t ebi = 0;
	ue_context *context = NULL;
	static uint32_t process_pgwc_s5s8_ds_req_cnt;

	/*gtpv2c_rx->teid_u.has_teid.teid = ntohl(gtpv2c_rx->teid_u.has_teid.teid);*/
	/* s11_sgw_gtpc_teid = s5s8_pgw_gtpc_base_teid =
	 * 	 * key->ue_context_by_fteid_hash */
	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &ds_req->header.teid.has_teid.teid,
			(void **) &context);
	if (ret < 0 || !context) {

		clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
				"\n\tprocess_pgwc_s5s8_delete_session_request:"
				"\n\tdelete_pgwc_context-ERROR!!!"
				"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
				"\n\tgtpv2c_s5s8_rx->teid_u.has_teid.teid= %X;"
				"\n\trte_hash_lookup_data("
				"ue_context_by_fteid_hash,..)= %d\n",
				process_pgwc_s5s8_ds_req_cnt++,
				ds_req->header.teid.has_teid.teid,
				ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/** TODO: we should verify mandatory fields within received message */
	if(ds_req->lbi.header.type == GTP_IE_EPS_BEARER_ID){
		if(ds_req->lbi.header.instance == IE_INSTANCE_ZERO){
			ebi = ds_req->lbi.ebi_ebi;
		}
	}

	if(ds_req->uli.header.type == GTP_IE_USER_LOC_INFO){
		if(ds_req->uli.header.instance == IE_INSTANCE_ZERO){
			/**/
		}
	}

	if(!ebi) {
		/* TODO: should be responding with response indicating error
		 * 		 * in request */
		clLog(clSystemLog, eCLSeverityCritical, "Received delete session without ebi! - "
				"dropping\n");
		return -EPERM;
	}

	resp->eps_bearer_id = ebi ;
	/* VS: Fill the eps bearer id in response */

	uint8_t ebi_index = ebi - 5;
	if (!(context->bearer_bitmap & (1 << ebi_index))) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received delete session on non-existent EBI - "
				"Dropping packet\n");
		/*clLog(clSystemLog, eCLSeverityCritical, "ebi %u\n",
		 * 		    *IE_TYPE_PTR_FROM_GTPV2C_IE(uint8_t, ebi_ei_to_be_removed));*/
		clLog(clSystemLog, eCLSeverityCritical, "ebi %u\n", ebi);
		clLog(clSystemLog, eCLSeverityCritical, "ebi_index %u\n", ebi_index);
		clLog(clSystemLog, eCLSeverityCritical, "bearer_bitmap %04x\n", context->bearer_bitmap);
		clLog(clSystemLog, eCLSeverityCritical, "mask %04x\n", (1 << ebi_index));
		return -EPERM;
	}

	pdn_connection *pdn = context->eps_bearers[ebi_index]->pdn;
	resp->seid = context->pdns[ebi_index]->seid;  //NK:change for seid
	if (!pdn) {
		clLog(clSystemLog, eCLSeverityCritical, "Received delete session on "
				"non-existent EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	if (pdn->default_bearer_id != ebi) {
		clLog(clSystemLog, eCLSeverityCritical,
				"Received delete session referencing incorrect "
				"default bearer ebi");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}
	/* s11_sgw_gtpc_teid= s5s8_sgw_gtpc_teid =
	 * 	 * key->ue_context_by_fteid_hash */
	resp->s5s8_sgw_gtpc_teid = pdn->s5s8_sgw_gtpc_teid;
	resp->s5s8_pgw_gtpc_ipv4 = pdn->s5s8_sgw_gtpc_ipv4.s_addr;

	clLog(s5s8logger, eCLSeverityDebug, "NGIC- delete_s5s8_session.c::"
			"\n\tdelete_pgwc_context(...);"
			"\n\tprocess_pgwc_s5s8_ds_req_cnt= %u;"
			"\n\tue_ip= pdn->ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_sgw_gtpc_teid= %X;"
			"\n\tpdn->s5s8_pgw_gtpc_ipv4= %s;"
			"\n\tpdn->s5s8_pgw_gtpc_teid= %X;"
			"\n\trte_hash_lookup_data("
			"ue_context_by_fteid_hash,..)= %d\n",
			process_pgwc_s5s8_ds_req_cnt++,
			inet_ntoa(pdn->ipv4),
			inet_ntoa(pdn->s5s8_sgw_gtpc_ipv4),
			pdn->s5s8_sgw_gtpc_teid,
			inet_ntoa(pdn->s5s8_pgw_gtpc_ipv4),
			pdn->s5s8_pgw_gtpc_teid,
			ret);

	eps_bearer *bearer = context->eps_bearers[ebi_index];
	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical, "Received delete session on non-existent "
				"default EBI\n");
		return GTPV2C_CAUSE_MANDATORY_IE_INCORRECT;
	}

	for (i = 0; i < MAX_BEARERS; ++i) {
		if (pdn->eps_bearers[i] == NULL)
			continue;

		if (context->eps_bearers[i] == pdn->eps_bearers[i]) {
			bearer = context->eps_bearers[i];
			struct session_info si;
			memset(&si, 0, sizeof(si));

			/**
			  * ebi and s1u_sgw_teid is set here for zmq/sdn
			 */
			si.bearer_id = ebi;
			si.ue_addr.u.ipv4_addr =
				htonl(pdn->ipv4.s_addr);
			si.ul_s1_info.sgw_teid =
				bearer->s1u_sgw_gtpu_teid;
			si.sess_id = SESS_ID(
					context->s11_sgw_gtpc_teid,
					si.bearer_id);
			/* Delete rules those are associated with PDN  */
			/* REVIEW: Remove the hardcoded rules counter, use the dynamic counter to maintain the list*/
			for (uint8_t iCnt = 0; iCnt < 16; ++iCnt) {
				if (NULL != bearer->dynamic_rules[iCnt]) {
					rule_name_key_t key = {0};
					memcpy(&key.rule_name, bearer->dynamic_rules[iCnt]->rule_name,
						255);
					sprintf(key.rule_name, "%s%d", key.rule_name, (bearer->pdn)->call_id);
					if (del_rule_name_entry(key) != 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							FORMAT" Error on delete rule name entries\n",
							ERR_MSG);
					}
				}
			}
			/*
			 * struct dp_id dp_id = { .id = DPN_ID };
			 * session_delete(dp_id, si);
			 * */

			rte_free(pdn->eps_bearers[i]);
			pdn->eps_bearers[i] = NULL;
			context->eps_bearers[i] = NULL;
			context->bearer_bitmap &= ~(1 << i);
		} else {
			rte_panic("Incorrect provisioning of bearers\n");
		}
	}
	--context->num_pdns;
	rte_free(pdn);
	context->pdns[ebi_index] = NULL;
	context->teid_bitmap = 0;

	*_context = context;
	return 0;
}

int
delete_sgwc_context(uint32_t gtpv2c_teid, ue_context **_context, uint64_t *seid)
{
	int i = 0;
	//int ret;
	pdn_connection *pdn_ctxt = NULL;
	int ebi_index = UE_BEAR_ID(*seid) - 5;
	pdn_ctxt = (*_context)->pdns[ebi_index];
	for (i = 0; i < MAX_BEARERS; ++i) {
		if (pdn_ctxt->eps_bearers[i]) {
			eps_bearer *bearer = pdn_ctxt->eps_bearers[i];
			struct session_info si;
			memset(&si, 0, sizeof(si));

			/**
			 * ebi and s1u_sgw_teid is set here for zmq/sdn
			 */
			si.bearer_id = i + 5;
			si.ue_addr.u.ipv4_addr =
				htonl(pdn_ctxt->ipv4.s_addr);
			si.ul_s1_info.sgw_teid =
				bearer->s1u_sgw_gtpu_teid;
			si.sess_id = SESS_ID(
					pdn_ctxt->context->s11_sgw_gtpc_teid,
					si.bearer_id);
			*seid = si.sess_id;

			/* Delete rules those are associated with PDN  */
			/* REVIEW: Remove the hardcoded rules counter, use the dynamic counter to maintain the list*/
			for (uint8_t iCnt = 0; iCnt < 16; ++iCnt) {
				if (NULL != bearer->dynamic_rules[iCnt]) {
					rule_name_key_t key = {0};
					memcpy(&key.rule_name, bearer->dynamic_rules[iCnt]->rule_name,
						255);
					sprintf(key.rule_name, "%s%d", key.rule_name, (bearer->pdn)->call_id);
					if (del_rule_name_entry(key) != 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							FORMAT" Error on delete rule name entries\n",
							ERR_MSG);
					}
				}
			}

			rte_free(pdn_ctxt->eps_bearers[i]);
			pdn_ctxt->eps_bearers[i] = NULL;
			pdn_ctxt->context->eps_bearers[i] = NULL;
			pdn_ctxt->context->pdns[i] = NULL;
			pdn_ctxt->context->bearer_bitmap &= ~(1 << i);
		}
	}

	--pdn_ctxt->context->num_pdns;
	pdn_ctxt->context->teid_bitmap = 0;

	//*_context = pdn_ctxt->context;
	rte_free(pdn_ctxt);
	RTE_SET_USED(gtpv2c_teid);
	return 0;
}

int
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_resp)
{
	int ret = 0;
	ue_context *context = NULL;
	struct eps_bearer_t *bearer = NULL;
	struct resp_info *resp = NULL;
	int ebi_index = 0;

	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	//int ret = delete_sgwc_context(ds_req->header.teid.has_teid.teid, &context, &seid);
	//if (ret)
	//	return ret;

	/* Retrieve the UE context */
	ret = get_ue_context_by_sgw_s5s8_teid(ds_resp->header.teid.has_teid.teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d Failed to get UE State for teid: %u\n",
				__func__, __LINE__,
				ds_resp->header.teid.has_teid.teid);
	}
	ret = get_bearer_by_teid(ds_resp->header.teid.has_teid.teid, &bearer);
	     if(ret < 0) {
	               clLog(clSystemLog, eCLSeverityCritical, "%s:%d Entry not found for teid:%x...\n", __func__, __LINE__, ds_resp->header.teid.has_teid.teid);
	               return -1;
	       }
	ebi_index = UE_BEAR_ID(bearer->pdn->seid) -5;
	//pfcp_sess_del_req.header.seid_seqno.has_seid.seid =
	//	SESS_ID(ds_resp->header.teid.has_teid.teid,ds_resp->lbi.ebi_ebi);

	uint8_t pfcp_msg[512]={0};

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = bearer->pdn->dp_seid;
	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg,encoded,
				&upf_pfcp_sockaddr) < 0 )
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	else {
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_del_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}
	/* Update UE State */
	bearer->pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* VS: Stored/Update the session information. */
	if (get_sess_entry(bearer->pdn->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Failed to get response entry in SM_HASH\n", __file__
				,__func__, __LINE__);
		return -1;
	}

	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	return 0;
}

int
process_pgwc_s5s8_delete_session_request(del_sess_req_t *ds_req)
{
	struct gw_info _resp = {0};
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	int ebi_index = 0;
	int ret = delete_pgwc_context(ds_req, &context, &_resp);

	if (ret)
		return ret;

	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	fill_pfcp_sess_del_req(&pfcp_sess_del_req);

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = _resp.seid;
	ebi_index =  UE_BEAR_ID(pfcp_sess_del_req.header.seid_seqno.has_seid.seid) -5 ;

	uint8_t pfcp_msg[512]={0};

	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg,encoded,
				&upf_pfcp_sockaddr) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,"Error sending: %i\n",errno);
	}else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(ds_req->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded,  _resp.eps_bearer_id - 5);
#endif /* CP_BUILD */
	}

	/* Update UE State */
	pdn = GET_PDN(context , ebi_index);
	pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* VS: Stored/Update the session information. */
	if (get_sess_entry(_resp.seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s %s %d Failed to add response in entry in SM_HASH\n", __file__
				,__func__, __LINE__);
		return -1;
	}

	/* Store s11 struture data into sm_hash for sending delete response back to s11 */
	resp->eps_bearer_id = _resp.eps_bearer_id;
	resp->s5s8_pgw_gtpc_ipv4 = _resp.s5s8_pgw_gtpc_ipv4;
	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	return 0;
}

int
process_sgwc_s5s8_delete_session_response(del_sess_rsp_t *dsr, uint8_t *gtpv2c_tx)
{
	uint16_t msg_len = 0;
	uint64_t seid = 0;
	ue_context *context = NULL;
	del_sess_rsp_t del_resp = {0};

	int ret = delete_sgwc_context(dsr->header.teid.has_teid.teid, &context, &seid);
	if (ret){
		return ret;
	}
	set_gtpv2c_header(&del_resp.header, dsr->header.gtpc.teid_flag, GTP_DELETE_SESSION_RSP,
								 context->s11_mme_gtpc_teid, dsr->header.teid.has_teid.seq);

	set_cause_accepted(&del_resp.cause, IE_INSTANCE_ZERO);

	msg_len = encode_del_sess_rsp(&del_resp, (uint8_t *)gtpv2c_tx);
	gtpv2c_header_t *header = (gtpv2c_header_t *) gtpv2c_tx;
	header->gtpc.message_len = htons(msg_len - 4);

	s11_mme_sockaddr.sin_addr.s_addr =
		htonl(context->s11_mme_gtpc_ipv4.s_addr);

	clLog(clSystemLog, eCLSeverityDebug, "%s: s11_mme_sockaddr.sin_addr.s_addr :%s\n", __func__,
			inet_ntoa(*((struct in_addr *)&s11_mme_sockaddr.sin_addr.s_addr)));

	/* Delete entry from session entry */
	if (del_sess_entry(seid) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "NO Session Entry Found for Key sess ID:%lu\n", seid);
		return -1;
	}

	/* Delete UE context entry from UE Hash */
	if (rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi) < 0){
	clLog(clSystemLog, eCLSeverityCritical,
			"%s %s - Error on ue_context_by_fteid_hash deletion\n",__file__,
			strerror(ret));
	}

	rte_free(context);
	return 0;
}

void
fill_pgwc_ds_sess_rsp(del_sess_rsp_t *ds_resp, uint32_t sequence, uint32_t has_teid)
{
	    set_gtpv2c_header(&ds_resp->header, 1, GTP_DELETE_SESSION_RSP,
				                                 has_teid, sequence);

		    set_cause_accepted(&ds_resp->cause, IE_INSTANCE_ZERO);

}

int
process_pgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp)
{
	uint8_t ret;
	ue_context *context = NULL;
	eps_bearer *bearer = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	struct resp_info *resp = NULL;
	uint8_t ebi_index;

	ret = get_ue_context(cb_rsp->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
					__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ebi_index = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi - 5;

	bearer = context->eps_bearers[ebi_index];
	bearer->eps_bearer_id = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi;
	if (NULL == bearer)
	{
		/* TODO: Invalid ebi index handling */
		return -1;
	}

	bearer->s5s8_sgw_gtpu_ipv4.s_addr = cb_rsp->bearer_contexts.s58_u_sgw_fteid.ipv4_address;
	bearer->s5s8_sgw_gtpu_teid = cb_rsp->bearer_contexts.s58_u_sgw_fteid.teid_gre_key;

	bearer->s5s8_pgw_gtpu_ipv4.s_addr = cb_rsp->bearer_contexts.s58_u_pgw_fteid.ipv4_address;
	bearer->s5s8_pgw_gtpu_teid = cb_rsp->bearer_contexts.s58_u_pgw_fteid.teid_gre_key;

	uint32_t  seq_no = 0;
	seq_no = bswap_32(cb_rsp->header.teid.has_teid.seq) ;
	seq_no = seq_no >> 8;

	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];

	pfcp_sess_mod_req.create_pdr_count = 0;
	pfcp_sess_mod_req.update_far_count = 0;

	if (cb_rsp->bearer_contexts.s58_u_sgw_fteid.header.len != 0) {
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_sgw_gtpu_teid;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(cb_rsp->bearer_contexts.s58_u_sgw_fteid.interface_type);
		update_far[pfcp_sess_mod_req.update_far_count].apply_action.forw = PRESENT;
		pfcp_sess_mod_req.update_far_count++;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cb_rsp->header, bearer, bearer->pdn, update_far, 0);

	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0)
		clLog(clSystemLog, eCLSeverityCritical, "Error in sending MBR to SGW-U. err_no: %i\n", errno);
	else
	{

		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(cb_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	bearer->pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	if (get_sess_entry(context->pdns[0]->seid, &resp) != 0) {
		clLog(clSystemLog, eCLSeverityCritical, "Failed to add response in entry in SM_HASH\n");
		return -1;
	}

	resp->eps_bearer_id = cb_rsp->bearer_contexts.eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_CREATE_BEARER_RSP;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

int
process_update_bearer_request(upd_bearer_req_t *ubr)
{
	int ret = 0;
	upd_bearer_req_t ubr_req = {0};
	uint8_t bearer_id = 0;
	uint8_t ebi_index = 0;
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;
	uint16_t payload_length = 0;

	ue_context *context = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	/* for now taking 0th element bearer id bcz
	 * a request will come from commom PGW for which PDN is same
	 */
	ebi_index = ubr->bearer_contexts[0].eps_bearer_id.ebi_ebi - 5;

	ret = get_ue_context_by_sgw_s5s8_teid(ubr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn_cntxt = context->eps_bearers[ebi_index]->pdn;

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, pdn_cntxt->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_req, GTP_UPDATE_BEARER_REQ,
 							 context->s11_mme_gtpc_teid, ubr->header.teid.has_teid.seq);

	if(ubr->apn_ambr.header.len){
		ubr_req.apn_ambr.apn_ambr_uplnk = ubr->apn_ambr.apn_ambr_uplnk;
		ubr_req.apn_ambr.apn_ambr_dnlnk = ubr->apn_ambr.apn_ambr_dnlnk;
		set_ie_header(&ubr_req.apn_ambr.header, GTP_IE_AGG_MAX_BIT_RATE, IE_INSTANCE_ZERO,
																			sizeof(uint64_t));
	}else{

		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;

	}

	if(!ubr->bearer_context_count)
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;

	if(ubr->indctn_flgs.header.len){
		set_ie_header(&ubr_req.indctn_flgs.header, GTP_IE_INDICATION,
								IE_INSTANCE_ZERO,
    		                    sizeof(gtp_indication_ie_t)- sizeof(ie_header_t));
		ubr_req.indctn_flgs.indication_retloc = 1;
	}

	ubr_req.bearer_context_count = ubr->bearer_context_count;
	for(uint32_t i = 0; i < ubr->bearer_context_count; i++){

		bearer_id = ubr->bearer_contexts[i].eps_bearer_id.ebi_ebi - 5;
		resp->list_bearer_ids[resp->num_of_bearers++] = bearer_id + 5;
		int len = 0;
		set_ie_header(&ubr_req.bearer_contexts[i].header,
									GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);
		//If QoS update is required
		/*if(ubr_req->bearer_contexts[i].bearer_lvl_qos.header.len){
			ubr_req->bearer_contexts[i].bearer_lvl_qos = ubr.bearer_contexts[i].bearer_lvl_qos;
			ubr_req.bearer_contexts[i].header.len += sizeof(gtp_bearer_qlty_of_svc_ie_t);
		}*/

		memset(ubr_req.bearer_contexts[i].tft.eps_bearer_lvl_tft, 0, 257);
		memcpy(ubr_req.bearer_contexts[i].tft.eps_bearer_lvl_tft,
					ubr->bearer_contexts[i].tft.eps_bearer_lvl_tft, 257);

		uint8_t tft_len = ubr->bearer_contexts[i].tft.header.len;
		set_ie_header(&ubr_req.bearer_contexts[i].tft.header,
			GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL, IE_INSTANCE_ZERO, tft_len);
		len = tft_len + IE_HEADER_SIZE;

		ubr_req.bearer_contexts[i].header.len += len;

		set_ebi(&ubr_req.bearer_contexts[i].eps_bearer_id,
					IE_INSTANCE_ZERO, context->eps_bearers[bearer_id]->eps_bearer_id);
		ubr_req.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	}

	pdn_cntxt->proc = UPDATE_BEARER_PROC;
	pdn_cntxt->state = UPDATE_BEARER_REQ_SNT_STATE;

	resp->msg_type = GTP_UPDATE_BEARER_REQ;
	resp->state =  UPDATE_BEARER_REQ_SNT_STATE;
	resp->proc =  UPDATE_BEARER_PROC;
	//Send ub_request to MME
	uint16_t msg_len = 0;
	msg_len = encode_upd_bearer_req(&ubr_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);


	s11_mme_sockaddr.sin_addr.s_addr =
				htonl(context->s11_mme_gtpc_ipv4.s_addr);

	gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);

	return 0;
}

int
process_s5s8_upd_bearer_response(upd_bearer_rsp_t *ub_rsp)
{
	int ret = 0;
	uint8_t ebi_index = 0;
	pdn_connection *pdn_cntxt = NULL;
	ue_context *context = NULL;
	uint32_t seq = 0;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_pdn(ub_rsp->header.teid.has_teid.teid, &pdn_cntxt);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,"%s:Entry not found for teid:%x...\n", __func__,
										ub_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
										__func__, __LINE__, pdn_cntxt->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	ret = get_ue_context(ub_rsp->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	//Start filling sess_mod_req

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header),
							PFCP_SESSION_MODIFICATION_REQUEST, HAS_SEID, seq);

	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn_cntxt->dp_seid;

	//TODO modify this hard code to generic
	char pAddr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
	unsigned long node_value = inet_addr(pAddr);

	set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn_cntxt->seid, node_value);

	for(uint8_t i = 0; i < ub_rsp->bearer_context_count; i++){

		ebi_index = ub_rsp->bearer_contexts[i].eps_bearer_id.ebi_ebi - 5;

		fill_update_pdr(&pfcp_sess_mod_req, context->eps_bearers[ebi_index]);

	}

	uint8_t pfcp_msg[512] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *)pfcp_msg;
	header->message_len = htons(encoded - 4);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0)
		clLog(clSystemLog, eCLSeverityCritical, "Error in sending MBR to SGW-U. err_no: %i\n", errno);
	else
	{
		update_cli_stats((uint32_t)upf_pfcp_sockaddr.sin_addr.s_addr,
				pfcp_sess_mod_req.header.message_type,SENT,SX);
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(ub_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}
	/* Update UE State */
	pdn_cntxt->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update UE Proc */
	pdn_cntxt->proc = UPDATE_BEARER_PROC;

	/* Set GX rar message */
	resp->msg_type = GTP_UPDATE_BEARER_RSP;
	resp->state =  PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->proc =  UPDATE_BEARER_PROC;

	return 0;

}

int
process_s11_upd_bearer_response(upd_bearer_rsp_t *ub_rsp)
{
	int ret = 0;
	uint8_t bearer_id = 0;
	upd_bearer_rsp_t ubr_rsp = {0};
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;
	ue_context *context = NULL;
	uint16_t payload_length = 0;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ret = get_pdn(ub_rsp->header.teid.has_teid.teid, &pdn_cntxt);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,"%s:Entry not found for teid:%x...\n", __func__, ub_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, "%s:%d NO Session Entry Found for sess ID:%lu\n",
				__func__, __LINE__, pdn_cntxt->seid);
		return -1;
	}

	ret = get_ue_context(ub_rsp->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(sxlogger, eCLSeverityCritical, "%s:%d Error: %d \n", __func__,
				__LINE__, ret);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if(ub_rsp->uli.header.len){
		memcpy(&ubr_rsp.uli, &ub_rsp->uli, sizeof(gtp_user_loc_info_ie_t));
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_rsp, GTP_UPDATE_BEARER_RSP,
	    pdn_cntxt->s5s8_pgw_gtpc_teid, ub_rsp->header.teid.has_teid.seq);

	set_cause_accepted(&ubr_rsp.cause, IE_INSTANCE_ZERO);

	ubr_rsp.bearer_context_count = ub_rsp->bearer_context_count;
	for(uint8_t i = 0; i < ub_rsp->bearer_context_count; i++){

		bearer_id = ub_rsp->bearer_contexts[i].eps_bearer_id.ebi_ebi - 5;
		resp->list_bearer_ids[resp->num_of_bearers++] = bearer_id + 5;
		set_ie_header(&ubr_rsp.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT,
			IE_INSTANCE_ZERO, 0);
		/* TODO  Remove hardcoded ebi */
		set_ebi(&ubr_rsp.bearer_contexts[i].eps_bearer_id, IE_INSTANCE_ZERO,
									ub_rsp->bearer_contexts[i].eps_bearer_id.ebi_ebi);
		ubr_rsp.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

		set_cause_accepted(&ubr_rsp.bearer_contexts[i].cause, IE_INSTANCE_ZERO);
		ubr_rsp.bearer_contexts[i].header.len += sizeof(uint16_t) + IE_HEADER_SIZE;

	}

	uint16_t msg_len = 0;
	msg_len = encode_upd_bearer_rsp(&ubr_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);
	//send S5S8 interface update bearer response.
	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
   	      		(struct sockaddr *) &s5s8_recv_sockaddr,
       			s5s8_sockaddr_len);

	/* Update UE State */
	pdn_cntxt->state = CONNECTED_STATE;

	/* Update UE Proc */
	pdn_cntxt->proc = UPDATE_BEARER_PROC;

	/* Set GX rar message */
	resp->msg_type = GTP_UPDATE_BEARER_RSP;
	resp->state = CONNECTED_STATE;
	resp->proc =  UPDATE_BEARER_PROC;
	return 0;
}
void
set_delete_bearer_command(del_bearer_cmd_t *del_bearer_cmd, pdn_connection *pdn, gtpv2c_header_t *gtpv2c_tx)
{
	del_bearer_cmd_t del_cmd = {0};
	ue_context *context = NULL;
	del_cmd.header.gtpc.message_len = 0;
	get_ue_context(del_bearer_cmd->header.teid.has_teid.teid, &context);
	pdn->context->sequence = del_bearer_cmd->header.teid.has_teid.seq;
	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_cmd, GTP_DELETE_BEARER_CMD,
			pdn->s5s8_pgw_gtpc_teid, del_bearer_cmd->header.teid.has_teid.seq);

	/*Below IE are Condition IE's*/

	set_ipv4_fteid(&del_cmd.sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
			IE_INSTANCE_ZERO, pdn->s5s8_sgw_gtpc_ipv4,
			pdn->s5s8_sgw_gtpc_teid);

	del_cmd.header.gtpc.message_len += del_bearer_cmd->sender_fteid_ctl_plane.header.len + sizeof(ie_header_t);

	if(del_bearer_cmd->uli.header.len != 0) {
		/*set uli*/
		memcpy(&del_cmd.uli, &(del_bearer_cmd->uli), sizeof(gtp_user_loc_info_ie_t));
		set_ie_header(&del_cmd.uli.header, GTP_IE_USER_LOC_INFO, IE_INSTANCE_ZERO, del_bearer_cmd->uli.header.len);
		del_cmd.header.gtpc.message_len += del_bearer_cmd->uli.header.len + sizeof(ie_header_t);

	}

	if(del_bearer_cmd->uli_timestamp.header.len != 0) {
		/*set uli timestamp*/
		memcpy(&del_cmd.uli_timestamp, &(del_bearer_cmd->uli_timestamp), sizeof(gtp_uli_timestamp_ie_t));
		set_ie_header(&del_cmd.uli_timestamp.header, GTP_IE_ULI_TIMESTAMP, IE_INSTANCE_ZERO,
				del_bearer_cmd->uli_timestamp.header.len);
		del_cmd.header.gtpc.message_len += del_bearer_cmd->uli_timestamp.header.len + sizeof(ie_header_t);
	}

	if(del_bearer_cmd->ue_time_zone.header.len != 0) {

		memcpy(&del_cmd.ue_time_zone, &(del_bearer_cmd->ue_time_zone), sizeof(gtp_ue_time_zone_ie_t));
		set_ie_header(&del_cmd.ue_time_zone.header, GTP_IE_UE_TIME_ZONE, IE_INSTANCE_ZERO, del_bearer_cmd->ue_time_zone.header.len);
		del_cmd.header.gtpc.message_len += del_bearer_cmd->ue_time_zone.header.len + sizeof(ie_header_t);
	}
	if(del_bearer_cmd->mmes4_sgsns_ovrld_ctl_info.header.len != 0) {

		memcpy(&del_cmd.mmes4_sgsns_ovrld_ctl_info, &(del_bearer_cmd->mmes4_sgsns_ovrld_ctl_info), sizeof(gtp_ovrld_ctl_info_ie_t));
		set_ie_header(&del_cmd.mmes4_sgsns_ovrld_ctl_info.header, GTP_IE_OVRLD_CTL_INFO, IE_INSTANCE_ZERO,
				del_bearer_cmd->mmes4_sgsns_ovrld_ctl_info.header.len);
		del_cmd.header.gtpc.message_len += del_bearer_cmd->mmes4_sgsns_ovrld_ctl_info.header.len + sizeof(ie_header_t);
	}

	if(del_bearer_cmd->sgws_ovrld_ctl_info.header.len != 0) {

		memcpy(&del_cmd.sgws_ovrld_ctl_info, &(del_bearer_cmd->sgws_ovrld_ctl_info), sizeof(gtp_ovrld_ctl_info_ie_t));
		set_ie_header(&del_cmd.sgws_ovrld_ctl_info.header, GTP_IE_OVRLD_CTL_INFO, IE_INSTANCE_ZERO,
				del_bearer_cmd->sgws_ovrld_ctl_info.header.len);
		del_cmd.header.gtpc.message_len += del_bearer_cmd->sgws_ovrld_ctl_info.header.len + sizeof(ie_header_t);
	}

	if(del_bearer_cmd->secdry_rat_usage_data_rpt.header.len != 0) {

		memcpy(&del_cmd.secdry_rat_usage_data_rpt, &(del_bearer_cmd->secdry_rat_usage_data_rpt), sizeof(gtp_secdry_rat_usage_data_rpt_ie_t));
		set_ie_header(&del_cmd.secdry_rat_usage_data_rpt.header, GTP_IE_SECDRY_RAT_USAGE_DATA_RPT, IE_INSTANCE_ZERO,
				del_bearer_cmd->secdry_rat_usage_data_rpt.header.len);

		del_cmd.header.gtpc.message_len += del_bearer_cmd->secdry_rat_usage_data_rpt.header.len + sizeof(ie_header_t);
	}

	del_cmd.bearer_count = del_bearer_cmd->bearer_count;

	for(uint8_t i= 0; i< del_bearer_cmd->bearer_count; i++) {

		set_ie_header(&del_cmd.bearer_contexts[i].header, GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO,
				0);

		set_ebi(&del_cmd.bearer_contexts[i].eps_bearer_id,
					IE_INSTANCE_ZERO,del_bearer_cmd->bearer_contexts[i].eps_bearer_id.ebi_ebi);

		del_cmd.bearer_contexts[i].header.len +=
	          sizeof(uint8_t) + IE_HEADER_SIZE;

		del_cmd.header.gtpc.message_len += del_bearer_cmd->bearer_contexts[i].header.len
					+ sizeof(ie_header_t);
	}


	uint16_t msg_len = 0;
	msg_len = encode_del_bearer_cmd(&del_cmd, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - 4);

}

