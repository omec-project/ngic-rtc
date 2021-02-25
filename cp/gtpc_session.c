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
#include "gtp_messages.h"


extern int pfcp_fd;
extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;
extern struct rte_hash *bearer_by_fteid_hash;
extern int gx_app_sock;

int
fill_cs_request(create_sess_req_t *cs_req, struct ue_context_t *context,
		int ebi_index )
{
	int len = 0 ;
	set_gtpv2c_header(&cs_req->header, 1, GTP_CREATE_SESSION_REQ,
			0, context->sequence, 0);

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

	if( context->ue_time_zone_flag == TRUE) {
		cs_req->ue_time_zone.time_zone = context->tz.tz;
		cs_req->ue_time_zone.daylt_svng_time = context->tz.dst;
		cs_req->ue_time_zone.spare2 = 0;

		set_ie_header(&cs_req->ue_time_zone.header, GTP_IE_UE_TIME_ZONE, IE_INSTANCE_ZERO,
		sizeof(gtp_ue_time_zone_ie_t) - sizeof(ie_header_t));
		cs_req->header.gtpc.message_len = cs_req->ue_time_zone.header.len + sizeof(ie_header_t);
	}

	if(context->indication_flag.crsi == 1){
		set_ie_header(&cs_req->indctn_flgs.header, GTP_IE_INDICATION, IE_INSTANCE_ZERO,
				sizeof(gtp_indication_ie_t) - sizeof(ie_header_t));
		cs_req->indctn_flgs.indication_crsi = 1;
		cs_req->header.gtpc.message_len += cs_req->indctn_flgs.header.len + sizeof(ie_header_t);
	}

	if(context->up_selection_flag == 1){
		set_ie_header(&cs_req->up_func_sel_indctn_flgs.header, GTP_IE_UP_FUNC_SEL_INDCTN_FLGS, IE_INSTANCE_ZERO,
				sizeof(gtp_up_func_sel_indctn_flgs_ie_t) - sizeof(ie_header_t));
		cs_req->up_func_sel_indctn_flgs.dcnr = context->dcnr_flag;
		cs_req->header.gtpc.message_len += cs_req->up_func_sel_indctn_flgs.header.len + sizeof(ie_header_t);

		cs_req->header.gtpc.message_len += cs_req->ue_time_zone.header.len + sizeof(ie_header_t);
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

	cs_req->paa.pdn_addr_and_pfx = context->pdns[ebi_index]->ipv4.s_addr;

	cs_req->max_apn_rstrct.rstrct_type_val = context->pdns[ebi_index]->apn_restriction;
	set_ie_header(&cs_req->max_apn_rstrct.header, GTP_IE_APN_RESTRICTION, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	cs_req->apn_ambr.apn_ambr_uplnk = context->pdns[ebi_index]->apn_ambr.ambr_uplink;
	cs_req->apn_ambr.apn_ambr_dnlnk = context->pdns[ebi_index]->apn_ambr.ambr_downlink;
	set_ie_header(&cs_req->apn_ambr.header, GTP_IE_AGG_MAX_BIT_RATE, IE_INSTANCE_ZERO,
			sizeof(uint64_t));

	cs_req->bearer_count = context->bearer_count;

	for (uint8_t uiCnt = 0; uiCnt < context->bearer_count; ++uiCnt) {

	set_ebi(&cs_req->bearer_contexts_to_be_created[uiCnt].eps_bearer_id, IE_INSTANCE_ZERO,
				context->eps_bearers[ebi_index]->eps_bearer_id);
	set_ie_header(&cs_req->bearer_contexts_to_be_created[uiCnt].eps_bearer_id.header,
			GTP_IE_EPS_BEARER_ID, IE_INSTANCE_ZERO,
			sizeof(uint8_t));

	set_ie_header(&cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.header,
			GTP_IE_BEARER_QLTY_OF_SVC, IE_INSTANCE_ZERO, sizeof(gtp_bearer_qlty_of_svc_ie_t) - sizeof(ie_header_t));
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.pvi =
			context->eps_bearers[ebi_index]->qos.arp.preemption_vulnerability;

	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.spare2 = 0;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.pl =
		context->eps_bearers[ebi_index]->qos.arp.priority_level;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.pci =
		context->eps_bearers[ebi_index]->qos.arp.preemption_capability;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.spare3 = 0;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.qci =
		context->eps_bearers[ebi_index]->qos.qci;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.max_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_mbr;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.max_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_mbr;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.guarntd_bit_rate_uplnk =
		context->eps_bearers[ebi_index]->qos.ul_gbr;
	cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.guarntd_bit_rate_dnlnk =
		context->eps_bearers[ebi_index]->qos.dl_gbr;

	set_ipv4_fteid(&cs_req->bearer_contexts_to_be_created[uiCnt].s5s8_u_sgw_fteid,
			GTPV2C_IFTYPE_S5S8_SGW_GTPU,
			IE_INSTANCE_TWO, context->eps_bearers[ebi_index]->s5s8_sgw_gtpu_ipv4,
			context->eps_bearers[ebi_index]->s5s8_sgw_gtpu_teid);
	cs_req->bearer_contexts_to_be_created[uiCnt].s5s8_u_sgw_fteid.ipv4_address =
		cs_req->bearer_contexts_to_be_created[uiCnt].s5s8_u_sgw_fteid.ipv4_address;
	set_ie_header(&cs_req->bearer_contexts_to_be_created[uiCnt].header,
			GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO,
		cs_req->bearer_contexts_to_be_created[uiCnt].eps_bearer_id.header.len
		+ sizeof(ie_header_t)
		+ cs_req->bearer_contexts_to_be_created[uiCnt].bearer_lvl_qos.header.len
		+ sizeof(ie_header_t)
		+ cs_req->bearer_contexts_to_be_created[uiCnt].s5s8_u_sgw_fteid.header.len
		+ sizeof(ie_header_t));
}
	/*fill fqdn string */
	set_ie_header(&cs_req->sgw_u_node_name.header, GTP_IE_FULLY_QUAL_DOMAIN_NAME, IE_INSTANCE_ZERO,
			    strnlen((char *)context->pdns[ebi_index]->fqdn,FQDN_LEN));
	strncpy((char *)&cs_req->sgw_u_node_name.fqdn, (char *)context->pdns[ebi_index]->fqdn, strnlen((char *)context->pdns[ebi_index]->fqdn,FQDN_LEN));

	if (context->pdns[ebi_index]->mapped_ue_usage_type >= 0)
		set_mapped_ue_usage_type(&cs_req->mapped_ue_usage_type, context->pdns[ebi_index]->mapped_ue_usage_type);

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
			+ sizeof(gtpv2c_header_t);

	if (context->pdns[ebi_index]->mapped_ue_usage_type >= 0)
			cs_req->header.gtpc.message_len +=
				cs_req->mapped_ue_usage_type.header.len
				+ sizeof(ie_header_t);

	return 0;
}

void
fill_ds_request(del_sess_req_t *ds_req, struct ue_context_t  *context,
		 int ebi_index , uint32_t teid)
{
	int len = 0;
	set_gtpv2c_header(&ds_req->header, 1,
			GTP_DELETE_SESSION_REQ, teid,
			context->sequence , 0);

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
	eps_bearer *bearers[MAX_BEARERS],*bearer = NULL;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE] = {0};
	uint8_t index = 0;
	int ebi_index = 0;

	/*extract ebi_id from array as all the ebi's will be of same pdn. */
	ebi_index = GET_EBI_INDEX(cs_rsp->bearer_contexts_created[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ret = get_ue_context_by_sgw_s5s8_teid(cs_rsp->header.teid.has_teid.teid,
						&context);
	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to UE context for teid: %d\n",
			LOG_VALUE, cs_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

#ifdef USE_REST
	/*CLI logic : add PGWC entry when CSResponse received*/
	if (cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address != 0) {
		if ((add_node_conn_entry(cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address,
				S5S8_SGWC_PORT_ID, context->cp_mode)) != 0) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Fail to add "
				"connection entry for PGWC\n", LOG_VALUE);
		}
	}
#endif

	pdn = GET_PDN(context, ebi_index);
	if (pdn == NULL) {

		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
			" for ebi_index: %d\n",
			LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	} else {

		struct in_addr ip = {0};

		pdn->apn_restriction = cs_rsp->apn_restriction.rstrct_type_val;
		ip.s_addr = cs_rsp->paa.pdn_addr_and_pfx;
		pdn->ipv4.s_addr = ip.s_addr;

		pdn->s5s8_pgw_gtpc_ipv4.s_addr =
			cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.ipv4_address;

		pdn->s5s8_pgw_gtpc_teid =
			cs_rsp->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.teid_gre_key;
	}

	pfcp_sess_mod_req.update_far_count = 0;

	for(uint8_t i= 0; i< MAX_BEARERS; i++) {

		bearer = pdn->eps_bearers[i];
		if(bearer == NULL)
			continue;
		/* TODO: Implement TFTs on default bearers
		 *          if (create_s5s8_session_response.bearer_tft_ie) {
		 *                     }
		 *                            */
		/* TODO: Implement PGWC S5S8 bearer QoS */
		if (cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.header.len) {
			bearer->qos.qci = cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.qci;
			bearer->qos.ul_mbr =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_uplnk;
			bearer->qos.dl_mbr =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.max_bit_rate_dnlnk;
			bearer->qos.ul_gbr =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_uplnk;
			bearer->qos.dl_gbr =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.guarntd_bit_rate_dnlnk;
			bearer->qos.arp.preemption_vulnerability =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.pvi;
			bearer->qos.arp.spare1 =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.spare2;
			bearer->qos.arp.priority_level =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.pl;
			bearer->qos.arp.preemption_capability =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.pci;
			bearer->qos.arp.spare2 =
				cs_rsp->bearer_contexts_created[index].bearer_lvl_qos.spare3;
		}

		bearer->s5s8_pgw_gtpu_ipv4.s_addr =
			cs_rsp->bearer_contexts_created[index].s5s8_u_pgw_fteid.ipv4_address;
		bearer->s5s8_pgw_gtpu_teid =
			cs_rsp->bearer_contexts_created[index].s5s8_u_pgw_fteid.teid_gre_key;
		bearer->pdn = pdn;

		update_far[index].upd_frwdng_parms.outer_hdr_creation.teid =
			bearer->s5s8_pgw_gtpu_teid;
		update_far[index].upd_frwdng_parms.outer_hdr_creation.ipv4_address =
			bearer->s5s8_pgw_gtpu_ipv4.s_addr;
		update_far[index].upd_frwdng_parms.dst_intfc.interface_value =
			check_interface_type(cs_rsp->bearer_contexts_created[index].s5s8_u_pgw_fteid.interface_type,
					context->cp_mode);
		update_far[index].far_id.far_id_value =
			get_far_id(bearer, update_far[index].upd_frwdng_parms.dst_intfc.interface_value);

		pfcp_sess_mod_req.update_far_count++;

		bearers[index] = bearer;
		index++;
	}

	context->change_report = FALSE;
	if(cs_rsp->chg_rptng_act.header.len != 0) {
		context->change_report = TRUE;
		context->change_report_action = cs_rsp->chg_rptng_act.action;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, NULL,
			bearers, pdn, update_far, 0, index, context);

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	/* PGW FQ-CSID */
	if (cs_rsp->pgw_fqcsid.header.len) {
		/* Remove Exsiting PGW CSID linked with session */
		if ((context->pgw_fqcsid)->num_csid) {
			memset(context->pgw_fqcsid, 0, sizeof(fqcsid_t));
		}
		/* Stored the PGW CSID by PGW Node address */
		ret = add_fqcsid_entry(&cs_rsp->pgw_fqcsid, context->pgw_fqcsid);
		if(ret)
			return ret;

	} else {
		tmp = get_peer_addr_csids_entry(pdn->s5s8_pgw_gtpc_ipv4.s_addr,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: Failed to "
				"add PGW CSID by PGW Node addres %s \n", LOG_VALUE,
				strerror(errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		tmp->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		(context->pgw_fqcsid)->node_addr = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}

	/* Link local CSID with PGW CSID */
	if (context->pgw_fqcsid != NULL) {
		if ((context->pgw_fqcsid)->num_csid) {
			if (link_gtpc_peer_csids((pdn->context)->pgw_fqcsid,
						(pdn->context)->sgw_fqcsid, S5S8_SGWC_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with PGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}

			/* Set PGW FQ-CSID */
			set_fq_csid_t(&pfcp_sess_mod_req.pgw_c_fqcsid, context->pgw_fqcsid);
		}
	}

	fqcsid_t tmp_fqcsid = {0};
	/* Set SGWC FQ-CSID explicitlly zero */
	set_fq_csid_t(&pfcp_sess_mod_req.sgw_c_fqcsid, &tmp_fqcsid);

	/* set MME FQ-CSID explicitlly zero */
	set_fq_csid_t(&pfcp_sess_mod_req.mme_fqcsid, &tmp_fqcsid);

#endif /* USE_CSID */

	if(pfcp_sess_mod_req.create_pdr_count){
		for(int itr = 0; itr < pfcp_sess_mod_req.create_pdr_count; itr++) {
			pfcp_sess_mod_req.create_pdr[itr].pdi.ue_ip_address.ipv4_address =
				(pdn->ipv4.s_addr);
			pfcp_sess_mod_req.create_pdr[itr].pdi.src_intfc.interface_value =
				SOURCE_INTERFACE_VALUE_ACCESS;
		}
	}

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *)pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);


	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Send "
			"PFCP Session Modification to SGW-U",LOG_VALUE);
	else
	{
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	/* Update UE State */
	pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Lookup Stored the session information. */
	if (get_sess_entry(pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id %lu\n", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	/* Set create session response */
	/*extract ebi_id from array as all the ebi's will be of same pdn.*/
	resp->linked_eps_bearer_id = cs_rsp->bearer_contexts_created[0].eps_bearer_id.ebi_ebi;
	resp->msg_type = GTP_CREATE_SESSION_RSP;
	resp->gtpc_msg.cs_rsp = *cs_rsp;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

int
process_create_bearer_response(create_bearer_rsp_t *cb_rsp)
{
	int ret = 0;
	int ebi_index = 0;
	uint8_t idx = 0;
	uint32_t  seq_no = 0;
	eps_bearer *bearers[MAX_BEARERS],*bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ret = get_ue_context(cb_rsp->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE"
			" context for teid: %d\n", LOG_VALUE, cb_rsp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (!cb_rsp->cause.header.len) {
		clLog(clSystemLog,eCLSeverityCritical,LOG_FORMAT"Mandatory IE not found "
			"in Create Bearer Response message\n", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if(!cb_rsp->bearer_cnt) {
		clLog(clSystemLog,eCLSeverityCritical,LOG_FORMAT"No bearer context found "
			" for Create Bearer Response message \n", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	pfcp_sess_mod_req.create_pdr_count = 0;
	pfcp_sess_mod_req.update_far_count = 0;

	for (idx = 0; idx < cb_rsp->bearer_cnt; idx++) {
		if(!cb_rsp->bearer_contexts[idx].eps_bearer_id.ebi_ebi){
			clLog(clSystemLog,eCLSeverityCritical,LOG_FORMAT"No EPS Bearer ID "
			" found in bearer context in Create Bearer Response \n", LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		if(!cb_rsp->bearer_contexts[idx].cause.header.len){
			clLog(clSystemLog,eCLSeverityCritical,LOG_FORMAT"No Cause found in "
			"bearer context in Create Bearer Response\n", LOG_VALUE);
			return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
		}

		ebi_index = GET_EBI_INDEX(cb_rsp->bearer_contexts[idx].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		bearer = context->eps_bearers[(idx + MAX_BEARERS)];
		context->eps_bearers[ebi_index] = bearer;
		bearer->eps_bearer_id =
						cb_rsp->bearer_contexts[idx].eps_bearer_id.ebi_ebi;

		(*context).bearer_bitmap |= (1 << ebi_index);

		context->eps_bearers[(idx + MAX_BEARERS )] = NULL;

		pdn = GET_PDN(context, ebi_index);
		if(pdn == NULL){
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
				" for ebi_index: %d\n",
				LOG_VALUE, ebi_index);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if(get_sess_entry(pdn->seid, &resp)) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id %lu\n", LOG_VALUE, pdn->seid);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if (resp == NULL)
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

		resp->eps_bearer_ids[idx] = cb_rsp->bearer_contexts[idx].eps_bearer_id.ebi_ebi;

		pdn->eps_bearers[ebi_index] = bearer;
		pdn->eps_bearers[(idx + MAX_BEARERS )] = NULL;

		if (bearer == NULL) {
			/* TODO:
			 * This mean ebi we allocated and received doesnt match
			 * In correct design match the bearer in transtient struct from sgw-u teid
			 * */
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Context not found "
				"Create Bearer Response with cause %d \n", LOG_VALUE, ret);
			return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		if( PGWC == context->cp_mode
			|| SAEGWC == context->cp_mode) {

			if(bearer->num_prdef_filters){
				for(int dyn_rule = 0; dyn_rule < bearer->num_prdef_filters; dyn_rule++){

					/* Adding rule and bearer id to a hash */
					bearer_id_t *id = NULL;

					id = malloc(sizeof(bearer_id_t));
					memset(id, 0 , sizeof(bearer_id_t));
					id->bearer_id = ebi_index;
					rule_name_key_t key = {0};
					snprintf(key.rule_name, RULE_NAME_LEN , "%s",
							bearer->prdef_rules[dyn_rule]->rule_name);
					if (add_rule_name_entry(key, id) != 0) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add_rule_name_entry with rule_name\n",
								LOG_VALUE);
						return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
					}
				}
			}else{
				for(int dyn_rule = 0; dyn_rule < bearer->num_dynamic_filters; dyn_rule++){

					/* Adding rule and bearer id to a hash */
					bearer_id_t *id = NULL;

					id = malloc(sizeof(bearer_id_t));
					memset(id, 0 , sizeof(bearer_id_t));
					id->bearer_id = ebi_index;
					rule_name_key_t key = {0};
					snprintf(key.rule_name, RULE_NAME_LEN , "%s%d",
							bearer->dynamic_rules[dyn_rule]->rule_name, pdn->call_id);
					if (add_rule_name_entry(key, id) != 0) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add_rule_name_entry with rule_name\n",
								LOG_VALUE);
						return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
					}
				}
			}
		}

		if ( PGWC == context->cp_mode ) {

			bearer->s5s8_sgw_gtpu_ipv4.s_addr =
				cb_rsp->bearer_contexts[idx].s58_u_sgw_fteid.ipv4_address;
			bearer->s5s8_sgw_gtpu_teid =
				cb_rsp->bearer_contexts[idx].s58_u_sgw_fteid.teid_gre_key;
			bearer->s5s8_pgw_gtpu_ipv4.s_addr =
					cb_rsp->bearer_contexts[idx].s58_u_pgw_fteid.ipv4_address;
			bearer->s5s8_pgw_gtpu_teid =
					cb_rsp->bearer_contexts[idx].s58_u_pgw_fteid.teid_gre_key;

			if (cb_rsp->bearer_contexts[idx].s58_u_sgw_fteid.header.len != 0) {
				update_far[pfcp_sess_mod_req.update_far_count].
				upd_frwdng_parms.outer_hdr_creation.teid =
													bearer->s5s8_sgw_gtpu_teid;
				update_far[pfcp_sess_mod_req.update_far_count].
				upd_frwdng_parms.outer_hdr_creation.ipv4_address =
													bearer->s5s8_sgw_gtpu_ipv4.s_addr;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(cb_rsp->bearer_contexts[idx].s58_u_sgw_fteid.interface_type,
							context->cp_mode);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(bearer, update_far[pfcp_sess_mod_req.
						update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				update_far[pfcp_sess_mod_req.update_far_count].
												apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].
								apply_action.dupl = GET_DUP_STATUS(context);
				pfcp_sess_mod_req.update_far_count++;
			}

		} else {

			bearer->s1u_enb_gtpu_ipv4.s_addr =
					cb_rsp->bearer_contexts[idx].s1u_enb_fteid.ipv4_address;
			bearer->s1u_enb_gtpu_teid =
					cb_rsp->bearer_contexts[idx].s1u_enb_fteid.teid_gre_key;
			bearer->s1u_sgw_gtpu_ipv4.s_addr =
					cb_rsp->bearer_contexts[idx].s1u_sgw_fteid.ipv4_address;
			bearer->s1u_sgw_gtpu_teid =
					cb_rsp->bearer_contexts[idx].s1u_sgw_fteid.teid_gre_key;

			if (cb_rsp->bearer_contexts[idx].s1u_enb_fteid.header.len  != 0) {
				update_far[pfcp_sess_mod_req.update_far_count].
				upd_frwdng_parms.outer_hdr_creation.teid =
													bearer->s1u_enb_gtpu_teid;
				update_far[pfcp_sess_mod_req.update_far_count].
				upd_frwdng_parms.outer_hdr_creation.ipv4_address =
											bearer->s1u_enb_gtpu_ipv4.s_addr;
				update_far[pfcp_sess_mod_req.update_far_count].upd_frwdng_parms.dst_intfc.interface_value =
					check_interface_type(cb_rsp->bearer_contexts[idx].s1u_enb_fteid.interface_type,
							context->cp_mode);
				update_far[pfcp_sess_mod_req.update_far_count].far_id.far_id_value =
					get_far_id(bearer, update_far[pfcp_sess_mod_req.
						update_far_count].upd_frwdng_parms.dst_intfc.interface_value);
				update_far[pfcp_sess_mod_req.update_far_count].
												apply_action.forw = PRESENT;
				update_far[pfcp_sess_mod_req.update_far_count].
								apply_action.dupl = GET_DUP_STATUS(context);
				pfcp_sess_mod_req.update_far_count++;
			}
		}

		bearers[idx] = bearer;
	}

	fill_pfcp_sess_mod_req(&pfcp_sess_mod_req, &cb_rsp->header, bearers,
					bearer->pdn, update_far, 0, cb_rsp->bearer_cnt, context);

	/* Update the next hop IP address */
	s11_mme_sockaddr.sin_addr.s_addr = context->s11_mme_gtpc_ipv4.s_addr;
	seq_no = cb_rsp->header.teid.has_teid.seq;

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req,
											pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure in sending "
			"Session Modification Request. Error No: %i\n", LOG_VALUE, errno);
	} else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(cb_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}

	context->sequence = seq_no;
	bearer->pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->bearer_count = cb_rsp->bearer_cnt;
	resp->msg_type = GTP_CREATE_BEARER_RSP;
	resp->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	return 0;
}

int
process_delete_session_response(del_sess_rsp_t *ds_resp)
{
	int ret = 0;
	ue_context *context = NULL;
	struct eps_bearer_t *bearer = NULL;
	struct resp_info *resp = NULL;
	int ebi_index = 0;

	pfcp_sess_del_req_t pfcp_sess_del_req = {0};

	/* Retrieve the UE context */
	ret = get_ue_context_by_sgw_s5s8_teid(ds_resp->header.teid.has_teid.teid, &context);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get UE "
			"context for teid: %u\n", LOG_VALUE,
			ds_resp->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);
	ret = get_bearer_by_teid(ds_resp->header.teid.has_teid.teid, &bearer);
	if(ret < 0) {
	   clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO Bearer found for "
			"teid : %x...\n", LOG_VALUE,
			ds_resp->header.teid.has_teid.teid);
	   return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}
	int ebi = UE_BEAR_ID(bearer->pdn->seid);
	ebi_index = GET_EBI_INDEX(ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}


	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};

	pfcp_sess_del_req.header.seid_seqno.has_seid.seid = bearer->pdn->dp_seid;
	int encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg,encoded, &upf_pfcp_sockaddr,SENT) < 0 )
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Error sending while "
			"session delete request at sgwc %i\n", LOG_VALUE, errno);
	else {
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(context->s11_sgw_gtpc_teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}
	/* Update UE State */
	bearer->pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	/* Stored/Update the session information. */
	if (get_sess_entry(bearer->pdn->seid, &resp) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE, bearer->pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	resp->msg_type = GTP_DELETE_SESSION_REQ;
	resp->state = PFCP_SESS_DEL_REQ_SNT_STATE;

	return 0;
}

void
fill_del_sess_rsp(del_sess_rsp_t *ds_resp, uint32_t sequence, uint32_t has_teid)
{
	set_gtpv2c_header(&ds_resp->header, 1, GTP_DELETE_SESSION_RSP,
			has_teid, sequence, 0);

	set_cause_accepted(&ds_resp->cause, IE_INSTANCE_ZERO);

}

int
process_update_bearer_request(upd_bearer_req_t *ubr)
{
	int ret = 0;
	upd_bearer_req_t ubr_req = {0};
	uint8_t bearer_id = 0;
	int ebi_index = 0;
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;
	uint16_t payload_length = 0;
	uint16_t msg_len = 0;
	uint8_t cp_mode = 0;

	ue_context *context = NULL;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	/* for now taking 0th element bearer id bcz
	 * a request will come from commom PGW for which PDN is same
	 */
	ebi_index = GET_EBI_INDEX(ubr->bearer_contexts[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ret = get_ue_context_by_sgw_s5s8_teid(ubr->header.teid.has_teid.teid, &context);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get"
		" UE context for teid %d\n", LOG_VALUE, ubr->header.teid.has_teid.teid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	pdn_cntxt = GET_PDN(context, ebi_index);
	if (pdn_cntxt == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No PDN found "
				"found for ebi_index : %lu\n", LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE, pdn_cntxt->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	context->eps_bearers[ebi_index]->sequence = ubr->header.teid.has_teid.seq;

	uint32_t seq_no = 0;
	/*TODO: need to revisit as not properly handle for BRC flow*/
	if(context->proc_trans_id) {
		seq_no = ubr->header.teid.has_teid.seq;
	} else {
		seq_no = generate_seq_no();
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_req, GTP_UPDATE_BEARER_REQ,
							 context->s11_mme_gtpc_teid, seq_no, 0);

	if(ubr->apn_ambr.header.len){
		ubr_req.apn_ambr.apn_ambr_uplnk = ubr->apn_ambr.apn_ambr_uplnk;
		ubr_req.apn_ambr.apn_ambr_dnlnk = ubr->apn_ambr.apn_ambr_dnlnk;
		set_ie_header(&ubr_req.apn_ambr.header, GTP_IE_AGG_MAX_BIT_RATE, IE_INSTANCE_ZERO,
				sizeof(uint64_t));
	}else{

		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;

	}

	/*Fill pti in ubr sent to MME*/
	if (ubr->pti.header.len)
		memcpy(&ubr_req.pti, &ubr->pti, sizeof(ubr->pti));

	/*Reset pti as transaction is completed for BRC flow*/
	if (context->proc_trans_id)
		context->proc_trans_id = 0;

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

		bearer_id = GET_EBI_INDEX(ubr->bearer_contexts[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		resp->eps_bearer_ids[resp->bearer_count++] =  ubr->bearer_contexts[i].eps_bearer_id.ebi_ebi;
		int len = 0;
		set_ie_header(&ubr_req.bearer_contexts[i].header,
									GTP_IE_BEARER_CONTEXT, IE_INSTANCE_ZERO, 0);
		//If QoS update is required
		/*if(ubr_req->bearer_contexts[i].bearer_lvl_qos.header.len){
			ubr_req->bearer_contexts[i].bearer_lvl_qos = ubr.bearer_contexts[i].bearer_lvl_qos;
			ubr_req.bearer_contexts[i].header.len += sizeof(gtp_bearer_qlty_of_svc_ie_t);
		}*/
		if(ubr->bearer_contexts[i].tft.header.len != 0) {

			memset(ubr_req.bearer_contexts[i].tft.eps_bearer_lvl_tft, 0, MAX_TFT_LEN);
			memcpy(ubr_req.bearer_contexts[i].tft.eps_bearer_lvl_tft,
						ubr->bearer_contexts[i].tft.eps_bearer_lvl_tft, MAX_TFT_LEN);

			uint8_t tft_len = ubr->bearer_contexts[i].tft.header.len;
			set_ie_header(&ubr_req.bearer_contexts[i].tft.header,
						GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL, IE_INSTANCE_ZERO, tft_len);
			len = tft_len + IE_HEADER_SIZE;
			ubr_req.bearer_contexts[i].header.len += len;
		}
		if(ubr->bearer_contexts[i].bearer_lvl_qos.header.len != 0) {

			ubr_req.bearer_contexts[i].bearer_lvl_qos = ubr->bearer_contexts[i].bearer_lvl_qos;
			uint8_t qos_len = ubr->bearer_contexts[i].bearer_lvl_qos.header.len;
			set_ie_header(&ubr_req.bearer_contexts[i].bearer_lvl_qos.header,
						GTP_IE_BEARER_QLTY_OF_SVC, IE_INSTANCE_ZERO, qos_len);
			len = qos_len + IE_HEADER_SIZE;
			ubr_req.bearer_contexts[i].header.len += len;
		}
		set_ebi(&ubr_req.bearer_contexts[i].eps_bearer_id,
					IE_INSTANCE_ZERO, context->eps_bearers[bearer_id]->eps_bearer_id);
		ubr_req.bearer_contexts[i].header.len += sizeof(uint8_t) + IE_HEADER_SIZE;

	}

	pdn_cntxt->proc = UPDATE_BEARER_PROC;
	pdn_cntxt->state = UPDATE_BEARER_REQ_SNT_STATE;

	resp->gtpc_msg.ub_req = *ubr;
	resp->msg_type = GTP_UPDATE_BEARER_REQ;
	resp->state =  UPDATE_BEARER_REQ_SNT_STATE;
	resp->proc =  UPDATE_BEARER_PROC;
	resp->cp_mode = context->cp_mode;

	cp_mode = context->cp_mode;

	//Send ub_request to MME
	msg_len = encode_upd_bearer_req(&ubr_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);


	s11_mme_sockaddr.sin_addr.s_addr =
				context->s11_mme_gtpc_ipv4.s_addr;

	gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len,SENT);

	add_gtpv2c_if_timer_entry(
			context->s11_sgw_gtpc_teid,
			&s11_mme_sockaddr, tx_buf, payload_length,
			ebi_index, S11_IFACE, cp_mode);


	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				pdn_cntxt->context, S11_INTFC_OUT, tx_buf, payload_length,
				ntohl(pfcp_config.s11_ip.s_addr), s11_mme_sockaddr.sin_addr.s_addr,
				pfcp_config.s11_port, s11_mme_sockaddr.sin_port);
	}

	return 0;
}

int
process_s5s8_upd_bearer_response(upd_bearer_rsp_t *ub_rsp, ue_context *context )
{
	int ebi_index = 0;
	pdn_connection *pdn_cntxt = NULL;
	uint32_t seq = 0;
	struct resp_info *resp = NULL;
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};

	ebi_index = GET_EBI_INDEX(ub_rsp->bearer_contexts[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn_cntxt = GET_PDN(context, ebi_index);
	if(pdn_cntxt == NULL){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
			" for ebi_index: %d\n",
			LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE, pdn_cntxt->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	//Start filling sess_mod_req

	seq = get_pfcp_sequence_number(PFCP_SESSION_MODIFICATION_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_mod_req.header),
							PFCP_SESSION_MODIFICATION_REQUEST, HAS_SEID, seq,
							context->cp_mode);

	pfcp_sess_mod_req.header.seid_seqno.has_seid.seid = pdn_cntxt->dp_seid;

	set_fseid(&(pfcp_sess_mod_req.cp_fseid), pdn_cntxt->seid,  pfcp_config.pfcp_ip.s_addr);

	for(uint8_t i = 0; i < ub_rsp->bearer_context_count; i++){

		ebi_index = GET_EBI_INDEX(ub_rsp->bearer_contexts[i].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
		fill_update_bearer_sess_mod(&pfcp_sess_mod_req, context->eps_bearers[ebi_index]);
	}

	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	int encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *)pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending "
			"PFCP Session Modification Request to SGW-U, Error : %i\n",
			LOG_VALUE, errno);
	else
	{
#ifdef CP_BUILD
		add_pfcp_if_timer_entry(ub_rsp->header.teid.has_teid.teid,
			&upf_pfcp_sockaddr, pfcp_msg, encoded, ebi_index);
#endif /* CP_BUILD */
	}
	/* Update UE State */
	pdn_cntxt->state = PFCP_SESS_MOD_REQ_SNT_STATE;

	/* Update UE Proc */
	if(pdn_cntxt->proc != UE_REQ_BER_RSRC_MOD_PROC) {
		pdn_cntxt->proc = UPDATE_BEARER_PROC;
		resp->proc =  UPDATE_BEARER_PROC;
	}

	/* Set GX rar message */
	resp->msg_type = GTP_UPDATE_BEARER_RSP;
	resp->state =  PFCP_SESS_MOD_REQ_SNT_STATE;
	resp->gtpc_msg.ub_rsp = *ub_rsp;
	resp->teid = ub_rsp->header.teid.has_teid.teid;

	return 0;

}

int
process_s11_upd_bearer_response(upd_bearer_rsp_t *ub_rsp, ue_context *context)
{
	int ebi_index = 0;
	upd_bearer_rsp_t ubr_rsp = {0};
	struct resp_info *resp = NULL;
	pdn_connection *pdn_cntxt = NULL;
	uint16_t payload_length = 0;
	uint32_t sequence = 0;

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ebi_index = GET_EBI_INDEX(ub_rsp->bearer_contexts[0].eps_bearer_id.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	pdn_cntxt = GET_PDN(context, ebi_index);
	if(pdn_cntxt == NULL){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
			" for ebi_index: %d\n",
			LOG_VALUE, ebi_index);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	if (get_sess_entry(pdn_cntxt->seid, &resp) != 0){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No session entry "
				"found for session id: %lu\n", LOG_VALUE, pdn_cntxt->seid);
		return -1;
	}

	if(ub_rsp->uli.header.len){
		memcpy(&ubr_rsp.uli, &ub_rsp->uli, sizeof(gtp_user_loc_info_ie_t));
	}

	/* Get seuence number from first valid bearer from list */
	ebi_index = -1;
	for(uint32_t itr = 0; itr < ub_rsp->bearer_context_count ; itr++){
		ebi_index = GET_EBI_INDEX(ub_rsp->bearer_contexts[itr].eps_bearer_id.ebi_ebi);
		if (ebi_index != -1) {
			break;
		}
	}
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}else{
		sequence = context->eps_bearers[ebi_index]->sequence;
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &ubr_rsp, GTP_UPDATE_BEARER_RSP,
	    pdn_cntxt->s5s8_pgw_gtpc_teid, sequence, 0);

	set_cause_accepted(&ubr_rsp.cause, IE_INSTANCE_ZERO);

	ubr_rsp.bearer_context_count = ub_rsp->bearer_context_count;
	for(uint8_t i = 0; i < ub_rsp->bearer_context_count; i++){

		resp->eps_bearer_ids[resp->bearer_count++] = ub_rsp->bearer_contexts[i].eps_bearer_id.ebi_ebi;

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
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);
	payload_length = ntohs(gtpv2c_tx->gtpc.message_len) + sizeof(gtpv2c_tx->gtpc);
	//send S5S8 interface update bearer response.
	s5s8_recv_sockaddr.sin_addr.s_addr = pdn_cntxt->s5s8_pgw_gtpc_ipv4.s_addr;
	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
   	      		(struct sockaddr *) &s5s8_recv_sockaddr,
       			s5s8_sockaddr_len,SENT);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				ntohl(pfcp_config.s5s8_ip.s_addr), ntohl(s5s8_recv_sockaddr.sin_addr.s_addr),
				pfcp_config.s5s8_port, ntohs(s5s8_recv_sockaddr.sin_port));
	}

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
	del_cmd.header.gtpc.message_len = 0;

	pdn->context->sequence = del_bearer_cmd->header.teid.has_teid.seq;

	set_gtpv2c_teid_header((gtpv2c_header_t *) &del_cmd, GTP_DELETE_BEARER_CMD,
			pdn->s5s8_pgw_gtpc_teid, del_bearer_cmd->header.teid.has_teid.seq, 0);

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
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}

int
delete_rule_in_bearer(eps_bearer *bearer)
{
	/* Deleting rules those are associated with Bearer */
	for (uint8_t itr = 0; itr < RULE_CNT; ++itr) {
		if (NULL != bearer->dynamic_rules[itr]) {
			rule_name_key_t key = {0};
			snprintf(key.rule_name, RULE_NAME_LEN, "%s%d",
					bearer->dynamic_rules[itr]->rule_name, (bearer->pdn)->call_id);
			if (del_rule_name_entry(key) != 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Error on delete rule name entries\n",
						LOG_VALUE);
				return -1;
			}
			rte_free(bearer->dynamic_rules[itr]);
			bearer->dynamic_rules[itr] = NULL;
		}
		if(NULL != bearer->prdef_rules[itr]){
			rule_name_key_t key = {0};
			snprintf(key.rule_name, RULE_NAME_LEN, "%s",
					bearer->prdef_rules[itr]->rule_name);
			if (del_rule_name_entry(key) != 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Error on delete rule name entries\n",
						LOG_VALUE);
				return -1;

			}
			rte_free(bearer->prdef_rules[itr]);
			bearer->prdef_rules[itr] = NULL;
		}
	}
	return 0;
}

/**
 * @brief  : Delete Bearer Context associate with EBI.
 * @param  : pdn, pdn information.
 * @param  : ebi_index, Bearer index.
 * @return : Returns 0 on success, -1 otherwise
 */
int
delete_bearer_context(pdn_connection *pdn, int ebi_index ) {

	if (pdn->eps_bearers[ebi_index]) {
		if(delete_rule_in_bearer(pdn->eps_bearers[ebi_index])){
			return -1;
		}
		/* TODO: Temp. Solution, Need to fix bug #1182 segmentation fault issue */
		//rte_free(pdn->eps_bearers[ebi_index]);
		pdn->eps_bearers[ebi_index] = NULL;
		pdn->context->eps_bearers[ebi_index] = NULL;
		pdn->context->bearer_bitmap &= ~(1 << ebi_index);
	}
	return 0;
}

void
delete_sess_context(ue_context *context, pdn_connection *pdn) {

	int ret = 0;
	/* Deleting session entry */
	del_sess_entry(pdn->seid);

	/* If EBI is Default EBI then delete all bearer and rule associate with PDN */
	for (uint8_t itr1 = 0; itr1 < MAX_BEARERS; ++itr1) {
		if (pdn->eps_bearers[itr1] == NULL)
			continue;

		del_rule_entries(pdn, itr1);
		delete_bearer_context(pdn, itr1);
	}
	if (context->cp_mode == SGWC) {
		/* Deleting Bearer hash */
		rte_hash_del_key(bearer_by_fteid_hash,
				(const void *) &(pdn)->s5s8_sgw_gtpc_teid);
	}

	/* free apn name label */
	if (pdn->apn_in_use->apn_idx < 0) {
		if (pdn->apn_in_use != NULL) {
			if (pdn->apn_in_use->apn_name_label != NULL) {
				rte_free(pdn->apn_in_use->apn_name_label);
				pdn->apn_in_use->apn_name_label = NULL;
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"apn name label memory free successfully\n",
					LOG_VALUE);
			}
			rte_free(pdn->apn_in_use);
			pdn->apn_in_use = NULL;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"apn in use memory free successfully\n",
				LOG_VALUE);
		}

	}

#ifdef USE_CSID
			/*
			 * De-link entry of the session from the CSID list
			 * for only default bearer id
			 * */
			if ((context->cp_mode == SGWC) || (context->cp_mode == SAEGWC)) {
				/* Remove session entry from the SGWC or SAEGWC CSID */
				cleanup_csid_entry(pdn->seid, (context)->sgw_fqcsid, pdn->context);
			} else if (context->cp_mode == PGWC) {
				/* Remove session entry from the PGWC CSID */
				cleanup_csid_entry(pdn->seid, (context)->pgw_fqcsid, pdn->context);
			}
#endif /* USE_CSID */
	if (pdn != NULL) {

		rte_free(pdn);
		pdn = NULL;
	}

	--context->num_pdns;

	if (context->num_pdns == 0) {

		/* Deleting UE context hash */
		rte_hash_del_key(ue_context_by_fteid_hash,
				(const void *) &(context)->s11_sgw_gtpc_teid);
		/* Delete UE context entry from UE Hash */
		if ((ret = rte_hash_del_key(ue_context_by_imsi_hash, &context->imsi)) < 0){
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"%s - Error on ue_context_by_fteid_hash"
							" deletion\n", LOG_VALUE,	strerror(ret));
		}
		if(pfcp_config.use_dns) {
			/* Delete UPFList entry from UPF Hash */
			if ((upflist_by_ue_hash_entry_delete(&context->imsi, sizeof(context->imsi)))
					< 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error on upflist_by_ue_hash deletion of IMSI \n",
						LOG_VALUE);
			}
		}
		if (context != NULL) {
			rte_free(context);
			context = NULL;
		}
	}
	return;
}

int
gtpc_context_replace_check(create_sess_req_t *csr, uint8_t cp_type, apn *apn_requested)
{
	int ret = 0;
	msg_info msg;
	uint8_t ebi = 0;
	int msg_len = 0;
	int encoded = 0;
	uint32_t teid = 0;
	uint8_t send_dsr = 0;
	uint32_t sequence = 0;
	uint32_t upf_ipv4 = 0;
	int payload_length = 0;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint64_t imsi = UINT64_MAX;
	del_sess_req_t ds_req = {0};
	struct resp_info *resp = NULL;
	uint32_t s5s8_pgw_gtpc_ipv4 = 0;
	uint8_t pfcp_msg[PFCP_MSG_LEN] = {0};
	uint8_t encoded_msg[GTP_MSG_LEN] = {0};
	eps_bearer *bearers[MAX_BEARERS] = {NULL};
	pfcp_sess_del_req_t pfcp_sess_del_req = {0};
	pfcp_sess_mod_req_t pfcp_sess_mod_req = {0};
	uint8_t send_ccr_t = 0;
	uint8_t  buffer[1024] = {0} ;
	uint16_t gx_msglen = 0;
	gx_msg ccr_request = {0};

	imsi = csr->imsi.imsi_number_digits;

	ret = rte_hash_lookup_data(ue_context_by_imsi_hash, &imsi, (void **) &(context));
	if (ret == -ENOENT) {

		/* Context not found for IMSI */
		return 0;
	}

	/* Validate the GateWay Mode in case of promotion/handover */
	if (csr->indctn_flgs.indication_oi) {

		if (context->cp_mode != cp_type) {

			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"GateWay Mode Changed for exsiting Session, Gateway: %s --> %s\n",
					LOG_VALUE, context->cp_mode == SGWC ? "SGW-C" : context->cp_mode == PGWC ? "PGW-C" :
					context->cp_mode == SAEGWC? "SAEGW-C" : "UNKNOWN",
					cp_type == SGWC ? "SGW-C" : cp_type == PGWC ? "PGW-C" :
					cp_type == SAEGWC ? "SAEGW-C" : "UNKNOWN");

			/* Continue, remove existing session info */
			return 0;
		}
	}

	/* copy csr for li */
	msg.gtpc_msg.csr = *csr;
	if (PGWC == context->cp_mode) {

		/*extract ebi_id from array as all the ebi's will be of same pdn.*/
		int ebi_index = GET_EBI_INDEX(msg.gtpc_msg.csr.bearer_contexts_to_be_created[0].eps_bearer_id.ebi_ebi);
		if (ebi_index == -1) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);

			cs_error_response(&msg, GTPV2C_CAUSE_SYSTEM_FAILURE, CAUSE_SOURCE_SET_TO_0,
					context->cp_mode != PGWC ? S11_IFACE : S5S8_IFACE);
			return -1;
		}

		pdn = GET_PDN(context, ebi_index);
		if (pdn == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"pdn for ebi_index %d\n", LOG_VALUE, ebi_index);
			return -1;
		}
		process_msg_for_li(context, S5S8_C_INTFC_IN, &msg, pdn->s5s8_sgw_gtpc_ipv4.s_addr,
			ntohl(pfcp_config.s5s8_ip.s_addr), pdn->s5s8_sgw_gtpc_teid, pfcp_config.s5s8_port);
	} else {
		process_msg_for_li(context, S11_INTFC_IN, &msg, ntohl(context->s11_mme_gtpc_ipv4.s_addr),
			ntohl(pfcp_config.s11_ip.s_addr), pfcp_config.s11_mme_port, pfcp_config.s11_port);
	}

	for (uint8_t itr = 0; itr < csr->bearer_count; itr++) {

		ebi = csr->bearer_contexts_to_be_created[itr].eps_bearer_id.ebi_ebi;
		ret = get_pdn(&(context), apn_requested, &pdn);

		if (!ret && pdn != NULL && pdn->default_bearer_id != ebi) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Requested APN"
					" has default bearer with different EBI \n", LOG_VALUE);

			return GTPV2C_CAUSE_MULTIPLE_PDN_CONNECTIONS_FOR_APN_NOT_ALLOWED;
		}

		int ebi_index = GET_EBI_INDEX(ebi);
		if (ebi_index == -1) {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);

			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}

		sequence = CSR_SEQUENCE(csr);

		bearer = (context)->eps_bearers[ebi_index];

		/* Checking Received CSR is re-transmitted CSR ot not */
		if (bearer != NULL ) {

			pdn = bearer->pdn;
			if (pdn != NULL ) {

				if (pdn->csr_sequence == sequence) {

					/* Discarding re-transmitted csr */
					return GTPC_RE_TRANSMITTED_REQ;
				}
			}
		} else {

			/* Bearer context not found for received EPS bearer ID */
			return 0;
		}

		/* looking for TEID */
		if (csr->header.gtpc.teid_flag == 1) {

			teid = csr->header.teid.has_teid.teid;
		}

		/* checking received EPS Bearer ID is default bearer id or not */
		if (pdn->default_bearer_id == ebi) {

			if ((context->eps_bearers[ebi_index] != NULL) &&
					(context->eps_bearers[ebi_index]->pdn != NULL)) {

				/* Fill PFCP deletion req with crosponding SEID and send it to SGWU */
				fill_pfcp_sess_del_req(&pfcp_sess_del_req, context->cp_mode);

				pfcp_sess_del_req.header.seid_seqno.has_seid.seid = pdn->dp_seid;

				encoded = encode_pfcp_sess_del_req_t(&pfcp_sess_del_req, pfcp_msg);

				pdn->state = PFCP_SESS_DEL_REQ_SNT_STATE;
			}
		} else {

			/*
			 * If Received EPS Bearer ID is not match with existing PDN connection
			 * context Default EPS Bearer ID , i.e Received EBI is dedicate bearer id
			 */
			if (((teid != 0) && (context->eps_bearers[ebi_index] != NULL)) &&
					(context->eps_bearers[ebi_index]->pdn != NULL)) {

				/* Fill PFCP MOD req with SEID, FAR and send it to DP */
				/* Need hardcoded index for pass single bearer info. to funtion */
				bearers[0] = context->eps_bearers[ebi_index];
				fill_pfcp_sess_mod_req_delete(&pfcp_sess_mod_req, pdn, bearers, 1);
				encoded = encode_pfcp_sess_mod_req_t(&pfcp_sess_mod_req, pfcp_msg);

				pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
				header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

				/* UPF ip address  */
				upf_pfcp_sockaddr.sin_addr.s_addr = pdn->upf_ipv4.s_addr;
				if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0)
					clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
							"Error in sending MSG to DP err_no: %i\n", LOG_VALUE, errno);
			}

			pdn->state = PFCP_SESS_MOD_REQ_SNT_STATE;
		}

		pdn->proc = INITIAL_PDN_ATTACH_PROC;

		/* Retrive the session information based on session id. */
		if (get_sess_entry(pdn->seid, &resp) != 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session Entry Found "
						"while sending PFCP Session Deletion / Modification Request for "
						"session ID:%lu\n", LOG_VALUE, pdn->seid);

				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
		}

		resp->state = pdn->state;
		resp->proc = pdn->proc;

		/* store csr in resp structure */
		resp->gtpc_msg.csr = *csr;
		//memcpy(&resp->gtpc_msg.csr, csr, sizeof(create_sess_req_t));

		upf_ipv4 = pdn->upf_ipv4.s_addr;

		/* Checking PGW change or not */
		if ((context->cp_mode == SGWC) && (pdn->s5s8_pgw_gtpc_ipv4.s_addr !=
					csr->pgw_s5s8_addr_ctl_plane_or_pmip.ipv4_address)) {

			/* Set flag  send dsr to PGWC */
			send_dsr = 1;

			/*
			 * Fill Delete Session request with crosponding TEID and
			 * EPS Bearer ID and send it to PGW
			 */
			/* Set DSR header */
			/* need to think about which sequence number we can set in DSR header */
			set_gtpv2c_teid_header(&ds_req.header, GTP_DELETE_SESSION_REQ,
					pdn->s5s8_pgw_gtpc_teid, 1/*Sequence*/, 0);
			/* Set EBI */
			set_ebi(&ds_req.lbi, IE_INSTANCE_ZERO , pdn->default_bearer_id);

			msg_len = encode_del_sess_req(&ds_req, encoded_msg);

			/* Coping S5S8 PGW ip address */
			s5s8_pgw_gtpc_ipv4 = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
		}

		/* Sending CCR-T to PCRF if PGWC/SAEGWC and Received EBI is default */
		if ((pfcp_config.use_gx) && (context->cp_mode != SGWC) &&
			(pdn->default_bearer_id == ebi)) {

			send_ccr_t = 1;
			gx_context_t *gx_context = NULL;

			/* Retrive Gx_context based on Sess ID. */
			ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
					(const void*)(pdn->gx_sess_id), (void **)&gx_context);
			if (ret < 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"NO ENTRY FOUND"
						" IN Gx HASH [%s]\n", LOG_VALUE, pdn->gx_sess_id);
			}

			/* Set the Msg header type for CCR-T */
			ccr_request.msg_type = GX_CCR_MSG ;

			/* Set Credit Control Request type */
			ccr_request.data.ccr.presence.cc_request_type = PRESENT;
			ccr_request.data.ccr.cc_request_type = TERMINATION_REQUEST ;

			/* Set Credit Control Bearer opertaion type */
			ccr_request.data.ccr.presence.bearer_operation = PRESENT;
			ccr_request.data.ccr.bearer_operation = TERMINATION ;

			/* Fill the Credit Crontrol Request to send PCRF */
			if(fill_ccr_request(&ccr_request.data.ccr, context, ebi_index,
						pdn->gx_sess_id, 0) != 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT" Failed CCR request filling process\n", LOG_VALUE);
			}

			/* Calculate the max size of CCR msg to allocate the buffer */
			gx_msglen = gx_ccr_calc_length(&ccr_request.data.ccr);
			ccr_request.msg_len = gx_msglen + GX_HEADER_LEN;

			memcpy(&buffer, &ccr_request.msg_type, sizeof(ccr_request.msg_type));
			memcpy(buffer + sizeof(ccr_request.msg_type),
									&ccr_request.msg_len,
							sizeof(ccr_request.msg_len));

			if (gx_ccr_pack(&(ccr_request.data.ccr),
						(unsigned char *)(buffer + GX_HEADER_LEN), gx_msglen) == 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ERROR:Packing CCR Buffer... \n", LOG_VALUE);
			}
			/* Deleting PDN hash map with GX call id */
			rte_hash_del_key(pdn_conn_hash,
					(const void *) &pdn->call_id);
			/* Deleting GX hash */
			rte_hash_del_key(gx_context_by_sess_id_hash,
					(const void *) &pdn->gx_sess_id);
			if (gx_context !=  NULL) {
				rte_free(gx_context);
				gx_context = NULL;
			}
		}

	} /* for loop */

	if ((context->cp_mode == SGWC) && (send_dsr)) {
		s5s8_recv_sockaddr.sin_addr.s_addr = s5s8_pgw_gtpc_ipv4;
		gtpv2c_header_t *header = NULL;
		header = (gtpv2c_header_t*) encoded_msg;
		header->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

		payload_length = (ntohs(header->gtpc.message_len) + sizeof(header->gtpc));

		gtpv2c_send(s5s8_fd, encoded_msg, payload_length,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				s5s8_sockaddr_len,SENT);
	}

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - PFCP_IE_HDR_SIZE);

	upf_pfcp_sockaddr.sin_addr.s_addr = upf_ipv4;

	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr,SENT) < 0)
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT
				"Error in sending MSG to DP err_no: %i\n", LOG_VALUE, errno);

	if (pfcp_config.use_gx) {
		/* Write or Send CCR -T msg to Gx_App */
		if ((context->cp_mode != SGWC) && (send_ccr_t)) {
			send_to_ipc_channel(gx_app_sock, buffer, gx_msglen + GX_HEADER_LEN);
		}

		if (ccr_request.data.ccr.subscription_id.list != NULL) {
			free(ccr_request.data.ccr.subscription_id.list);
			ccr_request.data.ccr.subscription_id.list = NULL;
			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
					"subscription id list is successfully free\n",
					LOG_VALUE);
		}
	}

	return GTPC_CONTEXT_REPLACEMENT;
}

uint8_t
check_mbr_procedure(ue_context *context)
{

	if((context->cp_mode == SGWC )) {

		if((context->ue_time_zone_flag == FALSE) &&  (context->rat_type_flag == FALSE) &&
				(context->uli_flag == FALSE) && (context->rat_type_flag == FALSE) && (context->uci_flag == FALSE)
				&& (context->serving_nw_flag == FALSE) && (context->ltem_rat_type_flag == FALSE) &&
				(context->second_rat_flag == FALSE) && (context->flag_fqcsid_modified == TRUE)) {

			return UPDATE_PDN_CONNECTION;

		} else if((context->ue_time_zone_flag == FALSE) &&  (context->rat_type_flag == FALSE) &&
				(context->uli_flag == FALSE) && (context->rat_type_flag == FALSE) && (context->uci_flag == FALSE)
				&& (context->serving_nw_flag == FALSE) &&  (context->ltem_rat_type_flag == FALSE) &&
				(context->flag_fqcsid_modified == FALSE) && (context->second_rat_flag == FALSE)) {

			return NO_UPDATE_MBR;

		} else if((context->ue_time_zone_flag != FALSE) ||  (context->rat_type_flag != FALSE) ||
				(context->uli_flag != FALSE) || (context->rat_type_flag != FALSE) || (context->uci_flag != FALSE)
				|| (context->serving_nw_flag != FALSE) || (context->ltem_rat_type_flag != FALSE) ||
				(context->flag_fqcsid_modified != FALSE) || (context->second_rat_flag != FALSE)) {

			return FORWARD_MBR_REQUEST;
		}
	} else if(context->cp_mode == PGWC) {

		return NO_UPDATE_MBR;

	} else if(context->cp_mode == SAEGWC){
		return NO_UPDATE_MBR;
	}

	return 0;
}

void
set_bearer_resource_command(bearer_rsrc_cmd_t *bearer_rsrc_cmd, pdn_connection *pdn,
								gtpv2c_header_t *gtpv2c_tx)
{
	bearer_rsrc_cmd_t brc_cmd = {0};
	brc_cmd.header.gtpc.message_len = 0;

	pdn->context->sequence = bearer_rsrc_cmd->header.teid.has_teid.seq;

	set_gtpv2c_teid_header((gtpv2c_header_t *) &brc_cmd, GTP_BEARER_RESOURCE_CMD,
			pdn->s5s8_pgw_gtpc_teid, bearer_rsrc_cmd->header.teid.has_teid.seq, 0);


	set_ipv4_fteid(&brc_cmd.sender_fteid_ctl_plane, GTPV2C_IFTYPE_S5S8_SGW_GTPC,
			IE_INSTANCE_ZERO, pdn->s5s8_sgw_gtpc_ipv4,
			pdn->s5s8_sgw_gtpc_teid);

	brc_cmd.header.gtpc.message_len += bearer_rsrc_cmd->sender_fteid_ctl_plane.header.len + sizeof(ie_header_t);

	/*Below IE are Condition IE's*/

	if (bearer_rsrc_cmd->lbi.header.len != 0) {
		memcpy(&brc_cmd.lbi, &(bearer_rsrc_cmd->lbi), sizeof(gtp_eps_bearer_id_ie_t));
		set_ie_header(&brc_cmd.lbi.header, GTP_IE_EPS_BEARER_ID, IE_INSTANCE_ZERO,
				bearer_rsrc_cmd->lbi.header.len);
	}

	if (bearer_rsrc_cmd->pti.header.len != 0) {
		memcpy(&brc_cmd.pti, &(bearer_rsrc_cmd->pti), sizeof(gtp_proc_trans_id_ie_t));
		set_ie_header(&brc_cmd.pti.header, GTP_IE_PROC_TRANS_ID, IE_INSTANCE_ZERO,
				bearer_rsrc_cmd->pti.header.len);
	}

	if (bearer_rsrc_cmd->tad.header.len != 0) {
		memcpy(&brc_cmd.tad, &(bearer_rsrc_cmd->tad), sizeof(gtp_traffic_agg_desc_ie_t));
		set_ie_header(&brc_cmd.tad.header, GTP_IE_TRAFFIC_AGG_DESC, IE_INSTANCE_ZERO,
				bearer_rsrc_cmd->tad.header.len);
	}

	if (bearer_rsrc_cmd->flow_qos.header.len != 0) {
		memcpy(&brc_cmd.flow_qos, &(bearer_rsrc_cmd->flow_qos), sizeof(gtp_flow_qlty_of_svc_ie_t));
		set_ie_header(&brc_cmd.flow_qos.header, GTP_IE_FLOW_QLTY_OF_SVC, IE_INSTANCE_ZERO,
				bearer_rsrc_cmd->flow_qos.header.len);
	}

	if (bearer_rsrc_cmd->eps_bearer_id.header.len != 0) {
		memcpy(&brc_cmd.eps_bearer_id, &(bearer_rsrc_cmd->eps_bearer_id), sizeof(gtp_eps_bearer_id_ie_t));
		set_ie_header(&brc_cmd.eps_bearer_id.header, GTP_IE_EPS_BEARER_ID, IE_INSTANCE_ONE,
				bearer_rsrc_cmd->eps_bearer_id.header.len);
	}

	if (bearer_rsrc_cmd->rat_type.header.len != 0) {
		memcpy(&brc_cmd.rat_type, &(bearer_rsrc_cmd->rat_type), sizeof(gtp_rat_type_ie_t));
		set_ie_header(&brc_cmd.rat_type.header, GTP_IE_RAT_TYPE, IE_INSTANCE_ZERO,
				bearer_rsrc_cmd->rat_type.header.len);
	}


	uint16_t msg_len = 0;
	msg_len = encode_bearer_rsrc_cmd(&brc_cmd, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}
