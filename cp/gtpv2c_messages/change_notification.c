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
#include "cp_config.h"
#include "cdr.h"
#include "cp_timer.h"

extern int s5s8_fd;
extern socklen_t s5s8_sockaddr_len;
extern socklen_t s11_mme_sockaddr_len;
extern struct sockaddr_in s5s8_recv_sockaddr;

/**
 * @brief  : Set the Change Notification Request gtpv2c message
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : change notification request structure pointer
			 This is the message which is received on the Gateway.
 * @return : Returns 0 for success, -1 for error
 */
int
set_change_notification_request(gtpv2c_header_t *gtpv2c_tx,
			change_noti_req_t  *change_not_req, pdn_connection **_pdn)
{

	change_noti_req_t chn_not_req = {0};
	pdn_connection *pdn =  NULL;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;
	int ret = 0;
	int ebi_index = 0;
	int len = 0;
	uint8_t instance = 0;
	uint16_t payload_length = 0;
	uint8_t cp_mode = 0;
	struct teid_value_t *teid_value = NULL;
	teid_key_t teid_key = {0};

	bzero(&tx_buf, sizeof(tx_buf));
	gtpv2c_tx = (gtpv2c_header_t *)tx_buf;

	ebi_index = GET_EBI_INDEX(change_not_req->lbi.ebi_ebi);
	if (ebi_index == -1) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID\n", LOG_VALUE);
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &change_not_req->header.teid.has_teid.teid,
			(void **) &context);

	if (ret < 0 || !context) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT" Failed to get UE context \n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	bearer = context->eps_bearers[ebi_index];

	if (!bearer) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT" Received modify bearer on non-existent EBI - "
				"Bitmap Inconsistency - Dropping packet\n", LOG_VALUE);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	context->sequence = change_not_req->header.teid.has_teid.seq;
	pdn = bearer->pdn;

	teid_value = rte_zmalloc_socket(NULL, sizeof(teid_value_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (teid_value == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
				"memory for teid value, Error : %s\n", LOG_VALUE,
				rte_strerror(rte_errno));
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	teid_value->teid = pdn->s5s8_sgw_gtpc_teid;
	teid_value->msg_type = change_not_req->header.gtpc.message_type;

	snprintf(teid_key.teid_key, PROC_LEN, "%s%d", get_proc_string(pdn->proc),
					change_not_req->header.teid.has_teid.seq);

	/* Add the entry for sequence and teid value for error handling */
	if (context->cp_mode != SAEGWC) {
		ret = add_seq_number_for_teid(teid_key, teid_value);
		if(ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add "
					"Sequence number for TEID: %u\n", LOG_VALUE,
					teid_value->teid);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		}
	}

	if(change_not_req->rat_type.header.len == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT" RAT TYPE missing in change notification request\n", LOG_VALUE);
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}
	if(change_not_req->imsi.header.len == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT" IMSI missing in change notification request\n", LOG_VALUE);
		return GTPV2C_CAUSE_IMSI_NOT_KNOWN;
	}

	set_gtpv2c_teid_header((gtpv2c_header_t *) &chn_not_req, GTP_CHANGE_NOTIFICATION_REQ,
		pdn->s5s8_pgw_gtpc_teid, change_not_req->header.teid.has_teid.seq, 0);


	memcpy(&chn_not_req.imsi.imsi_number_digits,
			&change_not_req->imsi.imsi_number_digits, change_not_req->imsi.header.len);

	set_ie_header(&chn_not_req.imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
								sizeof(chn_not_req.imsi.imsi_number_digits));

	set_ebi(&chn_not_req.lbi, IE_INSTANCE_ZERO, change_not_req->lbi.ebi_ebi);

	if(change_not_req->uli.header.len !=0) {
		if (change_not_req->uli.lai) {
			chn_not_req.uli.lai = context->uli.lai;
			chn_not_req.uli.lai2.lai_mcc_digit_2 = change_not_req->uli.lai2.lai_mcc_digit_2;
			chn_not_req.uli.lai2.lai_mcc_digit_1 = change_not_req->uli.lai2.lai_mcc_digit_1;
			chn_not_req.uli.lai2.lai_mnc_digit_3 = change_not_req->uli.lai2.lai_mnc_digit_3;
			chn_not_req.uli.lai2.lai_mcc_digit_3 = change_not_req->uli.lai2.lai_mcc_digit_3;
			chn_not_req.uli.lai2.lai_mnc_digit_2 = change_not_req->uli.lai2.lai_mnc_digit_2;
			chn_not_req.uli.lai2.lai_mnc_digit_1 = change_not_req->uli.lai2.lai_mnc_digit_1;
			chn_not_req.uli.lai2.lai_lac = change_not_req->uli.lai2.lai_lac;

			len += sizeof(chn_not_req.uli.lai2);
		}
		if (change_not_req->uli.tai) {
			chn_not_req.uli.tai = context->uli.tai;
			chn_not_req.uli.tai2.tai_mcc_digit_2 = change_not_req->uli.tai2.tai_mcc_digit_2;
			chn_not_req.uli.tai2.tai_mcc_digit_1 = change_not_req->uli.tai2.tai_mcc_digit_1;
			chn_not_req.uli.tai2.tai_mnc_digit_3 = change_not_req->uli.tai2.tai_mnc_digit_3;
			chn_not_req.uli.tai2.tai_mcc_digit_3 = change_not_req->uli.tai2.tai_mcc_digit_3;
			chn_not_req.uli.tai2.tai_mnc_digit_2 = change_not_req->uli.tai2.tai_mnc_digit_2;
			chn_not_req.uli.tai2.tai_mnc_digit_1 = change_not_req->uli.tai2.tai_mnc_digit_1;
			chn_not_req.uli.tai2.tai_tac = change_not_req->uli.tai2.tai_tac;
			len += sizeof(chn_not_req.uli.tai2);
		}
		if (change_not_req->uli.rai) {
			chn_not_req.uli.rai = change_not_req->uli.rai;
			chn_not_req.uli.rai2.ria_mcc_digit_2 = change_not_req->uli.rai2.ria_mcc_digit_2;
			chn_not_req.uli.rai2.ria_mcc_digit_1 = change_not_req->uli.rai2.ria_mcc_digit_1;
			chn_not_req.uli.rai2.ria_mnc_digit_3 = change_not_req->uli.rai2.ria_mnc_digit_3;
			chn_not_req.uli.rai2.ria_mcc_digit_3 = change_not_req->uli.rai2.ria_mcc_digit_3;
			chn_not_req.uli.rai2.ria_mnc_digit_2 = change_not_req->uli.rai2.ria_mnc_digit_2;
			chn_not_req.uli.rai2.ria_mnc_digit_1 = change_not_req->uli.rai2.ria_mnc_digit_1;
			chn_not_req.uli.rai2.ria_lac = change_not_req->uli.rai2.ria_lac;
			chn_not_req.uli.rai2.ria_rac = change_not_req->uli.rai2.ria_rac;
			len += sizeof(chn_not_req.uli.rai2);
		}
		if (change_not_req->uli.sai) {
			chn_not_req.uli.sai = context->uli.sai;
			chn_not_req.uli.sai2.sai_mcc_digit_2 = change_not_req->uli.sai2.sai_mcc_digit_2;
			chn_not_req.uli.sai2.sai_mcc_digit_1 = change_not_req->uli.sai2.sai_mcc_digit_1;
			chn_not_req.uli.sai2.sai_mnc_digit_3 = change_not_req->uli.sai2.sai_mnc_digit_3;
			chn_not_req.uli.sai2.sai_mcc_digit_3 = change_not_req->uli.sai2.sai_mcc_digit_3;
			chn_not_req.uli.sai2.sai_mnc_digit_2 = change_not_req->uli.sai2.sai_mnc_digit_2;
			chn_not_req.uli.sai2.sai_mnc_digit_1 = change_not_req->uli.sai2.sai_mnc_digit_1;
			chn_not_req.uli.sai2.sai_lac = change_not_req->uli.sai2.sai_lac;
			chn_not_req.uli.sai2.sai_sac = change_not_req->uli.sai2.sai_sac;
			len += sizeof(chn_not_req.uli.sai2);
		}
		if (change_not_req->uli.cgi) {
			chn_not_req.uli.cgi = change_not_req->uli.cgi;
			chn_not_req.uli.cgi2.cgi_mcc_digit_2 = change_not_req->uli.cgi2.cgi_mcc_digit_2;
			chn_not_req.uli.cgi2.cgi_mcc_digit_1 = change_not_req->uli.cgi2.cgi_mcc_digit_1;
			chn_not_req.uli.cgi2.cgi_mnc_digit_3 = change_not_req->uli.cgi2.cgi_mnc_digit_3;
			chn_not_req.uli.cgi2.cgi_mcc_digit_3 = change_not_req->uli.cgi2.cgi_mcc_digit_3;
			chn_not_req.uli.cgi2.cgi_mnc_digit_2 = change_not_req->uli.cgi2.cgi_mnc_digit_2;
			chn_not_req.uli.cgi2.cgi_mnc_digit_1 = change_not_req->uli.cgi2.cgi_mnc_digit_1;
			chn_not_req.uli.cgi2.cgi_lac = change_not_req->uli.cgi2.cgi_lac;
			chn_not_req.uli.cgi2.cgi_ci = context->uli.cgi2.cgi_ci;
			len += sizeof(chn_not_req.uli.cgi2);
		}
		if (change_not_req->uli.ecgi) {
			chn_not_req.uli.ecgi = change_not_req->uli.ecgi;
			chn_not_req.uli.ecgi2.ecgi_mcc_digit_2 = change_not_req->uli.ecgi2.ecgi_mcc_digit_2;
			chn_not_req.uli.ecgi2.ecgi_mcc_digit_1 = change_not_req->uli.ecgi2.ecgi_mcc_digit_1;
			chn_not_req.uli.ecgi2.ecgi_mnc_digit_3 = change_not_req->uli.ecgi2.ecgi_mnc_digit_3;
			chn_not_req.uli.ecgi2.ecgi_mcc_digit_3 = change_not_req->uli.ecgi2.ecgi_mcc_digit_3;
			chn_not_req.uli.ecgi2.ecgi_mnc_digit_2 = change_not_req->uli.ecgi2.ecgi_mnc_digit_2;
			chn_not_req.uli.ecgi2.ecgi_mnc_digit_1 = change_not_req->uli.ecgi2.ecgi_mnc_digit_1;
			chn_not_req.uli.ecgi2.ecgi_spare = change_not_req->uli.ecgi2.ecgi_spare;
			chn_not_req.uli.ecgi2.eci = change_not_req->uli.ecgi2.eci;
			len += sizeof(chn_not_req.uli.ecgi2);
		}
		if (change_not_req->uli.macro_enodeb_id) {
			chn_not_req.uli.macro_enodeb_id = change_not_req->uli.macro_enodeb_id;
			chn_not_req.uli.macro_enodeb_id2.menbid_mcc_digit_2 =
				change_not_req->uli.macro_enodeb_id2.menbid_mcc_digit_2;
			chn_not_req.uli.macro_enodeb_id2.menbid_mcc_digit_1 =
				change_not_req->uli.macro_enodeb_id2.menbid_mcc_digit_1;
			chn_not_req.uli.macro_enodeb_id2.menbid_mnc_digit_3 =
				change_not_req->uli.macro_enodeb_id2.menbid_mnc_digit_3;
			chn_not_req.uli.macro_enodeb_id2.menbid_mcc_digit_3 =
				change_not_req->uli.macro_enodeb_id2.menbid_mcc_digit_3;
			chn_not_req.uli.macro_enodeb_id2.menbid_mnc_digit_2 =
				change_not_req->uli.macro_enodeb_id2.menbid_mnc_digit_2;
			chn_not_req.uli.macro_enodeb_id2.menbid_mnc_digit_1 =
				change_not_req->uli.macro_enodeb_id2.menbid_mnc_digit_1;
			chn_not_req.uli.macro_enodeb_id2.menbid_spare =
				change_not_req->uli.macro_enodeb_id2.menbid_spare;
			chn_not_req.uli.macro_enodeb_id2.menbid_macro_enodeb_id =
				change_not_req->uli.macro_enodeb_id2.menbid_macro_enodeb_id;
			chn_not_req.uli.macro_enodeb_id2.menbid_macro_enb_id2 =
				change_not_req->uli.macro_enodeb_id2.menbid_macro_enb_id2;
			len += sizeof(chn_not_req.uli.macro_enodeb_id2);
		}
		if (change_not_req->uli.extnded_macro_enb_id) {
			chn_not_req.uli.extnded_macro_enb_id = change_not_req->uli.extnded_macro_enb_id;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_1;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_3;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_mcc_digit_3;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_2;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_mnc_digit_1;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_smenb =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_smenb;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_spare =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_spare;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id;
			chn_not_req.uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2 =
				change_not_req->uli.extended_macro_enodeb_id2.emenbid_extnded_macro_enb_id2;
			len += sizeof(chn_not_req.uli.extended_macro_enodeb_id2);
		}

		len += 1;
		set_ie_header(&chn_not_req.uli.header, GTP_IE_USER_LOC_INFO, IE_INSTANCE_ZERO, len);
	}

	if(change_not_req->rat_type.header.len !=0 ) {
		set_ie_header(&chn_not_req.rat_type.header, GTP_IE_RAT_TYPE,
				IE_INSTANCE_ZERO, sizeof(gtp_rat_type_ie_t) - sizeof(ie_header_t));
		chn_not_req.rat_type.rat_type = change_not_req->rat_type.rat_type;
	}

	if(change_not_req->uci.header.len !=0 ) {
		set_ie_header(&chn_not_req.rat_type.header,GTP_IE_USER_LOC_INFO,
				IE_INSTANCE_ZERO, sizeof(gtp_rat_type_ie_t) - sizeof(ie_header_t));
	}

	chn_not_req.second_rat_count = change_not_req->second_rat_count;

	uint8_t flag_pgwc_second_rat = 0;
	if(chn_not_req.second_rat_count != 0) {

		for(uint8_t i =0; i< change_not_req->second_rat_count; i++) {

			uint8_t trigg_buff[] = "Secondary_rat_usage";
			if(change_not_req->secdry_rat_usage_data_rpt[i].irsgw == 1) {
				cdr second_rat_data ;
				struct timeval unix_start_time;
				struct timeval unix_end_time;
				if(change_not_req->secdry_rat_usage_data_rpt[i].irsgw == 1) {
					flag_pgwc_second_rat++;
				}
				second_rat_data.cdr_type = CDR_BY_SEC_RAT;
				second_rat_data.change_rat_type_flag = 1;
				/*rat type in sec_rat_usage_rpt is NR=0 i.e RAT is 10 as per spec 29.274*/
				second_rat_data.rat_type = (change_not_req->secdry_rat_usage_data_rpt[i].secdry_rat_type == 0) ? 10 : 0;
				second_rat_data.bearer_id = change_not_req->lbi.ebi_ebi;
				second_rat_data.seid = pdn->seid;
				second_rat_data.imsi = pdn->context->imsi;
				second_rat_data.start_time = change_not_req->secdry_rat_usage_data_rpt[i].start_timestamp;
				second_rat_data.end_time = change_not_req->secdry_rat_usage_data_rpt[i].end_timestamp;
				second_rat_data.data_volume_uplink = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_ul;
				second_rat_data.data_volume_downlink = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_dl;
				ntp_to_unix_time(&change_not_req->secdry_rat_usage_data_rpt[i].start_timestamp,&unix_start_time);
				ntp_to_unix_time(&change_not_req->secdry_rat_usage_data_rpt[i].end_timestamp,&unix_end_time);
				second_rat_data.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
				second_rat_data.data_start_time = 0;
				second_rat_data.data_end_time = 0;
				second_rat_data.total_data_volume = change_not_req->secdry_rat_usage_data_rpt[i].usage_data_ul +
				change_not_req->secdry_rat_usage_data_rpt[i].usage_data_dl;
				memcpy(&second_rat_data.trigg_buff, &trigg_buff, sizeof(trigg_buff));
				if(generate_cdr_info(&second_rat_data) == -1) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"failed to generate CDR\n",
						LOG_VALUE);
					return -1;
				}
			}
			else if(change_not_req->secdry_rat_usage_data_rpt[i].irpgw == 1) {
					flag_pgwc_second_rat++;
			}
			else{
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IRPGW and IRSGW not set "
					"not expected from MME\n", LOG_VALUE);
			}
		}
	}


	if((flag_pgwc_second_rat == 0) &&
				(change_not_req->uli.header.len == 0)) {

		bzero(&tx_buf, sizeof(tx_buf));
		gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *)tx_buf;
		set_change_notification_response(gtpv2c_tx, pdn);

		payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
			+ sizeof(gtpv2c_tx->gtpc);

		s11_mme_sockaddr.sin_addr.s_addr =
			pdn->context->s11_mme_gtpc_ipv4.s_addr;

		gtpv2c_send(s11_fd, tx_buf, payload_length,
				(struct sockaddr *) &s11_mme_sockaddr,
				s11_mme_sockaddr_len, SENT);

		/* copy packet for user level packet copying or li */
		if (context->dupl) {
			process_pkt_for_li(
					context, S11_INTFC_OUT, tx_buf, payload_length,
					ntohl(pfcp_config.s11_ip.s_addr), s11_mme_sockaddr.sin_addr.s_addr,
					pfcp_config.s11_port, ntohs(s11_mme_sockaddr.sin_port));
		}

		pdn->state = CONNECTED_STATE;
		return 0;

	}

	if(chn_not_req.second_rat_count != 0) {

		for(uint8_t i =0; i< change_not_req->second_rat_count; i++) {

			if((change_not_req->secdry_rat_usage_data_rpt[i].irpgw == 1)) {

				set_ie_header(&chn_not_req.secdry_rat_usage_data_rpt[i].header,
						GTP_IE_SECDRY_RAT_USAGE_DATA_RPT, instance,
						sizeof(gtp_secdry_rat_usage_data_rpt_ie_t) - sizeof(ie_header_t));

				chn_not_req.secdry_rat_usage_data_rpt[i].spare2 = 0;

				chn_not_req.secdry_rat_usage_data_rpt[i].irsgw
					= change_not_req->secdry_rat_usage_data_rpt[i].irsgw;

				chn_not_req.secdry_rat_usage_data_rpt[i].irpgw
					= change_not_req->secdry_rat_usage_data_rpt[i].irpgw;

				chn_not_req.secdry_rat_usage_data_rpt[i].secdry_rat_type
					= change_not_req->secdry_rat_usage_data_rpt[i].secdry_rat_type;

				chn_not_req.secdry_rat_usage_data_rpt[i].ebi
					= change_not_req->secdry_rat_usage_data_rpt[i].ebi;

				chn_not_req.secdry_rat_usage_data_rpt[i].spare3
					= change_not_req->secdry_rat_usage_data_rpt[i].spare3;

				chn_not_req.secdry_rat_usage_data_rpt[i].start_timestamp
					= change_not_req->secdry_rat_usage_data_rpt[i].start_timestamp;

				chn_not_req.secdry_rat_usage_data_rpt[i].end_timestamp
					= change_not_req->secdry_rat_usage_data_rpt[i].end_timestamp;

				chn_not_req.secdry_rat_usage_data_rpt[i].usage_data_dl
					= change_not_req->secdry_rat_usage_data_rpt[i].usage_data_dl;

				chn_not_req.secdry_rat_usage_data_rpt[i].usage_data_ul
					= change_not_req->secdry_rat_usage_data_rpt[i].usage_data_ul;

				instance++;

			}
		}
	}


	struct resp_info *resp= NULL;
	ret = get_sess_entry(pdn->seid , &resp);
	if(ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No Session entry found "
					"for seid: %lu", LOG_VALUE, pdn->seid);
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
	}

	reset_resp_info_structure(resp);

	*_pdn = pdn;

	resp->state = CONNECTED_STATE;
	resp->proc = CHANGE_NOTIFICATION_PROC;

	uint16_t msg_len = 0;
	msg_len = encode_change_noti_req(&chn_not_req, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

	s5s8_recv_sockaddr.sin_addr.s_addr =
			pdn->s5s8_pgw_gtpc_ipv4.s_addr;

	payload_length = ntohs(gtpv2c_tx->gtpc.message_len)
		+ sizeof(gtpv2c_tx->gtpc);

	gtpv2c_send(s5s8_fd, tx_buf, payload_length,
			(struct sockaddr *) &s5s8_recv_sockaddr,
			s5s8_sockaddr_len,SENT);

	cp_mode = pdn->context->cp_mode;
	add_gtpv2c_if_timer_entry(
			change_not_req->header.teid.has_teid.teid,
			&s5s8_recv_sockaddr, tx_buf, payload_length,
			ebi_index, S5S8_IFACE, cp_mode);

	/* copy packet for user level packet copying or li */
	if (context->dupl) {
		process_pkt_for_li(
				context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
				ntohl(pfcp_config.s5s8_ip.s_addr), ntohl(s5s8_recv_sockaddr.sin_addr.s_addr),
				pfcp_config.s5s8_port, ntohs(s5s8_recv_sockaddr.sin_port));
	}

	return 0;
}

/**
 * @brief  : Set the Change Notification Response gtpv2c message
 * @param  : gtpv2c_tx
 *           transmission buffer to contain 'modify bearer request' message
 * @param  : pdn_connection structre pointer
 * @return : Returns nothing
 */

void
set_change_notification_response(gtpv2c_header_t *gtpv2c_tx, pdn_connection *pdn)
{
	change_noti_rsp_t chn_not_rsp = {0};

	if (pdn->context->cp_mode == PGWC) {

		set_gtpv2c_teid_header((gtpv2c_header_t *) &chn_not_rsp, GTP_CHANGE_NOTIFICATION_RSP,
				pdn->s5s8_sgw_gtpc_teid, pdn->context->sequence, 0);
	} else {

		set_gtpv2c_teid_header((gtpv2c_header_t *) &chn_not_rsp, GTP_CHANGE_NOTIFICATION_RSP,
				pdn->context->s11_mme_gtpc_teid, pdn->context->sequence, 0);
	}

	chn_not_rsp.imsi.imsi_number_digits = pdn->context->imsi;
	set_ie_header(&chn_not_rsp.imsi.header, GTP_IE_IMSI, IE_INSTANCE_ZERO,
				                 pdn->context->imsi_len);

	set_cause_accepted(&chn_not_rsp.cause, IE_INSTANCE_ZERO);

	uint16_t msg_len = 0;
	msg_len = encode_change_noti_rsp(&chn_not_rsp, (uint8_t *)gtpv2c_tx);
	gtpv2c_tx->gtpc.message_len = htons(msg_len - IE_HEADER_SIZE);

}


