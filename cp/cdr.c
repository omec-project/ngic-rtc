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

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>

#include "pfcp_session.h"
#include "pfcp_util.h"
#include "cdr.h"
#include "redis_client.h"

#include "pfcp_set_ie.h"

pfcp_config_t pfcp_config;

const uint32_t base_urr_seq_no = 0x00000000;
static uint32_t urr_seq_no_offset;

int
fill_cdr_info_sess_rpt_req(uint64_t seid, pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report)
{
	struct timeval unix_start_time;
	struct timeval unix_end_time;

	cdr fill_cdr;
	memset(&fill_cdr,0,sizeof(cdr));

	if(usage_report->urseqn.header.len != 0)
	{
		fill_cdr.urseqn = usage_report->urseqn.urseqn;
	}

	fill_cdr.cdr_type = CDR_BY_URR;
	fill_cdr.seid = seid;
	fill_cdr.urr_id =
		usage_report->urr_id.urr_id_value;
	fill_cdr.start_time =
		usage_report->start_time.start_time;
	fill_cdr.end_time =
		usage_report->end_time.end_time;
	fill_cdr.data_start_time =
		usage_report->time_of_frst_pckt.time_of_frst_pckt;
	fill_cdr.data_end_time =
		usage_report->time_of_lst_pckt.time_of_lst_pckt;
	fill_cdr.data_volume_uplink =
		usage_report->vol_meas.uplink_volume;
	fill_cdr.data_volume_downlink =
		usage_report->vol_meas.downlink_volume;
	fill_cdr.total_data_volume =
		usage_report->vol_meas.total_volume;

	if(usage_report->dur_meas.header.len!= 0)
	{
		fill_cdr.duration_meas = usage_report->dur_meas.duration_value;
	} else {
		ntp_to_unix_time(&fill_cdr.start_time,&unix_start_time);
		ntp_to_unix_time(&fill_cdr.end_time,&unix_end_time);

		fill_cdr.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
	}

	urr_cause_code_to_str(&usage_report->usage_rpt_trig, fill_cdr.trigg_buff);
	if(generate_cdr_info(&fill_cdr) == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d failed to generate CDR\n",
				__FUNCTION__, __LINE__);
		return -1;
	}
	return 0;
}

int
fill_cdr_info_sess_mod_resp(uint64_t seid, pfcp_usage_rpt_sess_mod_rsp_ie_t *usage_report)
{
	struct timeval unix_start_time;
	struct timeval unix_end_time;

	cdr fill_cdr;
	memset(&fill_cdr,0,sizeof(cdr));

	if(usage_report->urseqn.header.len != 0)
	{
		fill_cdr.urseqn = usage_report->urseqn.urseqn;
	}

	fill_cdr.cdr_type = CDR_BY_URR;
	fill_cdr.seid = seid;
	fill_cdr.urr_id =
		usage_report->urr_id.urr_id_value;
	fill_cdr.start_time =
		usage_report->start_time.start_time;
	fill_cdr.end_time =
		usage_report->end_time.end_time;
	fill_cdr.data_start_time =
		usage_report->time_of_frst_pckt.time_of_frst_pckt;
	fill_cdr.data_end_time =
		usage_report->time_of_lst_pckt.time_of_lst_pckt;
	fill_cdr.data_volume_uplink =
		usage_report->vol_meas.uplink_volume;
	fill_cdr.data_volume_downlink =
		usage_report->vol_meas.downlink_volume;
	fill_cdr.total_data_volume =
		 usage_report->vol_meas.total_volume;

	if(usage_report->dur_meas.header.len!= 0)
	{
		fill_cdr.duration_meas = usage_report->dur_meas.duration_value;
	} else {
		ntp_to_unix_time(&fill_cdr.start_time,&unix_start_time);
		ntp_to_unix_time(&fill_cdr.end_time,&unix_end_time);

		fill_cdr.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
	}

	urr_cause_code_to_str(&usage_report->usage_rpt_trig, fill_cdr.trigg_buff);
	if(generate_cdr_info(&fill_cdr) == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d failed to generate CDR\n",
				__FUNCTION__, __LINE__);
		return -1;
	}
	return 0;
}


int
fill_cdr_info_sess_del_resp(uint64_t seid, pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report)
{
	struct timeval unix_start_time;
	struct timeval unix_end_time;

	cdr fill_cdr;
	memset(&fill_cdr,0,sizeof(cdr));

	if(usage_report->urseqn.header.len != 0)
	{
		fill_cdr.urseqn = usage_report->urseqn.urseqn;
	}

	fill_cdr.cdr_type = CDR_BY_URR;
	fill_cdr.seid = seid;
	fill_cdr.urr_id =
		usage_report->urr_id.urr_id_value;
	fill_cdr.start_time =
		usage_report->start_time.start_time;
	fill_cdr.end_time =
		usage_report->end_time.end_time;
	fill_cdr.data_start_time =
		usage_report->time_of_frst_pckt.time_of_frst_pckt;
	fill_cdr.data_end_time =
		usage_report->time_of_lst_pckt.time_of_lst_pckt;
	fill_cdr.data_volume_uplink =
		usage_report->vol_meas.uplink_volume;
	fill_cdr.data_volume_downlink =
		usage_report->vol_meas.downlink_volume;
	fill_cdr.total_data_volume =
		usage_report->vol_meas.total_volume;

	if(usage_report->dur_meas.header.len!= 0)
	{
		fill_cdr.duration_meas = usage_report->dur_meas.duration_value;
	} else {
		ntp_to_unix_time(&fill_cdr.start_time,&unix_start_time);
		ntp_to_unix_time(&fill_cdr.end_time,&unix_end_time);
		fill_cdr.duration_meas = unix_end_time.tv_sec - unix_start_time.tv_sec;
	}

	urr_cause_code_to_str(&usage_report->usage_rpt_trig, fill_cdr.trigg_buff);
	if(generate_cdr_info(&fill_cdr) == -1) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d failed to generate CDR\n",
				__FUNCTION__, __LINE__);
		return -1;
	}
	return 0;
}

int
generate_cdr_info(cdr *fill_cdr)
{
	char cdr_buff[CDR_BUFF_SIZE];
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	uint32_t teid;
	uint8_t ebi_index;
	int ret = 0;
	int bearer_index = -1;
	char apn_name[MAX_APN_LEN] = {0};
	char sgw_addr_buff[CDR_BUFF_SIZE] = {0};
	char mcc_buff[MCC_BUFF_SIZE] = {0};
	char mnc_buff[MNC_BUFF_SIZE] = {0};
	struct timeval unix_start_time = {0};
	struct timeval unix_end_time = {0};
	struct timeval unix_data_start_time = {0};
	struct timeval unix_data_end_time = {0};
	char start_time_buff[CDR_TIME_BUFF] = {0};
	char end_time_buff[CDR_TIME_BUFF] = {0};
	char data_start_time_buff[CDR_TIME_BUFF] = {0};
	char data_end_time_buff[CDR_TIME_BUFF] = {0};
	char buf_pdn[CDR_PDN_BUFF] = {0};

	memset(cdr_buff,0,CDR_BUFF_SIZE);

	teid = UE_SESS_ID(fill_cdr->seid);
	ret = get_ue_context(teid,&context);

	//Add check if context not found.
	if(ret!=0) {
		clLog(clSystemLog, eCLSeverityCritical,
				"%s:%d Context not found, Failed to generate CDR\n",
				__FUNCTION__, __LINE__);
		return -1;
	}

	ebi_index = UE_BEAR_ID(fill_cdr->seid) - 5;
	pdn = context->eps_bearers[ebi_index]->pdn;

	if (fill_cdr->cdr_type == CDR_BY_URR) {
		bearer_index = get_bearer_index_by_urr_id(fill_cdr->urr_id,pdn);
	} else { /*case of secondary RAT*/
		bearer_index = fill_cdr->bearer_id - 5;
	}

	if (bearer_index != -1) {
		fill_cdr->ul_mbr = pdn->eps_bearers[bearer_index]->qos.ul_mbr;
		fill_cdr->dl_mbr = pdn->eps_bearers[bearer_index]->qos.dl_mbr;
		fill_cdr->ul_gbr = pdn->eps_bearers[bearer_index]->qos.ul_gbr;
		fill_cdr->dl_gbr = pdn->eps_bearers[bearer_index]->qos.dl_gbr;
	}else {
		clLog(clSystemLog, eCLSeverityCritical,
				"Bearer not found for URR id : %d\n,can't generate CDR"
				,fill_cdr->urr_id);
		return -1;
	}

	/*for record type
	 * SGW_CDR = for sgwc
	 * PGW_CDR = for pgwc
	 * SAEGW_CDR = for saegwc*/
	if (pfcp_config.cp_type == PGWC) {
		fill_cdr->record_type = PGW_CDR;
	} else if (pfcp_config.cp_type == SGWC) {
		fill_cdr->record_type = SGW_CDR;
	} else {
		fill_cdr->record_type = SAEGW_CDR;
	}

	/*RAT type*/
	if (fill_cdr->cdr_type == CDR_BY_URR) {
		fill_cdr->rat_type = context->rat_type.rat_type;
	} else {
		if (fill_cdr->change_rat_type_flag == 0)
			fill_cdr->rat_type = context->rat_type.rat_type;
	}

	/*Selection mode*/
	fill_cdr->selec_mode = context->select_mode.selec_mode;

	memcpy(&fill_cdr->imsi,&(context->imsi),context->imsi_len);
	//fill_cdr->apn  = pdn->apn_in_use->apn_name_label;
	memcpy(apn_name, (pdn->apn_in_use)->apn_name_label + 1, (pdn->apn_in_use)->apn_name_length -1);
	fill_cdr->ue_ip = pdn->ipv4;

	fill_cdr->sgw_addr = pfcp_config.pfcp_ip;
	snprintf(sgw_addr_buff,CDR_BUFF_SIZE,"%s",
			inet_ntoa(*((struct in_addr *)&fill_cdr->sgw_addr.s_addr)));

	snprintf(mcc_buff,MCC_BUFF_SIZE,"%d%d%d",context->serving_nw.mcc_digit_1,
			context->serving_nw.mcc_digit_2,
			context->serving_nw.mcc_digit_3);
	snprintf(mnc_buff,MNC_BUFF_SIZE,"%d%d",context->serving_nw.mnc_digit_1,
			context->serving_nw.mnc_digit_2);

	if (context->serving_nw.mnc_digit_3 != 15)
			snprintf(mnc_buff + strnlen(mnc_buff,MNC_BUFF_SIZE),MNC_BUFF_SIZE,"%d",
					context->serving_nw.mnc_digit_3);

	ntp_to_unix_time(&fill_cdr->start_time,&unix_start_time);
	snprintf(start_time_buff,CDR_TIME_BUFF,"%lu",unix_start_time.tv_sec);

	ntp_to_unix_time(&fill_cdr->end_time,&unix_end_time);
	snprintf(end_time_buff,CDR_TIME_BUFF,"%lu",unix_end_time.tv_sec);

	ntp_to_unix_time(&fill_cdr->data_start_time,&unix_data_start_time);
	snprintf(data_start_time_buff,CDR_TIME_BUFF,"%lu",unix_data_start_time.tv_sec);

	ntp_to_unix_time(&fill_cdr->data_end_time,&unix_data_end_time);
	snprintf(data_end_time_buff,CDR_TIME_BUFF,"%lu",unix_data_end_time.tv_sec);

	check_pdn_type(&pdn->pdn_type, buf_pdn);

	ret = snprintf(cdr_buff,CDR_BUFF_SIZE,
			"%u,%d,%d,%d,""""%"PRIu64",%s,%s,%lu,%lu,%lu,%lu,%s,%s,%s,%s,%s,%s,%s,%s,%lu,%lu,%lu,%u,%s",
								generate_cdr_seq_no(),
								fill_cdr->record_type,
								fill_cdr->rat_type,
								fill_cdr->selec_mode,
								fill_cdr->imsi,
								fill_cdr->trigg_buff,
								apn_name,
								fill_cdr->ul_mbr,
								fill_cdr->dl_mbr,
								fill_cdr->ul_gbr,
								fill_cdr->dl_gbr,
								start_time_buff,
								end_time_buff,
								data_start_time_buff,
								data_end_time_buff,
								mcc_buff,
								mnc_buff,
								inet_ntoa(*((struct in_addr *)&fill_cdr->ue_ip.s_addr)),
								sgw_addr_buff,
								fill_cdr->data_volume_uplink,
								fill_cdr->data_volume_downlink,
								fill_cdr->total_data_volume,
								fill_cdr->duration_meas,
								buf_pdn
								);
	if (ret < 0 || ret >= CDR_BUFF_SIZE  ) {
		clLog(clSystemLog, eCLSeverityCritical,"Discarding generated CDR due to"
												"CDR buffer overflow\n");
		return -1;
	}

	if (ctx!=NULL) {
		redis_save_cdr(ctx,sgw_addr_buff,cdr_buff);
	} else {
		return -2;
	}

	return 0;

}


void
urr_cause_code_to_str(pfcp_usage_rpt_trig_ie_t *usage_rpt_trig, char *buf)
{
	if(usage_rpt_trig->volth == 1) {
		strncpy(buf, VOLUME_LIMIT, CDR_TRIGG_BUFF);
		return;
	}
	if(usage_rpt_trig->timth == 1) {
		strncpy(buf, TIME_LIMIT, CDR_TRIGG_BUFF);
		return;
	}
	if(usage_rpt_trig->termr == 1) {
		strncpy(buf, CDR_TERMINATION, CDR_TRIGG_BUFF);
		return;
	}

}


void
check_pdn_type(pdn_type_ie *pdn_type, char *buf)
{
	if(pdn_type->ipv4 == 1) {
		strncpy(buf, IPV4, CDR_PDN_BUFF);
		return;
	}
	if(pdn_type->ipv6 == 1) {
		strncpy(buf, IPV6, CDR_PDN_BUFF);
		return;
	}
}

uint32_t
generate_cdr_seq_no(void)
{
	uint32_t id = 0;
	id = base_urr_seq_no + (++urr_seq_no_offset);
	return id;
}

int
get_bearer_index_by_urr_id(uint32_t urr_id, pdn_connection *pdn)
{
	for ( int i = 0; i < MAX_BEARERS; i++ )
	{
		if (pdn->eps_bearers[i]!= NULL) {
			for (int j = 0 ; j < pdn->eps_bearers[i]->pdr_count; j++)
			{
				if (urr_id ==
						pdn->eps_bearers[i]->pdrs[j]->urr.urr_id_value)
					return i;
			}
		}
	}

	return -1;

}
