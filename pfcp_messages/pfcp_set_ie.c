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

#include "cp.h"
#include "main.h"
#include "pfcp_ies.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_enum.h"

/* extern */
uint32_t start_time;

#ifdef CP_BUILD
extern pfcp_config_t pfcp_config;
static uint32_t pfcp_sgwc_seid_offset;
#endif /* CP_BUILD */

static uint16_t pdn_conn_set_id;
extern struct rte_hash *node_id_hash;
struct rte_hash *heartbeat_recovery_hash;
const uint64_t pfcp_sgwc_base_seid = 0xC0FFEE;

struct app_params app;

void
set_pfcp_header(pfcp_header_t *pfcp, uint8_t type, bool flag )
{
	pfcp->s       = flag;
	pfcp->mp      = 0;
	pfcp->spare   = 0;
	pfcp->version = PFCP_VERSION;
	pfcp->message_type = type;
}


void
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag,uint32_t seq)
{
	set_pfcp_header(pfcp, type, flag );

	if(flag == HAS_SEID){

#ifdef CP_BUILD
		if (pfcp_config.cp_type == SGWC){
			pfcp->seid_seqno.has_seid.seid  =
						pfcp_sgwc_base_seid + pfcp_sgwc_seid_offset;
			pfcp_sgwc_seid_offset++;
		}
#endif /* CP_BUILD */

		pfcp->seid_seqno.has_seid.seq_no = seq;
		pfcp->seid_seqno.has_seid.spare  = 0;
		pfcp->seid_seqno.has_seid.message_prio = 0;

	}else if (flag == NO_SEID){
		pfcp->seid_seqno.no_seid.seq_no = seq;
		pfcp->seid_seqno.no_seid.spare  = 0;
	}
}

void
pfcp_set_ie_header(pfcp_ie_header_t *header, uint8_t type, uint16_t length)
{
	header->type = type;
	header->len = length;
}

void
set_node_id(pfcp_node_id_ie_t *node_id, uint32_t nodeid_value)
{
	node_id->node_id_type = NODE_ID_TYPE_TYPE_IPV4ADDRESS;
	//Vikram : node_id->node_id_value_len = 4;
	memcpy(node_id->node_id_value, &nodeid_value, 4); //node_id->node_id_value_len);

	pfcp_set_ie_header(&(node_id->header), PFCP_IE_NODE_ID,
				4 + 1);
				//node_id->node_id_value_len + 1);
}

void
set_recovery_time_stamp(pfcp_rcvry_time_stmp_ie_t *rec_time_stamp)
{
	pfcp_set_ie_header(&(rec_time_stamp->header),
						PFCP_IE_RCVRY_TIME_STMP,UINT32_SIZE);

	rec_time_stamp->rcvry_time_stmp_val = start_time; //uptime();

}

void
set_upf_features(pfcp_up_func_feat_ie_t *upf_feat)
{
	pfcp_set_ie_header(&(upf_feat->header), PFCP_IE_UP_FUNC_FEAT,
					UINT16_SIZE);

	//upf_feat->supported_features = ALL_UPF_FEATURES_SUPPORTED;
	upf_feat->sup_feat = 0;
}

void
set_cpf_features(pfcp_cp_func_feat_ie_t *cpf_feat)
{
	pfcp_set_ie_header(&(cpf_feat->header), PFCP_IE_CP_FUNC_FEAT,
					UINT8_SIZE);
	//cpf_feat->supported_features = ALL_CPF_FEATURES_SUPPORTED;
	cpf_feat->sup_feat = 0;
}
void
set_up_ip_resource_info(pfcp_user_plane_ip_rsrc_info_ie_t *up_ip_resource_info,
						uint8_t i)
{
	pfcp_set_ie_header(&(up_ip_resource_info->header),
								PFCP_IE_USER_PLANE_IP_RSRC_INFO, 6);

	up_ip_resource_info->user_plane_ip_rsrc_info_spare  = 0;
	up_ip_resource_info->assosi = 1;
	up_ip_resource_info->assoni = 0;
	up_ip_resource_info->teidri = 0;
	up_ip_resource_info->v6     = 0;
	up_ip_resource_info->v4     = 1;
	up_ip_resource_info->teid_range  = 0;

	if( up_ip_resource_info->assoni == 1)
		up_ip_resource_info->ntwk_inst  = 1;

	up_ip_resource_info->user_plane_ip_rsrc_info_spare2  = 0;
	if( up_ip_resource_info->assosi ) {
		switch (app.spgw_cfg) {
			case SGWU :
				if (i == 0 && up_ip_resource_info->v4 == 1 ) {
					up_ip_resource_info->src_intfc  =
									SOURCE_INTERFACE_VALUE_ACCESS; /*UL*/
					/* TODO: Revisit this for change in yang */
					up_ip_resource_info->ipv4_address = htonl(app.s1u_ip);
				}
				if (i == 1 && up_ip_resource_info->v4 == 1 ){
					up_ip_resource_info->src_intfc  =
									SOURCE_INTERFACE_VALUE_CORE; /*DL*/
					/* TODO: Revisit this for change in yang */
					up_ip_resource_info->ipv4_address =htonl (app.s5s8_sgwu_ip);
				}
				break;
			case PGWU :
				if (i == 0 && up_ip_resource_info->v4 == 1 ) {
					up_ip_resource_info->src_intfc  =
									SOURCE_INTERFACE_VALUE_ACCESS; /*DL*/

					up_ip_resource_info->ipv4_address = htonl(app.s5s8_pgwu_ip);
				}
				break;

			case SAEGWU :
				if (i == 0 && up_ip_resource_info->v4 == 1 ) {
					up_ip_resource_info->src_intfc  =
									SOURCE_INTERFACE_VALUE_ACCESS; /*UL*/

					/* TODO: Revisit this for change in yang */
					up_ip_resource_info->ipv4_address = htonl(app.s1u_ip);
				}
				break;

			default :
				printf("default pfcp asso req\n");
				break;
		}
	}
}

void
set_bar_id(pfcp_bar_id_ie_t *bar_id)
{
	pfcp_set_ie_header(&(bar_id->header), PFCP_IE_BAR_ID, UINT8_SIZE);
	bar_id->bar_id_value = 1;
}

void
set_dl_data_notification_delay(pfcp_dnlnk_data_notif_delay_ie_t *dl_data_notification_delay)
{
	pfcp_set_ie_header(&(dl_data_notification_delay->header),
			PFCP_IE_DNLNK_DATA_NOTIF_DELAY, UINT8_SIZE);

	dl_data_notification_delay->delay_val_in_integer_multiples_of_50_millisecs_or_zero= 123;
}

void
set_sgstd_buff_pkts_cnt( pfcp_suggstd_buf_pckts_cnt_ie_t *sgstd_buff_pkts_cnt)
{
	pfcp_set_ie_header(&(sgstd_buff_pkts_cnt->header),
			PFCP_IE_DL_BUF_SUGGSTD_PCKT_CNT,UINT8_SIZE);
	sgstd_buff_pkts_cnt->pckt_cnt_val = 121;
}

void
set_pdr_id( pfcp_pdr_id_ie_t *pdr_id )
{
	pfcp_set_ie_header(&(pdr_id->header), PFCP_IE_PDR_ID, UINT16_SIZE);
	pdr_id->rule_id = 2;
}

void
set_far_id(pfcp_far_id_ie_t *far_id)
{
	pfcp_set_ie_header(&(far_id->header), PFCP_IE_FAR_ID, UINT32_SIZE);
	far_id->far_id_value = 2;

}
void
set_urr_id(pfcp_urr_id_ie_t *urr_id)
{
	pfcp_set_ie_header(&(urr_id->header), PFCP_IE_URR_ID, UINT32_SIZE);
	urr_id->urr_id_value = 3;
}
void
set_precedence( pfcp_precedence_ie_t *prec )
{
	pfcp_set_ie_header(&(prec->header), PFCP_IE_PRECEDENCE, UINT32_SIZE);
	prec->prcdnc_val = 1;
}
void
set_outer_hdr_removal(pfcp_outer_hdr_removal_ie_t *out_hdr_rem)
{
	pfcp_set_ie_header(&(out_hdr_rem->header), PFCP_IE_OUTER_HDR_REMOVAL,
			 UINT8_SIZE);

	/* TODO: Revisit this for change in yang */
	out_hdr_rem->outer_hdr_removal_desc = 0;
	/* TODO: Revisit this for change in yang */
	//out_hdr_rem->gtpu_ext_hdr_del = 0;
	//	PFCP_IE_OUTER_HDR_REMOVAL;// OUTER_HEADER_REMOVAL_DESCRIPTION_GTP_U_UDP_IPV4;

}
void
set_application_id(pfcp_application_id_ie_t *app_id)
{
	int j =1;
	pfcp_set_ie_header(&(app_id->header), PFCP_IE_APPLICATION_ID,
			sizeof(pfcp_application_id_ie_t) - sizeof(pfcp_ie_header_t));

	/* TODO: Revisit this for change in yang */
	for(int i = 0 ;i < 8 ; i++)
		app_id->app_ident[i] = j++;

}

void
set_source_intf(pfcp_src_intfc_ie_t *src_intf)
{
	pfcp_set_ie_header(&(src_intf->header), PFCP_IE_SRC_INTFC, (sizeof(pfcp_src_intfc_ie_t) - sizeof(pfcp_ie_header_t)));
	src_intf->src_intfc_spare = 0;
	src_intf->interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
}

void
set_pdi(pfcp_pdi_ie_t *pdi)
{
	/* TODO: Revisit this for change in yang */
	/*TODO: REmove hardcoded value of length*/
	pfcp_set_ie_header(&(pdi->header), IE_PDI, 69);
			//sizeof(pfcp_pdi_ie_t) - sizeof(pfcp_ie_header_t) -18);
	set_source_intf(&(pdi->src_intfc));
	set_fteid(&(pdi->local_fteid));
	set_network_instance(&(pdi->ntwk_inst));
	set_ue_ip(&(pdi->ue_ip_address));
	set_traffic_endpoint(&(pdi->traffic_endpt_id));
	set_application_id(&(pdi->application_id));
	set_ethernet_pdu_sess_info(&(pdi->eth_pdu_sess_info));
	set_framed_routing(&(pdi->framed_routing));
}

void
set_activate_predefined_rules(pfcp_actvt_predef_rules_ie_t *act_predef_rule)
{

	pfcp_set_ie_header(&(act_predef_rule->header),PFCP_IE_ACTVT_PREDEF_RULES,
						sizeof(pfcp_actvt_predef_rules_ie_t) - sizeof(pfcp_ie_header_t));
	memcpy(&(act_predef_rule->predef_rules_nm), "PCC_RULE",8);
}
void
creating_pdr(pfcp_create_pdr_ie_t *create_pdr)
{

	/*Substracting 21
	 * 18: As we are not using IPv6
	 * 3: Remove the counter*/

//	create_pdr->urr_id_count = 1;
//	create_pdr->qer_id_count = 1;
//	create_pdr->actvt_predef_rules_count = 1;
/*
	int size = sizeof(pfcp_create_pdr_ie_t) - sizeof(pfcp_ie_header_t) -
		((MAX_LIST_SIZE - create_pdr->urr_id_count) * sizeof(pfcp_urr_id_ie_t)) -
		((MAX_LIST_SIZE - create_pdr->qer_id_count) * sizeof(pfcp_qer_id_ie_t)) -
		((MAX_LIST_SIZE - create_pdr->actvt_predef_rules_count) * sizeof(pfcp_actvt_predef_rules_ie_t)) - 21;
*/

	/*TODO: Remove hardcoded value of pdr length*/
	pfcp_set_ie_header(&(create_pdr->header), IE_CREATE_PDR, 128);
				//sizeof(pfcp_create_pdr_ie_t) - sizeof(pfcp_ie_header_t) -18);
				//sizeof(pfcp_create_pdr_ie_t) - sizeof(pfcp_ie_header_t) -18);

	set_pdr_id(&(create_pdr->pdr_id));
	set_precedence(&(create_pdr->precedence));
	set_pdi(&(create_pdr->pdi));
	set_outer_hdr_removal(&(create_pdr->outer_hdr_removal));
	set_far_id(&(create_pdr->far_id));

	/* TODO: Revisit this for change in yang */
	create_pdr->urr_id_count = 1;
	for(int i=0; i < create_pdr->urr_id_count; i++ ) {
		set_urr_id(&(create_pdr->urr_id[i]));
	}

	/* TODO: Revisit this for change in yang */
	create_pdr->qer_id_count = 1;
	for(int i=0; i < create_pdr->qer_id_count; i++ ) {
		set_qer_id(&(create_pdr->qer_id[i]));
		}
	/* TODO: Revisit this for change in yang */

	create_pdr->actvt_predef_rules_count = 1;
	for(int i=0; i < create_pdr->actvt_predef_rules_count; i++ ) {
		set_activate_predefined_rules(&(create_pdr->actvt_predef_rules[i]));
		}

}

void
creating_bar(pfcp_create_bar_ie_t *create_bar)
{
	pfcp_set_ie_header(&(create_bar->header), IE_CREATE_BAR,
			sizeof(pfcp_create_bar_ie_t) - sizeof(pfcp_ie_header_t));

	set_bar_id(&(create_bar->bar_id));
	set_dl_data_notification_delay(&(create_bar->dnlnk_data_notif_delay));
	set_sgstd_buff_pkts_cnt(&(create_bar->suggstd_buf_pckts_cnt));
}

void
set_fq_csid(pfcp_fqcsid_ie_t *fq_csid,uint32_t nodeid_value)
{
	fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;
	//TODO identify the number of CSID
	fq_csid->number_of_csids = 1;
	memcpy(&(fq_csid->node_address), &nodeid_value, IPV4_SIZE);

	for(int i = 0; i < fq_csid->number_of_csids ;i++)
		fq_csid->pdn_conn_set_ident[i] = htons(pdn_conn_set_id++);
	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID,2*(fq_csid->number_of_csids) + 5);

}

void
set_trace_info(pfcp_trc_info_ie_t *trace_info)
{
	//TODO from where we will fil MCC and MNC
	trace_info->mcc_digit_1 = 1;
	trace_info->mcc_digit_2 = 2;
	trace_info->mcc_digit_3 = 3;
	trace_info->mnc_digit_1 = 4;
	trace_info->mnc_digit_2 = 5;
	trace_info->mnc_digit_3 = 6;
	trace_info->trace_id  = 11231;
	trace_info->len_of_trigrng_evnts= 1;
	trace_info->trigrng_evnts  = 1;
	trace_info->sess_trc_depth = 1;
	trace_info->len_of_list_of_intfcs = 1 ;
	trace_info->list_of_intfcs = 1;
	trace_info->len_of_ip_addr_of_trc_coll_ent = 1;

	uint32_t ipv4 = htonl(32);
	memcpy(&(trace_info->ip_addr_of_trc_coll_ent), &ipv4, IPV4_SIZE);
	//trace_info->ip_address_of_trace_collection_entity[0] = 92;
	uint32_t length = trace_info->len_of_trigrng_evnts=+
		trace_info->len_of_list_of_intfcs+
					trace_info->len_of_ip_addr_of_trc_coll_ent + 14  ;

	//As Wireshark donot have spare so reducing size with 1 byte
	pfcp_set_ie_header(&(trace_info->header), PFCP_IE_TRC_INFO, length);
}

void
set_up_inactivity_timer(pfcp_user_plane_inact_timer_ie_t *up_inact_timer)
{
	//pfcp_set_ie_header(&(up_inact_timer->header),IE_USER_PLANE_INACTIVITY_TIMER ,4);
	pfcp_set_ie_header(&(up_inact_timer->header), PFCP_IE_USER_PLANE_INACT_TIMER,
			UINT32_SIZE);
	//TODO , check the report from DP and value inact_timer accordingly 8.2.83
	up_inact_timer->user_plane_inact_timer = 10;
}
void
set_user_id(pfcp_user_id_ie_t *user_id)
{
	user_id->user_id_spare   = 0;
	user_id->naif    = 0;
	user_id->msisdnf = 0;
	user_id->imeif   = 0;
	user_id->imsif   = 1;
	user_id->length_of_imsi   = 8;
	user_id->length_of_imei   = 0;
	user_id->len_of_msisdn = 0;
	user_id->length_of_nai    = 0;

	user_id->imsi[0] = 0x77;
	user_id->imsi[1] = 0x77;
	user_id->imsi[2] = 0x77;
	user_id->imsi[3] = 0x77;
	user_id->imsi[4] = 0x77;
	user_id->imsi[5] = 0x77;
	user_id->imsi[6] = 0x77;
	user_id->imsi[7] = 0xf7;

	//pfcp_set_ie_header(&(user_id->header),IE_USER_ID , length);
	pfcp_set_ie_header(&(user_id->header), PFCP_IE_USER_ID , 10);
}

void
set_fseid(pfcp_fseid_ie_t *fseid,uint64_t seid, uint32_t nodeid_value)
{

	fseid->fseid_spare  = 0;
	fseid->fseid_spare2 = 0;
	fseid->fseid_spare3 = 0;
	fseid->fseid_spare4 = 0;
	fseid->fseid_spare5 = 0;
	fseid->fseid_spare6 = 0;
	fseid->v4     = 1;
	fseid->v6     = 0;
	fseid->seid   = seid;
	memcpy(&(fseid->ipv4_address), &nodeid_value, IPV4_SIZE);

	fseid->ipv6_address[0] = 0;

	int size = sizeof(pfcp_fseid_ie_t) - (PFCP_IE_HDR_SIZE + IPV6_ADDRESS_LEN );
	pfcp_set_ie_header(&(fseid->header), PFCP_IE_FSEID, size);

}

void
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val)
{
	pfcp_set_ie_header(&(cause->header), PFCP_IE_CAUSE, UINT8_SIZE);
	cause->cause_value = cause_val;  /*CAUSE_VALUES_REQUESTACCEPTEDSUCCESS;*/
}

void
removing_bar( pfcp_remove_bar_ie_t *remove_bar)
{
	pfcp_set_ie_header(&(remove_bar->header), IE_REMOVE_BAR, sizeof(pfcp_bar_id_ie_t));
	set_bar_id(&(remove_bar->bar_id));
}
void
set_traffic_endpoint(pfcp_traffic_endpt_id_ie_t *traffic_endpoint_id)
{
	pfcp_set_ie_header(&(traffic_endpoint_id->header), PFCP_IE_TRAFFIC_ENDPT_ID, UINT8_SIZE);
	traffic_endpoint_id->traffic_endpt_id_val = 2;

}
void
removing_traffic_endpoint(pfcp_rmv_traffic_endpt_ie_t *remove_traffic_endpoint)
{
	pfcp_set_ie_header(&(remove_traffic_endpoint->header),
				IE_RMV_TRAFFIC_ENDPT, sizeof(pfcp_traffic_endpt_id_ie_t));

	set_traffic_endpoint(&(remove_traffic_endpoint->traffic_endpt_id));

}
void
set_fteid( pfcp_fteid_ie_t *local_fteid)
{
	pfcp_set_ie_header(&(local_fteid->header), PFCP_IE_FTEID, 9);
			//sizeof(pfcp_fteid_ie_t) - (PFCP_IE_HDR_SIZE + IPV6_SIZE +UINT8_SIZE));
	local_fteid->fteid_spare = 0;
	local_fteid->chid = 0;
	local_fteid->ch = 0;
	local_fteid->v6 = 0;
	local_fteid->v4 = 1;
	local_fteid->teid = 1231;
	uint32_t ipv4 = htonl(3232236600);
	memcpy(&(local_fteid->ipv4_address), &ipv4, IPV4_SIZE);

	//local_fteid->choose_id = 12;
}
void
set_network_instance(pfcp_ntwk_inst_ie_t *network_instance)
{
	pfcp_set_ie_header(&(network_instance->header), PFCP_IE_NTWK_INST, 8);
	network_instance->ntwk_inst[0] = 1;
	network_instance->ntwk_inst[1] = 1;
	network_instance->ntwk_inst[2] = 1;
	network_instance->ntwk_inst[3] = 1;
	network_instance->ntwk_inst[4] = 1;
	network_instance->ntwk_inst[5] = 1;
	network_instance->ntwk_inst[6] = 1;
	network_instance->ntwk_inst[7] = 1;
}
void
set_ue_ip(pfcp_ue_ip_address_ie_t *ue_ip)
{
	pfcp_set_ie_header(&(ue_ip->header), PFCP_IE_UE_IP_ADDRESS, 5);
		//	sizeof(pfcp_ue_ip_address_ie_t)-(PFCP_IE_HDR_SIZE + IPV6_SIZE+ UINT8_SIZE));
	ue_ip->ue_ip_addr_spare = 0;
	ue_ip->ipv6d = 0;
	ue_ip->sd = 0;
	ue_ip->v4 = 1;
	ue_ip->v6 = 0;
	uint32_t ipv4 = htonl(3232236600);
	memcpy(&(ue_ip->ipv4_address), &ipv4, IPV4_SIZE);
}
void
set_ethernet_pdu_sess_info( pfcp_eth_pdu_sess_info_ie_t *eth_pdu_sess_info)
{
	pfcp_set_ie_header(&(eth_pdu_sess_info->header),
			PFCP_IE_ETH_PDU_SESS_INFO, UINT8_SIZE);
	eth_pdu_sess_info->eth_pdu_sess_info_spare = 0;
	eth_pdu_sess_info->ethi = 1;
}

void
set_framed_routing(pfcp_framed_routing_ie_t *framedrouting)
{
	pfcp_set_ie_header(&(framedrouting->header), PFCP_IE_FRAMED_ROUTING, 4);

	framedrouting->framed_routing= 2;
	//framedrouting->framed_routing[1] = 2;
	//framedrouting->framed_routing[2] = 2;
	//framedrouting->framed_routing[3] = 2;
	//framedrouting->framed_routing[4] = 2;
	//framedrouting->framed_routing[5] = 2;
	//framedrouting->framed_routing[6] = 2;
	//framedrouting->framed_routing[7] = 2;

}
void
set_qer_id(pfcp_qer_id_ie_t *qer_id)
{

	pfcp_set_ie_header(&(qer_id->header), PFCP_IE_QER_ID, UINT32_SIZE);
	qer_id->qer_id_value = 33424;
}
void
set_qer_correl_id(pfcp_qer_corr_id_ie_t *qer_correl_id)
{
	pfcp_set_ie_header(&(qer_correl_id->header),PFCP_IE_QER_CORR_ID,
			UINT32_SIZE);
	qer_correl_id->qer_corr_id_val = 1231;
}

void
set_gate_status( pfcp_gate_status_ie_t *gate_status)
{
	pfcp_set_ie_header(&(gate_status->header), PFCP_IE_GATE_STATUS,
			UINT8_SIZE);
	gate_status->gate_status_spare = 0;
	gate_status->ul_gate = UL_GATE_OPEN;
	gate_status->ul_gate = DL_GATE_OPEN;
}

void
set_mbr(pfcp_mbr_ie_t *mbr)
{
	pfcp_set_ie_header(&(mbr->header), PFCP_IE_MBR, BITRATE_SIZE);
	mbr->ul_mbr =1;
	mbr->dl_mbr =1;
}

void
set_gbr(pfcp_gbr_ie_t *gbr)
{
	pfcp_set_ie_header(&(gbr->header), PFCP_IE_GBR, BITRATE_SIZE);
	gbr->ul_gbr =1;
	gbr->dl_gbr =1;
}

void
set_packet_rate(pfcp_packet_rate_ie_t *pkt_rate)
{
	pkt_rate->pckt_rate_spare = 0;
	pkt_rate->dlpr = 1;
	pkt_rate->ulpr = 1;
	pkt_rate->pckt_rate_spare2 = 0;
	pkt_rate->uplnk_time_unit =  UPLINKDOWNLINK_TIME_UNIT_MINUTE;
	pkt_rate->max_uplnk_pckt_rate = 2;
	pkt_rate->pckt_rate_spare3 = 0;
	pkt_rate->dnlnk_time_unit = UPLINKDOWNLINK_TIME_UNIT_MINUTE;
	pkt_rate->max_dnlnk_pckt_rate = 2;
	pfcp_set_ie_header(&(pkt_rate->header), PFCP_IE_PACKET_RATE,
			sizeof(pfcp_packet_rate_ie_t) - PFCP_IE_HDR_SIZE);
}

void
set_dl_flow_level_mark(pfcp_dl_flow_lvl_marking_ie_t *dl_flow_level_marking)
{
	dl_flow_level_marking->dl_flow_lvl_marking_spare = 0;
	dl_flow_level_marking->sci = 1;
	dl_flow_level_marking->ttc = 1;
	dl_flow_level_marking->tostraffic_cls = 12;
	dl_flow_level_marking->svc_cls_indctr =1;
	pfcp_set_ie_header(&(dl_flow_level_marking->header),
		PFCP_IE_DL_FLOW_LVL_MARKING, sizeof(pfcp_dl_flow_lvl_marking_ie_t)-PFCP_IE_HDR_SIZE);
}

void
set_qfi(pfcp_qfi_ie_t *qfi)
{
	qfi->qfi_spare = 0;
	qfi->qfi_value = 3;
	pfcp_set_ie_header(&(qfi->header), PFCP_IE_QFI,UINT8_SIZE);
}
void
set_rqi(pfcp_rqi_ie_t *rqi)
{
	rqi->rqi_spare = 0;
	rqi->rqi = 0;
	pfcp_set_ie_header(&(rqi->header), PFCP_IE_RQI,UINT8_SIZE);
}
void
updating_qer(pfcp_update_qer_ie_t *up_qer)
{
	//set qer id
	set_qer_id(&(up_qer->qer_id));

	//set qer correlation id
	set_qer_correl_id(&(up_qer->qer_corr_id));

	//set gate status
	set_gate_status(&(up_qer->gate_status));

	//set mbr
	set_mbr(&(up_qer->maximum_bitrate));

	//set gbr
	set_gbr(&(up_qer->guaranteed_bitrate));

	//set packet rate
	set_packet_rate(&(up_qer->packet_rate));

	//set dl flow level
	set_dl_flow_level_mark(&(up_qer->dl_flow_lvl_marking));

	//set qfi
	set_qfi(&(up_qer->qos_flow_ident));

	//set rqi
	set_rqi(&(up_qer->reflective_qos));
	uint8_t size = 79;
	//sizeof(pfcp_update_qer_ie_t) - sizeof(pfcp_ie_header_t) - 12;
	pfcp_set_ie_header(&(up_qer->header), IE_UPDATE_QER,size);
}

void
creating_traffic_endpoint(pfcp_create_traffic_endpt_ie_t  *create_traffic_endpoint)
{
	//set traffic endpoint id
	set_traffic_endpoint(&(create_traffic_endpoint->traffic_endpt_id));

	//set local fteid
	set_fteid(&(create_traffic_endpoint->local_fteid));

	//set network isntance
	set_network_instance(&(create_traffic_endpoint->ntwk_inst));

	//set ue ip address
	set_ue_ip(&(create_traffic_endpoint->ue_ip_address));

	//set ethernet pdu session info
	set_ethernet_pdu_sess_info(&(create_traffic_endpoint->eth_pdu_sess_info));

	//set framed routing
	set_framed_routing(&(create_traffic_endpoint->framed_routing));

	uint16_t size = sizeof(pfcp_traffic_endpt_id_ie_t) +
			sizeof(pfcp_fteid_ie_t) +sizeof(pfcp_ntwk_inst_ie_t) +

	sizeof(pfcp_ue_ip_address_ie_t) + sizeof(pfcp_eth_pdu_sess_info_ie_t) +
	sizeof(pfcp_framed_routing_ie_t);
	size = size - 18;
	pfcp_set_ie_header(&(create_traffic_endpoint->header),
							IE_CREATE_TRAFFIC_ENDPT, size);
}
void
updating_bar( pfcp_upd_bar_sess_mod_req_ie_t *up_bar)
{
	set_bar_id(&(up_bar->bar_id));
	set_dl_data_notification_delay(&(up_bar->dnlnk_data_notif_delay));
	set_sgstd_buff_pkts_cnt(&(up_bar->suggstd_buf_pckts_cnt));

	uint8_t size =  sizeof(pfcp_bar_id_ie_t) + sizeof(pfcp_dnlnk_data_notif_delay_ie_t)+
	sizeof(pfcp_suggstd_buf_pckts_cnt_ie_t);
	pfcp_set_ie_header(&(up_bar->header), IE_UPD_BAR_SESS_MOD_REQ, size);
}

void
updating_traffic_endpoint(pfcp_upd_traffic_endpt_ie_t *up_traffic_endpoint)
{
	set_traffic_endpoint(&(up_traffic_endpoint->traffic_endpt_id));
	set_fteid(&(up_traffic_endpoint->local_fteid));
	set_network_instance(&(up_traffic_endpoint->ntwk_inst));
	set_ue_ip(&(up_traffic_endpoint->ue_ip_address));
	set_framed_routing(&(up_traffic_endpoint->framed_routing));

	uint8_t size = sizeof(pfcp_traffic_endpt_id_ie_t) + sizeof(pfcp_fteid_ie_t) +
			sizeof(pfcp_ntwk_inst_ie_t) + sizeof(pfcp_ue_ip_address_ie_t) +
			sizeof(pfcp_framed_routing_ie_t);
	size = size - (2*IPV6_SIZE) - 2;
	pfcp_set_ie_header(&(up_traffic_endpoint->header),
								IE_UPD_TRAFFIC_ENDPT, size);

}

void
set_pfcpsmreqflags(pfcp_pfcpsmreq_flags_ie_t *pfcp_sm_req_flags)
{
	pfcp_set_ie_header(&(pfcp_sm_req_flags->header),
						PFCP_IE_PFCPSMREQ_FLAGS,UINT8_SIZE);

	pfcp_sm_req_flags->pfcpsmreq_flgs_spare = 0;
	pfcp_sm_req_flags->pfcpsmreq_flgs_spare2 = 0;
	pfcp_sm_req_flags->pfcpsmreq_flgs_spare3 = 0;
	pfcp_sm_req_flags->pfcpsmreq_flgs_spare4 = 0;
	pfcp_sm_req_flags->pfcpsmreq_flgs_spare5 = 0;
	pfcp_sm_req_flags->qaurr = 0;
	pfcp_sm_req_flags->sndem = 0;
	pfcp_sm_req_flags->drobu = 0;
}

void
set_query_urr_refernce( pfcp_query_urr_ref_ie_t *query_urr_ref)
{
	pfcp_set_ie_header(&(query_urr_ref->header),
					PFCP_IE_QUERY_URR_REF,UINT32_SIZE);
	query_urr_ref->query_urr_ref_val = 3;

}

void
set_pfcp_ass_rel_req(pfcp_up_assn_rel_req_ie_t *ass_rel_req)
{

	pfcp_set_ie_header(&(ass_rel_req->header),
			PFCP_IE_UP_ASSN_REL_REQ, UINT8_SIZE);
	ass_rel_req->up_assn_rel_req_spare = 0;
	ass_rel_req->sarr = 0;
}

void
set_graceful_release_period(pfcp_graceful_rel_period_ie_t *graceful_rel_period)
{
	pfcp_set_ie_header(&(graceful_rel_period->header),
						PFCP_IE_GRACEFUL_REL_PERIOD,UINT8_SIZE);
	graceful_rel_period->timer_unit =
				GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;

	graceful_rel_period->timer_value = 1;

}

void
set_sequence_num(pfcp_sequence_number_ie_t *seq)
{
	pfcp_set_ie_header(&(seq->header), PFCP_IE_SEQUENCE_NUMBER, UINT32_SIZE);
	seq->sequence_number = 12;
}

void
set_metric(pfcp_metric_ie_t *metric)
{
	pfcp_set_ie_header(&(metric->header), PFCP_IE_METRIC, UINT8_SIZE);
	metric->metric = 2;
}

void
set_period_of_validity(pfcp_timer_ie_t *pov)
{
	pfcp_set_ie_header(&(pov->header), PFCP_IE_TIMER, UINT8_SIZE);
	pov->timer_unit =
		TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS ;
	pov->timer_value = 20;
}
void
set_oci_flag( pfcp_oci_flags_ie_t *oci)
{
	pfcp_set_ie_header(&(oci->header), PFCP_IE_OCI_FLAGS, UINT8_SIZE);
	oci->oci_flags_spare = 0;
	oci->aoci = 1;
}

void
set_offending_ie( pfcp_offending_ie_ie_t *offending_ie, int offend_val)
{
	pfcp_set_ie_header(&(offending_ie->header), PFCP_IE_OFFENDING_IE, UINT16_SIZE);
	offending_ie->type_of_the_offending_ie = offend_val;
}

void
set_lci(pfcp_load_ctl_info_ie_t *lci)
{
	pfcp_set_ie_header(&(lci->header),IE_LOAD_CTL_INFO,
			sizeof(pfcp_sequence_number_ie_t) + sizeof(pfcp_metric_ie_t));
	set_sequence_num(&(lci->load_ctl_seqn_nbr));
	set_metric(&(lci->load_metric));
}

void
set_olci(pfcp_ovrld_ctl_info_ie_t *olci)
{
	pfcp_set_ie_header(&(olci->header), IE_OVRLD_CTL_INFO,
			sizeof(pfcp_sequence_number_ie_t) +
			sizeof(pfcp_metric_ie_t)+sizeof(pfcp_timer_ie_t) + sizeof(pfcp_oci_flags_ie_t));

	set_sequence_num(&(olci->ovrld_ctl_seqn_nbr));
	set_metric(&(olci->ovrld_reduction_metric));
	set_period_of_validity(&(olci->period_of_validity));
	set_oci_flag(&(olci->ovrld_ctl_info_flgs));
}

void
set_failed_rule_id(pfcp_failed_rule_id_ie_t *rule)
{
	pfcp_set_ie_header(&(rule->header), PFCP_IE_FAILED_RULE_ID, 3);
	rule->failed_rule_id_spare = 0;
	rule ->rule_id_type = RULE_ID_TYPE_PDR;
	//rule->rule_id_value = 2;
	rule->rule_id_value[1] = 2;
}

void
set_traffic_endpoint_id(pfcp_traffic_endpt_id_ie_t *tnp)
{
	pfcp_set_ie_header(&(tnp->header), PFCP_IE_TRAFFIC_ENDPT_ID, UINT8_SIZE);
	tnp->traffic_endpt_id_val = 12;
}
void set_pdr_id_ie(pfcp_pdr_id_ie_t *pdr)
{
	pfcp_set_ie_header(&(pdr->header), PFCP_IE_PDR_ID,
			sizeof(pfcp_pdr_id_ie_t) - PFCP_IE_HDR_SIZE );
	pdr->rule_id = 12;  //Need to check value
}
void set_created_pdr_ie(pfcp_created_pdr_ie_t *pdr)
{

	//pfcp_set_ie_header(&(pdr->header),IE_CREATED_PDR,sizeof(pfcp_created_pdr_ie_t)-4);
	pfcp_set_ie_header(&(pdr->header), IE_CREATED_PDR, 19);
	set_pdr_id_ie(&(pdr->pdr_id));
	set_fteid(&(pdr->local_fteid));

}

void set_created_traffic_endpoint(pfcp_created_traffic_endpt_ie_t *cte)
{
	//pfcp_set_ie_header(&(cte->header),IE_CREATE_TRAFFIC_ENDPOINT,sizeof(pfcp_created_traffic_endpt_ie_t)-4);
	pfcp_set_ie_header(&(cte->header), IE_CREATE_TRAFFIC_ENDPT, 18);
	set_traffic_endpoint_id(&(cte->traffic_endpt_id));
	set_fteid(&(cte->local_fteid));

}

void set_additional_usage(pfcp_add_usage_rpts_info_ie_t *adr)
{
	//pfcp_set_ie_header(&(adr->header),IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,sizeof(pfcp_add_usage_rpts_info_ie_t)-4);
	pfcp_set_ie_header(&(adr->header), PFCP_IE_ADD_USAGE_RPTS_INFO,
			UINT16_SIZE);
	adr->auri = 0;
	adr->nbr_of_add_usage_rpts_val = 12;
}
void
set_node_report_type( pfcp_node_rpt_type_ie_t *nrt)
{
	pfcp_set_ie_header(&(nrt->header), PFCP_IE_NODE_RPT_TYPE, UINT8_SIZE);
	nrt->node_rpt_type_spare = 0;
	nrt->upfr = 0;
}

void
set_remote_gtpu_peer_ip( pfcp_rmt_gtpu_peer_ie_t *remote_gtpu_peer)
{

	pfcp_set_ie_header(&(remote_gtpu_peer->header), PFCP_IE_RMT_GTPU_PEER,
			sizeof(pfcp_rmt_gtpu_peer_ie_t) - (IPV6_SIZE+PFCP_IE_HDR_SIZE));
	remote_gtpu_peer->v4 = 1;
	remote_gtpu_peer->v6 = 0;
	uint32_t ipv4 = htonl(3211236600);
	memcpy(&(remote_gtpu_peer->ipv4_address), &ipv4, IPV4_SIZE);
}
void
set_user_plane_path_failure_report(pfcp_user_plane_path_fail_rpt_ie_t *uppfr)
{
	pfcp_set_ie_header(&(uppfr->header), IE_USER_PLANE_PATH_FAIL_RPT,
			sizeof(pfcp_rmt_gtpu_peer_ie_t));
	//set remote gtpu peer
	uppfr->rmt_gtpu_peer_count = 2;
	for(int i=0; i < uppfr->rmt_gtpu_peer_count; i++ )
		set_remote_gtpu_peer_ip(&(uppfr->rmt_gtpu_peer[i]));

}

void cause_check_association(pfcp_assn_setup_req_t *pfcp_ass_setup_req,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id = REQUESTACCEPTED ;
	*offend_id = 0;

	if(!(pfcp_ass_setup_req->node_id.header.len)){
		*cause_id = MANDATORYIEMISSING;
		*offend_id = PFCP_IE_NODE_ID;
	} else {

		if (pfcp_ass_setup_req->node_id.node_id_type == IPTYPE_IPV4) {
				if (NODE_ID_IPV4_LEN != pfcp_ass_setup_req->node_id.header.len) {
					*cause_id = INVALIDLENGTH;
				}
		}
		if (pfcp_ass_setup_req->node_id.node_id_type == IPTYPE_IPV6) {
				if (NODE_ID_IPV6_LEN != pfcp_ass_setup_req->node_id.header.len) {
					*cause_id = INVALIDLENGTH;
				}
		}

		//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if (!(pfcp_ass_setup_req->rcvry_time_stmp.header.len)) {

		*cause_id = MANDATORYIEMISSING;
		*offend_id =PFCP_IE_RCVRY_TIME_STMP;
	} else if(pfcp_ass_setup_req->rcvry_time_stmp.header.len != RECOV_TIMESTAMP_LEN){

		*cause_id = INVALIDLENGTH;
	}

	if (!(pfcp_ass_setup_req->cp_func_feat.header.len)) {

		*cause_id = CONDITIONALIEMISSING;
		*offend_id = PFCP_IE_CP_FUNC_FEAT ;
	} else if (pfcp_ass_setup_req->cp_func_feat.header.len != CP_FUNC_FEATURES_LEN) {

		*cause_id = INVALIDLENGTH;
	}
}


void cause_check_sess_estab(pfcp_sess_estab_req_t *pfcp_session_request,
				 uint8_t *cause_id, int *offend_id)
{
	*cause_id  = REQUESTACCEPTED;
	*offend_id = 0;

	if(!(pfcp_session_request->node_id.header.len)) {

		*offend_id = PFCP_IE_NODE_ID;
		*cause_id = MANDATORYIEMISSING;

	} else {

		 if (pfcp_session_request->node_id.node_id_type == IPTYPE_IPV4) {
				 if (NODE_ID_IPV4_LEN != pfcp_session_request->node_id.header.len) {
					*cause_id = INVALIDLENGTH;
				 }
		 }
		 if (pfcp_session_request->node_id.node_id_type == IPTYPE_IPV6) {
			 if (NODE_ID_IPV6_LEN != pfcp_session_request->node_id.header.len) {
				 *cause_id = INVALIDLENGTH;
			 }
		 }
		 //*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_request->cp_fseid.header.len)){

		*offend_id = PFCP_IE_FSEID;
		*cause_id = MANDATORYIEMISSING;


	} else if (pfcp_session_request->cp_fseid.header.len != CP_FSEID_LEN) {

		*cause_id = INVALIDLENGTH;
	}

	/*if(!(pfcp_session_request->pgwc_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;

	} else if(pfcp_session_request->pgwc_fqcsid.header.len != PGWC_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;

	}*/

	if(!(pfcp_session_request->sgw_c_fqcsid.header.len)) {

		*cause_id = CONDITIONALIEMISSING;
		*offend_id =PFCP_IE_FQCSID;

	} else if(pfcp_session_request->sgw_c_fqcsid.header.len != SGWC_FQCSID_LEN) {
		*cause_id = INVALIDLENGTH;
	}

	/*if(!(pfcp_session_request->mme_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if(pfcp_session_request->mme_fqcsid.header.len != MME_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_request->epdg_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if(pfcp_session_request->epdg_fqcsid.header.len != EPDG_FQCSID_LEN ) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if(!(pfcp_session_request->twan_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if (pfcp_session_request->twan_fqcsid.header.len != TWAN_FQCSID_LEN ) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if (pfcp_session_request->sgwc_fqcsid.fq_csid_node_id_type == IPTYPE_IPV4 ) {
		if(29 != (pfcp_session_request->sgwc_fqcsid.header.len)) {
			*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}
	} else if (pfcp_session_request->sgwc_fqcsid.fq_csid_node_id_type == IPTYPE_IPV6 ) {
		if(33 != (pfcp_session_request->sgwc_fqcsid.header.len)) {
			*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}
	}*/


}

uint8_t
upf_context_entry_add(uint32_t *upf_ip, upf_context_t *entry)
{
	int ret = 0;
	ret = rte_hash_add_key_data(upf_context_by_ip_hash,
			(const void *)upf_ip , (void *)entry);

	if (ret < 0) {
		fprintf(stderr,
				"%s - Error on rte_hash_add_key_data add\n",
				strerror(ret));
		return 1;
	}
	return 0;
}

int
upf_context_entry_lookup(uint32_t upf_ip, upf_context_t **entry)
{
	int ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ip), (void **) entry);

	if (ret < 0) {
		RTE_LOG_DP(DEBUG, DP, "NO ENTRY FOUND IN UPF HASH [%u]\n", upf_ip);
		return -1;
	}

	return 0;
}

uint8_t
add_node_id_hash(uint32_t *nodeid, uint64_t *data )
{
	int ret = 0;
	uint32_t key = UINT32_MAX;
	uint64_t *temp = NULL;
	memcpy(&key ,nodeid, sizeof(uint32_t));

	temp =(uint64_t *) rte_zmalloc_socket(NULL, sizeof(uint64_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (temp == NULL) {
		fprintf(stderr, "Failure to allocate ue context "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return 1;
	}
	*temp = *data;
	ret = rte_hash_add_key_data(node_id_hash,
			(const void *)&key , (void *)temp);
	if (ret < 0) {
		fprintf(stderr,
				"%s - Error on rte_hash_add_key_data add\n",
				strerror(ret));
		rte_free((temp));
		return 1;
	}
	return 0;
}


void
cause_check_sess_modification(pfcp_sess_mod_req_t *pfcp_session_mod_req,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id  = REQUESTACCEPTED;
	*offend_id = 0;

	if(!(pfcp_session_mod_req->cp_fseid.header.len)){
		*cause_id = CONDITIONALIEMISSING;
		*offend_id = PFCP_IE_FSEID;
	} else if (pfcp_session_mod_req->cp_fseid.header.len != CP_FSEID_LEN)
	{
		//TODO: IPV4 consideration only
		*cause_id = INVALIDLENGTH;
	}


	if( pfcp_ctxt.up_supported_features & UP_PDIU ) {
		if(!(pfcp_session_mod_req->rmv_traffic_endpt.header.len)) {

			*cause_id = CONDITIONALIEMISSING;
			*offend_id = IE_RMV_TRAFFIC_ENDPT;
		} else if(pfcp_session_mod_req->rmv_traffic_endpt.header.len !=
				REMOVE_TRAFFIC_ENDPOINT_LEN) {

			//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}


		if(!(pfcp_session_mod_req->create_traffic_endpt.header.len)) {

			*cause_id = CONDITIONALIEMISSING;
			*offend_id = IE_CREATE_TRAFFIC_ENDPT ;
		} else if (pfcp_session_mod_req->create_traffic_endpt.header.len !=
				CREATE_TRAFFIC_ENDPOINT_LEN){
			//TODO:Consdiering IP4
			//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}
	}
	if(!(pfcp_session_mod_req->create_bar.header.len)){

		*cause_id = CONDITIONALIEMISSING;
		*offend_id = IE_CREATE_BAR;
	} else if (pfcp_session_mod_req->create_bar.header.len != CREATE_BAR_LEN) {

		*cause_id = INVALIDLENGTH;
	}

	/*if(!(pfcp_session_mod_req->update_qer.header.len)) {
		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_UPDATE_QER;
	} else if(pfcp_session_mod_req->update_qer.header.len != UPDATE_QER_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}*/

	if(!(pfcp_session_mod_req->update_bar.header.len)) {
		*cause_id = CONDITIONALIEMISSING;
		*offend_id = IE_UPD_BAR_SESS_MOD_REQ;

	} else if(pfcp_session_mod_req->update_bar.header.len != UPDATE_BAR_LEN) {
		//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	/*TODO: There must a different FQCSID flag which is not comming from CP,that is why
	code is commented*/

	/*if(!(pfcp_session_mod_req->update_traffic_endpt.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_UPDATE_TRAFFIC_ENDPOINT;
	} else if (pfcp_session_mod_req->update_traffic_endpoint.header.len != UPDATE_TRAFFIC_ENDPOINT_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if(!(pfcp_session_mod_req->pfcpsmreqflags.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCPSMREQ_FLAGS;
	} else if(pfcp_session_mod_req->pfcpsmreqflags.header.len != PFCP_SEMREQ_FLAG_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if(!(pfcp_session_mod_req->query_urr_reference.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_QUERY_URR_REFERENCE ;
	} else if(pfcp_session_mod_req->query_urr_reference.header.len != QUERY_URR_REFERENCE_LEN){

		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}
	if(!(pfcp_session_mod_req->pgwc_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if(pfcp_session_mod_req->pgwc_fqcsid.header.len != PGWC_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_mod_req->sgwc_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id =IE_PFCP_FQ_CSID;
	} else if(pfcp_session_mod_req->sgwc_fqcsid.header.len != SGWC_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}
	if(!(pfcp_session_mod_req->mme_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if(pfcp_session_mod_req->mme_fqcsid.header.len != MME_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_mod_req->epdg_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if(pfcp_session_mod_req->epdg_fqcsid.header.len != EPDG_FQCSID_LEN ) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_mod_req->twan_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;
	} else if (pfcp_session_mod_req->twan_fqcsid.header.len != TWAN_FQCSID_LEN ) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_mod_req->user_plane_inact_timer.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_USER_PLANE_INACTIVITY_TIMER ;
	} else if(pfcp_session_mod_req->user_plane_inact_timer.header.len != USER_PLANE_INACTIV_TIMER_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}*/
}

void
cause_check_delete_session(pfcp_sess_del_req_t *pfcp_session_delete_req,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id  = REQUESTACCEPTED;
	*offend_id = 0;
	if(!(pfcp_session_delete_req->header.message_len)) {
		*cause_id = MANDATORYIEMISSING;
		*offend_id = PFCP_IE_FSEID;
	} else if(pfcp_session_delete_req->header.message_len !=
			DELETE_SESSION_HEADER_LEN){
		*cause_id = INVALIDLENGTH;
	}
}

int
add_data_to_heartbeat_hash_table(uint32_t *ip, uint32_t *recov_time)
{
	int ret = 0;
	uint32_t key = UINT32_MAX;
	uint32_t *temp = NULL;
	memcpy(&key,ip,UINT32_SIZE);

	temp = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (temp == NULL) {
		fprintf(stderr, "Failure to allocate fseid context "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return 1;
	}
	*temp = *recov_time;
	ret = rte_hash_add_key_data(heartbeat_recovery_hash,
			(const void *) &key, temp);
	if (ret < 0) {
		fprintf(stderr,"%s - Error on rte_hash_add_key_data add in heartbeat\n",
				strerror(ret));
		free(temp);
		return 1;
	}
	return 0;
}

void add_ip_to_heartbeat_hash(struct sockaddr_in *peer_addr, uint32_t recovery_time)
{
	uint32_t *default_recov_time = NULL;
	default_recov_time = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(default_recov_time == NULL) {
		fprintf(stderr, "Failure to allocate memory in adding ip to heartbeat"
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);

	} else {

		*default_recov_time = recovery_time;
		int ret = add_data_to_heartbeat_hash_table( &peer_addr->sin_addr.s_addr ,
				default_recov_time);

		if(ret !=0) {
			fprintf(stderr,"%s - Error on rte_hash_add_key_data add in heartbeat\n",
					strerror(ret));
		}
	}
}


void
create_heartbeat_hash_table(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "recovery_time_hash",
		.entries = 50,
		.key_len = UINT32_SIZE,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	heartbeat_recovery_hash = rte_hash_create(&rte_hash_params);
	if (!heartbeat_recovery_hash) {
		rte_panic("%s heartbeat_recovery_hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void delete_entry_heartbeat_hash(struct sockaddr_in *peer_addr)
{
	int ret = rte_hash_del_key(heartbeat_recovery_hash,
			(const void *)&(peer_addr->sin_addr.s_addr));
	if (ret == -EINVAL || ret == -ENOENT) {
		fprintf(stderr,"%s - Error on rte_delete_enrty_key_data add in heartbeat\n",
				strerror(ret));
	}
}

void clear_heartbeat_hash_table(void)
{
	rte_hash_free(heartbeat_recovery_hash);
}

void
create_upf_context_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "upf_context_by_ip_hash",
	    .entries = UPF_ENTRIES_DEFAULT,
	    .key_len = sizeof(uint32_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	upf_context_by_ip_hash = rte_hash_create(&rte_hash_params);
	if (!upf_context_by_ip_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

void
create_upf_by_ue_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "upflist_by_ue_hash",
	    .entries = BUFFERED_ENTRIES_DEFAULT,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	upflist_by_ue_hash = rte_hash_create(&rte_hash_params);
	if (!upflist_by_ue_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

#ifdef CP_BUILD
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn,pdn_type_ie_t *pdn_mme)
{
	pfcp_set_ie_header(&(pdn->header), PFCP_IE_PDN_TYPE, UINT8_SIZE);
	pdn->pdn_type_spare = 0;
	//pdn->pdn_type = PFCP_PDN_TYPE_NON_IP;
	//TODO :need to check what received from MME
	pdn->pdn_type = pdn_mme->pdn_type;
	//pdn->pdn_type = PFCP_PDN_TYPE_IPV4;
}

int
decode_check_csr(gtpv2c_header *gtpv2c_rx,
		create_session_request_t *csr)
{
	int ret = 0;
	ret = decode_create_session_request_t((uint8_t *) gtpv2c_rx,
			csr);

	if (!ret)
		 return -EPERM;

	if (csr->indication.header.len &&
			csr->indication.indication_value.uimsi) {
		fprintf(stderr, "Unauthenticated IMSI Not Yet Implemented - "
				"Dropping packet\n");
		return -EPERM;
	}

	if ((pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC) &&
			(!csr->s5s8pgw_pmip.header.len)) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (!csr->apn_restriction.header.len
			|| !csr->bearer_context.header.len
			|| !csr->sender_ftied.header.len
			|| !csr->imsi.header.len
			|| !csr->ambr.header.len
			|| !csr->pdn_type.header.len
			|| !csr->bearer_context.bearer_qos.header.len
			|| !(csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV4) ) {
		fprintf(stderr, "Mandatory IE missing. Dropping packet\n");
		return GTPV2C_CAUSE_MANDATORY_IE_MISSING;
	}

	if (csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV6 ||
			csr->pdn_type.pdn_type == PDN_IP_TYPE_IPV4V6) {
			fprintf(stderr, "IPv6 Not Yet Implemented - Dropping packet\n");
			return GTPV2C_CAUSE_PREFERRED_PDN_TYPE_UNSUPPORTED;
	}

	return 0;
}
#endif /* CP_BUILD */

int
upflist_by_ue_hash_entry_add(uint8_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t *entry)
{
	uint64_t imsi = UINT64_MAX;
	memcpy(&imsi, imsi_val, imsi_len);

	/* TODO: Check before adding */
	int ret = rte_hash_add_key_data(upflist_by_ue_hash, &imsi,
			entry);

	if (ret < 0) {
		RTE_LOG_DP(ERR, DP, "Failed to add entry in upflist_by_ue_hash"
				"hash table");
		return -1;
	}

	return 0;
}

int
upflist_by_ue_hash_entry_lookup(uint8_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t **entry)
{
	uint64_t imsi = UINT64_MAX;
	memcpy(&imsi, imsi_val, imsi_len);

	/* TODO: Check before adding */
	int ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi,
			(void **)entry);

	if (ret < 0) {
		RTE_LOG_DP(ERR, DP, "Failed to search entry in upflist_by_ue_hash"
				"hash table");
		return ret;
	}

	return 0;
}
