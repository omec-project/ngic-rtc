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
#include <string.h>
#include <inttypes.h>
#include <ctype.h>

#include <rte_debug.h>
#include <rte_hash.h>
#include <stdint.h>

#include "pfcp_ies.h"
#include "pfcp_set_ie.h"
#include "pfcp_util.h"

/*extern*/
uint32_t start_time;
pfcp_context_t pfcp_ctxt;
extern pfcp_config_t pfcp_config;
const uint64_t pfcp_sgwc_base_seid = 0xC0FFEE;
static uint32_t pfcp_sgwc_seid_offset;
static uint16_t pdn_conn_set_id;
extern struct rte_hash *node_id_hash;
extern struct rte_hash *teid_fseid_hash;
struct rte_hash *heartbeat_recovery_hash;
struct rte_hash *associated_upf_hash;

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
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag,uint32_t seq )
{
	set_pfcp_header(pfcp, type, flag );
	if(flag == HAS_SEID){
		if (pfcp_config.cp_type == SGWC){
			pfcp->seid_seqno.has_seid.seid   = pfcp_sgwc_base_seid + pfcp_sgwc_seid_offset;
			pfcp_sgwc_seid_offset++;
		}
		pfcp->seid_seqno.has_seid.seq_no = seq;
		pfcp->seid_seqno.has_seid.spare  = 0;
		pfcp->seid_seqno.has_seid.message_prio = 0;
	}else if (flag == NO_SEID){
		pfcp->seid_seqno.no_seid.seq_no = seq;
		pfcp->seid_seqno.no_seid.spare  = 0;
	}
}

void
pfcp_set_ie_header(pfcp_ie_header_t *header, uint8_t type,uint16_t length)
{
	header->type = type;
	header->len = length;
}

void
set_node_id(node_id_ie_t *node_id,uint32_t nodeid_value)
{
	node_id->node_id_type = NODE_ID_TYPE_IPV4ADDRESS;
	node_id->node_id_value_len = 4;
	memcpy(node_id->node_id_value, &nodeid_value, node_id->node_id_value_len);
	pfcp_set_ie_header(&(node_id->header), IE_NODE_ID, node_id->node_id_value_len + 1);
}

void
set_recovery_time_stamp(recovery_time_stamp_ie_t *rec_time_stamp)
{
	pfcp_set_ie_header(&(rec_time_stamp->header), IE_RECOVERY_TIME_STAMP,UINT32_SIZE);
	rec_time_stamp->recovery_time_stamp_value = start_time; //uptime();

}

void
set_upf_features(up_function_features_ie_t *upf_feat)
{
	pfcp_set_ie_header(&(upf_feat->header),IE_UP_FUNCTION_FEATURES,UINT16_SIZE);
	//upf_feat->supported_features = ALL_UPF_FEATURES_SUPPORTED;
	upf_feat->supported_features = 0;
}

void
set_cpf_features(cp_function_features_ie_t *cpf_feat)
{
	pfcp_set_ie_header(&(cpf_feat->header),IE_CP_FUNCTION_FEATURES, UINT8_SIZE);
	//cpf_feat->supported_features = ALL_CPF_FEATURES_SUPPORTED;
	cpf_feat->supported_features = 0;
}
void
set_up_ip_resource_info(user_plane_ip_resource_information_ie_t *up_ip_resource_info)
{
	pfcp_set_ie_header(&(up_ip_resource_info->header),IE_UP_IP_RESOURCE_INFORMATION,5);
	up_ip_resource_info->spare  = 0;
	up_ip_resource_info->assosi = 0;
	up_ip_resource_info->assoni = 0;
	up_ip_resource_info->teidri = 0;
	up_ip_resource_info->v6     = 0;
	up_ip_resource_info->v4     = 1;
	up_ip_resource_info->teid_range     = 0;
	if(up_ip_resource_info->v4 == 1)
		up_ip_resource_info->ipv4_address  = htonl(0);
	else
		up_ip_resource_info->ipv6_address  = htonl(0);
	if( up_ip_resource_info->assoni == 1)
		up_ip_resource_info->network_instance  = 1;
	up_ip_resource_info->spare  = 0;
	if( up_ip_resource_info->assosi == 1)
		up_ip_resource_info->source_interface  = 1;

}
void
set_bar_id(bar_id_ie_t *bar_id)
{
	pfcp_set_ie_header(&(bar_id->header),IE_BAR_ID,UINT8_SIZE);
	bar_id->bar_id_value = 1;
}

void
set_dl_data_notification_delay(downlink_data_notification_delay_ie_t *dl_data_notification_delay)
{
	pfcp_set_ie_header(&(dl_data_notification_delay->header),IE_DOWNLINK_DATA_NOTIFICATION_DELAY, UINT8_SIZE);
	dl_data_notification_delay->delay_value_in_integer_multiples_of_50_millisecs_or_zero = 123;
}

void
set_sgstd_buff_pkts_cnt( suggested_buffering_packets_count_ie_t *sgstd_buff_pkts_cnt)
{
	pfcp_set_ie_header(&(sgstd_buff_pkts_cnt->header),IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT,UINT8_SIZE);
	sgstd_buff_pkts_cnt->packet_count_value = 121;
}

void
set_pdr_id(pdr_id_ie_t *pdr_id)
{
	pfcp_set_ie_header(&(pdr_id->header),IE_PDR_ID,UINT16_SIZE);
	pdr_id->rule_id =1;
}

void
set_far_id(far_id_ie_t *far_id)
{
	pfcp_set_ie_header(&(far_id->header),IE_FAR_ID,UINT32_SIZE);
	far_id->far_id_value = 2;

}
void
set_urr_id(urr_id_ie_t *urr_id)
{
	pfcp_set_ie_header(&(urr_id->header),IE_URR_ID,UINT32_SIZE);
	urr_id->urr_id_value = 3;
}
void	
set_precedence(precedence_ie_t *prec)
{
	pfcp_set_ie_header(&(prec->header),IE_PRECEDENCE,UINT32_SIZE);
	prec->precedence_value = 1;
}
void	
set_outer_hdr_removal(outer_header_removal_ie_t *out_hdr_rem)
{
	pfcp_set_ie_header(&(out_hdr_rem->header),IE_OUTER_HEADER_REMOVAL,UINT8_SIZE);
	out_hdr_rem->outer_header_removal_description = OUTER_HEADER_REMOVAL_DESCRIPTION_GTP_U_UDP_IPV4;

}
void
set_application_id(application_id_ie_t *app_id)
{	
	int j =1;
	pfcp_set_ie_header(&(app_id->header), IE_APPLICATION_ID, sizeof(application_id_ie_t) - sizeof(pfcp_ie_header_t));
	for(int i = 0 ;i < APPLICATION_IDENTIFIER_LEN ; i++)
		app_id->application_identifier[i] = j++;

}

void	
set_source_intf(source_interface_ie_t *src_intf)
{
	pfcp_set_ie_header(&(src_intf->header), IE_SOURCE_INTERFACE, sizeof(source_interface_ie_t) - sizeof(pfcp_ie_header_t));
	src_intf->spare = 0;
	src_intf->interface_value = SOURCE_INTERFACE_VALUE_ACCESS;
}

void
set_pdi(pdi_ie_t *pdi)
{
	pfcp_set_ie_header(&(pdi->header), IE_PDI, sizeof(pdi_ie_t) - sizeof(pfcp_ie_header_t) -18);
	set_source_intf(&(pdi->source_interface));
	set_fteid(&(pdi->local_fteid));
	set_network_instance(&(pdi->network_instance));
	set_ue_ip(&(pdi->ue_ip_address));
	set_traffic_endpoint(&(pdi->traffic_endpoint_id));
	set_application_id(&(pdi->application_id));
	set_ethernet_pdu_sess_info(&(pdi->ethernet_pdu_session_information));
	set_framed_routing(&(pdi->framedrouting));
}

void
set_activate_predefined_rules(activate_predefined_rules_ie_t *act_predef_rule)
{

	pfcp_set_ie_header(&(act_predef_rule->header),IE_ACTIVATE_PREDEFINED_RULES,sizeof(activate_predefined_rules_ie_t) - sizeof(pfcp_ie_header_t));
	memcpy(&(act_predef_rule->predefined_rules_name),"PCC_RULE",8);
}
void
creating_pdr(create_pdr_ie_t *create_pdr)
{
	pfcp_set_ie_header(&(create_pdr->header),IE_CREATE_PDR,sizeof(create_pdr_ie_t) - sizeof(pfcp_ie_header_t) -18);
	set_pdr_id(&(create_pdr->pdr_id));
	set_precedence(&(create_pdr->precedence));
	set_pdi(&(create_pdr->pdi));
	set_outer_hdr_removal(&(create_pdr->outer_header_removal));
	set_far_id(&(create_pdr->far_id));
	set_urr_id(&(create_pdr->urr_id));
	set_qer_id(&(create_pdr->qer_id));
	set_activate_predefined_rules(&(create_pdr->activate_predefined_rules));
}

void
creating_bar(create_bar_ie_t *create_bar)
{
	pfcp_set_ie_header(&(create_bar->header),IE_CREATE_BAR,sizeof(create_bar_ie_t) - sizeof(pfcp_ie_header_t));
	//pfcp_set_ie_header(&(create_bar->header),IE_CREATE_BAR, 15);

	set_bar_id(&(create_bar->bar_id));
	set_dl_data_notification_delay(&(create_bar->downlink_data_notification_delay));
	set_sgstd_buff_pkts_cnt(&(create_bar->suggested_buffering_packets_count));
}

void
set_fq_csid(fq_csid_ie_t *fq_csid,uint32_t nodeid_value)
{
	fq_csid->fq_csid_node_id_type = IPV4_GLOBAL_UNICAST;
	//TODO identify the number of CSID
	fq_csid->number_of_csids = 1;
	memcpy(&(fq_csid->node_address.ipv4_address), &nodeid_value, IPV4_SIZE);
	for(int i = 0; i < fq_csid->number_of_csids ;i++)
		fq_csid->pdn_connection_set_identifier[i] = htons(pdn_conn_set_id++);
	pfcp_set_ie_header(&(fq_csid->header), IE_PFCP_FQ_CSID,2*(fq_csid->number_of_csids) + 5);

}

void
set_trace_info(trace_information_ie_t *trace_info)
{	
	//TODO from where we will fil MCC and MNC
	trace_info->mcc_digit_1 = 1;
	trace_info->mcc_digit_2 = 2;
	trace_info->mcc_digit_3 = 3;
	trace_info->mnc_digit_1 = 4;
	trace_info->mnc_digit_2 = 5;
	trace_info->mnc_digit_3 = 6;
	trace_info->trace_id  = 11231;
	trace_info->spare  = 0;
	trace_info->length_of_triggering_events = 1;
	trace_info->triggering_events[0]  = 1;
	trace_info->session_trace_depth = 1;
	trace_info->length_of_list_of_interfaces = 1 ;
	trace_info->list_of_interfaces[0] = 1;
	trace_info->length_of_ip_address_of_trace_collection_entity = 1;

	uint32_t ipv4 = htonl(32);
	memcpy(&(trace_info->ip_address_of_trace_collection_entity), &ipv4, IPV4_SIZE);
	//trace_info->ip_address_of_trace_collection_entity[0] = 92;
	uint32_t length = trace_info->length_of_triggering_events +
		trace_info->length_of_list_of_interfaces + trace_info->length_of_ip_address_of_trace_collection_entity + 14  ;
	//As Wireshark donot have spare so reducing size with 1 byte
	pfcp_set_ie_header(&(trace_info->header), IE_PFCP_TRACE_INFORMATION, length);
}

void
set_up_inactivity_timer(user_plane_inactivity_timer_ie_t *up_inact_timer)
{
	//pfcp_set_ie_header(&(up_inact_timer->header),IE_USER_PLANE_INACTIVITY_TIMER ,4);
	pfcp_set_ie_header(&(up_inact_timer->header),IE_USER_PLANE_INACTIVITY_TIMER ,UINT32_SIZE);
	//TODO , check the report from DP and value inact_timer accordingly 8.2.83
	up_inact_timer->user_plane_inactivity_timer = 10;
}
void
set_user_id(user_id_ie_t *user_id)
{
	user_id->spare   = 0;
	user_id->naif    = 0;
	user_id->msisdnf = 0;
	user_id->imeif   = 0;
	user_id->imsif   = 1;
	user_id->length_of_imsi   = 8;
	user_id->length_of_imei   = 0;
	user_id->length_of_msisdn = 0;
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
	pfcp_set_ie_header(&(user_id->header),IE_USER_ID , 10);
}

void
set_fseid(f_seid_ie_t *fseid,uint64_t seid,uint32_t nodeid_value)
{
	pfcp_set_ie_header(&(fseid->header),IE_F_SEID,sizeof(f_seid_ie_t)-(PFCP_IE_HDR_SIZE + IPV6_SIZE));
	fseid->spare  = 0;
	fseid->spare2 = 0;
	fseid->spare3 = 0;
	fseid->spare4 = 0;
	fseid->spare5 = 0;
	fseid->spare6 = 0;
	fseid->v4     = 1;
	fseid->v6     = 0;
	fseid->seid   = seid;
	memcpy(&(fseid->ipv4_address), &nodeid_value, IPV4_SIZE);

	fseid->ipv6_address = 0;

}

#if defined(PFCP_COMM) && defined(CP_BUILD)
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn,pdn_type_ie_t *pdn_mme)
#else
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn)
#endif
{
	pfcp_set_ie_header(&(pdn->header),IE_PFCP_PDN_TYPE,UINT8_SIZE);
	pdn->spare    = 0;
	//pdn->pdn_type = PFCP_PDN_TYPE_NON_IP;
	//TODO :need to check what received from MME
#if defined(PFCP_COMM) && defined(CP_BUILD)
	pdn->pdn_type =	pdn_mme->pdn_type;
#else
	pdn->pdn_type =	PFCP_PDN_TYPE_IPV4;
#endif
}

void
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val)
{
	pfcp_set_ie_header(&(cause->header), IE_CAUSE_ID,  UINT8_SIZE);
	cause->cause_value = cause_val;  /*CAUSE_VALUES_REQUESTACCEPTEDSUCCESS;*/
}

void
removing_bar( remove_bar_ie_t *remove_bar)
{
	pfcp_set_ie_header(&(remove_bar->header), IE_REMOVE_BAR,  sizeof(bar_id_ie_t));
	set_bar_id(&(remove_bar->bar_id));
}
void
set_traffic_endpoint(traffic_endpoint_id_ie_t *traffic_endpoint_id)
{
	pfcp_set_ie_header(&(traffic_endpoint_id->header), IE_TRAFFIC_ENDPOINT_ID,  UINT8_SIZE);
	traffic_endpoint_id->traffic_endpoint_id_value = 2;

}
void
removing_traffic_endpoint(remove_traffic_endpoint_ie_t *remove_traffic_endpoint)
{
	pfcp_set_ie_header(&(remove_traffic_endpoint->header), IE_REMOVE_TRAFFIC_ENDPOINT, sizeof(traffic_endpoint_id_ie_t));
	set_traffic_endpoint(&(remove_traffic_endpoint->traffic_endpoint_id));

}
void
set_fteid( f_teid_ie_t *local_fteid)
{
	pfcp_set_ie_header(&(local_fteid->header), IE_F_TEID, sizeof(f_teid_ie_t) - (PFCP_IE_HDR_SIZE + IPV6_SIZE +UINT8_SIZE));
	local_fteid->spare = 0;
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
set_network_instance(network_instance_ie_t *network_instance)
{
	pfcp_set_ie_header(&(network_instance->header), IE_NETWORK_INSTANCE, 8);
	network_instance->network_instance[0] = 1;
	network_instance->network_instance[1] = 1;
	network_instance->network_instance[2] = 1;
	network_instance->network_instance[3] = 1;
	network_instance->network_instance[4] = 1;
	network_instance->network_instance[5] = 1;
	network_instance->network_instance[6] = 1;
	network_instance->network_instance[7] = 1;
}
void
set_ue_ip(ue_ip_address_ie_t *ue_ip)
{
	pfcp_set_ie_header(&(ue_ip->header), IE_UE_IP_ADDRESS,sizeof(ue_ip_address_ie_t)-(PFCP_IE_HDR_SIZE + IPV6_SIZE+ UINT8_SIZE));
	ue_ip->spare = 0;
	ue_ip->ipv6d = 0;
	ue_ip->sd = 0;
	ue_ip->v4 = 1;
	ue_ip->v6 = 0;
	uint32_t ipv4 = htonl(3232236600);
	memcpy(&(ue_ip->ipv4_address), &ipv4, IPV4_SIZE);
}
void
set_ethernet_pdu_sess_info( ethernet_pdu_session_information_ie_t *eth_pdu_sess_info)
{
	pfcp_set_ie_header(&(eth_pdu_sess_info->header),IE_ETHERNET_PDU_SESSION_INFORMATION,UINT8_SIZE);
	eth_pdu_sess_info->spare = 0;
	eth_pdu_sess_info->ethi = 1;
}

void
set_framed_routing(framed_routing_ie_t *framedrouting)
{
	pfcp_set_ie_header(&(framedrouting->header),IE_FRAMED_ROUTING,8);
	framedrouting->framed_routing[0] = 2;
	framedrouting->framed_routing[1] = 2;
	framedrouting->framed_routing[2] = 2;
	framedrouting->framed_routing[3] = 2;
	framedrouting->framed_routing[4] = 2;
	framedrouting->framed_routing[5] = 2;
	framedrouting->framed_routing[6] = 2;
	framedrouting->framed_routing[7] = 2;

}
void
set_qer_id(qer_id_ie_t *qer_id)
{

	pfcp_set_ie_header(&(qer_id->header),IE_QER_ID,UINT32_SIZE);
	qer_id->qer_id_value = 33424;
}
void
set_qer_correl_id(qer_correlation_id_ie_t *qer_correl_id)
{
	pfcp_set_ie_header(&(qer_correl_id->header),IE_QER_CORRELATION_ID,UINT32_SIZE);
	qer_correl_id->qer_correlation_id_value = 1231;
}

void
set_gate_status( gate_status_ie_t *gate_status)
{
	pfcp_set_ie_header(&(gate_status->header),IE_GATE_STATUS,UINT8_SIZE);
	gate_status->spare = 0;
	gate_status->ul_gate = UL_GATE_OPEN;
	gate_status->ul_gate = DL_GATE_OPEN;
}

void
set_mbr(mbr_ie_t *mbr)
{
	pfcp_set_ie_header(&(mbr->header),IE_MBR,BITRATE_SIZE);
	mbr->ul_mbr =1;
	mbr->dl_mbr =1;
}

void
set_gbr(gbr_ie_t *gbr)
{
	pfcp_set_ie_header(&(gbr->header),IE_GBR,BITRATE_SIZE);
	gbr->ul_gbr =1;
	gbr->dl_gbr =1;
}

void
set_packet_rate(packet_rate_ie_t *pkt_rate)
{
	pkt_rate->spare = 0;
	pkt_rate->dlpr = 1;
	pkt_rate->ulpr = 1;
	pkt_rate->spare2 = 0;
	pkt_rate->uplink_time_unit =  UPLINKDOWNLINK_TIME_UNIT_MINUTE;
	pkt_rate->maximum_uplink_packet_rate = 2;
	pkt_rate->spare3 = 0;
	pkt_rate->downlink_time_unit = UPLINKDOWNLINK_TIME_UNIT_MINUTE;
	pkt_rate->maximum_downlink_packet_rate = 2;
	pfcp_set_ie_header(&(pkt_rate->header),IE_PACKET_RATE,sizeof(packet_rate_ie_t) - PFCP_IE_HDR_SIZE);
}

void
set_dl_flow_level_mark(dl_flow_level_marking_ie_t *dl_flow_level_marking)
{
	dl_flow_level_marking->spare = 0;
	dl_flow_level_marking->sci = 1;
	dl_flow_level_marking->ttc = 1;
	dl_flow_level_marking->tostraffic_class = 12;
	dl_flow_level_marking->service_class_indicator =1;
	pfcp_set_ie_header(&(dl_flow_level_marking->header),IE_DL_FLOW_LEVEL_MARKING,sizeof(dl_flow_level_marking_ie_t)-PFCP_IE_HDR_SIZE);

}

void
set_qfi(qfi_ie_t *qfi)
{
	qfi->spare = 0;
	qfi->qfi_value = 3;
	pfcp_set_ie_header(&(qfi->header),IE_QFI,UINT8_SIZE);
}
void
set_rqi(rqi_ie_t *rqi)
{
	rqi->spare = 0;
	rqi->rqi = 0;
	pfcp_set_ie_header(&(rqi->header),IE_RQI,UINT8_SIZE);
}
void
updating_qer(update_qer_ie_t *up_qer)
{
	//set qer id
	set_qer_id(&(up_qer->qer_id));

	//set qer correlation id
	set_qer_correl_id(&(up_qer->qer_correlation_id));

	//set gate status
	set_gate_status(&(up_qer->gate_status));

	//set mbr
	set_mbr(&(up_qer->maximum_bitrate));

	//set gbr
	set_gbr(&(up_qer->guaranteed_bitrate));

	//set packet rate
	set_packet_rate(&(up_qer->packet_rate));

	//set dl flow level
	set_dl_flow_level_mark(&(up_qer->dl_flow_level_marking));

	//set qfi
	set_qfi(&(up_qer->qos_flow_identifier));

	//set rqi
	set_rqi(&(up_qer->reflective_qos));
	uint8_t size = sizeof(update_qer_ie_t) - sizeof(pfcp_ie_header_t) - 12;
	pfcp_set_ie_header(&(up_qer->header),IE_UPDATE_QER,size);
}

void
creating_traffic_endpoint(create_traffic_endpoint_ie_t  *create_traffic_endpoint)
{
	//set traffic endpoint id
	set_traffic_endpoint(&(create_traffic_endpoint->traffic_endpoint_id));

	//set local fteid
	set_fteid(&(create_traffic_endpoint->local_fteid));

	//set network isntance
	set_network_instance(&(create_traffic_endpoint->network_instance));

	//set ue ip address
	set_ue_ip(&(create_traffic_endpoint->ue_ip_address));

	//set ethernet pdu session info
	set_ethernet_pdu_sess_info(&(create_traffic_endpoint->ethernet_pdu_session_information));

	//set framed routing
	set_framed_routing(&(create_traffic_endpoint->framedrouting));

	uint16_t size = sizeof(traffic_endpoint_id_ie_t) +sizeof(f_teid_ie_t) +sizeof(network_instance_ie_t) +
	sizeof(ue_ip_address_ie_t) + sizeof(ethernet_pdu_session_information_ie_t) +
	sizeof(framed_routing_ie_t);
	size = size - 18;
	pfcp_set_ie_header(&(create_traffic_endpoint->header), IE_CREATE_TRAFFIC_ENDPOINT, size);
}
void
updating_bar( update_bar_ie_t *up_bar)
{
	set_bar_id(&(up_bar->bar_id));
	set_dl_data_notification_delay(&(up_bar->downlink_data_notification_delay));
	set_sgstd_buff_pkts_cnt(&(up_bar->suggested_buffering_packets_count));

	uint8_t size =  sizeof(bar_id_ie_t) + sizeof(downlink_data_notification_delay_ie_t)+
	sizeof(suggested_buffering_packets_count_ie_t);
	pfcp_set_ie_header(&(up_bar->header), IE_UPDATE_BAR, size);
}

void
updating_traffic_endpoint(update_traffic_endpoint_ie_t *up_traffic_endpoint)
{
	set_traffic_endpoint(&(up_traffic_endpoint->traffic_endpoint_id));
	set_fteid(&(up_traffic_endpoint->local_fteid));
	set_network_instance(&(up_traffic_endpoint->network_instance));
	set_ue_ip(&(up_traffic_endpoint->ue_ip_address));
	set_framed_routing(&(up_traffic_endpoint->framedrouting));

	uint8_t size = sizeof(traffic_endpoint_id_ie_t) + sizeof(f_teid_ie_t) +
			sizeof(network_instance_ie_t) + sizeof(ue_ip_address_ie_t) +
			sizeof(framed_routing_ie_t);
	size = size - (2*IPV6_SIZE) - 2;
	pfcp_set_ie_header(&(up_traffic_endpoint->header), IE_UPDATE_TRAFFIC_ENDPOINT, size);

}

void
set_pfcpsmreqflags(pfcpsmreq_flags_ie_t *pfcp_sm_req_flags)
{
	pfcp_set_ie_header(&(pfcp_sm_req_flags->header), IE_PFCPSMREQ_FLAGS,UINT8_SIZE);
	pfcp_sm_req_flags->spare = 0;
	pfcp_sm_req_flags->spare2 = 0;
	pfcp_sm_req_flags->spare3 = 0;
	pfcp_sm_req_flags->spare4 = 0;
	pfcp_sm_req_flags->spare5 = 0;
	pfcp_sm_req_flags->qaurr = 0;
	pfcp_sm_req_flags->sndem = 0;
	pfcp_sm_req_flags->drobu = 0;
}

void
set_query_urr_refernce( query_urr_reference_ie_t *query_urr_ref)
{
	pfcp_set_ie_header(&(query_urr_ref->header), IE_QUERY_URR_REFERENCE,UINT32_SIZE);
	query_urr_ref->query_urr_reference_value = 3;

}

void
set_pfcp_ass_rel_req(pfcp_association_release_request_ie_t *ass_rel_req)
{

	pfcp_set_ie_header(&(ass_rel_req->header), IE_PFCP_ASSOCIATION_RELEASE_REQUEST,UINT8_SIZE);
	ass_rel_req->spare = 0;
	ass_rel_req->sarr = 0;
}

void
set_graceful_release_period(graceful_release_period_ie_t *graceful_rel_period)
{
	pfcp_set_ie_header(&(graceful_rel_period->header), IE_GRACEFUL_RELEASE_PERIOD,UINT8_SIZE);
	graceful_rel_period->timer_unit = GRACEFUL_RELEASE_PERIOD_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS;
	graceful_rel_period->timer_value = 1;

}

void
set_sequence_num(sequence_number_ie_t *seq)
{
	pfcp_set_ie_header(&(seq->header),IE_SEQUENCE_NUMBER,UINT32_SIZE);
	seq->sequence_number = 12;
}

void
set_metric(metric_ie_t *metric)
{
	pfcp_set_ie_header(&(metric->header),IE_METRIC,UINT8_SIZE);
	metric->metric = 2;
}

void
set_period_of_validity(timer_ie_t *pov)
{
	pfcp_set_ie_header(&(pov->header),IE_TIMER, UINT8_SIZE);
	pov->timer_unit = TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS ;
	pov->timer_value = 20;
}
void
set_oci_flag( oci_flags_ie_t *oci)
{
	pfcp_set_ie_header(&(oci->header),IE_OCI_FLAGS, UINT8_SIZE);
	oci->spare = 0;
	oci->aoci = 1;
}

void
set_offending_ie( offending_ie_ie_t *offending_ie, int offend_val)
{
	pfcp_set_ie_header(&(offending_ie->header),IE_OFFENDING_IE,UINT16_SIZE);
	offending_ie->type_of_the_offending_ie = offend_val;
}

void
set_lci(load_control_information_ie_t *lci)
{
	pfcp_set_ie_header(&(lci->header),IE_LOAD_CONTROL_INFORMATION,sizeof(sequence_number_ie_t) + sizeof(metric_ie_t));
	set_sequence_num(&(lci->load_control_sequence_number));
	set_metric(&(lci->load_metric));
}

void
set_olci(overload_control_information_ie_t *olci)
{
	pfcp_set_ie_header(&(olci->header),IE_OVERLOAD_CONTROL_INFORMATION,sizeof(sequence_number_ie_t) +
			sizeof(metric_ie_t)+sizeof(timer_ie_t) + sizeof(oci_flags_ie_t));
	set_sequence_num(&(olci->overload_control_sequence_number));
	set_metric(&(olci->overload_reduction_metric));
	set_period_of_validity(&(olci->period_of_validity));
	set_oci_flag(&(olci->overload_control_information_flags));
}

void
set_failed_rule_id(failed_rule_id_ie_t *rule)
{
	pfcp_set_ie_header(&(rule->header),IE_FAILED_RULE_ID,3);
	rule->spare = 0;
	rule ->rule_id_type = RULE_ID_TYPE_PDR;
	rule->rule_id_value[0] = 2;
	rule->rule_id_value[1] = 2;
}

void
set_traffic_endpoint_id(traffic_endpoint_id_ie_t *tnp)
{
	pfcp_set_ie_header(&(tnp->header),IE_TRAFFIC_ENDPOINT_ID, UINT8_SIZE);
	tnp->traffic_endpoint_id_value = 12;
}
void set_pdr_id_ie(pdr_id_ie_t *pdr)
{
	pfcp_set_ie_header(&(pdr->header),IE_PDR_ID,sizeof(pdr_id_ie_t) - PFCP_IE_HDR_SIZE );
	pdr->rule_id = 12;  //Need to check value
}
void set_created_pdr_ie(created_pdr_ie_t *pdr)
{

	//pfcp_set_ie_header(&(pdr->header),IE_CREATED_PDR,sizeof(created_pdr_ie_t)-4);
	pfcp_set_ie_header(&(pdr->header),IE_CREATED_PDR,19);
	set_pdr_id_ie(&(pdr->pdr_id));
	set_fteid(&(pdr->local_fteid));

}

void set_created_traffic_endpoint(created_traffic_endpoint_ie_t *cte)
{
	//pfcp_set_ie_header(&(cte->header),IE_CREATE_TRAFFIC_ENDPOINT,sizeof(created_traffic_endpoint_ie_t)-4);
	pfcp_set_ie_header(&(cte->header),IE_CREATE_TRAFFIC_ENDPOINT, 18);
	set_traffic_endpoint_id(&(cte->traffic_endpoint_id));
	set_fteid(&(cte->local_fteid));

}

void set_additional_usage(additional_usage_reports_information_ie_t *adr)
{
	//pfcp_set_ie_header(&(adr->header),IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,sizeof(additional_usage_reports_information_ie_t)-4);
	pfcp_set_ie_header(&(adr->header),IE_ADDITIONAL_USAGE_REPORTS_INFORMATION,UINT16_SIZE);
	adr->auri = 0;
	adr->number_of_additional_usage_reports_value = 12;
}
void	
set_node_report_type( node_report_type_ie_t *nrt)
{
	pfcp_set_ie_header(&(nrt->header),IE_NODE_REPORT_TYPE,UINT8_SIZE);
	nrt->spare = 0;
	nrt->upfr = 0;
}
	
void	
set_remote_gtpu_peer_ip( remote_gtp_u_peer_ie_t *remote_gtpu_peer)
{

	pfcp_set_ie_header(&(remote_gtpu_peer->header),IE_REMOTE_GTP_U_PEER,sizeof(remote_gtp_u_peer_ie_t) - (IPV6_SIZE+PFCP_IE_HDR_SIZE));
	remote_gtpu_peer->v4 = 1;
	remote_gtpu_peer->v6 = 0;
	uint32_t ipv4 = htonl(3211236600);
	memcpy(&(remote_gtpu_peer->ipv4_address), &ipv4, IPV4_SIZE);
}
void
set_user_plane_path_failure_report(user_plane_path_failure_report_ie_t *uppfr)
{
	pfcp_set_ie_header(&(uppfr->header), IE_USER_PLANE_PATH_FAILURE_REPORT,sizeof(remote_gtp_u_peer_ie_t));
	//set remote gtpu peer
	set_remote_gtpu_peer_ip(&(uppfr->remote_gtpu_peer));
}
 
void cause_check_association(pfcp_association_setup_request_t *pfcp_ass_setup_req, 
		uint8_t *cause_id, int *offend_id)
{
	*cause_id = CAUSE_VALUES_REQUESTACCEPTEDSUCCESS ;
	*offend_id = 0;

	if(!(pfcp_ass_setup_req->node_id.header.len)){
		*cause_id = CAUSE_VALUES_MANDATORYIEMISSING;
		*offend_id = IE_NODE_ID;
	} else {

		if (pfcp_ass_setup_req->node_id.node_id_type == IPTYPE_IPV4) {
                	if (NODE_ID_IPV4_LEN != pfcp_ass_setup_req->node_id.header.len) {
                        *cause_id = CAUSE_VALUES_INVALIDLENGTH;
                	}
		}
		if (pfcp_ass_setup_req->node_id.node_id_type == IPTYPE_IPV6) {
                        if (NODE_ID_IPV6_LEN != pfcp_ass_setup_req->node_id.header.len) {
                        *cause_id = CAUSE_VALUES_INVALIDLENGTH;
                	}
		}
			
		//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if (!(pfcp_ass_setup_req->recovery_time_stamp.header.len)) {

		*cause_id = CAUSE_VALUES_MANDATORYIEMISSING;
		*offend_id = IE_RECOVERY_TIME_STAMP;
	} else if(pfcp_ass_setup_req->recovery_time_stamp.header.len != RECOV_TIMESTAMP_LEN){

		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if (!(pfcp_ass_setup_req->cp_function_features.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_CP_FUNCTION_FEATURES ;
	} else if (pfcp_ass_setup_req->cp_function_features.header.len != CP_FUNC_FEATURES_LEN) {

		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}
}


void cause_check_sess_estab(pfcp_session_establishment_request_t *pfcp_session_request,
				 uint8_t *cause_id, int *offend_id)
{
	*cause_id  = CAUSE_VALUES_REQUESTACCEPTEDSUCCESS;
	*offend_id = 0;

	if(!(pfcp_session_request->node_id.header.len)) {

		*offend_id = IE_NODE_ID;
		*cause_id = CAUSE_VALUES_MANDATORYIEMISSING;

	} else /*if(pfcp_session_request->node_id.header.len != 5)*/ {

		 if (pfcp_session_request->node_id.node_id_type == IPTYPE_IPV4) {
                        if (NODE_ID_IPV4_LEN != pfcp_session_request->node_id.header.len) {
                        *cause_id = CAUSE_VALUES_INVALIDLENGTH;
                        }
                }
                if (pfcp_session_request->node_id.node_id_type == IPTYPE_IPV6) {
                        if (NODE_ID_IPV6_LEN != pfcp_session_request->node_id.header.len) {
                        *cause_id = CAUSE_VALUES_INVALIDLENGTH;
                        }
                }
	//	*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	if(!(pfcp_session_request->cp_fseid.header.len)){

		*offend_id = IE_F_SEID;
		*cause_id = CAUSE_VALUES_MANDATORYIEMISSING;


	} else if (pfcp_session_request->cp_fseid.header.len != CP_FSEID_LEN) {

		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}
	
	/*if(!(pfcp_session_request->pgwc_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_PFCP_FQ_CSID;

	} else if(pfcp_session_request->pgwc_fqcsid.header.len != PGWC_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;

	}*/

	if(!(pfcp_session_request->sgwc_fqcsid.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id =IE_PFCP_FQ_CSID;

	} else if(pfcp_session_request->sgwc_fqcsid.header.len != SGWC_FQCSID_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
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

uint8_t add_associated_upf_ip_hash(uint32_t *nodeid, uint8_t *data )
{
	int ret = 0;
	uint32_t key = UINT32_MAX;
	uint8_t *temp = NULL;
	memcpy(&key,nodeid,sizeof(uint32_t));

	temp =(uint8_t *) rte_zmalloc_socket(NULL, sizeof(uint64_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (temp == NULL) {
		fprintf(stderr, "Failure to allocate associated ip "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return 1;
	}
	*temp = *data; 
	ret = rte_hash_add_key_data(associated_upf_hash,
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

uint8_t
add_node_id_hash(uint32_t *nodeid,uint64_t *data )
{
	int ret = 0;
	uint32_t key = UINT32_MAX;
	uint64_t *temp = NULL;
	memcpy(&key,nodeid,sizeof(uint32_t));

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
cause_check_sess_modification(pfcp_session_modification_request_t *pfcp_session_mod_req ,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id  = CAUSE_VALUES_REQUESTACCEPTEDSUCCESS;
	*offend_id = 0;

	if(!(pfcp_session_mod_req->cp_fseid.header.len)){
		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_F_SEID;
	} else if (pfcp_session_mod_req->cp_fseid.header.len != CP_FSEID_LEN)
	{
		//TODO: IPV4 consideration only
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}


	if( pfcp_ctxt.up_supported_features & UP_PDIU )	{
		if(!(pfcp_session_mod_req->remove_traffic_endpoint.header.len)) {

			*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
			*offend_id = IE_REMOVE_TRAFFIC_ENDPOINT;
		} else if(pfcp_session_mod_req->remove_traffic_endpoint.header.len != REMOVE_TRAFFIC_ENDPOINT_LEN) {

			//	*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}


		if(!(pfcp_session_mod_req->create_traffic_endpoint.header.len)) {

			*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
			*offend_id = IE_CREATE_TRAFFIC_ENDPOINT ;
		} else if (pfcp_session_mod_req->create_traffic_endpoint.header.len != CREATE_TRAFFIC_ENDPOINT_LEN){
			//TODO:Consdiering IP4
			//	*cause_id = CAUSE_VALUES_INVALIDLENGTH;
		}
	}
	if(!(pfcp_session_mod_req->create_bar.header.len)){

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_CREATE_BAR;
	} else if (pfcp_session_mod_req->create_bar.header.len != CREATE_BAR_LEN) {

		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

	/*if(!(pfcp_session_mod_req->update_qer.header.len)) {
		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_UPDATE_QER;
	} else if(pfcp_session_mod_req->update_qer.header.len != UPDATE_QER_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}*/

	if(!(pfcp_session_mod_req->update_bar.header.len)) {
		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_UPDATE_BAR;

	} else if(pfcp_session_mod_req->update_bar.header.len != UPDATE_BAR_LEN) {
		//*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}

        /*TODO: There must a different FQCSID flag which is not comming from CP,that is why 
	code is commented*/

	/*if(!(pfcp_session_mod_req->update_traffic_endpoint.header.len)) {

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

	if(!(pfcp_session_mod_req->user_plane_inactivity_timer.header.len)) {

		*cause_id = CAUSE_VALUES_CONDITIONALIEMISSING;
		*offend_id = IE_USER_PLANE_INACTIVITY_TIMER ;
	} else if(pfcp_session_mod_req->user_plane_inactivity_timer.header.len != USER_PLANE_INACTIV_TIMER_LEN) {
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}*/
}

void
cause_check_delete_session(pfcp_session_deletion_request_t *pfcp_session_delete_req ,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id  = CAUSE_VALUES_REQUESTACCEPTEDSUCCESS;
	*offend_id = 0;
	if(!(pfcp_session_delete_req->header.message_len)) {
		*cause_id = CAUSE_VALUES_MANDATORYIEMISSING;
		*offend_id = IE_F_SEID;
	} else if(pfcp_session_delete_req->header.message_len != DELETE_SESSION_HEADER_LEN){
		*cause_id = CAUSE_VALUES_INVALIDLENGTH;
	}
}

int
add_data_to_heartbeat_hash_table(uint32_t *ip,uint32_t *recov_time)
{
	int ret = 0;
	uint32_t key = UINT32_MAX ;
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

void add_ip_to_heartbeat_hash(struct sockaddr_in *peer_addr)
{
	uint32_t *default_recov_time = NULL;
	default_recov_time = rte_zmalloc_socket(NULL, sizeof(uint32_t),
                                                RTE_CACHE_LINE_SIZE, rte_socket_id());
	
	*default_recov_time = 1000;
	int ret = add_data_to_heartbeat_hash_table( &peer_addr->sin_addr.s_addr ,default_recov_time);
                      
    if(ret !=0){

        fprintf(stderr,"%s - Error on rte_hash_add_key_data add in heartbeat\n",
		strerror(ret));
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

