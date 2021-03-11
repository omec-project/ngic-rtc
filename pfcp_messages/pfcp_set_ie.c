/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#include "pfcp_ies.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_enum.h"
#include "gw_adapter.h"

#ifdef CP_BUILD
#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "debug_str.h"
#else
#include "pfcp_struct.h"
#include "up_main.h"
#endif /* CP_BUILD */

/* size of user ip resource info ie will be 6 if teid_range is not included otherwise 7 */
#define SIZE_IF_TEIDRI_PRESENT 7
#define SIZE_IF_TEIDRI_NOT_PRESENT 6
#define USER_ID_LEN 10

/* extern */
uint32_t start_time;
const uint32_t pfcp_base_seq_no = 0x00000000;
const uint32_t pfcp_base_urr_seq_no = 0x00000000;
static uint32_t pfcp_seq_no_offset;
extern int clSystemLog;

#ifdef CP_BUILD
extern pfcp_config_t config;
static uint32_t pfcp_sgwc_seid_offset;
#endif /* CP_BUILD */

extern struct rte_hash *heartbeat_recovery_hash;
const uint64_t pfcp_sgwc_base_seid = 0xC0FFEE;


void
set_pfcp_header(pfcp_header_t *pfcp, uint8_t type, bool flag )
{
	pfcp->s       = flag;
	pfcp->mp      = 0;
	pfcp->spare   = 0;
	pfcp->version = PFCP_VERSION;
	pfcp->message_type = type;
}

uint32_t
generate_seq_no(void){
	uint32_t id = 0;
	id = pfcp_base_seq_no + (++pfcp_seq_no_offset);
	return id;
}

uint32_t
get_pfcp_sequence_number(uint8_t type, uint32_t seq){
	switch(type){
		case PFCP_HEARTBEAT_REQUEST :
		case PFCP_PFD_MGMT_REQUEST:
		case PFCP_ASSOCIATION_SETUP_REQUEST:
		case PFCP_ASSOCIATION_UPDATE_REQUEST:
		case PFCP_ASSOCIATION_RELEASE_REQUEST:
		case PFCP_NODE_REPORT_REQUEST:
		case PFCP_SESSION_SET_DELETION_REQUEST:
		case PFCP_SESSION_ESTABLISHMENT_REQUEST:
		case PFCP_SESSION_MODIFICATION_REQUEST:
		case PFCP_SESSION_DELETION_REQUEST:
		case PFCP_SESSION_REPORT_REQUEST:
			return generate_seq_no();
		case PFCP_HEARTBEAT_RESPONSE:
		case PFCP_ASSOCIATION_SETUP_RESPONSE:
		case PFCP_ASSOCIATION_UPDATE_RESPONSE:
		case PFCP_ASSOCIATION_RELEASE_RESPONSE:
		case PFCP_NODE_REPORT_RESPONSE:
		case PFCP_SESSION_SET_DELETION_RESPONSE:
		case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
		case PFCP_SESSION_MODIFICATION_RESPONSE:
		case PFCP_SESSION_DELETION_RESPONSE:
		case PFCP_SESSION_REPORT_RESPONSE:
			return seq;
		default:
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Unknown PFCP Msg "
				"type. \n", LOG_VALUE);
			return 0;
			break;
	}
	return 0;
}

void
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag,
		uint32_t seq, uint8_t cp_type)
{
	set_pfcp_header(pfcp, type, flag );

	if(flag == HAS_SEID){

#ifdef CP_BUILD
		if (cp_type == SGWC){
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

int
set_node_id(pfcp_node_id_ie_t *node_id, node_address_t node_value)
{
	memset(node_id, 0, sizeof(pfcp_node_id_ie_t));
	int ie_length = sizeof(pfcp_node_id_ie_t) -
			sizeof(node_id->node_id_value_ipv4_address) -
			sizeof(node_id->node_id_value_ipv6_address) -
			sizeof(node_id->node_id_value_fqdn);

	if(node_value.ip_type == PDN_TYPE_IPV6 || node_value.ip_type == PDN_TYPE_IPV4_IPV6) {
		/* IPv6 Handling */
		ie_length += sizeof(struct in6_addr);
		node_id->node_id_type = NODE_ID_TYPE_TYPE_IPV6ADDRESS;
		memcpy(node_id->node_id_value_ipv6_address, node_value.ipv6_addr, IPV6_ADDRESS_LEN);

	} else if(node_value.ip_type == PDN_TYPE_IPV4) {
		/* IPv4 Handling */
		node_id->node_id_type = NODE_ID_TYPE_TYPE_IPV4ADDRESS;
		node_id->node_id_value_ipv4_address = node_value.ipv4_addr;
		ie_length += sizeof(struct in_addr);

	} else {
		/* FQDN Handling */
	}

	pfcp_set_ie_header(&(node_id->header), PFCP_IE_NODE_ID, ie_length - PFCP_IE_HDR_SIZE);
	ie_length += PFCP_IE_HDR_SIZE;

	return ie_length;
}

void
set_recovery_time_stamp(pfcp_rcvry_time_stmp_ie_t *rec_time_stamp)
{
	pfcp_set_ie_header(&(rec_time_stamp->header),
						PFCP_IE_RCVRY_TIME_STMP,UINT32_SIZE);

	rec_time_stamp->rcvry_time_stmp_val = start_time;

}

void
set_upf_features(pfcp_up_func_feat_ie_t *upf_feat)
{
	pfcp_set_ie_header(&(upf_feat->header), PFCP_IE_UP_FUNC_FEAT,
					UINT16_SIZE);
}

void
set_cpf_features(pfcp_cp_func_feat_ie_t *cpf_feat)
{
	pfcp_set_ie_header(&(cpf_feat->header), PFCP_IE_CP_FUNC_FEAT,
					UINT8_SIZE);
}

void
set_sess_report_type(pfcp_report_type_ie_t *rt)
{
	pfcp_set_ie_header(&(rt->header), PFCP_IE_REPORT_TYPE, UINT8_SIZE);
	rt->rpt_type_spare = 0;
	rt->upir  = 0;
	rt->erir  = 0;
	rt->usar  = 0;
	rt->dldr  = 1;
}

#ifdef DP_BUILD

static void

set_up_resource_info_addr(ip_type_t type, uint32_t ipv4_addr, uint8_t ipv6_addr[],
					pfcp_user_plane_ip_rsrc_info_ie_t *up_ip_resource_info, int *size) {

	if (type.ipv6) {

		up_ip_resource_info->v6 = PRESENT;
		memcpy(up_ip_resource_info->ipv6_address, ipv6_addr, IPV6_ADDRESS_LEN);
		*size += sizeof(struct in6_addr);
	}

	if (type.ipv4) {

		up_ip_resource_info->v4 = PRESENT;
		up_ip_resource_info->ipv4_address = htonl(ipv4_addr);
		*size += sizeof(struct in_addr);
	}

	return;
}

void
set_up_ip_resource_info(pfcp_user_plane_ip_rsrc_info_ie_t *up_ip_resource_info,
		uint8_t i, int8_t teid_range, uint8_t logical_iface)
{
	if(app.teidri_val == 0){
		pfcp_set_ie_header(&(up_ip_resource_info->header),
				PFCP_IE_USER_PLANE_IP_RSRC_INFO, SIZE_IF_TEIDRI_NOT_PRESENT);
	}else{
		pfcp_set_ie_header(&(up_ip_resource_info->header),
				PFCP_IE_USER_PLANE_IP_RSRC_INFO, SIZE_IF_TEIDRI_PRESENT);
	}

	up_ip_resource_info->user_plane_ip_rsrc_info_spare  = 0;
	up_ip_resource_info->assosi = 1;
	up_ip_resource_info->assoni = 0;

	int size = sizeof(uint8_t);

	if( up_ip_resource_info->assoni == 1) {
		memset(up_ip_resource_info->ntwk_inst, 0, PFCP_NTWK_INST_LEN);
		size += sizeof(up_ip_resource_info->ntwk_inst);
	}

	if (app.teidri_val != 0) {
		up_ip_resource_info->teidri = app.teidri_val;
		up_ip_resource_info->teid_range = teid_range;
		size += sizeof(up_ip_resource_info->teid_range);
	}


	up_ip_resource_info->user_plane_ip_rsrc_info_spare2  = 0;
	size += sizeof(uint8_t);

	if( up_ip_resource_info->assosi ) {
		if (logical_iface) {
			/* WB/ACCESS:1 Logical Interface */
			if ((logical_iface == 1) && (app.wb_li_ip || isIPv6Present(&app.wb_li_ipv6))) {
				up_ip_resource_info->src_intfc  =
								SOURCE_INTERFACE_VALUE_ACCESS; /*UL*/
				set_up_resource_info_addr(app.wb_li_ip_type,
					app.wb_li_ip, app.wb_li_ipv6.s6_addr,
					up_ip_resource_info, &size);
			}

			/* EB/CORE:2 Logical Interface */
			if ((logical_iface == 2) && (app.eb_li_ip || isIPv6Present(&app.eb_li_ipv6))) {
				/* East Bound Interface */
				up_ip_resource_info->src_intfc  =
								SOURCE_INTERFACE_VALUE_CORE; /*DL*/
				set_up_resource_info_addr(app.eb_li_ip_type,
					app.eb_li_ip, app.eb_li_ipv6.s6_addr,
					up_ip_resource_info, &size);
			}
		} else {
			if ((i == 0) && (app.wb_ip || isIPv6Present(&app.wb_ipv6))) {
				/* West Bound Interface */
				up_ip_resource_info->src_intfc  =
								SOURCE_INTERFACE_VALUE_ACCESS; /*UL*/
				set_up_resource_info_addr(app.wb_ip_type,
					app.wb_ip, app.wb_ipv6.s6_addr,
					up_ip_resource_info, &size);
			}

			if ((i == 1) && (app.eb_ip || isIPv6Present(&app.eb_ipv6))) {
				/* East Bound Interface */
				up_ip_resource_info->src_intfc  =
								SOURCE_INTERFACE_VALUE_CORE; /*DL*/
				set_up_resource_info_addr(app.eb_ip_type,
					app.eb_ip, app.eb_ipv6.s6_addr,
					up_ip_resource_info, &size);
			}
		}
	}
	pfcp_set_ie_header(&(up_ip_resource_info->header),
			PFCP_IE_USER_PLANE_IP_RSRC_INFO, size);

}
#endif /* DP_BUILD*/

int
set_bar_id(pfcp_bar_id_ie_t *bar_id, uint8_t bar_id_value)
{
	int size = sizeof(pfcp_bar_id_ie_t);

	pfcp_set_ie_header(&(bar_id->header), PFCP_IE_BAR_ID,
			(sizeof(pfcp_bar_id_ie_t) - sizeof(pfcp_ie_header_t)));
	bar_id->bar_id_value = bar_id_value;

	return size;
}

void
set_dl_data_notification_delay(pfcp_dnlnk_data_notif_delay_ie_t *dl_data_notification_delay)
{
	pfcp_set_ie_header(&(dl_data_notification_delay->header),
			PFCP_IE_DNLNK_DATA_NOTIF_DELAY, UINT8_SIZE);

	dl_data_notification_delay->delay_val_in_integer_multiples_of_50_millisecs_or_zero = 0;
}

int
set_sgstd_buff_pkts_cnt(pfcp_suggstd_buf_pckts_cnt_ie_t *sgstd_buff_pkts_cnt, uint8_t pkt_cnt)
{
	int size = sizeof(pfcp_suggstd_buf_pckts_cnt_ie_t);

	pfcp_set_ie_header(&(sgstd_buff_pkts_cnt->header), PFCP_IE_SUGGSTD_BUF_PCKT_CNT,
			(sizeof(pfcp_suggstd_buf_pckts_cnt_ie_t) - sizeof(pfcp_ie_header_t)));
	sgstd_buff_pkts_cnt->pckt_cnt_val = pkt_cnt;

	return size;
}

int
set_dl_buf_sgstd_pkts_cnt(pfcp_dl_buf_suggstd_pckt_cnt_ie_t *dl_buf_sgstd_pkts_cnt, uint8_t pkt_cnt)
{

	int size = sizeof(pfcp_dl_buf_suggstd_pckt_cnt_ie_t);

	pfcp_set_ie_header(&(dl_buf_sgstd_pkts_cnt->header), PFCP_IE_DL_BUF_SUGGSTD_PCKT_CNT,
			(sizeof(pfcp_dl_buf_suggstd_pckt_cnt_ie_t) - sizeof(pfcp_ie_header_t)));
	dl_buf_sgstd_pkts_cnt->pckt_cnt_val = pkt_cnt;

	return size;
}

int
set_pdr_id(pfcp_pdr_id_ie_t *pdr_id, uint16_t pdr_id_value)
{
	int size = sizeof(pfcp_pdr_id_ie_t);

	pfcp_set_ie_header(&(pdr_id->header), PFCP_IE_PDR_ID,
			(sizeof(pfcp_pdr_id_ie_t) - sizeof(pfcp_ie_header_t)));
	pdr_id->rule_id = pdr_id_value;

	return size;
}

int
set_far_id(pfcp_far_id_ie_t *far_id, uint32_t far_id_value)
{
	int size = sizeof(pfcp_far_id_ie_t);

	pfcp_set_ie_header(&(far_id->header), PFCP_IE_FAR_ID,
			(sizeof(pfcp_far_id_ie_t) - sizeof(pfcp_ie_header_t)));
	far_id->far_id_value = far_id_value;

	return size;

}

int
set_urr_id(pfcp_urr_id_ie_t *urr_id, uint32_t urr_id_value)
{
	int size = sizeof(pfcp_urr_id_ie_t);

	urr_id->urr_id_value = urr_id_value;
	pfcp_set_ie_header(&(urr_id->header), PFCP_IE_URR_ID, UINT32_SIZE);

	return size;
}
int
set_precedence(pfcp_precedence_ie_t *prec, uint32_t prec_value)
{
	int size = sizeof(pfcp_precedence_ie_t);

	pfcp_set_ie_header(&(prec->header), PFCP_IE_PRECEDENCE,
			(sizeof(pfcp_precedence_ie_t) - sizeof(pfcp_ie_header_t)));
	prec->prcdnc_val = prec_value;

	return size;
}
int
set_outer_hdr_removal(pfcp_outer_hdr_removal_ie_t *out_hdr_rem,
		uint8_t outer_header_desc)
{
	int size = sizeof(pfcp_outer_hdr_removal_ie_t) - sizeof(out_hdr_rem->gtpu_ext_hdr_del);
	pfcp_set_ie_header(&(out_hdr_rem->header), PFCP_IE_OUTER_HDR_REMOVAL,
			 UINT8_SIZE);

	/* TODO: Revisit this for change in yang */
	out_hdr_rem->outer_hdr_removal_desc = outer_header_desc;
	/* TODO: Revisit this for change in yang */
	return size;
}

int
set_source_intf(pfcp_src_intfc_ie_t *src_intf, uint8_t src_intf_value)
{
	int size = sizeof(pfcp_src_intfc_ie_t);

	pfcp_set_ie_header(&(src_intf->header), PFCP_IE_SRC_INTFC,
			(sizeof(pfcp_src_intfc_ie_t) - sizeof(pfcp_ie_header_t)));
	src_intf->src_intfc_spare = 0;
	src_intf->interface_value = src_intf_value;

	return size;
}

int
set_pdi(pfcp_pdi_ie_t *pdi, pdi_t *bearer_pdi, uint8_t cp_type)
{
	int size = 0;

	size += set_source_intf(&(pdi->src_intfc), bearer_pdi->src_intfc.interface_value);
#ifdef CP_BUILD
	if((cp_type != SGWC)  &&
		bearer_pdi->src_intfc.interface_value == SOURCE_INTERFACE_VALUE_CORE){
		size += set_network_instance(&(pdi->ntwk_inst), &bearer_pdi->ntwk_inst);
		size += set_ue_ip(&(pdi->ue_ip_address), bearer_pdi->ue_addr);
	}else{
		size += set_fteid(&(pdi->local_fteid),  &bearer_pdi->local_fteid);
		if((cp_type != SGWC) && bearer_pdi->ue_addr.v6){
				size += set_ue_ip(&(pdi->ue_ip_address), bearer_pdi->ue_addr);
				pdi->ue_ip_address.ipv6d = 1;
				pdi->ue_ip_address.ipv6_pfx_dlgtn_bits =  bearer_pdi->ue_addr.ipv6_pfx_dlgtn_bits;
				pdi->ue_ip_address.header.len += sizeof(pdi->ue_ip_address.ipv6_pfx_dlgtn_bits);
				size += sizeof(pdi->ue_ip_address.ipv6_pfx_dlgtn_bits);
		}
	}
#endif /* CP_BUILD */

	/* TODO: Revisit this for change in yang */
	pfcp_set_ie_header(&(pdi->header), IE_PDI, size);

	return (size + sizeof(pfcp_ie_header_t));
}

int
set_create_pdr(pfcp_create_pdr_ie_t *create_pdr, pdr_t *bearer_pdr,
		uint8_t cp_type)
{
	int size = 0;

	size += set_pdr_id(&(create_pdr->pdr_id), bearer_pdr->rule_id);
	size += set_precedence(&(create_pdr->precedence), bearer_pdr->prcdnc_val);
	size += set_pdi(&(create_pdr->pdi), &bearer_pdr->pdi, cp_type);
#ifdef CP_BUILD
	uint8_t outer_header_desc = 0;

	if (bearer_pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {
		if(cp_type != SGWC) {

			if (create_pdr->pdi.local_fteid.v6)
				outer_header_desc = GTP_U_UDP_IPv6;
			else if (create_pdr->pdi.local_fteid.v4)
				outer_header_desc = GTP_U_UDP_IPv4;

			size += set_outer_hdr_removal(&(create_pdr->outer_hdr_removal),
						outer_header_desc);
		}
	}

	size += set_far_id(&(create_pdr->far_id), bearer_pdr->far.far_id_value);
	for(int i=0; i < create_pdr->urr_id_count; i++ ) {
		size += set_urr_id(&(create_pdr->urr_id[i]), bearer_pdr->urr.urr_id_value);
	}
	/* TODO: Revisit this for change in yang*/
	if (cp_type != SGWC){
		for(int i=0; i < create_pdr->qer_id_count; i++ ) {
			size += set_qer_id(&(create_pdr->qer_id[i]), bearer_pdr->qer_id[i].qer_id);
		}
	}
#endif /* CP_BUILD */

	pfcp_set_ie_header(&(create_pdr->header), IE_CREATE_PDR, size);

	return size;
}

void
set_create_far(pfcp_create_far_ie_t *create_far, far_t *bearer_far)
{
	uint16_t len = 0;

	len += set_far_id(&(create_far->far_id), bearer_far->far_id_value);
	len += set_apply_action(&(create_far->apply_action), &bearer_far->actions);

	pfcp_set_ie_header(&(create_far->header), IE_CREATE_FAR, len);
}

void
set_create_urr(pfcp_create_urr_ie_t *create_urr, pdr_t *bearer_pdr)
{
	uint16_t len = 0;

	len += set_urr_id(&(create_urr->urr_id), bearer_pdr->urr.urr_id_value);
	len += set_measurement_method(&(create_urr->meas_mthd), &bearer_pdr->urr);
	len += set_reporting_trigger(&(create_urr->rptng_triggers), &bearer_pdr->urr);
	if(bearer_pdr->urr.rept_trigg.volth == PRESENT)
		len += set_volume_threshold(&(create_urr->vol_thresh), &bearer_pdr->urr,
										bearer_pdr->pdi.src_intfc.interface_value);
	if(bearer_pdr->urr.rept_trigg.timth == PRESENT)
		len += set_time_threshold(&(create_urr->time_threshold), &bearer_pdr->urr);

	pfcp_set_ie_header(&(create_urr->header), IE_CREATE_URR, len);
}

void
set_create_bar(pfcp_create_bar_ie_t *create_bar, bar_t *bearer_bar)
{
	uint16_t len = 0;

	len += set_bar_id(&(create_bar->bar_id), bearer_bar->bar_id);
	/* len += set_sgstd_buff_pkts_cnt(&(create_bar->suggstd_buf_pckts_cnt),
		bearer_bar->suggstd_buf_pckts_cnt.pckt_cnt_val);
	set_dl_data_notification_delay(&(create_bar->dnlnk_data_notif_delay)); */

	pfcp_set_ie_header(&(create_bar->header), IE_CREATE_BAR, len);
}

int
set_update_pdr(pfcp_update_pdr_ie_t *update_pdr, pdr_t *bearer_pdr, uint8_t cp_type)
{
	int size = 0;

	size += set_pdr_id(&(update_pdr->pdr_id), bearer_pdr->rule_id);
	size += set_precedence(&(update_pdr->precedence), bearer_pdr->prcdnc_val);
	size += set_pdi(&(update_pdr->pdi), &bearer_pdr->pdi, cp_type);
#ifdef CP_BUILD
	uint8_t outer_header_desc = 0;

	if (cp_type != SGWC &&
		bearer_pdr->pdi.src_intfc.interface_value == SOURCE_INTERFACE_VALUE_ACCESS) {

		if (update_pdr->pdi.local_fteid.v6)
			outer_header_desc = GTP_U_UDP_IPv6;
		else if (update_pdr->pdi.local_fteid.v4)
			outer_header_desc = GTP_U_UDP_IPv4;

		size += set_outer_hdr_removal(&(update_pdr->outer_hdr_removal), outer_header_desc);
	}
	size += set_far_id(&(update_pdr->far_id), bearer_pdr->far.far_id_value);
#endif /* CP_BUILD */

	pfcp_set_ie_header(&(update_pdr->header), IE_UPDATE_PDR, size);

	return size;
}

void
creating_bar(pfcp_create_bar_ie_t *create_bar)
{
	pfcp_set_ie_header(&(create_bar->header), IE_CREATE_BAR,
			sizeof(pfcp_create_bar_ie_t) - sizeof(pfcp_ie_header_t));

	set_bar_id(&(create_bar->bar_id), 1);
	set_dl_data_notification_delay(&(create_bar->dnlnk_data_notif_delay));
	set_sgstd_buff_pkts_cnt(&(create_bar->suggstd_buf_pckts_cnt), 11);
}

uint16_t
set_apply_action(pfcp_apply_action_ie_t *apply_action_t, apply_action *bearer_action)
{
	pfcp_set_ie_header(&(apply_action_t->header), IE_APPLY_ACTION_ID, UINT8_SIZE);
	apply_action_t->apply_act_spare = 0;
	apply_action_t->apply_act_spare2 = 0;
	apply_action_t->apply_act_spare3 = 0;
	apply_action_t->dupl = bearer_action->dupl;
	apply_action_t->nocp = bearer_action->nocp;
	apply_action_t->buff = bearer_action->buff;
	apply_action_t->forw = bearer_action->forw;
	apply_action_t->drop = bearer_action->drop;

	return sizeof(pfcp_apply_action_ie_t);
}

uint16_t
set_measurement_method(pfcp_meas_mthd_ie_t *meas_mt, urr_t *bearer_urr)
{
	pfcp_set_ie_header(&(meas_mt->header), PFCP_IE_MEAS_MTHD, UINT8_SIZE);
	meas_mt->event = 0;
	meas_mt->volum = bearer_urr->mea_mt.volum;
	meas_mt->durat = bearer_urr->mea_mt.durat;

	return sizeof(pfcp_meas_mthd_ie_t);
}

uint16_t
set_reporting_trigger(pfcp_rptng_triggers_ie_t *rptng_triggers, urr_t *bearer_urr)
{
	pfcp_set_ie_header(&(rptng_triggers->header), PFCP_IE_RPTNG_TRIGGERS, UINT16_SIZE);
	rptng_triggers->volth = bearer_urr->rept_trigg.volth;
	rptng_triggers->timth = bearer_urr->rept_trigg.timth;

	return sizeof(pfcp_rptng_triggers_ie_t);

}


int
set_volume_threshold(pfcp_vol_thresh_ie_t *vol_thresh, urr_t *bearer_urr, uint8_t interface_value)
{
	int size = sizeof(pfcp_ie_header_t) + sizeof(uint8_t);

	if(interface_value == SOURCE_INTERFACE_VALUE_ACCESS){
		vol_thresh->ulvol = PRESENT;
		vol_thresh->uplink_volume = bearer_urr->vol_th.uplink_volume;
		size += sizeof(uint64_t);

	}else{
		vol_thresh->dlvol = PRESENT;
		vol_thresh->downlink_volume = bearer_urr->vol_th.downlink_volume;
		size += sizeof(uint64_t);
	}

	pfcp_set_ie_header(&(vol_thresh->header), PFCP_IE_VOL_THRESH, size - sizeof(pfcp_ie_header_t));

	return size;

}

int
set_volume_measurment(pfcp_vol_meas_ie_t *vol_meas)
{
	int size = sizeof(pfcp_vol_meas_ie_t);

	pfcp_set_ie_header(&(vol_meas->header), PFCP_IE_VOL_MEAS,
			sizeof(pfcp_vol_meas_ie_t) - sizeof(pfcp_ie_header_t));
	vol_meas->tovol = 1;
	vol_meas->dlvol = 1;
	vol_meas->ulvol = 1;
	vol_meas->total_volume = 0;
	vol_meas->uplink_volume = 0;
	vol_meas->downlink_volume = 0;

	return size;

}

int
set_start_time(pfcp_start_time_ie_t *start_time)
{
	int size = sizeof(pfcp_start_time_ie_t);

	pfcp_set_ie_header(&(start_time->header), PFCP_IE_START_TIME, sizeof(uint32_t));
	start_time->start_time = 0;

	return size;
}

int
set_end_time(pfcp_end_time_ie_t *end_time)
{
	int size = sizeof(pfcp_end_time_ie_t);

	pfcp_set_ie_header(&(end_time->header), PFCP_IE_END_TIME, sizeof(uint32_t));
	end_time->end_time = 0;

	return size;
}

int
set_first_pkt_time(pfcp_time_of_frst_pckt_ie_t *first_pkt_time)
{
	int size = sizeof(pfcp_time_of_frst_pckt_ie_t);

	pfcp_set_ie_header(&(first_pkt_time->header), PFCP_IE_TIME_OF_FRST_PCKT,
														sizeof(uint32_t));
	first_pkt_time->time_of_frst_pckt = 0;

	return size;
}

int
set_last_pkt_time(pfcp_time_of_lst_pckt_ie_t *last_pkt_time)
{
	int size = sizeof(pfcp_time_of_lst_pckt_ie_t);

	pfcp_set_ie_header(&(last_pkt_time->header), PFCP_IE_TIME_OF_LST_PCKT,
														sizeof(uint32_t));
	last_pkt_time->time_of_lst_pckt = 0;

	return size;
}

int
set_time_threshold(pfcp_time_threshold_ie_t *time_thresh, urr_t *bearer_urr)
{
	int size = sizeof(pfcp_time_threshold_ie_t);

	pfcp_set_ie_header(&(time_thresh->header), PFCP_IE_TIME_THRESHOLD,
			sizeof(pfcp_time_threshold_ie_t) - sizeof(pfcp_ie_header_t));
	time_thresh->time_threshold = bearer_urr->time_th.time_threshold;

	return size;

}

uint16_t
set_forwarding_param(pfcp_frwdng_parms_ie_t *frwdng_parms,
		node_address_t node_value, uint32_t teid, uint8_t interface_value)
{
	uint16_t len = 0;
	len += set_destination_interface(&(frwdng_parms->dst_intfc), interface_value);
	len += set_outer_header_creation(&(frwdng_parms->outer_hdr_creation),
											node_value, teid);

	pfcp_set_ie_header(&(frwdng_parms->header), IE_FRWDNG_PARMS, len);

	return len + sizeof(pfcp_ie_header_t);
}

uint16_t
set_duplicating_param(pfcp_dupng_parms_ie_t *dupng_parms)
{
	uint16_t len = 0;
	node_address_t node_value = {0};
	len += set_destination_interface(&(dupng_parms->dst_intfc), 5);
	len += set_outer_header_creation(&(dupng_parms->outer_hdr_creation), node_value, 0);
	len += set_frwding_policy(&(dupng_parms->frwdng_plcy));

	pfcp_set_ie_header(&(dupng_parms->header), IE_DUPNG_PARMS, len);

	return len;
}

uint16_t
set_upd_duplicating_param(pfcp_upd_dupng_parms_ie_t *dupng_parms)
{
	uint16_t len = 0;
	node_address_t node_value = {0};
	len += set_destination_interface(&(dupng_parms->dst_intfc), 5);
	len += set_outer_header_creation(&(dupng_parms->outer_hdr_creation), node_value, 0);
	len += set_frwding_policy(&(dupng_parms->frwdng_plcy));
	len += PFCP_IE_HEADER_SIZE * 3;
	pfcp_set_ie_header(&(dupng_parms->header), IE_DUPNG_PARMS, len);

	return len;
}

uint16_t
set_upd_forwarding_param(pfcp_upd_frwdng_parms_ie_t *upd_frwdng_parms,
											node_address_t node_value)
{
	uint16_t len = 0;
	len += set_destination_interface(&(upd_frwdng_parms->dst_intfc), 0);
	len += set_outer_header_creation(&(upd_frwdng_parms->outer_hdr_creation), node_value, 0);

	pfcp_set_ie_header(&(upd_frwdng_parms->header), IE_UPD_FRWDNG_PARMS, len);
	return len;
}

uint16_t
set_frwding_policy(pfcp_frwdng_plcy_ie_t *frwdng_plcy){

	uint16_t len = 0;
	frwdng_plcy->frwdng_plcy_ident_len = sizeof(uint8_t);
	len += sizeof(uint8_t);
	memset(frwdng_plcy->frwdng_plcy_ident, 0, sizeof(frwdng_plcy->frwdng_plcy_ident));
	len += sizeof(frwdng_plcy->frwdng_plcy_ident);

	pfcp_set_ie_header(&(frwdng_plcy->header), PFCP_IE_FRWDNG_PLCY, len);

	return len;

}

uint16_t
set_outer_header_creation(pfcp_outer_hdr_creation_ie_t *outer_hdr_creation,
						node_address_t node_value, uint32_t teid)
{
	uint16_t len = 0;

	outer_hdr_creation->teid = teid;
	len += sizeof(outer_hdr_creation->teid);

	if (node_value.ip_type == PDN_TYPE_IPV6 || node_value.ip_type == PDN_TYPE_IPV4_IPV6) {

		memcpy(outer_hdr_creation->ipv6_address, node_value.ipv6_addr, IPV6_ADDRESS_LEN);
		len += sizeof(outer_hdr_creation->ipv6_address);

		outer_hdr_creation->outer_hdr_creation_desc.gtpu_udp_ipv6 = PRESENT;

	} else if (node_value.ip_type == PDN_TYPE_IPV4) {

		outer_hdr_creation->ipv4_address = node_value.ipv4_addr;
		len += sizeof(outer_hdr_creation->ipv4_address);

		outer_hdr_creation->outer_hdr_creation_desc.gtpu_udp_ipv4 = PRESENT;
	}

	len += sizeof(outer_hdr_creation->outer_hdr_creation_desc);

	pfcp_set_ie_header(&(outer_hdr_creation->header), PFCP_IE_OUTER_HDR_CREATION, len);

	return (len + sizeof(pfcp_ie_header_t));
}

uint16_t
set_destination_interface(pfcp_dst_intfc_ie_t *dst_intfc, uint8_t interface_value)
{
	dst_intfc->dst_intfc_spare = 0;
	dst_intfc->interface_value = interface_value;
	pfcp_set_ie_header(&(dst_intfc->header), IE_DEST_INTRFACE_ID, UINT8_SIZE);
	return sizeof(pfcp_dst_intfc_ie_t);
}

void
set_fq_csid(pfcp_fqcsid_ie_t *fq_csid,uint32_t nodeid_value)
{
	fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;
	/* TODO identify the number of CSID */
	fq_csid->number_of_csids = 1;
	memcpy(&(fq_csid->node_address), &nodeid_value, IPV4_SIZE);

	for(int i = 0; i < fq_csid->number_of_csids ;i++) {
		/*PDN CONN value is 0 when it is not used */
		fq_csid->pdn_conn_set_ident[i] = 0;
		/*fq_csid->pdn_conn_set_ident[i] = htons(pdn_conn_set_id++);*/
	}

	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID,2*(fq_csid->number_of_csids) + 5);

}


#ifdef CP_BUILD
void
set_user_id(pfcp_user_id_ie_t *user_id, uint64_t imsi)
{
	user_id->user_id_spare   = 0;
	user_id->naif    = 0;
	user_id->msisdnf = 0;
	user_id->imeif   = 0;
	user_id->imsif   = 1;
	user_id->length_of_imsi   = BINARY_IMSI_LEN;
	user_id->length_of_imei   = 0;
	user_id->len_of_msisdn = 0;
	user_id->length_of_nai    = 0;

	encode_imsi_to_bin(imsi, BINARY_IMSI_LEN , user_id->imsi);

	pfcp_set_ie_header(&(user_id->header), PFCP_IE_USER_ID , USER_ID_LEN);
}
#endif /* CP_BUILD */

void
set_fseid(pfcp_fseid_ie_t *fseid,uint64_t seid, node_address_t node_value)
{

	int size = sizeof(uint8_t);

	fseid->fseid_spare  = 0;
	fseid->fseid_spare2 = 0;
	fseid->fseid_spare3 = 0;
	fseid->fseid_spare4 = 0;
	fseid->fseid_spare5 = 0;
	fseid->fseid_spare6 = 0;

	size += sizeof(uint64_t);
	fseid->seid = seid;

	if (node_value.ip_type == PDN_TYPE_IPV6) {
		/* IPv6 Handling */
		size += sizeof(struct in6_addr);

		fseid->v6 = PRESENT;
		memcpy(fseid->ipv6_address, node_value.ipv6_addr, IPV6_ADDRESS_LEN);

	} else if (node_value.ip_type == PDN_TYPE_IPV4) {
		/* IPv4 Handling */
		size += sizeof(struct in_addr);

		fseid->v4 = PRESENT;
		fseid->ipv4_address = node_value.ipv4_addr;
	}

	pfcp_set_ie_header(&(fseid->header), PFCP_IE_FSEID, size);

}

int
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val)
{
	int ie_length = sizeof(pfcp_cause_ie_t);

	pfcp_set_ie_header(&(cause->header), PFCP_IE_CAUSE,
			(sizeof(pfcp_cause_ie_t) - sizeof(pfcp_ie_header_t)));
	cause->cause_value = cause_val;

	return ie_length;
}

void
set_remove_pdr(pfcp_remove_pdr_ie_t *remove_pdr, uint16_t pdr_id_value)
{
	pfcp_set_ie_header(&(remove_pdr->header), IE_REMOVE_PDR, sizeof(pfcp_pdr_id_ie_t));
	set_pdr_id(&(remove_pdr->pdr_id), pdr_id_value);
}

void
set_remove_bar(pfcp_remove_bar_ie_t *remove_bar, uint8_t bar_id_value)
{
	pfcp_set_ie_header(&(remove_bar->header), IE_REMOVE_BAR, sizeof(pfcp_bar_id_ie_t));
	set_bar_id(&(remove_bar->bar_id), bar_id_value);
}

void
set_traffic_endpoint(pfcp_traffic_endpt_id_ie_t *traffic_endpoint_id)
{
	pfcp_set_ie_header(&(traffic_endpoint_id->header), PFCP_IE_TRAFFIC_ENDPT_ID, UINT8_SIZE);
	traffic_endpoint_id->traffic_endpt_id_val = 2;

}

int
set_fteid( pfcp_fteid_ie_t *local_fteid, fteid_ie_t *local_fteid_value)
{
	int size = sizeof(uint8_t);

	local_fteid->chid = 0;
	local_fteid->ch = 0;

	local_fteid->fteid_spare = 0;

	if(local_fteid_value == NULL) {
			local_fteid->teid = 0;
			local_fteid->ipv4_address = 0;
			memset(local_fteid->ipv6_address, 0, sizeof(local_fteid->ipv6_address));
			size = sizeof(uint32_t) + sizeof(struct in_addr) + sizeof(struct in6_addr);

	} else {

		local_fteid->teid = local_fteid_value->teid;
		size += sizeof(uint32_t);
		if ((local_fteid_value->v4 == PRESENT) && (local_fteid_value->ch == 0)) {

			local_fteid->v4 = PRESENT;
			local_fteid->ipv4_address = local_fteid_value->ipv4_address;
			size += sizeof(struct in_addr);
		}

		if ((local_fteid_value->v6 == PRESENT) && (local_fteid_value->ch == 0)) {

			local_fteid->v6 = PRESENT;
			memcpy(local_fteid->ipv6_address,
					local_fteid_value->ipv6_address, IPV6_ADDRESS_LEN);
			size += sizeof(struct in6_addr);
		}
	}

	pfcp_set_ie_header(&(local_fteid->header), PFCP_IE_FTEID, size);

	return size + sizeof(pfcp_ie_header_t);
}

int
set_network_instance(pfcp_ntwk_inst_ie_t *network_instance,
						ntwk_inst_t *network_instance_value) {

	int size = sizeof(pfcp_ntwk_inst_ie_t);
	pfcp_set_ie_header(&(network_instance->header), PFCP_IE_NTWK_INST,
			(sizeof(pfcp_ntwk_inst_ie_t) - sizeof(pfcp_ie_header_t)));
	strncpy((char *)network_instance->ntwk_inst, (char *)&network_instance_value->ntwk_inst, PFCP_NTWK_INST_LEN);

	return size;
}

int
set_ue_ip(pfcp_ue_ip_address_ie_t *ue_ip, ue_ip_addr_t ue_addr)
{
	int size = sizeof(pfcp_ue_ip_address_ie_t) -
		(sizeof(ue_ip->ipv4_address) + sizeof(ue_ip->ipv6_address) + sizeof(ue_ip->ipv6_pfx_dlgtn_bits));

	/* Need to remove hard coded values */
	ue_ip->ue_ip_addr_spare = 0;
	ue_ip->ipv6d = 0;
	ue_ip->sd = 0;

	if (ue_addr.v4 == 1) {
		ue_ip->v4 = 1;
		memcpy(&(ue_ip->ipv4_address), &ue_addr.ipv4_address, IPV4_SIZE);
		size += sizeof(ue_ip->ipv4_address);
	}

	/* TODO: IPv6 handling */
	if (ue_addr.v6 == 1) {
		if (ue_ip->ipv6d == 1) {
			/* Use IPv6 prefix */
			// size += sizeof(ue_ip->ipv6_pfx_dlgtn_bits);
		} else {
			/* Use default 64 prefix */
		}
		/* IPv6 Handling */
		ue_ip->v6 = 1;
		memcpy(ue_ip->ipv6_address, ue_addr.ipv6_address, IPV6_ADDRESS_LEN);
		size += sizeof(ue_ip->ipv6_address);
	}

	/* TODO: Need to merge below if and else in above conditions */
	if (ue_addr.sd == 0) {
		/* Source IP Address */
	} else {
		/* Destination IP Address */
	}

	pfcp_set_ie_header(&(ue_ip->header), PFCP_IE_UE_IP_ADDRESS,
			(size - sizeof(pfcp_ie_header_t)));

	return size;
}

int
set_qer_id(pfcp_qer_id_ie_t *qer_id, uint32_t qer_id_value)
{

	int size = sizeof(pfcp_qer_id_ie_t);

	pfcp_set_ie_header(&(qer_id->header), PFCP_IE_QER_ID,
			(sizeof(pfcp_qer_id_ie_t) - sizeof(pfcp_ie_header_t)));
	qer_id->qer_id_value = qer_id_value;

	return size;
}

int
set_gate_status( pfcp_gate_status_ie_t *gate_status, gate_status_t *qer_gate_status)
{
	int size = sizeof(pfcp_gate_status_ie_t);

	pfcp_set_ie_header(&(gate_status->header), PFCP_IE_GATE_STATUS,
			(sizeof(pfcp_gate_status_ie_t) - sizeof(pfcp_ie_header_t)));

	gate_status->gate_status_spare = 0;
	gate_status->ul_gate = qer_gate_status->ul_gate;
	gate_status->dl_gate = qer_gate_status->dl_gate;

	return size;
}

int
set_mbr(pfcp_mbr_ie_t *mbr, mbr_t *qer_mbr)
{
	int size = sizeof(pfcp_mbr_ie_t);

	pfcp_set_ie_header(&(mbr->header), PFCP_IE_MBR,
			(sizeof(pfcp_mbr_ie_t) - sizeof(pfcp_ie_header_t)));

	mbr->ul_mbr = qer_mbr->ul_mbr;
	mbr->dl_mbr = qer_mbr->dl_mbr;

	return size;
}

int
set_gbr(pfcp_gbr_ie_t *gbr, gbr_t *qer_gbr)
{
	int size = sizeof(pfcp_gbr_ie_t);

	pfcp_set_ie_header(&(gbr->header), PFCP_IE_GBR,
			(sizeof(pfcp_gbr_ie_t) - sizeof(pfcp_ie_header_t)));

	gbr->ul_gbr = qer_gbr->ul_gbr;
	gbr->dl_gbr = qer_gbr->dl_gbr;

	return size ;
}

void
set_create_qer(pfcp_create_qer_ie_t *qer, qer_t *bearer_qer)
{
	int size = 0;

	size += set_qer_id(&(qer->qer_id), bearer_qer->qer_id);

	size += set_gate_status(&(qer->gate_status), &(bearer_qer->gate_status));

	size += set_mbr(&(qer->maximum_bitrate), &(bearer_qer->max_bitrate));

	size += set_gbr(&(qer->guaranteed_bitrate), &(bearer_qer->guaranteed_bitrate));

	pfcp_set_ie_header(&(qer->header), IE_CREATE_QER, size);

}

void
set_update_qer(pfcp_update_qer_ie_t *up_qer, qer_t *bearer_qer)
{
	int size = 0;

	size += set_qer_id(&(up_qer->qer_id), bearer_qer->qer_id);

	size += set_mbr(&(up_qer->maximum_bitrate), &(bearer_qer->max_bitrate));

	size += set_gbr(&(up_qer->guaranteed_bitrate), &(bearer_qer->guaranteed_bitrate));

	pfcp_set_ie_header(&(up_qer->header), IE_UPDATE_QER, size);
}

void
updating_bar( pfcp_upd_bar_sess_mod_req_ie_t *up_bar)
{
	set_bar_id(&(up_bar->bar_id), 1);
	set_dl_data_notification_delay(&(up_bar->dnlnk_data_notif_delay));
	set_sgstd_buff_pkts_cnt(&(up_bar->suggstd_buf_pckts_cnt), 111);

	uint8_t size =  sizeof(pfcp_bar_id_ie_t) + sizeof(pfcp_dnlnk_data_notif_delay_ie_t)+
	sizeof(pfcp_suggstd_buf_pckts_cnt_ie_t);
	pfcp_set_ie_header(&(up_bar->header), IE_UPD_BAR_SESS_MOD_REQ, size);
}

void
set_update_bar_sess_rpt_rsp(pfcp_upd_bar_sess_rpt_rsp_ie_t *up_bar, bar_t *bearer_bar)
{
	uint16_t len = 0;

	len = set_bar_id(&(up_bar->bar_id), bearer_bar->bar_id);
	len += set_dl_buf_sgstd_pkts_cnt(&(up_bar->dl_buf_suggstd_pckt_cnt),
			bearer_bar->dl_buf_suggstd_pckts_cnt.pckt_cnt_val);

	pfcp_set_ie_header(&(up_bar->header), IE_UPDATE_BAR_SESS_RPT_RESP, len);

	/* set_dl_data_notification_delay(&(up_bar->dnlnk_data_notif_delay));
	set_sgstd_buff_pkts_cnt(&(up_bar->suggstd_buf_pckts_cnt), 111);

	uint8_t size =  sizeof(pfcp_bar_id_ie_t) + sizeof(pfcp_dnlnk_data_notif_delay_ie_t)+
	sizeof(pfcp_suggstd_buf_pckts_cnt_ie_t);
	pfcp_set_ie_header(&(up_bar->header), IE_UPD_BAR_SESS_MOD_REQ, size); */
}

void
set_update_far(pfcp_update_far_ie_t *up_far, far_t *bearer_far)
{
	uint16_t len = 0;
	if(bearer_far != NULL){
		len += set_far_id(&(up_far->far_id), bearer_far->far_id_value);
		len += set_apply_action(&(up_far->apply_action), &bearer_far->actions);
	}else{
		apply_action action = {0};
		len += set_far_id(&(up_far->far_id), 0);
		len += set_apply_action(&(up_far->apply_action), &action);
	}
	pfcp_set_ie_header(&(up_far->header), IE_UPDATE_FAR, len);
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
	query_urr_ref->query_urr_ref_val = 0;

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
	seq->sequence_number = 0;
}

void
set_metric(pfcp_metric_ie_t *metric)
{
	pfcp_set_ie_header(&(metric->header), PFCP_IE_METRIC, UINT8_SIZE);
	metric->metric = 0;
}

void
set_period_of_validity(pfcp_timer_ie_t *pov)
{
	pfcp_set_ie_header(&(pov->header), PFCP_IE_TIMER, UINT8_SIZE);
	pov->timer_unit =
		TIMER_INFORMATIONLEMENT_VALUE_IS_INCREMENTED_IN_MULTIPLES_OF_2_SECONDS ;
	pov->timer_value = 0;
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
	rule->rule_id_value = 0;
}

void
set_traffic_endpoint_id(pfcp_traffic_endpt_id_ie_t *tnp)
{
	pfcp_set_ie_header(&(tnp->header), PFCP_IE_TRAFFIC_ENDPT_ID, UINT8_SIZE);
	tnp->traffic_endpt_id_val = 0;
}

int
set_pdr_id_ie(pfcp_pdr_id_ie_t *pdr)
{
	int ie_length = sizeof(pfcp_pdr_id_ie_t);

	pfcp_set_ie_header(&(pdr->header), PFCP_IE_PDR_ID,
			sizeof(pfcp_pdr_id_ie_t) - PFCP_IE_HDR_SIZE);
	pdr->rule_id = 0;

	return ie_length;
}

int
set_created_pdr_ie(pfcp_created_pdr_ie_t *pdr)
{
	int ie_length = 0;

	ie_length += set_pdr_id_ie(&(pdr->pdr_id));
	ie_length += set_fteid(&(pdr->local_fteid), NULL);

	pfcp_set_ie_header(&(pdr->header), IE_CREATED_PDR, ie_length);

	ie_length += PFCP_IE_HDR_SIZE;
	return ie_length;
}

void set_created_traffic_endpoint(pfcp_created_traffic_endpt_ie_t *cte)
{
	pfcp_set_ie_header(&(cte->header), IE_CREATE_TRAFFIC_ENDPT, 18);
	set_traffic_endpoint_id(&(cte->traffic_endpt_id));
	set_fteid(&(cte->local_fteid), NULL);

}

void
set_node_report_type( pfcp_node_rpt_type_ie_t *nrt)
{
	pfcp_set_ie_header(&(nrt->header), PFCP_IE_NODE_RPT_TYPE, UINT8_SIZE);
	nrt->node_rpt_type_spare = 0;
	nrt->upfr = 0;
}

void
set_user_plane_path_failure_report(pfcp_user_plane_path_fail_rpt_ie_t *uppfr)
{
	pfcp_set_ie_header(&(uppfr->header), IE_USER_PLANE_PATH_FAIL_RPT,
			sizeof(pfcp_rmt_gtpu_peer_ie_t));
	uppfr->rmt_gtpu_peer_count = 0;
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

	}


	if (!(pfcp_ass_setup_req->rcvry_time_stmp.header.len)) {

		*cause_id = MANDATORYIEMISSING;
		*offend_id =PFCP_IE_RCVRY_TIME_STMP;
	} else if(pfcp_ass_setup_req->rcvry_time_stmp.header.len != RECOV_TIMESTAMP_LEN){

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
	}

	if(!(pfcp_session_request->cp_fseid.header.len)){

		*offend_id = PFCP_IE_FSEID;
		*cause_id = MANDATORYIEMISSING;

	} else if (pfcp_session_request->cp_fseid.v6
				&& pfcp_session_request->cp_fseid.v4) {

		if (pfcp_session_request->cp_fseid.header.len != CP_FSEID_LEN_V4V6)
			*cause_id = INVALIDLENGTH;

	} else if (pfcp_session_request->cp_fseid.v4) {

		if (pfcp_session_request->cp_fseid.header.len != CP_FSEID_LEN_V4)
			*cause_id = INVALIDLENGTH;
	} else if (pfcp_session_request->cp_fseid.v6) {

		if (pfcp_session_request->cp_fseid.header.len != CP_FSEID_LEN_V6)
			*cause_id = INVALIDLENGTH;
	}

	if(!pfcp_session_request->create_far_count) {

		*offend_id = PFCP_IE_FAR_ID;
		*cause_id = MANDATORYIEMISSING;

	} else {
		for(uint8_t i = 0; i < pfcp_session_request->create_far_count; i++){
			if(!pfcp_session_request->create_far[i].far_id.header.len){

				*offend_id = PFCP_IE_FAR_ID;
				*cause_id = MANDATORYIEMISSING;
				return;
			}

			if(!pfcp_session_request->create_far[i].apply_action.header.len){

				*offend_id = PFCP_IE_APPLY_ACTION;
				*cause_id = MANDATORYIEMISSING;
				return;
			}
		}
	}

	if(!pfcp_session_request->create_pdr_count){

		*offend_id = PFCP_IE_PDR_ID;
		*cause_id = MANDATORYIEMISSING;

	}else{
		for(uint8_t i =0; i < pfcp_session_request->create_pdr_count; i++){
			if(!pfcp_session_request->create_pdr[i].pdr_id.header.len){

				*offend_id = PFCP_IE_PDR_ID;
				*cause_id = MANDATORYIEMISSING;
				return;
			}

			if(!pfcp_session_request->create_pdr[i].precedence.header.len){

				*offend_id = PFCP_IE_PRECEDENCE;
				*cause_id = MANDATORYIEMISSING;
				return;
			}

			if(!pfcp_session_request->create_pdr[i].pdi.header.len){

				*offend_id = IE_PDI;
				*cause_id = MANDATORYIEMISSING;
				return;
			}else{
				if(!pfcp_session_request->create_pdr[i].pdi.src_intfc.header.len){
					*offend_id = PFCP_IE_SRC_INTFC;
					*cause_id = MANDATORYIEMISSING;
					return;
				}
			}
		}
	}

}

#ifdef CP_BUILD

int
gx_context_entry_add(char *sess_id, gx_context_t *entry)
{
	int ret = 0;
	ret = rte_hash_add_key_data(gx_context_by_sess_id_hash,
			(const void *)sess_id , (void *)entry);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT" Failed to add GX context entry in hash\n",
			LOG_VALUE, strerror(ret));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}
	return 0;
}

int
gx_context_entry_lookup(char *sess_id, gx_context_t **entry)
{
	int ret = rte_hash_lookup_data(gx_context_by_sess_id_hash,
			(const void*) (sess_id), (void **) entry);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NO ENTRY FOUND IN UPF "
			"HASH [%s]\n", LOG_VALUE, sess_id);
		return -1;
	}

	return 0;
}


uint8_t
upf_context_entry_add(node_address_t *upf_ip, upf_context_t *entry)
{
	int ret = 0;
	ret = rte_hash_add_key_data(upf_context_by_ip_hash,
			(const void *)upf_ip , (void *)entry);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to add UPF "
			"context entry in hash for IP Type : %s\n"
			"with IP IPv4 : "IPV4_ADDR"\tIPv6 : "IPv6_FMT"", LOG_VALUE,
			ip_type_str(upf_ip->ip_type),
			IPV4_ADDR_HOST_FORMAT(upf_ip->ipv4_addr),
			PRINT_IPV6_ADDR(upf_ip->ipv6_addr));
		return 1;
	}
	return 0;
}

int
upf_context_entry_lookup(node_address_t upf_ip, upf_context_t **entry)
{
	int ret = rte_hash_lookup_data(upf_context_by_ip_hash,
			(const void*) &(upf_ip), (void **) entry);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" NO ENTRY FOUND IN UPF "
			"HASH for IP Type : %s\n"
			"with IP IPv4 : "IPV4_ADDR"\tIPv6 : "IPv6_FMT"", LOG_VALUE,
			ip_type_str(upf_ip.ip_type),
			IPV4_ADDR_HOST_FORMAT(upf_ip.ipv4_addr),
			PRINT_IPV6_ADDR(upf_ip.ipv6_addr));

		return -1;
	}

	return 0;
}

#endif /* CP_BUILD */

void
cause_check_sess_modification(pfcp_sess_mod_req_t *pfcp_session_mod_req,
		uint8_t *cause_id, int *offend_id)
{
	*cause_id  = REQUESTACCEPTED;
	*offend_id = 0;

	if(!(pfcp_session_mod_req->cp_fseid.header.len)){
		*cause_id = CONDITIONALIEMISSING;
		*offend_id = PFCP_IE_FSEID;
	} else if (pfcp_session_mod_req->cp_fseid.v6
				&& pfcp_session_mod_req->cp_fseid.v4) {

		if (pfcp_session_mod_req->cp_fseid.header.len != CP_FSEID_LEN_V4V6)
			*cause_id = INVALIDLENGTH;

	} else if (pfcp_session_mod_req->cp_fseid.v4) {

		if (pfcp_session_mod_req->cp_fseid.header.len != CP_FSEID_LEN_V4)
			*cause_id = INVALIDLENGTH;
	} else if (pfcp_session_mod_req->cp_fseid.v6) {

		if (pfcp_session_mod_req->cp_fseid.header.len != CP_FSEID_LEN_V6)
			*cause_id = INVALIDLENGTH;
	}


	if( pfcp_ctxt.up_supported_features & UP_PDIU ) {
		if(!(pfcp_session_mod_req->rmv_traffic_endpt.header.len)) {

			*cause_id = CONDITIONALIEMISSING;
			*offend_id = IE_RMV_TRAFFIC_ENDPT;
		} else if(pfcp_session_mod_req->rmv_traffic_endpt.header.len !=
				REMOVE_TRAFFIC_ENDPOINT_LEN) {

		}

		if(!(pfcp_session_mod_req->create_traffic_endpt.header.len)) {

			*cause_id = CONDITIONALIEMISSING;
			*offend_id = IE_CREATE_TRAFFIC_ENDPT ;
		} else if (pfcp_session_mod_req->create_traffic_endpt.header.len !=
				CREATE_TRAFFIC_ENDPOINT_LEN){

		}
	}

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
add_data_to_heartbeat_hash_table(node_address_t *key, uint32_t *recov_time)
{
	int ret = 0;
	uint32_t *temp = NULL;

	temp = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (temp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory data to add in heartbeat hash, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
		return 1;
	}
	*temp = *recov_time;
	ret = rte_hash_add_key_data(heartbeat_recovery_hash,
			(const void *)key, temp);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to add data in "
			"heartbeat recovery hash\n", LOG_VALUE, strerror(ret));
		rte_free(temp);
		return 1;
	}
	return 0;
}

void get_peer_node_addr(peer_addr_t *peer_addr, node_address_t *node_addr) {

	switch(peer_addr->type) {
		case PDN_TYPE_IPV4 :
				node_addr->ip_type = PDN_TYPE_IPV4;
				node_addr->ipv4_addr = peer_addr->ipv4.sin_addr.s_addr;
				break;
		case PDN_TYPE_IPV6 :
				node_addr->ip_type = PDN_TYPE_IPV6;
				memcpy(&node_addr->ipv6_addr,
						&peer_addr->ipv6.sin6_addr.s6_addr,
						IPV6_ADDRESS_LEN);
				break;
		case PDN_TYPE_IPV4_IPV6:
				node_addr->ip_type = PDN_TYPE_IPV6;
				memcpy(&node_addr->ipv6_addr,
						&peer_addr->ipv6.sin6_addr.s6_addr,
						IPV6_ADDRESS_LEN);
				break;
		default :
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Neither IPv4 nor "
								"IPv6 type is set ", LOG_VALUE);
				break;
	}

}

void add_ip_to_heartbeat_hash(node_address_t *peer_addr, uint32_t recovery_time)
{
	uint32_t *default_recov_time = NULL;
	default_recov_time = rte_zmalloc_socket(NULL, sizeof(uint32_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	if(default_recov_time == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate "
			"memory to default recovery time, Error : %s\n", LOG_VALUE,
			rte_strerror(rte_errno));
	} else {
		*default_recov_time = recovery_time;
		int ret = add_data_to_heartbeat_hash_table(peer_addr,
				default_recov_time);

		if(ret !=0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to add "
				"default recovery time in heartbeat recovery hash\n",
				LOG_VALUE, strerror(ret));
		}

		if (default_recov_time != NULL) {
			rte_free(default_recov_time);
			default_recov_time = NULL;
		}
	}
}


void delete_entry_heartbeat_hash(node_address_t *node_addr)
{
	int ret = 0;

	ret = rte_hash_del_key(heartbeat_recovery_hash,
			(const void *)(node_addr));
	if (ret == -EINVAL || ret == -ENOENT) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Error on "
			"rte_delete_enrty_key_data add in heartbeat\n", LOG_VALUE,
			strerror(ret));
	}
}

void clear_heartbeat_hash_table(void)
{
	rte_hash_free(heartbeat_recovery_hash);
}

#ifdef CP_BUILD
void
create_gx_context_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "gx_context_by_sess_id_hash",
	    .entries = UPF_ENTRIES_DEFAULT,
	    .key_len = GX_SESS_ID_LEN,
	    .hash_func = rte_jhash,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	gx_context_by_sess_id_hash = rte_hash_create(&rte_hash_params);
	if (!gx_context_by_sess_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

void
create_upf_context_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "upf_context_by_ip_hash",
	    .entries = UPF_ENTRIES_DEFAULT,
	    .key_len = sizeof(node_address_t),
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
	    .entries = UPF_ENTRIES_BY_UE_DEFAULT,
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

void
set_pdn_type(pfcp_pdn_type_ie_t *pdn, pdn_type_ie *pdn_mme)
{
	pfcp_set_ie_header(&(pdn->header), PFCP_IE_PDN_TYPE, UINT8_SIZE);
	pdn->pdn_type_spare = 0;

	/* Need to check the following conditions*/
	if (pdn_mme->ipv4 && pdn_mme->ipv6) {
		pdn->pdn_type = PDN_TYPE_IPV4_IPV6;

	} else if (pdn_mme->ipv4)
		pdn->pdn_type = PDN_TYPE_IPV4;

	else if (pdn_mme->ipv6)
		pdn->pdn_type = PDN_TYPE_IPV6;
}


int
upflist_by_ue_hash_entry_add(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t *entry)
{
	int ret = 0;
	uint64_t imsi = UINT64_MAX;
	memcpy(&imsi, imsi_val, imsi_len);
	upfs_dnsres_t *temp = NULL;

	ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi,
			(void **)&temp);

	if(ret < 0){
		/* TODO: Check before adding */
		int ret = rte_hash_add_key_data(upflist_by_ue_hash, &imsi,
				entry);

		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT "Failed to add entry "
				"in upflist by UE hash table", LOG_VALUE);
			return -1;
		}
	}else{
		memcpy(temp, entry, sizeof(upfs_dnsres_t));
	}

	return 0;
}

int
upflist_by_ue_hash_entry_lookup(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t **entry)
{
	uint64_t imsi = UINT64_MAX;
	memcpy(&imsi, imsi_val, imsi_len);

	/* TODO: Check before adding */
	int ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi,
			(void **)entry);

	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to search entry "
			"in upflist by UE hash table", LOG_VALUE);
		return ret;
	}

	return 0;
}

int
upflist_by_ue_hash_entry_delete(uint64_t *imsi_val, uint16_t imsi_len)
{
	uint64_t imsi = UINT64_MAX;
	upfs_dnsres_t *entry = NULL;
	memcpy(&imsi, imsi_val, imsi_len);

	int ret = rte_hash_lookup_data(upflist_by_ue_hash, &imsi,
			(void **)&entry);
	if (ret >= 0) {
		/* PDN Conn Entry is present. Delete PDN Conn Entry */
		ret = rte_hash_del_key(upflist_by_ue_hash, &imsi);

		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IMSI entry is not "
				"found:%lu\n", LOG_VALUE, imsi);
			return -1;
		}
	}

	/* Free data from hash */
	if (entry != NULL) {
		rte_free(entry);
		entry = NULL;
	}

	return 0;
}

#endif /*CP_BUILD */

/*get msg type from cstm ie string */
uint64_t
get_rule_type(pfcp_pfd_contents_ie_t *pfd_conts, uint16_t *idx)
{
	char Temp_buf[3] = {0};
	for(*idx = 0; pfd_conts->cstm_pfd_cntnt[*idx] != 32; (*idx += 1))
	{
		Temp_buf[*idx] = pfd_conts->cstm_pfd_cntnt[*idx];
	}

	*idx += 1;
	Temp_buf[*idx] = '\0';
	return atoi(Temp_buf);
}

int
set_duration_measurment(pfcp_dur_meas_ie_t *dur_meas){

		int size = sizeof(pfcp_dur_meas_ie_t);
			pfcp_set_ie_header(&(dur_meas->header), PFCP_IE_DUR_MEAS, sizeof(uint32_t));
				dur_meas->duration_value = 0;
					return size;
}

int
set_node_address(uint32_t *ipv4_addr, uint8_t ipv6_addr[],
					node_address_t node_value) {

	if(node_value.ip_type == NONE_PDN_TYPE) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" None of the IPv4 "
			"or IPv6 IP is set", LOG_VALUE);
		return -1;
	}

	if (node_value.ip_type == PDN_TYPE_IPV6
				|| node_value.ip_type == PDN_TYPE_IPV4_IPV6) {

		memcpy(ipv6_addr, node_value.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	if (node_value.ip_type == PDN_TYPE_IPV4
				|| node_value.ip_type == PDN_TYPE_IPV4_IPV6) {

		*ipv4_addr = node_value.ipv4_addr;
	}

	return 0;
}

int
fill_ip_addr(uint32_t ipv4_addr, uint8_t ipv6_addr[],
						node_address_t *node_value) {
	memset(node_value, 0, sizeof(node_address_t));
	if (ipv4_addr == 0 && !*ipv6_addr) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" None of the IPv4 "
			"or IPv6 IP is present while storing IP address", LOG_VALUE);
		return -1;
	}

	if (ipv4_addr != 0) {
		node_value->ip_type |= PDN_TYPE_IPV4;
		node_value->ipv4_addr = ipv4_addr;
	}

	if (*ipv6_addr) {
		node_value->ip_type |= PDN_TYPE_IPV6;
		memcpy(node_value->ipv6_addr, ipv6_addr, IPV6_ADDRESS_LEN);
	}

	return 0;
}


int
check_ipv6_zero(uint8_t addr[], uint8_t len) {
	for (int i = 0; i < len; i++) {
		if (addr[i] != 0)
			return -1;
	}
	return 0;
}
