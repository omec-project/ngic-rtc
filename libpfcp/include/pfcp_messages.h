/*Copyright (c) 2019 Sprint
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


#ifndef __PFCP_MESSAGES_H
#define __PFCP_MESSAGES_H


#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "pfcp_ies.h"

#define MAX_LIST_SIZE 16
#define CHAR_SIZE 8
#define PFCP_HRTBEAT_REQ (1)
#define PFCP_HRTBEAT_RSP (2)
#define PFCP_PFD_MGMT_REQ (3)
#define IE_APP_IDS_PFDS (58)
#define IE_PFD_CONTEXT (59)
#define PFCP_PFD_MGMT_RSP (4)
#define PFCP_ASSN_SETUP_REQ (5)
#define PFCP_ASSN_SETUP_RSP (6)
#define PFCP_ASSN_UPD_REQ (7)
#define PFCP_ASSN_UPD_RSP (8)
#define PFCP_ASSN_REL_REQ (9)
#define PFCP_ASSN_REL_RSP (10)
#define PFCP_NODE_RPT_REQ (12)
#define IE_USER_PLANE_PATH_FAIL_RPT (102)
#define PFCP_NODE_RPT_RSP (13)
#define PFCP_SESS_SET_DEL_REQ (14)
#define PFCP_SESS_SET_DEL_RSP (15)
#define PFCP_SESS_ESTAB_REQ (50)
#define IE_CREATE_PDR (1)
#define IE_PDI (2)
#define IE_ETH_PCKT_FLTR (132)
#define IE_CREATE_FAR (3)
#define IE_FRWDNG_PARMS (4)
#define IE_DUPNG_PARMS (5)
#define IE_CREATE_URR (6)
#define IE_AGGREGATED_URRS (118)
#define IE_ADD_MNTRNG_TIME (147)
#define IE_CREATE_QER (7)
#define IE_CREATE_BAR (85)
#define IE_CREATE_TRAFFIC_ENDPT (127)
#define PFCP_SESS_ESTAB_RSP (51)
#define IE_CREATED_PDR (8)
#define IE_LOAD_CTL_INFO (51)
#define IE_OVRLD_CTL_INFO (54)
#define IE_CREATED_TRAFFIC_ENDPT (128)
#define PFCP_SESS_MOD_REQ (52)
#define IE_UPDATE_PDR (9)
#define IE_UPDATE_FAR (10)
#define IE_UPD_FRWDNG_PARMS (11)
#define IE_UPD_DUPNG_PARMS (105)
#define IE_UPDATE_URR (13)
#define IE_UPDATE_QER (14)
#define IE_REMOVE_PDR (15)
#define IE_REMOVE_FAR (16)
#define IE_REMOVE_URR (17)
#define IE_REMOVE_QER (18)
#define IE_QUERY_URR (77)
#define IE_UPD_BAR_SESS_MOD_REQ (86)
#define IE_REMOVE_BAR (87)
#define IE_UPD_TRAFFIC_ENDPT (129)
#define IE_RMV_TRAFFIC_ENDPT (130)
#define PFCP_SESS_MOD_RSP (53)
#define IE_USAGE_RPT_SESS_MOD_RSP (78)
#define PFCP_SESS_DEL_REQ (54)
#define PFCP_SESS_DEL_RSP (55)
#define IE_USAGE_RPT_SESS_DEL_RSP (79)
#define PFCP_SESS_RPT_REQ (56)
#define IE_DNLNK_DATA_RPT (83)
#define IE_USAGE_RPT_SESS_RPT_REQ (80)
#define IE_APP_DET_INFO (68)
#define IE_ETH_TRAFFIC_INFO (143)
#define IE_ERR_INDCTN_RPT (99)
#define PFCP_SESS_RPT_RSP (57)
#define IE_UPD_BAR_SESS_RPT_RSP (12)
#define IE_APPLY_ACTION_ID (44)
#define IE_DEST_INTRFACE_ID (42)
#define IE_PFCPSM_ID (49)

/* TODO: Revisit this for change in yang */
#pragma pack(1)

typedef struct pfcp_dnlnk_data_rpt_ie_t {
  pfcp_ie_header_t header;
  uint8_t pdr_id_count;
  pfcp_pdr_id_ie_t pdr_id[MAX_LIST_SIZE];
  pfcp_dnlnk_data_svc_info_ie_t dnlnk_data_svc_info;
} pfcp_dnlnk_data_rpt_ie_t;

typedef struct pfcp_err_indctn_rpt_ie_t {
  pfcp_ie_header_t header;
  uint8_t remote_fteid_count;
  pfcp_fteid_ie_t remote_fteid[MAX_LIST_SIZE];
} pfcp_err_indctn_rpt_ie_t;

typedef struct pfcp_load_ctl_info_ie_t {
  pfcp_ie_header_t header;
  pfcp_sequence_number_ie_t load_ctl_seqn_nbr;
  pfcp_metric_ie_t load_metric;
} pfcp_load_ctl_info_ie_t;

typedef struct pfcp_ovrld_ctl_info_ie_t {
  pfcp_ie_header_t header;
  pfcp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  pfcp_metric_ie_t ovrld_reduction_metric;
  pfcp_timer_ie_t period_of_validity;
  pfcp_oci_flags_ie_t ovrld_ctl_info_flgs;
} pfcp_ovrld_ctl_info_ie_t;

typedef struct pfcp_app_det_info_ie_t {
  pfcp_ie_header_t header;
  pfcp_application_id_ie_t application_id;
  pfcp_app_inst_id_ie_t app_inst_id;
  pfcp_flow_info_ie_t flow_info;
} pfcp_app_det_info_ie_t;

typedef struct pfcp_eth_traffic_info_ie_t {
  pfcp_ie_header_t header;
  pfcp_mac_addrs_detctd_ie_t mac_addrs_detctd;
  pfcp_mac_addrs_rmvd_ie_t mac_addrs_rmvd;
} pfcp_eth_traffic_info_ie_t;

typedef struct pfcp_usage_rpt_sess_rpt_req_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
  pfcp_urseqn_ie_t urseqn;
  pfcp_usage_rpt_trig_ie_t usage_rpt_trig;
  pfcp_start_time_ie_t start_time;
  pfcp_end_time_ie_t end_time;
  pfcp_vol_meas_ie_t vol_meas;
  pfcp_dur_meas_ie_t dur_meas;
  pfcp_app_det_info_ie_t app_det_info;
  pfcp_ue_ip_address_ie_t ue_ip_address;
  pfcp_ntwk_inst_ie_t ntwk_inst;
  pfcp_time_of_frst_pckt_ie_t time_of_frst_pckt;
  pfcp_time_of_lst_pckt_ie_t time_of_lst_pckt;
  pfcp_usage_info_ie_t usage_info;
  pfcp_query_urr_ref_ie_t query_urr_ref;
  pfcp_eth_traffic_info_ie_t eth_traffic_info;
  uint8_t evnt_time_stmp_count;
  pfcp_evnt_time_stmp_ie_t evnt_time_stmp[MAX_LIST_SIZE];
} pfcp_usage_rpt_sess_rpt_req_ie_t;

typedef struct pfcp_pfd_context_ie_t {
  pfcp_ie_header_t header;
  uint8_t pfd_contents_count;
  pfcp_pfd_contents_ie_t pfd_contents[MAX_LIST_SIZE];
} pfcp_pfd_context_ie_t;

typedef struct pfcp_app_ids_pfds_ie_t {
  pfcp_ie_header_t header;
  pfcp_application_id_ie_t application_id;
  uint8_t pfd_context_count;
  pfcp_pfd_context_ie_t pfd_context[MAX_LIST_SIZE];
} pfcp_app_ids_pfds_ie_t;

typedef struct pfcp_aggregated_urrs_ie_t {
  pfcp_ie_header_t header;
  pfcp_agg_urr_id_ie_t agg_urr_id;
  pfcp_multiplier_ie_t multiplier;
} pfcp_aggregated_urrs_ie_t;

typedef struct pfcp_add_mntrng_time_ie_t {
  pfcp_ie_header_t header;
  pfcp_monitoring_time_ie_t monitoring_time;
  pfcp_sbsqnt_vol_thresh_ie_t sbsqnt_vol_thresh;
  pfcp_sbsqnt_time_thresh_ie_t sbsqnt_time_thresh;
  pfcp_sbsqnt_vol_quota_ie_t sbsqnt_vol_quota;
  pfcp_sbsqnt_time_quota_ie_t sbsqnt_time_quota;
  pfcp_event_threshold_ie_t sbsqnt_evnt_thresh;
  pfcp_event_quota_ie_t sbsqnt_evnt_quota;
} pfcp_add_mntrng_time_ie_t;

typedef struct pfcp_frwdng_parms_ie_t {
  pfcp_ie_header_t header;
  pfcp_dst_intfc_ie_t dst_intfc;
  pfcp_ntwk_inst_ie_t ntwk_inst;
  pfcp_redir_info_ie_t redir_info;
  pfcp_outer_hdr_creation_ie_t outer_hdr_creation;
  pfcp_trnspt_lvl_marking_ie_t trnspt_lvl_marking;
  pfcp_frwdng_plcy_ie_t frwdng_plcy;
  pfcp_hdr_enrchmt_ie_t hdr_enrchmt;
  pfcp_traffic_endpt_id_ie_t lnkd_traffic_endpt_id;
  pfcp_proxying_ie_t proxying;
} pfcp_frwdng_parms_ie_t;

typedef struct pfcp_dupng_parms_ie_t {
  pfcp_ie_header_t header;
  pfcp_dst_intfc_ie_t dst_intfc;
  pfcp_outer_hdr_creation_ie_t outer_hdr_creation;
  pfcp_trnspt_lvl_marking_ie_t trnspt_lvl_marking;
  pfcp_frwdng_plcy_ie_t frwdng_plcy;
} pfcp_dupng_parms_ie_t;

typedef struct pfcp_remove_bar_ie_t {
	pfcp_ie_header_t header;
	pfcp_bar_id_ie_t bar_id;
} pfcp_remove_bar_ie_t;

typedef struct pfcp_rmv_traffic_endpt_ie_t {
  pfcp_ie_header_t header;
  pfcp_traffic_endpt_id_ie_t traffic_endpt_id;
} pfcp_rmv_traffic_endpt_ie_t;

typedef struct pfcp_create_bar_ie_t {
	pfcp_ie_header_t header;
	pfcp_bar_id_ie_t bar_id;
	pfcp_dnlnk_data_notif_delay_ie_t dnlnk_data_notif_delay;
	pfcp_suggstd_buf_pckts_cnt_ie_t suggstd_buf_pckts_cnt;
} pfcp_create_bar_ie_t;

typedef struct pfcp_create_traffic_endpt_ie_t {
  pfcp_ie_header_t header;
  pfcp_traffic_endpt_id_ie_t traffic_endpt_id;
  pfcp_fteid_ie_t local_fteid;
  pfcp_ntwk_inst_ie_t ntwk_inst;
  pfcp_ue_ip_address_ie_t ue_ip_address;
  pfcp_eth_pdu_sess_info_ie_t eth_pdu_sess_info;
  pfcp_framed_routing_ie_t framed_routing;
  uint8_t framed_route_count;
  pfcp_framed_route_ie_t framed_route[MAX_LIST_SIZE];
  uint8_t frmd_ipv6_rte_count;
  pfcp_frmd_ipv6_rte_ie_t frmd_ipv6_rte[MAX_LIST_SIZE];
} pfcp_create_traffic_endpt_ie_t;

typedef struct pfcp_upd_bar_sess_mod_req_ie_t {
  pfcp_ie_header_t header;
  pfcp_bar_id_ie_t bar_id;
  pfcp_dnlnk_data_notif_delay_ie_t dnlnk_data_notif_delay;
  pfcp_suggstd_buf_pckts_cnt_ie_t suggstd_buf_pckts_cnt;
} pfcp_upd_bar_sess_mod_req_ie_t;

typedef struct pfcp_upd_traffic_endpt_ie_t {
  pfcp_ie_header_t header;
  pfcp_traffic_endpt_id_ie_t traffic_endpt_id;
  pfcp_fteid_ie_t local_fteid;
  pfcp_ntwk_inst_ie_t ntwk_inst;
  pfcp_ue_ip_address_ie_t ue_ip_address;
  pfcp_framed_routing_ie_t framed_routing;
  uint8_t framed_route_count;
  pfcp_framed_route_ie_t framed_route[MAX_LIST_SIZE];
  uint8_t frmd_ipv6_rte_count;
  pfcp_frmd_ipv6_rte_ie_t frmd_ipv6_rte[MAX_LIST_SIZE];
} pfcp_upd_traffic_endpt_ie_t;

typedef struct pfcp_remove_pdr_ie_t {
  pfcp_ie_header_t header;
  pfcp_pdr_id_ie_t pdr_id;
} pfcp_remove_pdr_ie_t;

typedef struct pfcp_remove_far_ie_t {
  pfcp_ie_header_t header;
  pfcp_far_id_ie_t far_id;
} pfcp_remove_far_ie_t;

typedef struct pfcp_remove_urr_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
} pfcp_remove_urr_ie_t;

typedef struct pfcp_remove_qer_ie_t {
  pfcp_ie_header_t header;
  pfcp_qer_id_ie_t qer_id;
} pfcp_remove_qer_ie_t;

typedef struct pfcp_eth_pckt_fltr_ie_t {
  pfcp_ie_header_t header;
  pfcp_eth_fltr_id_ie_t eth_fltr_id;
  pfcp_eth_fltr_props_ie_t eth_fltr_props;
  pfcp_mac_address_ie_t mac_address;
  pfcp_ethertype_ie_t ethertype;
  pfcp_ctag_ie_t ctag;
  pfcp_stag_ie_t stag;
  uint8_t sdf_filter_count;
  pfcp_sdf_filter_ie_t sdf_filter[MAX_LIST_SIZE];
} pfcp_eth_pckt_fltr_ie_t;

typedef struct pfcp_pdi_ie_t {
	pfcp_ie_header_t header;
	pfcp_src_intfc_ie_t src_intfc;
	pfcp_fteid_ie_t local_fteid;
	pfcp_ntwk_inst_ie_t ntwk_inst;
	pfcp_ue_ip_address_ie_t ue_ip_address;
	pfcp_traffic_endpt_id_ie_t traffic_endpt_id;
	pfcp_application_id_ie_t application_id;
	pfcp_eth_pdu_sess_info_ie_t eth_pdu_sess_info;
	pfcp_framed_routing_ie_t framed_routing;
	uint8_t sdf_filter_count;
	pfcp_sdf_filter_ie_t sdf_filter[MAX_LIST_SIZE];
	uint8_t eth_pckt_fltr_count;
	pfcp_eth_pckt_fltr_ie_t eth_pckt_fltr[MAX_LIST_SIZE];
	uint8_t qfi_count;
	pfcp_qfi_ie_t qfi[MAX_LIST_SIZE];
	uint8_t framed_route_count;
	pfcp_framed_route_ie_t framed_route[MAX_LIST_SIZE];
	uint8_t frmd_ipv6_rte_count;
	pfcp_frmd_ipv6_rte_ie_t frmd_ipv6_rte[MAX_LIST_SIZE];
} pfcp_pdi_ie_t;

typedef struct pfcp_create_pdr_ie_t {
	pfcp_ie_header_t header;
	pfcp_pdr_id_ie_t pdr_id;
	pfcp_precedence_ie_t precedence;
	pfcp_pdi_ie_t pdi;
	pfcp_outer_hdr_removal_ie_t outer_hdr_removal;
	pfcp_far_id_ie_t far_id;
	uint8_t urr_id_count;
	pfcp_urr_id_ie_t urr_id[MAX_LIST_SIZE];
	uint8_t qer_id_count;
	pfcp_qer_id_ie_t qer_id[MAX_LIST_SIZE];
	uint8_t actvt_predef_rules_count;
	pfcp_actvt_predef_rules_ie_t actvt_predef_rules[MAX_LIST_SIZE];
} pfcp_create_pdr_ie_t;

typedef struct pfcp_create_far_ie_t {
  pfcp_ie_header_t header;
  pfcp_far_id_ie_t far_id;
  pfcp_apply_action_ie_t apply_action;
  pfcp_frwdng_parms_ie_t frwdng_parms;
  pfcp_bar_id_ie_t bar_id;
  uint8_t dupng_parms_count;
  pfcp_dupng_parms_ie_t dupng_parms[MAX_LIST_SIZE];
} pfcp_create_far_ie_t;

typedef struct pfcp_create_urr_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
  pfcp_meas_mthd_ie_t meas_mthd;
  pfcp_rptng_triggers_ie_t rptng_triggers;
  pfcp_meas_period_ie_t meas_period;
  pfcp_vol_thresh_ie_t vol_thresh;
  pfcp_volume_quota_ie_t volume_quota;
  pfcp_event_threshold_ie_t event_threshold;
  pfcp_event_quota_ie_t event_quota;
  pfcp_time_threshold_ie_t time_threshold;
  pfcp_time_quota_ie_t time_quota;
  pfcp_quota_hldng_time_ie_t quota_hldng_time;
  pfcp_drpd_dl_traffic_thresh_ie_t drpd_dl_traffic_thresh;
  pfcp_monitoring_time_ie_t monitoring_time;
  pfcp_sbsqnt_vol_thresh_ie_t sbsqnt_vol_thresh;
  pfcp_sbsqnt_time_thresh_ie_t sbsqnt_time_thresh;
  pfcp_sbsqnt_vol_quota_ie_t sbsqnt_vol_quota;
  pfcp_sbsqnt_time_quota_ie_t sbsqnt_time_quota;
  pfcp_sbsqnt_evnt_thresh_ie_t sbsqnt_evnt_thresh;
  pfcp_sbsqnt_evnt_quota_ie_t sbsqnt_evnt_quota;
  pfcp_inact_det_time_ie_t inact_det_time;
  pfcp_meas_info_ie_t meas_info;
  pfcp_time_quota_mech_ie_t time_quota_mech;
  pfcp_far_id_ie_t far_id_for_quota_act;
  pfcp_eth_inact_timer_ie_t eth_inact_timer;
  uint8_t linked_urr_id_count;
  pfcp_linked_urr_id_ie_t linked_urr_id[MAX_LIST_SIZE];
  uint8_t aggregated_urrs_count;
  pfcp_aggregated_urrs_ie_t aggregated_urrs[MAX_LIST_SIZE];
  uint8_t add_mntrng_time_count;
  pfcp_add_mntrng_time_ie_t add_mntrng_time[MAX_LIST_SIZE];
} pfcp_create_urr_ie_t;

typedef struct pfcp_create_qer_ie_t {
  pfcp_ie_header_t header;
  pfcp_qer_id_ie_t qer_id;
  pfcp_qer_corr_id_ie_t qer_corr_id;
  pfcp_gate_status_ie_t gate_status;
  pfcp_mbr_ie_t maximum_bitrate;
  pfcp_gbr_ie_t guaranteed_bitrate;
  pfcp_packet_rate_ie_t packet_rate;
  pfcp_dl_flow_lvl_marking_ie_t dl_flow_lvl_marking;
  pfcp_qfi_ie_t qos_flow_ident;
  pfcp_rqi_ie_t reflective_qos;
  pfcp_paging_plcy_indctr_ie_t paging_plcy_indctr;
  pfcp_avgng_wnd_ie_t avgng_wnd;
} pfcp_create_qer_ie_t;

typedef struct pfcp_update_pdr_ie_t {
  pfcp_ie_header_t header;
  pfcp_pdr_id_ie_t pdr_id;
  pfcp_outer_hdr_removal_ie_t outer_hdr_removal;
  pfcp_precedence_ie_t precedence;
  pfcp_pdi_ie_t pdi;
  pfcp_far_id_ie_t far_id;
  pfcp_urr_id_ie_t urr_id;
  pfcp_qer_id_ie_t qer_id;
  uint8_t actvt_predef_rules_count;
  pfcp_actvt_predef_rules_ie_t actvt_predef_rules[MAX_LIST_SIZE];
  uint8_t deact_predef_rules_count;
  pfcp_deact_predef_rules_ie_t deact_predef_rules[MAX_LIST_SIZE];
} pfcp_update_pdr_ie_t;

typedef struct pfcp_upd_frwdng_parms_ie_t {
  pfcp_ie_header_t header;
  pfcp_dst_intfc_ie_t dst_intfc;
  pfcp_ntwk_inst_ie_t ntwk_inst;
  pfcp_redir_info_ie_t redir_info;
  pfcp_outer_hdr_creation_ie_t outer_hdr_creation;
  pfcp_trnspt_lvl_marking_ie_t trnspt_lvl_marking;
  pfcp_frwdng_plcy_ie_t frwdng_plcy;
  pfcp_hdr_enrchmt_ie_t hdr_enrchmt;
  pfcp_pfcpsmreq_flags_ie_t pfcpsmreq_flags;
  pfcp_traffic_endpt_id_ie_t lnkd_traffic_endpt_id;
} pfcp_upd_frwdng_parms_ie_t;

typedef struct pfcp_upd_dupng_parms_ie_t {
  pfcp_ie_header_t header;
  pfcp_dst_intfc_ie_t dst_intfc;
  pfcp_outer_hdr_creation_ie_t outer_hdr_creation;
  pfcp_trnspt_lvl_marking_ie_t trnspt_lvl_marking;
  pfcp_frwdng_plcy_ie_t frwdng_plcy;
} pfcp_upd_dupng_parms_ie_t;

typedef struct pfcp_update_far_ie_t {
  pfcp_ie_header_t header;
  pfcp_far_id_ie_t far_id;
  pfcp_apply_action_ie_t apply_action;
  pfcp_upd_frwdng_parms_ie_t upd_frwdng_parms;
  pfcp_bar_id_ie_t bar_id;
  uint8_t upd_dupng_parms_count;
  pfcp_upd_dupng_parms_ie_t upd_dupng_parms[MAX_LIST_SIZE];
} pfcp_update_far_ie_t;

typedef struct pfcp_update_urr_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
  pfcp_meas_mthd_ie_t meas_mthd;
  pfcp_rptng_triggers_ie_t rptng_triggers;
  pfcp_meas_period_ie_t meas_period;
  pfcp_vol_thresh_ie_t vol_thresh;
  pfcp_volume_quota_ie_t volume_quota;
  pfcp_time_threshold_ie_t time_threshold;
  pfcp_time_quota_ie_t time_quota;
  pfcp_event_threshold_ie_t event_threshold;
  pfcp_event_quota_ie_t event_quota;
  pfcp_quota_hldng_time_ie_t quota_hldng_time;
  pfcp_drpd_dl_traffic_thresh_ie_t drpd_dl_traffic_thresh;
  pfcp_monitoring_time_ie_t monitoring_time;
  pfcp_sbsqnt_vol_thresh_ie_t sbsqnt_vol_thresh;
  pfcp_sbsqnt_time_thresh_ie_t sbsqnt_time_thresh;
  pfcp_sbsqnt_vol_quota_ie_t sbsqnt_vol_quota;
  pfcp_sbsqnt_time_quota_ie_t sbsqnt_time_quota;
  pfcp_sbsqnt_evnt_thresh_ie_t sbsqnt_evnt_thresh;
  pfcp_sbsqnt_evnt_quota_ie_t sbsqnt_evnt_quota;
  pfcp_inact_det_time_ie_t inact_det_time;
  pfcp_meas_info_ie_t meas_info;
  pfcp_time_quota_mech_ie_t time_quota_mech;
  pfcp_far_id_ie_t far_id_for_quota_act;
  pfcp_eth_inact_timer_ie_t eth_inact_timer;
  pfcp_add_mntrng_time_ie_t add_mntrng_time;
  uint8_t linked_urr_id_count;
  pfcp_linked_urr_id_ie_t linked_urr_id[MAX_LIST_SIZE];
  uint8_t aggregated_urrs_count;
  pfcp_aggregated_urrs_ie_t aggregated_urrs[MAX_LIST_SIZE];
} pfcp_update_urr_ie_t;

typedef struct pfcp_update_qer_ie_t {
  pfcp_ie_header_t header;
  pfcp_qer_id_ie_t qer_id;
  pfcp_qer_corr_id_ie_t qer_corr_id;
  pfcp_gate_status_ie_t gate_status;
  pfcp_mbr_ie_t maximum_bitrate;
  pfcp_gbr_ie_t guaranteed_bitrate;
  pfcp_packet_rate_ie_t packet_rate;
  pfcp_dl_flow_lvl_marking_ie_t dl_flow_lvl_marking;
  pfcp_qfi_ie_t qos_flow_ident;
  pfcp_rqi_ie_t reflective_qos;
  pfcp_paging_plcy_indctr_ie_t paging_plcy_indctr;
  pfcp_avgng_wnd_ie_t avgng_wnd;
} pfcp_update_qer_ie_t;

typedef struct pfcp_query_urr_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
} pfcp_query_urr_ie_t;

typedef struct pfcp_upd_bar_sess_rpt_rsp_ie_t {
  pfcp_ie_header_t header;
  pfcp_bar_id_ie_t bar_id;
  pfcp_dnlnk_data_notif_delay_ie_t dnlnk_data_notif_delay;
  pfcp_dl_buf_dur_ie_t dl_buf_dur;
  pfcp_dl_buf_suggstd_pckt_cnt_ie_t dl_buf_suggstd_pckt_cnt;
  pfcp_suggstd_buf_pckts_cnt_ie_t suggstd_buf_pckts_cnt;
} pfcp_upd_bar_sess_rpt_rsp_ie_t;

typedef struct pfcp_usage_rpt_sess_del_rsp_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
  pfcp_urseqn_ie_t urseqn;
  pfcp_usage_rpt_trig_ie_t usage_rpt_trig;
  pfcp_start_time_ie_t start_time;
  pfcp_end_time_ie_t end_time;
  pfcp_vol_meas_ie_t vol_meas;
  pfcp_dur_meas_ie_t dur_meas;
  pfcp_time_of_frst_pckt_ie_t time_of_frst_pckt;
  pfcp_time_of_lst_pckt_ie_t time_of_lst_pckt;
  pfcp_usage_info_ie_t usage_info;
  pfcp_eth_traffic_info_ie_t eth_traffic_info;
} pfcp_usage_rpt_sess_del_rsp_ie_t;

typedef struct pfcp_created_pdr_ie_t {
  pfcp_ie_header_t header;
  pfcp_pdr_id_ie_t pdr_id;
  pfcp_fteid_ie_t local_fteid;
} pfcp_created_pdr_ie_t;

typedef struct pfcp_created_traffic_endpt_ie_t {
  pfcp_ie_header_t header;
  pfcp_traffic_endpt_id_ie_t traffic_endpt_id;
  pfcp_fteid_ie_t local_fteid;
} pfcp_created_traffic_endpt_ie_t;

typedef struct pfcp_usage_rpt_sess_mod_rsp_ie_t {
  pfcp_ie_header_t header;
  pfcp_urr_id_ie_t urr_id;
  pfcp_urseqn_ie_t urseqn;
  pfcp_usage_rpt_trig_ie_t usage_rpt_trig;
  pfcp_start_time_ie_t start_time;
  pfcp_end_time_ie_t end_time;
  pfcp_vol_meas_ie_t vol_meas;
  pfcp_dur_meas_ie_t dur_meas;
  pfcp_time_of_frst_pckt_ie_t time_of_frst_pckt;
  pfcp_time_of_lst_pckt_ie_t time_of_lst_pckt;
  pfcp_usage_info_ie_t usage_info;
  pfcp_query_urr_ref_ie_t query_urr_ref;
  pfcp_eth_traffic_info_ie_t eth_traffic_info;
} pfcp_usage_rpt_sess_mod_rsp_ie_t;

typedef struct pfcp_user_plane_path_fail_rpt_ie_t {
  pfcp_ie_header_t header;
  uint8_t rmt_gtpu_peer_count;
  pfcp_rmt_gtpu_peer_ie_t rmt_gtpu_peer[MAX_LIST_SIZE];
} pfcp_user_plane_path_fail_rpt_ie_t;

typedef struct pfcp_hrtbeat_req_t {
  pfcp_header_t header;
  pfcp_rcvry_time_stmp_ie_t rcvry_time_stmp;
} pfcp_hrtbeat_req_t;

typedef struct pfcp_hrtbeat_rsp_t {
  pfcp_header_t header;
  pfcp_rcvry_time_stmp_ie_t rcvry_time_stmp;
} pfcp_hrtbeat_rsp_t;

typedef struct pfcp_pfd_mgmt_req_t {
  pfcp_header_t header;
  uint8_t app_ids_pfds_count;
  pfcp_app_ids_pfds_ie_t app_ids_pfds[MAX_LIST_SIZE];
} pfcp_pfd_mgmt_req_t;

typedef struct pfcp_pfd_mgmt_rsp_t {
  pfcp_header_t header;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
} pfcp_pfd_mgmt_rsp_t;

typedef struct pfcp_assn_setup_req_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_rcvry_time_stmp_ie_t rcvry_time_stmp;
  pfcp_up_func_feat_ie_t up_func_feat;
  pfcp_cp_func_feat_ie_t cp_func_feat;
  uint8_t user_plane_ip_rsrc_info_count;
  pfcp_user_plane_ip_rsrc_info_ie_t user_plane_ip_rsrc_info[MAX_LIST_SIZE];
} pfcp_assn_setup_req_t;

typedef struct pfcp_assn_setup_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
  pfcp_rcvry_time_stmp_ie_t rcvry_time_stmp;
  pfcp_up_func_feat_ie_t up_func_feat;
  pfcp_cp_func_feat_ie_t cp_func_feat;
  uint8_t user_plane_ip_rsrc_info_count;
  pfcp_user_plane_ip_rsrc_info_ie_t user_plane_ip_rsrc_info[MAX_LIST_SIZE];
} pfcp_assn_setup_rsp_t;

typedef struct pfcp_assn_upd_req_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_up_func_feat_ie_t up_func_feat;
  pfcp_cp_func_feat_ie_t cp_func_feat;
  pfcp_up_assn_rel_req_ie_t up_assn_rel_req;
  pfcp_graceful_rel_period_ie_t graceful_rel_period;
  uint8_t user_plane_ip_rsrc_info_count;
  pfcp_user_plane_ip_rsrc_info_ie_t user_plane_ip_rsrc_info[MAX_LIST_SIZE];
} pfcp_assn_upd_req_t;

typedef struct pfcp_assn_upd_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
  pfcp_up_func_feat_ie_t up_func_feat;
  pfcp_cp_func_feat_ie_t cp_func_feat;
} pfcp_assn_upd_rsp_t;

typedef struct pfcp_assn_rel_req_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
} pfcp_assn_rel_req_t;

typedef struct pfcp_assn_rel_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
} pfcp_assn_rel_rsp_t;

typedef struct pfcp_node_rpt_req_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_node_rpt_type_ie_t node_rpt_type;
  pfcp_user_plane_path_fail_rpt_ie_t user_plane_path_fail_rpt;
} pfcp_node_rpt_req_t;

typedef struct pfcp_node_rpt_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
} pfcp_node_rpt_rsp_t;

typedef struct pfcp_sess_set_del_req_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_fqcsid_ie_t sgw_c_fqcsid;
  pfcp_fqcsid_ie_t pgw_c_fqcsid;
  pfcp_fqcsid_ie_t sgw_u_fqcsid;
  pfcp_fqcsid_ie_t pgw_u_fqcsid;
  pfcp_fqcsid_ie_t twan_fqcsid;
  pfcp_fqcsid_ie_t epdg_fqcsid;
  pfcp_fqcsid_ie_t mme_fqcsid;
} pfcp_sess_set_del_req_t;

typedef struct pfcp_sess_set_del_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
} pfcp_sess_set_del_rsp_t;

typedef struct pfcp_sess_estab_req_t {
	pfcp_header_t header;
	pfcp_node_id_ie_t node_id;
	pfcp_fseid_ie_t cp_fseid;
	pfcp_create_bar_ie_t create_bar;
	pfcp_pdn_type_ie_t pdn_type;
	pfcp_fqcsid_ie_t sgw_c_fqcsid;
	pfcp_fqcsid_ie_t mme_fqcsid;
	pfcp_fqcsid_ie_t pgw_c_fqcsid;
	pfcp_fqcsid_ie_t epdg_fqcsid;
	pfcp_fqcsid_ie_t twan_fqcsid;
	pfcp_user_plane_inact_timer_ie_t user_plane_inact_timer;
	pfcp_user_id_ie_t user_id;
	pfcp_trc_info_ie_t trc_info;
	uint8_t create_pdr_count;
	pfcp_create_pdr_ie_t create_pdr[MAX_LIST_SIZE];
	uint8_t create_far_count;
	pfcp_create_far_ie_t create_far[MAX_LIST_SIZE];
	uint8_t create_urr_count;
	pfcp_create_urr_ie_t create_urr[MAX_LIST_SIZE];
	uint8_t create_qer_count;
	pfcp_create_qer_ie_t create_qer[MAX_LIST_SIZE];
	uint8_t create_traffic_endpt_count;
	pfcp_create_traffic_endpt_ie_t create_traffic_endpt[MAX_LIST_SIZE];
} pfcp_sess_estab_req_t;

typedef struct pfcp_sess_estab_rsp_t {
  pfcp_header_t header;
  pfcp_node_id_ie_t node_id;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
  pfcp_fseid_ie_t up_fseid;
  pfcp_created_pdr_ie_t created_pdr;
  pfcp_load_ctl_info_ie_t load_ctl_info;
  pfcp_ovrld_ctl_info_ie_t ovrld_ctl_info;
  pfcp_fqcsid_ie_t sgw_u_fqcsid;
  pfcp_fqcsid_ie_t pgw_u_fqcsid;
  pfcp_failed_rule_id_ie_t failed_rule_id;
  pfcp_created_traffic_endpt_ie_t created_traffic_endpt;
} pfcp_sess_estab_rsp_t;

typedef struct pfcp_sess_mod_req_t {
	pfcp_header_t header;
	pfcp_fseid_ie_t cp_fseid;
	pfcp_remove_bar_ie_t remove_bar;
	pfcp_rmv_traffic_endpt_ie_t rmv_traffic_endpt;
	pfcp_create_bar_ie_t create_bar;
	pfcp_create_traffic_endpt_ie_t create_traffic_endpt;
	pfcp_upd_bar_sess_mod_req_ie_t update_bar;
	pfcp_upd_traffic_endpt_ie_t upd_traffic_endpt;
	pfcp_pfcpsmreq_flags_ie_t pfcpsmreq_flags;
	pfcp_fqcsid_ie_t pgw_c_fqcsid;
	pfcp_fqcsid_ie_t sgw_c_fqcsid;
	pfcp_fqcsid_ie_t mme_fqcsid;
	pfcp_fqcsid_ie_t epdg_fqcsid;
	pfcp_fqcsid_ie_t twan_fqcsid;
	pfcp_user_plane_inact_timer_ie_t user_plane_inact_timer;
	pfcp_query_urr_ref_ie_t query_urr_ref;
	pfcp_trc_info_ie_t trc_info;
	uint8_t remove_pdr_count;
	pfcp_remove_pdr_ie_t remove_pdr[MAX_LIST_SIZE];
	uint8_t remove_far_count;
	pfcp_remove_far_ie_t remove_far[MAX_LIST_SIZE];
	uint8_t remove_urr_count;
	pfcp_remove_urr_ie_t remove_urr[MAX_LIST_SIZE];
	uint8_t remove_qer_count;
	pfcp_remove_qer_ie_t remove_qer[MAX_LIST_SIZE];
	uint8_t create_pdr_count;
	pfcp_create_pdr_ie_t create_pdr[MAX_LIST_SIZE];
	uint8_t create_far_count;
	pfcp_create_far_ie_t create_far[MAX_LIST_SIZE];
	uint8_t create_urr_count;
	pfcp_create_urr_ie_t create_urr[MAX_LIST_SIZE];
	uint8_t create_qer_count;
	pfcp_create_qer_ie_t create_qer[MAX_LIST_SIZE];
	uint8_t update_pdr_count;
	pfcp_update_pdr_ie_t update_pdr[MAX_LIST_SIZE];
	uint8_t update_far_count;
	pfcp_update_far_ie_t update_far[MAX_LIST_SIZE];
	uint8_t update_urr_count;
	pfcp_update_urr_ie_t update_urr[MAX_LIST_SIZE];
	uint8_t update_qer_count;
	pfcp_update_qer_ie_t update_qer[MAX_LIST_SIZE];
	uint8_t query_urr_count;
	pfcp_query_urr_ie_t query_urr[MAX_LIST_SIZE];
} pfcp_sess_mod_req_t;

typedef struct pfcp_sess_mod_rsp_t {
  pfcp_header_t header;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
  pfcp_created_pdr_ie_t created_pdr;
  pfcp_load_ctl_info_ie_t load_ctl_info;
  pfcp_ovrld_ctl_info_ie_t ovrld_ctl_info;
  pfcp_failed_rule_id_ie_t failed_rule_id;
  pfcp_add_usage_rpts_info_ie_t add_usage_rpts_info;
  pfcp_created_traffic_endpt_ie_t createdupdated_traffic_endpt;
  uint8_t usage_report_count;
  pfcp_usage_rpt_sess_mod_rsp_ie_t usage_report[MAX_LIST_SIZE];
} pfcp_sess_mod_rsp_t;

typedef struct pfcp_sess_del_req_t {
  pfcp_header_t header;
} pfcp_sess_del_req_t;

typedef struct pfcp_sess_del_rsp_t {
  pfcp_header_t header;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
  pfcp_load_ctl_info_ie_t load_ctl_info;
  pfcp_ovrld_ctl_info_ie_t ovrld_ctl_info;
  uint8_t usage_report_count;
  pfcp_usage_rpt_sess_del_rsp_ie_t usage_report[MAX_LIST_SIZE];
} pfcp_sess_del_rsp_t;

typedef struct pfcp_sess_rpt_req_t {
  pfcp_header_t header;
  pfcp_report_type_ie_t report_type;
  pfcp_dnlnk_data_rpt_ie_t dnlnk_data_rpt;
  pfcp_err_indctn_rpt_ie_t err_indctn_rpt;
  pfcp_load_ctl_info_ie_t load_ctl_info;
  pfcp_ovrld_ctl_info_ie_t ovrld_ctl_info;
  pfcp_add_usage_rpts_info_ie_t add_usage_rpts_info;
  uint8_t usage_report_count;
  pfcp_usage_rpt_sess_rpt_req_ie_t usage_report[MAX_LIST_SIZE];
} pfcp_sess_rpt_req_t;

typedef struct pfcp_sess_rpt_rsp_t {
  pfcp_header_t header;
  pfcp_cause_ie_t cause;
  pfcp_offending_ie_ie_t offending_ie;
  pfcp_upd_bar_sess_rpt_rsp_ie_t update_bar;
  pfcp_pfcpsrrsp_flags_ie_t sxsrrsp_flags;
} pfcp_sess_rpt_rsp_t;

/* TODO: Revisit this for change in yang */
#pragma pack()
#endif
