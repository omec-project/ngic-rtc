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

#ifndef __PFCP_IES_ENCODE_H__
#define __PFCP_IES_ENCODE_H__


#include "pfcp_ies.h"

#define MBR_BUF_SIZE 5

/**
 * Encodes pfcp_header_t to buffer.
 * @param value
 *     pfcp_header_t
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_header_t(pfcp_header_t *value,
	uint8_t *buf);

/**
 * Encodes pfcp_ie_header to buffer.
 * @param value
 *     pfcp_ie_header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_ie_header_t(pfcp_ie_header_t *value,
	uint8_t *buf);

/**
* Encodes pfcp_cause_ie_t to buffer.
* @param value 
*    pfcp_cause_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_cause_ie_t(pfcp_cause_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_src_intfc_ie_t to buffer.
* @param value 
*    pfcp_src_intfc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_src_intfc_ie_t(pfcp_src_intfc_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_fteid_ie_t to buffer.
* @param value 
*    pfcp_fteid_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_fteid_ie_t(pfcp_fteid_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_ntwk_inst_ie_t to buffer.
* @param value 
*    pfcp_ntwk_inst_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ntwk_inst_ie_t(pfcp_ntwk_inst_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sdf_filter_ie_t to buffer.
* @param value 
*    pfcp_sdf_filter_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sdf_filter_ie_t(pfcp_sdf_filter_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_application_id_ie_t to buffer.
* @param value 
*    pfcp_application_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_application_id_ie_t(pfcp_application_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_gate_status_ie_t to buffer.
* @param value 
*    pfcp_gate_status_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_gate_status_ie_t(pfcp_gate_status_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_mbr_ie_t to buffer.
* @param value 
*    pfcp_mbr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mbr_ie_t(pfcp_mbr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_gbr_ie_t to buffer.
* @param value 
*    pfcp_gbr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_gbr_ie_t(pfcp_gbr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_qer_corr_id_ie_t to buffer.
* @param value 
*    pfcp_qer_corr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qer_corr_id_ie_t(pfcp_qer_corr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_precedence_ie_t to buffer.
* @param value 
*    pfcp_precedence_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_precedence_ie_t(pfcp_precedence_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_trnspt_lvl_marking_ie_t to buffer.
* @param value 
*    pfcp_trnspt_lvl_marking_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_trnspt_lvl_marking_ie_t(pfcp_trnspt_lvl_marking_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_vol_thresh_ie_t to buffer.
* @param value 
*    pfcp_vol_thresh_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_vol_thresh_ie_t(pfcp_vol_thresh_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_time_threshold_ie_t to buffer.
* @param value 
*    pfcp_time_threshold_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_threshold_ie_t(pfcp_time_threshold_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_monitoring_time_ie_t to buffer.
* @param value 
*    pfcp_monitoring_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_monitoring_time_ie_t(pfcp_monitoring_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_vol_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_vol_thresh_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_vol_thresh_ie_t(pfcp_sbsqnt_vol_thresh_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_time_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_time_thresh_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_time_thresh_ie_t(pfcp_sbsqnt_time_thresh_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_inact_det_time_ie_t to buffer.
* @param value 
*    pfcp_inact_det_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_inact_det_time_ie_t(pfcp_inact_det_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_rptng_triggers_ie_t to buffer.
* @param value 
*    pfcp_rptng_triggers_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rptng_triggers_ie_t(pfcp_rptng_triggers_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_redir_info_ie_t to buffer.
* @param value 
*    pfcp_redir_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_redir_info_ie_t(pfcp_redir_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_report_type_ie_t to buffer.
* @param value 
*    pfcp_report_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_report_type_ie_t(pfcp_report_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_offending_ie_ie_t to buffer.
* @param value 
*    pfcp_offending_ie_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_offending_ie_ie_t(pfcp_offending_ie_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_frwdng_plcy_ie_t to buffer.
* @param value 
*    pfcp_frwdng_plcy_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_frwdng_plcy_ie_t(pfcp_frwdng_plcy_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dst_intfc_ie_t to buffer.
* @param value 
*    pfcp_dst_intfc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dst_intfc_ie_t(pfcp_dst_intfc_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_up_func_feat_ie_t to buffer.
* @param value 
*    pfcp_up_func_feat_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_up_func_feat_ie_t(pfcp_up_func_feat_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_apply_action_ie_t to buffer.
* @param value 
*    pfcp_apply_action_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_apply_action_ie_t(pfcp_apply_action_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dnlnk_data_svc_info_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_svc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_svc_info_ie_t(pfcp_dnlnk_data_svc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dnlnk_data_notif_delay_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_notif_delay_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_notif_delay_ie_t(pfcp_dnlnk_data_notif_delay_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dl_buf_dur_ie_t to buffer.
* @param value 
*    pfcp_dl_buf_dur_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_buf_dur_ie_t(pfcp_dl_buf_dur_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dl_buf_suggstd_pckt_cnt_ie_t to buffer.
* @param value 
*    pfcp_dl_buf_suggstd_pckt_cnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(pfcp_dl_buf_suggstd_pckt_cnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfcpsmreq_flags_ie_t to buffer.
* @param value 
*    pfcp_pfcpsmreq_flags_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfcpsmreq_flags_ie_t(pfcp_pfcpsmreq_flags_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfcpsrrsp_flags_ie_t to buffer.
* @param value 
*    pfcp_pfcpsrrsp_flags_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfcpsrrsp_flags_ie_t(pfcp_pfcpsrrsp_flags_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sequence_number_ie_t to buffer.
* @param value 
*    pfcp_sequence_number_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sequence_number_ie_t(pfcp_sequence_number_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_metric_ie_t to buffer.
* @param value 
*    pfcp_metric_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_metric_ie_t(pfcp_metric_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_timer_ie_t to buffer.
* @param value 
*    pfcp_timer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_timer_ie_t(pfcp_timer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pdr_id_ie_t to buffer.
* @param value 
*    pfcp_pdr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pdr_id_ie_t(pfcp_pdr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_fseid_ie_t to buffer.
* @param value 
*    pfcp_fseid_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_fseid_ie_t(pfcp_fseid_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_node_id_ie_t to buffer.
* @param value 
*    pfcp_node_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_id_ie_t(pfcp_node_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfd_contents_ie_t to buffer.
* @param value 
*    pfcp_pfd_contents_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_contents_ie_t(pfcp_pfd_contents_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_meas_mthd_ie_t to buffer.
* @param value 
*    pfcp_meas_mthd_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_mthd_ie_t(pfcp_meas_mthd_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_usage_rpt_trig_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_trig_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_rpt_trig_ie_t(pfcp_usage_rpt_trig_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_meas_period_ie_t to buffer.
* @param value 
*    pfcp_meas_period_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_period_ie_t(pfcp_meas_period_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_fqcsid_ie_t to buffer.
* @param value 
*    pfcp_fqcsid_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_fqcsid_ie_t(pfcp_fqcsid_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_vol_meas_ie_t to buffer.
* @param value 
*    pfcp_vol_meas_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_vol_meas_ie_t(pfcp_vol_meas_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dur_meas_ie_t to buffer.
* @param value 
*    pfcp_dur_meas_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dur_meas_ie_t(pfcp_dur_meas_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_time_of_frst_pckt_ie_t to buffer.
* @param value 
*    pfcp_time_of_frst_pckt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_of_frst_pckt_ie_t(pfcp_time_of_frst_pckt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_time_of_lst_pckt_ie_t to buffer.
* @param value 
*    pfcp_time_of_lst_pckt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_of_lst_pckt_ie_t(pfcp_time_of_lst_pckt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_quota_hldng_time_ie_t to buffer.
* @param value 
*    pfcp_quota_hldng_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_quota_hldng_time_ie_t(pfcp_quota_hldng_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_drpd_dl_traffic_thresh_ie_t to buffer.
* @param value 
*    pfcp_drpd_dl_traffic_thresh_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_drpd_dl_traffic_thresh_ie_t(pfcp_drpd_dl_traffic_thresh_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_volume_quota_ie_t to buffer.
* @param value 
*    pfcp_volume_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_volume_quota_ie_t(pfcp_volume_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_time_quota_ie_t to buffer.
* @param value 
*    pfcp_time_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_quota_ie_t(pfcp_time_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_start_time_ie_t to buffer.
* @param value 
*    pfcp_start_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_start_time_ie_t(pfcp_start_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_end_time_ie_t to buffer.
* @param value 
*    pfcp_end_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_end_time_ie_t(pfcp_end_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_urr_id_ie_t to buffer.
* @param value 
*    pfcp_urr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_urr_id_ie_t(pfcp_urr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_linked_urr_id_ie_t to buffer.
* @param value 
*    pfcp_linked_urr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_linked_urr_id_ie_t(pfcp_linked_urr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_outer_hdr_creation_ie_t to buffer.
* @param value 
*    pfcp_outer_hdr_creation_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_outer_hdr_creation_ie_t(pfcp_outer_hdr_creation_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_bar_id_ie_t to buffer.
* @param value 
*    pfcp_bar_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_bar_id_ie_t(pfcp_bar_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_cp_func_feat_ie_t to buffer.
* @param value 
*    pfcp_cp_func_feat_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_cp_func_feat_ie_t(pfcp_cp_func_feat_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_usage_info_ie_t to buffer.
* @param value 
*    pfcp_usage_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_info_ie_t(pfcp_usage_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_app_inst_id_ie_t to buffer.
* @param value 
*    pfcp_app_inst_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_app_inst_id_ie_t(pfcp_app_inst_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_flow_info_ie_t to buffer.
* @param value 
*    pfcp_flow_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_flow_info_ie_t(pfcp_flow_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_ue_ip_address_ie_t to buffer.
* @param value 
*    pfcp_ue_ip_address_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ue_ip_address_ie_t(pfcp_ue_ip_address_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_packet_rate_ie_t to buffer.
* @param value 
*    pfcp_packet_rate_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_packet_rate_ie_t(pfcp_packet_rate_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_outer_hdr_removal_ie_t to buffer.
* @param value 
*    pfcp_outer_hdr_removal_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_outer_hdr_removal_ie_t(pfcp_outer_hdr_removal_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_rcvry_time_stmp_ie_t to buffer.
* @param value 
*    pfcp_rcvry_time_stmp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rcvry_time_stmp_ie_t(pfcp_rcvry_time_stmp_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dl_flow_lvl_marking_ie_t to buffer.
* @param value 
*    pfcp_dl_flow_lvl_marking_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_flow_lvl_marking_ie_t(pfcp_dl_flow_lvl_marking_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_hdr_enrchmt_ie_t to buffer.
* @param value 
*    pfcp_hdr_enrchmt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_hdr_enrchmt_ie_t(pfcp_hdr_enrchmt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_meas_info_ie_t to buffer.
* @param value 
*    pfcp_meas_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_info_ie_t(pfcp_meas_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_node_rpt_type_ie_t to buffer.
* @param value 
*    pfcp_node_rpt_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_rpt_type_ie_t(pfcp_node_rpt_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_rmt_gtpu_peer_ie_t to buffer.
* @param value 
*    pfcp_rmt_gtpu_peer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rmt_gtpu_peer_ie_t(pfcp_rmt_gtpu_peer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_urseqn_ie_t to buffer.
* @param value 
*    pfcp_urseqn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_urseqn_ie_t(pfcp_urseqn_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_actvt_predef_rules_ie_t to buffer.
* @param value 
*    pfcp_actvt_predef_rules_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_actvt_predef_rules_ie_t(pfcp_actvt_predef_rules_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_deact_predef_rules_ie_t to buffer.
* @param value 
*    pfcp_deact_predef_rules_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_deact_predef_rules_ie_t(pfcp_deact_predef_rules_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_far_id_ie_t to buffer.
* @param value 
*    pfcp_far_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_far_id_ie_t(pfcp_far_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_qer_id_ie_t to buffer.
* @param value 
*    pfcp_qer_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qer_id_ie_t(pfcp_qer_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_oci_flags_ie_t to buffer.
* @param value 
*    pfcp_oci_flags_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_oci_flags_ie_t(pfcp_oci_flags_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_up_assn_rel_req_ie_t to buffer.
* @param value 
*    pfcp_up_assn_rel_req_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_up_assn_rel_req_ie_t(pfcp_up_assn_rel_req_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_graceful_rel_period_ie_t to buffer.
* @param value 
*    pfcp_graceful_rel_period_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_graceful_rel_period_ie_t(pfcp_graceful_rel_period_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pdn_type_ie_t to buffer.
* @param value 
*    pfcp_pdn_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pdn_type_ie_t(pfcp_pdn_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_failed_rule_id_ie_t to buffer.
* @param value 
*    pfcp_failed_rule_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_failed_rule_id_ie_t(pfcp_failed_rule_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_time_quota_mech_ie_t to buffer.
* @param value 
*    pfcp_time_quota_mech_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_quota_mech_ie_t(pfcp_time_quota_mech_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_user_plane_ip_rsrc_info_ie_t to buffer.
* @param value 
*    pfcp_user_plane_ip_rsrc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_plane_ip_rsrc_info_ie_t(pfcp_user_plane_ip_rsrc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_user_plane_inact_timer_ie_t to buffer.
* @param value 
*    pfcp_user_plane_inact_timer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_plane_inact_timer_ie_t(pfcp_user_plane_inact_timer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_multiplier_ie_t to buffer.
* @param value 
*    pfcp_multiplier_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_multiplier_ie_t(pfcp_multiplier_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_agg_urr_id_ie_t to buffer.
* @param value 
*    pfcp_agg_urr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_agg_urr_id_ie_t(pfcp_agg_urr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_vol_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_vol_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_vol_quota_ie_t(pfcp_sbsqnt_vol_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_time_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_time_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_time_quota_ie_t(pfcp_sbsqnt_time_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_rqi_ie_t to buffer.
* @param value 
*    pfcp_rqi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rqi_ie_t(pfcp_rqi_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_qfi_ie_t to buffer.
* @param value 
*    pfcp_qfi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qfi_ie_t(pfcp_qfi_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_query_urr_ref_ie_t to buffer.
* @param value 
*    pfcp_query_urr_ref_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_query_urr_ref_ie_t(pfcp_query_urr_ref_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_add_usage_rpts_info_ie_t to buffer.
* @param value 
*    pfcp_add_usage_rpts_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_add_usage_rpts_info_ie_t(pfcp_add_usage_rpts_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_traffic_endpt_id_ie_t to buffer.
* @param value 
*    pfcp_traffic_endpt_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_traffic_endpt_id_ie_t(pfcp_traffic_endpt_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_mac_address_ie_t to buffer.
* @param value 
*    pfcp_mac_address_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mac_address_ie_t(pfcp_mac_address_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_ctag_ie_t to buffer.
* @param value 
*    pfcp_ctag_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ctag_ie_t(pfcp_ctag_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_stag_ie_t to buffer.
* @param value 
*    pfcp_stag_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_stag_ie_t(pfcp_stag_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_ethertype_ie_t to buffer.
* @param value 
*    pfcp_ethertype_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ethertype_ie_t(pfcp_ethertype_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_proxying_ie_t to buffer.
* @param value 
*    pfcp_proxying_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_proxying_ie_t(pfcp_proxying_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_fltr_id_ie_t to buffer.
* @param value 
*    pfcp_eth_fltr_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_fltr_id_ie_t(pfcp_eth_fltr_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_fltr_props_ie_t to buffer.
* @param value 
*    pfcp_eth_fltr_props_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_fltr_props_ie_t(pfcp_eth_fltr_props_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_suggstd_buf_pckts_cnt_ie_t to buffer.
* @param value 
*    pfcp_suggstd_buf_pckts_cnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_suggstd_buf_pckts_cnt_ie_t(pfcp_suggstd_buf_pckts_cnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_user_id_ie_t to buffer.
* @param value 
*    pfcp_user_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_id_ie_t(pfcp_user_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_pdu_sess_info_ie_t to buffer.
* @param value 
*    pfcp_eth_pdu_sess_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_pdu_sess_info_ie_t(pfcp_eth_pdu_sess_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_mac_addrs_detctd_ie_t to buffer.
* @param value 
*    pfcp_mac_addrs_detctd_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mac_addrs_detctd_ie_t(pfcp_mac_addrs_detctd_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_mac_addrs_rmvd_ie_t to buffer.
* @param value 
*    pfcp_mac_addrs_rmvd_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mac_addrs_rmvd_ie_t(pfcp_mac_addrs_rmvd_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_inact_timer_ie_t to buffer.
* @param value 
*    pfcp_eth_inact_timer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_inact_timer_ie_t(pfcp_eth_inact_timer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_evnt_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_evnt_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_evnt_quota_ie_t(pfcp_sbsqnt_evnt_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sbsqnt_evnt_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_evnt_thresh_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_evnt_thresh_ie_t(pfcp_sbsqnt_evnt_thresh_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_trc_info_ie_t to buffer.
* @param value 
*    pfcp_trc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_trc_info_ie_t(pfcp_trc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_framed_route_ie_t to buffer.
* @param value 
*    pfcp_framed_route_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_framed_route_ie_t(pfcp_framed_route_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_framed_routing_ie_t to buffer.
* @param value 
*    pfcp_framed_routing_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_framed_routing_ie_t(pfcp_framed_routing_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_frmd_ipv6_rte_ie_t to buffer.
* @param value 
*    pfcp_frmd_ipv6_rte_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_frmd_ipv6_rte_ie_t(pfcp_frmd_ipv6_rte_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_event_quota_ie_t to buffer.
* @param value 
*    pfcp_event_quota_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_event_quota_ie_t(pfcp_event_quota_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_event_threshold_ie_t to buffer.
* @param value 
*    pfcp_event_threshold_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_event_threshold_ie_t(pfcp_event_threshold_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_evnt_time_stmp_ie_t to buffer.
* @param value 
*    pfcp_evnt_time_stmp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_evnt_time_stmp_ie_t(pfcp_evnt_time_stmp_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_avgng_wnd_ie_t to buffer.
* @param value 
*    pfcp_avgng_wnd_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_avgng_wnd_ie_t(pfcp_avgng_wnd_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_paging_plcy_indctr_ie_t to buffer.
* @param value 
*    pfcp_paging_plcy_indctr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_paging_plcy_indctr_ie_t(pfcp_paging_plcy_indctr_ie_t *value,
    uint8_t *buf);


#endif /*__PFCP_IES_ENCODE_H__*/