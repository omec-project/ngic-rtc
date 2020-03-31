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

#ifndef __PFCP_IES_DECODE_H__
#define __PFCP_IES_DECODE_H__


#include "pfcp_ies.h"

/**
 * decodes pfcp_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pfcp_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_header_t(uint8_t *buf, pfcp_header_t *value);

/**
 * decodes pfcp_ie_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     pfcp_ie_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_ie_header_t(uint8_t *buf,
	pfcp_ie_header_t *value);

/**
* Decodes pfcp_cause_ie_t to buffer.
* @param value 
*    pfcp_cause_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_cause_ie_t(uint8_t *buf,
    pfcp_cause_ie_t *value);

/**
* Decodes pfcp_src_intfc_ie_t to buffer.
* @param value 
*    pfcp_src_intfc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_src_intfc_ie_t(uint8_t *buf,
    pfcp_src_intfc_ie_t *value);

/**
* Decodes pfcp_fteid_ie_t to buffer.
* @param value 
*    pfcp_fteid_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fteid_ie_t(uint8_t *buf,
    pfcp_fteid_ie_t *value);

/**
* Decodes pfcp_ntwk_inst_ie_t to buffer.
* @param value 
*    pfcp_ntwk_inst_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ntwk_inst_ie_t(uint8_t *buf,
    pfcp_ntwk_inst_ie_t *value);

/**
* Decodes pfcp_sdf_filter_ie_t to buffer.
* @param value 
*    pfcp_sdf_filter_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sdf_filter_ie_t(uint8_t *buf,
    pfcp_sdf_filter_ie_t *value);

/**
* Decodes pfcp_application_id_ie_t to buffer.
* @param value 
*    pfcp_application_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_application_id_ie_t(uint8_t *buf,
    pfcp_application_id_ie_t *value);

/**
* Decodes pfcp_gate_status_ie_t to buffer.
* @param value 
*    pfcp_gate_status_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_gate_status_ie_t(uint8_t *buf,
    pfcp_gate_status_ie_t *value);

/**
* Decodes pfcp_mbr_ie_t to buffer.
* @param value 
*    pfcp_mbr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mbr_ie_t(uint8_t *buf,
    pfcp_mbr_ie_t *value);

/**
* Decodes pfcp_gbr_ie_t to buffer.
* @param value 
*    pfcp_gbr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_gbr_ie_t(uint8_t *buf,
    pfcp_gbr_ie_t *value);

/**
* Decodes pfcp_qer_corr_id_ie_t to buffer.
* @param value 
*    pfcp_qer_corr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qer_corr_id_ie_t(uint8_t *buf,
    pfcp_qer_corr_id_ie_t *value);

/**
* Decodes pfcp_precedence_ie_t to buffer.
* @param value 
*    pfcp_precedence_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_precedence_ie_t(uint8_t *buf,
    pfcp_precedence_ie_t *value);

/**
* Decodes pfcp_trnspt_lvl_marking_ie_t to buffer.
* @param value 
*    pfcp_trnspt_lvl_marking_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_trnspt_lvl_marking_ie_t(uint8_t *buf,
    pfcp_trnspt_lvl_marking_ie_t *value);

/**
* Decodes pfcp_vol_thresh_ie_t to buffer.
* @param value 
*    pfcp_vol_thresh_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_vol_thresh_ie_t(uint8_t *buf,
    pfcp_vol_thresh_ie_t *value);

/**
* Decodes pfcp_time_threshold_ie_t to buffer.
* @param value 
*    pfcp_time_threshold_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_threshold_ie_t(uint8_t *buf,
    pfcp_time_threshold_ie_t *value);

/**
* Decodes pfcp_monitoring_time_ie_t to buffer.
* @param value 
*    pfcp_monitoring_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_monitoring_time_ie_t(uint8_t *buf,
    pfcp_monitoring_time_ie_t *value);

/**
* Decodes pfcp_sbsqnt_vol_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_vol_thresh_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_vol_thresh_ie_t(uint8_t *buf,
    pfcp_sbsqnt_vol_thresh_ie_t *value);

/**
* Decodes pfcp_sbsqnt_time_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_time_thresh_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_time_thresh_ie_t(uint8_t *buf,
    pfcp_sbsqnt_time_thresh_ie_t *value);

/**
* Decodes pfcp_inact_det_time_ie_t to buffer.
* @param value 
*    pfcp_inact_det_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_inact_det_time_ie_t(uint8_t *buf,
    pfcp_inact_det_time_ie_t *value);

/**
* Decodes pfcp_rptng_triggers_ie_t to buffer.
* @param value 
*    pfcp_rptng_triggers_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rptng_triggers_ie_t(uint8_t *buf,
    pfcp_rptng_triggers_ie_t *value);

/**
* Decodes pfcp_redir_info_ie_t to buffer.
* @param value 
*    pfcp_redir_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_redir_info_ie_t(uint8_t *buf,
    pfcp_redir_info_ie_t *value);

/**
* Decodes pfcp_report_type_ie_t to buffer.
* @param value 
*    pfcp_report_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_report_type_ie_t(uint8_t *buf,
    pfcp_report_type_ie_t *value);

/**
* Decodes pfcp_offending_ie_ie_t to buffer.
* @param value 
*    pfcp_offending_ie_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_offending_ie_ie_t(uint8_t *buf,
    pfcp_offending_ie_ie_t *value);

/**
* Decodes pfcp_frwdng_plcy_ie_t to buffer.
* @param value 
*    pfcp_frwdng_plcy_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frwdng_plcy_ie_t(uint8_t *buf,
    pfcp_frwdng_plcy_ie_t *value);

/**
* Decodes pfcp_dst_intfc_ie_t to buffer.
* @param value 
*    pfcp_dst_intfc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dst_intfc_ie_t(uint8_t *buf,
    pfcp_dst_intfc_ie_t *value);

/**
* Decodes pfcp_up_func_feat_ie_t to buffer.
* @param value 
*    pfcp_up_func_feat_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_up_func_feat_ie_t(uint8_t *buf,
    pfcp_up_func_feat_ie_t *value);

/**
* Decodes pfcp_apply_action_ie_t to buffer.
* @param value 
*    pfcp_apply_action_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_apply_action_ie_t(uint8_t *buf,
    pfcp_apply_action_ie_t *value);

/**
* Decodes pfcp_dnlnk_data_svc_info_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_svc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_svc_info_ie_t(uint8_t *buf,
    pfcp_dnlnk_data_svc_info_ie_t *value);

/**
* Decodes pfcp_dnlnk_data_notif_delay_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_notif_delay_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_notif_delay_ie_t(uint8_t *buf,
    pfcp_dnlnk_data_notif_delay_ie_t *value);

/**
* Decodes pfcp_dl_buf_dur_ie_t to buffer.
* @param value 
*    pfcp_dl_buf_dur_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_buf_dur_ie_t(uint8_t *buf,
    pfcp_dl_buf_dur_ie_t *value);

/**
* Decodes pfcp_dl_buf_suggstd_pckt_cnt_ie_t to buffer.
* @param value 
*    pfcp_dl_buf_suggstd_pckt_cnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(uint8_t *buf,
    pfcp_dl_buf_suggstd_pckt_cnt_ie_t *value);

/**
* Decodes pfcp_pfcpsmreq_flags_ie_t to buffer.
* @param value 
*    pfcp_pfcpsmreq_flags_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfcpsmreq_flags_ie_t(uint8_t *buf,
    pfcp_pfcpsmreq_flags_ie_t *value);

/**
* Decodes pfcp_pfcpsrrsp_flags_ie_t to buffer.
* @param value 
*    pfcp_pfcpsrrsp_flags_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfcpsrrsp_flags_ie_t(uint8_t *buf,
    pfcp_pfcpsrrsp_flags_ie_t *value);

/**
* Decodes pfcp_sequence_number_ie_t to buffer.
* @param value 
*    pfcp_sequence_number_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sequence_number_ie_t(uint8_t *buf,
    pfcp_sequence_number_ie_t *value);

/**
* Decodes pfcp_metric_ie_t to buffer.
* @param value 
*    pfcp_metric_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_metric_ie_t(uint8_t *buf,
    pfcp_metric_ie_t *value);

/**
* Decodes pfcp_timer_ie_t to buffer.
* @param value 
*    pfcp_timer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_timer_ie_t(uint8_t *buf,
    pfcp_timer_ie_t *value);

/**
* Decodes pfcp_pdr_id_ie_t to buffer.
* @param value 
*    pfcp_pdr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdr_id_ie_t(uint8_t *buf,
    pfcp_pdr_id_ie_t *value);

/**
* Decodes pfcp_fseid_ie_t to buffer.
* @param value 
*    pfcp_fseid_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fseid_ie_t(uint8_t *buf,
    pfcp_fseid_ie_t *value);

/**
* Decodes pfcp_node_id_ie_t to buffer.
* @param value 
*    pfcp_node_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_id_ie_t(uint8_t *buf,
    pfcp_node_id_ie_t *value);

/**
* Decodes pfcp_pfd_contents_ie_t to buffer.
* @param value 
*    pfcp_pfd_contents_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_contents_ie_t(uint8_t *buf,
    pfcp_pfd_contents_ie_t *value);

/**
* Decodes pfcp_meas_mthd_ie_t to buffer.
* @param value 
*    pfcp_meas_mthd_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_mthd_ie_t(uint8_t *buf,
    pfcp_meas_mthd_ie_t *value);

/**
* Decodes pfcp_usage_rpt_trig_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_trig_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_trig_ie_t(uint8_t *buf,
    pfcp_usage_rpt_trig_ie_t *value);

/**
* Decodes pfcp_meas_period_ie_t to buffer.
* @param value 
*    pfcp_meas_period_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_period_ie_t(uint8_t *buf,
    pfcp_meas_period_ie_t *value);

/**
* Decodes pfcp_fqcsid_ie_t to buffer.
* @param value 
*    pfcp_fqcsid_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fqcsid_ie_t(uint8_t *buf,
    pfcp_fqcsid_ie_t *value);

/**
* Decodes pfcp_vol_meas_ie_t to buffer.
* @param value 
*    pfcp_vol_meas_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_vol_meas_ie_t(uint8_t *buf,
    pfcp_vol_meas_ie_t *value);

/**
* Decodes pfcp_dur_meas_ie_t to buffer.
* @param value 
*    pfcp_dur_meas_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dur_meas_ie_t(uint8_t *buf,
    pfcp_dur_meas_ie_t *value);

/**
* Decodes pfcp_time_of_frst_pckt_ie_t to buffer.
* @param value 
*    pfcp_time_of_frst_pckt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_of_frst_pckt_ie_t(uint8_t *buf,
    pfcp_time_of_frst_pckt_ie_t *value);

/**
* Decodes pfcp_time_of_lst_pckt_ie_t to buffer.
* @param value 
*    pfcp_time_of_lst_pckt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_of_lst_pckt_ie_t(uint8_t *buf,
    pfcp_time_of_lst_pckt_ie_t *value);

/**
* Decodes pfcp_quota_hldng_time_ie_t to buffer.
* @param value 
*    pfcp_quota_hldng_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_quota_hldng_time_ie_t(uint8_t *buf,
    pfcp_quota_hldng_time_ie_t *value);

/**
* Decodes pfcp_drpd_dl_traffic_thresh_ie_t to buffer.
* @param value 
*    pfcp_drpd_dl_traffic_thresh_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_drpd_dl_traffic_thresh_ie_t(uint8_t *buf,
    pfcp_drpd_dl_traffic_thresh_ie_t *value);

/**
* Decodes pfcp_volume_quota_ie_t to buffer.
* @param value 
*    pfcp_volume_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_volume_quota_ie_t(uint8_t *buf,
    pfcp_volume_quota_ie_t *value);

/**
* Decodes pfcp_time_quota_ie_t to buffer.
* @param value 
*    pfcp_time_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_quota_ie_t(uint8_t *buf,
    pfcp_time_quota_ie_t *value);

/**
* Decodes pfcp_start_time_ie_t to buffer.
* @param value 
*    pfcp_start_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_start_time_ie_t(uint8_t *buf,
    pfcp_start_time_ie_t *value);

/**
* Decodes pfcp_end_time_ie_t to buffer.
* @param value 
*    pfcp_end_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_end_time_ie_t(uint8_t *buf,
    pfcp_end_time_ie_t *value);

/**
* Decodes pfcp_urr_id_ie_t to buffer.
* @param value 
*    pfcp_urr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_urr_id_ie_t(uint8_t *buf,
    pfcp_urr_id_ie_t *value);

/**
* Decodes pfcp_linked_urr_id_ie_t to buffer.
* @param value 
*    pfcp_linked_urr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_linked_urr_id_ie_t(uint8_t *buf,
    pfcp_linked_urr_id_ie_t *value);

/**
* Decodes pfcp_outer_hdr_creation_ie_t to buffer.
* @param value 
*    pfcp_outer_hdr_creation_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_outer_hdr_creation_ie_t(uint8_t *buf,
    pfcp_outer_hdr_creation_ie_t *value);

/**
* Decodes pfcp_bar_id_ie_t to buffer.
* @param value 
*    pfcp_bar_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_bar_id_ie_t(uint8_t *buf,
    pfcp_bar_id_ie_t *value);

/**
* Decodes pfcp_cp_func_feat_ie_t to buffer.
* @param value 
*    pfcp_cp_func_feat_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_cp_func_feat_ie_t(uint8_t *buf,
    pfcp_cp_func_feat_ie_t *value);

/**
* Decodes pfcp_usage_info_ie_t to buffer.
* @param value 
*    pfcp_usage_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_info_ie_t(uint8_t *buf,
    pfcp_usage_info_ie_t *value);

/**
* Decodes pfcp_app_inst_id_ie_t to buffer.
* @param value 
*    pfcp_app_inst_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_inst_id_ie_t(uint8_t *buf,
    pfcp_app_inst_id_ie_t *value);

/**
* Decodes pfcp_flow_info_ie_t to buffer.
* @param value 
*    pfcp_flow_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_flow_info_ie_t(uint8_t *buf,
    pfcp_flow_info_ie_t *value);

/**
* Decodes pfcp_ue_ip_address_ie_t to buffer.
* @param value 
*    pfcp_ue_ip_address_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ue_ip_address_ie_t(uint8_t *buf,
    pfcp_ue_ip_address_ie_t *value);

/**
* Decodes pfcp_packet_rate_ie_t to buffer.
* @param value 
*    pfcp_packet_rate_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_packet_rate_ie_t(uint8_t *buf,
    pfcp_packet_rate_ie_t *value);

/**
* Decodes pfcp_outer_hdr_removal_ie_t to buffer.
* @param value 
*    pfcp_outer_hdr_removal_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_outer_hdr_removal_ie_t(uint8_t *buf,
    pfcp_outer_hdr_removal_ie_t *value);

/**
* Decodes pfcp_rcvry_time_stmp_ie_t to buffer.
* @param value 
*    pfcp_rcvry_time_stmp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rcvry_time_stmp_ie_t(uint8_t *buf,
    pfcp_rcvry_time_stmp_ie_t *value);

/**
* Decodes pfcp_dl_flow_lvl_marking_ie_t to buffer.
* @param value 
*    pfcp_dl_flow_lvl_marking_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_flow_lvl_marking_ie_t(uint8_t *buf,
    pfcp_dl_flow_lvl_marking_ie_t *value);

/**
* Decodes pfcp_hdr_enrchmt_ie_t to buffer.
* @param value 
*    pfcp_hdr_enrchmt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hdr_enrchmt_ie_t(uint8_t *buf,
    pfcp_hdr_enrchmt_ie_t *value);

/**
* Decodes pfcp_meas_info_ie_t to buffer.
* @param value 
*    pfcp_meas_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_info_ie_t(uint8_t *buf,
    pfcp_meas_info_ie_t *value);

/**
* Decodes pfcp_node_rpt_type_ie_t to buffer.
* @param value 
*    pfcp_node_rpt_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_type_ie_t(uint8_t *buf,
    pfcp_node_rpt_type_ie_t *value);

/**
* Decodes pfcp_rmt_gtpu_peer_ie_t to buffer.
* @param value 
*    pfcp_rmt_gtpu_peer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rmt_gtpu_peer_ie_t(uint8_t *buf,
    pfcp_rmt_gtpu_peer_ie_t *value);

/**
* Decodes pfcp_urseqn_ie_t to buffer.
* @param value 
*    pfcp_urseqn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_urseqn_ie_t(uint8_t *buf,
    pfcp_urseqn_ie_t *value);

/**
* Decodes pfcp_actvt_predef_rules_ie_t to buffer.
* @param value 
*    pfcp_actvt_predef_rules_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_actvt_predef_rules_ie_t(uint8_t *buf,
    pfcp_actvt_predef_rules_ie_t *value);

/**
* Decodes pfcp_deact_predef_rules_ie_t to buffer.
* @param value 
*    pfcp_deact_predef_rules_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_deact_predef_rules_ie_t(uint8_t *buf,
    pfcp_deact_predef_rules_ie_t *value);

/**
* Decodes pfcp_far_id_ie_t to buffer.
* @param value 
*    pfcp_far_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_far_id_ie_t(uint8_t *buf,
    pfcp_far_id_ie_t *value);

/**
* Decodes pfcp_qer_id_ie_t to buffer.
* @param value 
*    pfcp_qer_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qer_id_ie_t(uint8_t *buf,
    pfcp_qer_id_ie_t *value);

/**
* Decodes pfcp_oci_flags_ie_t to buffer.
* @param value 
*    pfcp_oci_flags_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_oci_flags_ie_t(uint8_t *buf,
    pfcp_oci_flags_ie_t *value);

/**
* Decodes pfcp_up_assn_rel_req_ie_t to buffer.
* @param value 
*    pfcp_up_assn_rel_req_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_up_assn_rel_req_ie_t(uint8_t *buf,
    pfcp_up_assn_rel_req_ie_t *value);

/**
* Decodes pfcp_graceful_rel_period_ie_t to buffer.
* @param value 
*    pfcp_graceful_rel_period_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_graceful_rel_period_ie_t(uint8_t *buf,
    pfcp_graceful_rel_period_ie_t *value);

/**
* Decodes pfcp_pdn_type_ie_t to buffer.
* @param value 
*    pfcp_pdn_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdn_type_ie_t(uint8_t *buf,
    pfcp_pdn_type_ie_t *value);

/**
* Decodes pfcp_failed_rule_id_ie_t to buffer.
* @param value 
*    pfcp_failed_rule_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_failed_rule_id_ie_t(uint8_t *buf,
    pfcp_failed_rule_id_ie_t *value);

/**
* Decodes pfcp_time_quota_mech_ie_t to buffer.
* @param value 
*    pfcp_time_quota_mech_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_quota_mech_ie_t(uint8_t *buf,
    pfcp_time_quota_mech_ie_t *value);

/**
* Decodes pfcp_user_plane_ip_rsrc_info_ie_t to buffer.
* @param value 
*    pfcp_user_plane_ip_rsrc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_ip_rsrc_info_ie_t(uint8_t *buf,
    pfcp_user_plane_ip_rsrc_info_ie_t *value);

/**
* Decodes pfcp_user_plane_inact_timer_ie_t to buffer.
* @param value 
*    pfcp_user_plane_inact_timer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_inact_timer_ie_t(uint8_t *buf,
    pfcp_user_plane_inact_timer_ie_t *value);

/**
* Decodes pfcp_multiplier_ie_t to buffer.
* @param value 
*    pfcp_multiplier_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_multiplier_ie_t(uint8_t *buf,
    pfcp_multiplier_ie_t *value);

/**
* Decodes pfcp_agg_urr_id_ie_t to buffer.
* @param value 
*    pfcp_agg_urr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_agg_urr_id_ie_t(uint8_t *buf,
    pfcp_agg_urr_id_ie_t *value);

/**
* Decodes pfcp_sbsqnt_vol_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_vol_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_vol_quota_ie_t(uint8_t *buf,
    pfcp_sbsqnt_vol_quota_ie_t *value);

/**
* Decodes pfcp_sbsqnt_time_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_time_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_time_quota_ie_t(uint8_t *buf,
    pfcp_sbsqnt_time_quota_ie_t *value);

/**
* Decodes pfcp_rqi_ie_t to buffer.
* @param value 
*    pfcp_rqi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rqi_ie_t(uint8_t *buf,
    pfcp_rqi_ie_t *value);

/**
* Decodes pfcp_qfi_ie_t to buffer.
* @param value 
*    pfcp_qfi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qfi_ie_t(uint8_t *buf,
    pfcp_qfi_ie_t *value);

/**
* Decodes pfcp_query_urr_ref_ie_t to buffer.
* @param value 
*    pfcp_query_urr_ref_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_query_urr_ref_ie_t(uint8_t *buf,
    pfcp_query_urr_ref_ie_t *value);

/**
* Decodes pfcp_add_usage_rpts_info_ie_t to buffer.
* @param value 
*    pfcp_add_usage_rpts_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_add_usage_rpts_info_ie_t(uint8_t *buf,
    pfcp_add_usage_rpts_info_ie_t *value);

/**
* Decodes pfcp_traffic_endpt_id_ie_t to buffer.
* @param value 
*    pfcp_traffic_endpt_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_traffic_endpt_id_ie_t(uint8_t *buf,
    pfcp_traffic_endpt_id_ie_t *value);

/**
* Decodes pfcp_mac_address_ie_t to buffer.
* @param value 
*    pfcp_mac_address_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_address_ie_t(uint8_t *buf,
    pfcp_mac_address_ie_t *value);

/**
* Decodes pfcp_ctag_ie_t to buffer.
* @param value 
*    pfcp_ctag_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ctag_ie_t(uint8_t *buf,
    pfcp_ctag_ie_t *value);

/**
* Decodes pfcp_stag_ie_t to buffer.
* @param value 
*    pfcp_stag_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_stag_ie_t(uint8_t *buf,
    pfcp_stag_ie_t *value);

/**
* Decodes pfcp_ethertype_ie_t to buffer.
* @param value 
*    pfcp_ethertype_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ethertype_ie_t(uint8_t *buf,
    pfcp_ethertype_ie_t *value);

/**
* Decodes pfcp_proxying_ie_t to buffer.
* @param value 
*    pfcp_proxying_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_proxying_ie_t(uint8_t *buf,
    pfcp_proxying_ie_t *value);

/**
* Decodes pfcp_eth_fltr_id_ie_t to buffer.
* @param value 
*    pfcp_eth_fltr_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_fltr_id_ie_t(uint8_t *buf,
    pfcp_eth_fltr_id_ie_t *value);

/**
* Decodes pfcp_eth_fltr_props_ie_t to buffer.
* @param value 
*    pfcp_eth_fltr_props_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_fltr_props_ie_t(uint8_t *buf,
    pfcp_eth_fltr_props_ie_t *value);

/**
* Decodes pfcp_suggstd_buf_pckts_cnt_ie_t to buffer.
* @param value 
*    pfcp_suggstd_buf_pckts_cnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_suggstd_buf_pckts_cnt_ie_t(uint8_t *buf,
    pfcp_suggstd_buf_pckts_cnt_ie_t *value);

/**
* Decodes pfcp_user_id_ie_t to buffer.
* @param value 
*    pfcp_user_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_id_ie_t(uint8_t *buf,
    pfcp_user_id_ie_t *value);

/**
* Decodes pfcp_eth_pdu_sess_info_ie_t to buffer.
* @param value 
*    pfcp_eth_pdu_sess_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_pdu_sess_info_ie_t(uint8_t *buf,
    pfcp_eth_pdu_sess_info_ie_t *value);

/**
* Decodes pfcp_mac_addrs_detctd_ie_t to buffer.
* @param value 
*    pfcp_mac_addrs_detctd_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_addrs_detctd_ie_t(uint8_t *buf,
    pfcp_mac_addrs_detctd_ie_t *value);

/**
* Decodes pfcp_mac_addrs_rmvd_ie_t to buffer.
* @param value 
*    pfcp_mac_addrs_rmvd_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_addrs_rmvd_ie_t(uint8_t *buf,
    pfcp_mac_addrs_rmvd_ie_t *value);

/**
* Decodes pfcp_eth_inact_timer_ie_t to buffer.
* @param value 
*    pfcp_eth_inact_timer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_inact_timer_ie_t(uint8_t *buf,
    pfcp_eth_inact_timer_ie_t *value);

/**
* Decodes pfcp_sbsqnt_evnt_quota_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_evnt_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_evnt_quota_ie_t(uint8_t *buf,
    pfcp_sbsqnt_evnt_quota_ie_t *value);

/**
* Decodes pfcp_sbsqnt_evnt_thresh_ie_t to buffer.
* @param value 
*    pfcp_sbsqnt_evnt_thresh_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_evnt_thresh_ie_t(uint8_t *buf,
    pfcp_sbsqnt_evnt_thresh_ie_t *value);

/**
* Decodes pfcp_trc_info_ie_t to buffer.
* @param value 
*    pfcp_trc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_trc_info_ie_t(uint8_t *buf,
    pfcp_trc_info_ie_t *value);

/**
* Decodes pfcp_framed_route_ie_t to buffer.
* @param value 
*    pfcp_framed_route_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_framed_route_ie_t(uint8_t *buf,
    pfcp_framed_route_ie_t *value);

/**
* Decodes pfcp_framed_routing_ie_t to buffer.
* @param value 
*    pfcp_framed_routing_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_framed_routing_ie_t(uint8_t *buf,
    pfcp_framed_routing_ie_t *value);

/**
* Decodes pfcp_frmd_ipv6_rte_ie_t to buffer.
* @param value 
*    pfcp_frmd_ipv6_rte_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frmd_ipv6_rte_ie_t(uint8_t *buf,
    pfcp_frmd_ipv6_rte_ie_t *value);

/**
* Decodes pfcp_event_quota_ie_t to buffer.
* @param value 
*    pfcp_event_quota_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_event_quota_ie_t(uint8_t *buf,
    pfcp_event_quota_ie_t *value);

/**
* Decodes pfcp_event_threshold_ie_t to buffer.
* @param value 
*    pfcp_event_threshold_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_event_threshold_ie_t(uint8_t *buf,
    pfcp_event_threshold_ie_t *value);

/**
* Decodes pfcp_evnt_time_stmp_ie_t to buffer.
* @param value 
*    pfcp_evnt_time_stmp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_evnt_time_stmp_ie_t(uint8_t *buf,
    pfcp_evnt_time_stmp_ie_t *value);

/**
* Decodes pfcp_avgng_wnd_ie_t to buffer.
* @param value 
*    pfcp_avgng_wnd_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_avgng_wnd_ie_t(uint8_t *buf,
    pfcp_avgng_wnd_ie_t *value);

/**
* Decodes pfcp_paging_plcy_indctr_ie_t to buffer.
* @param value 
*    pfcp_paging_plcy_indctr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_paging_plcy_indctr_ie_t(uint8_t *buf,
    pfcp_paging_plcy_indctr_ie_t *value);


#endif /*__PFCP_IES_DECODE_H__*/