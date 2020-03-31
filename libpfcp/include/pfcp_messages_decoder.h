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

#ifndef __PFCP_MESSAGES_DECODE_H__
#define __PFCP_MESSAGES_DECODE_H__


#include "pfcp_messages.h"

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
* Decodes pfcp_hrtbeat_req_t to buffer.
* @param value 
*    pfcp_hrtbeat_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hrtbeat_req_t(uint8_t *buf,
    pfcp_hrtbeat_req_t *value);

/**
* Decodes pfcp_hrtbeat_rsp_t to buffer.
* @param value 
*    pfcp_hrtbeat_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hrtbeat_rsp_t(uint8_t *buf,
    pfcp_hrtbeat_rsp_t *value);

/**
* Decodes pfcp_pfd_mgmt_req_t to buffer.
* @param value 
*    pfcp_pfd_mgmt_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_mgmt_req_t(uint8_t *buf,
    pfcp_pfd_mgmt_req_t *value);

/**
* Decodes pfcp_app_ids_pfds_ie_t to buffer.
* @param value 
*    pfcp_app_ids_pfds_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_ids_pfds_ie_t(uint8_t *buf,
    pfcp_app_ids_pfds_ie_t *value);

/**
* Decodes pfcp_pfd_context_ie_t to buffer.
* @param value 
*    pfcp_pfd_context_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_context_ie_t(uint8_t *buf,
    pfcp_pfd_context_ie_t *value);

/**
* Decodes pfcp_pfd_mgmt_rsp_t to buffer.
* @param value 
*    pfcp_pfd_mgmt_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_mgmt_rsp_t(uint8_t *buf,
    pfcp_pfd_mgmt_rsp_t *value);

/**
* Decodes pfcp_assn_setup_req_t to buffer.
* @param value 
*    pfcp_assn_setup_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_setup_req_t(uint8_t *buf,
    pfcp_assn_setup_req_t *value);

/**
* Decodes pfcp_assn_setup_rsp_t to buffer.
* @param value 
*    pfcp_assn_setup_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_setup_rsp_t(uint8_t *buf,
    pfcp_assn_setup_rsp_t *value);

/**
* Decodes pfcp_assn_upd_req_t to buffer.
* @param value 
*    pfcp_assn_upd_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_upd_req_t(uint8_t *buf,
    pfcp_assn_upd_req_t *value);

/**
* Decodes pfcp_assn_upd_rsp_t to buffer.
* @param value 
*    pfcp_assn_upd_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_upd_rsp_t(uint8_t *buf,
    pfcp_assn_upd_rsp_t *value);

/**
* Decodes pfcp_assn_rel_req_t to buffer.
* @param value 
*    pfcp_assn_rel_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_rel_req_t(uint8_t *buf,
    pfcp_assn_rel_req_t *value);

/**
* Decodes pfcp_assn_rel_rsp_t to buffer.
* @param value 
*    pfcp_assn_rel_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_rel_rsp_t(uint8_t *buf,
    pfcp_assn_rel_rsp_t *value);

/**
* Decodes pfcp_node_rpt_req_t to buffer.
* @param value 
*    pfcp_node_rpt_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_req_t(uint8_t *buf,
    pfcp_node_rpt_req_t *value);

/**
* Decodes pfcp_user_plane_path_fail_rpt_ie_t to buffer.
* @param value 
*    pfcp_user_plane_path_fail_rpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_path_fail_rpt_ie_t(uint8_t *buf,
    pfcp_user_plane_path_fail_rpt_ie_t *value);

/**
* Decodes pfcp_node_rpt_rsp_t to buffer.
* @param value 
*    pfcp_node_rpt_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_rsp_t(uint8_t *buf,
    pfcp_node_rpt_rsp_t *value);

/**
* Decodes pfcp_sess_set_del_req_t to buffer.
* @param value 
*    pfcp_sess_set_del_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_set_del_req_t(uint8_t *buf,
    pfcp_sess_set_del_req_t *value);

/**
* Decodes pfcp_sess_set_del_rsp_t to buffer.
* @param value 
*    pfcp_sess_set_del_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_set_del_rsp_t(uint8_t *buf,
    pfcp_sess_set_del_rsp_t *value);

/**
* Decodes pfcp_sess_estab_req_t to buffer.
* @param value 
*    pfcp_sess_estab_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_estab_req_t(uint8_t *buf,
    pfcp_sess_estab_req_t *value);

/**
* Decodes pfcp_create_pdr_ie_t to buffer.
* @param value 
*    pfcp_create_pdr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_pdr_ie_t(uint8_t *buf,
    pfcp_create_pdr_ie_t *value);

/**
* Decodes pfcp_pdi_ie_t to buffer.
* @param value 
*    pfcp_pdi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdi_ie_t(uint8_t *buf,
    pfcp_pdi_ie_t *value);

/**
* Decodes pfcp_eth_pckt_fltr_ie_t to buffer.
* @param value 
*    pfcp_eth_pckt_fltr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_pckt_fltr_ie_t(uint8_t *buf,
    pfcp_eth_pckt_fltr_ie_t *value);

/**
* Decodes pfcp_create_far_ie_t to buffer.
* @param value 
*    pfcp_create_far_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_far_ie_t(uint8_t *buf,
    pfcp_create_far_ie_t *value);

/**
* Decodes pfcp_frwdng_parms_ie_t to buffer.
* @param value 
*    pfcp_frwdng_parms_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frwdng_parms_ie_t(uint8_t *buf,
    pfcp_frwdng_parms_ie_t *value);

/**
* Decodes pfcp_dupng_parms_ie_t to buffer.
* @param value 
*    pfcp_dupng_parms_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dupng_parms_ie_t(uint8_t *buf,
    pfcp_dupng_parms_ie_t *value);

/**
* Decodes pfcp_create_urr_ie_t to buffer.
* @param value 
*    pfcp_create_urr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_urr_ie_t(uint8_t *buf,
    pfcp_create_urr_ie_t *value);

/**
* Decodes pfcp_aggregated_urrs_ie_t to buffer.
* @param value 
*    pfcp_aggregated_urrs_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_aggregated_urrs_ie_t(uint8_t *buf,
    pfcp_aggregated_urrs_ie_t *value);

/**
* Decodes pfcp_add_mntrng_time_ie_t to buffer.
* @param value 
*    pfcp_add_mntrng_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_add_mntrng_time_ie_t(uint8_t *buf,
    pfcp_add_mntrng_time_ie_t *value);

/**
* Decodes pfcp_create_qer_ie_t to buffer.
* @param value 
*    pfcp_create_qer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_qer_ie_t(uint8_t *buf,
    pfcp_create_qer_ie_t *value);

/**
* Decodes pfcp_create_bar_ie_t to buffer.
* @param value 
*    pfcp_create_bar_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_bar_ie_t(uint8_t *buf,
    pfcp_create_bar_ie_t *value);

/**
* Decodes pfcp_create_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_create_traffic_endpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_traffic_endpt_ie_t(uint8_t *buf,
    pfcp_create_traffic_endpt_ie_t *value);

/**
* Decodes pfcp_sess_estab_rsp_t to buffer.
* @param value 
*    pfcp_sess_estab_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_estab_rsp_t(uint8_t *buf,
    pfcp_sess_estab_rsp_t *value);

/**
* Decodes pfcp_created_pdr_ie_t to buffer.
* @param value 
*    pfcp_created_pdr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_created_pdr_ie_t(uint8_t *buf,
    pfcp_created_pdr_ie_t *value);

/**
* Decodes pfcp_load_ctl_info_ie_t to buffer.
* @param value 
*    pfcp_load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_load_ctl_info_ie_t(uint8_t *buf,
    pfcp_load_ctl_info_ie_t *value);

/**
* Decodes pfcp_ovrld_ctl_info_ie_t to buffer.
* @param value 
*    pfcp_ovrld_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ovrld_ctl_info_ie_t(uint8_t *buf,
    pfcp_ovrld_ctl_info_ie_t *value);

/**
* Decodes pfcp_created_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_created_traffic_endpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_created_traffic_endpt_ie_t(uint8_t *buf,
    pfcp_created_traffic_endpt_ie_t *value);

/**
* Decodes pfcp_sess_mod_req_t to buffer.
* @param value 
*    pfcp_sess_mod_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_mod_req_t(uint8_t *buf,
    pfcp_sess_mod_req_t *value);

/**
* Decodes pfcp_update_pdr_ie_t to buffer.
* @param value 
*    pfcp_update_pdr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_pdr_ie_t(uint8_t *buf,
    pfcp_update_pdr_ie_t *value);

/**
* Decodes pfcp_update_far_ie_t to buffer.
* @param value 
*    pfcp_update_far_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_far_ie_t(uint8_t *buf,
    pfcp_update_far_ie_t *value);

/**
* Decodes pfcp_upd_frwdng_parms_ie_t to buffer.
* @param value 
*    pfcp_upd_frwdng_parms_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_frwdng_parms_ie_t(uint8_t *buf,
    pfcp_upd_frwdng_parms_ie_t *value);

/**
* Decodes pfcp_upd_dupng_parms_ie_t to buffer.
* @param value 
*    pfcp_upd_dupng_parms_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_dupng_parms_ie_t(uint8_t *buf,
    pfcp_upd_dupng_parms_ie_t *value);

/**
* Decodes pfcp_update_urr_ie_t to buffer.
* @param value 
*    pfcp_update_urr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_urr_ie_t(uint8_t *buf,
    pfcp_update_urr_ie_t *value);

/**
* Decodes pfcp_update_qer_ie_t to buffer.
* @param value 
*    pfcp_update_qer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_qer_ie_t(uint8_t *buf,
    pfcp_update_qer_ie_t *value);

/**
* Decodes pfcp_remove_pdr_ie_t to buffer.
* @param value 
*    pfcp_remove_pdr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_pdr_ie_t(uint8_t *buf,
    pfcp_remove_pdr_ie_t *value);

/**
* Decodes pfcp_remove_far_ie_t to buffer.
* @param value 
*    pfcp_remove_far_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_far_ie_t(uint8_t *buf,
    pfcp_remove_far_ie_t *value);

/**
* Decodes pfcp_remove_urr_ie_t to buffer.
* @param value 
*    pfcp_remove_urr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_urr_ie_t(uint8_t *buf,
    pfcp_remove_urr_ie_t *value);

/**
* Decodes pfcp_remove_qer_ie_t to buffer.
* @param value 
*    pfcp_remove_qer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_qer_ie_t(uint8_t *buf,
    pfcp_remove_qer_ie_t *value);

/**
* Decodes pfcp_query_urr_ie_t to buffer.
* @param value 
*    pfcp_query_urr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_query_urr_ie_t(uint8_t *buf,
    pfcp_query_urr_ie_t *value);

/**
* Decodes pfcp_upd_bar_sess_mod_req_ie_t to buffer.
* @param value 
*    pfcp_upd_bar_sess_mod_req_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_bar_sess_mod_req_ie_t(uint8_t *buf,
    pfcp_upd_bar_sess_mod_req_ie_t *value);

/**
* Decodes pfcp_remove_bar_ie_t to buffer.
* @param value 
*    pfcp_remove_bar_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_bar_ie_t(uint8_t *buf,
    pfcp_remove_bar_ie_t *value);

/**
* Decodes pfcp_upd_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_upd_traffic_endpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_traffic_endpt_ie_t(uint8_t *buf,
    pfcp_upd_traffic_endpt_ie_t *value);

/**
* Decodes pfcp_rmv_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_rmv_traffic_endpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rmv_traffic_endpt_ie_t(uint8_t *buf,
    pfcp_rmv_traffic_endpt_ie_t *value);

/**
* Decodes pfcp_sess_mod_rsp_t to buffer.
* @param value 
*    pfcp_sess_mod_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_mod_rsp_t(uint8_t *buf,
    pfcp_sess_mod_rsp_t *value);

/**
* Decodes pfcp_usage_rpt_sess_mod_rsp_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_mod_rsp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_mod_rsp_ie_t(uint8_t *buf,
    pfcp_usage_rpt_sess_mod_rsp_ie_t *value);

/**
* Decodes pfcp_sess_del_req_t to buffer.
* @param value 
*    pfcp_sess_del_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_del_req_t(uint8_t *buf,
    pfcp_sess_del_req_t *value);

/**
* Decodes pfcp_sess_del_rsp_t to buffer.
* @param value 
*    pfcp_sess_del_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_del_rsp_t(uint8_t *buf,
    pfcp_sess_del_rsp_t *value);

/**
* Decodes pfcp_usage_rpt_sess_del_rsp_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_del_rsp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_del_rsp_ie_t(uint8_t *buf,
    pfcp_usage_rpt_sess_del_rsp_ie_t *value);

/**
* Decodes pfcp_sess_rpt_req_t to buffer.
* @param value 
*    pfcp_sess_rpt_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_rpt_req_t(uint8_t *buf,
    pfcp_sess_rpt_req_t *value);

/**
* Decodes pfcp_dnlnk_data_rpt_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_rpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_rpt_ie_t(uint8_t *buf,
    pfcp_dnlnk_data_rpt_ie_t *value);

/**
* Decodes pfcp_usage_rpt_sess_rpt_req_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_rpt_req_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_rpt_req_ie_t(uint8_t *buf,
    pfcp_usage_rpt_sess_rpt_req_ie_t *value);

/**
* Decodes pfcp_app_det_info_ie_t to buffer.
* @param value 
*    pfcp_app_det_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_det_info_ie_t(uint8_t *buf,
    pfcp_app_det_info_ie_t *value);

/**
* Decodes pfcp_eth_traffic_info_ie_t to buffer.
* @param value 
*    pfcp_eth_traffic_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_traffic_info_ie_t(uint8_t *buf,
    pfcp_eth_traffic_info_ie_t *value);

/**
* Decodes pfcp_err_indctn_rpt_ie_t to buffer.
* @param value 
*    pfcp_err_indctn_rpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_err_indctn_rpt_ie_t(uint8_t *buf,
    pfcp_err_indctn_rpt_ie_t *value);

/**
* Decodes pfcp_sess_rpt_rsp_t to buffer.
* @param value 
*    pfcp_sess_rpt_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_rpt_rsp_t(uint8_t *buf,
    pfcp_sess_rpt_rsp_t *value);

/**
* Decodes pfcp_upd_bar_sess_rpt_rsp_ie_t to buffer.
* @param value 
*    pfcp_upd_bar_sess_rpt_rsp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_bar_sess_rpt_rsp_ie_t(uint8_t *buf,
    pfcp_upd_bar_sess_rpt_rsp_ie_t *value);


#endif /*__PFCP_MESSAGES_DECODE_H__*/