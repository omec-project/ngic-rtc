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

#ifndef __PFCP_MESSAGES_ENCODE_H__
#define __PFCP_MESSAGES_ENCODE_H__


#include "pfcp_messages.h"

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
* Encodes pfcp_hrtbeat_req_t to buffer.
* @param value 
*    pfcp_hrtbeat_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_hrtbeat_req_t(pfcp_hrtbeat_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_hrtbeat_rsp_t to buffer.
* @param value 
*    pfcp_hrtbeat_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_hrtbeat_rsp_t(pfcp_hrtbeat_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfd_mgmt_req_t to buffer.
* @param value 
*    pfcp_pfd_mgmt_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_mgmt_req_t(pfcp_pfd_mgmt_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_app_ids_pfds_ie_t to buffer.
* @param value 
*    pfcp_app_ids_pfds_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_app_ids_pfds_ie_t(pfcp_app_ids_pfds_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfd_context_ie_t to buffer.
* @param value 
*    pfcp_pfd_context_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_context_ie_t(pfcp_pfd_context_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pfd_mgmt_rsp_t to buffer.
* @param value 
*    pfcp_pfd_mgmt_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_mgmt_rsp_t(pfcp_pfd_mgmt_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_setup_req_t to buffer.
* @param value 
*    pfcp_assn_setup_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_setup_req_t(pfcp_assn_setup_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_setup_rsp_t to buffer.
* @param value 
*    pfcp_assn_setup_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_setup_rsp_t(pfcp_assn_setup_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_upd_req_t to buffer.
* @param value 
*    pfcp_assn_upd_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_upd_req_t(pfcp_assn_upd_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_upd_rsp_t to buffer.
* @param value 
*    pfcp_assn_upd_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_upd_rsp_t(pfcp_assn_upd_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_rel_req_t to buffer.
* @param value 
*    pfcp_assn_rel_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_rel_req_t(pfcp_assn_rel_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_assn_rel_rsp_t to buffer.
* @param value 
*    pfcp_assn_rel_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_rel_rsp_t(pfcp_assn_rel_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_node_rpt_req_t to buffer.
* @param value 
*    pfcp_node_rpt_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_rpt_req_t(pfcp_node_rpt_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_user_plane_path_fail_rpt_ie_t to buffer.
* @param value 
*    pfcp_user_plane_path_fail_rpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_plane_path_fail_rpt_ie_t(pfcp_user_plane_path_fail_rpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_node_rpt_rsp_t to buffer.
* @param value 
*    pfcp_node_rpt_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_rpt_rsp_t(pfcp_node_rpt_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_set_del_req_t to buffer.
* @param value 
*    pfcp_sess_set_del_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_set_del_rsp_t to buffer.
* @param value 
*    pfcp_sess_set_del_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_estab_req_t to buffer.
* @param value 
*    pfcp_sess_estab_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_estab_req_t(pfcp_sess_estab_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_pdr_ie_t to buffer.
* @param value 
*    pfcp_create_pdr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_pdr_ie_t(pfcp_create_pdr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_pdi_ie_t to buffer.
* @param value 
*    pfcp_pdi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pdi_ie_t(pfcp_pdi_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_pckt_fltr_ie_t to buffer.
* @param value 
*    pfcp_eth_pckt_fltr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_pckt_fltr_ie_t(pfcp_eth_pckt_fltr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_far_ie_t to buffer.
* @param value 
*    pfcp_create_far_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_far_ie_t(pfcp_create_far_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_frwdng_parms_ie_t to buffer.
* @param value 
*    pfcp_frwdng_parms_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_frwdng_parms_ie_t(pfcp_frwdng_parms_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dupng_parms_ie_t to buffer.
* @param value 
*    pfcp_dupng_parms_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dupng_parms_ie_t(pfcp_dupng_parms_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_urr_ie_t to buffer.
* @param value 
*    pfcp_create_urr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_urr_ie_t(pfcp_create_urr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_aggregated_urrs_ie_t to buffer.
* @param value 
*    pfcp_aggregated_urrs_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_aggregated_urrs_ie_t(pfcp_aggregated_urrs_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_add_mntrng_time_ie_t to buffer.
* @param value 
*    pfcp_add_mntrng_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_add_mntrng_time_ie_t(pfcp_add_mntrng_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_qer_ie_t to buffer.
* @param value 
*    pfcp_create_qer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_qer_ie_t(pfcp_create_qer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_bar_ie_t to buffer.
* @param value 
*    pfcp_create_bar_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_bar_ie_t(pfcp_create_bar_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_create_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_create_traffic_endpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_traffic_endpt_ie_t(pfcp_create_traffic_endpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_estab_rsp_t to buffer.
* @param value 
*    pfcp_sess_estab_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_estab_rsp_t(pfcp_sess_estab_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_created_pdr_ie_t to buffer.
* @param value 
*    pfcp_created_pdr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_created_pdr_ie_t(pfcp_created_pdr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_load_ctl_info_ie_t to buffer.
* @param value 
*    pfcp_load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_load_ctl_info_ie_t(pfcp_load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_ovrld_ctl_info_ie_t to buffer.
* @param value 
*    pfcp_ovrld_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ovrld_ctl_info_ie_t(pfcp_ovrld_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_created_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_created_traffic_endpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_created_traffic_endpt_ie_t(pfcp_created_traffic_endpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_mod_req_t to buffer.
* @param value 
*    pfcp_sess_mod_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_mod_req_t(pfcp_sess_mod_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_update_pdr_ie_t to buffer.
* @param value 
*    pfcp_update_pdr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_update_pdr_ie_t(pfcp_update_pdr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_update_far_ie_t to buffer.
* @param value 
*    pfcp_update_far_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_update_far_ie_t(pfcp_update_far_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_upd_frwdng_parms_ie_t to buffer.
* @param value 
*    pfcp_upd_frwdng_parms_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_upd_frwdng_parms_ie_t(pfcp_upd_frwdng_parms_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_upd_dupng_parms_ie_t to buffer.
* @param value 
*    pfcp_upd_dupng_parms_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_upd_dupng_parms_ie_t(pfcp_upd_dupng_parms_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_update_urr_ie_t to buffer.
* @param value 
*    pfcp_update_urr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_update_urr_ie_t(pfcp_update_urr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_update_qer_ie_t to buffer.
* @param value 
*    pfcp_update_qer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_update_qer_ie_t(pfcp_update_qer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_remove_pdr_ie_t to buffer.
* @param value 
*    pfcp_remove_pdr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_pdr_ie_t(pfcp_remove_pdr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_remove_far_ie_t to buffer.
* @param value 
*    pfcp_remove_far_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_far_ie_t(pfcp_remove_far_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_remove_urr_ie_t to buffer.
* @param value 
*    pfcp_remove_urr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_urr_ie_t(pfcp_remove_urr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_remove_qer_ie_t to buffer.
* @param value 
*    pfcp_remove_qer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_qer_ie_t(pfcp_remove_qer_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_query_urr_ie_t to buffer.
* @param value 
*    pfcp_query_urr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_query_urr_ie_t(pfcp_query_urr_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_upd_bar_sess_mod_req_ie_t to buffer.
* @param value 
*    pfcp_upd_bar_sess_mod_req_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_upd_bar_sess_mod_req_ie_t(pfcp_upd_bar_sess_mod_req_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_remove_bar_ie_t to buffer.
* @param value 
*    pfcp_remove_bar_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_bar_ie_t(pfcp_remove_bar_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_upd_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_upd_traffic_endpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_upd_traffic_endpt_ie_t(pfcp_upd_traffic_endpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_rmv_traffic_endpt_ie_t to buffer.
* @param value 
*    pfcp_rmv_traffic_endpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rmv_traffic_endpt_ie_t(pfcp_rmv_traffic_endpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_mod_rsp_t to buffer.
* @param value 
*    pfcp_sess_mod_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_mod_rsp_t(pfcp_sess_mod_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_usage_rpt_sess_mod_rsp_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_mod_rsp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_rpt_sess_mod_rsp_ie_t(pfcp_usage_rpt_sess_mod_rsp_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_del_req_t to buffer.
* @param value 
*    pfcp_sess_del_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_del_req_t(pfcp_sess_del_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_del_rsp_t to buffer.
* @param value 
*    pfcp_sess_del_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_del_rsp_t(pfcp_sess_del_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_usage_rpt_sess_del_rsp_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_del_rsp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_rpt_sess_del_rsp_ie_t(pfcp_usage_rpt_sess_del_rsp_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_rpt_req_t to buffer.
* @param value 
*    pfcp_sess_rpt_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_rpt_req_t(pfcp_sess_rpt_req_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_dnlnk_data_rpt_ie_t to buffer.
* @param value 
*    pfcp_dnlnk_data_rpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_rpt_ie_t(pfcp_dnlnk_data_rpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_usage_rpt_sess_rpt_req_ie_t to buffer.
* @param value 
*    pfcp_usage_rpt_sess_rpt_req_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_rpt_sess_rpt_req_ie_t(pfcp_usage_rpt_sess_rpt_req_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_app_det_info_ie_t to buffer.
* @param value 
*    pfcp_app_det_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_app_det_info_ie_t(pfcp_app_det_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_eth_traffic_info_ie_t to buffer.
* @param value 
*    pfcp_eth_traffic_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_traffic_info_ie_t(pfcp_eth_traffic_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_err_indctn_rpt_ie_t to buffer.
* @param value 
*    pfcp_err_indctn_rpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_err_indctn_rpt_ie_t(pfcp_err_indctn_rpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_sess_rpt_rsp_t to buffer.
* @param value 
*    pfcp_sess_rpt_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_rpt_rsp_t(pfcp_sess_rpt_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pfcp_upd_bar_sess_rpt_rsp_ie_t to buffer.
* @param value 
*    pfcp_upd_bar_sess_rpt_rsp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pfcp_upd_bar_sess_rpt_rsp_ie_t(pfcp_upd_bar_sess_rpt_rsp_ie_t *value,
    uint8_t *buf);


#endif /*__PFCP_MESSAGES_ENCODE_H__*/