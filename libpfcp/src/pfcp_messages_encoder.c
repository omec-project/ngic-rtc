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

#include "../include/pfcp_ies_encoder.h"
#include "../include/pfcp_messages_encoder.h"
/**
* Encodes pfcp_sess_rpt_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sess_rpt_req_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sess_rpt_req_t(pfcp_sess_rpt_req_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

    if (value->report_type.header.len)
        enc_len += encode_pfcp_report_type_ie_t(&(value->report_type), buf + enc_len);

    if (value->dnlnk_data_rpt.header.len)
        enc_len += encode_pfcp_dnlnk_data_rpt_ie_t(&(value->dnlnk_data_rpt), buf + enc_len);

    if (value->err_indctn_rpt.header.len)
        enc_len += encode_pfcp_err_indctn_rpt_ie_t(&(value->err_indctn_rpt), buf + enc_len);

    if (value->load_ctl_info.header.len)
        enc_len += encode_pfcp_load_ctl_info_ie_t(&(value->load_ctl_info), buf + enc_len);

    if (value->ovrld_ctl_info.header.len)
        enc_len += encode_pfcp_ovrld_ctl_info_ie_t(&(value->ovrld_ctl_info), buf + enc_len);

    if (value->add_usage_rpts_info.header.len)
        enc_len += encode_pfcp_add_usage_rpts_info_ie_t(&(value->add_usage_rpts_info), buf + enc_len);

    for (uint8_t i = 0; i < value->usage_report_count; i++) {
        if (value->usage_report[i].header.len)
            enc_len += encode_pfcp_usage_rpt_sess_rpt_req_ie_t(&(value->usage_report[i]), buf + enc_len);
    }


    return enc_len;
}

/**
* Encodes pfcp_pfd_mgmt_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pfd_mgmt_req_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_mgmt_req_t(pfcp_pfd_mgmt_req_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

    for (uint8_t i = 0; i < value->app_ids_pfds_count; i++) {
        if (value->app_ids_pfds[i].header.len)
            enc_len += encode_pfcp_app_ids_pfds_ie_t(&(value->app_ids_pfds[i]), buf + enc_len);
    }


    return enc_len;
}

/**
* Encodes pfcp_create_traffic_endpt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_create_traffic_endpt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_traffic_endpt_ie_t(pfcp_create_traffic_endpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->traffic_endpt_id), buf + enc_len);

	if (value->local_fteid.header.len)
		enc_len += encode_pfcp_fteid_ie_t(&(value->local_fteid), buf + enc_len);

	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + enc_len);

	if (value->ue_ip_address.header.len)
		enc_len += encode_pfcp_ue_ip_address_ie_t(&(value->ue_ip_address), buf + enc_len);

	if (value->eth_pdu_sess_info.header.len)
		enc_len += encode_pfcp_eth_pdu_sess_info_ie_t(&(value->eth_pdu_sess_info), buf + enc_len);

	if (value->framed_routing.header.len)
		enc_len += encode_pfcp_framed_routing_ie_t(&(value->framed_routing), buf + enc_len);

	for (uint8_t i = 0; i < value->framed_route_count; i++) {
		if (value->framed_route[i].header.len)
			enc_len += encode_pfcp_framed_route_ie_t(&(value->framed_route[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->frmd_ipv6_rte_count; i++) {
		if (value->frmd_ipv6_rte[i].header.len)
			enc_len += encode_pfcp_frmd_ipv6_rte_ie_t(&(value->frmd_ipv6_rte[i]), buf + enc_len);
	}


	return enc_len;
}

/**
* Encodes pfcp_pfd_context_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pfd_context_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_context_ie_t(pfcp_pfd_context_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    for (uint8_t i = 0; i < value->pfd_contents_count; i++) {
        if (value->pfd_contents[i].header.len)
            enc_len += encode_pfcp_pfd_contents_ie_t(&(value->pfd_contents[i]), buf + (enc_len/CHAR_SIZE));
    }


    return enc_len;
}

/**
* Encodes pfcp_create_urr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_create_urr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_create_urr_ie_t(pfcp_create_urr_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    if (value->urr_id.header.len)
        enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

    if (value->meas_mthd.header.len)
        enc_len += encode_pfcp_meas_mthd_ie_t(&(value->meas_mthd), buf + enc_len);

    if (value->rptng_triggers.header.len)
        enc_len += encode_pfcp_rptng_triggers_ie_t(&(value->rptng_triggers), buf + enc_len);

    if (value->meas_period.header.len)
        enc_len += encode_pfcp_meas_period_ie_t(&(value->meas_period), buf + enc_len);

    if (value->vol_thresh.header.len)
        enc_len += encode_pfcp_vol_thresh_ie_t(&(value->vol_thresh), buf + enc_len);

    if (value->volume_quota.header.len)
        enc_len += encode_pfcp_volume_quota_ie_t(&(value->volume_quota), buf + enc_len);

    if (value->event_threshold.header.len)
        enc_len += encode_pfcp_event_threshold_ie_t(&(value->event_threshold), buf + enc_len);

    if (value->event_quota.header.len)
        enc_len += encode_pfcp_event_quota_ie_t(&(value->event_quota), buf + enc_len);

    if (value->time_threshold.header.len)
        enc_len += encode_pfcp_time_threshold_ie_t(&(value->time_threshold), buf + enc_len);

    if (value->time_quota.header.len)
        enc_len += encode_pfcp_time_quota_ie_t(&(value->time_quota), buf + enc_len);

    if (value->quota_hldng_time.header.len)
        enc_len += encode_pfcp_quota_hldng_time_ie_t(&(value->quota_hldng_time), buf + enc_len);

    if (value->drpd_dl_traffic_thresh.header.len)
        enc_len += encode_pfcp_drpd_dl_traffic_thresh_ie_t(&(value->drpd_dl_traffic_thresh), buf + enc_len);

    if (value->monitoring_time.header.len)
        enc_len += encode_pfcp_monitoring_time_ie_t(&(value->monitoring_time), buf + enc_len);

    if (value->sbsqnt_vol_thresh.header.len)
        enc_len += encode_pfcp_sbsqnt_vol_thresh_ie_t(&(value->sbsqnt_vol_thresh), buf + enc_len);

    if (value->sbsqnt_time_thresh.header.len)
        enc_len += encode_pfcp_sbsqnt_time_thresh_ie_t(&(value->sbsqnt_time_thresh), buf + enc_len);

    if (value->sbsqnt_vol_quota.header.len)
        enc_len += encode_pfcp_sbsqnt_vol_quota_ie_t(&(value->sbsqnt_vol_quota), buf + enc_len);

    if (value->sbsqnt_time_quota.header.len)
        enc_len += encode_pfcp_sbsqnt_time_quota_ie_t(&(value->sbsqnt_time_quota), buf + enc_len);

    if (value->sbsqnt_evnt_thresh.header.len)
        enc_len += encode_pfcp_sbsqnt_evnt_thresh_ie_t(&(value->sbsqnt_evnt_thresh), buf + enc_len);

    if (value->sbsqnt_evnt_quota.header.len)
        enc_len += encode_pfcp_sbsqnt_evnt_quota_ie_t(&(value->sbsqnt_evnt_quota), buf + enc_len);

    if (value->inact_det_time.header.len)
        enc_len += encode_pfcp_inact_det_time_ie_t(&(value->inact_det_time), buf + enc_len);

    if (value->meas_info.header.len)
        enc_len += encode_pfcp_meas_info_ie_t(&(value->meas_info), buf + enc_len);

    if (value->time_quota_mech.header.len)
        enc_len += encode_pfcp_time_quota_mech_ie_t(&(value->time_quota_mech), buf + enc_len);

    if (value->far_id_for_quota_act.header.len)
        enc_len += encode_pfcp_far_id_ie_t(&(value->far_id_for_quota_act), buf + enc_len);

    if (value->eth_inact_timer.header.len)
        enc_len += encode_pfcp_eth_inact_timer_ie_t(&(value->eth_inact_timer), buf + enc_len);

    for (uint8_t i = 0; i < value->linked_urr_id_count; i++) {
        if (value->linked_urr_id[i].header.len)
            enc_len += encode_pfcp_linked_urr_id_ie_t(&(value->linked_urr_id[i]), buf + enc_len);
    }

    for (uint8_t i = 0; i < value->aggregated_urrs_count; i++) {
        if (value->aggregated_urrs[i].header.len)
            enc_len += encode_pfcp_aggregated_urrs_ie_t(&(value->aggregated_urrs[i]), buf + enc_len);
    }

    for (uint8_t i = 0; i < value->add_mntrng_time_count; i++) {
        if (value->add_mntrng_time[i].header.len)
            enc_len += encode_pfcp_add_mntrng_time_ie_t(&(value->add_mntrng_time[i]), buf + enc_len);
    }


    return enc_len;
}

/**
* Encodes pfcp_eth_pckt_fltr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_eth_pckt_fltr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_pckt_fltr_ie_t(pfcp_eth_pckt_fltr_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    if (value->eth_fltr_id.header.len)
        enc_len += encode_pfcp_eth_fltr_id_ie_t(&(value->eth_fltr_id), buf + enc_len);

    if (value->eth_fltr_props.header.len)
        enc_len += encode_pfcp_eth_fltr_props_ie_t(&(value->eth_fltr_props), buf + enc_len);

    if (value->mac_address.header.len)
        enc_len += encode_pfcp_mac_address_ie_t(&(value->mac_address), buf + enc_len);

    if (value->ethertype.header.len)
        enc_len += encode_pfcp_ethertype_ie_t(&(value->ethertype), buf + enc_len);

    if (value->ctag.header.len)
        enc_len += encode_pfcp_ctag_ie_t(&(value->ctag), buf + enc_len);

    if (value->stag.header.len)
        enc_len += encode_pfcp_stag_ie_t(&(value->stag), buf + enc_len);

    for (uint8_t i = 0; i < value->sdf_filter_count; i++) {
        if (value->sdf_filter[i].header.len)
            enc_len += encode_pfcp_sdf_filter_ie_t(&(value->sdf_filter[i]), buf + enc_len);
    }


    return enc_len;
}

/**
* Encodes pfcp_remove_far_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_remove_far_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_remove_far_ie_t(pfcp_remove_far_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    if (value->far_id.header.len)
        enc_len += encode_pfcp_far_id_ie_t(&(value->far_id), buf + enc_len);


    return enc_len;
}

/**
* Encodes pfcp_hrtbeat_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_hrtbeat_req_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_hrtbeat_req_t(pfcp_hrtbeat_req_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

    if (value->rcvry_time_stmp.header.len)
        enc_len += encode_pfcp_rcvry_time_stmp_ie_t(&(value->rcvry_time_stmp), buf + enc_len);


    return enc_len;
}

/**
* Encodes pfcp_create_far_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
	pfcp_create_far_ie_t
* @return
*   number of encoded bytes.
*/

int encode_pfcp_create_far_ie_t(pfcp_create_far_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->far_id.header.len)
		enc_len += encode_pfcp_far_id_ie_t(&(value->far_id), buf + (enc_len/CHAR_SIZE));

	if (value->apply_action.header.len)
		enc_len += encode_pfcp_apply_action_ie_t(&(value->apply_action), buf + (enc_len/CHAR_SIZE));

	if (value->frwdng_parms.header.len)
		enc_len += encode_pfcp_frwdng_parms_ie_t(&(value->frwdng_parms), buf + (enc_len/CHAR_SIZE));

	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + enc_len);

	for (uint8_t i = 0; i < value->dupng_parms_count; i++) {
		if (value->dupng_parms[i].header.len)
			enc_len += encode_pfcp_dupng_parms_ie_t(&(value->dupng_parms[i]), buf + enc_len);
	}

	return enc_len/CHAR_SIZE;
}
/**
* Encodes pfcp_assn_setup_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_assn_setup_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_assn_setup_rsp_t(pfcp_assn_setup_rsp_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

    if (value->node_id.header.len)
        enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

    if (value->cause.header.len)
        enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

    if (value->rcvry_time_stmp.header.len)
        enc_len += encode_pfcp_rcvry_time_stmp_ie_t(&(value->rcvry_time_stmp), buf + enc_len);

    if (value->up_func_feat.header.len)
        enc_len += encode_pfcp_up_func_feat_ie_t(&(value->up_func_feat), buf + enc_len);

    if (value->cp_func_feat.header.len)
        enc_len += encode_pfcp_cp_func_feat_ie_t(&(value->cp_func_feat), buf + enc_len);

    for (uint8_t i = 0; i < value->user_plane_ip_rsrc_info_count; i++) {
        if (value->user_plane_ip_rsrc_info[i].header.len)
            enc_len += encode_pfcp_user_plane_ip_rsrc_info_ie_t(&(value->user_plane_ip_rsrc_info[i]), buf + enc_len);
    }


    return enc_len;
}

/**
* Encodes pfcp_dnlnk_data_rpt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dnlnk_data_rpt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_rpt_ie_t(pfcp_dnlnk_data_rpt_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    for (uint8_t i = 0; i < value->pdr_id_count; i++) {
        if (value->pdr_id[i].header.len)
            enc_len += encode_pfcp_pdr_id_ie_t(&(value->pdr_id[i]), buf + (enc_len/CHAR_SIZE));
    }

    if (value->dnlnk_data_svc_info.header.len)
        enc_len += encode_pfcp_dnlnk_data_svc_info_ie_t(&(value->dnlnk_data_svc_info), buf + (enc_len/CHAR_SIZE));


    return enc_len/CHAR_SIZE;
}

/**
* Encodes pfcp_query_urr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_query_urr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_query_urr_ie_t(pfcp_query_urr_ie_t *value,
    uint8_t *buf)
{
    uint16_t enc_len = 0;

    enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

    if (value->urr_id.header.len)
        enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);


    return enc_len;
}

/**
 * Encodes pfcp_assn_setup_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_assn_setup_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_assn_setup_req_t(pfcp_assn_setup_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->rcvry_time_stmp.header.len)
		enc_len += encode_pfcp_rcvry_time_stmp_ie_t(&(value->rcvry_time_stmp), buf + enc_len);

	if (value->up_func_feat.header.len)
		enc_len += encode_pfcp_up_func_feat_ie_t(&(value->up_func_feat), buf + enc_len);

	if (value->cp_func_feat.header.len)
		enc_len += encode_pfcp_cp_func_feat_ie_t(&(value->cp_func_feat), buf + enc_len);

	for (uint8_t i = 0; i < value->user_plane_ip_rsrc_info_count; i++) {
		if (value->user_plane_ip_rsrc_info[i].header.len)
			enc_len += encode_pfcp_user_plane_ip_rsrc_info_ie_t(&(value->user_plane_ip_rsrc_info[i]), buf + enc_len);
	}

	return enc_len;
}

/**
 * Encodes pfcp_upd_bar_sess_rpt_rsp_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_upd_bar_sess_rpt_rsp_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_upd_bar_sess_rpt_rsp_ie_t(pfcp_upd_bar_sess_rpt_rsp_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + enc_len);

	if (value->dnlnk_data_notif_delay.header.len)
		enc_len += encode_pfcp_dnlnk_data_notif_delay_ie_t(&(value->dnlnk_data_notif_delay), buf + enc_len);

	if (value->dl_buf_dur.header.len)
		enc_len += encode_pfcp_dl_buf_dur_ie_t(&(value->dl_buf_dur), buf + enc_len);

	if (value->dl_buf_suggstd_pckt_cnt.header.len)
		enc_len += encode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(&(value->dl_buf_suggstd_pckt_cnt), buf + enc_len);

	if (value->suggstd_buf_pckts_cnt.header.len)
		enc_len += encode_pfcp_suggstd_buf_pckts_cnt_ie_t(&(value->suggstd_buf_pckts_cnt), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_sess_mod_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_mod_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_mod_req_t(pfcp_sess_mod_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf);

	if (value->cp_fseid.header.len)
		enc_len += encode_pfcp_fseid_ie_t(&(value->cp_fseid), buf + enc_len);

	if (value->remove_bar.header.len)
		enc_len += encode_pfcp_remove_bar_ie_t(&(value->remove_bar), buf + enc_len);

	if (value->rmv_traffic_endpt.header.len)
		enc_len += encode_pfcp_rmv_traffic_endpt_ie_t(&(value->rmv_traffic_endpt), buf + enc_len);

	if (value->create_bar.header.len) {
		enc_len += encode_pfcp_create_bar_ie_t(&(value->create_bar), buf + enc_len);
	}

	if (value->create_traffic_endpt.header.len) {
		enc_len += encode_pfcp_create_traffic_endpt_ie_t(&(value->create_traffic_endpt), buf + enc_len);
	}

	if (value->update_bar.header.len) {
		enc_len += encode_pfcp_upd_bar_sess_mod_req_ie_t(&(value->update_bar), buf + enc_len);
	}

	if (value->upd_traffic_endpt.header.len) {
		enc_len += encode_pfcp_upd_traffic_endpt_ie_t(&(value->upd_traffic_endpt), buf + enc_len);
	}

	if (value->pfcpsmreq_flags.header.len) {
		enc_len += encode_pfcp_pfcpsmreq_flags_ie_t(&(value->pfcpsmreq_flags), buf + enc_len);
	}

	if (value->pgw_c_fqcsid.header.len) {
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->pgw_c_fqcsid), buf + enc_len);
	}

	if (value->sgw_c_fqcsid.header.len) {
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->sgw_c_fqcsid), buf + enc_len);
	}

	if (value->mme_fqcsid.header.len) {
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->mme_fqcsid), buf + enc_len);
	}

	if (value->epdg_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->epdg_fqcsid), buf + enc_len);

	if (value->twan_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->twan_fqcsid), buf + enc_len);

	if (value->user_plane_inact_timer.header.len)
		enc_len += encode_pfcp_user_plane_inact_timer_ie_t(&(value->user_plane_inact_timer), buf + enc_len);

	if (value->query_urr_ref.header.len)
		enc_len += encode_pfcp_query_urr_ref_ie_t(&(value->query_urr_ref), buf + enc_len);

	if (value->trc_info.header.len) {
		enc_len += encode_pfcp_trc_info_ie_t(&(value->trc_info), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->remove_pdr_count; i++) {
		if (value->remove_pdr[i].header.len)
			enc_len += encode_pfcp_remove_pdr_ie_t(&(value->remove_pdr[i]), buf + enc_len);
	}
	for (uint8_t i = 0; i < value->remove_far_count; i++) {
		if (value->remove_far[i].header.len)
			enc_len += encode_pfcp_remove_far_ie_t(&(value->remove_far[i]), buf + enc_len);
	}
	for (uint8_t i = 0; i < value->remove_urr_count; i++) {
		if (value->remove_urr[i].header.len)
			enc_len += encode_pfcp_remove_urr_ie_t(&(value->remove_urr[i]), buf + enc_len);
	}
	for (uint8_t i = 0; i < value->remove_qer_count; i++) {
		if (value->remove_qer[i].header.len)
			enc_len += encode_pfcp_remove_qer_ie_t(&(value->remove_qer[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_pdr_count; i++) {
		if (value->create_pdr[i].header.len)
			enc_len += encode_pfcp_create_pdr_ie_t(&(value->create_pdr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_far_count; i++) {
		if (value->create_far[i].header.len)
			enc_len += encode_pfcp_create_far_ie_t(&(value->create_far[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_urr_count; i++) {
		if (value->create_urr[i].header.len)
			enc_len += encode_pfcp_create_urr_ie_t(&(value->create_urr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_qer_count; i++) {
		if (value->create_qer[i].header.len)
			enc_len += encode_pfcp_create_qer_ie_t(&(value->create_qer[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->update_pdr_count; i++) {
		if (value->update_pdr[i].header.len)
			enc_len += encode_pfcp_update_pdr_ie_t(&(value->update_pdr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->update_far_count; i++) {
		if (value->update_far[i].header.len)
			enc_len += encode_pfcp_update_far_ie_t(&(value->update_far[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->update_urr_count; i++) {
		if (value->update_urr[i].header.len)
			enc_len += encode_pfcp_update_urr_ie_t(&(value->update_urr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->update_qer_count; i++) {
		if (value->update_qer[i].header.len)
			enc_len += encode_pfcp_update_qer_ie_t(&(value->update_qer[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->query_urr_count; i++) {
		if (value->query_urr[i].header.len)
			enc_len += encode_pfcp_query_urr_ie_t(&(value->query_urr[i]), buf + enc_len);
	}
	return enc_len;
}

/**
 * Encodes pfcp_usage_rpt_sess_mod_rsp_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_usage_rpt_sess_mod_rsp_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_usage_rpt_sess_mod_rsp_ie_t(pfcp_usage_rpt_sess_mod_rsp_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

	if (value->urseqn.header.len)
		enc_len += encode_pfcp_urseqn_ie_t(&(value->urseqn), buf + enc_len);

	if (value->usage_rpt_trig.header.len)
		enc_len += encode_pfcp_usage_rpt_trig_ie_t(&(value->usage_rpt_trig), buf + enc_len);

	if (value->start_time.header.len)
		enc_len += encode_pfcp_start_time_ie_t(&(value->start_time), buf + enc_len);

	if (value->end_time.header.len)
		enc_len += encode_pfcp_end_time_ie_t(&(value->end_time), buf + enc_len);

	if (value->vol_meas.header.len)
		enc_len += encode_pfcp_vol_meas_ie_t(&(value->vol_meas), buf + enc_len);

	if (value->dur_meas.header.len)
		enc_len += encode_pfcp_dur_meas_ie_t(&(value->dur_meas), buf + enc_len);

	if (value->time_of_frst_pckt.header.len)
		enc_len += encode_pfcp_time_of_frst_pckt_ie_t(&(value->time_of_frst_pckt), buf + enc_len);

	if (value->time_of_lst_pckt.header.len)
		enc_len += encode_pfcp_time_of_lst_pckt_ie_t(&(value->time_of_lst_pckt), buf + enc_len);

	if (value->usage_info.header.len)
		enc_len += encode_pfcp_usage_info_ie_t(&(value->usage_info), buf + enc_len);

	if (value->query_urr_ref.header.len)
		enc_len += encode_pfcp_query_urr_ref_ie_t(&(value->query_urr_ref), buf + enc_len);

	if (value->eth_traffic_info.header.len)
		enc_len += encode_pfcp_eth_traffic_info_ie_t(&(value->eth_traffic_info), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_remove_urr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_remove_urr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_remove_urr_ie_t(pfcp_remove_urr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_sess_rpt_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_rpt_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_rpt_rsp_t(pfcp_sess_rpt_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);

	if (value->update_bar.header.len)
		enc_len += encode_pfcp_upd_bar_sess_rpt_rsp_ie_t(&(value->update_bar), buf + enc_len);

	if (value->sxsrrsp_flags.header.len)
		enc_len += encode_pfcp_pfcpsrrsp_flags_ie_t(&(value->sxsrrsp_flags), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_usage_rpt_sess_del_rsp_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_usage_rpt_sess_del_rsp_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_usage_rpt_sess_del_rsp_ie_t(pfcp_usage_rpt_sess_del_rsp_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

	if (value->urseqn.header.len)
		enc_len += encode_pfcp_urseqn_ie_t(&(value->urseqn), buf + enc_len);

	if (value->usage_rpt_trig.header.len)
		enc_len += encode_pfcp_usage_rpt_trig_ie_t(&(value->usage_rpt_trig), buf + enc_len);

	if (value->start_time.header.len)
		enc_len += encode_pfcp_start_time_ie_t(&(value->start_time), buf + enc_len);

	if (value->end_time.header.len)
		enc_len += encode_pfcp_end_time_ie_t(&(value->end_time), buf + enc_len);

	if (value->vol_meas.header.len)
		enc_len += encode_pfcp_vol_meas_ie_t(&(value->vol_meas), buf + enc_len);

	if (value->dur_meas.header.len)
		enc_len += encode_pfcp_dur_meas_ie_t(&(value->dur_meas), buf + enc_len);

	if (value->time_of_frst_pckt.header.len)
		enc_len += encode_pfcp_time_of_frst_pckt_ie_t(&(value->time_of_frst_pckt), buf + enc_len);

	if (value->time_of_lst_pckt.header.len)
		enc_len += encode_pfcp_time_of_lst_pckt_ie_t(&(value->time_of_lst_pckt), buf + enc_len);

	if (value->usage_info.header.len)
		enc_len += encode_pfcp_usage_info_ie_t(&(value->usage_info), buf + enc_len);

	if (value->eth_traffic_info.header.len)
		enc_len += encode_pfcp_eth_traffic_info_ie_t(&(value->eth_traffic_info), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_assn_upd_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_assn_upd_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_assn_upd_rsp_t(pfcp_assn_upd_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->up_func_feat.header.len)
		enc_len += encode_pfcp_up_func_feat_ie_t(&(value->up_func_feat), buf + enc_len);

	if (value->cp_func_feat.header.len)
		enc_len += encode_pfcp_cp_func_feat_ie_t(&(value->cp_func_feat), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_assn_rel_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_assn_rel_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_assn_rel_rsp_t(pfcp_assn_rel_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_usage_rpt_sess_rpt_req_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_usage_rpt_sess_rpt_req_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_usage_rpt_sess_rpt_req_ie_t(pfcp_usage_rpt_sess_rpt_req_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

	if (value->urseqn.header.len)
		enc_len += encode_pfcp_urseqn_ie_t(&(value->urseqn), buf + enc_len);

	if (value->usage_rpt_trig.header.len)
		enc_len += encode_pfcp_usage_rpt_trig_ie_t(&(value->usage_rpt_trig), buf + enc_len);

	if (value->start_time.header.len)
		enc_len += encode_pfcp_start_time_ie_t(&(value->start_time), buf + enc_len);

	if (value->end_time.header.len)
		enc_len += encode_pfcp_end_time_ie_t(&(value->end_time), buf + enc_len);

	if (value->vol_meas.header.len)
		enc_len += encode_pfcp_vol_meas_ie_t(&(value->vol_meas), buf + enc_len);

	if (value->dur_meas.header.len)
		enc_len += encode_pfcp_dur_meas_ie_t(&(value->dur_meas), buf + enc_len);

	if (value->app_det_info.header.len)
		enc_len += encode_pfcp_app_det_info_ie_t(&(value->app_det_info), buf + enc_len);

	if (value->ue_ip_address.header.len)
		enc_len += encode_pfcp_ue_ip_address_ie_t(&(value->ue_ip_address), buf + enc_len);

	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + enc_len);

	if (value->time_of_frst_pckt.header.len)
		enc_len += encode_pfcp_time_of_frst_pckt_ie_t(&(value->time_of_frst_pckt), buf + enc_len);

	if (value->time_of_lst_pckt.header.len)
		enc_len += encode_pfcp_time_of_lst_pckt_ie_t(&(value->time_of_lst_pckt), buf + enc_len);

	if (value->usage_info.header.len)
		enc_len += encode_pfcp_usage_info_ie_t(&(value->usage_info), buf + enc_len);

	if (value->query_urr_ref.header.len)
		enc_len += encode_pfcp_query_urr_ref_ie_t(&(value->query_urr_ref), buf + enc_len);

	if (value->eth_traffic_info.header.len)
		enc_len += encode_pfcp_eth_traffic_info_ie_t(&(value->eth_traffic_info), buf + enc_len);

	for (uint8_t i = 0; i < value->evnt_time_stmp_count; i++) {
		if (value->evnt_time_stmp[i].header.len)
			enc_len += encode_pfcp_evnt_time_stmp_ie_t(&(value->evnt_time_stmp[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_sess_del_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_del_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_del_rsp_t(pfcp_sess_del_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);

	if (value->load_ctl_info.header.len)
		enc_len += encode_pfcp_load_ctl_info_ie_t(&(value->load_ctl_info), buf + enc_len);

	if (value->ovrld_ctl_info.header.len)
		enc_len += encode_pfcp_ovrld_ctl_info_ie_t(&(value->ovrld_ctl_info), buf + enc_len);

	for (uint8_t i = 0; i < value->usage_report_count; i++) {
		if (value->usage_report[i].header.len)
			enc_len += encode_pfcp_usage_rpt_sess_del_rsp_ie_t(&(value->usage_report[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_sess_set_del_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_set_del_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->sgw_c_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->sgw_c_fqcsid), buf + enc_len);

	if (value->pgw_c_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->pgw_c_fqcsid), buf + enc_len);

	if (value->sgw_u_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->sgw_u_fqcsid), buf + enc_len);

	if (value->pgw_u_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->pgw_u_fqcsid), buf + enc_len);

	if (value->twan_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->twan_fqcsid), buf + enc_len);

	if (value->epdg_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->epdg_fqcsid), buf + enc_len);

	if (value->mme_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->mme_fqcsid), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_sess_set_del_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_set_del_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_created_pdr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_created_pdr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_created_pdr_ie_t(pfcp_created_pdr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->pdr_id.header.len)
		enc_len += encode_pfcp_pdr_id_ie_t(&(value->pdr_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->local_fteid.header.len)
		enc_len += encode_pfcp_fteid_ie_t(&(value->local_fteid), buf + (enc_len/CHAR_SIZE));


	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_load_ctl_info_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_load_ctl_info_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_load_ctl_info_ie_t(pfcp_load_ctl_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->load_ctl_seqn_nbr.header.len)
		enc_len += encode_pfcp_sequence_number_ie_t(&(value->load_ctl_seqn_nbr), buf + enc_len);

	if (value->load_metric.header.len)
		enc_len += encode_pfcp_metric_ie_t(&(value->load_metric), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_sess_mod_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_mod_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_mod_rsp_t(pfcp_sess_mod_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);

	if (value->created_pdr.header.len)
		enc_len += encode_pfcp_created_pdr_ie_t(&(value->created_pdr), buf + enc_len);

	if (value->load_ctl_info.header.len)
		enc_len += encode_pfcp_load_ctl_info_ie_t(&(value->load_ctl_info), buf + enc_len);

	if (value->ovrld_ctl_info.header.len)
		enc_len += encode_pfcp_ovrld_ctl_info_ie_t(&(value->ovrld_ctl_info), buf + enc_len);

	if (value->failed_rule_id.header.len)
		enc_len += encode_pfcp_failed_rule_id_ie_t(&(value->failed_rule_id), buf + enc_len);

	if (value->add_usage_rpts_info.header.len)
		enc_len += encode_pfcp_add_usage_rpts_info_ie_t(&(value->add_usage_rpts_info), buf + enc_len);

	if (value->createdupdated_traffic_endpt.header.len)
		enc_len += encode_pfcp_created_traffic_endpt_ie_t(&(value->createdupdated_traffic_endpt), buf + enc_len);

	for (uint8_t i = 0; i < value->usage_report_count; i++) {
		if (value->usage_report[i].header.len)
			enc_len += encode_pfcp_usage_rpt_sess_mod_rsp_ie_t(&(value->usage_report[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_created_traffic_endpt_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_created_traffic_endpt_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_created_traffic_endpt_ie_t(pfcp_created_traffic_endpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->traffic_endpt_id), buf + enc_len);

	if (value->local_fteid.header.len)
		enc_len += encode_pfcp_fteid_ie_t(&(value->local_fteid), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_pfd_mgmt_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_pfd_mgmt_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_pfd_mgmt_rsp_t(pfcp_pfd_mgmt_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_upd_traffic_endpt_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_upd_traffic_endpt_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_upd_traffic_endpt_ie_t(pfcp_upd_traffic_endpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->traffic_endpt_id), buf + enc_len);

	if (value->local_fteid.header.len)
		enc_len += encode_pfcp_fteid_ie_t(&(value->local_fteid), buf + enc_len);

	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + enc_len);

	if (value->ue_ip_address.header.len)
		enc_len += encode_pfcp_ue_ip_address_ie_t(&(value->ue_ip_address), buf + enc_len);

	if (value->framed_routing.header.len)
		enc_len += encode_pfcp_framed_routing_ie_t(&(value->framed_routing), buf + enc_len);

	for (uint8_t i = 0; i < value->framed_route_count; i++) {
		if (value->framed_route[i].header.len)
			enc_len += encode_pfcp_framed_route_ie_t(&(value->framed_route[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->frmd_ipv6_rte_count; i++) {
		if (value->frmd_ipv6_rte[i].header.len)
			enc_len += encode_pfcp_frmd_ipv6_rte_ie_t(&(value->frmd_ipv6_rte[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_upd_dupng_parms_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_upd_dupng_parms_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_upd_dupng_parms_ie_t(pfcp_upd_dupng_parms_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->dst_intfc.header.len)
		enc_len += encode_pfcp_dst_intfc_ie_t(&(value->dst_intfc), buf + enc_len);

	if (value->outer_hdr_creation.header.len)
		enc_len += encode_pfcp_outer_hdr_creation_ie_t(&(value->outer_hdr_creation), buf + enc_len);

	if (value->trnspt_lvl_marking.header.len)
		enc_len += encode_pfcp_trnspt_lvl_marking_ie_t(&(value->trnspt_lvl_marking), buf + enc_len);

	if (value->frwdng_plcy.header.len)
		enc_len += encode_pfcp_frwdng_plcy_ie_t(&(value->frwdng_plcy), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_frwdng_parms_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 *   pfcp_frwdng_parms_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_frwdng_parms_ie_t(pfcp_frwdng_parms_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->dst_intfc.header.len)
		enc_len += encode_pfcp_dst_intfc_ie_t(&(value->dst_intfc), buf + (enc_len/CHAR_SIZE));

	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + enc_len);

	if (value->redir_info.header.len)
		enc_len += encode_pfcp_redir_info_ie_t(&(value->redir_info), buf + enc_len);

	if (value->outer_hdr_creation.header.len)
		enc_len += encode_pfcp_outer_hdr_creation_ie_t(&(value->outer_hdr_creation), buf + (enc_len/CHAR_SIZE));

	if (value->trnspt_lvl_marking.header.len)
		enc_len += encode_pfcp_trnspt_lvl_marking_ie_t(&(value->trnspt_lvl_marking), buf + enc_len);

	if (value->frwdng_plcy.header.len)
		enc_len += encode_pfcp_frwdng_plcy_ie_t(&(value->frwdng_plcy), buf + enc_len);

	if (value->hdr_enrchmt.header.len)
		enc_len += encode_pfcp_hdr_enrchmt_ie_t(&(value->hdr_enrchmt), buf + enc_len);

	if (value->lnkd_traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->lnkd_traffic_endpt_id), buf + enc_len);

	if (value->proxying.header.len)
		enc_len += encode_pfcp_proxying_ie_t(&(value->proxying), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_dupng_parms_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 *   pfcp_dupng_parms_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_dupng_parms_ie_t(pfcp_dupng_parms_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->dst_intfc.header.len)
		enc_len += encode_pfcp_dst_intfc_ie_t(&(value->dst_intfc), buf + enc_len);

	if (value->outer_hdr_creation.header.len)
		enc_len += encode_pfcp_outer_hdr_creation_ie_t(&(value->outer_hdr_creation), buf + enc_len);

	if (value->trnspt_lvl_marking.header.len)
		enc_len += encode_pfcp_trnspt_lvl_marking_ie_t(&(value->trnspt_lvl_marking), buf + enc_len);

	if (value->frwdng_plcy.header.len)
		enc_len += encode_pfcp_frwdng_plcy_ie_t(&(value->frwdng_plcy), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_update_pdr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_update_pdr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_update_pdr_ie_t(pfcp_update_pdr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->pdr_id.header.len)
		enc_len += encode_pfcp_pdr_id_ie_t(&(value->pdr_id), buf + enc_len);

	if (value->outer_hdr_removal.header.len)
		enc_len += encode_pfcp_outer_hdr_removal_ie_t(&(value->outer_hdr_removal), buf + enc_len);

	if (value->precedence.header.len)
		enc_len += encode_pfcp_precedence_ie_t(&(value->precedence), buf + enc_len);

	if (value->pdi.header.len)
		enc_len += encode_pfcp_pdi_ie_t(&(value->pdi), buf + enc_len);

	if (value->far_id.header.len)
		enc_len += encode_pfcp_far_id_ie_t(&(value->far_id), buf + enc_len);

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

	if (value->qer_id.header.len)
		enc_len += encode_pfcp_qer_id_ie_t(&(value->qer_id), buf + enc_len);

	for (uint8_t i = 0; i < value->actvt_predef_rules_count; i++) {
		if (value->actvt_predef_rules[i].header.len)
			enc_len += encode_pfcp_actvt_predef_rules_ie_t(&(value->actvt_predef_rules[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->deact_predef_rules_count; i++) {
		if (value->deact_predef_rules[i].header.len)
			enc_len += encode_pfcp_deact_predef_rules_ie_t(&(value->deact_predef_rules[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_upd_frwdng_parms_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_upd_frwdng_parms_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_upd_frwdng_parms_ie_t(pfcp_upd_frwdng_parms_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->dst_intfc.header.len)
		enc_len += encode_pfcp_dst_intfc_ie_t(&(value->dst_intfc), buf + (enc_len/CHAR_SIZE));

	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + enc_len);

	if (value->redir_info.header.len)
		enc_len += encode_pfcp_redir_info_ie_t(&(value->redir_info), buf + enc_len);

	if (value->outer_hdr_creation.header.len)
		enc_len += encode_pfcp_outer_hdr_creation_ie_t(&(value->outer_hdr_creation), buf + (enc_len/CHAR_SIZE));

	if (value->trnspt_lvl_marking.header.len)
		enc_len += encode_pfcp_trnspt_lvl_marking_ie_t(&(value->trnspt_lvl_marking), buf + enc_len);

	if (value->frwdng_plcy.header.len)
		enc_len += encode_pfcp_frwdng_plcy_ie_t(&(value->frwdng_plcy), buf + enc_len);

	if (value->hdr_enrchmt.header.len)
		enc_len += encode_pfcp_hdr_enrchmt_ie_t(&(value->hdr_enrchmt), buf + enc_len);

	if (value->pfcpsmreq_flags.header.len) {
		uint8_t len =
		len = encode_pfcp_pfcpsmreq_flags_ie_t(&(value->pfcpsmreq_flags), buf + (enc_len/CHAR_SIZE));
		len = (len * CHAR_SIZE);
		enc_len += len;
	}

	if (value->lnkd_traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->lnkd_traffic_endpt_id), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_node_rpt_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_node_rpt_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_node_rpt_rsp_t(pfcp_node_rpt_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_ovrld_ctl_info_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_ovrld_ctl_info_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_ovrld_ctl_info_ie_t(pfcp_ovrld_ctl_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->ovrld_ctl_seqn_nbr.header.len)
		enc_len += encode_pfcp_sequence_number_ie_t(&(value->ovrld_ctl_seqn_nbr), buf + enc_len);

	if (value->ovrld_reduction_metric.header.len)
		enc_len += encode_pfcp_metric_ie_t(&(value->ovrld_reduction_metric), buf + enc_len);

	if (value->period_of_validity.header.len)
		enc_len += encode_pfcp_timer_ie_t(&(value->period_of_validity), buf + enc_len);

	if (value->ovrld_ctl_info_flgs.header.len)
		enc_len += encode_pfcp_oci_flags_ie_t(&(value->ovrld_ctl_info_flgs), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_hrtbeat_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_hrtbeat_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_hrtbeat_rsp_t(pfcp_hrtbeat_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->rcvry_time_stmp.header.len)
		enc_len += encode_pfcp_rcvry_time_stmp_ie_t(&(value->rcvry_time_stmp), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_node_rpt_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_node_rpt_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_node_rpt_req_t(pfcp_node_rpt_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->node_rpt_type.header.len)
		enc_len += encode_pfcp_node_rpt_type_ie_t(&(value->node_rpt_type), buf + enc_len);

	if (value->user_plane_path_fail_rpt.header.len)
		enc_len += encode_pfcp_user_plane_path_fail_rpt_ie_t(&(value->user_plane_path_fail_rpt), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_app_det_info_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_app_det_info_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_app_det_info_ie_t(pfcp_app_det_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->application_id.header.len)
		enc_len += encode_pfcp_application_id_ie_t(&(value->application_id), buf + enc_len);

	if (value->app_inst_id.header.len)
		enc_len += encode_pfcp_app_inst_id_ie_t(&(value->app_inst_id), buf + enc_len);

	if (value->flow_info.header.len)
		enc_len += encode_pfcp_flow_info_ie_t(&(value->flow_info), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_pdi_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_pdi_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_pdi_ie_t(pfcp_pdi_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;
	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->src_intfc.header.len)
		enc_len += encode_pfcp_src_intfc_ie_t(&(value->src_intfc), buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->local_fteid.header.len)
		enc_len += encode_pfcp_fteid_ie_t(&(value->local_fteid), buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->ntwk_inst.header.len)
		enc_len += encode_pfcp_ntwk_inst_ie_t(&(value->ntwk_inst), buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->ue_ip_address.header.len)
		enc_len += encode_pfcp_ue_ip_address_ie_t(&(value->ue_ip_address), buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->traffic_endpt_id), buf + (enc_len/CHAR_SIZE));
/* TODO: Revisit this for change in yang */

	if (value->application_id.header.len)
		enc_len += encode_pfcp_application_id_ie_t(&(value->application_id), buf + (enc_len/CHAR_SIZE));

/* TODO: Revisit this for change in yang */
	if (value->eth_pdu_sess_info.header.len)
		enc_len += encode_pfcp_eth_pdu_sess_info_ie_t(&(value->eth_pdu_sess_info), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->framed_routing.header.len)
		enc_len += encode_pfcp_framed_routing_ie_t(&(value->framed_routing), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->sdf_filter_count; i++) {
		if (value->sdf_filter[i].header.len)
			enc_len += encode_pfcp_sdf_filter_ie_t(&(value->sdf_filter[i]), buf + (enc_len/CHAR_SIZE));
	}
/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->eth_pckt_fltr_count; i++) {
		if (value->eth_pckt_fltr[i].header.len)
			enc_len += encode_pfcp_eth_pckt_fltr_ie_t(&(value->eth_pckt_fltr[i]), buf + (enc_len/CHAR_SIZE));
	}

/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->qfi_count; i++) {
		if (value->qfi[i].header.len)
			enc_len += encode_pfcp_qfi_ie_t(&(value->qfi[i]), buf + (enc_len/CHAR_SIZE));
	}

/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->framed_route_count; i++) {
		if (value->framed_route[i].header.len)
			enc_len += encode_pfcp_framed_route_ie_t(&(value->framed_route[i]), buf + (enc_len/CHAR_SIZE));
	}

	/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->frmd_ipv6_rte_count; i++) {
		if (value->frmd_ipv6_rte[i].header.len)
			enc_len += encode_pfcp_frmd_ipv6_rte_ie_t(&(value->frmd_ipv6_rte[i]), buf + (enc_len/CHAR_SIZE));
	}


	return enc_len;
}

/**
 * Encodes pfcp_create_bar_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_create_bar_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_create_bar_ie_t(pfcp_create_bar_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->dnlnk_data_notif_delay.header.len)
		enc_len += encode_pfcp_dnlnk_data_notif_delay_ie_t(&(value->dnlnk_data_notif_delay), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->suggstd_buf_pckts_cnt.header.len)
		enc_len += encode_pfcp_suggstd_buf_pckts_cnt_ie_t(&(value->suggstd_buf_pckts_cnt), buf + (enc_len/CHAR_SIZE));


	/* TODO: Revisit this for change in yang */
	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_sess_del_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_del_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_del_req_t(pfcp_sess_del_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_assn_upd_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_assn_upd_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_assn_upd_req_t(pfcp_assn_upd_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->up_func_feat.header.len)
		enc_len += encode_pfcp_up_func_feat_ie_t(&(value->up_func_feat), buf + enc_len);

	if (value->cp_func_feat.header.len)
		enc_len += encode_pfcp_cp_func_feat_ie_t(&(value->cp_func_feat), buf + enc_len);

	if (value->up_assn_rel_req.header.len)
		enc_len += encode_pfcp_up_assn_rel_req_ie_t(&(value->up_assn_rel_req), buf + enc_len);

	if (value->graceful_rel_period.header.len)
		enc_len += encode_pfcp_graceful_rel_period_ie_t(&(value->graceful_rel_period), buf + enc_len);

	for (uint8_t i = 0; i < value->user_plane_ip_rsrc_info_count; i++) {
		if (value->user_plane_ip_rsrc_info[i].header.len)
			enc_len += encode_pfcp_user_plane_ip_rsrc_info_ie_t(&(value->user_plane_ip_rsrc_info[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_sess_estab_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_sess_estab_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_estab_req_t(pfcp_sess_estab_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cp_fseid.header.len)
		enc_len += encode_pfcp_fseid_ie_t(&(value->cp_fseid), buf + enc_len);

	if (value->create_bar.header.len)
		enc_len += encode_pfcp_create_bar_ie_t(&(value->create_bar), buf + enc_len);

	if (value->pdn_type.header.len)
		enc_len += encode_pfcp_pdn_type_ie_t(&(value->pdn_type), buf + enc_len);

	if (value->sgw_c_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->sgw_c_fqcsid), buf + enc_len);

	if (value->mme_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->mme_fqcsid), buf + enc_len);

	if (value->pgw_c_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->pgw_c_fqcsid), buf + enc_len);

	if (value->epdg_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->epdg_fqcsid), buf + enc_len);

	if (value->twan_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->twan_fqcsid), buf + enc_len);

	if (value->user_plane_inact_timer.header.len)
		enc_len += encode_pfcp_user_plane_inact_timer_ie_t(&(value->user_plane_inact_timer), buf + enc_len);

	if (value->user_id.header.len)
		enc_len += encode_pfcp_user_id_ie_t(&(value->user_id), buf + enc_len);

	if (value->trc_info.header.len)
		enc_len += encode_pfcp_trc_info_ie_t(&(value->trc_info), buf + enc_len);

	for (uint8_t i = 0; i < value->create_pdr_count; i++) {
		if (value->create_pdr[i].header.len)
			enc_len += encode_pfcp_create_pdr_ie_t(&(value->create_pdr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_far_count; i++) {
		if (value->create_far[i].header.len)
			enc_len += encode_pfcp_create_far_ie_t(&(value->create_far[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_urr_count; i++) {
		if (value->create_urr[i].header.len)
			enc_len += encode_pfcp_create_urr_ie_t(&(value->create_urr[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_qer_count; i++) {
		if (value->create_qer[i].header.len)
			enc_len += encode_pfcp_create_qer_ie_t(&(value->create_qer[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->create_traffic_endpt_count; i++) {
		if (value->create_traffic_endpt[i].header.len)
			enc_len += encode_pfcp_create_traffic_endpt_ie_t(&(value->create_traffic_endpt[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_err_indctn_rpt_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_err_indctn_rpt_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_err_indctn_rpt_ie_t(pfcp_err_indctn_rpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	for (uint8_t i = 0; i < value->remote_fteid_count; i++) {
		if (value->remote_fteid[i].header.len)
			enc_len += encode_pfcp_fteid_ie_t(&(value->remote_fteid[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_eth_traffic_info_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_eth_traffic_info_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_eth_traffic_info_ie_t(pfcp_eth_traffic_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->mac_addrs_detctd.header.len)
		enc_len += encode_pfcp_mac_addrs_detctd_ie_t(&(value->mac_addrs_detctd), buf + enc_len);

	if (value->mac_addrs_rmvd.header.len)
		enc_len += encode_pfcp_mac_addrs_rmvd_ie_t(&(value->mac_addrs_rmvd), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_app_ids_pfds_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_app_ids_pfds_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_app_ids_pfds_ie_t(pfcp_app_ids_pfds_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->application_id.header.len)
		enc_len += encode_pfcp_application_id_ie_t(&(value->application_id), buf + (enc_len/CHAR_SIZE));

	for (uint8_t i = 0; i < value->pfd_context_count; i++) {
		if (value->pfd_context[i].header.len)
			enc_len += encode_pfcp_pfd_context_ie_t(&(value->pfd_context[i]), buf + (enc_len/CHAR_SIZE));
	}


	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_remove_qer_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_remove_qer_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_remove_qer_ie_t(pfcp_remove_qer_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->qer_id.header.len)
		enc_len += encode_pfcp_qer_id_ie_t(&(value->qer_id), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_create_qer_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_create_qer_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_create_qer_ie_t(pfcp_create_qer_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->qer_id.header.len)
		enc_len += encode_pfcp_qer_id_ie_t(&(value->qer_id), buf + (enc_len/CHAR_SIZE));

	if (value->qer_corr_id.header.len)
		enc_len += encode_pfcp_qer_corr_id_ie_t(&(value->qer_corr_id), buf + (enc_len/CHAR_SIZE));

	if (value->gate_status.header.len)
		enc_len += encode_pfcp_gate_status_ie_t(&(value->gate_status), buf + (enc_len/CHAR_SIZE));

	if (value->maximum_bitrate.header.len)
		enc_len += encode_pfcp_mbr_ie_t(&(value->maximum_bitrate), buf + (enc_len/CHAR_SIZE));

	if (value->guaranteed_bitrate.header.len)
		enc_len += encode_pfcp_gbr_ie_t(&(value->guaranteed_bitrate), buf + (enc_len/CHAR_SIZE));

	if (value->packet_rate.header.len)
		enc_len += encode_pfcp_packet_rate_ie_t(&(value->packet_rate), buf + (enc_len/CHAR_SIZE));

	if (value->dl_flow_lvl_marking.header.len)
		enc_len += encode_pfcp_dl_flow_lvl_marking_ie_t(&(value->dl_flow_lvl_marking), buf + (enc_len/CHAR_SIZE));

	if (value->qos_flow_ident.header.len)
		enc_len += encode_pfcp_qfi_ie_t(&(value->qos_flow_ident), buf + (enc_len/CHAR_SIZE));

	if (value->reflective_qos.header.len)
		enc_len += encode_pfcp_rqi_ie_t(&(value->reflective_qos), buf + (enc_len/CHAR_SIZE));

	if (value->paging_plcy_indctr.header.len)
		enc_len += encode_pfcp_paging_plcy_indctr_ie_t(&(value->paging_plcy_indctr), buf + (enc_len/CHAR_SIZE));

	if (value->avgng_wnd.header.len)
		enc_len += encode_pfcp_avgng_wnd_ie_t(&(value->avgng_wnd), buf + (enc_len/CHAR_SIZE));


	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_rmv_traffic_endpt_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_rmv_traffic_endpt_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_rmv_traffic_endpt_ie_t(pfcp_rmv_traffic_endpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	//TODO: Revisit this for change in yang
	if (value->traffic_endpt_id.header.len)
		enc_len += encode_pfcp_traffic_endpt_id_ie_t(&(value->traffic_endpt_id), buf + (enc_len/CHAR_SIZE));


	return enc_len;
}

/**
 * Encodes pfcp_update_urr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_update_urr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_update_urr_ie_t(pfcp_update_urr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->urr_id.header.len)
		enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id), buf + enc_len);

	if (value->meas_mthd.header.len)
		enc_len += encode_pfcp_meas_mthd_ie_t(&(value->meas_mthd), buf + enc_len);

	if (value->rptng_triggers.header.len)
		enc_len += encode_pfcp_rptng_triggers_ie_t(&(value->rptng_triggers), buf + enc_len);

	if (value->meas_period.header.len)
		enc_len += encode_pfcp_meas_period_ie_t(&(value->meas_period), buf + enc_len);

	if (value->vol_thresh.header.len)
		enc_len += encode_pfcp_vol_thresh_ie_t(&(value->vol_thresh), buf + enc_len);

	if (value->volume_quota.header.len)
		enc_len += encode_pfcp_volume_quota_ie_t(&(value->volume_quota), buf + enc_len);

	if (value->time_threshold.header.len)
		enc_len += encode_pfcp_time_threshold_ie_t(&(value->time_threshold), buf + enc_len);

	if (value->time_quota.header.len)
		enc_len += encode_pfcp_time_quota_ie_t(&(value->time_quota), buf + enc_len);

	if (value->event_threshold.header.len)
		enc_len += encode_pfcp_event_threshold_ie_t(&(value->event_threshold), buf + enc_len);

	if (value->event_quota.header.len)
		enc_len += encode_pfcp_event_quota_ie_t(&(value->event_quota), buf + enc_len);

	if (value->quota_hldng_time.header.len)
		enc_len += encode_pfcp_quota_hldng_time_ie_t(&(value->quota_hldng_time), buf + enc_len);

	if (value->drpd_dl_traffic_thresh.header.len)
		enc_len += encode_pfcp_drpd_dl_traffic_thresh_ie_t(&(value->drpd_dl_traffic_thresh), buf + enc_len);

	if (value->monitoring_time.header.len)
		enc_len += encode_pfcp_monitoring_time_ie_t(&(value->monitoring_time), buf + enc_len);

	if (value->sbsqnt_vol_thresh.header.len)
		enc_len += encode_pfcp_sbsqnt_vol_thresh_ie_t(&(value->sbsqnt_vol_thresh), buf + enc_len);

	if (value->sbsqnt_time_thresh.header.len)
		enc_len += encode_pfcp_sbsqnt_time_thresh_ie_t(&(value->sbsqnt_time_thresh), buf + enc_len);

	if (value->sbsqnt_vol_quota.header.len)
		enc_len += encode_pfcp_sbsqnt_vol_quota_ie_t(&(value->sbsqnt_vol_quota), buf + enc_len);

	if (value->sbsqnt_time_quota.header.len)
		enc_len += encode_pfcp_sbsqnt_time_quota_ie_t(&(value->sbsqnt_time_quota), buf + enc_len);

	if (value->sbsqnt_evnt_thresh.header.len)
		enc_len += encode_pfcp_sbsqnt_evnt_thresh_ie_t(&(value->sbsqnt_evnt_thresh), buf + enc_len);

	if (value->sbsqnt_evnt_quota.header.len)
		enc_len += encode_pfcp_sbsqnt_evnt_quota_ie_t(&(value->sbsqnt_evnt_quota), buf + enc_len);

	if (value->inact_det_time.header.len)
		enc_len += encode_pfcp_inact_det_time_ie_t(&(value->inact_det_time), buf + enc_len);

	if (value->meas_info.header.len)
		enc_len += encode_pfcp_meas_info_ie_t(&(value->meas_info), buf + enc_len);

	if (value->time_quota_mech.header.len)
		enc_len += encode_pfcp_time_quota_mech_ie_t(&(value->time_quota_mech), buf + enc_len);

	if (value->far_id_for_quota_act.header.len)
		enc_len += encode_pfcp_far_id_ie_t(&(value->far_id_for_quota_act), buf + enc_len);

	if (value->eth_inact_timer.header.len)
		enc_len += encode_pfcp_eth_inact_timer_ie_t(&(value->eth_inact_timer), buf + enc_len);

	if (value->add_mntrng_time.header.len)
		enc_len += encode_pfcp_add_mntrng_time_ie_t(&(value->add_mntrng_time), buf + enc_len);

	for (uint8_t i = 0; i < value->linked_urr_id_count; i++) {
		if (value->linked_urr_id[i].header.len)
			enc_len += encode_pfcp_linked_urr_id_ie_t(&(value->linked_urr_id[i]), buf + enc_len);
	}

	for (uint8_t i = 0; i < value->aggregated_urrs_count; i++) {
		if (value->aggregated_urrs[i].header.len)
			enc_len += encode_pfcp_aggregated_urrs_ie_t(&(value->aggregated_urrs[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_update_far_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_update_far_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_update_far_ie_t(pfcp_update_far_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->far_id.header.len)
		enc_len += encode_pfcp_far_id_ie_t(&(value->far_id), buf + (enc_len/CHAR_SIZE));

	if (value->apply_action.header.len)
		enc_len += encode_pfcp_apply_action_ie_t(&(value->apply_action), buf + (enc_len/CHAR_SIZE));

	if (value->upd_frwdng_parms.header.len)
		enc_len += encode_pfcp_upd_frwdng_parms_ie_t(&(value->upd_frwdng_parms), buf + (enc_len/CHAR_SIZE));

	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + enc_len);

	for (uint8_t i = 0; i < value->upd_dupng_parms_count; i++) {
		if (value->upd_dupng_parms[i].header.len)
			enc_len += encode_pfcp_upd_dupng_parms_ie_t(&(value->upd_dupng_parms[i]), buf + enc_len);
	}


	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_user_plane_path_fail_rpt_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_user_plane_path_fail_rpt_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_user_plane_path_fail_rpt_ie_t(pfcp_user_plane_path_fail_rpt_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	for (uint8_t i = 0; i < value->rmt_gtpu_peer_count; i++) {
		if (value->rmt_gtpu_peer[i].header.len)
			enc_len += encode_pfcp_rmt_gtpu_peer_ie_t(&(value->rmt_gtpu_peer[i]), buf + enc_len);
	}


	return enc_len;
}

/**
 * Encodes pfcp_remove_pdr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_remove_pdr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_remove_pdr_ie_t(pfcp_remove_pdr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->pdr_id.header.len)
		enc_len += encode_pfcp_pdr_id_ie_t(&(value->pdr_id), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_update_qer_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_update_qer_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_update_qer_ie_t(pfcp_update_qer_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->qer_id.header.len)
		enc_len += encode_pfcp_qer_id_ie_t(&(value->qer_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->qer_corr_id.header.len)
		enc_len += encode_pfcp_qer_corr_id_ie_t(&(value->qer_corr_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->gate_status.header.len)
		enc_len += encode_pfcp_gate_status_ie_t(&(value->gate_status), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->maximum_bitrate.header.len)
		enc_len += encode_pfcp_mbr_ie_t(&(value->maximum_bitrate), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->guaranteed_bitrate.header.len)
		enc_len += encode_pfcp_gbr_ie_t(&(value->guaranteed_bitrate), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->packet_rate.header.len)
		enc_len += encode_pfcp_packet_rate_ie_t(&(value->packet_rate), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->dl_flow_lvl_marking.header.len)
		enc_len += encode_pfcp_dl_flow_lvl_marking_ie_t(&(value->dl_flow_lvl_marking), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->qos_flow_ident.header.len)
		enc_len += encode_pfcp_qfi_ie_t(&(value->qos_flow_ident), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->reflective_qos.header.len)
		enc_len += encode_pfcp_rqi_ie_t(&(value->reflective_qos), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->paging_plcy_indctr.header.len)
		enc_len += encode_pfcp_paging_plcy_indctr_ie_t(&(value->paging_plcy_indctr), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->avgng_wnd.header.len)
		enc_len += encode_pfcp_avgng_wnd_ie_t(&(value->avgng_wnd), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_add_mntrng_time_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_add_mntrng_time_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_add_mntrng_time_ie_t(pfcp_add_mntrng_time_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->monitoring_time.header.len)
		enc_len += encode_pfcp_monitoring_time_ie_t(&(value->monitoring_time), buf + enc_len);

	if (value->sbsqnt_vol_thresh.header.len)
		enc_len += encode_pfcp_sbsqnt_vol_thresh_ie_t(&(value->sbsqnt_vol_thresh), buf + enc_len);

	if (value->sbsqnt_time_thresh.header.len)
		enc_len += encode_pfcp_sbsqnt_time_thresh_ie_t(&(value->sbsqnt_time_thresh), buf + enc_len);

	if (value->sbsqnt_vol_quota.header.len)
		enc_len += encode_pfcp_sbsqnt_vol_quota_ie_t(&(value->sbsqnt_vol_quota), buf + enc_len);

	if (value->sbsqnt_time_quota.header.len)
		enc_len += encode_pfcp_sbsqnt_time_quota_ie_t(&(value->sbsqnt_time_quota), buf + enc_len);

	if (value->sbsqnt_evnt_thresh.header.len)
		enc_len += encode_pfcp_event_threshold_ie_t(&(value->sbsqnt_evnt_thresh), buf + enc_len);

	if (value->sbsqnt_evnt_quota.header.len)
		enc_len += encode_pfcp_event_quota_ie_t(&(value->sbsqnt_evnt_quota), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_sess_estab_rsp_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_sess_estab_rsp_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_sess_estab_rsp_t(pfcp_sess_estab_rsp_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);

	if (value->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(value->cause), buf + enc_len);

	if (value->offending_ie.header.len)
		enc_len += encode_pfcp_offending_ie_ie_t(&(value->offending_ie), buf + enc_len);

	if (value->up_fseid.header.len)
		enc_len += encode_pfcp_fseid_ie_t(&(value->up_fseid), buf + enc_len);

	if (value->created_pdr.header.len)
		enc_len += encode_pfcp_created_pdr_ie_t(&(value->created_pdr), buf + enc_len);

	if (value->load_ctl_info.header.len)
		enc_len += encode_pfcp_load_ctl_info_ie_t(&(value->load_ctl_info), buf + enc_len);

	if (value->ovrld_ctl_info.header.len)
		enc_len += encode_pfcp_ovrld_ctl_info_ie_t(&(value->ovrld_ctl_info), buf + enc_len);

	if (value->sgw_u_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->sgw_u_fqcsid), buf + enc_len);

	if (value->pgw_u_fqcsid.header.len)
		enc_len += encode_pfcp_fqcsid_ie_t(&(value->pgw_u_fqcsid), buf + enc_len);

	if (value->failed_rule_id.header.len)
		enc_len += encode_pfcp_failed_rule_id_ie_t(&(value->failed_rule_id), buf + enc_len);

	if (value->created_traffic_endpt.header.len)
		enc_len += encode_pfcp_created_traffic_endpt_ie_t(&(value->created_traffic_endpt), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_remove_bar_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_remove_bar_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_remove_bar_ie_t(pfcp_remove_bar_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	//TODO: Revisit this for change in yang
	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + (enc_len/CHAR_SIZE));


	//TODO: Revisit this for change in yang
	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_assn_rel_req_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_assn_rel_req_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_assn_rel_req_t(pfcp_assn_rel_req_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&value->header, buf +enc_len);

	if (value->node_id.header.len)
		enc_len += encode_pfcp_node_id_ie_t(&(value->node_id), buf + enc_len);


	return enc_len;
}

/**
	* Encodes pfcp_create_pdr_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_create_pdr_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_create_pdr_ie_t(pfcp_create_pdr_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->pdr_id.header.len)
		enc_len += encode_pfcp_pdr_id_ie_t(&(value->pdr_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->precedence.header.len)
		enc_len += encode_pfcp_precedence_ie_t(&(value->precedence), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->pdi.header.len)
		enc_len += encode_pfcp_pdi_ie_t(&(value->pdi), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->outer_hdr_removal.header.len)
		enc_len += encode_pfcp_outer_hdr_removal_ie_t(&(value->outer_hdr_removal), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->far_id.header.len)
		enc_len += encode_pfcp_far_id_ie_t(&(value->far_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->urr_id_count; i++) {
		if (value->urr_id[i].header.len)
			enc_len += encode_pfcp_urr_id_ie_t(&(value->urr_id[i]), buf + (enc_len/CHAR_SIZE));
	}

	/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->qer_id_count; i++) {
		if (value->qer_id[i].header.len)
			enc_len += encode_pfcp_qer_id_ie_t(&(value->qer_id[i]), buf + (enc_len/CHAR_SIZE));
	}

	/* TODO: Revisit this for change in yang */
	for (uint8_t i = 0; i < value->actvt_predef_rules_count; i++) {
		if (value->actvt_predef_rules[i].header.len)
			enc_len += encode_pfcp_actvt_predef_rules_ie_t(&(value->actvt_predef_rules[i]), buf + (enc_len/CHAR_SIZE));
	}

	/* TODO: Revisit this for change in yang */
	return enc_len/CHAR_SIZE;
}

/**
 * Encodes pfcp_aggregated_urrs_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_aggregated_urrs_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_aggregated_urrs_ie_t(pfcp_aggregated_urrs_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	if (value->agg_urr_id.header.len)
		enc_len += encode_pfcp_agg_urr_id_ie_t(&(value->agg_urr_id), buf + enc_len);

	if (value->multiplier.header.len)
		enc_len += encode_pfcp_multiplier_ie_t(&(value->multiplier), buf + enc_len);


	return enc_len;
}

/**
 * Encodes pfcp_upd_bar_sess_mod_req_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_upd_bar_sess_mod_req_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_upd_bar_sess_mod_req_ie_t(pfcp_upd_bar_sess_mod_req_ie_t *value,
		uint8_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_ie_header_t(&value->header, buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->bar_id.header.len)
		enc_len += encode_pfcp_bar_id_ie_t(&(value->bar_id), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->dnlnk_data_notif_delay.header.len)
		enc_len += encode_pfcp_dnlnk_data_notif_delay_ie_t(&(value->dnlnk_data_notif_delay), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	if (value->suggstd_buf_pckts_cnt.header.len)
		enc_len += encode_pfcp_suggstd_buf_pckts_cnt_ie_t(&(value->suggstd_buf_pckts_cnt), buf + (enc_len/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	return enc_len/CHAR_SIZE;
}

