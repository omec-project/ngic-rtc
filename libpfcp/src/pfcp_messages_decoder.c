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

#include "../include/pfcp_ies_decoder.h"
#include "../include/pfcp_messages_decoder.h"

/**
* Decodes pfcp_sess_rpt_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_rpt_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_rpt_req_t(uint8_t *buf,
      pfcp_sess_rpt_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->usage_report_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_REPORT_TYPE) {
            count += decode_pfcp_report_type_ie_t(buf + count, &value->report_type);
      }  else if (ie_type == IE_DNLNK_DATA_RPT) {
            count += decode_pfcp_dnlnk_data_rpt_ie_t(buf + count, &value->dnlnk_data_rpt);
      }  else if (ie_type == IE_ERR_INDCTN_RPT) {
            count += decode_pfcp_err_indctn_rpt_ie_t(buf + count, &value->err_indctn_rpt);
      }  else if (ie_type == IE_LOAD_CTL_INFO) {
            count += decode_pfcp_load_ctl_info_ie_t(buf + count, &value->load_ctl_info);
      }  else if (ie_type == IE_OVRLD_CTL_INFO) {
            count += decode_pfcp_ovrld_ctl_info_ie_t(buf + count, &value->ovrld_ctl_info);
      }  else if (ie_type == PFCP_IE_ADD_USAGE_RPTS_INFO) {
            count += decode_pfcp_add_usage_rpts_info_ie_t(buf + count, &value->add_usage_rpts_info);
      }  else if (ie_type == IE_USAGE_RPT_SESS_RPT_REQ) {
            count += decode_pfcp_usage_rpt_sess_rpt_req_ie_t(buf + count, &value->usage_report[value->usage_report_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_pfd_mgmt_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_pfd_mgmt_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_mgmt_req_t(uint8_t *buf,
      pfcp_pfd_mgmt_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->app_ids_pfds_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == IE_APP_IDS_PFDS) {
            count += decode_pfcp_app_ids_pfds_ie_t(buf + count, &value->app_ids_pfds[value->app_ids_pfds_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_create_traffic_endpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_traffic_endpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_traffic_endpt_ie_t(uint8_t *buf,
		pfcp_create_traffic_endpt_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	value->framed_route_count = 0;
	value->frmd_ipv6_rte_count = 0;


	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
			count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->traffic_endpt_id);
		}  else if (ie_type == PFCP_IE_FTEID) {
			count += decode_pfcp_fteid_ie_t(buf + count, &value->local_fteid);
		}  else if (ie_type == PFCP_IE_NTWK_INST) {
			count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
		}  else if (ie_type == PFCP_IE_UE_IP_ADDRESS) {
			count += decode_pfcp_ue_ip_address_ie_t(buf + count, &value->ue_ip_address);
		}  else if (ie_type == PFCP_IE_ETH_PDU_SESS_INFO) {
			count += decode_pfcp_eth_pdu_sess_info_ie_t(buf + count, &value->eth_pdu_sess_info);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTING) {
			count += decode_pfcp_framed_routing_ie_t(buf + count, &value->framed_routing);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTE) {
			count += decode_pfcp_framed_route_ie_t(buf + count, &value->framed_route[value->framed_route_count++]);
		}  else if (ie_type == PFCP_IE_FRMD_IPV6_RTE) {
			count += decode_pfcp_frmd_ipv6_rte_ie_t(buf + count, &value->frmd_ipv6_rte[value->frmd_ipv6_rte_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_pfd_context_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_pfd_context_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_context_ie_t(uint8_t *buf,
      pfcp_pfd_context_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
	  count /= CHAR_SIZE;
	  buf_len = value->header.len;
      value->pfd_contents_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_PFD_CONTENTS) {
            count += decode_pfcp_pfd_contents_ie_t(buf + count, &value->pfd_contents[value->pfd_contents_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_create_urr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_urr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_urr_ie_t(uint8_t *buf,
      pfcp_create_urr_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->linked_urr_id_count = 0;
      value->aggregated_urrs_count = 0;
      value->add_mntrng_time_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_MEAS_MTHD) {
            count += decode_pfcp_meas_mthd_ie_t(buf + count, &value->meas_mthd);
      }  else if (ie_type == PFCP_IE_RPTNG_TRIGGERS) {
            count += decode_pfcp_rptng_triggers_ie_t(buf + count, &value->rptng_triggers);
      }  else if (ie_type == PFCP_IE_MEAS_PERIOD) {
            count += decode_pfcp_meas_period_ie_t(buf + count, &value->meas_period);
      }  else if (ie_type == PFCP_IE_VOL_THRESH) {
            count += decode_pfcp_vol_thresh_ie_t(buf + count, &value->vol_thresh);
      }  else if (ie_type == PFCP_IE_VOLUME_QUOTA) {
            count += decode_pfcp_volume_quota_ie_t(buf + count, &value->volume_quota);
      }  else if (ie_type == PFCP_IE_EVENT_THRESHOLD) {
            count += decode_pfcp_event_threshold_ie_t(buf + count, &value->event_threshold);
      }  else if (ie_type == PFCP_IE_EVENT_QUOTA) {
            count += decode_pfcp_event_quota_ie_t(buf + count, &value->event_quota);
      }  else if (ie_type == PFCP_IE_TIME_THRESHOLD) {
            count += decode_pfcp_time_threshold_ie_t(buf + count, &value->time_threshold);
      }  else if (ie_type == PFCP_IE_TIME_QUOTA) {
            count += decode_pfcp_time_quota_ie_t(buf + count, &value->time_quota);
      }  else if (ie_type == PFCP_IE_QUOTA_HLDNG_TIME) {
            count += decode_pfcp_quota_hldng_time_ie_t(buf + count, &value->quota_hldng_time);
      }  else if (ie_type == PFCP_IE_DRPD_DL_TRAFFIC_THRESH) {
            count += decode_pfcp_drpd_dl_traffic_thresh_ie_t(buf + count, &value->drpd_dl_traffic_thresh);
      }  else if (ie_type == PFCP_IE_MONITORING_TIME) {
            count += decode_pfcp_monitoring_time_ie_t(buf + count, &value->monitoring_time);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_THRESH) {
            count += decode_pfcp_sbsqnt_vol_thresh_ie_t(buf + count, &value->sbsqnt_vol_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_THRESH) {
            count += decode_pfcp_sbsqnt_time_thresh_ie_t(buf + count, &value->sbsqnt_time_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_QUOTA) {
            count += decode_pfcp_sbsqnt_vol_quota_ie_t(buf + count, &value->sbsqnt_vol_quota);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_QUOTA) {
            count += decode_pfcp_sbsqnt_time_quota_ie_t(buf + count, &value->sbsqnt_time_quota);
      }  else if (ie_type == PFCP_IE_SBSQNT_EVNT_THRESH) {
            count += decode_pfcp_sbsqnt_evnt_thresh_ie_t(buf + count, &value->sbsqnt_evnt_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_EVNT_QUOTA) {
            count += decode_pfcp_sbsqnt_evnt_quota_ie_t(buf + count, &value->sbsqnt_evnt_quota);
      }  else if (ie_type == PFCP_IE_INACT_DET_TIME) {
            count += decode_pfcp_inact_det_time_ie_t(buf + count, &value->inact_det_time);
      }  else if (ie_type == PFCP_IE_MEAS_INFO) {
            count += decode_pfcp_meas_info_ie_t(buf + count, &value->meas_info);
      }  else if (ie_type == PFCP_IE_TIME_QUOTA_MECH) {
            count += decode_pfcp_time_quota_mech_ie_t(buf + count, &value->time_quota_mech);
      }  else if (ie_type == PFCP_IE_FAR_ID) {
            count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id_for_quota_act);
      }  else if (ie_type == PFCP_IE_ETH_INACT_TIMER) {
            count += decode_pfcp_eth_inact_timer_ie_t(buf + count, &value->eth_inact_timer);
      }  else if (ie_type == PFCP_IE_LINKED_URR_ID) {
            count += decode_pfcp_linked_urr_id_ie_t(buf + count, &value->linked_urr_id[value->linked_urr_id_count++]);
      }  else if (ie_type == IE_AGGREGATED_URRS) {
            count += decode_pfcp_aggregated_urrs_ie_t(buf + count, &value->aggregated_urrs[value->aggregated_urrs_count++]);
      }  else if (ie_type == IE_ADD_MNTRNG_TIME) {
            count += decode_pfcp_add_mntrng_time_ie_t(buf + count, &value->add_mntrng_time[value->add_mntrng_time_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_eth_pckt_fltr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_eth_pckt_fltr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_pckt_fltr_ie_t(uint8_t *buf,
      pfcp_eth_pckt_fltr_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->sdf_filter_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_ETH_FLTR_ID) {
            count += decode_pfcp_eth_fltr_id_ie_t(buf + count, &value->eth_fltr_id);
      }  else if (ie_type == PFCP_IE_ETH_FLTR_PROPS) {
            count += decode_pfcp_eth_fltr_props_ie_t(buf + count, &value->eth_fltr_props);
      }  else if (ie_type == PFCP_IE_MAC_ADDRESS) {
            count += decode_pfcp_mac_address_ie_t(buf + count, &value->mac_address);
      }  else if (ie_type == PFCP_IE_ETHERTYPE) {
            count += decode_pfcp_ethertype_ie_t(buf + count, &value->ethertype);
      }  else if (ie_type == PFCP_IE_CTAG) {
            count += decode_pfcp_ctag_ie_t(buf + count, &value->ctag);
      }  else if (ie_type == PFCP_IE_STAG) {
            count += decode_pfcp_stag_ie_t(buf + count, &value->stag);
      }  else if (ie_type == PFCP_IE_SDF_FILTER) {
            count += decode_pfcp_sdf_filter_ie_t(buf + count, &value->sdf_filter[value->sdf_filter_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_remove_far_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_remove_far_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_far_ie_t(uint8_t *buf,
		pfcp_remove_far_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */

	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;
	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_FAR_ID) {
			count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_hrtbeat_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_hrtbeat_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hrtbeat_req_t(uint8_t *buf,
      pfcp_hrtbeat_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_RCVRY_TIME_STMP) {
            count += decode_pfcp_rcvry_time_stmp_ie_t(buf + count, &value->rcvry_time_stmp);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_create_far_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_far_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_far_ie_t(uint8_t *buf,
		pfcp_create_far_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	value->dupng_parms_count = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_FAR_ID) {
			count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id);
		}  else if (ie_type == PFCP_IE_APPLY_ACTION) {
			count += decode_pfcp_apply_action_ie_t(buf + count, &value->apply_action);
		}  else if (ie_type == IE_FRWDNG_PARMS) {
			count += decode_pfcp_frwdng_parms_ie_t(buf + count, &value->frwdng_parms);
		}  else if (ie_type == PFCP_IE_BAR_ID) {
			count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
		}  else if (ie_type == IE_DUPNG_PARMS) {
			count += decode_pfcp_dupng_parms_ie_t(buf + count, &value->dupng_parms[value->dupng_parms_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_assn_setup_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_setup_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_setup_rsp_t(uint8_t *buf,
		pfcp_assn_setup_rsp_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	count = decode_pfcp_header_t(buf + count, &value->header);

	if (value->header.s)
		buf_len = value->header.message_len - 12;
	else
		buf_len = value->header.message_len - 4;

	buf = buf + count;
	count = 0;

	value->user_plane_ip_rsrc_info_count = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_NODE_ID) {
			count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
		}  else if (ie_type == PFCP_IE_CAUSE) {
			count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
		}  else if (ie_type == PFCP_IE_RCVRY_TIME_STMP) {
			count += decode_pfcp_rcvry_time_stmp_ie_t(buf + count, &value->rcvry_time_stmp);
		}  else if (ie_type == PFCP_IE_UP_FUNC_FEAT) {
			count += decode_pfcp_up_func_feat_ie_t(buf + count, &value->up_func_feat);
		}  else if (ie_type == PFCP_IE_CP_FUNC_FEAT) {
			count += decode_pfcp_cp_func_feat_ie_t(buf + count, &value->cp_func_feat);
		}  else if (ie_type == PFCP_IE_USER_PLANE_IP_RSRC_INFO) {
			count += decode_pfcp_user_plane_ip_rsrc_info_ie_t(buf + count, &value->user_plane_ip_rsrc_info[value->user_plane_ip_rsrc_info_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_dnlnk_data_rpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_dnlnk_data_rpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_rpt_ie_t(uint8_t *buf,
      pfcp_dnlnk_data_rpt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
      count /= CHAR_SIZE;

      buf_len = value->header.len;

      value->pdr_id_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_PDR_ID) {
            count += decode_pfcp_pdr_id_ie_t(buf + count, &value->pdr_id[value->pdr_id_count++]);
      }  else if (ie_type == PFCP_IE_DNLNK_DATA_SVC_INFO) {
            count += decode_pfcp_dnlnk_data_svc_info_ie_t(buf + count, &value->dnlnk_data_svc_info);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_query_urr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_query_urr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_query_urr_ie_t(uint8_t *buf,
		pfcp_query_urr_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_URR_ID) {
			count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_assn_setup_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_setup_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_setup_req_t(uint8_t *buf,
      pfcp_assn_setup_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->user_plane_ip_rsrc_info_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_RCVRY_TIME_STMP) {
            count += decode_pfcp_rcvry_time_stmp_ie_t(buf + count, &value->rcvry_time_stmp);
      }  else if (ie_type == PFCP_IE_UP_FUNC_FEAT) {
            count += decode_pfcp_up_func_feat_ie_t(buf + count, &value->up_func_feat);
      }  else if (ie_type == PFCP_IE_CP_FUNC_FEAT) {
            count += decode_pfcp_cp_func_feat_ie_t(buf + count, &value->cp_func_feat);
      }  else if (ie_type == PFCP_IE_USER_PLANE_IP_RSRC_INFO) {
            count += decode_pfcp_user_plane_ip_rsrc_info_ie_t(buf + count, &value->user_plane_ip_rsrc_info[value->user_plane_ip_rsrc_info_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_upd_bar_sess_rpt_rsp_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_upd_bar_sess_rpt_rsp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_bar_sess_rpt_rsp_ie_t(uint8_t *buf,
      pfcp_upd_bar_sess_rpt_rsp_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_BAR_ID) {
            count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
      }  else if (ie_type == PFCP_IE_DNLNK_DATA_NOTIF_DELAY) {
            count += decode_pfcp_dnlnk_data_notif_delay_ie_t(buf + count, &value->dnlnk_data_notif_delay);
      }  else if (ie_type == PFCP_IE_DL_BUF_DUR) {
            count += decode_pfcp_dl_buf_dur_ie_t(buf + count, &value->dl_buf_dur);
      }  else if (ie_type == PFCP_IE_DL_BUF_SUGGSTD_PCKT_CNT) {
            count += decode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(buf + count, &value->dl_buf_suggstd_pckt_cnt);
      }  else if (ie_type == PFCP_IE_SUGGSTD_BUF_PCKTS_CNT) {
            count += decode_pfcp_suggstd_buf_pckts_cnt_ie_t(buf + count, &value->suggstd_buf_pckts_cnt);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_mod_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_mod_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_mod_req_t(uint8_t *buf,
		pfcp_sess_mod_req_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	count = decode_pfcp_header_t(buf + count, &value->header);

	if (value->header.s)
		buf_len = value->header.message_len - 12;
	else
		buf_len = value->header.message_len - 4;

	buf = buf + count;
	count = 0;

	value->remove_pdr_count = 0;
	value->remove_far_count = 0;
	value->remove_urr_count = 0;
	value->remove_qer_count = 0;
	value->create_pdr_count = 0;
	value->create_far_count = 0;
	value->create_urr_count = 0;
	value->create_qer_count = 0;
	value->update_pdr_count = 0;
	value->update_far_count = 0;
	value->update_urr_count = 0;
	value->update_qer_count = 0;
	value->query_urr_count = 0;
	value->pfcpsmreq_flags.qaurr = 0;
	value->pfcpsmreq_flags.sndem = 0;
	value->pfcpsmreq_flags.drobu = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_FSEID) {
			count += decode_pfcp_fseid_ie_t(buf + count, &value->cp_fseid);
		}  else if (ie_type == IE_REMOVE_BAR) {
			count += decode_pfcp_remove_bar_ie_t(buf + count, &value->remove_bar);
		}  else if (ie_type == IE_RMV_TRAFFIC_ENDPT) {
			count += decode_pfcp_rmv_traffic_endpt_ie_t(buf + count, &value->rmv_traffic_endpt);
		}  else if (ie_type == IE_CREATE_BAR) {
			count += decode_pfcp_create_bar_ie_t(buf + count, &value->create_bar);
		}  else if (ie_type == IE_CREATE_TRAFFIC_ENDPT) {
			count += decode_pfcp_create_traffic_endpt_ie_t(buf + count, &value->create_traffic_endpt);
		}  else if (ie_type == IE_UPD_BAR_SESS_MOD_REQ) {
			count += decode_pfcp_upd_bar_sess_mod_req_ie_t(buf + count, &value->update_bar);
		}  else if (ie_type == IE_UPD_TRAFFIC_ENDPT) {
			count += decode_pfcp_upd_traffic_endpt_ie_t(buf + count, &value->upd_traffic_endpt);
		}  else if (ie_type == PFCP_IE_PFCPSMREQ_FLAGS) {
			count += decode_pfcp_pfcpsmreq_flags_ie_t(buf + count, &value->pfcpsmreq_flags);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->pgw_c_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->sgw_c_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->mme_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->epdg_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->twan_fqcsid);
		}  else if (ie_type == PFCP_IE_USER_PLANE_INACT_TIMER) {
			count += decode_pfcp_user_plane_inact_timer_ie_t(buf + count, &value->user_plane_inact_timer);
		}  else if (ie_type == PFCP_IE_QUERY_URR_REF) {
			count += decode_pfcp_query_urr_ref_ie_t(buf + count, &value->query_urr_ref);
		}  else if (ie_type == PFCP_IE_TRC_INFO) {
			count += decode_pfcp_trc_info_ie_t(buf + count, &value->trc_info);
		}  else if (ie_type == IE_REMOVE_PDR) {
			count += decode_pfcp_remove_pdr_ie_t(buf + count, &value->remove_pdr[value->remove_pdr_count++]);
		}  else if (ie_type == IE_REMOVE_FAR) {
			count += decode_pfcp_remove_far_ie_t(buf + count, &value->remove_far[value->remove_far_count++]);
		}  else if (ie_type == IE_REMOVE_URR) {
			count += decode_pfcp_remove_urr_ie_t(buf + count, &value->remove_urr[value->remove_urr_count++]);
		}  else if (ie_type == IE_REMOVE_QER) {
			count += decode_pfcp_remove_qer_ie_t(buf + count, &value->remove_qer[value->remove_qer_count++]);
		}  else if (ie_type == IE_CREATE_PDR) {
			count += decode_pfcp_create_pdr_ie_t(buf + count, &value->create_pdr[value->create_pdr_count++]);
		}  else if (ie_type == IE_CREATE_FAR) {
			count += decode_pfcp_create_far_ie_t(buf + count, &value->create_far[value->create_far_count++]);
		}  else if (ie_type == IE_CREATE_URR) {
			count += decode_pfcp_create_urr_ie_t(buf + count, &value->create_urr[value->create_urr_count++]);
		}  else if (ie_type == IE_CREATE_QER) {
			count += decode_pfcp_create_qer_ie_t(buf + count, &value->create_qer[value->create_qer_count++]);
		}  else if (ie_type == IE_UPDATE_PDR) {
			count += decode_pfcp_update_pdr_ie_t(buf + count, &value->update_pdr[value->update_pdr_count++]);
		}  else if (ie_type == IE_UPDATE_FAR) {
			count += decode_pfcp_update_far_ie_t(buf + count, &value->update_far[value->update_far_count++]);
		}  else if (ie_type == IE_UPDATE_URR) {
			count += decode_pfcp_update_urr_ie_t(buf + count, &value->update_urr[value->update_urr_count++]);
		}  else if (ie_type == IE_UPDATE_QER) {
			count += decode_pfcp_update_qer_ie_t(buf + count, &value->update_qer[value->update_qer_count++]);
		}  else if (ie_type == IE_QUERY_URR) {
			count += decode_pfcp_query_urr_ie_t(buf + count, &value->query_urr[value->query_urr_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_usage_rpt_sess_mod_rsp_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_usage_rpt_sess_mod_rsp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_mod_rsp_ie_t(uint8_t *buf,
      pfcp_usage_rpt_sess_mod_rsp_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_URSEQN) {
            count += decode_pfcp_urseqn_ie_t(buf + count, &value->urseqn);
      }  else if (ie_type == PFCP_IE_USAGE_RPT_TRIG) {
            count += decode_pfcp_usage_rpt_trig_ie_t(buf + count, &value->usage_rpt_trig);
      }  else if (ie_type == PFCP_IE_START_TIME) {
            count += decode_pfcp_start_time_ie_t(buf + count, &value->start_time);
      }  else if (ie_type == PFCP_IE_END_TIME) {
            count += decode_pfcp_end_time_ie_t(buf + count, &value->end_time);
      }  else if (ie_type == PFCP_IE_VOL_MEAS) {
            count += decode_pfcp_vol_meas_ie_t(buf + count, &value->vol_meas);
      }  else if (ie_type == PFCP_IE_DUR_MEAS) {
            count += decode_pfcp_dur_meas_ie_t(buf + count, &value->dur_meas);
      }  else if (ie_type == PFCP_IE_TIME_OF_FRST_PCKT) {
            count += decode_pfcp_time_of_frst_pckt_ie_t(buf + count, &value->time_of_frst_pckt);
      }  else if (ie_type == PFCP_IE_TIME_OF_LST_PCKT) {
            count += decode_pfcp_time_of_lst_pckt_ie_t(buf + count, &value->time_of_lst_pckt);
      }  else if (ie_type == PFCP_IE_USAGE_INFO) {
            count += decode_pfcp_usage_info_ie_t(buf + count, &value->usage_info);
      }  else if (ie_type == PFCP_IE_QUERY_URR_REF) {
            count += decode_pfcp_query_urr_ref_ie_t(buf + count, &value->query_urr_ref);
      }  else if (ie_type == IE_ETH_TRAFFIC_INFO) {
            count += decode_pfcp_eth_traffic_info_ie_t(buf + count, &value->eth_traffic_info);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_remove_urr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_remove_urr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_urr_ie_t(uint8_t *buf,
		pfcp_remove_urr_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;
	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_URR_ID) {
			count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_sess_rpt_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_rpt_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_rpt_rsp_t(uint8_t *buf,
      pfcp_sess_rpt_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else if (ie_type == IE_UPD_BAR_SESS_RPT_RSP) {
            count += decode_pfcp_upd_bar_sess_rpt_rsp_ie_t(buf + count, &value->update_bar);
      }  else if (ie_type == PFCP_IE_PFCPSRRSP_FLAGS) {
            count += decode_pfcp_pfcpsrrsp_flags_ie_t(buf + count, &value->sxsrrsp_flags);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_usage_rpt_sess_del_rsp_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_usage_rpt_sess_del_rsp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_del_rsp_ie_t(uint8_t *buf,
      pfcp_usage_rpt_sess_del_rsp_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_URSEQN) {
            count += decode_pfcp_urseqn_ie_t(buf + count, &value->urseqn);
      }  else if (ie_type == PFCP_IE_USAGE_RPT_TRIG) {
            count += decode_pfcp_usage_rpt_trig_ie_t(buf + count, &value->usage_rpt_trig);
      }  else if (ie_type == PFCP_IE_START_TIME) {
            count += decode_pfcp_start_time_ie_t(buf + count, &value->start_time);
      }  else if (ie_type == PFCP_IE_END_TIME) {
            count += decode_pfcp_end_time_ie_t(buf + count, &value->end_time);
      }  else if (ie_type == PFCP_IE_VOL_MEAS) {
            count += decode_pfcp_vol_meas_ie_t(buf + count, &value->vol_meas);
      }  else if (ie_type == PFCP_IE_DUR_MEAS) {
            count += decode_pfcp_dur_meas_ie_t(buf + count, &value->dur_meas);
      }  else if (ie_type == PFCP_IE_TIME_OF_FRST_PCKT) {
            count += decode_pfcp_time_of_frst_pckt_ie_t(buf + count, &value->time_of_frst_pckt);
      }  else if (ie_type == PFCP_IE_TIME_OF_LST_PCKT) {
            count += decode_pfcp_time_of_lst_pckt_ie_t(buf + count, &value->time_of_lst_pckt);
      }  else if (ie_type == PFCP_IE_USAGE_INFO) {
            count += decode_pfcp_usage_info_ie_t(buf + count, &value->usage_info);
      }  else if (ie_type == IE_ETH_TRAFFIC_INFO) {
            count += decode_pfcp_eth_traffic_info_ie_t(buf + count, &value->eth_traffic_info);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_assn_upd_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_upd_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_upd_rsp_t(uint8_t *buf,
      pfcp_assn_upd_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_UP_FUNC_FEAT) {
            count += decode_pfcp_up_func_feat_ie_t(buf + count, &value->up_func_feat);
      }  else if (ie_type == PFCP_IE_CP_FUNC_FEAT) {
            count += decode_pfcp_cp_func_feat_ie_t(buf + count, &value->cp_func_feat);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_assn_rel_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_rel_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_rel_rsp_t(uint8_t *buf,
      pfcp_assn_rel_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_usage_rpt_sess_rpt_req_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_usage_rpt_sess_rpt_req_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_sess_rpt_req_ie_t(uint8_t *buf,
      pfcp_usage_rpt_sess_rpt_req_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->evnt_time_stmp_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_URSEQN) {
            count += decode_pfcp_urseqn_ie_t(buf + count, &value->urseqn);
      }  else if (ie_type == PFCP_IE_USAGE_RPT_TRIG) {
            count += decode_pfcp_usage_rpt_trig_ie_t(buf + count, &value->usage_rpt_trig);
      }  else if (ie_type == PFCP_IE_START_TIME) {
            count += decode_pfcp_start_time_ie_t(buf + count, &value->start_time);
      }  else if (ie_type == PFCP_IE_END_TIME) {
            count += decode_pfcp_end_time_ie_t(buf + count, &value->end_time);
      }  else if (ie_type == PFCP_IE_VOL_MEAS) {
            count += decode_pfcp_vol_meas_ie_t(buf + count, &value->vol_meas);
      }  else if (ie_type == PFCP_IE_DUR_MEAS) {
            count += decode_pfcp_dur_meas_ie_t(buf + count, &value->dur_meas);
      }  else if (ie_type == IE_APP_DET_INFO) {
            count += decode_pfcp_app_det_info_ie_t(buf + count, &value->app_det_info);
      }  else if (ie_type == PFCP_IE_UE_IP_ADDRESS) {
            count += decode_pfcp_ue_ip_address_ie_t(buf + count, &value->ue_ip_address);
      }  else if (ie_type == PFCP_IE_NTWK_INST) {
            count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
      }  else if (ie_type == PFCP_IE_TIME_OF_FRST_PCKT) {
            count += decode_pfcp_time_of_frst_pckt_ie_t(buf + count, &value->time_of_frst_pckt);
      }  else if (ie_type == PFCP_IE_TIME_OF_LST_PCKT) {
            count += decode_pfcp_time_of_lst_pckt_ie_t(buf + count, &value->time_of_lst_pckt);
      }  else if (ie_type == PFCP_IE_USAGE_INFO) {
            count += decode_pfcp_usage_info_ie_t(buf + count, &value->usage_info);
      }  else if (ie_type == PFCP_IE_QUERY_URR_REF) {
            count += decode_pfcp_query_urr_ref_ie_t(buf + count, &value->query_urr_ref);
      }  else if (ie_type == IE_ETH_TRAFFIC_INFO) {
            count += decode_pfcp_eth_traffic_info_ie_t(buf + count, &value->eth_traffic_info);
      }  else if (ie_type == PFCP_IE_EVNT_TIME_STMP) {
            count += decode_pfcp_evnt_time_stmp_ie_t(buf + count, &value->evnt_time_stmp[value->evnt_time_stmp_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_del_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_del_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_del_rsp_t(uint8_t *buf,
      pfcp_sess_del_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->usage_report_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else if (ie_type == IE_LOAD_CTL_INFO) {
            count += decode_pfcp_load_ctl_info_ie_t(buf + count, &value->load_ctl_info);
      }  else if (ie_type == IE_OVRLD_CTL_INFO) {
            count += decode_pfcp_ovrld_ctl_info_ie_t(buf + count, &value->ovrld_ctl_info);
      }  else if (ie_type == IE_USAGE_RPT_SESS_DEL_RSP) {
            count += decode_pfcp_usage_rpt_sess_del_rsp_ie_t(buf + count, &value->usage_report[value->usage_report_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_set_del_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_set_del_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_set_del_req_t(uint8_t *buf,
      pfcp_sess_set_del_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->sgw_c_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->pgw_c_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->sgw_u_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->pgw_u_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->twan_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->epdg_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->mme_fqcsid);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_set_del_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_set_del_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_set_del_rsp_t(uint8_t *buf,
      pfcp_sess_set_del_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_created_pdr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_created_pdr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_created_pdr_ie_t(uint8_t *buf,
      pfcp_created_pdr_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_PDR_ID) {
            count += decode_pfcp_pdr_id_ie_t(buf + count, &value->pdr_id);
      }  else if (ie_type == PFCP_IE_FTEID) {
            count += decode_pfcp_fteid_ie_t(buf + count, &value->local_fteid);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_load_ctl_info_ie_t(uint8_t *buf,
      pfcp_load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_SEQUENCE_NUMBER) {
            count += decode_pfcp_sequence_number_ie_t(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_type == PFCP_IE_METRIC) {
            count += decode_pfcp_metric_ie_t(buf + count, &value->load_metric);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_mod_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_mod_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_mod_rsp_t(uint8_t *buf,
      pfcp_sess_mod_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->usage_report_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else if (ie_type == IE_CREATED_PDR) {
            count += decode_pfcp_created_pdr_ie_t(buf + count, &value->created_pdr);
      }  else if (ie_type == IE_LOAD_CTL_INFO) {
            count += decode_pfcp_load_ctl_info_ie_t(buf + count, &value->load_ctl_info);
      }  else if (ie_type == IE_OVRLD_CTL_INFO) {
            count += decode_pfcp_ovrld_ctl_info_ie_t(buf + count, &value->ovrld_ctl_info);
      }  else if (ie_type == PFCP_IE_FAILED_RULE_ID) {
            count += decode_pfcp_failed_rule_id_ie_t(buf + count, &value->failed_rule_id);
      }  else if (ie_type == PFCP_IE_ADD_USAGE_RPTS_INFO) {
            count += decode_pfcp_add_usage_rpts_info_ie_t(buf + count, &value->add_usage_rpts_info);
      }  else if (ie_type == IE_CREATED_TRAFFIC_ENDPT) {
            count += decode_pfcp_created_traffic_endpt_ie_t(buf + count, &value->createdupdated_traffic_endpt);
      }  else if (ie_type == IE_USAGE_RPT_SESS_MOD_RSP) {
            count += decode_pfcp_usage_rpt_sess_mod_rsp_ie_t(buf + count, &value->usage_report[value->usage_report_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_created_traffic_endpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_created_traffic_endpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_created_traffic_endpt_ie_t(uint8_t *buf,
      pfcp_created_traffic_endpt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
            count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->traffic_endpt_id);
      }  else if (ie_type == PFCP_IE_FTEID) {
            count += decode_pfcp_fteid_ie_t(buf + count, &value->local_fteid);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_pfd_mgmt_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_pfd_mgmt_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_mgmt_rsp_t(uint8_t *buf,
      pfcp_pfd_mgmt_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_upd_traffic_endpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_upd_traffic_endpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_traffic_endpt_ie_t(uint8_t *buf,
		pfcp_upd_traffic_endpt_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	value->framed_route_count = 0;
	value->frmd_ipv6_rte_count = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
			count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->traffic_endpt_id);
		}  else if (ie_type == PFCP_IE_FTEID) {
			count += decode_pfcp_fteid_ie_t(buf + count, &value->local_fteid);
		}  else if (ie_type == PFCP_IE_NTWK_INST) {
			count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
		}  else if (ie_type == PFCP_IE_UE_IP_ADDRESS) {
			count += decode_pfcp_ue_ip_address_ie_t(buf + count, &value->ue_ip_address);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTING) {
			count += decode_pfcp_framed_routing_ie_t(buf + count, &value->framed_routing);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTE) {
			count += decode_pfcp_framed_route_ie_t(buf + count, &value->framed_route[value->framed_route_count++]);
		}  else if (ie_type == PFCP_IE_FRMD_IPV6_RTE) {
			count += decode_pfcp_frmd_ipv6_rte_ie_t(buf + count, &value->frmd_ipv6_rte[value->frmd_ipv6_rte_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_upd_dupng_parms_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_upd_dupng_parms_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_dupng_parms_ie_t(uint8_t *buf,
      pfcp_upd_dupng_parms_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

	  count = count/CHAR_SIZE;
	  buf_len = value->header.len;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_DST_INTFC) {
            count += decode_pfcp_dst_intfc_ie_t(buf + count, &value->dst_intfc);
      }  else if (ie_type == PFCP_IE_OUTER_HDR_CREATION) {
            count += decode_pfcp_outer_hdr_creation_ie_t(buf + count, &value->outer_hdr_creation);
      }  else if (ie_type == PFCP_IE_TRNSPT_LVL_MARKING) {
            count += decode_pfcp_trnspt_lvl_marking_ie_t(buf + count, &value->trnspt_lvl_marking);
      }  else if (ie_type == PFCP_IE_FRWDNG_PLCY) {
            count += decode_pfcp_frwdng_plcy_ie_t(buf + count, &value->frwdng_plcy);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_frwdng_parms_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_frwdng_parms_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frwdng_parms_ie_t(uint8_t *buf,
      pfcp_frwdng_parms_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
	  count = count/CHAR_SIZE;

	  buf_len = value->header.len;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_DST_INTFC) {
            count += decode_pfcp_dst_intfc_ie_t(buf + count, &value->dst_intfc);
      }  else if (ie_type == PFCP_IE_NTWK_INST) {
            count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
      }  else if (ie_type == PFCP_IE_REDIR_INFO) {
            count += decode_pfcp_redir_info_ie_t(buf + count, &value->redir_info);
      }  else if (ie_type == PFCP_IE_OUTER_HDR_CREATION) {
            count += decode_pfcp_outer_hdr_creation_ie_t(buf + count, &value->outer_hdr_creation);
      }  else if (ie_type == PFCP_IE_TRNSPT_LVL_MARKING) {
            count += decode_pfcp_trnspt_lvl_marking_ie_t(buf + count, &value->trnspt_lvl_marking);
      }  else if (ie_type == PFCP_IE_FRWDNG_PLCY) {
            count += decode_pfcp_frwdng_plcy_ie_t(buf + count, &value->frwdng_plcy);
      }  else if (ie_type == PFCP_IE_HDR_ENRCHMT) {
            count += decode_pfcp_hdr_enrchmt_ie_t(buf + count, &value->hdr_enrchmt);
      }  else if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
            count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->lnkd_traffic_endpt_id);
      }  else if (ie_type == PFCP_IE_PROXYING) {
            count += decode_pfcp_proxying_ie_t(buf + count, &value->proxying);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_dupng_parms_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_dupng_parms_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dupng_parms_ie_t(uint8_t *buf,
		pfcp_dupng_parms_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	count = decode_pfcp_ie_header_t(buf + count, &value->header);

	/* TODO: Revisit this for change in yang */
	count = count/CHAR_SIZE;
	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_DST_INTFC) {
			count += decode_pfcp_dst_intfc_ie_t(buf + count, &value->dst_intfc);
		}  else if (ie_type == PFCP_IE_OUTER_HDR_CREATION) {
			count += decode_pfcp_outer_hdr_creation_ie_t(buf + count, &value->outer_hdr_creation);
		}  else if (ie_type == PFCP_IE_TRNSPT_LVL_MARKING) {
			count += decode_pfcp_trnspt_lvl_marking_ie_t(buf + count, &value->trnspt_lvl_marking);
		}  else if (ie_type == PFCP_IE_FRWDNG_PLCY) {
			count += decode_pfcp_frwdng_plcy_ie_t(buf + count, &value->frwdng_plcy);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_update_pdr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_update_pdr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_pdr_ie_t(uint8_t *buf,
      pfcp_update_pdr_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->actvt_predef_rules_count = 0;
      value->deact_predef_rules_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_PDR_ID) {
            count += decode_pfcp_pdr_id_ie_t(buf + count, &value->pdr_id);
      }  else if (ie_type == PFCP_IE_OUTER_HDR_REMOVAL) {
            count += decode_pfcp_outer_hdr_removal_ie_t(buf + count, &value->outer_hdr_removal);
      }  else if (ie_type == PFCP_IE_PRECEDENCE) {
            count += decode_pfcp_precedence_ie_t(buf + count, &value->precedence);
      }  else if (ie_type == IE_PDI) {
            count += decode_pfcp_pdi_ie_t(buf + count, &value->pdi);
      }  else if (ie_type == PFCP_IE_FAR_ID) {
            count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id);
      }  else if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_QER_ID) {
            count += decode_pfcp_qer_id_ie_t(buf + count, &value->qer_id);
      }  else if (ie_type == PFCP_IE_ACTVT_PREDEF_RULES) {
            count += decode_pfcp_actvt_predef_rules_ie_t(buf + count, &value->actvt_predef_rules[value->actvt_predef_rules_count++]);
      }  else if (ie_type == PFCP_IE_DEACT_PREDEF_RULES) {
            count += decode_pfcp_deact_predef_rules_ie_t(buf + count, &value->deact_predef_rules[value->deact_predef_rules_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_upd_frwdng_parms_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_upd_frwdng_parms_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_frwdng_parms_ie_t(uint8_t *buf,
      pfcp_upd_frwdng_parms_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
	  count = count/CHAR_SIZE;

	  buf_len = value->header.len;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_DST_INTFC) {
            count += decode_pfcp_dst_intfc_ie_t(buf + count, &value->dst_intfc);
      }  else if (ie_type == PFCP_IE_NTWK_INST) {
            count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
      }  else if (ie_type == PFCP_IE_REDIR_INFO) {
            count += decode_pfcp_redir_info_ie_t(buf + count, &value->redir_info);
      }  else if (ie_type == PFCP_IE_OUTER_HDR_CREATION) {
            count += decode_pfcp_outer_hdr_creation_ie_t(buf + count, &value->outer_hdr_creation);
      }  else if (ie_type == PFCP_IE_TRNSPT_LVL_MARKING) {
            count += decode_pfcp_trnspt_lvl_marking_ie_t(buf + count, &value->trnspt_lvl_marking);
      }  else if (ie_type == PFCP_IE_FRWDNG_PLCY) {
            count += decode_pfcp_frwdng_plcy_ie_t(buf + count, &value->frwdng_plcy);
      }  else if (ie_type == PFCP_IE_HDR_ENRCHMT) {
            count += decode_pfcp_hdr_enrchmt_ie_t(buf + count, &value->hdr_enrchmt);
      }  else if (ie_type == PFCP_IE_PFCPSMREQ_FLAGS) {
            count += decode_pfcp_pfcpsmreq_flags_ie_t(buf + count, &value->pfcpsmreq_flags);
      }  else if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
            count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->lnkd_traffic_endpt_id);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_node_rpt_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_node_rpt_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_rsp_t(uint8_t *buf,
      pfcp_node_rpt_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_ovrld_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_ovrld_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ovrld_ctl_info_ie_t(uint8_t *buf,
      pfcp_ovrld_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_SEQUENCE_NUMBER) {
            count += decode_pfcp_sequence_number_ie_t(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_type == PFCP_IE_METRIC) {
            count += decode_pfcp_metric_ie_t(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_type == PFCP_IE_TIMER) {
            count += decode_pfcp_timer_ie_t(buf + count, &value->period_of_validity);
      }  else if (ie_type == PFCP_IE_OCI_FLAGS) {
            count += decode_pfcp_oci_flags_ie_t(buf + count, &value->ovrld_ctl_info_flgs);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_hrtbeat_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_hrtbeat_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hrtbeat_rsp_t(uint8_t *buf,
      pfcp_hrtbeat_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_RCVRY_TIME_STMP) {
            count += decode_pfcp_rcvry_time_stmp_ie_t(buf + count, &value->rcvry_time_stmp);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_node_rpt_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_node_rpt_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_req_t(uint8_t *buf,
      pfcp_node_rpt_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_NODE_RPT_TYPE) {
            count += decode_pfcp_node_rpt_type_ie_t(buf + count, &value->node_rpt_type);
      }  else if (ie_type == IE_USER_PLANE_PATH_FAIL_RPT) {
            count += decode_pfcp_user_plane_path_fail_rpt_ie_t(buf + count, &value->user_plane_path_fail_rpt);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_app_det_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_app_det_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_det_info_ie_t(uint8_t *buf,
      pfcp_app_det_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_APPLICATION_ID) {
            count += decode_pfcp_application_id_ie_t(buf + count, &value->application_id);
      }  else if (ie_type == PFCP_IE_APP_INST_ID) {
            count += decode_pfcp_app_inst_id_ie_t(buf + count, &value->app_inst_id);
      }  else if (ie_type == PFCP_IE_FLOW_INFO) {
            count += decode_pfcp_flow_info_ie_t(buf + count, &value->flow_info);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_pdi_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_pdi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdi_ie_t(uint8_t *buf,
		pfcp_pdi_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

//	buf_len = sizeof(*value) - 4;


	count = decode_pfcp_ie_header_t(buf + count, &value->header);

	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	value->sdf_filter_count = 0;
	value->eth_pckt_fltr_count = 0;
	value->qfi_count = 0;
	value->framed_route_count = 0;
	value->frmd_ipv6_rte_count = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_SRC_INTFC) {
			count += decode_pfcp_src_intfc_ie_t(buf + count, &value->src_intfc);
		}  else if (ie_type == PFCP_IE_FTEID) {
			count += decode_pfcp_fteid_ie_t(buf + count, &value->local_fteid);
		}  else if (ie_type == PFCP_IE_NTWK_INST) {
			count += decode_pfcp_ntwk_inst_ie_t(buf + count, &value->ntwk_inst);
		}  else if (ie_type == PFCP_IE_UE_IP_ADDRESS) {
			count += decode_pfcp_ue_ip_address_ie_t(buf + count, &value->ue_ip_address);
		}  else if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
			count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->traffic_endpt_id);
		}  else if (ie_type == PFCP_IE_APPLICATION_ID) {
			count += decode_pfcp_application_id_ie_t(buf + count, &value->application_id);
		}  else if (ie_type == PFCP_IE_ETH_PDU_SESS_INFO) {
			count += decode_pfcp_eth_pdu_sess_info_ie_t(buf + count, &value->eth_pdu_sess_info);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTING) {
			count += decode_pfcp_framed_routing_ie_t(buf + count, &value->framed_routing);
		}  else if (ie_type == PFCP_IE_SDF_FILTER) {
			count += decode_pfcp_sdf_filter_ie_t(buf + count, &value->sdf_filter[value->sdf_filter_count++]);
		}  else if (ie_type == IE_ETH_PCKT_FLTR) {
			count += decode_pfcp_eth_pckt_fltr_ie_t(buf + count, &value->eth_pckt_fltr[value->eth_pckt_fltr_count++]);
		}  else if (ie_type == PFCP_IE_QFI) {
			count += decode_pfcp_qfi_ie_t(buf + count, &value->qfi[value->qfi_count++]);
		}  else if (ie_type == PFCP_IE_FRAMED_ROUTE) {
			count += decode_pfcp_framed_route_ie_t(buf + count, &value->framed_route[value->framed_route_count++]);
		}  else if (ie_type == PFCP_IE_FRMD_IPV6_RTE) {
			count += decode_pfcp_frmd_ipv6_rte_ie_t(buf + count, &value->frmd_ipv6_rte[value->frmd_ipv6_rte_count++]);
		}  else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}
	return count;
}
/**
* Decodes pfcp_create_bar_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_bar_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_bar_ie_t(uint8_t *buf,
		pfcp_create_bar_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count  = count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_BAR_ID) {
			count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
		}  else if (ie_type == PFCP_IE_DNLNK_DATA_NOTIF_DELAY) {
			count += decode_pfcp_dnlnk_data_notif_delay_ie_t(buf + count, &value->dnlnk_data_notif_delay);
			/* TODO: Revisit this for change in yang */
		}  else if (ie_type == PFCP_IE_DL_BUF_SUGGSTD_PCKT_CNT /*PFCP_IE_SUGGSTD_BUF_PCKTS_CNT*/) {
			count += decode_pfcp_suggstd_buf_pckts_cnt_ie_t(buf + count, &value->suggstd_buf_pckts_cnt);
		}  else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}
	return count;
}
/**
* Decodes pfcp_sess_del_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_del_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_del_req_t(uint8_t *buf,
      pfcp_sess_del_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_assn_upd_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_upd_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_upd_req_t(uint8_t *buf,
      pfcp_assn_upd_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;

      value->user_plane_ip_rsrc_info_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_UP_FUNC_FEAT) {
            count += decode_pfcp_up_func_feat_ie_t(buf + count, &value->up_func_feat);
      }  else if (ie_type == PFCP_IE_CP_FUNC_FEAT) {
            count += decode_pfcp_cp_func_feat_ie_t(buf + count, &value->cp_func_feat);
      }  else if (ie_type == PFCP_IE_UP_ASSN_REL_REQ) {
            count += decode_pfcp_up_assn_rel_req_ie_t(buf + count, &value->up_assn_rel_req);
      }  else if (ie_type == PFCP_IE_GRACEFUL_REL_PERIOD) {
            count += decode_pfcp_graceful_rel_period_ie_t(buf + count, &value->graceful_rel_period);
      }  else if (ie_type == PFCP_IE_USER_PLANE_IP_RSRC_INFO) {
            count += decode_pfcp_user_plane_ip_rsrc_info_ie_t(buf + count, &value->user_plane_ip_rsrc_info[value->user_plane_ip_rsrc_info_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_estab_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_estab_req_t
* @return
v*   number of decoded bytes.
*/
int decode_pfcp_sess_estab_req_t(uint8_t *buf,
		pfcp_sess_estab_req_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	count = decode_pfcp_header_t(buf + count, &value->header);

	if (value->header.s)
		buf_len = value->header.message_len - 12;
	else
		buf_len = value->header.message_len - 4;

	buf = buf + count;
	count = 0;

	value->create_pdr_count = 0;
	value->create_far_count = 0;
	value->create_urr_count = 0;
	value->create_qer_count = 0;
	value->create_traffic_endpt_count = 0;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_NODE_ID) {
			count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
		}  else if (ie_type == PFCP_IE_FSEID) {
			count += decode_pfcp_fseid_ie_t(buf + count, &value->cp_fseid);
		}  else if (ie_type == IE_CREATE_BAR) {
			count += decode_pfcp_create_bar_ie_t(buf + count, &value->create_bar);
		}  else if (ie_type == PFCP_IE_PDN_TYPE) {
			count += decode_pfcp_pdn_type_ie_t(buf + count, &value->pdn_type);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->sgw_c_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->mme_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->pgw_c_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->epdg_fqcsid);
		}  else if (ie_type == PFCP_IE_FQCSID) {
			count += decode_pfcp_fqcsid_ie_t(buf + count, &value->twan_fqcsid);
		}  else if (ie_type == PFCP_IE_USER_PLANE_INACT_TIMER) {
			count += decode_pfcp_user_plane_inact_timer_ie_t(buf + count, &value->user_plane_inact_timer);
		}  else if (ie_type == PFCP_IE_USER_ID) {
			count += decode_pfcp_user_id_ie_t(buf + count, &value->user_id);
		}  else if (ie_type == PFCP_IE_TRC_INFO) {
			count += decode_pfcp_trc_info_ie_t(buf + count, &value->trc_info);
		}  else if (ie_type == IE_CREATE_PDR) {
			count += decode_pfcp_create_pdr_ie_t(buf + count, &value->create_pdr[value->create_pdr_count++]);
		}  else if (ie_type == IE_CREATE_FAR) {
			count += decode_pfcp_create_far_ie_t(buf + count, &value->create_far[value->create_far_count++]);
		}  else if (ie_type == IE_CREATE_URR) {
			count += decode_pfcp_create_urr_ie_t(buf + count, &value->create_urr[value->create_urr_count++]);
		}  else if (ie_type == IE_CREATE_QER) {
			count += decode_pfcp_create_qer_ie_t(buf + count, &value->create_qer[value->create_qer_count++]);
		}  else if (ie_type == IE_CREATE_TRAFFIC_ENDPT) {
			count += decode_pfcp_create_traffic_endpt_ie_t(buf + count, &value->create_traffic_endpt[value->create_traffic_endpt_count++]);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_err_indctn_rpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_err_indctn_rpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_err_indctn_rpt_ie_t(uint8_t *buf,
      pfcp_err_indctn_rpt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->remote_fteid_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_FTEID) {
            count += decode_pfcp_fteid_ie_t(buf + count, &value->remote_fteid[value->remote_fteid_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_eth_traffic_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_eth_traffic_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_traffic_info_ie_t(uint8_t *buf,
      pfcp_eth_traffic_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_MAC_ADDRS_DETCTD) {
            count += decode_pfcp_mac_addrs_detctd_ie_t(buf + count, &value->mac_addrs_detctd);
      }  else if (ie_type == PFCP_IE_MAC_ADDRS_RMVD) {
            count += decode_pfcp_mac_addrs_rmvd_ie_t(buf + count, &value->mac_addrs_rmvd);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_app_ids_pfds_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_app_ids_pfds_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_ids_pfds_ie_t(uint8_t *buf,
      pfcp_app_ids_pfds_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
      count /= CHAR_SIZE;
	  buf_len = value->header.len;
      value->pfd_context_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_APPLICATION_ID) {
            count += decode_pfcp_application_id_ie_t(buf + count, &value->application_id);
      }  else if (ie_type == IE_PFD_CONTEXT) {
            count += decode_pfcp_pfd_context_ie_t(buf + count, &value->pfd_context[value->pfd_context_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_remove_qer_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_remove_qer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_qer_ie_t(uint8_t *buf,
		pfcp_remove_qer_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_QER_ID) {
			count += decode_pfcp_qer_id_ie_t(buf + count, &value->qer_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_create_qer_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_qer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_qer_ie_t(uint8_t *buf,
      pfcp_create_qer_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
	  count = count/CHAR_SIZE;

	  buf_len = value->header.len;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_QER_ID) {
            count += decode_pfcp_qer_id_ie_t(buf + count, &value->qer_id);
      }  else if (ie_type == PFCP_IE_QER_CORR_ID) {
            count += decode_pfcp_qer_corr_id_ie_t(buf + count, &value->qer_corr_id);
      }  else if (ie_type == PFCP_IE_GATE_STATUS) {
            count += decode_pfcp_gate_status_ie_t(buf + count, &value->gate_status);
      }  else if (ie_type == PFCP_IE_MBR) {
            count += decode_pfcp_mbr_ie_t(buf + count, &value->maximum_bitrate);
      }  else if (ie_type == PFCP_IE_GBR) {
            count += decode_pfcp_gbr_ie_t(buf + count, &value->guaranteed_bitrate);
      }  else if (ie_type == PFCP_IE_PACKET_RATE) {
            count += decode_pfcp_packet_rate_ie_t(buf + count, &value->packet_rate);
      }  else if (ie_type == PFCP_IE_DL_FLOW_LVL_MARKING) {
            count += decode_pfcp_dl_flow_lvl_marking_ie_t(buf + count, &value->dl_flow_lvl_marking);
      }  else if (ie_type == PFCP_IE_QFI) {
            count += decode_pfcp_qfi_ie_t(buf + count, &value->qos_flow_ident);
      }  else if (ie_type == PFCP_IE_RQI) {
            count += decode_pfcp_rqi_ie_t(buf + count, &value->reflective_qos);
      }  else if (ie_type == PFCP_IE_PAGING_PLCY_INDCTR) {
            count += decode_pfcp_paging_plcy_indctr_ie_t(buf + count, &value->paging_plcy_indctr);
      }  else if (ie_type == PFCP_IE_AVGNG_WND) {
            count += decode_pfcp_avgng_wnd_ie_t(buf + count, &value->avgng_wnd);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_rmv_traffic_endpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_rmv_traffic_endpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rmv_traffic_endpt_ie_t(uint8_t *buf,
		pfcp_rmv_traffic_endpt_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */

	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_TRAFFIC_ENDPT_ID) {
			count += decode_pfcp_traffic_endpt_id_ie_t(buf + count, &value->traffic_endpt_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_update_urr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_update_urr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_urr_ie_t(uint8_t *buf,
      pfcp_update_urr_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->linked_urr_id_count = 0;
      value->aggregated_urrs_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_URR_ID) {
            count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id);
      }  else if (ie_type == PFCP_IE_MEAS_MTHD) {
            count += decode_pfcp_meas_mthd_ie_t(buf + count, &value->meas_mthd);
      }  else if (ie_type == PFCP_IE_RPTNG_TRIGGERS) {
            count += decode_pfcp_rptng_triggers_ie_t(buf + count, &value->rptng_triggers);
      }  else if (ie_type == PFCP_IE_MEAS_PERIOD) {
            count += decode_pfcp_meas_period_ie_t(buf + count, &value->meas_period);
      }  else if (ie_type == PFCP_IE_VOL_THRESH) {
            count += decode_pfcp_vol_thresh_ie_t(buf + count, &value->vol_thresh);
      }  else if (ie_type == PFCP_IE_VOLUME_QUOTA) {
            count += decode_pfcp_volume_quota_ie_t(buf + count, &value->volume_quota);
      }  else if (ie_type == PFCP_IE_TIME_THRESHOLD) {
            count += decode_pfcp_time_threshold_ie_t(buf + count, &value->time_threshold);
      }  else if (ie_type == PFCP_IE_TIME_QUOTA) {
            count += decode_pfcp_time_quota_ie_t(buf + count, &value->time_quota);
      }  else if (ie_type == PFCP_IE_EVENT_THRESHOLD) {
            count += decode_pfcp_event_threshold_ie_t(buf + count, &value->event_threshold);
      }  else if (ie_type == PFCP_IE_EVENT_QUOTA) {
            count += decode_pfcp_event_quota_ie_t(buf + count, &value->event_quota);
      }  else if (ie_type == PFCP_IE_QUOTA_HLDNG_TIME) {
            count += decode_pfcp_quota_hldng_time_ie_t(buf + count, &value->quota_hldng_time);
      }  else if (ie_type == PFCP_IE_DRPD_DL_TRAFFIC_THRESH) {
            count += decode_pfcp_drpd_dl_traffic_thresh_ie_t(buf + count, &value->drpd_dl_traffic_thresh);
      }  else if (ie_type == PFCP_IE_MONITORING_TIME) {
            count += decode_pfcp_monitoring_time_ie_t(buf + count, &value->monitoring_time);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_THRESH) {
            count += decode_pfcp_sbsqnt_vol_thresh_ie_t(buf + count, &value->sbsqnt_vol_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_THRESH) {
            count += decode_pfcp_sbsqnt_time_thresh_ie_t(buf + count, &value->sbsqnt_time_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_QUOTA) {
            count += decode_pfcp_sbsqnt_vol_quota_ie_t(buf + count, &value->sbsqnt_vol_quota);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_QUOTA) {
            count += decode_pfcp_sbsqnt_time_quota_ie_t(buf + count, &value->sbsqnt_time_quota);
      }  else if (ie_type == PFCP_IE_SBSQNT_EVNT_THRESH) {
            count += decode_pfcp_sbsqnt_evnt_thresh_ie_t(buf + count, &value->sbsqnt_evnt_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_EVNT_QUOTA) {
            count += decode_pfcp_sbsqnt_evnt_quota_ie_t(buf + count, &value->sbsqnt_evnt_quota);
      }  else if (ie_type == PFCP_IE_INACT_DET_TIME) {
            count += decode_pfcp_inact_det_time_ie_t(buf + count, &value->inact_det_time);
      }  else if (ie_type == PFCP_IE_MEAS_INFO) {
            count += decode_pfcp_meas_info_ie_t(buf + count, &value->meas_info);
      }  else if (ie_type == PFCP_IE_TIME_QUOTA_MECH) {
            count += decode_pfcp_time_quota_mech_ie_t(buf + count, &value->time_quota_mech);
      }  else if (ie_type == PFCP_IE_FAR_ID) {
            count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id_for_quota_act);
      }  else if (ie_type == PFCP_IE_ETH_INACT_TIMER) {
            count += decode_pfcp_eth_inact_timer_ie_t(buf + count, &value->eth_inact_timer);
      }  else if (ie_type == IE_ADD_MNTRNG_TIME) {
            count += decode_pfcp_add_mntrng_time_ie_t(buf + count, &value->add_mntrng_time);
      }  else if (ie_type == PFCP_IE_LINKED_URR_ID) {
            count += decode_pfcp_linked_urr_id_ie_t(buf + count, &value->linked_urr_id[value->linked_urr_id_count++]);
      }  else if (ie_type == IE_AGGREGATED_URRS) {
            count += decode_pfcp_aggregated_urrs_ie_t(buf + count, &value->aggregated_urrs[value->aggregated_urrs_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_update_far_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_update_far_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_far_ie_t(uint8_t *buf,
      pfcp_update_far_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);
	  count = count/CHAR_SIZE;

      value->upd_dupng_parms_count = 0;
	  buf_len = value->header.len;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_FAR_ID) {
            count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id);
      }  else if (ie_type == PFCP_IE_APPLY_ACTION) {
            count += decode_pfcp_apply_action_ie_t(buf + count, &value->apply_action);
      }  else if (ie_type == IE_UPD_FRWDNG_PARMS) {
            count += decode_pfcp_upd_frwdng_parms_ie_t(buf + count, &value->upd_frwdng_parms);
      }  else if (ie_type == PFCP_IE_BAR_ID) {
            count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
      }  else if (ie_type == IE_UPD_DUPNG_PARMS) {
            count += decode_pfcp_upd_dupng_parms_ie_t(buf + count, &value->upd_dupng_parms[value->upd_dupng_parms_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_user_plane_path_fail_rpt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_user_plane_path_fail_rpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_path_fail_rpt_ie_t(uint8_t *buf,
      pfcp_user_plane_path_fail_rpt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);

      value->rmt_gtpu_peer_count = 0;

      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_RMT_GTPU_PEER) {
            count += decode_pfcp_rmt_gtpu_peer_ie_t(buf + count, &value->rmt_gtpu_peer[value->rmt_gtpu_peer_count++]);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_remove_pdr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_remove_pdr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_remove_pdr_ie_t(uint8_t *buf,
		pfcp_remove_pdr_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_PDR_ID) {
			count += decode_pfcp_pdr_id_ie_t(buf + count, &value->pdr_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_update_qer_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_update_qer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_update_qer_ie_t(uint8_t *buf,
	pfcp_update_qer_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;
/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count =  count/CHAR_SIZE;

	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_QER_ID) {
			count += decode_pfcp_qer_id_ie_t(buf + count, &value->qer_id);
		}  else if (ie_type == PFCP_IE_QER_CORR_ID) {
			count += decode_pfcp_qer_corr_id_ie_t(buf + count, &value->qer_corr_id);
		}  else if (ie_type == PFCP_IE_GATE_STATUS) {
			count += decode_pfcp_gate_status_ie_t(buf + count, &value->gate_status);
		}  else if (ie_type == PFCP_IE_MBR) {
			count += decode_pfcp_mbr_ie_t(buf + count, &value->maximum_bitrate);
		}  else if (ie_type == PFCP_IE_GBR) {
			count += decode_pfcp_gbr_ie_t(buf + count, &value->guaranteed_bitrate);
		}  else if (ie_type == PFCP_IE_PACKET_RATE) {
			count += decode_pfcp_packet_rate_ie_t(buf + count, &value->packet_rate);
		}  else if (ie_type == PFCP_IE_DL_FLOW_LVL_MARKING) {
			count += decode_pfcp_dl_flow_lvl_marking_ie_t(buf + count, &value->dl_flow_lvl_marking);
		}  else if (ie_type == PFCP_IE_QFI) {
			count += decode_pfcp_qfi_ie_t(buf + count, &value->qos_flow_ident);
		}  else if (ie_type == PFCP_IE_RQI) {
			count += decode_pfcp_rqi_ie_t(buf + count, &value->reflective_qos);
		}  else if (ie_type == PFCP_IE_PAGING_PLCY_INDCTR) {
			count += decode_pfcp_paging_plcy_indctr_ie_t(buf + count, &value->paging_plcy_indctr);
		}  else if (ie_type == PFCP_IE_AVGNG_WND) {
			count += decode_pfcp_avgng_wnd_ie_t(buf + count, &value->avgng_wnd);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_add_mntrng_time_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_add_mntrng_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_add_mntrng_time_ie_t(uint8_t *buf,
      pfcp_add_mntrng_time_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_MONITORING_TIME) {
            count += decode_pfcp_monitoring_time_ie_t(buf + count, &value->monitoring_time);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_THRESH) {
            count += decode_pfcp_sbsqnt_vol_thresh_ie_t(buf + count, &value->sbsqnt_vol_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_THRESH) {
            count += decode_pfcp_sbsqnt_time_thresh_ie_t(buf + count, &value->sbsqnt_time_thresh);
      }  else if (ie_type == PFCP_IE_SBSQNT_VOL_QUOTA) {
            count += decode_pfcp_sbsqnt_vol_quota_ie_t(buf + count, &value->sbsqnt_vol_quota);
      }  else if (ie_type == PFCP_IE_SBSQNT_TIME_QUOTA) {
            count += decode_pfcp_sbsqnt_time_quota_ie_t(buf + count, &value->sbsqnt_time_quota);
      }  else if (ie_type == PFCP_IE_EVENT_THRESHOLD) {
            count += decode_pfcp_event_threshold_ie_t(buf + count, &value->sbsqnt_evnt_thresh);
      }  else if (ie_type == PFCP_IE_EVENT_QUOTA) {
            count += decode_pfcp_event_quota_ie_t(buf + count, &value->sbsqnt_evnt_quota);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_sess_estab_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_sess_estab_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sess_estab_rsp_t(uint8_t *buf,
      pfcp_sess_estab_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else if (ie_type == PFCP_IE_CAUSE) {
            count += decode_pfcp_cause_ie_t(buf + count, &value->cause);
      }  else if (ie_type == PFCP_IE_OFFENDING_IE) {
            count += decode_pfcp_offending_ie_ie_t(buf + count, &value->offending_ie);
      }  else if (ie_type == PFCP_IE_FSEID) {
            count += decode_pfcp_fseid_ie_t(buf + count, &value->up_fseid);
      }  else if (ie_type == IE_CREATED_PDR) {
            count += decode_pfcp_created_pdr_ie_t(buf + count, &value->created_pdr);
      }  else if (ie_type == IE_LOAD_CTL_INFO) {
            count += decode_pfcp_load_ctl_info_ie_t(buf + count, &value->load_ctl_info);
      }  else if (ie_type == IE_OVRLD_CTL_INFO) {
            count += decode_pfcp_ovrld_ctl_info_ie_t(buf + count, &value->ovrld_ctl_info);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->sgw_u_fqcsid);
      }  else if (ie_type == PFCP_IE_FQCSID) {
            count += decode_pfcp_fqcsid_ie_t(buf + count, &value->pgw_u_fqcsid);
      }  else if (ie_type == PFCP_IE_FAILED_RULE_ID) {
            count += decode_pfcp_failed_rule_id_ie_t(buf + count, &value->failed_rule_id);
      }  else if (ie_type == IE_CREATED_TRAFFIC_ENDPT) {
            count += decode_pfcp_created_traffic_endpt_ie_t(buf + count, &value->created_traffic_endpt);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_remove_bar_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_remove_bar_ie_t
* @return
*   number of decoded bytes.
*/

int decode_pfcp_remove_bar_ie_t(uint8_t *buf,
		pfcp_remove_bar_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;

	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;
	buf_len = value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_BAR_ID) {
			count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
/**
* Decodes pfcp_assn_rel_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_assn_rel_req_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_assn_rel_req_t(uint8_t *buf,
      pfcp_assn_rel_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_header_t(buf + count, &value->header);

      if (value->header.s)
          buf_len = value->header.message_len - 12;
      else
          buf_len = value->header.message_len - 4;

      buf = buf + count;
      count = 0;


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_NODE_ID) {
            count += decode_pfcp_node_id_ie_t(buf + count, &value->node_id);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_create_pdr_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_create_pdr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_create_pdr_ie_t(uint8_t *buf,
		pfcp_create_pdr_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;


	/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count =  count/CHAR_SIZE;

	buf_len = value->header.len;

	value->urr_id_count = 0;
	value->qer_id_count = 0;
	value->actvt_predef_rules_count = 0;


	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_PDR_ID) {
			count += decode_pfcp_pdr_id_ie_t(buf + count, &value->pdr_id);
		}  else if (ie_type == PFCP_IE_PRECEDENCE) {
			count += decode_pfcp_precedence_ie_t(buf + count, &value->precedence);
		}  else if (ie_type == IE_PDI) {
			count += decode_pfcp_pdi_ie_t(buf + count, &value->pdi);
		}  else if (ie_type == PFCP_IE_OUTER_HDR_REMOVAL) {
			count += decode_pfcp_outer_hdr_removal_ie_t(buf + count, &value->outer_hdr_removal);
		}  else if (ie_type == PFCP_IE_FAR_ID) {
			count += decode_pfcp_far_id_ie_t(buf + count, &value->far_id);
		}  else if (ie_type == PFCP_IE_URR_ID) {
			count += decode_pfcp_urr_id_ie_t(buf + count, &value->urr_id[value->urr_id_count++]);
		}  else if (ie_type == PFCP_IE_QER_ID) {
			count += decode_pfcp_qer_id_ie_t(buf + count, &value->qer_id[value->qer_id_count++]);
		}  else if (ie_type == PFCP_IE_ACTVT_PREDEF_RULES) {
			count += decode_pfcp_actvt_predef_rules_ie_t(buf + count, &value->actvt_predef_rules[value->actvt_predef_rules_count++]);
		}  else{
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}
	/* TODO: Revisit this for change in yang */
	return count;
}
/**
* Decodes pfcp_aggregated_urrs_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_aggregated_urrs_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_aggregated_urrs_ie_t(uint8_t *buf,
      pfcp_aggregated_urrs_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

      count = decode_pfcp_ie_header_t(buf + count, &value->header);


      while (count < buf_len) {

          pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

          uint16_t ie_type = ntohs(ie_header->type);

      if (ie_type == PFCP_IE_AGG_URR_ID) {
            count += decode_pfcp_agg_urr_id_ie_t(buf + count, &value->agg_urr_id);
      }  else if (ie_type == PFCP_IE_MULTIPLIER) {
            count += decode_pfcp_multiplier_ie_t(buf + count, &value->multiplier);
      }  else
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pfcp_upd_bar_sess_mod_req_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pfcp_upd_bar_sess_mod_req_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_upd_bar_sess_mod_req_ie_t(uint8_t *buf,
		pfcp_upd_bar_sess_mod_req_ie_t *value)
{
	uint16_t count = 0;
	uint16_t buf_len = 0;
/* TODO: Revisit this for change in yang */
	count = decode_pfcp_ie_header_t(buf + count, &value->header);
	count = count/CHAR_SIZE;

	buf_len =  value->header.len;

	while (count < buf_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (buf + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == PFCP_IE_BAR_ID) {
			count += decode_pfcp_bar_id_ie_t(buf + count, &value->bar_id);
		}  else if (ie_type == PFCP_IE_DNLNK_DATA_NOTIF_DELAY) {
			count += decode_pfcp_dnlnk_data_notif_delay_ie_t(buf + count, &value->dnlnk_data_notif_delay);
		}  else if (ie_type == PFCP_IE_SUGGSTD_BUF_PCKTS_CNT) {
			count += decode_pfcp_suggstd_buf_pckts_cnt_ie_t(buf + count, &value->suggstd_buf_pckts_cnt);
		}  else
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
	return count;
}
