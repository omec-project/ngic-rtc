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

#include "../include/enc_dec_bits.h"

#include "../include/pfcp_cond_decoder.h"

/**
 * Decode pfcp buffer.
 * @param value
 *     gtpc
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int decode_pfcp_header_t(uint8_t *buf, pfcp_header_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;

    value->version = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->mp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->s = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;

    value->message_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->message_len = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;

    if (value->s == 1) {
	value->seid_seqno.has_seid.seid = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;

	value->seid_seqno.has_seid.seq_no = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;

	value->seid_seqno.has_seid.spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;

	value->seid_seqno.has_seid.message_prio = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;

    } else {
	value->seid_seqno.no_seid.seq_no = decode_bits(buf, total_decoded, 24, &decoded);
	total_decoded += decoded;

	value->seid_seqno.no_seid.spare = decode_bits(buf, total_decoded, 8, &decoded);
	total_decoded += decoded;

    }

    return total_decoded/CHAR_SIZE;
}

/**
 * decodes ie header to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ie header
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_ie_header_t(uint8_t *buf,
	pfcp_ie_header_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;

    value->type = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->len = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;

    return total_decoded;
}

/**
* decodes pfcp_end_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_end_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_end_time_ie_t(uint8_t *buf,
        pfcp_end_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->end_time = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_trnspt_lvl_marking_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_trnspt_lvl_marking_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_trnspt_lvl_marking_ie_t(uint8_t *buf,
        pfcp_trnspt_lvl_marking_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->tostraffic_cls = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_failed_rule_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_failed_rule_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_failed_rule_id_ie_t(uint8_t *buf,
		pfcp_failed_rule_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->failed_rule_id_spare = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->rule_id_type = decode_bits(buf, total_decoded, 5, &decoded);
	total_decoded += decoded;

	/* TODO: Revisit this for change in yang */
	if(value->rule_id_type == 0) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 2);
		total_decoded +=  2 * CHAR_SIZE;
	}else if(value->rule_id_type == 2) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}else if(value->rule_id_type == 3) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}else if(value->rule_id_type == 4) {
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 1);
		total_decoded +=  1 * CHAR_SIZE;
	}else{
		memcpy(&value->rule_id_value, buf + (total_decoded/CHAR_SIZE), 4);
		total_decoded +=  4 * CHAR_SIZE;
	}//FAR is by default 3gpp 29.244 15.03 (8.2.80)


	//    value->rule_id_value = decode_bits(buf, total_decoded, 8, &decoded);
	//  total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_vol_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_vol_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_vol_quota_ie_t(uint8_t *buf,
        pfcp_sbsqnt_vol_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_vol_quota_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOTAL_VOLUME_COND_5(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_UPLINK_VOLUME_COND_5(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_DOWNLINK_VOLUME_COND_5(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_eth_fltr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_eth_fltr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_fltr_id_ie_t(uint8_t *buf,
        pfcp_eth_fltr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->eth_fltr_id_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_mac_addrs_rmvd_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_mac_addrs_rmvd_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_addrs_rmvd_ie_t(uint8_t *buf,
        pfcp_mac_addrs_rmvd_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->nbr_of_mac_addrs = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->mac_addr_val, buf + (total_decoded/CHAR_SIZE), MAC_ADDR_VAL_LEN);
    total_decoded +=  MAC_ADDR_VAL_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_linked_urr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_linked_urr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_linked_urr_id_ie_t(uint8_t *buf,
        pfcp_linked_urr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->lnkd_urr_id_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_evnt_time_stmp_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_evnt_time_stmp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_evnt_time_stmp_ie_t(uint8_t *buf,
        pfcp_evnt_time_stmp_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->evnt_time_stmp = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_mac_addrs_detctd_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_mac_addrs_detctd_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_addrs_detctd_ie_t(uint8_t *buf,
        pfcp_mac_addrs_detctd_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->nbr_of_mac_addrs = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->mac_addr_val, buf + (total_decoded/CHAR_SIZE), MAC_ADDR_VAL_LEN);
    total_decoded +=  MAC_ADDR_VAL_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_node_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_node_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_id_ie_t(uint8_t *buf,
        pfcp_node_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->node_id_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->node_id_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;

    //DECODE_NODE_ID_VALUE_COND_1(buf, total_decoded, 8, decoded, value);
  /* TODO: Revisit this for change in yang */

    memcpy(&value->node_id_value, buf + (total_decoded/CHAR_SIZE), value->header.len - 1);
    total_decoded +=  (value->header.len - 1) * CHAR_SIZE;
   // total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_bar_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_bar_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_bar_id_ie_t(uint8_t *buf,
        pfcp_bar_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->bar_id_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_usage_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_usage_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_info_ie_t(uint8_t *buf,
        pfcp_usage_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->usage_info_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->ube = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->uae = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->aft = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->bef = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dnlnk_data_svc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dnlnk_data_svc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_svc_info_ie_t(uint8_t *buf,
        pfcp_dnlnk_data_svc_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->dnlnk_data_svc_info_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->qfii = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ppi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->dnlnk_data_svc_info_spare2 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    //DECODE_PAGING_PLCY_INDCTN_VAL_COND_1(buf, total_decoded, 6, decoded, value);
    value->paging_plcy_indctn_val = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->dnlnk_data_svc_info_spare3 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    //DECODE_QFI_COND_1(buf, total_decoded, 6, decoded, value);
    value->qfi = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dur_meas_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dur_meas_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dur_meas_ie_t(uint8_t *buf,
        pfcp_dur_meas_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->duration_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_up_assn_rel_req_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_up_assn_rel_req_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_up_assn_rel_req_ie_t(uint8_t *buf,
        pfcp_up_assn_rel_req_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->up_assn_rel_req_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->sarr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_application_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_application_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_application_id_ie_t(uint8_t *buf,
		pfcp_application_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	//uint16_t decoded = 0;
	//value->app_ident = decode_bits(buf, total_decoded, 8, &decoded);
	/* TODO: Revisit this for change in yang */
	memcpy(&value->app_ident, buf + (total_decoded/CHAR_SIZE), 8);
	total_decoded +=  8 * CHAR_SIZE;

	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_urseqn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_urseqn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_urseqn_ie_t(uint8_t *buf,
        pfcp_urseqn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->urseqn = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dl_flow_lvl_marking_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dl_flow_lvl_marking_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_flow_lvl_marking_ie_t(uint8_t *buf,
        pfcp_dl_flow_lvl_marking_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->dl_flow_lvl_marking_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->sci = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ttc = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOSTRAFFIC_CLS_COND_1(buf, total_decoded, 16, decoded, value);
    DECODE_SVC_CLS_INDCTR_COND_1(buf, total_decoded, 16, decoded, value);
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_ue_ip_address_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_ue_ip_address_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ue_ip_address_ie_t(uint8_t *buf,
        pfcp_ue_ip_address_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->ue_ip_addr_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ipv6d = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sd = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_IPV4_ADDRESS_COND_6(buf, total_decoded, 32, decoded, value);
	/* TODO: Revisit this for change in yang */
   // total_decoded += decoded;
    DECODE_IPV6_ADDRESS_COND_6(buf, total_decoded, 8, decoded, value);
	/* TODO: Revisit this for change in yang */
    //total_decoded += decoded;
    DECODE_IPV6_PFX_DLGTN_BITS_COND_1(buf, total_decoded, 8, decoded, value);
	/* TODO: Revisit this for change in yang */
   // total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_evnt_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_evnt_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_evnt_quota_ie_t(uint8_t *buf,
        pfcp_sbsqnt_evnt_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_evnt_quota = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_gate_status_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_gate_status_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_gate_status_ie_t(uint8_t *buf,
        pfcp_gate_status_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->gate_status_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ul_gate = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->dl_gate = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_suggstd_buf_pckts_cnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_suggstd_buf_pckts_cnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_suggstd_buf_pckts_cnt_ie_t(uint8_t *buf,
        pfcp_suggstd_buf_pckts_cnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->pckt_cnt_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_pfd_contents_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_pfd_contents_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfd_contents_ie_t(uint8_t *buf,
        pfcp_pfd_contents_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;

	value->pfd_contents_spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;

	value->pfd_contents_cp = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	value->dn = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	value->url = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	value->fd = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	//value->pfd_contents_spare2 = decode_bits(buf, total_decoded, 8, &decoded);
	//total_decoded += decoded;

	DECODE_LEN_OF_FLOW_DESC_COND_2(buf, total_decoded, 16, decoded, value);
	total_decoded += decoded;

	DECODE_FLOW_DESC_COND_2(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;

	DECODE_LENGTH_OF_URL_COND_1(buf, total_decoded, 16, decoded, value);
	total_decoded += decoded;

	DECODE_URL2_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;

	DECODE_LEN_OF_DOMAIN_NM_COND_1(buf, total_decoded, 16, decoded, value);
	total_decoded += decoded;

	DECODE_DOMAIN_NAME_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;

	DECODE_LEN_OF_CSTM_PFD_CNTNT_COND_1(buf, total_decoded, 16, decoded, value);

	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sequence_number_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sequence_number_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sequence_number_ie_t(uint8_t *buf,
        pfcp_sequence_number_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sequence_number = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_packet_rate_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_packet_rate_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_packet_rate_ie_t(uint8_t *buf,
        pfcp_packet_rate_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->pckt_rate_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->dlpr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulpr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pckt_rate_spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->uplnk_time_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    DECODE_MAX_UPLNK_PCKT_RATE_COND_1(buf, total_decoded, 16, decoded, value);
    value->pckt_rate_spare3 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dnlnk_time_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    DECODE_MAX_DNLNK_PCKT_RATE_COND_1(buf, total_decoded, 16, decoded, value);
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_hdr_enrchmt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_hdr_enrchmt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_hdr_enrchmt_ie_t(uint8_t *buf,
        pfcp_hdr_enrchmt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->hdr_enrchmt_spare = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->header_type = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->len_of_hdr_fld_nm = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->hdr_fld_nm = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_hdr_fld_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->hdr_fld_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_time_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_time_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_quota_ie_t(uint8_t *buf,
        pfcp_time_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_quota_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_deact_predef_rules_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_deact_predef_rules_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_deact_predef_rules_ie_t(uint8_t *buf,
        pfcp_deact_predef_rules_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->predef_rules_nm = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_apply_action_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_apply_action_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_apply_action_ie_t(uint8_t *buf,
        pfcp_apply_action_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->apply_act_spare = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->apply_act_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->apply_act_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->dupl = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nocp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->buff = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->forw = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drop = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_node_rpt_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_node_rpt_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_node_rpt_type_ie_t(uint8_t *buf,
        pfcp_node_rpt_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->node_rpt_type_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->upfr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_fteid_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_fteid_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fteid_ie_t(uint8_t *buf,
        pfcp_fteid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->fteid_spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->chid = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->ch = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	DECODE_TEID_COND_2(buf, total_decoded, 32, decoded, value);
	//total_decoded += decoded;
	DECODE_IPV4_ADDRESS_COND_5(buf, total_decoded, 32, decoded, value);
	//total_decoded += decoded;
	DECODE_IPV6_ADDRESS_COND_5(buf, total_decoded, 8, decoded, value);

	/* TODO: Revisit this for change in yang */
	 //total_decoded += decoded;

	DECODE_CHOOSE_ID_COND_1(buf, total_decoded, 8, decoded, value);
	//total_decoded += decoded;

	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_meas_period_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_meas_period_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_period_ie_t(uint8_t *buf,
        pfcp_meas_period_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->meas_period = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_up_func_feat_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_up_func_feat_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_up_func_feat_ie_t(uint8_t *buf,
        pfcp_up_func_feat_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sup_feat = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_inact_det_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_inact_det_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_inact_det_time_ie_t(uint8_t *buf,
        pfcp_inact_det_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->inact_det_time = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_pfcpsmreq_flags_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_pfcpsmreq_flags_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfcpsmreq_flags_ie_t(uint8_t *buf,
		pfcp_pfcpsmreq_flags_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->pfcpsmreq_flgs_spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pfcpsmreq_flgs_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pfcpsmreq_flgs_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pfcpsmreq_flgs_spare4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->pfcpsmreq_flgs_spare5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->qaurr = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->sndem = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->drobu = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_meas_mthd_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_meas_mthd_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_mthd_ie_t(uint8_t *buf,
        pfcp_meas_mthd_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->meas_mthd_spare = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->meas_mthd_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->meas_mthd_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->meas_mthd_spare4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->meas_mthd_spare5 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->event = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->volum = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->durat = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_paging_plcy_indctr_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_paging_plcy_indctr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_paging_plcy_indctr_ie_t(uint8_t *buf,
        pfcp_paging_plcy_indctr_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->paging_plcy_indctr_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->ppi_value = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_framed_routing_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_framed_routing_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_framed_routing_ie_t(uint8_t *buf,
        pfcp_framed_routing_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->framed_routing = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_time_quota_mech_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_time_quota_mech_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_quota_mech_ie_t(uint8_t *buf,
        pfcp_time_quota_mech_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_quota_mech_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->btit = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->base_time_int = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_quota_hldng_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_quota_hldng_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_quota_hldng_time_ie_t(uint8_t *buf,
        pfcp_quota_hldng_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->quota_hldng_time_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_gbr_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_gbr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_gbr_ie_t(uint8_t *buf,
        pfcp_gbr_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->ul_gbr = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->dl_gbr = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_traffic_endpt_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_traffic_endpt_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_traffic_endpt_id_ie_t(uint8_t *buf,
        pfcp_traffic_endpt_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->traffic_endpt_id_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dl_buf_dur_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dl_buf_dur_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_buf_dur_ie_t(uint8_t *buf,
        pfcp_dl_buf_dur_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_volume_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_volume_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_volume_quota_ie_t(uint8_t *buf,
        pfcp_volume_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->vol_quota_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOTAL_VOLUME_COND_4(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_UPLINK_VOLUME_COND_4(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_DOWNLINK_VOLUME_COND_4(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_event_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_event_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_event_quota_ie_t(uint8_t *buf,
        pfcp_event_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_evnt_quota = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_query_urr_ref_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_query_urr_ref_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_query_urr_ref_ie_t(uint8_t *buf,
		pfcp_query_urr_ref_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->query_urr_ref_val = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_time_quota_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_time_quota_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_time_quota_ie_t(uint8_t *buf,
        pfcp_sbsqnt_time_quota_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_quota_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_qer_corr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_qer_corr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qer_corr_id_ie_t(uint8_t *buf,
        pfcp_qer_corr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->qer_corr_id_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_vol_meas_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_vol_meas_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_vol_meas_ie_t(uint8_t *buf,
        pfcp_vol_meas_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->vol_meas_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOTAL_VOLUME_COND_3(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_UPLINK_VOLUME_COND_3(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_DOWNLINK_VOLUME_COND_3(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_far_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_far_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_far_id_ie_t(uint8_t *buf,
        pfcp_far_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->far_id_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_proxying_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_proxying_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_proxying_ie_t(uint8_t *buf,
        pfcp_proxying_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->proxying_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->ins = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->arp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_rptng_triggers_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_rptng_triggers_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rptng_triggers_ie_t(uint8_t *buf,
        pfcp_rptng_triggers_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->liusa = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->droth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->stopt = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->start = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->quhti = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->timth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->volth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->perio = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->rptng_triggers_spare = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->rptng_triggers_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->evequ = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->eveth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->macar = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->envcl = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->timqu = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->volqu = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_qer_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_qer_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qer_id_ie_t(uint8_t *buf,
        pfcp_qer_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->qer_id_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_monitoring_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_monitoring_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_monitoring_time_ie_t(uint8_t *buf,
        pfcp_monitoring_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->monitoring_time = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_flow_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_flow_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_flow_info_ie_t(uint8_t *buf,
        pfcp_flow_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->flow_info_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->flow_direction = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->len_of_flow_desc = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->flow_desc = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_precedence_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_precedence_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_precedence_ie_t(uint8_t *buf,
        pfcp_precedence_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->prcdnc_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_metric_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_metric_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_metric_ie_t(uint8_t *buf,
        pfcp_metric_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->metric = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_multiplier_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_multiplier_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_multiplier_ie_t(uint8_t *buf,
        pfcp_multiplier_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->value_digits = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    value->exponent = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_cause_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_cause_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_cause_ie_t(uint8_t *buf,
        pfcp_cause_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->cause_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_offending_ie_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_offending_ie_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_offending_ie_ie_t(uint8_t *buf,
        pfcp_offending_ie_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->type_of_the_offending_ie = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_ntwk_inst_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_ntwk_inst_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ntwk_inst_ie_t(uint8_t *buf,
        pfcp_ntwk_inst_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    /* uint16_t decoded = 0; */
	/* TODO: Revisit this for change in yang */
	memcpy(&value->ntwk_inst, buf + (total_decoded/CHAR_SIZE), 32);
    //value->ntwk_inst = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += 32*CHAR_SIZE;//decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_redir_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_redir_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_redir_info_ie_t(uint8_t *buf,
        pfcp_redir_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->redir_info_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->redir_addr_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->redir_svr_addr_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->redir_svr_addr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_event_threshold_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_event_threshold_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_event_threshold_ie_t(uint8_t *buf,
        pfcp_event_threshold_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->event_threshold = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_app_inst_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_app_inst_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_app_inst_id_ie_t(uint8_t *buf,
        pfcp_app_inst_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->app_inst_ident = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_drpd_dl_traffic_thresh_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_drpd_dl_traffic_thresh_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_drpd_dl_traffic_thresh_ie_t(uint8_t *buf,
        pfcp_drpd_dl_traffic_thresh_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->drpd_dl_traffic_thresh_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->dlby = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->dlpa = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_DNLNK_PCKTS_COND_1(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_NBR_OF_BYTES_OF_DNLNK_DATA_COND_1(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_frmd_ipv6_rte_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_frmd_ipv6_rte_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frmd_ipv6_rte_ie_t(uint8_t *buf,
        pfcp_frmd_ipv6_rte_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->frmd_ipv6_rte = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_user_plane_inact_timer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_user_plane_inact_timer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_inact_timer_ie_t(uint8_t *buf,
		pfcp_user_plane_inact_timer_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->user_plane_inact_timer = decode_bits(buf, total_decoded, 32, &decoded);
	total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_vol_thresh_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_vol_thresh_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_vol_thresh_ie_t(uint8_t *buf,
        pfcp_sbsqnt_vol_thresh_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_vol_thresh_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOTAL_VOLUME_COND_2(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_UPLINK_VOLUME_COND_2(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_DOWNLINK_VOLUME_COND_2(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_outer_hdr_removal_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_outer_hdr_removal_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_outer_hdr_removal_ie_t(uint8_t *buf,
        pfcp_outer_hdr_removal_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->outer_hdr_removal_desc = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
	/* TODO: Revisit this for change in yang */
    //value->gtpu_ext_hdr_del = decode_bits(buf, total_decoded, 8, &decoded);
    //total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_user_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_user_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_id_ie_t(uint8_t *buf,
		pfcp_user_id_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->user_id_spare = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->naif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->msisdnf = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->imeif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->imsif = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;


	/* TODO: Revisit this for change in yang */
	if(value->imsif == 1){
		value->length_of_imsi = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->imsi), buf + (total_decoded/CHAR_SIZE),value->length_of_imsi );
		total_decoded +=  value->length_of_imsi * CHAR_SIZE;
	}
	if(value->imeif == 1){
		value->length_of_imei = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->imei), buf + (total_decoded/CHAR_SIZE), value->length_of_imei);
		total_decoded +=  value->length_of_imei * CHAR_SIZE;
	}
	if(value->msisdnf ==1){
		value->len_of_msisdn = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&(value->msisdn), buf + (total_decoded/CHAR_SIZE), value->len_of_msisdn);
		total_decoded +=  value->len_of_msisdn * CHAR_SIZE;
	}
	if(value->naif == 1){
		value->length_of_nai = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
		memcpy(&value->nai, buf + (total_decoded/CHAR_SIZE), value->length_of_nai);
		total_decoded +=  value->length_of_nai * CHAR_SIZE;
	}



/*
	DECODE_LENGTH_OF_IMSI_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_IMSI_COND_1(buf, total_decoded, 64, decoded, value);
	total_decoded += decoded;
	DECODE_LENGTH_OF_IMEI_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_IMEI_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_LEN_OF_MSISDN_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_MSISDN_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_LENGTH_OF_NAI_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
	DECODE_NAI_COND_1(buf, total_decoded, 8, decoded, value);
	total_decoded += decoded;
*/
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dst_intfc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dst_intfc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dst_intfc_ie_t(uint8_t *buf,
        pfcp_dst_intfc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->dst_intfc_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->interface_value = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_ethertype_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_ethertype_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ethertype_ie_t(uint8_t *buf,
        pfcp_ethertype_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->ethertype = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_pdr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_pdr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdr_id_ie_t(uint8_t *buf,
        pfcp_pdr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->rule_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_frwdng_plcy_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_frwdng_plcy_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_frwdng_plcy_ie_t(uint8_t *buf,
        pfcp_frwdng_plcy_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->frwdng_plcy_ident_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->frwdng_plcy_ident = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_evnt_thresh_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_evnt_thresh_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_evnt_thresh_ie_t(uint8_t *buf,
        pfcp_sbsqnt_evnt_thresh_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_evnt_thresh = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_eth_pdu_sess_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_eth_pdu_sess_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_pdu_sess_info_ie_t(uint8_t *buf,
        pfcp_eth_pdu_sess_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->eth_pdu_sess_info_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->ethi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_ctag_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_ctag_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_ctag_ie_t(uint8_t *buf,
        pfcp_ctag_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->ctag_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->ctag_vid = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ctag_dei = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ctag_pcp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cvid_value = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ctag_dei_flag = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ctag_pcp_value = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    DECODE_CVID_VALUE2_COND_1(buf, total_decoded, 8, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dl_buf_suggstd_pckt_cnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dl_buf_suggstd_pckt_cnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(uint8_t *buf,
        pfcp_dl_buf_suggstd_pckt_cnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->pckt_cnt_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_user_plane_ip_rsrc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_user_plane_ip_rsrc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_user_plane_ip_rsrc_info_ie_t(uint8_t *buf,
		pfcp_user_plane_ip_rsrc_info_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->user_plane_ip_rsrc_info_spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->assosi = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->assoni = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->teidri = decode_bits(buf, total_decoded, 3, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;

	/* TODO: Revisit this for change in yang */
	if(value->teidri != 0) {
		value->teid_range = decode_bits(buf, total_decoded, 8, &decoded);
		total_decoded += decoded;
	}

	/* TODO: Revisit this for change in yang */
	DECODE_IPV4_ADDRESS_COND_4(buf, total_decoded, 32, decoded, value);
	//total_decoded += decoded;
	/* TODO: Revisit this for change in yang */
	DECODE_IPV6_ADDRESS_COND_4(buf, total_decoded, 8, decoded, value);
	//total_decoded += decoded;
	/* TODO: Revisit this for change in yang */
	DECODE_NTWK_INST_COND_1(buf, total_decoded, 8, decoded, value);
	//total_decoded += decoded;
	value->user_plane_ip_rsrc_info_spare2 = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	DECODE_SRC_INTFC_COND_1(buf, total_decoded, 4, decoded, value);
	/* TODO: Revisit this for change in yang */
	//total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_pdn_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_pdn_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pdn_type_ie_t(uint8_t *buf,
        pfcp_pdn_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->pdn_type_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->pdn_type = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sbsqnt_time_thresh_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sbsqnt_time_thresh_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sbsqnt_time_thresh_ie_t(uint8_t *buf,
        pfcp_sbsqnt_time_thresh_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sbsqnt_time_thresh = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_actvt_predef_rules_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_actvt_predef_rules_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_actvt_predef_rules_ie_t(uint8_t *buf,
		pfcp_actvt_predef_rules_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	/* uint16_t decoded = 0; */

	/* TODO: Revisit this for change in yang */
	// value->predef_rules_nm = decode_bits(buf, total_decoded, 8, &decoded);
	memcpy(&value->predef_rules_nm, buf + (total_decoded/CHAR_SIZE), 8);

	total_decoded += (8 * CHAR_SIZE);
/* TODO: Revisit this for change in yang */

	return total_decoded/CHAR_SIZE;

}

/**
* decodes pfcp_time_of_frst_pckt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_time_of_frst_pckt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_of_frst_pckt_ie_t(uint8_t *buf,
        pfcp_time_of_frst_pckt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_of_frst_pckt = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_cp_func_feat_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_cp_func_feat_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_cp_func_feat_ie_t(uint8_t *buf,
        pfcp_cp_func_feat_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sup_feat = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_rcvry_time_stmp_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_rcvry_time_stmp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rcvry_time_stmp_ie_t(uint8_t *buf,
        pfcp_rcvry_time_stmp_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->rcvry_time_stmp_val = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_report_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_report_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_report_type_ie_t(uint8_t *buf,
        pfcp_report_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->rpt_type_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->upir = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->erir = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->usar = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->dldr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_framed_route_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_framed_route_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_framed_route_ie_t(uint8_t *buf,
        pfcp_framed_route_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->framed_route = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_usage_rpt_trig_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_usage_rpt_trig_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_usage_rpt_trig_ie_t(uint8_t *buf,
        pfcp_usage_rpt_trig_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->immer = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->droth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->stopt = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->start = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->quhti = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->timth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->volth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->perio = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->eveth = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->macar = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->envcl = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->monit = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->termr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->liusa = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->timqu = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->volqu = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->usage_rpt_trig_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->evequ = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_trc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_trc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_trc_info_ie_t(uint8_t *buf,
        pfcp_trc_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->trace_id = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->len_of_trigrng_evnts = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->trigrng_evnts = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sess_trc_depth = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_list_of_intfcs = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->list_of_intfcs = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_ip_addr_of_trc_coll_ent = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ip_addr_of_trc_coll_ent = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_start_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_start_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_start_time_ie_t(uint8_t *buf,
        pfcp_start_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->start_time = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_src_intfc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_src_intfc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_src_intfc_ie_t(uint8_t *buf,
        pfcp_src_intfc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->src_intfc_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->interface_value = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_urr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_urr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_urr_id_ie_t(uint8_t *buf,
        pfcp_urr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->urr_id_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_sdf_filter_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_sdf_filter_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_sdf_filter_ie_t(uint8_t *buf,
        pfcp_sdf_filter_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->sdf_fltr_spare = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->bid = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->fl = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ttc = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->fd = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sdf_fltr_spare2 = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    DECODE_LEN_OF_FLOW_DESC_COND_1(buf, total_decoded, 16, decoded, value);
	if (value->fd){
		memcpy(&value->flow_desc, buf + (total_decoded/CHAR_SIZE), value->len_of_flow_desc );
		total_decoded += (value->len_of_flow_desc * CHAR_SIZE);
	}
    DECODE_TOS_TRAFFIC_CLS_COND_1(buf, total_decoded, 16, decoded, value);
    DECODE_SECUR_PARM_IDX_COND_1(buf, total_decoded, 32, decoded, value);
    DECODE_FLOW_LABEL_COND_1(buf, total_decoded, 24, decoded, value);
    DECODE_SDF_FILTER_ID_COND_1(buf, total_decoded, 32, decoded, value);
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_add_usage_rpts_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_add_usage_rpts_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_add_usage_rpts_info_ie_t(uint8_t *buf,
        pfcp_add_usage_rpts_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->auri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbr_of_add_usage_rpts_val = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->nbr_of_add_usage_rpts_value2 = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_pfcpsrrsp_flags_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_pfcpsrrsp_flags_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_pfcpsrrsp_flags_ie_t(uint8_t *buf,
        pfcp_pfcpsrrsp_flags_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->pfcpsrrsp_flgs_spare = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare5 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare6 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfcpsrrsp_flgs_spare7 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drobu = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_timer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_timer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_timer_ie_t(uint8_t *buf,
        pfcp_timer_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_mac_address_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_mac_address_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mac_address_ie_t(uint8_t *buf,
        pfcp_mac_address_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->udes = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->usou = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->dest = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sour = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_SRC_MAC_ADDR_VAL_COND_1(buf, total_decoded, 48, decoded, value);
    total_decoded += decoded;
    DECODE_DST_MAC_ADDR_VAL_COND_1(buf, total_decoded, 48, decoded, value);
    total_decoded += decoded;
    DECODE_UPR_SRC_MAC_ADDR_VAL_COND_1(buf, total_decoded, 48, decoded, value);
    total_decoded += decoded;
    DECODE_UPR_DST_MAC_ADDR_VAL_COND_1(buf, total_decoded, 48, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_outer_hdr_creation_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_outer_hdr_creation_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_outer_hdr_creation_ie_t(uint8_t *buf,
        pfcp_outer_hdr_creation_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
	value->outer_hdr_creation_desc = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
	value->teid = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    DECODE_IPV4_ADDRESS_COND_3(buf, total_decoded, 32, decoded, value);
    //total_decoded += decoded;
    DECODE_IPV6_ADDRESS_COND_3(buf, total_decoded, 8, decoded, value);
    //total_decoded += decoded;
    DECODE_PORT_NUMBER_COND_1(buf, total_decoded, 16, decoded, value);
    //total_decoded += decoded;
    DECODE_CTAG_COND_1(buf, total_decoded, 24, decoded, value);
    //total_decoded += decoded;
    DECODE_STAG_COND_1(buf, total_decoded, 24, decoded, value);
    //total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_fqcsid_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_fqcsid_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fqcsid_ie_t(uint8_t *buf,
		pfcp_fqcsid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->fqcsid_node_id_type = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	value->number_of_csids = decode_bits(buf, total_decoded, 4, &decoded);
	total_decoded += decoded;
	DECODE_NODE_ADDRESS_COND_1(buf, total_decoded, 32, decoded, value);
	total_decoded += decoded;
	/* TODO: Revisit this for change in yang */
	//DECODE_PDN_CONN_SET_IDENT_COND(buf, total_decoded, 16, decoded, value);
	//total_decoded += decoded;

	memcpy(&value->pdn_conn_set_ident, buf + (total_decoded/CHAR_SIZE), 2*(value->number_of_csids));
	total_decoded +=  2*(value->number_of_csids) * CHAR_SIZE;

	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_time_of_lst_pckt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_time_of_lst_pckt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_of_lst_pckt_ie_t(uint8_t *buf,
        pfcp_time_of_lst_pckt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_of_lst_pckt = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_rqi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_rqi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rqi_ie_t(uint8_t *buf,
        pfcp_rqi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->rqi_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->rqi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_vol_thresh_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_vol_thresh_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_vol_thresh_ie_t(uint8_t *buf,
        pfcp_vol_thresh_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->vol_thresh_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->dlvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ulvol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tovol = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_TOTAL_VOLUME_COND_1(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_UPLINK_VOLUME_COND_1(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    DECODE_DOWNLINK_VOLUME_COND_1(buf, total_decoded, 64, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_graceful_rel_period_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_graceful_rel_period_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_graceful_rel_period_ie_t(uint8_t *buf,
        pfcp_graceful_rel_period_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_qfi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_qfi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_qfi_ie_t(uint8_t *buf,
        pfcp_qfi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->qfi_spare = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->qfi_value = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_agg_urr_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_agg_urr_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_agg_urr_id_ie_t(uint8_t *buf,
        pfcp_agg_urr_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->urr_id_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_mbr_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_mbr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_mbr_ie_t(uint8_t *buf,
        pfcp_mbr_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->ul_mbr = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->dl_mbr = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_dnlnk_data_notif_delay_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_dnlnk_data_notif_delay_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_dnlnk_data_notif_delay_ie_t(uint8_t *buf,
        pfcp_dnlnk_data_notif_delay_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->delay_val_in_integer_multiples_of_50_millisecs_or_zero = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_avgng_wnd_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_avgng_wnd_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_avgng_wnd_ie_t(uint8_t *buf,
        pfcp_avgng_wnd_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->avgng_wnd = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_oci_flags_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_oci_flags_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_oci_flags_ie_t(uint8_t *buf,
        pfcp_oci_flags_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->oci_flags_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->aoci = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_time_threshold_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_time_threshold_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_time_threshold_ie_t(uint8_t *buf,
        pfcp_time_threshold_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->time_threshold = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_fseid_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_fseid_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_fseid_ie_t(uint8_t *buf,
		pfcp_fseid_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
	uint16_t decoded = 0;
	value->fseid_spare = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->fseid_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->fseid_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->fseid_spare4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->fseid_spare5 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->fseid_spare6 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
	total_decoded += decoded;
	value->v6 = decode_bits(buf, total_decoded, 1, &decoded);

	total_decoded += decoded;
	value->seid = decode_bits(buf, total_decoded, 64, &decoded);
	total_decoded += decoded;
	DECODE_IPV4_ADDRESS_COND_2(buf, total_decoded, 32, decoded, value);
	//total_decoded += decoded;
	DECODE_IPV6_ADDRESS_COND_2(buf, total_decoded, 8, decoded, value);

	/* TODO: Revisit this for change in yang */
	//total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_stag_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_stag_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_stag_ie_t(uint8_t *buf,
        pfcp_stag_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->stag_spare = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->stag_vid = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->stag_dei = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->stag_pcp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->svid_value = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->stag_dei_flag = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->stag_pcp_value = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    DECODE_SVID_VALUE2_COND_1(buf, total_decoded, 8, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_eth_inact_timer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_eth_inact_timer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_inact_timer_ie_t(uint8_t *buf,
        pfcp_eth_inact_timer_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->eth_inact_timer = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_meas_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_meas_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_meas_info_ie_t(uint8_t *buf,
        pfcp_meas_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->meas_info_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->istm = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->radi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->inam = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->mbqe = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_eth_fltr_props_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_eth_fltr_props_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_eth_fltr_props_ie_t(uint8_t *buf,
        pfcp_eth_fltr_props_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->eth_fltr_props_spare = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->bide = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes pfcp_rmt_gtpu_peer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    pfcp_rmt_gtpu_peer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_pfcp_rmt_gtpu_peer_ie_t(uint8_t *buf,
        pfcp_rmt_gtpu_peer_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_pfcp_ie_header_t(buf + (total_decoded/CHAR_SIZE), &value->header);
    uint16_t decoded = 0;
    value->rmt_gtpu_peer_spare = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    DECODE_IPV4_ADDRESS_COND_1(buf, total_decoded, 32, decoded, value);
    total_decoded += decoded;
    DECODE_IPV6_ADDRESS_COND_1(buf, total_decoded, 8, decoded, value);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

