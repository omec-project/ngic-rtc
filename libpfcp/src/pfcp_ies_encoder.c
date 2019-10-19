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

#include "../include/enc_dec_bits.h"

#include "../include/pfcp_cond_encoder.h"

/**
 * Encodes pfcp ie header to buffer.
 * @param value
 *     ie header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_ie_header_t(pfcp_ie_header_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_bits(value->type, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->len, 16, buf + (encoded/8), encoded % CHAR_SIZE);
	/*return encoded/CHAR_SIZE;*/
	return encoded;
}

/**
 * Encodes gtpc to buffer.
 * @param value
 *     gtpc
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_header_t(pfcp_header_t *value,
	uint8_t *buf)
{
	uint16_t encoded = 0;

	encoded += encode_bits(value->version, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->mp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->s, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->message_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->message_len, 16, buf + (encoded/8), encoded % CHAR_SIZE);

	if (value->s == 1) {
		encoded += encode_bits(value->seid_seqno.has_seid.seid, 64, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.seq_no, 24, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.has_seid.message_prio, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	} else {
		encoded += encode_bits(value->seid_seqno.no_seid.seq_no, 24, buf + (encoded/8), encoded % CHAR_SIZE);
		encoded += encode_bits(value->seid_seqno.no_seid.spare, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	}

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_end_time_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_end_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_end_time_ie_t(pfcp_end_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->end_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_trnspt_lvl_marking_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_trnspt_lvl_marking_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_trnspt_lvl_marking_ie_t(pfcp_trnspt_lvl_marking_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->tostraffic_cls, 16, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_failed_rule_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_failed_rule_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_failed_rule_id_ie_t(pfcp_failed_rule_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->failed_rule_id_spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->rule_id_type, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	//   encoded += encode_bits(value->rule_id_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */

	if(value->rule_id_type == RULE_ID_TYPE_PDR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 2);
		encoded +=  2* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_QER) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_URR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	} else if(value->rule_id_type == RULE_ID_TYPE_BAR) {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 1);
		encoded +=  1* CHAR_SIZE;
	}else {
		memcpy(buf + (encoded/CHAR_SIZE), &value->rule_id_value, 4);
		encoded +=  4* CHAR_SIZE;
	}//FAR is by default 3gpp 29.244 15.03 (8.2.80)
	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_vol_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_vol_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_vol_quota_ie_t(pfcp_sbsqnt_vol_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_vol_quota_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOTAL_VOLUME_COND_5(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPLINK_VOLUME_COND_5(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DOWNLINK_VOLUME_COND_5(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_eth_fltr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_eth_fltr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_fltr_id_ie_t(pfcp_eth_fltr_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->eth_fltr_id_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_mac_addrs_rmvd_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_mac_addrs_rmvd_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mac_addrs_rmvd_ie_t(pfcp_mac_addrs_rmvd_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->nbr_of_mac_addrs, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->mac_addr_val, MAC_ADDR_VAL_LEN);
    encoded += MAC_ADDR_VAL_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_linked_urr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_linked_urr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_linked_urr_id_ie_t(pfcp_linked_urr_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->lnkd_urr_id_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_evnt_time_stmp_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_evnt_time_stmp_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_evnt_time_stmp_ie_t(pfcp_evnt_time_stmp_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->evnt_time_stmp, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_mac_addrs_detctd_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	pfcp_mac_addrs_detctd_ie_t
 * @return
 *  number of encoded bytes.
 */
int encode_pfcp_mac_addrs_detctd_ie_t(pfcp_mac_addrs_detctd_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->nbr_of_mac_addrs, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/8), &value->mac_addr_val, MAC_ADDR_VAL_LEN);
	encoded += MAC_ADDR_VAL_LEN * CHAR_SIZE;

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_node_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
	pfcp_node_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_id_ie_t(pfcp_node_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->node_id_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->node_id_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */

	ENCODE_NODE_ID_VALUE_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_bar_id_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	pfcp_bar_id_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_bar_id_ie_t(pfcp_bar_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->bar_id_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded;
}


/**
* Encodes pfcp_usage_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_usage_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_info_ie_t(pfcp_usage_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->usage_info_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ube, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uae, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->aft, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bef, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_dnlnk_data_svc_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dnlnk_data_svc_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_svc_info_ie_t(pfcp_dnlnk_data_svc_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->dnlnk_data_svc_info_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->qfii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ppi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_data_svc_info_spare2, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    //ENCODE_PAGING_PLCY_INDCTN_VAL_COND_1(value, 6, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    encoded += encode_bits(value->paging_plcy_indctn_val, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_data_svc_info_spare3, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    //ENCODE_QFI_COND_1(value, 6, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    encoded += encode_bits(value->qfi, 6, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded;
}


/**
* Encodes pfcp_dur_meas_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dur_meas_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dur_meas_ie_t(pfcp_dur_meas_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->duration_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_up_assn_rel_req_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_up_assn_rel_req_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_up_assn_rel_req_ie_t(pfcp_up_assn_rel_req_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->up_assn_rel_req_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sarr, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_application_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_application_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_application_id_ie_t(pfcp_application_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	/* TODO: Revisit this for change in yang */
	memcpy(buf + (encoded/CHAR_SIZE), &value->app_ident, 8);
	encoded +=  8  * CHAR_SIZE;

//    encoded += encode_bits(value->app_ident, 8, buf + (encoded/8), encoded % CHAR_SIZE);
//
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_urseqn_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_urseqn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_urseqn_ie_t(pfcp_urseqn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->urseqn, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_dl_flow_lvl_marking_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dl_flow_lvl_marking_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_flow_lvl_marking_ie_t(pfcp_dl_flow_lvl_marking_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->dl_flow_lvl_marking_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ttc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOSTRAFFIC_CLS_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_SVC_CLS_INDCTR_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_ue_ip_address_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_ue_ip_address_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ue_ip_address_ie_t(pfcp_ue_ip_address_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->ue_ip_addr_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ipv6d, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->sd, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	ENCODE_IPV4_ADDRESS_COND_6(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV6_ADDRESS_COND_6(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV6_PFX_DLGTN_BITS_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	/* TODO: Revisit this for change in yang */
	return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_evnt_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_evnt_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_evnt_quota_ie_t(pfcp_sbsqnt_evnt_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_evnt_quota, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_gate_status_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_gate_status_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_gate_status_ie_t(pfcp_gate_status_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->gate_status_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ul_gate, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_gate, 2, buf + (encoded/8), encoded % CHAR_SIZE);

/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_suggstd_buf_pckts_cnt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_suggstd_buf_pckts_cnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_suggstd_buf_pckts_cnt_ie_t(pfcp_suggstd_buf_pckts_cnt_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->pckt_cnt_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded;
}


/**
* Encodes pfcp_pfd_contents_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pfd_contents_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfd_contents_ie_t(pfcp_pfd_contents_ie_t *value,
    uint8_t *buf)
{
    	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/8));
	encoded += encode_bits(value->pfd_contents_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pfd_contents_cp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dn, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->url, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fd, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	//encoded += encode_bits(value->pfd_contents_spare2, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	ENCODE_LEN_OF_FLOW_DESC_COND_2(value, 16, buf+(encoded/8), encoded % CHAR_SIZE, encoded);
	ENCODE_FLOW_DESC_COND_2(value, 8, buf+(encoded/8), encoded % CHAR_SIZE, encoded);

	ENCODE_LENGTH_OF_URL_COND_1(value, 16, buf+(encoded/8), encoded % CHAR_SIZE, encoded);
	ENCODE_URL2_COND_1(value, 8, buf+(encoded/8), encoded % CHAR_SIZE, encoded);

	ENCODE_LEN_OF_DOMAIN_NM_COND_1(value, 16, buf+(encoded/8), encoded % CHAR_SIZE, encoded);
	ENCODE_DOMAIN_NAME_COND_1(value, 8, buf+(encoded/8), encoded % CHAR_SIZE, encoded);

	ENCODE_LEN_OF_CSTM_PFD_CNTNT_COND_1(value, 16, (buf+(encoded/8)), encoded % CHAR_SIZE, encoded);

	return encoded;
}


/**
* Encodes pfcp_sequence_number_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sequence_number_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sequence_number_ie_t(pfcp_sequence_number_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sequence_number, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_packet_rate_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_packet_rate_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_packet_rate_ie_t(pfcp_packet_rate_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pckt_rate_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlpr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulpr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pckt_rate_spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_time_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_MAX_UPLNK_PCKT_RATE_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    encoded += encode_bits(value->pckt_rate_spare3, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_time_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_MAX_DNLNK_PCKT_RATE_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_hdr_enrchmt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_hdr_enrchmt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_hdr_enrchmt_ie_t(pfcp_hdr_enrchmt_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->hdr_enrchmt_spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->header_type, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->len_of_hdr_fld_nm, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->hdr_fld_nm, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->len_of_hdr_fld_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->hdr_fld_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_time_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_time_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_quota_ie_t(pfcp_time_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_quota_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_deact_predef_rules_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_deact_predef_rules_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_deact_predef_rules_ie_t(pfcp_deact_predef_rules_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->predef_rules_nm, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_apply_action_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_apply_action_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_apply_action_ie_t(pfcp_apply_action_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->apply_act_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->apply_act_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->apply_act_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->dupl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->nocp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->buff, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->forw, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->drop, 1, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded;
}


/**
* Encodes pfcp_node_rpt_type_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_node_rpt_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_node_rpt_type_ie_t(pfcp_node_rpt_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->node_rpt_type_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->upfr, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_fteid_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_fteid_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_fteid_ie_t(pfcp_fteid_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->fteid_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->chid, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ch, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	ENCODE_TEID_COND_2(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV4_ADDRESS_COND_5(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV6_ADDRESS_COND_5(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_CHOOSE_ID_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	/* TODO: Revisit this for change in yang */
	return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_meas_period_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_meas_period_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_period_ie_t(pfcp_meas_period_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->meas_period, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_up_func_feat_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	pfcp_up_func_feat_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_up_func_feat_ie_t(pfcp_up_func_feat_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->sup_feat, 16, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_inact_det_time_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_inact_det_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_inact_det_time_ie_t(pfcp_inact_det_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->inact_det_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_pfcpsmreq_flags_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pfcpsmreq_flags_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfcpsmreq_flags_ie_t(pfcp_pfcpsmreq_flags_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pfcpsmreq_flgs_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsmreq_flgs_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsmreq_flgs_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsmreq_flgs_spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsmreq_flgs_spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->qaurr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sndem, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drobu, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_meas_mthd_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_meas_mthd_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_mthd_ie_t(pfcp_meas_mthd_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->meas_mthd_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->meas_mthd_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->meas_mthd_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->meas_mthd_spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->meas_mthd_spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->event, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->volum, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->durat, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_paging_plcy_indctr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_paging_plcy_indctr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_paging_plcy_indctr_ie_t(pfcp_paging_plcy_indctr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->paging_plcy_indctr_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ppi_value, 3, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_framed_routing_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_framed_routing_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_framed_routing_ie_t(pfcp_framed_routing_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->framed_routing, 32, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_time_quota_mech_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_time_quota_mech_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_quota_mech_ie_t(pfcp_time_quota_mech_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_quota_mech_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->btit, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->base_time_int, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_quota_hldng_time_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_quota_hldng_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_quota_hldng_time_ie_t(pfcp_quota_hldng_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->quota_hldng_time_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_gbr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_gbr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_gbr_ie_t(pfcp_gbr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ul_gbr, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_gbr, 40, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_traffic_endpt_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_traffic_endpt_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_traffic_endpt_id_ie_t(pfcp_traffic_endpt_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->traffic_endpt_id_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
	return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_dl_buf_dur_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dl_buf_dur_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_buf_dur_ie_t(pfcp_dl_buf_dur_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_volume_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_volume_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_volume_quota_ie_t(pfcp_volume_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->vol_quota_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOTAL_VOLUME_COND_4(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPLINK_VOLUME_COND_4(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DOWNLINK_VOLUME_COND_4(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_event_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_event_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_event_quota_ie_t(pfcp_event_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_evnt_quota, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_query_urr_ref_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_query_urr_ref_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_query_urr_ref_ie_t(pfcp_query_urr_ref_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->query_urr_ref_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_time_quota_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_time_quota_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_time_quota_ie_t(pfcp_sbsqnt_time_quota_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_quota_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_qer_corr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_qer_corr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qer_corr_id_ie_t(pfcp_qer_corr_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->qer_corr_id_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_vol_meas_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_vol_meas_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_vol_meas_ie_t(pfcp_vol_meas_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->vol_meas_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOTAL_VOLUME_COND_3(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPLINK_VOLUME_COND_3(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DOWNLINK_VOLUME_COND_3(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_far_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_far_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_far_id_ie_t(pfcp_far_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->far_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
	return encoded;
}


/**
* Encodes pfcp_proxying_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_proxying_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_proxying_ie_t(pfcp_proxying_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->proxying_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->ins, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->arp, 1, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_rptng_triggers_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_rptng_triggers_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rptng_triggers_ie_t(pfcp_rptng_triggers_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->liusa, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->droth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stopt, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->start, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->quhti, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->volth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->perio, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rptng_triggers_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rptng_triggers_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->evequ, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->eveth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macar, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->envcl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->volqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_qer_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_qer_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qer_id_ie_t(pfcp_qer_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->qer_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
	return encoded;
}


/**
* Encodes pfcp_monitoring_time_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_monitoring_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_monitoring_time_ie_t(pfcp_monitoring_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->monitoring_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_flow_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_flow_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_flow_info_ie_t(pfcp_flow_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->flow_info_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->flow_direction, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_flow_desc, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->flow_desc, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_precedence_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_precedence_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_precedence_ie_t(pfcp_precedence_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->prcdnc_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

/* TODO: Revisit this for change in yang */
	return encoded;
}


/**
* Encodes pfcp_metric_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_metric_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_metric_ie_t(pfcp_metric_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->metric, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_multiplier_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_multiplier_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_multiplier_ie_t(pfcp_multiplier_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->value_digits, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->exponent, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_cause_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_cause_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_cause_ie_t(pfcp_cause_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->cause_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_offending_ie_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_offending_ie_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_offending_ie_ie_t(pfcp_offending_ie_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->type_of_the_offending_ie, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_ntwk_inst_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_ntwk_inst_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ntwk_inst_ie_t(pfcp_ntwk_inst_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	/* TODO: Revisit this for change in yang */
	//encoded += encode_bits(value->ntwk_inst, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	memcpy(buf + (encoded/CHAR_SIZE), &value->ntwk_inst, 32);
	encoded +=  32 * CHAR_SIZE;

	return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_redir_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_redir_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_redir_info_ie_t(pfcp_redir_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->redir_info_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->redir_addr_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->redir_svr_addr_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->redir_svr_addr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_event_threshold_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_event_threshold_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_event_threshold_ie_t(pfcp_event_threshold_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->event_threshold, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_app_inst_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_app_inst_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_app_inst_id_ie_t(pfcp_app_inst_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->app_inst_ident, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_drpd_dl_traffic_thresh_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_drpd_dl_traffic_thresh_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_drpd_dl_traffic_thresh_ie_t(pfcp_drpd_dl_traffic_thresh_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->drpd_dl_traffic_thresh_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlby, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlpa, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_DNLNK_PCKTS_COND_1(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_NBR_OF_BYTES_OF_DNLNK_DATA_COND_1(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_frmd_ipv6_rte_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_frmd_ipv6_rte_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_frmd_ipv6_rte_ie_t(pfcp_frmd_ipv6_rte_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->frmd_ipv6_rte, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_user_plane_inact_timer_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_user_plane_inact_timer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_plane_inact_timer_ie_t(pfcp_user_plane_inact_timer_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->user_plane_inact_timer, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_vol_thresh_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_vol_thresh_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_vol_thresh_ie_t(pfcp_sbsqnt_vol_thresh_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_vol_thresh_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOTAL_VOLUME_COND_2(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPLINK_VOLUME_COND_2(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DOWNLINK_VOLUME_COND_2(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_outer_hdr_removal_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_outer_hdr_removal_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_outer_hdr_removal_ie_t(pfcp_outer_hdr_removal_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->outer_hdr_removal_desc, 8, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
	//encoded += encode_bits(value->gtpu_ext_hdr_del, 8, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
	return encoded;///CHAR_SIZE;
}


/**
* Encodes pfcp_user_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_user_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_user_id_ie_t(pfcp_user_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->user_id_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->naif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->msisdnf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->imeif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->imsif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	ENCODE_LENGTH_OF_IMSI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IMSI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_LENGTH_OF_IMEI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IMEI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_LEN_OF_MSISDN_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_MSISDN_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_LENGTH_OF_NAI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_NAI_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_dst_intfc_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dst_intfc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dst_intfc_ie_t(pfcp_dst_intfc_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->dst_intfc_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->interface_value, 4, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded;
}


/**
* Encodes pfcp_ethertype_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_ethertype_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ethertype_ie_t(pfcp_ethertype_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ethertype, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_pdr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pdr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pdr_id_ie_t(pfcp_pdr_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rule_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
	return encoded;
}


/**
* Encodes pfcp_frwdng_plcy_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_frwdng_plcy_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_frwdng_plcy_ie_t(pfcp_frwdng_plcy_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->frwdng_plcy_ident_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->frwdng_plcy_ident, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_evnt_thresh_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_evnt_thresh_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_evnt_thresh_ie_t(pfcp_sbsqnt_evnt_thresh_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_evnt_thresh, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_eth_pdu_sess_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_eth_pdu_sess_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_pdu_sess_info_ie_t(pfcp_eth_pdu_sess_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->eth_pdu_sess_info_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ethi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_ctag_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_ctag_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_ctag_ie_t(pfcp_ctag_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ctag_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ctag_vid, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ctag_dei, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ctag_pcp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cvid_value, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ctag_dei_flag, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ctag_pcp_value, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_CVID_VALUE2_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_dl_buf_suggstd_pckt_cnt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dl_buf_suggstd_pckt_cnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dl_buf_suggstd_pckt_cnt_ie_t(pfcp_dl_buf_suggstd_pckt_cnt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pckt_cnt_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_user_plane_ip_rsrc_info_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_user_plane_ip_rsrc_info_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_user_plane_ip_rsrc_info_ie_t(pfcp_user_plane_ip_rsrc_info_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->user_plane_ip_rsrc_info_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->assosi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->assoni, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teidri, 3, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	/* TODO: Revisit this for change in yang */
	if(value->teidri != 0)
		encoded += encode_bits(value->teid_range, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	ENCODE_IPV4_ADDRESS_COND_4(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV6_ADDRESS_COND_4(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_NTWK_INST_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	encoded += encode_bits(value->user_plane_ip_rsrc_info_spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	ENCODE_SRC_INTFC_COND_1(value, 4, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_pdn_type_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_pdn_type_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_pdn_type_ie_t(pfcp_pdn_type_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->pdn_type_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->pdn_type, 3, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_sbsqnt_time_thresh_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sbsqnt_time_thresh_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sbsqnt_time_thresh_ie_t(pfcp_sbsqnt_time_thresh_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sbsqnt_time_thresh, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_actvt_predef_rules_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_actvt_predef_rules_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_actvt_predef_rules_ie_t(pfcp_actvt_predef_rules_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
//	encoded += encode_bits(value->predef_rules_nm, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
	for(int i =0;i < 8 ;i++)
			 encoded += encode_bits(value->predef_rules_nm[i], 8, buf + (encoded/8), encoded % CHAR_SIZE);


	return encoded;
}


/**
* Encodes pfcp_time_of_frst_pckt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_time_of_frst_pckt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_of_frst_pckt_ie_t(pfcp_time_of_frst_pckt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_of_frst_pckt, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_cp_func_feat_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_cp_func_feat_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_cp_func_feat_ie_t(pfcp_cp_func_feat_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->sup_feat, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_rcvry_time_stmp_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	 pfcp_rcvry_time_stmp_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_rcvry_time_stmp_ie_t(pfcp_rcvry_time_stmp_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->rcvry_time_stmp_val, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_report_type_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_report_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_report_type_ie_t(pfcp_report_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rpt_type_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->upir, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->erir, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->usar, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dldr, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_framed_route_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_framed_route_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_framed_route_ie_t(pfcp_framed_route_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->framed_route, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_usage_rpt_trig_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_usage_rpt_trig_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_usage_rpt_trig_ie_t(pfcp_usage_rpt_trig_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->immer, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->droth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stopt, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->start, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->quhti, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->volth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->perio, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->eveth, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macar, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->envcl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->monit, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->termr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->liusa, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->volqu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->usage_rpt_trig_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->evequ, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_trc_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_trc_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_trc_info_ie_t(pfcp_trc_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->trace_id, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_trigrng_evnts, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->trigrng_evnts, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sess_trc_depth, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_list_of_intfcs, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->list_of_intfcs, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_ip_addr_of_trc_coll_ent, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ip_addr_of_trc_coll_ent, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_start_time_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_start_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_start_time_ie_t(pfcp_start_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->start_time, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_src_intfc_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_src_intfc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_src_intfc_ie_t(pfcp_src_intfc_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->src_intfc_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->interface_value, 4, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
	return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_urr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_urr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_urr_id_ie_t(pfcp_urr_id_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->urr_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);

	/* TODO: Revisit this for change in yang */
	return encoded;
}


/**
* Encodes pfcp_sdf_filter_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_sdf_filter_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_sdf_filter_ie_t(pfcp_sdf_filter_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sdf_fltr_spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bid, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ttc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fd, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sdf_fltr_spare2, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_LEN_OF_FLOW_DESC_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	if (value->fd){
		memcpy(buf + (encoded/CHAR_SIZE), value->flow_desc, value->len_of_flow_desc);
		encoded +=  (value->len_of_flow_desc * CHAR_SIZE);
	}
    ENCODE_TOS_TRAFFIC_CLS_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_SECUR_PARM_IDX_COND_1(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_FLOW_LABEL_COND_1(value, 24, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_SDF_FILTER_ID_COND_1(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded;
}


/**
* Encodes pfcp_add_usage_rpts_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_add_usage_rpts_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_add_usage_rpts_info_ie_t(pfcp_add_usage_rpts_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->auri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_add_usage_rpts_val, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_add_usage_rpts_value2, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_pfcpsrrsp_flags_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_pfcpsrrsp_flags_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_pfcpsrrsp_flags_ie_t(pfcp_pfcpsrrsp_flags_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfcpsrrsp_flgs_spare7, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drobu, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_timer_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_timer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_timer_ie_t(pfcp_timer_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_mac_address_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_mac_address_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mac_address_ie_t(pfcp_mac_address_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->udes, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->usou, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dest, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sour, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_SRC_MAC_ADDR_VAL_COND_1(value, 48, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DST_MAC_ADDR_VAL_COND_1(value, 48, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPR_SRC_MAC_ADDR_VAL_COND_1(value, 48, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPR_DST_MAC_ADDR_VAL_COND_1(value, 48, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_outer_hdr_creation_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_outer_hdr_creation_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_outer_hdr_creation_ie_t(pfcp_outer_hdr_creation_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	ENCODE_OUTER_HDR_CREATION_DESC_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_TEID_COND_1(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV4_ADDRESS_COND_3(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
#if 0
	ENCODE_IPV6_ADDRESS_COND_3(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_PORT_NUMBER_COND_1(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_CTAG_COND_1(value, 24, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_STAG_COND_1(value, 24, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
#endif
	return encoded;
}


/**
 * Encodes pfcp_fqcsid_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
 pfcp_fqcsid_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_fqcsid_ie_t(pfcp_fqcsid_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->fqcsid_node_id_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->number_of_csids, 4, buf + (encoded/8), encoded % CHAR_SIZE);

	/*TODO: Revisit this for change in yang */
	ENCODE_NODE_ADDRESS_COND_1(value, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	//TODO: Revisit this for change in yang

	for(int i =0; i < value->number_of_csids ;i++)
		encoded += encode_bits(value-> pdn_conn_set_ident[i], 16, buf + (encoded/8), encoded % CHAR_SIZE);

	//ENCODE_PDN_CONN_SET_IDENT_COND(value, 16, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_time_of_lst_pckt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_time_of_lst_pckt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_of_lst_pckt_ie_t(pfcp_time_of_lst_pckt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_of_lst_pckt, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_rqi_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_rqi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rqi_ie_t(pfcp_rqi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rqi_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rqi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_vol_thresh_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_vol_thresh_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_vol_thresh_ie_t(pfcp_vol_thresh_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->vol_thresh_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dlvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ulvol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tovol, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_TOTAL_VOLUME_COND_1(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_UPLINK_VOLUME_COND_1(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_DOWNLINK_VOLUME_COND_1(value, 64, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_graceful_rel_period_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_graceful_rel_period_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_graceful_rel_period_ie_t(pfcp_graceful_rel_period_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_qfi_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_qfi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_qfi_ie_t(pfcp_qfi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->qfi_spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->qfi_value, 6, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded; //CHAR_SIZE;
}


/**
* Encodes pfcp_agg_urr_id_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_agg_urr_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_agg_urr_id_ie_t(pfcp_agg_urr_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->urr_id_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_mbr_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_mbr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_mbr_ie_t(pfcp_mbr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ul_mbr, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_mbr, 40, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_dnlnk_data_notif_delay_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_dnlnk_data_notif_delay_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_dnlnk_data_notif_delay_ie_t(pfcp_dnlnk_data_notif_delay_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
	encoded += encode_bits(value->delay_val_in_integer_multiples_of_50_millisecs_or_zero, 8, buf + (encoded/8), encoded % CHAR_SIZE);

	return encoded;
}


/**
* Encodes pfcp_avgng_wnd_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_avgng_wnd_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_avgng_wnd_ie_t(pfcp_avgng_wnd_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->avgng_wnd, 32, buf + (encoded/8), encoded % CHAR_SIZE);
/* TODO: Revisit this for change in yang */
    return encoded;//CHAR_SIZE;
}


/**
* Encodes pfcp_oci_flags_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_oci_flags_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_oci_flags_ie_t(pfcp_oci_flags_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->oci_flags_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->aoci, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_time_threshold_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_time_threshold_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_time_threshold_ie_t(pfcp_time_threshold_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_threshold, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
 * Encodes pfcp_fseid_ie_t to buffer.
 * @param buf
 *   buffer to store encoded values.
 * @param value
	pfcp_fseid_ie_t
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_fseid_ie_t(pfcp_fseid_ie_t *value,
		uint8_t *buf)
{
	uint16_t encoded = 0;
	encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

	encoded += encode_bits(value->fseid_spare, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fseid_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fseid_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fseid_spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fseid_spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->fseid_spare6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->seid, 64, buf + (encoded/8), encoded % CHAR_SIZE);
	ENCODE_IPV4_ADDRESS_COND_2(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
	ENCODE_IPV6_ADDRESS_COND_2(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

	return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_stag_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_stag_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_stag_ie_t(pfcp_stag_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->stag_spare, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stag_vid, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stag_dei, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stag_pcp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->svid_value, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stag_dei_flag, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->stag_pcp_value, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_SVID_VALUE2_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_eth_inact_timer_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_eth_inact_timer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_inact_timer_ie_t(pfcp_eth_inact_timer_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->eth_inact_timer, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_meas_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_meas_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_meas_info_ie_t(pfcp_meas_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->meas_info_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->istm, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->radi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->inam, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mbqe, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_eth_fltr_props_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_eth_fltr_props_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_eth_fltr_props_ie_t(pfcp_eth_fltr_props_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->eth_fltr_props_spare, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bide, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes pfcp_rmt_gtpu_peer_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pfcp_rmt_gtpu_peer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_pfcp_rmt_gtpu_peer_ie_t(pfcp_rmt_gtpu_peer_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_pfcp_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rmt_gtpu_peer_spare, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    ENCODE_IPV4_ADDRESS_COND_1(value, 32, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);
    ENCODE_IPV6_ADDRESS_COND_1(value, 8, buf+(encoded)/8, encoded % CHAR_SIZE, encoded);

    return encoded/CHAR_SIZE;
}

