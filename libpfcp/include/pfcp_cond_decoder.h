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


#ifndef __PFCP_COND_DECODER_H__
#define __PFCP_COND_DECODER_H__

#include "pfcp_enum.h"

/* Inside pfcp_fteid_ie_t */
/* TODO: Revisit this for change in yang */
#define DECODE_TEID_COND_2(buf, total_decoded, bit_count, decoded, value) \
	if (value->ch == 0) \
{ \
	memcpy(&value->teid, buf + (total_decoded/CHAR_SIZE), 4); \
	total_decoded += 4 * CHAR_SIZE; \
}

/* Inside pfcp_ue_ip_address_ie_t */
#define DECODE_IPV4_ADDRESS_COND_6(buf, total_decoded, bit_count, decoded, value) \
	if (value->v4 ) \
{ \
	memcpy(&value->ipv4_address, buf + (total_decoded/CHAR_SIZE), 4); \
	total_decoded += 4 * CHAR_SIZE; \
}

/* Inside pfcp_ue_ip_address_ie_t */
#define DECODE_IPV6_ADDRESS_COND_6(buf, total_decoded, bit_count, decoded, value) \
	if (value->v6 ) \
{ \
	memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
	total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE; \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_fteid_ie_t */
#define DECODE_CHOOSE_ID_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->ch) \
{ \
	value->choose_id += decode_bits(buf, total_decoded, bit_count, &decoded); \
	total_decoded += decoded; \
}

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_LEN_OF_FLOW_DESC_COND_2(buf, total_decoded, bit_count, decoded, value) \
	if (value->fd) \
{ \
	value->len_of_flow_desc += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_LEN_OF_FLOW_DESC_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->fd) \
    { \
        value->len_of_flow_desc += decode_bits(buf, total_decoded, bit_count, &decoded); \
        total_decoded += decoded;\
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_FLOW_DESC_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->fd) \
    { \
        value->flow_desc += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_TOS_TRAFFIC_CLS_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ttc) \
    { \
        value->tos_traffic_cls += decode_bits(buf, total_decoded, bit_count, &decoded); \
        total_decoded += decoded; \
    }

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_SECUR_PARM_IDX_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->spi) \
    { \
        value->secur_parm_idx += decode_bits(buf, total_decoded, bit_count, &decoded); \
        total_decoded += decoded;\
    }

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_FLOW_LABEL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->fl) \
    { \
        value->flow_label += decode_bits(buf, total_decoded, bit_count, &decoded); \
        total_decoded += decoded;\
    }

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_SDF_FILTER_ID_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->bid) \
    { \
        value->sdf_filter_id += decode_bits(buf, total_decoded, bit_count, &decoded); \
        total_decoded += decoded;\
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_TOTAL_VOLUME_COND_5(buf, total_decoded, bit_count, decoded, value) \
    if (value->tovol) \
    { \
        value->total_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_UPLINK_VOLUME_COND_5(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulvol) \
    { \
        value->uplink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_DOWNLINK_VOLUME_COND_5(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlvol) \
    { \
        value->downlink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_volume_quota_ie_t */
#define DECODE_TOTAL_VOLUME_COND_4(buf, total_decoded, bit_count, decoded, value) \
    if (value->tovol) \
    { \
        value->total_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_volume_quota_ie_t */
#define DECODE_UPLINK_VOLUME_COND_4(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulvol) \
    { \
        value->uplink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_volume_quota_ie_t */
#define DECODE_DOWNLINK_VOLUME_COND_4(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlvol) \
    { \
        value->downlink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_dnlnk_data_svc_info_ie_t */
#define DECODE_PAGING_PLCY_INDCTN_VAL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ppi) \
    { \
        value->paging_plcy_indctn_val += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_dnlnk_data_svc_info_ie_t */
#define DECODE_QFI_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->qfii) \
    { \
        value->qfi += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_fteid_ie_t */
#define DECODE_IPV4_ADDRESS_COND_5(buf, total_decoded, bit_count, decoded, value) \
    if (value->v4 && value->ch == 0) \
    { \
        memcpy(&value->ipv4_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
        total_decoded +=  4 * CHAR_SIZE; \
    }

/* Inside pfcp_fteid_ie_t */
#define DECODE_IPV6_ADDRESS_COND_5(buf, total_decoded, bit_count, decoded, value) \
    if (value->v6 && value->ch == 0) \
    { \
        memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
        total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE; \
    }
/* Inside pfcp_node_id_ie_t */
#define DECODE_NODE_ID_VALUE_COND_1(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* Inside pfcp_sdf_filter_ie_t */
#define DECODE_FLOW_DESC_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->fd) \
    { \
        value->flow_desc += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_LENGTH_OF_URL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->url) \
    { \
        value->length_of_url += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_URL2_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->url) \
    { \
        value->url2 += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_LEN_OF_DOMAIN_NM_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dn) \
    { \
        value->len_of_domain_nm += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_DOMAIN_NAME_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dn) \
    { \
        value->domain_name += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_LEN_OF_CSTM_PFD_CNTNT_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->pfd_contents_cp) \
{ \
	value->len_of_cstm_pfd_cntnt += decode_bits(buf, total_decoded, bit_count, &decoded); \
	total_decoded += decoded;\
	value->cstm_pfd_cntnt = malloc(value->len_of_cstm_pfd_cntnt); \
	memcpy(value->cstm_pfd_cntnt, buf +(total_decoded/CHAR_SIZE), value->len_of_cstm_pfd_cntnt); \
	total_decoded += value->len_of_cstm_pfd_cntnt * CHAR_SIZE; \
}

/* Inside pfcp_pfd_contents_ie_t */
#define DECODE_CSTM_PFD_CNTNT_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->pfd_contents_cp) \
{ \
	value->cstm_pfd_cntnt += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_fqcsid_ie_t */
#define DECODE_NODE_ADDRESS_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if(value->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST ) \
{ \
	memcpy(value->node_address, buf, 4); \
	decoded = 4 * CHAR_SIZE; \
}


/* Inside pfcp_fqcsid_ie_t */
#define DECODE_PDN_CONN_SET_IDENT_COND(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* Inside pfcp_vol_meas_ie_t */
#define DECODE_TOTAL_VOLUME_COND_3(buf, total_decoded, bit_count, decoded, value) \
    if (value->tovol) \
    { \
        value->total_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_vol_meas_ie_t */
#define DECODE_UPLINK_VOLUME_COND_3(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulvol) \
    { \
        value->uplink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_vol_meas_ie_t */
#define DECODE_DOWNLINK_VOLUME_COND_3(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlvol) \
    { \
        value->downlink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_drpd_dl_traffic_thresh_ie_t */
#define DECODE_DNLNK_PCKTS_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlpa) \
    { \
        value->dnlnk_pckts += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_drpd_dl_traffic_thresh_ie_t */
#define DECODE_NBR_OF_BYTES_OF_DNLNK_DATA_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlby) \
    { \
        value->nbr_of_bytes_of_dnlnk_data += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_TOTAL_VOLUME_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->tovol) \
    { \
        value->total_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_UPLINK_VOLUME_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulvol) \
    { \
        value->uplink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define DECODE_DOWNLINK_VOLUME_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlvol) \
    { \
        value->downlink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_OUTER_HDR_CREATION_DESC_COND_1(buf, total_decoded, bit_count, decoded, value) \
{\
	value->outer_hdr_creation_desc += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_TEID_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->outer_hdr_creation_desc) \
{ \
	memcpy(&value->teid, buf + (total_decoded/CHAR_SIZE), 4); \
	total_decoded += 4 * CHAR_SIZE; \
}

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define DECODE_IPV4_ADDRESS_COND_4(buf, total_decoded, bit_count, decoded, value) \
    if (value->v4) \
    { \
        value->ipv4_address += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define DECODE_IPV6_ADDRESS_COND_4(buf, total_decoded, bit_count, decoded, value) \
    if (value->v6) \
    { \
        memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
        total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE; \
    }

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_PORT_NUMBER_COND_1(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_CTAG_COND_1(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_STAG_COND_1(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* Inside pfcp_outer_hdr_creation_ie_t */
//if (value->outer_hdr_creation_desc)
#define DECODE_IPV4_ADDRESS_COND_3(buf, total_decoded, bit_count, decoded, value) \
if (1) \
{ \
	value->ipv4_address = decode_bits(buf, total_decoded, bit_count, &decoded); \
	total_decoded += decoded; \
}

/* Inside pfcp_outer_hdr_creation_ie_t */
#define DECODE_IPV6_ADDRESS_COND_3(buf, total_decoded, bit_count, decoded, value) \
    /* To check */

/* TODO: Revisit this for change in yang */
/* Inside pfcp_ue_ip_address_ie_t */
#define DECODE_IPV6_PFX_DLGTN_BITS_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->ipv6d) \
{ \
	value->ipv6_pfx_dlgtn_bits += decode_bits(buf, total_decoded, bit_count, &decoded); \
	total_decoded += decoded; \
}

/* Inside pfcp_packet_rate_ie_t */
#define DECODE_MAX_UPLNK_PCKT_RATE_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulpr) \
    { \
        value->max_uplnk_pckt_rate += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* Inside pfcp_packet_rate_ie_t */
#define DECODE_MAX_DNLNK_PCKT_RATE_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlpr) \
    { \
        value->max_dnlnk_pckt_rate += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* Inside pfcp_dl_flow_lvl_marking_ie_t */
#define DECODE_TOSTRAFFIC_CLS_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ttc) \
    { \
        value->tostraffic_cls += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* Inside pfcp_dl_flow_lvl_marking_ie_t */
#define DECODE_SVC_CLS_INDCTR_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->sci) \
    { \
        value->svc_cls_indctr += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* TODO: Revisit this for change in yang */
/* Inside pfcp_fseid_ie_t */
#define DECODE_IPV4_ADDRESS_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->v4) \
    { \
		memcpy(&value->ipv4_address, buf + (total_decoded/CHAR_SIZE), 4); \
		total_decoded += 4 * CHAR_SIZE; \
    }

/* Inside pfcp_fseid_ie_t */
#define DECODE_IPV6_ADDRESS_COND_2(buf, total_decoded, bit_count, decoded, value) \
    if (value->v6) \
    { \
        memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
        total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE; \
    }

/* Inside pfcp_rmt_gtpu_peer_ie_t */
#define DECODE_IPV4_ADDRESS_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->v4) \
    { \
        value->ipv4_address += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_rmt_gtpu_peer_ie_t */
#define DECODE_IPV6_ADDRESS_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->v6) \
    { \
        memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN); \
        total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE; \
    }

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define DECODE_NTWK_INST_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->assoni) \
    { \
        value->ntwk_inst += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded; \
    }

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define DECODE_SRC_INTFC_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->assosi) \
    { \
        value->src_intfc += decode_bits(buf, total_decoded, bit_count, &decoded); \
		total_decoded += decoded;\
    }
/* Inside pfcp_vol_thresh_ie_t */
#define DECODE_TOTAL_VOLUME_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->tovol) \
    { \
        value->total_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_vol_thresh_ie_t */
#define DECODE_UPLINK_VOLUME_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ulvol) \
    { \
        value->uplink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_vol_thresh_ie_t */
#define DECODE_DOWNLINK_VOLUME_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dlvol) \
    { \
        value->downlink_volume += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_mac_address_ie_t */
#define DECODE_SRC_MAC_ADDR_VAL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->sour) \
    { \
        value->src_mac_addr_val += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_mac_address_ie_t */
#define DECODE_DST_MAC_ADDR_VAL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->dest) \
    { \
        value->dst_mac_addr_val += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_mac_address_ie_t */
#define DECODE_UPR_SRC_MAC_ADDR_VAL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->usou) \
    { \
        value->upr_src_mac_addr_val += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_mac_address_ie_t */
#define DECODE_UPR_DST_MAC_ADDR_VAL_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->udes) \
    { \
        value->upr_dst_mac_addr_val += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_ctag_ie_t */
#define DECODE_CVID_VALUE2_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->ctag_vid) \
    { \
        value->cvid_value2 += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_stag_ie_t */
#define DECODE_SVID_VALUE2_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->stag_vid) \
    { \
        value->svid_value2 += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* Inside pfcp_user_id_ie_t */
#define DECODE_LENGTH_OF_IMSI_COND_1(buf, total_decoded, bit_count, decoded, value) \
    if (value->imsif) \
    { \
        value->length_of_imsi += decode_bits(buf, total_decoded, bit_count, &decoded); \
    }

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define DECODE_IMSI_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->imsif) \
{ \
	memcpy(&(value->imsi), buf + (total_decoded/CHAR_SIZE),value->length_of_imsi ); \
	decoded = value->length_of_imsi * CHAR_SIZE; \
}

/* Inside pfcp_user_id_ie_t */
#define DECODE_LENGTH_OF_IMEI_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->imeif) \
{ \
	value->length_of_imei += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define DECODE_IMEI_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->imeif) \
{ \
	memcpy(&(value->imei), buf + (total_decoded/CHAR_SIZE), value->length_of_imei); \
}

/* Inside pfcp_user_id_ie_t */
#define DECODE_LEN_OF_MSISDN_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->msisdnf) \
{ \
	value->len_of_msisdn += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define DECODE_MSISDN_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->msisdnf) \
{ \
	memcpy(&(value->msisdn), buf + (total_decoded/CHAR_SIZE), value->len_of_msisdn); \
}

/* Inside pfcp_user_id_ie_t */
#define DECODE_LENGTH_OF_NAI_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->naif) \
{ \
	value->length_of_nai += decode_bits(buf, total_decoded, bit_count, &decoded); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define DECODE_NAI_COND_1(buf, total_decoded, bit_count, decoded, value) \
	if (value->naif) \
{ \
	memcpy(&value->nai, buf + (total_decoded/CHAR_SIZE), value->length_of_nai); \
}

#endif /*__PFCP_COND_DECODER_H__*/
