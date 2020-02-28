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


#ifndef __PFCP_COND_ENCODER_H__
#define __PFCP_COND_ENCODER_H__

#include "pfcp_enum.h"

/* Inside pfcp_fteid_ie_t */
#define ENCODE_TEID_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->ch == 0) \
{ \
	encoded += encode_bits(value->teid, bit_count, destination, offset); \
}

/* Inside pfcp_ue_ip_address_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_6(value, bit_count, destination, offset, encoded) \
	if (value->v4) \
{ \
	encoded += encode_bits(value->ipv4_address, bit_count, destination, offset); \
}

/* Inside pfcp_ue_ip_address_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_6(value, bit_count, destination, offset, encoded) \
	if (value->v6) \
{ \
	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN); \
	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE; \
}

/* Inside pfcp_fteid_ie_t */
#define ENCODE_CHOOSE_ID_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ch) \
{ \
	encoded += encode_bits(value->choose_id, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_LEN_OF_FLOW_DESC_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->fd) \
{ \
	encoded += encode_bits(value->len_of_flow_desc, bit_count, destination, offset); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_LEN_OF_FLOW_DESC_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->fd) \
{ \
	encoded += encode_bits(value->len_of_flow_desc, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_FLOW_DESC_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->fd) \
{ \
	encoded += encode_bits(value->flow_desc, bit_count, destination, offset); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_TOS_TRAFFIC_CLS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ttc) \
{ \
	encoded += encode_bits(value->tos_traffic_cls, bit_count, destination, offset); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_SECUR_PARM_IDX_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->spi) \
{ \
	encoded += encode_bits(value->secur_parm_idx, bit_count, destination, offset); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_FLOW_LABEL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->fl) \
{ \
	encoded += encode_bits(value->flow_label, bit_count, destination, offset); \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_SDF_FILTER_ID_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->bid) \
{ \
	encoded += encode_bits(value->sdf_filter_id, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_TOTAL_VOLUME_COND_5(value, bit_count, destination, offset, encoded) \
	if (value->tovol) \
{ \
	encoded += encode_bits(value->total_volume, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_UPLINK_VOLUME_COND_5(value, bit_count, destination, offset, encoded) \
	if (value->ulvol) \
{ \
	encoded += encode_bits(value->uplink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_DOWNLINK_VOLUME_COND_5(value, bit_count, destination, offset, encoded) \
	if (value->dlvol) \
{ \
	encoded += encode_bits(value->downlink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_volume_quota_ie_t */
#define ENCODE_TOTAL_VOLUME_COND_4(value, bit_count, destination, offset, encoded) \
	if (value->tovol) \
{ \
	encoded += encode_bits(value->total_volume, bit_count, destination, offset); \
}

/* Inside pfcp_volume_quota_ie_t */
#define ENCODE_UPLINK_VOLUME_COND_4(value, bit_count, destination, offset, encoded) \
	if (value->ulvol) \
{ \
	encoded += encode_bits(value->uplink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_volume_quota_ie_t */
#define ENCODE_DOWNLINK_VOLUME_COND_4(value, bit_count, destination, offset, encoded) \
	if (value->dlvol) \
{ \
	encoded += encode_bits(value->downlink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_dnlnk_data_svc_info_ie_t */
#define ENCODE_PAGING_PLCY_INDCTN_VAL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ppi) \
{ \
	encoded += encode_bits(value->paging_plcy_indctn_val, bit_count, destination, offset); \
}

/* Inside pfcp_dnlnk_data_svc_info_ie_t */
#define ENCODE_QFI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->qfii) \
{ \
	encoded += encode_bits(value->qfi, bit_count, destination, offset); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_fteid_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_5(value, bit_count, destination, offset, encoded) \
	if (value->v4 && value->ch == 0) \
{ \
	memcpy(buf + (encoded/8), &value->ipv4_address, 4); \
	encoded += 4 * CHAR_SIZE; \
}

/* Inside pfcp_fteid_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_5(value, bit_count, destination, offset, encoded) \
	if (value->v6 && value->ch == 0) \
{ \
	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN); \
	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE; \
}
/* Inside pfcp_node_id_ie_t */
/* TODO: Revisit this for change in yang */
#define ENCODE_NODE_ID_VALUE_COND_1(value, bit_count, destination, offset, encoded) \
	if(value->node_id_type == 0) \
{ \
	memcpy(buf + (encoded/8), &value->node_id_value, 4); \
	encoded +=  4 * CHAR_SIZE; \
}

/* Inside pfcp_sdf_filter_ie_t */
#define ENCODE_FLOW_DESC_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->fd) \
{ \
	encoded += encode_bits(value->flow_desc, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_LENGTH_OF_URL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->url) \
{ \
	encoded += encode_bits(value->length_of_url, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_URL2_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->url) \
{ \
	encoded += encode_bits(value->url2, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_LEN_OF_DOMAIN_NM_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dn) \
{ \
	encoded += encode_bits(value->len_of_domain_nm, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_DOMAIN_NAME_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dn) \
{ \
	encoded += encode_bits(value->domain_name, bit_count, destination, offset); \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_LEN_OF_CSTM_PFD_CNTNT_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->pfd_contents_cp) \
{ \
	encoded += encode_bits(value->len_of_cstm_pfd_cntnt, bit_count, destination, offset); \
	memcpy(buf+ (encoded/CHAR_SIZE), (char *)value->cstm_pfd_cntnt, value->len_of_cstm_pfd_cntnt); \
	encoded += value->len_of_cstm_pfd_cntnt * 8; \
}

/* Inside pfcp_pfd_contents_ie_t */
#define ENCODE_CSTM_PFD_CNTNT_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->pfd_contents_cp) \
{ \
	encoded += encode_bits(value->cstm_pfd_cntnt, bit_count, destination, offset); \
}

/* Inside pfcp_fqcsid_ie_t */
//TODO: Revisit this for change in yang
#define ENCODE_NODE_ADDRESS_COND_1(value, destination, offset, encoded) \
	 if (value->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) \
{  \
	memcpy(buf + (encoded/8), &value->node_address, 4); \
	encoded +=  4 * CHAR_SIZE; \
}


//TODO: Revisit this for change in yang
//Dont require this condition
/* Inside pfcp_fqcsid_ie_t */
#define ENCODE_PDN_CONN_SET_IDENT_COND(value, bit_count, destination, offset, encoded) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
}

/* Inside pfcp_vol_meas_ie_t */
#define ENCODE_TOTAL_VOLUME_COND_3(value, bit_count, destination, offset, encoded) \
	if (value->tovol) \
{ \
	encoded += encode_bits(value->total_volume, bit_count, destination, offset); \
}

/* Inside pfcp_vol_meas_ie_t */
#define ENCODE_UPLINK_VOLUME_COND_3(value, bit_count, destination, offset, encoded) \
	if (value->ulvol) \
{ \
	encoded += encode_bits(value->uplink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_vol_meas_ie_t */
#define ENCODE_DOWNLINK_VOLUME_COND_3(value, bit_count, destination, offset, encoded) \
	if (value->dlvol) \
{ \
	encoded += encode_bits(value->downlink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_drpd_dl_traffic_thresh_ie_t */
#define ENCODE_DNLNK_PCKTS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dlpa) \
{ \
	encoded += encode_bits(value->dnlnk_pckts, bit_count, destination, offset); \
}

/* Inside pfcp_drpd_dl_traffic_thresh_ie_t */
#define ENCODE_NBR_OF_BYTES_OF_DNLNK_DATA_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dlby) \
{ \
	encoded += encode_bits(value->nbr_of_bytes_of_dnlnk_data, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_TOTAL_VOLUME_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->tovol) \
{ \
	encoded += encode_bits(value->total_volume, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_UPLINK_VOLUME_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->ulvol) \
{ \
	encoded += encode_bits(value->uplink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_sbsqnt_vol_thresh_ie_t */
#define ENCODE_DOWNLINK_VOLUME_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->dlvol) \
{ \
	encoded += encode_bits(value->downlink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_OUTER_HDR_CREATION_DESC_COND_1(value, bit_count, destination, offset, encoded) \
{ \
	encoded += encode_bits(value->outer_hdr_creation_desc, bit_count, destination, offset); \
}

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_TEID_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->outer_hdr_creation_desc)\
{ \
	encoded += encode_bits(value->teid, bit_count, destination, offset); \
}
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->teid, bit_count, destination, offset); \
}*/

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_4(value, bit_count, destination, offset, encoded) \
	if (value->v4) \
{ \
	encoded += encode_bits(value->ipv4_address, bit_count, destination, offset); \
}

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_4(value, bit_count, destination, offset, encoded) \
	if (value->v6) \
{ \
	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN); \
	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE; \
}

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_PORT_NUMBER_COND_1(value, bit_count, destination, offset, encoded) \
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
} */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_CTAG_COND_1(value, bit_count, destination, offset, encoded) \
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
} */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_STAG_COND_1(value, bit_count, destination, offset, encoded) \
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
} */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_3(value, bit_count, destination, offset, encoded) \
	if (1)\
{ \
	encoded += encode_bits(value->ipv4_address, bit_count, destination, offset); \
}
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
} */

/* Inside pfcp_outer_hdr_creation_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_3(value, bit_count, destination, offset, encoded) \
	/* To check */
/* if (value->) \
{ \
	encoded += encode_bits(value->, bit_count, destination, offset); \
} */

/* Inside pfcp_ue_ip_address_ie_t */
#define ENCODE_IPV6_PFX_DLGTN_BITS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ipv6d) \
{ \
	encoded += encode_bits(value->ipv6_pfx_dlgtn_bits, bit_count, destination, offset); \
}

/* Inside pfcp_packet_rate_ie_t */
#define ENCODE_MAX_UPLNK_PCKT_RATE_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ulpr) \
{ \
	encoded += encode_bits(value->max_uplnk_pckt_rate, bit_count, destination, offset); \
}

/* Inside pfcp_packet_rate_ie_t */
#define ENCODE_MAX_DNLNK_PCKT_RATE_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dlpr) \
{ \
	encoded += encode_bits(value->max_dnlnk_pckt_rate, bit_count, destination, offset); \
}

/* Inside pfcp_dl_flow_lvl_marking_ie_t */
#define ENCODE_TOSTRAFFIC_CLS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ttc) \
{ \
	encoded += encode_bits(value->tostraffic_cls, bit_count, destination, offset); \
}

/* Inside pfcp_dl_flow_lvl_marking_ie_t */
#define ENCODE_SVC_CLS_INDCTR_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->sci) \
{ \
	encoded += encode_bits(value->svc_cls_indctr, bit_count, destination, offset); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_fseid_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->v4) \
{ \
	memcpy(buf + (encoded/8), &value->ipv4_address, 4); \
	encoded +=  4 * CHAR_SIZE; \
}

/* Inside pfcp_fseid_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_2(value, bit_count, destination, offset, encoded) \
	if (value->v6) \
{ \
	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN); \
	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE; \
}

/* Inside pfcp_rmt_gtpu_peer_ie_t */
#define ENCODE_IPV4_ADDRESS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->v4) \
{ \
	encoded += encode_bits(value->ipv4_address, bit_count, destination, offset); \
}

/* Inside pfcp_rmt_gtpu_peer_ie_t */
#define ENCODE_IPV6_ADDRESS_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->v6) \
{ \
	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN); \
	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE; \
}

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define ENCODE_NTWK_INST_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->assoni) \
{ \
	encoded += encode_bits(value->ntwk_inst, bit_count, destination, offset); \
}

/* Inside pfcp_user_plane_ip_rsrc_info_ie_t */
#define ENCODE_SRC_INTFC_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->assosi) \
{ \
	encoded += encode_bits(value->src_intfc, bit_count, destination, offset); \
}
/* Inside pfcp_vol_thresh_ie_t */
#define ENCODE_TOTAL_VOLUME_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->tovol) \
{ \
	encoded += encode_bits(value->total_volume, bit_count, destination, offset); \
}

/* Inside pfcp_vol_thresh_ie_t */
#define ENCODE_UPLINK_VOLUME_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ulvol) \
{ \
	encoded += encode_bits(value->uplink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_vol_thresh_ie_t */
#define ENCODE_DOWNLINK_VOLUME_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dlvol) \
{ \
	encoded += encode_bits(value->downlink_volume, bit_count, destination, offset); \
}

/* Inside pfcp_mac_address_ie_t */
#define ENCODE_SRC_MAC_ADDR_VAL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->sour) \
{ \
	encoded += encode_bits(value->src_mac_addr_val, bit_count, destination, offset); \
}

/* Inside pfcp_mac_address_ie_t */
#define ENCODE_DST_MAC_ADDR_VAL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->dest) \
{ \
	encoded += encode_bits(value->dst_mac_addr_val, bit_count, destination, offset); \
}

/* Inside pfcp_mac_address_ie_t */
#define ENCODE_UPR_SRC_MAC_ADDR_VAL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->usou) \
{ \
	encoded += encode_bits(value->upr_src_mac_addr_val, bit_count, destination, offset); \
}

/* Inside pfcp_mac_address_ie_t */
#define ENCODE_UPR_DST_MAC_ADDR_VAL_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->udes) \
{ \
	encoded += encode_bits(value->upr_dst_mac_addr_val, bit_count, destination, offset); \
}

/* Inside pfcp_ctag_ie_t */
#define ENCODE_CVID_VALUE2_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->ctag_vid) \
{ \
	encoded += encode_bits(value->cvid_value2, bit_count, destination, offset); \
}

/* Inside pfcp_stag_ie_t */
#define ENCODE_SVID_VALUE2_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->stag_vid) \
{ \
	encoded += encode_bits(value->svid_value2, bit_count, destination, offset); \
}

/* Inside pfcp_user_id_ie_t */
#define ENCODE_LENGTH_OF_IMSI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->imsif) \
{ \
	encoded += encode_bits(value->length_of_imsi, bit_count, destination, offset); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define ENCODE_IMSI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->imsif) \
{ \
	memcpy(destination, &value->imsi, value->length_of_imsi); \
	encoded +=  value->length_of_imsi * CHAR_SIZE; \
}

/* Inside pfcp_user_id_ie_t */
#define ENCODE_LENGTH_OF_IMEI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->imeif) \
{ \
	encoded += encode_bits(value->length_of_imei, bit_count, destination, offset); \
}

/* Inside pfcp_user_id_ie_t */
/* TODO: Revisit this for change in yang */
#define ENCODE_IMEI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->imeif) \
{ \
	memcpy(buf + (encoded/CHAR_SIZE), &value->imei, value->length_of_imei);\
	encoded +=  value->length_of_imei * CHAR_SIZE;\
}

/* Inside pfcp_user_id_ie_t */
#define ENCODE_LEN_OF_MSISDN_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->msisdnf) \
{ \
	encoded += encode_bits(value->len_of_msisdn, bit_count, destination, offset); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define ENCODE_MSISDN_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->msisdnf) \
{ \
	memcpy(buf + (encoded/CHAR_SIZE), &value->msisdn, value->len_of_msisdn); \
	encoded +=  value->len_of_msisdn * CHAR_SIZE; \
}

/* Inside pfcp_user_id_ie_t */
#define ENCODE_LENGTH_OF_NAI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->naif) \
{ \
	encoded += encode_bits(value->length_of_nai, bit_count, destination, offset); \
}

/* TODO: Revisit this for change in yang */
/* Inside pfcp_user_id_ie_t */
#define ENCODE_NAI_COND_1(value, bit_count, destination, offset, encoded) \
	if (value->naif) \
{ \
		memcpy(buf + (encoded/CHAR_SIZE), &value->nai, value->length_of_nai); \
		encoded +=  value->length_of_nai * CHAR_SIZE; \
}

#endif /*__PFCP_COND_ENCODER_H__*/
