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

#ifndef __GTP_IES_DECODE_H__
#define __GTP_IES_DECODE_H__


#include "gtp_ies.h"

/**
 * decodes gtpv2c_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     gtpv2c_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_gtpv2c_header_t(uint8_t *buf, gtpv2c_header_t *value);

/**
 * decodes ie_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ie_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_ie_header_t(uint8_t *buf,
	ie_header_t *value, uint16_t val_len);

/**
* Decodes gtp_imsi_ie_t to buffer.
* @param value
*    gtp_imsi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_imsi_ie(uint8_t *buf,
    gtp_imsi_ie_t *value);

/**
* Decodes gtp_cause_ie_t to buffer.
* @param value
*    gtp_cause_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_cause_ie(uint8_t *buf,
    gtp_cause_ie_t *value);

/**
* Decodes gtp_recovery_ie_t to buffer.
* @param value
*    gtp_recovery_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_recovery_ie(uint8_t *buf,
    gtp_recovery_ie_t *value);

/**
* Decodes gtp_acc_pt_name_ie_t to buffer.
* @param value
*    gtp_acc_pt_name_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_acc_pt_name_ie(uint8_t *buf,
    gtp_acc_pt_name_ie_t *value);

/**
* Decodes gtp_agg_max_bit_rate_ie_t to buffer.
* @param value
*    gtp_agg_max_bit_rate_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_agg_max_bit_rate_ie(uint8_t *buf,
    gtp_agg_max_bit_rate_ie_t *value);

/**
* Decodes gtp_eps_bearer_id_ie_t to buffer.
* @param value
*    gtp_eps_bearer_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_bearer_id_ie(uint8_t *buf,
    gtp_eps_bearer_id_ie_t *value);

/**
* Decodes gtp_ip_address_ie_t to buffer.
* @param value
*    gtp_ip_address_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ip_address_ie(uint8_t *buf,
    gtp_ip_address_ie_t *value);

/**
* Decodes gtp_mbl_equip_idnty_ie_t to buffer.
* @param value
*    gtp_mbl_equip_idnty_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbl_equip_idnty_ie(uint8_t *buf,
    gtp_mbl_equip_idnty_ie_t *value);

/**
* Decodes gtp_msisdn_ie_t to buffer.
* @param value
*    gtp_msisdn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_msisdn_ie(uint8_t *buf,
    gtp_msisdn_ie_t *value);

/**
* Decodes gtp_indication_ie_t to buffer.
* @param value
*    gtp_indication_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_indication_ie(uint8_t *buf,
    gtp_indication_ie_t *value);

/**
* Decodes gtp_prot_cfg_opts_ie_t to buffer.
* @param value
*    gtp_prot_cfg_opts_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_prot_cfg_opts_ie(uint8_t *buf,
    gtp_prot_cfg_opts_ie_t *value);

/**
* Decodes gtp_pdn_addr_alloc_ie_t to buffer.
* @param value
*    gtp_pdn_addr_alloc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_addr_alloc_ie(uint8_t *buf,
    gtp_pdn_addr_alloc_ie_t *value);

/**
* Decodes gtp_bearer_qlty_of_svc_ie_t to buffer.
* @param value
*    gtp_bearer_qlty_of_svc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_qlty_of_svc_ie(uint8_t *buf,
    gtp_bearer_qlty_of_svc_ie_t *value);

/**
* Decodes gtp_flow_qlty_of_svc_ie_t to buffer.
* @param value
*    gtp_flow_qlty_of_svc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_flow_qlty_of_svc_ie(uint8_t *buf,
    gtp_flow_qlty_of_svc_ie_t *value);

/**
* Decodes gtp_rat_type_ie_t to buffer.
* @param value
*    gtp_rat_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rat_type_ie(uint8_t *buf,
    gtp_rat_type_ie_t *value);

/**
* Decodes gtp_serving_network_ie_t to buffer.
* @param value
*    gtp_serving_network_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_serving_network_ie(uint8_t *buf,
    gtp_serving_network_ie_t *value);

/**
* Decodes gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t to buffer.
* @param value
*    gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(uint8_t *buf,
    gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *value);

/**
* Decodes gtp_traffic_agg_desc_ie_t to buffer.
* @param value
*    gtp_traffic_agg_desc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_traffic_agg_desc_ie(uint8_t *buf,
    gtp_traffic_agg_desc_ie_t *value);

/**
* Decodes gtp_user_loc_info_ie_t to buffer.
* @param value
*    gtp_user_loc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_user_loc_info_ie(uint8_t *buf,
    gtp_user_loc_info_ie_t *value);

/**
* Decodes cgi_field_t to buffer.
* @param value
*    cgi_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_cgi_field(uint8_t *buf,
    cgi_field_t *value);

/**
* Decodes sai_field_t to buffer.
* @param value
*    sai_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_sai_field(uint8_t *buf,
    sai_field_t *value);

/**
* Decodes rai_field_t to buffer.
* @param value
*    rai_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_rai_field(uint8_t *buf,
    rai_field_t *value);

/**
* Decodes tai_field_t to buffer.
* @param value
*    tai_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_tai_field(uint8_t *buf,
    tai_field_t *value);

/**
* Decodes ecgi_field_t to buffer.
* @param value
*    ecgi_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ecgi_field(uint8_t *buf,
    ecgi_field_t *value);

/**
* Decodes lai_field_t to buffer.
* @param value
*    lai_field_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_lai_field(uint8_t *buf,
    lai_field_t *value);

/**
* Decodes macro_enb_id_fld_t to buffer.
* @param value
*    macro_enb_id_fld_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_macro_enb_id_fld(uint8_t *buf,
    macro_enb_id_fld_t *value);

/**
* Decodes extnded_macro_enb_id_fld_t to buffer.
* @param value
*    extnded_macro_enb_id_fld_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_extnded_macro_enb_id_fld(uint8_t *buf,
    extnded_macro_enb_id_fld_t *value);

/**
* Decodes gtp_fully_qual_tunn_endpt_idnt_ie_t to buffer.
* @param value
*    gtp_fully_qual_tunn_endpt_idnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fully_qual_tunn_endpt_idnt_ie(uint8_t *buf,
    gtp_fully_qual_tunn_endpt_idnt_ie_t *value);

/**
* Decodes gtp_tmsi_ie_t to buffer.
* @param value
*    gtp_tmsi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_tmsi_ie(uint8_t *buf,
    gtp_tmsi_ie_t *value);

/**
* Decodes gtp_global_cn_id_ie_t to buffer.
* @param value
*    gtp_global_cn_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_global_cn_id_ie(uint8_t *buf,
    gtp_global_cn_id_ie_t *value);

/**
* Decodes gtp_s103_pdn_data_fwdng_info_ie_t to buffer.
* @param value
*    gtp_s103_pdn_data_fwdng_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_s103_pdn_data_fwdng_info_ie(uint8_t *buf,
    gtp_s103_pdn_data_fwdng_info_ie_t *value);

/**
* Decodes gtp_s1u_data_fwdng_ie_t to buffer.
* @param value
*    gtp_s1u_data_fwdng_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_s1u_data_fwdng_ie(uint8_t *buf,
    gtp_s1u_data_fwdng_ie_t *value);

/**
* Decodes gtp_delay_value_ie_t to buffer.
* @param value
*    gtp_delay_value_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_delay_value_ie(uint8_t *buf,
    gtp_delay_value_ie_t *value);

/**
* Decodes gtp_bearer_context_ie_t to buffer.
* @param value
*    gtp_bearer_context_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_context_ie(uint8_t *buf,
    gtp_bearer_context_ie_t *value);

/**
* Decodes gtp_charging_id_ie_t to buffer.
* @param value
*    gtp_charging_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_charging_id_ie(uint8_t *buf,
    gtp_charging_id_ie_t *value);

/**
* Decodes gtp_chrgng_char_ie_t to buffer.
* @param value
*    gtp_chrgng_char_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_chrgng_char_ie(uint8_t *buf,
    gtp_chrgng_char_ie_t *value);

/**
* Decodes gtp_trc_info_ie_t to buffer.
* @param value
*    gtp_trc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_trc_info_ie(uint8_t *buf,
    gtp_trc_info_ie_t *value);

/**
* Decodes gtp_bearer_flags_ie_t to buffer.
* @param value
*    gtp_bearer_flags_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_flags_ie(uint8_t *buf,
    gtp_bearer_flags_ie_t *value);

/**
* Decodes gtp_pdn_type_ie_t to buffer.
* @param value
*    gtp_pdn_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_type_ie(uint8_t *buf,
    gtp_pdn_type_ie_t *value);

/**
* Decodes gtp_proc_trans_id_ie_t to buffer.
* @param value
*    gtp_proc_trans_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_proc_trans_id_ie(uint8_t *buf,
    gtp_proc_trans_id_ie_t *value);

/**
* Decodes gtp_gsm_key_and_triplets_ie_t to buffer.
* @param value
*    gtp_gsm_key_and_triplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_gsm_key_and_triplets_ie(uint8_t *buf,
    gtp_gsm_key_and_triplets_ie_t *value);

/**
* Decodes gtp_umts_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param value
*    gtp_umts_key_used_cipher_and_quintuplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_used_cipher_and_quintuplets_ie(uint8_t *buf,
    gtp_umts_key_used_cipher_and_quintuplets_ie_t *value);

/**
* Decodes gtp_gsm_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param value
*    gtp_gsm_key_used_cipher_and_quintuplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_gsm_key_used_cipher_and_quintuplets_ie(uint8_t *buf,
    gtp_gsm_key_used_cipher_and_quintuplets_ie_t *value);

/**
* Decodes gtp_umts_key_and_quintuplets_ie_t to buffer.
* @param value
*    gtp_umts_key_and_quintuplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_and_quintuplets_ie(uint8_t *buf,
    gtp_umts_key_and_quintuplets_ie_t *value);

/**
* Decodes gtp_eps_secur_ctxt_and_quadruplets_ie_t to buffer.
* @param value
*    gtp_eps_secur_ctxt_and_quadruplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_secur_ctxt_and_quadruplets_ie(uint8_t *buf,
    gtp_eps_secur_ctxt_and_quadruplets_ie_t *value);

/**
* Decodes gtp_umts_key_quadruplets_and_quintuplets_ie_t to buffer.
* @param value
*    gtp_umts_key_quadruplets_and_quintuplets_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_quadruplets_and_quintuplets_ie(uint8_t *buf,
    gtp_umts_key_quadruplets_and_quintuplets_ie_t *value);

/**
* Decodes mm_context_t to buffer.
* @param value
*    mm_context_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mm_context(uint8_t *buf,
    mm_context_t *value);

/**
* Decodes auth_triplet_t to buffer.
* @param value
*    auth_triplet_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_auth_triplet(uint8_t *buf,
    auth_triplet_t *value);

/**
* Decodes auth_quintuplet_t to buffer.
* @param value
*    auth_quintuplet_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_auth_quintuplet(uint8_t *buf,
    auth_quintuplet_t *value);

/**
* Decodes auth_quadruplet_t to buffer.
* @param value
*    auth_quadruplet_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_auth_quadruplet(uint8_t *buf,
    auth_quadruplet_t *value);

/**
* Decodes gtp_pdn_connection_ie_t to buffer.
* @param value
*    gtp_pdn_connection_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_connection_ie(uint8_t *buf,
    gtp_pdn_connection_ie_t *value);

/**
* Decodes gtp_pdu_numbers_ie_t to buffer.
* @param value
*    gtp_pdu_numbers_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdu_numbers_ie(uint8_t *buf,
    gtp_pdu_numbers_ie_t *value);

/**
* Decodes gtp_ptmsi_ie_t to buffer.
* @param value
*    gtp_ptmsi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ptmsi_ie(uint8_t *buf,
    gtp_ptmsi_ie_t *value);

/**
* Decodes gtp_ptmsi_signature_ie_t to buffer.
* @param value
*    gtp_ptmsi_signature_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ptmsi_signature_ie(uint8_t *buf,
    gtp_ptmsi_signature_ie_t *value);

/**
* Decodes gtp_hop_counter_ie_t to buffer.
* @param value
*    gtp_hop_counter_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_hop_counter_ie(uint8_t *buf,
    gtp_hop_counter_ie_t *value);

/**
* Decodes gtp_ue_time_zone_ie_t to buffer.
* @param value
*    gtp_ue_time_zone_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ue_time_zone_ie(uint8_t *buf,
    gtp_ue_time_zone_ie_t *value);

/**
* Decodes gtp_trace_reference_ie_t to buffer.
* @param value
*    gtp_trace_reference_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_trace_reference_ie(uint8_t *buf,
    gtp_trace_reference_ie_t *value);

/**
* Decodes gtp_cmplt_req_msg_ie_t to buffer.
* @param value
*    gtp_cmplt_req_msg_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_cmplt_req_msg_ie(uint8_t *buf,
    gtp_cmplt_req_msg_ie_t *value);

/**
* Decodes gtp_guti_ie_t to buffer.
* @param value
*    gtp_guti_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_guti_ie(uint8_t *buf,
    gtp_guti_ie_t *value);

/**
* Decodes gtp_full_qual_cntnr_ie_t to buffer.
* @param value
*    gtp_full_qual_cntnr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_full_qual_cntnr_ie(uint8_t *buf,
    gtp_full_qual_cntnr_ie_t *value);

/**
* Decodes bss_container_t to buffer.
* @param value
*    bss_container_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_bss_container(uint8_t *buf,
    bss_container_t *value);

/**
* Decodes gtp_full_qual_cause_ie_t to buffer.
* @param value
*    gtp_full_qual_cause_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_full_qual_cause_ie(uint8_t *buf,
    gtp_full_qual_cause_ie_t *value);

/**
* Decodes gtp_plmn_id_ie_t to buffer.
* @param value
*    gtp_plmn_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_plmn_id_ie(uint8_t *buf,
    gtp_plmn_id_ie_t *value);

/**
* Decodes gtp_trgt_id_ie_t to buffer.
* @param value
*    gtp_trgt_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_trgt_id_ie(uint8_t *buf,
    gtp_trgt_id_ie_t *value);

/**
* Decodes trgt_id_type_rnc_id_t to buffer.
* @param value
*    trgt_id_type_rnc_id_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_rnc_id(uint8_t *buf,
    trgt_id_type_rnc_id_t *value);

/**
* Decodes trgt_id_type_macro_enb_t to buffer.
* @param value
*    trgt_id_type_macro_enb_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_macro_enb(uint8_t *buf,
    trgt_id_type_macro_enb_t *value);

/**
* Decodes trgt_id_type_home_enb_t to buffer.
* @param value
*    trgt_id_type_home_enb_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_home_enb(uint8_t *buf,
    trgt_id_type_home_enb_t *value);

/**
* Decodes trgt_id_type_extnded_macro_enb_t to buffer.
* @param value
*    trgt_id_type_extnded_macro_enb_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_extnded_macro_enb(uint8_t *buf,
    trgt_id_type_extnded_macro_enb_t *value);

/**
* Decodes trgt_id_type_gnode_id_t to buffer.
* @param value
*    trgt_id_type_gnode_id_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_gnode_id(uint8_t *buf,
    trgt_id_type_gnode_id_t *value);

/**
* Decodes trgt_id_type_macro_ng_enb_t to buffer.
* @param value
*    trgt_id_type_macro_ng_enb_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_macro_ng_enb(uint8_t *buf,
    trgt_id_type_macro_ng_enb_t *value);

/**
* Decodes trgt_id_type_extnded_macro_ng_enb_t to buffer.
* @param value
*    trgt_id_type_extnded_macro_ng_enb_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_extnded_macro_ng_enb(uint8_t *buf,
    trgt_id_type_extnded_macro_ng_enb_t *value);

/**
* Decodes gtp_packet_flow_id_ie_t to buffer.
* @param value
*    gtp_packet_flow_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_packet_flow_id_ie(uint8_t *buf,
    gtp_packet_flow_id_ie_t *value);

/**
* Decodes gtp_rab_context_ie_t to buffer.
* @param value
*    gtp_rab_context_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rab_context_ie(uint8_t *buf,
    gtp_rab_context_ie_t *value);

/**
* Decodes gtp_src_rnc_pdcp_ctxt_info_ie_t to buffer.
* @param value
*    gtp_src_rnc_pdcp_ctxt_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_src_rnc_pdcp_ctxt_info_ie(uint8_t *buf,
    gtp_src_rnc_pdcp_ctxt_info_ie_t *value);

/**
* Decodes gtp_port_number_ie_t to buffer.
* @param value
*    gtp_port_number_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_port_number_ie(uint8_t *buf,
    gtp_port_number_ie_t *value);

/**
* Decodes gtp_apn_restriction_ie_t to buffer.
* @param value
*    gtp_apn_restriction_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_apn_restriction_ie(uint8_t *buf,
    gtp_apn_restriction_ie_t *value);

/**
* Decodes gtp_selection_mode_ie_t to buffer.
* @param value
*    gtp_selection_mode_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_selection_mode_ie(uint8_t *buf,
    gtp_selection_mode_ie_t *value);

/**
* Decodes gtp_src_id_ie_t to buffer.
* @param value
*    gtp_src_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_src_id_ie(uint8_t *buf,
    gtp_src_id_ie_t *value);

/**
* Decodes gtp_chg_rptng_act_ie_t to buffer.
* @param value
*    gtp_chg_rptng_act_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_chg_rptng_act_ie(uint8_t *buf,
    gtp_chg_rptng_act_ie_t *value);

/**
* Decodes gtp_fqcsid_ie_t to buffer.
* @param value
*    gtp_fqcsid_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fqcsid_ie(uint8_t *buf,
    gtp_fqcsid_ie_t *value);

/**
* Decodes gtp_channel_needed_ie_t to buffer.
* @param value
*    gtp_channel_needed_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_channel_needed_ie(uint8_t *buf,
    gtp_channel_needed_ie_t *value);

/**
* Decodes gtp_emlpp_priority_ie_t to buffer.
* @param value
*    gtp_emlpp_priority_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_emlpp_priority_ie(uint8_t *buf,
    gtp_emlpp_priority_ie_t *value);

/**
* Decodes gtp_node_type_ie_t to buffer.
* @param value
*    gtp_node_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_type_ie(uint8_t *buf,
    gtp_node_type_ie_t *value);

/**
* Decodes gtp_fully_qual_domain_name_ie_t to buffer.
* @param value
*    gtp_fully_qual_domain_name_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fully_qual_domain_name_ie(uint8_t *buf,
    gtp_fully_qual_domain_name_ie_t *value);

/**
* Decodes gtp_priv_ext_ie_t to buffer.
* @param value
*    gtp_priv_ext_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_priv_ext_ie(uint8_t *buf,
    gtp_priv_ext_ie_t *value);

/**
* Decodes gtp_trans_idnt_ie_t to buffer.
* @param value
*    gtp_trans_idnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_trans_idnt_ie(uint8_t *buf,
    gtp_trans_idnt_ie_t *value);

/**
* Decodes gtp_mbms_sess_dur_ie_t to buffer.
* @param value
*    gtp_mbms_sess_dur_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_sess_dur_ie(uint8_t *buf,
    gtp_mbms_sess_dur_ie_t *value);

/**
* Decodes gtp_mbms_svc_area_ie_t to buffer.
* @param value
*    gtp_mbms_svc_area_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_svc_area_ie(uint8_t *buf,
    gtp_mbms_svc_area_ie_t *value);

/**
* Decodes gtp_mbms_sess_idnt_ie_t to buffer.
* @param value
*    gtp_mbms_sess_idnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_sess_idnt_ie(uint8_t *buf,
    gtp_mbms_sess_idnt_ie_t *value);

/**
* Decodes gtp_mbms_flow_idnt_ie_t to buffer.
* @param value
*    gtp_mbms_flow_idnt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_flow_idnt_ie(uint8_t *buf,
    gtp_mbms_flow_idnt_ie_t *value);

/**
* Decodes gtp_mbms_ip_multcst_dist_ie_t to buffer.
* @param value
*    gtp_mbms_ip_multcst_dist_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_ip_multcst_dist_ie(uint8_t *buf,
    gtp_mbms_ip_multcst_dist_ie_t *value);

/**
* Decodes gtp_mbms_dist_ack_ie_t to buffer.
* @param value
*    gtp_mbms_dist_ack_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_dist_ack_ie(uint8_t *buf,
    gtp_mbms_dist_ack_ie_t *value);

/**
* Decodes gtp_user_csg_info_ie_t to buffer.
* @param value
*    gtp_user_csg_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_user_csg_info_ie(uint8_t *buf,
    gtp_user_csg_info_ie_t *value);

/**
* Decodes gtp_csg_info_rptng_act_ie_t to buffer.
* @param value
*    gtp_csg_info_rptng_act_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_info_rptng_act_ie(uint8_t *buf,
    gtp_csg_info_rptng_act_ie_t *value);

/**
* Decodes gtp_rfsp_index_ie_t to buffer.
* @param value
*    gtp_rfsp_index_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rfsp_index_ie(uint8_t *buf,
    gtp_rfsp_index_ie_t *value);

/**
* Decodes gtp_csg_id_ie_t to buffer.
* @param value
*    gtp_csg_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_id_ie(uint8_t *buf,
    gtp_csg_id_ie_t *value);

/**
* Decodes gtp_csg_memb_indctn_ie_t to buffer.
* @param value
*    gtp_csg_memb_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_memb_indctn_ie(uint8_t *buf,
    gtp_csg_memb_indctn_ie_t *value);

/**
* Decodes gtp_svc_indctr_ie_t to buffer.
* @param value
*    gtp_svc_indctr_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_svc_indctr_ie(uint8_t *buf,
    gtp_svc_indctr_ie_t *value);

/**
* Decodes gtp_detach_type_ie_t to buffer.
* @param value
*    gtp_detach_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_detach_type_ie(uint8_t *buf,
    gtp_detach_type_ie_t *value);

/**
* Decodes gtp_local_distgsd_name_ie_t to buffer.
* @param value
*    gtp_local_distgsd_name_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_local_distgsd_name_ie(uint8_t *buf,
    gtp_local_distgsd_name_ie_t *value);

/**
* Decodes gtp_node_features_ie_t to buffer.
* @param value
*    gtp_node_features_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_features_ie(uint8_t *buf,
    gtp_node_features_ie_t *value);

/**
* Decodes gtp_mbms_time_to_data_xfer_ie_t to buffer.
* @param value
*    gtp_mbms_time_to_data_xfer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_time_to_data_xfer_ie(uint8_t *buf,
    gtp_mbms_time_to_data_xfer_ie_t *value);

/**
* Decodes gtp_throttling_ie_t to buffer.
* @param value
*    gtp_throttling_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_throttling_ie(uint8_t *buf,
    gtp_throttling_ie_t *value);

/**
* Decodes gtp_alloc_reten_priority_ie_t to buffer.
* @param value
*    gtp_alloc_reten_priority_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_alloc_reten_priority_ie(uint8_t *buf,
    gtp_alloc_reten_priority_ie_t *value);

/**
* Decodes gtp_epc_timer_ie_t to buffer.
* @param value
*    gtp_epc_timer_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_epc_timer_ie(uint8_t *buf,
    gtp_epc_timer_ie_t *value);

/**
* Decodes gtp_sgnllng_priority_indctn_ie_t to buffer.
* @param value
*    gtp_sgnllng_priority_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_sgnllng_priority_indctn_ie(uint8_t *buf,
    gtp_sgnllng_priority_indctn_ie_t *value);

/**
* Decodes gtp_tmgi_ie_t to buffer.
* @param value
*    gtp_tmgi_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_tmgi_ie(uint8_t *buf,
    gtp_tmgi_ie_t *value);

/**
* Decodes gtp_addtl_mm_ctxt_srvcc_ie_t to buffer.
* @param value
*    gtp_addtl_mm_ctxt_srvcc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_mm_ctxt_srvcc_ie(uint8_t *buf,
    gtp_addtl_mm_ctxt_srvcc_ie_t *value);

/**
* Decodes gtp_addtl_flgs_srvcc_ie_t to buffer.
* @param value
*    gtp_addtl_flgs_srvcc_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_flgs_srvcc_ie(uint8_t *buf,
    gtp_addtl_flgs_srvcc_ie_t *value);

/**
* Decodes gtp_mdt_cfg_ie_t to buffer.
* @param value
*    gtp_mdt_cfg_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mdt_cfg_ie(uint8_t *buf,
    gtp_mdt_cfg_ie_t *value);

/**
* Decodes gtp_addtl_prot_cfg_opts_ie_t to buffer.
* @param value
*    gtp_addtl_prot_cfg_opts_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_prot_cfg_opts_ie(uint8_t *buf,
    gtp_addtl_prot_cfg_opts_ie_t *value);

/**
* Decodes gtp_mbms_data_xfer_abs_time_ie_t to buffer.
* @param value
*    gtp_mbms_data_xfer_abs_time_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_data_xfer_abs_time_ie(uint8_t *buf,
    gtp_mbms_data_xfer_abs_time_ie_t *value);

/**
* Decodes gtp_henb_info_rptng_ie_t to buffer.
* @param value
*    gtp_henb_info_rptng_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_henb_info_rptng_ie(uint8_t *buf,
    gtp_henb_info_rptng_ie_t *value);

/**
* Decodes gtp_ipv4_cfg_parms_ie_t to buffer.
* @param value
*    gtp_ipv4_cfg_parms_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ipv4_cfg_parms_ie(uint8_t *buf,
    gtp_ipv4_cfg_parms_ie_t *value);

/**
* Decodes gtp_chg_to_rpt_flgs_ie_t to buffer.
* @param value
*    gtp_chg_to_rpt_flgs_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_chg_to_rpt_flgs_ie(uint8_t *buf,
    gtp_chg_to_rpt_flgs_ie_t *value);

/**
* Decodes gtp_act_indctn_ie_t to buffer.
* @param value
*    gtp_act_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_act_indctn_ie(uint8_t *buf,
    gtp_act_indctn_ie_t *value);

/**
* Decodes gtp_twan_identifier_ie_t to buffer.
* @param value
*    gtp_twan_identifier_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_twan_identifier_ie(uint8_t *buf,
    gtp_twan_identifier_ie_t *value);

/**
* Decodes gtp_uli_timestamp_ie_t to buffer.
* @param value
*    gtp_uli_timestamp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_uli_timestamp_ie(uint8_t *buf,
    gtp_uli_timestamp_ie_t *value);

/**
* Decodes gtp_mbms_flags_ie_t to buffer.
* @param value
*    gtp_mbms_flags_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_flags_ie(uint8_t *buf,
    gtp_mbms_flags_ie_t *value);

/**
* Decodes gtp_ran_nas_cause_ie_t to buffer.
* @param value
*    gtp_ran_nas_cause_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ran_nas_cause_ie(uint8_t *buf,
    gtp_ran_nas_cause_ie_t *value);

/**
* Decodes gtp_cn_oper_sel_entity_ie_t to buffer.
* @param value
*    gtp_cn_oper_sel_entity_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_cn_oper_sel_entity_ie(uint8_t *buf,
    gtp_cn_oper_sel_entity_ie_t *value);

/**
* Decodes gtp_trstd_wlan_mode_indctn_ie_t to buffer.
* @param value
*    gtp_trstd_wlan_mode_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_trstd_wlan_mode_indctn_ie(uint8_t *buf,
    gtp_trstd_wlan_mode_indctn_ie_t *value);

/**
* Decodes gtp_node_number_ie_t to buffer.
* @param value
*    gtp_node_number_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_number_ie(uint8_t *buf,
    gtp_node_number_ie_t *value);

/**
* Decodes gtp_node_identifier_ie_t to buffer.
* @param value
*    gtp_node_identifier_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_identifier_ie(uint8_t *buf,
    gtp_node_identifier_ie_t *value);

/**
* Decodes gtp_pres_rptng_area_act_ie_t to buffer.
* @param value
*    gtp_pres_rptng_area_act_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pres_rptng_area_act_ie(uint8_t *buf,
    gtp_pres_rptng_area_act_ie_t *value);

/**
* Decodes gtp_pres_rptng_area_info_ie_t to buffer.
* @param value
*    gtp_pres_rptng_area_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_pres_rptng_area_info_ie(uint8_t *buf,
    gtp_pres_rptng_area_info_ie_t *value);

/**
* Decodes gtp_twan_idnt_ts_ie_t to buffer.
* @param value
*    gtp_twan_idnt_ts_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_twan_idnt_ts_ie(uint8_t *buf,
    gtp_twan_idnt_ts_ie_t *value);

/**
* Decodes gtp_ovrld_ctl_info_ie_t to buffer.
* @param value
*    gtp_ovrld_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ovrld_ctl_info_ie(uint8_t *buf,
    gtp_ovrld_ctl_info_ie_t *value);

/**
* Decodes gtp_load_ctl_info_ie_t to buffer.
* @param value
*    gtp_load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_load_ctl_info_ie(uint8_t *buf,
    gtp_load_ctl_info_ie_t *value);

/**
* Decodes gtp_metric_ie_t to buffer.
* @param value
*    gtp_metric_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_metric_ie(uint8_t *buf,
    gtp_metric_ie_t *value);

/**
* Decodes gtp_sequence_number_ie_t to buffer.
* @param value
*    gtp_sequence_number_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_sequence_number_ie(uint8_t *buf,
    gtp_sequence_number_ie_t *value);

/**
* Decodes gtp_apn_and_rltv_cap_ie_t to buffer.
* @param value
*    gtp_apn_and_rltv_cap_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_apn_and_rltv_cap_ie(uint8_t *buf,
    gtp_apn_and_rltv_cap_ie_t *value);

/**
* Decodes gtp_wlan_offldblty_indctn_ie_t to buffer.
* @param value
*    gtp_wlan_offldblty_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_wlan_offldblty_indctn_ie(uint8_t *buf,
    gtp_wlan_offldblty_indctn_ie_t *value);

/**
* Decodes gtp_paging_and_svc_info_ie_t to buffer.
* @param value
*    gtp_paging_and_svc_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_paging_and_svc_info_ie(uint8_t *buf,
    gtp_paging_and_svc_info_ie_t *value);

/**
* Decodes gtp_integer_number_ie_t to buffer.
* @param value
*    gtp_integer_number_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_integer_number_ie(uint8_t *buf,
    gtp_integer_number_ie_t *value);

/**
* Decodes gtp_msec_time_stmp_ie_t to buffer.
* @param value
*    gtp_msec_time_stmp_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_msec_time_stmp_ie(uint8_t *buf,
    gtp_msec_time_stmp_ie_t *value);

/**
* Decodes gtp_mntrng_evnt_info_ie_t to buffer.
* @param value
*    gtp_mntrng_evnt_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mntrng_evnt_info_ie(uint8_t *buf,
    gtp_mntrng_evnt_info_ie_t *value);

/**
* Decodes gtp_ecgi_list_ie_t to buffer.
* @param value
*    gtp_ecgi_list_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ecgi_list_ie(uint8_t *buf,
    gtp_ecgi_list_ie_t *value);

/**
* Decodes gtp_rmt_ue_ctxt_ie_t to buffer.
* @param value
*    gtp_rmt_ue_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_ctxt_ie(uint8_t *buf,
    gtp_rmt_ue_ctxt_ie_t *value);

/**
* Decodes gtp_remote_user_id_ie_t to buffer.
* @param value
*    gtp_remote_user_id_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_remote_user_id_ie(uint8_t *buf,
    gtp_remote_user_id_ie_t *value);

/**
* Decodes gtp_rmt_ue_ip_info_ie_t to buffer.
* @param value
*    gtp_rmt_ue_ip_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_ip_info_ie(uint8_t *buf,
    gtp_rmt_ue_ip_info_ie_t *value);

/**
* Decodes gtp_ciot_optim_supp_indctn_ie_t to buffer.
* @param value
*    gtp_ciot_optim_supp_indctn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ciot_optim_supp_indctn_ie(uint8_t *buf,
    gtp_ciot_optim_supp_indctn_ie_t *value);

/**
* Decodes gtp_scef_pdn_conn_ie_t to buffer.
* @param value
*    gtp_scef_pdn_conn_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_scef_pdn_conn_ie(uint8_t *buf,
    gtp_scef_pdn_conn_ie_t *value);

/**
* Decodes gtp_hdr_comp_cfg_ie_t to buffer.
* @param value
*    gtp_hdr_comp_cfg_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_hdr_comp_cfg_ie(uint8_t *buf,
    gtp_hdr_comp_cfg_ie_t *value);

/**
* Decodes gtp_extnded_prot_cfg_opts_ie_t to buffer.
* @param value
*    gtp_extnded_prot_cfg_opts_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_extnded_prot_cfg_opts_ie(uint8_t *buf,
    gtp_extnded_prot_cfg_opts_ie_t *value);

/**
* Decodes gtp_srvng_plmn_rate_ctl_ie_t to buffer.
* @param value
*    gtp_srvng_plmn_rate_ctl_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_srvng_plmn_rate_ctl_ie(uint8_t *buf,
    gtp_srvng_plmn_rate_ctl_ie_t *value);

/**
* Decodes gtp_counter_ie_t to buffer.
* @param value
*    gtp_counter_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_counter_ie(uint8_t *buf,
    gtp_counter_ie_t *value);

/**
* Decodes gtp_mapped_ue_usage_type_ie_t to buffer.
* @param value
*    gtp_mapped_ue_usage_type_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mapped_ue_usage_type_ie(uint8_t *buf,
    gtp_mapped_ue_usage_type_ie_t *value);

/**
* Decodes gtp_secdry_rat_usage_data_rpt_ie_t to buffer.
* @param value
*    gtp_secdry_rat_usage_data_rpt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_secdry_rat_usage_data_rpt_ie(uint8_t *buf,
    gtp_secdry_rat_usage_data_rpt_ie_t *value);

/**
* Decodes gtp_up_func_sel_indctn_flgs_ie_t to buffer.
* @param value
*    gtp_up_func_sel_indctn_flgs_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_up_func_sel_indctn_flgs_ie(uint8_t *buf,
    gtp_up_func_sel_indctn_flgs_ie_t *value);

/**
* Decodes gtp_max_pckt_loss_rate_ie_t to buffer.
* @param value
*    gtp_max_pckt_loss_rate_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_max_pckt_loss_rate_ie(uint8_t *buf,
    gtp_max_pckt_loss_rate_ie_t *value);


#endif /*__GTP_IES_DECODE_H__*/
