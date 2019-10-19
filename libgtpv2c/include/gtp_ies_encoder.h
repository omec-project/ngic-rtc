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

#ifndef __GTP_IES_ENCODE_H__
#define __GTP_IES_ENCODE_H__


#include "gtp_ies.h"

#define MBR_BUF_SIZE 5

/**
 * Encodes gtpv2c_header_t to buffer.
 * @param value
 *    gtpv2c_header_t
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_gtpv2c_header_t(gtpv2c_header_t *value,
	uint8_t *buf);

/**
 * Encodes ie_header_t to buffer.
 * @param value
 *     ie_header_t
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ie_header_t(ie_header_t *value,
	uint8_t *buf);

/**
* Encodes gtp_imsi_ie_t to buffer.
* @param value 
*    gtp_imsi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_imsi_ie(gtp_imsi_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_cause_ie_t to buffer.
* @param value 
*    gtp_cause_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_cause_ie(gtp_cause_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_recovery_ie_t to buffer.
* @param value 
*    gtp_recovery_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_recovery_ie(gtp_recovery_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_acc_pt_name_ie_t to buffer.
* @param value 
*    gtp_acc_pt_name_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_acc_pt_name_ie(gtp_acc_pt_name_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_agg_max_bit_rate_ie_t to buffer.
* @param value 
*    gtp_agg_max_bit_rate_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_agg_max_bit_rate_ie(gtp_agg_max_bit_rate_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_eps_bearer_id_ie_t to buffer.
* @param value 
*    gtp_eps_bearer_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_bearer_id_ie(gtp_eps_bearer_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ip_address_ie_t to buffer.
* @param value 
*    gtp_ip_address_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ip_address_ie(gtp_ip_address_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbl_equip_idnty_ie_t to buffer.
* @param value 
*    gtp_mbl_equip_idnty_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbl_equip_idnty_ie(gtp_mbl_equip_idnty_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_msisdn_ie_t to buffer.
* @param value 
*    gtp_msisdn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_msisdn_ie(gtp_msisdn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_indication_ie_t to buffer.
* @param value 
*    gtp_indication_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_indication_ie(gtp_indication_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_prot_cfg_opts_ie_t to buffer.
* @param value 
*    gtp_prot_cfg_opts_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_prot_cfg_opts_ie(gtp_prot_cfg_opts_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pdn_addr_alloc_ie_t to buffer.
* @param value 
*    gtp_pdn_addr_alloc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_addr_alloc_ie(gtp_pdn_addr_alloc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_bearer_qlty_of_svc_ie_t to buffer.
* @param value 
*    gtp_bearer_qlty_of_svc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_qlty_of_svc_ie(gtp_bearer_qlty_of_svc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_flow_qlty_of_svc_ie_t to buffer.
* @param value 
*    gtp_flow_qlty_of_svc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_flow_qlty_of_svc_ie(gtp_flow_qlty_of_svc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rat_type_ie_t to buffer.
* @param value 
*    gtp_rat_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rat_type_ie(gtp_rat_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_serving_network_ie_t to buffer.
* @param value 
*    gtp_serving_network_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_serving_network_ie(gtp_serving_network_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t to buffer.
* @param value 
*    gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_traffic_agg_desc_ie_t to buffer.
* @param value 
*    gtp_traffic_agg_desc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_traffic_agg_desc_ie(gtp_traffic_agg_desc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_user_loc_info_ie_t to buffer.
* @param value 
*    gtp_user_loc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_user_loc_info_ie(gtp_user_loc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes cgi_field_t to buffer.
* @param value 
*    cgi_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_cgi_field(cgi_field_t *value,
    uint8_t *buf);

/**
* Encodes sai_field_t to buffer.
* @param value 
*    sai_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_sai_field(sai_field_t *value,
    uint8_t *buf);

/**
* Encodes rai_field_t to buffer.
* @param value 
*    rai_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_rai_field(rai_field_t *value,
    uint8_t *buf);

/**
* Encodes tai_field_t to buffer.
* @param value 
*    tai_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_tai_field(tai_field_t *value,
    uint8_t *buf);

/**
* Encodes ecgi_field_t to buffer.
* @param value 
*    ecgi_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ecgi_field(ecgi_field_t *value,
    uint8_t *buf);

/**
* Encodes lai_field_t to buffer.
* @param value 
*    lai_field_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_lai_field(lai_field_t *value,
    uint8_t *buf);

/**
* Encodes macro_enb_id_fld_t to buffer.
* @param value 
*    macro_enb_id_fld_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_macro_enb_id_fld(macro_enb_id_fld_t *value,
    uint8_t *buf);

/**
* Encodes extnded_macro_enb_id_fld_t to buffer.
* @param value 
*    extnded_macro_enb_id_fld_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_extnded_macro_enb_id_fld(extnded_macro_enb_id_fld_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fully_qual_tunn_endpt_idnt_ie_t to buffer.
* @param value 
*    gtp_fully_qual_tunn_endpt_idnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fully_qual_tunn_endpt_idnt_ie(gtp_fully_qual_tunn_endpt_idnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_tmsi_ie_t to buffer.
* @param value 
*    gtp_tmsi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_tmsi_ie(gtp_tmsi_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_global_cn_id_ie_t to buffer.
* @param value 
*    gtp_global_cn_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_global_cn_id_ie(gtp_global_cn_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_s103_pdn_data_fwdng_info_ie_t to buffer.
* @param value 
*    gtp_s103_pdn_data_fwdng_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_s103_pdn_data_fwdng_info_ie(gtp_s103_pdn_data_fwdng_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_s1u_data_fwdng_ie_t to buffer.
* @param value 
*    gtp_s1u_data_fwdng_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_s1u_data_fwdng_ie(gtp_s1u_data_fwdng_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_delay_value_ie_t to buffer.
* @param value 
*    gtp_delay_value_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_delay_value_ie(gtp_delay_value_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_bearer_context_ie_t to buffer.
* @param value 
*    gtp_bearer_context_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_context_ie(gtp_bearer_context_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_charging_id_ie_t to buffer.
* @param value 
*    gtp_charging_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_charging_id_ie(gtp_charging_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_chrgng_char_ie_t to buffer.
* @param value 
*    gtp_chrgng_char_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_chrgng_char_ie(gtp_chrgng_char_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_trc_info_ie_t to buffer.
* @param value 
*    gtp_trc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_trc_info_ie(gtp_trc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_bearer_flags_ie_t to buffer.
* @param value 
*    gtp_bearer_flags_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_flags_ie(gtp_bearer_flags_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pdn_type_ie_t to buffer.
* @param value 
*    gtp_pdn_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_type_ie(gtp_pdn_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_proc_trans_id_ie_t to buffer.
* @param value 
*    gtp_proc_trans_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_proc_trans_id_ie(gtp_proc_trans_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_gsm_key_and_triplets_ie_t to buffer.
* @param value 
*    gtp_gsm_key_and_triplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_gsm_key_and_triplets_ie(gtp_gsm_key_and_triplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_umts_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param value 
*    gtp_umts_key_used_cipher_and_quintuplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_used_cipher_and_quintuplets_ie(gtp_umts_key_used_cipher_and_quintuplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_gsm_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param value 
*    gtp_gsm_key_used_cipher_and_quintuplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_gsm_key_used_cipher_and_quintuplets_ie(gtp_gsm_key_used_cipher_and_quintuplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_umts_key_and_quintuplets_ie_t to buffer.
* @param value 
*    gtp_umts_key_and_quintuplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_and_quintuplets_ie(gtp_umts_key_and_quintuplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_eps_secur_ctxt_and_quadruplets_ie_t to buffer.
* @param value 
*    gtp_eps_secur_ctxt_and_quadruplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_secur_ctxt_and_quadruplets_ie(gtp_eps_secur_ctxt_and_quadruplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_umts_key_quadruplets_and_quintuplets_ie_t to buffer.
* @param value 
*    gtp_umts_key_quadruplets_and_quintuplets_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_quadruplets_and_quintuplets_ie(gtp_umts_key_quadruplets_and_quintuplets_ie_t *value,
    uint8_t *buf);

/**
* Encodes mm_context_t to buffer.
* @param value 
*    mm_context_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mm_context(mm_context_t *value,
    uint8_t *buf);

/**
* Encodes auth_triplet_t to buffer.
* @param value 
*    auth_triplet_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_auth_triplet(auth_triplet_t *value,
    uint8_t *buf);

/**
* Encodes auth_quintuplet_t to buffer.
* @param value 
*    auth_quintuplet_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_auth_quintuplet(auth_quintuplet_t *value,
    uint8_t *buf);

/**
* Encodes auth_quadruplet_t to buffer.
* @param value 
*    auth_quadruplet_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_auth_quadruplet(auth_quadruplet_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pdn_connection_ie_t to buffer.
* @param value 
*    gtp_pdn_connection_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_connection_ie(gtp_pdn_connection_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pdu_numbers_ie_t to buffer.
* @param value 
*    gtp_pdu_numbers_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdu_numbers_ie(gtp_pdu_numbers_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ptmsi_ie_t to buffer.
* @param value 
*    gtp_ptmsi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ptmsi_ie(gtp_ptmsi_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ptmsi_signature_ie_t to buffer.
* @param value 
*    gtp_ptmsi_signature_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ptmsi_signature_ie(gtp_ptmsi_signature_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_hop_counter_ie_t to buffer.
* @param value 
*    gtp_hop_counter_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_hop_counter_ie(gtp_hop_counter_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ue_time_zone_ie_t to buffer.
* @param value 
*    gtp_ue_time_zone_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ue_time_zone_ie(gtp_ue_time_zone_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_trace_reference_ie_t to buffer.
* @param value 
*    gtp_trace_reference_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_trace_reference_ie(gtp_trace_reference_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_cmplt_req_msg_ie_t to buffer.
* @param value 
*    gtp_cmplt_req_msg_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_cmplt_req_msg_ie(gtp_cmplt_req_msg_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_guti_ie_t to buffer.
* @param value 
*    gtp_guti_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_guti_ie(gtp_guti_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_full_qual_cntnr_ie_t to buffer.
* @param value 
*    gtp_full_qual_cntnr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_full_qual_cntnr_ie(gtp_full_qual_cntnr_ie_t *value,
    uint8_t *buf);

/**
* Encodes bss_container_t to buffer.
* @param value 
*    bss_container_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_bss_container(bss_container_t *value,
    uint8_t *buf);

/**
* Encodes gtp_full_qual_cause_ie_t to buffer.
* @param value 
*    gtp_full_qual_cause_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_full_qual_cause_ie(gtp_full_qual_cause_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_plmn_id_ie_t to buffer.
* @param value 
*    gtp_plmn_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_plmn_id_ie(gtp_plmn_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_trgt_id_ie_t to buffer.
* @param value 
*    gtp_trgt_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_trgt_id_ie(gtp_trgt_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_rnc_id_t to buffer.
* @param value 
*    trgt_id_type_rnc_id_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_rnc_id(trgt_id_type_rnc_id_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_macro_enb_t to buffer.
* @param value 
*    trgt_id_type_macro_enb_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_macro_enb(trgt_id_type_macro_enb_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_home_enb_t to buffer.
* @param value 
*    trgt_id_type_home_enb_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_home_enb(trgt_id_type_home_enb_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_extnded_macro_enb_t to buffer.
* @param value 
*    trgt_id_type_extnded_macro_enb_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_extnded_macro_enb(trgt_id_type_extnded_macro_enb_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_gnode_id_t to buffer.
* @param value 
*    trgt_id_type_gnode_id_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_gnode_id(trgt_id_type_gnode_id_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_macro_ng_enb_t to buffer.
* @param value 
*    trgt_id_type_macro_ng_enb_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_macro_ng_enb(trgt_id_type_macro_ng_enb_t *value,
    uint8_t *buf);

/**
* Encodes trgt_id_type_extnded_macro_ng_enb_t to buffer.
* @param value 
*    trgt_id_type_extnded_macro_ng_enb_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_extnded_macro_ng_enb(trgt_id_type_extnded_macro_ng_enb_t *value,
    uint8_t *buf);

/**
* Encodes gtp_packet_flow_id_ie_t to buffer.
* @param value 
*    gtp_packet_flow_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_packet_flow_id_ie(gtp_packet_flow_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rab_context_ie_t to buffer.
* @param value 
*    gtp_rab_context_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rab_context_ie(gtp_rab_context_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_src_rnc_pdcp_ctxt_info_ie_t to buffer.
* @param value 
*    gtp_src_rnc_pdcp_ctxt_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_src_rnc_pdcp_ctxt_info_ie(gtp_src_rnc_pdcp_ctxt_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_port_number_ie_t to buffer.
* @param value 
*    gtp_port_number_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_port_number_ie(gtp_port_number_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_apn_restriction_ie_t to buffer.
* @param value 
*    gtp_apn_restriction_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_apn_restriction_ie(gtp_apn_restriction_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_selection_mode_ie_t to buffer.
* @param value 
*    gtp_selection_mode_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_selection_mode_ie(gtp_selection_mode_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_src_id_ie_t to buffer.
* @param value 
*    gtp_src_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_src_id_ie(gtp_src_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_chg_rptng_act_ie_t to buffer.
* @param value 
*    gtp_chg_rptng_act_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_chg_rptng_act_ie(gtp_chg_rptng_act_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fqcsid_ie_t to buffer.
* @param value 
*    gtp_fqcsid_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fqcsid_ie(gtp_fqcsid_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_channel_needed_ie_t to buffer.
* @param value 
*    gtp_channel_needed_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_channel_needed_ie(gtp_channel_needed_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_emlpp_priority_ie_t to buffer.
* @param value 
*    gtp_emlpp_priority_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_emlpp_priority_ie(gtp_emlpp_priority_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_node_type_ie_t to buffer.
* @param value 
*    gtp_node_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_type_ie(gtp_node_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fully_qual_domain_name_ie_t to buffer.
* @param value 
*    gtp_fully_qual_domain_name_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fully_qual_domain_name_ie(gtp_fully_qual_domain_name_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_priv_ext_ie_t to buffer.
* @param value 
*    gtp_priv_ext_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_priv_ext_ie(gtp_priv_ext_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_trans_idnt_ie_t to buffer.
* @param value 
*    gtp_trans_idnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_trans_idnt_ie(gtp_trans_idnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_sess_dur_ie_t to buffer.
* @param value 
*    gtp_mbms_sess_dur_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_sess_dur_ie(gtp_mbms_sess_dur_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_svc_area_ie_t to buffer.
* @param value 
*    gtp_mbms_svc_area_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_svc_area_ie(gtp_mbms_svc_area_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_sess_idnt_ie_t to buffer.
* @param value 
*    gtp_mbms_sess_idnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_sess_idnt_ie(gtp_mbms_sess_idnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_flow_idnt_ie_t to buffer.
* @param value 
*    gtp_mbms_flow_idnt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_flow_idnt_ie(gtp_mbms_flow_idnt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_ip_multcst_dist_ie_t to buffer.
* @param value 
*    gtp_mbms_ip_multcst_dist_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_ip_multcst_dist_ie(gtp_mbms_ip_multcst_dist_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_dist_ack_ie_t to buffer.
* @param value 
*    gtp_mbms_dist_ack_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_dist_ack_ie(gtp_mbms_dist_ack_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_user_csg_info_ie_t to buffer.
* @param value 
*    gtp_user_csg_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_user_csg_info_ie(gtp_user_csg_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_csg_info_rptng_act_ie_t to buffer.
* @param value 
*    gtp_csg_info_rptng_act_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_info_rptng_act_ie(gtp_csg_info_rptng_act_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rfsp_index_ie_t to buffer.
* @param value 
*    gtp_rfsp_index_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rfsp_index_ie(gtp_rfsp_index_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_csg_id_ie_t to buffer.
* @param value 
*    gtp_csg_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_id_ie(gtp_csg_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_csg_memb_indctn_ie_t to buffer.
* @param value 
*    gtp_csg_memb_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_memb_indctn_ie(gtp_csg_memb_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_svc_indctr_ie_t to buffer.
* @param value 
*    gtp_svc_indctr_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_svc_indctr_ie(gtp_svc_indctr_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_detach_type_ie_t to buffer.
* @param value 
*    gtp_detach_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_detach_type_ie(gtp_detach_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_local_distgsd_name_ie_t to buffer.
* @param value 
*    gtp_local_distgsd_name_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_local_distgsd_name_ie(gtp_local_distgsd_name_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_node_features_ie_t to buffer.
* @param value 
*    gtp_node_features_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_features_ie(gtp_node_features_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_time_to_data_xfer_ie_t to buffer.
* @param value 
*    gtp_mbms_time_to_data_xfer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_time_to_data_xfer_ie(gtp_mbms_time_to_data_xfer_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_throttling_ie_t to buffer.
* @param value 
*    gtp_throttling_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_throttling_ie(gtp_throttling_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_alloc_reten_priority_ie_t to buffer.
* @param value 
*    gtp_alloc_reten_priority_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_alloc_reten_priority_ie(gtp_alloc_reten_priority_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_epc_timer_ie_t to buffer.
* @param value 
*    gtp_epc_timer_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_epc_timer_ie(gtp_epc_timer_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_sgnllng_priority_indctn_ie_t to buffer.
* @param value 
*    gtp_sgnllng_priority_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_sgnllng_priority_indctn_ie(gtp_sgnllng_priority_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_tmgi_ie_t to buffer.
* @param value 
*    gtp_tmgi_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_tmgi_ie(gtp_tmgi_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_addtl_mm_ctxt_srvcc_ie_t to buffer.
* @param value 
*    gtp_addtl_mm_ctxt_srvcc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_mm_ctxt_srvcc_ie(gtp_addtl_mm_ctxt_srvcc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_addtl_flgs_srvcc_ie_t to buffer.
* @param value 
*    gtp_addtl_flgs_srvcc_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_flgs_srvcc_ie(gtp_addtl_flgs_srvcc_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mdt_cfg_ie_t to buffer.
* @param value 
*    gtp_mdt_cfg_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mdt_cfg_ie(gtp_mdt_cfg_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_addtl_prot_cfg_opts_ie_t to buffer.
* @param value 
*    gtp_addtl_prot_cfg_opts_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_prot_cfg_opts_ie(gtp_addtl_prot_cfg_opts_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_data_xfer_abs_time_ie_t to buffer.
* @param value 
*    gtp_mbms_data_xfer_abs_time_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_data_xfer_abs_time_ie(gtp_mbms_data_xfer_abs_time_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_henb_info_rptng_ie_t to buffer.
* @param value 
*    gtp_henb_info_rptng_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_henb_info_rptng_ie(gtp_henb_info_rptng_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ipv4_cfg_parms_ie_t to buffer.
* @param value 
*    gtp_ipv4_cfg_parms_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ipv4_cfg_parms_ie(gtp_ipv4_cfg_parms_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_chg_to_rpt_flgs_ie_t to buffer.
* @param value 
*    gtp_chg_to_rpt_flgs_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_chg_to_rpt_flgs_ie(gtp_chg_to_rpt_flgs_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_act_indctn_ie_t to buffer.
* @param value 
*    gtp_act_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_act_indctn_ie(gtp_act_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_twan_identifier_ie_t to buffer.
* @param value 
*    gtp_twan_identifier_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_twan_identifier_ie(gtp_twan_identifier_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_uli_timestamp_ie_t to buffer.
* @param value 
*    gtp_uli_timestamp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_uli_timestamp_ie(gtp_uli_timestamp_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mbms_flags_ie_t to buffer.
* @param value 
*    gtp_mbms_flags_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_flags_ie(gtp_mbms_flags_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ran_nas_cause_ie_t to buffer.
* @param value 
*    gtp_ran_nas_cause_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ran_nas_cause_ie(gtp_ran_nas_cause_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_cn_oper_sel_entity_ie_t to buffer.
* @param value 
*    gtp_cn_oper_sel_entity_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_cn_oper_sel_entity_ie(gtp_cn_oper_sel_entity_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_trstd_wlan_mode_indctn_ie_t to buffer.
* @param value 
*    gtp_trstd_wlan_mode_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_trstd_wlan_mode_indctn_ie(gtp_trstd_wlan_mode_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_node_number_ie_t to buffer.
* @param value 
*    gtp_node_number_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_number_ie(gtp_node_number_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_node_identifier_ie_t to buffer.
* @param value 
*    gtp_node_identifier_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_identifier_ie(gtp_node_identifier_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pres_rptng_area_act_ie_t to buffer.
* @param value 
*    gtp_pres_rptng_area_act_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pres_rptng_area_act_ie(gtp_pres_rptng_area_act_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_pres_rptng_area_info_ie_t to buffer.
* @param value 
*    gtp_pres_rptng_area_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_pres_rptng_area_info_ie(gtp_pres_rptng_area_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_twan_idnt_ts_ie_t to buffer.
* @param value 
*    gtp_twan_idnt_ts_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_twan_idnt_ts_ie(gtp_twan_idnt_ts_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ovrld_ctl_info_ie_t to buffer.
* @param value 
*    gtp_ovrld_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ovrld_ctl_info_ie(gtp_ovrld_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_load_ctl_info_ie(gtp_load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_metric_ie_t to buffer.
* @param value 
*    gtp_metric_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_metric_ie(gtp_metric_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_sequence_number_ie_t to buffer.
* @param value 
*    gtp_sequence_number_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_sequence_number_ie(gtp_sequence_number_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_apn_and_rltv_cap_ie_t to buffer.
* @param value 
*    gtp_apn_and_rltv_cap_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_apn_and_rltv_cap_ie(gtp_apn_and_rltv_cap_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_wlan_offldblty_indctn_ie_t to buffer.
* @param value 
*    gtp_wlan_offldblty_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_wlan_offldblty_indctn_ie(gtp_wlan_offldblty_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_paging_and_svc_info_ie_t to buffer.
* @param value 
*    gtp_paging_and_svc_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_paging_and_svc_info_ie(gtp_paging_and_svc_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_integer_number_ie_t to buffer.
* @param value 
*    gtp_integer_number_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_integer_number_ie(gtp_integer_number_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_msec_time_stmp_ie_t to buffer.
* @param value 
*    gtp_msec_time_stmp_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_msec_time_stmp_ie(gtp_msec_time_stmp_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mntrng_evnt_info_ie_t to buffer.
* @param value 
*    gtp_mntrng_evnt_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mntrng_evnt_info_ie(gtp_mntrng_evnt_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ecgi_list_ie_t to buffer.
* @param value 
*    gtp_ecgi_list_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ecgi_list_ie(gtp_ecgi_list_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rmt_ue_ctxt_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_ctxt_ie(gtp_rmt_ue_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_remote_user_id_ie_t to buffer.
* @param value 
*    gtp_remote_user_id_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_remote_user_id_ie(gtp_remote_user_id_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rmt_ue_ip_info_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_ip_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_ip_info_ie(gtp_rmt_ue_ip_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ciot_optim_supp_indctn_ie_t to buffer.
* @param value 
*    gtp_ciot_optim_supp_indctn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ciot_optim_supp_indctn_ie(gtp_ciot_optim_supp_indctn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_scef_pdn_conn_ie_t to buffer.
* @param value 
*    gtp_scef_pdn_conn_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_scef_pdn_conn_ie(gtp_scef_pdn_conn_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_hdr_comp_cfg_ie_t to buffer.
* @param value 
*    gtp_hdr_comp_cfg_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_hdr_comp_cfg_ie(gtp_hdr_comp_cfg_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_extnded_prot_cfg_opts_ie_t to buffer.
* @param value 
*    gtp_extnded_prot_cfg_opts_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_extnded_prot_cfg_opts_ie(gtp_extnded_prot_cfg_opts_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_srvng_plmn_rate_ctl_ie_t to buffer.
* @param value 
*    gtp_srvng_plmn_rate_ctl_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_srvng_plmn_rate_ctl_ie(gtp_srvng_plmn_rate_ctl_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_counter_ie_t to buffer.
* @param value 
*    gtp_counter_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_counter_ie(gtp_counter_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mapped_ue_usage_type_ie_t to buffer.
* @param value 
*    gtp_mapped_ue_usage_type_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mapped_ue_usage_type_ie(gtp_mapped_ue_usage_type_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_secdry_rat_usage_data_rpt_ie_t to buffer.
* @param value 
*    gtp_secdry_rat_usage_data_rpt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_secdry_rat_usage_data_rpt_ie(gtp_secdry_rat_usage_data_rpt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_up_func_sel_indctn_flgs_ie_t to buffer.
* @param value 
*    gtp_up_func_sel_indctn_flgs_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_up_func_sel_indctn_flgs_ie(gtp_up_func_sel_indctn_flgs_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_max_pckt_loss_rate_ie_t to buffer.
* @param value 
*    gtp_max_pckt_loss_rate_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_max_pckt_loss_rate_ie(gtp_max_pckt_loss_rate_ie_t *value,
    uint8_t *buf);


#endif /*__GTP_IES_ENCODE_H__*/