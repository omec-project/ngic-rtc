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

#include "../include/gtp_ies_encoder.h"

#include "../include/gtp_messages_encoder.h"


#include "../include/sv_ies_encoder.h"
#include "../include/enc_dec_bits.h"


/**
* Encodes detach_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    detach_ack_t
* @return
*   number of encoded bytes.
*/
int encode_detach_ack(detach_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes dnlnk_data_notif_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    dnlnk_data_notif_ack_t
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif_ack(dnlnk_data_notif_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->data_notif_delay.header.len)
        encoded += encode_gtp_delay_value_ie(&(value->data_notif_delay), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->dl_low_priority_traffic_thrtlng.header.len)
        encoded += encode_gtp_throttling_ie(&(value->dl_low_priority_traffic_thrtlng), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->dl_buffering_dur.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->dl_buffering_dur), buf + encoded);

if (value->dl_buffering_suggested_pckt_cnt.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->dl_buffering_suggested_pckt_cnt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes reloc_cncl_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    reloc_cncl_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_reloc_cncl_rsp(reloc_cncl_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes bearer_rsrc_cmd_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    bearer_rsrc_cmd_t
* @return
*   number of encoded bytes.
*/
int encode_bearer_rsrc_cmd(bearer_rsrc_cmd_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->lbi.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->lbi), buf + encoded);

if (value->pti.header.len)
        encoded += encode_gtp_proc_trans_id_ie(&(value->pti), buf + encoded);

if (value->flow_qos.header.len)
        encoded += encode_gtp_flow_qlty_of_svc_ie(&(value->flow_qos), buf + encoded);

if (value->tad.header.len)
        encoded += encode_gtp_traffic_agg_desc_ie(&(value->tad), buf + encoded);

if (value->rat_type.header.len)
        encoded += encode_gtp_rat_type_ie(&(value->rat_type), buf + encoded);

if (value->serving_network.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->serving_network), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

if (value->s12_rnc_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_rnc_fteid), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->sgnllng_priority_indctn.header.len)
        encoded += encode_gtp_sgnllng_priority_indctn_ie(&(value->sgnllng_priority_indctn), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_reloc_cmplt_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_reloc_cmplt_ack_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_cmplt_ack(fwd_reloc_cmplt_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes isr_status_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    isr_status_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_isr_status_indctn(isr_status_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->act_indctn.header.len)
        encoded += encode_gtp_act_indctn_ie(&(value->act_indctn), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ctxt_acknowledge__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ctxt_acknowledge__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_acknowledge__bearer_ctxt_ie(gtp_ctxt_acknowledge__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->fwdng_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->fwdng_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_request__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__overload_ctl_info_ie(gtp_del_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_bearer_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_response__overload_ctl_info_ie(gtp_create_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie(gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->s1u_enb_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_enb_fteid), buf + encoded);

if (value->s11_u_mme_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_mme_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes ran_info_rly_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ran_info_rly_t
* @return
*   number of encoded bytes.
*/
int encode_ran_info_rly(ran_info_rly_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->bss_container.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->bss_container), buf + encoded);

if (value->rim_rtng_addr.header.len)
        encoded += encode_gtp_trgt_id_ie(&(value->rim_rtng_addr), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes ue_reg_qry_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ue_reg_qry_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_ue_reg_qry_rsp(ue_reg_qry_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->selected_core_ntwk_oper_idnt.header.len)
        encoded += encode_gtp_plmn_id_ie(&(value->selected_core_ntwk_oper_idnt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes create_indir_data_fwdng_tunn_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_indir_data_fwdng_tunn_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_create_indir_data_fwdng_tunn_rsp(create_indir_data_fwdng_tunn_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie(gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->remote_user_id.header.len)
        encoded += encode_gtp_remote_user_id_ie(&(value->remote_user_id), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie(gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->remote_user_id.header.len)
        encoded += encode_gtp_remote_user_id_ie(&(value->remote_user_id), buf + encoded);

if (value->rmt_ue_ip_info.header.len)
        encoded += encode_gtp_rmt_ue_ip_info_ie(&(value->rmt_ue_ip_info), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_reloc_cmplt_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_reloc_cmplt_notif_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_cmplt_notif(fwd_reloc_cmplt_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_fail_indication__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_fail_indication__overload_ctl_info_ie(gtp_del_bearer_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->tft.header.len)
        encoded += encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(&(value->tft), buf + encoded);

if (value->s1u_enb_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_enb_fteid), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

if (value->s5s8_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s5s8_u_sgw_fteid), buf + encoded);

if (value->s5s8_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s5s8_u_pgw_fteid), buf + encoded);

if (value->s12_rnc_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_rnc_fteid), buf + encoded);

if (value->s2b_u_epdg_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2b_u_epdg_fteid), buf + encoded);

if (value->s2a_u_twan_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2a_u_twan_fteid), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->s11_u_mme_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_mme_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes del_bearer_cmd_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_bearer_cmd_t
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_cmd(del_bearer_cmd_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->uli_timestamp.header.len)
        encoded += encode_gtp_uli_timestamp_ie(&(value->uli_timestamp), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mod_bearer_cmd_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_bearer_cmd_t
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_cmd(mod_bearer_cmd_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->bearer_context.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_context), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mod_bearer_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_bearer_req_t
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_req(mod_bearer_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->mei.header.len)
        encoded += encode_gtp_mbl_equip_idnty_ie(&(value->mei), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->serving_network.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->serving_network), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->delay_dnlnk_pckt_notif_req.header.len)
        encoded += encode_gtp_delay_value_ie(&(value->delay_dnlnk_pckt_notif_req), buf + encoded);

if (value->bearer_contexts_to_be_modified.header.len)
        encoded += encode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(&(value->bearer_contexts_to_be_modified), buf + encoded);

if (value->bearer_contexts_to_be_removed.header.len)
        encoded += encode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(&(value->bearer_contexts_to_be_removed), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->uci.header.len)
        encoded += encode_gtp_user_csg_info_ie(&(value->uci), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->sgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->sgw_ldn), buf + encoded);

if (value->henb_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->henb_local_ip_addr), buf + encoded);

if (value->henb_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->henb_udp_port), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->cn_oper_sel_entity.header.len)
        encoded += encode_gtp_cn_oper_sel_entity_ie(&(value->cn_oper_sel_entity), buf + encoded);

if (value->pres_rptng_area_info.header.len)
        encoded += encode_gtp_pres_rptng_area_info_ie(&(value->pres_rptng_area_info), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->epdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->epdgs_ovrld_ctl_info), buf + encoded);

if (value->srvng_plmn_rate_ctl.header.len)
        encoded += encode_gtp_srvng_plmn_rate_ctl_ie(&(value->srvng_plmn_rate_ctl), buf + encoded);

if (value->mo_exception_data_cntr.header.len)
        encoded += encode_gtp_counter_ie(&(value->mo_exception_data_cntr), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->user_loc_info_sgw.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->user_loc_info_sgw), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_upd_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_upd_bearer_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_response__overload_ctl_info_ie(gtp_upd_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_request__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__bearer_ctxt_ie(gtp_del_bearer_request__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_upd_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_upd_bearer_request__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__overload_ctl_info_ie(gtp_upd_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes id_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    id_req_t
* @return
*   number of encoded bytes.
*/
int encode_id_req(id_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->guti.header.len)
        encoded += encode_gtp_guti_ie(&(value->guti), buf + encoded);

if (value->rai.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->rai), buf + encoded);

if (value->ptmsi.header.len)
        encoded += encode_gtp_ptmsi_ie(&(value->ptmsi), buf + encoded);

if (value->ptmsi_signature.header.len)
        encoded += encode_gtp_ptmsi_signature_ie(&(value->ptmsi_signature), buf + encoded);

if (value->cmplt_attach_req_msg.header.len)
        encoded += encode_gtp_cmplt_req_msg_ie(&(value->cmplt_attach_req_msg), buf + encoded);

if (value->addr_ctl_plane.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->addr_ctl_plane), buf + encoded);

if (value->udp_src_port_nbr.header.len)
        encoded += encode_gtp_port_number_ie(&(value->udp_src_port_nbr), buf + encoded);

if (value->hop_counter.header.len)
        encoded += encode_gtp_hop_counter_ie(&(value->hop_counter), buf + encoded);

if (value->target_plmn_id.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->target_plmn_id), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes ue_reg_qry_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ue_reg_qry_req_t
* @return
*   number of encoded bytes.
*/
int encode_ue_reg_qry_req(ue_reg_qry_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie(gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

if (value->apn_restriction.header.len)
        encoded += encode_gtp_apn_restriction_ie(&(value->apn_restriction), buf + encoded);

if (value->selection_mode.header.len)
        encoded += encode_gtp_selection_mode_ie(&(value->selection_mode), buf + encoded);

if (value->ipv4_address.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ipv4_address), buf + encoded);

if (value->ipv6_address.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ipv6_address), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->pgw_s5s8_ip_addr_ctl_plane_or_pmip.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_ip_addr_ctl_plane_or_pmip), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->chrgng_char.header.len)
        encoded += encode_gtp_chrgng_char_ie(&(value->chrgng_char), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sgnllng_priority_indctn.header.len)
        encoded += encode_gtp_sgnllng_priority_indctn_ie(&(value->sgnllng_priority_indctn), buf + encoded);

if (value->chg_to_rpt_flgs.header.len)
        encoded += encode_gtp_chg_to_rpt_flgs_ie(&(value->chg_to_rpt_flgs), buf + encoded);

if (value->local_home_ntwk_id.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->local_home_ntwk_id), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->wlan_offldblty_indctn.header.len)
        encoded += encode_gtp_wlan_offldblty_indctn_ie(&(value->wlan_offldblty_indctn), buf + encoded);

if (value->rmt_ue_ctxt_connected.header.len)
        encoded += encode_gtp_rmt_ue_ctxt_ie(&(value->rmt_ue_ctxt_connected), buf + encoded);

if (value->pdn_type.header.len)
        encoded += encode_gtp_pdn_type_ie(&(value->pdn_type), buf + encoded);

if (value->hdr_comp_cfg.header.len)
        encoded += encode_gtp_hdr_comp_cfg_ie(&(value->hdr_comp_cfg), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_dnlnk_data_notification__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_dnlnk_data_notification__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_dnlnk_data_notification__load_ctl_info_ie(gtp_dnlnk_data_notification__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

    return encoded;
}


/**
* Encodes del_sess_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_sess_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_del_sess_rsp(del_sess_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_reloc_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_reloc_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_rsp(fwd_reloc_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->senders_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->senders_fteid_ctl_plane), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->list_of_set_up_bearers.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->list_of_set_up_bearers), buf + encoded);

if (value->list_of_set_up_rabs.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->list_of_set_up_rabs), buf + encoded);

if (value->list_of_set_up_pfcs.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->list_of_set_up_pfcs), buf + encoded);

if (value->s1_ap_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->s1_ap_cause), buf + encoded);

if (value->ranap_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->ranap_cause), buf + encoded);

if (value->bssgp_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->bssgp_cause), buf + encoded);

if (value->e_utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->e_utran_transparent_cntnr), buf + encoded);

if (value->utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->utran_transparent_cntnr), buf + encoded);

if (value->bss_container.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->bss_container), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->sgsn_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgsn_node_name), buf + encoded);

if (value->mme_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->mme_node_name), buf + encoded);

if (value->sgsn_number.header.len)
        encoded += encode_gtp_node_number_ie(&(value->sgsn_number), buf + encoded);

if (value->sgsn_identifier.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->sgsn_identifier), buf + encoded);

if (value->mme_identifier.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->mme_identifier), buf + encoded);

if (value->mme_nbr_mt_sms.header.len)
        encoded += encode_gtp_node_number_ie(&(value->mme_nbr_mt_sms), buf + encoded);

if (value->sgsn_idnt_mt_sms.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->sgsn_idnt_mt_sms), buf + encoded);

if (value->mme_idnt_mt_sms.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->mme_idnt_mt_sms), buf + encoded);

if (value->list_of_set_up_bearers_scef_pdn_connections.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->list_of_set_up_bearers_scef_pdn_connections), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes trc_sess_actvn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trc_sess_actvn_t
* @return
*   number of encoded bytes.
*/
int encode_trc_sess_actvn(trc_sess_actvn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->trc_info.header.len)
        encoded += encode_gtp_trc_info_ie(&(value->trc_info), buf + encoded);

if (value->mei.header.len)
        encoded += encode_gtp_mbl_equip_idnty_ie(&(value->mei), buf + encoded);

    return encoded;
}


/**
* Encodes cfg_xfer_tunn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    cfg_xfer_tunn_t
* @return
*   number of encoded bytes.
*/
int encode_cfg_xfer_tunn(cfg_xfer_tunn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->e_utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->e_utran_transparent_cntnr), buf + encoded);

if (value->trgt_enb_id.header.len)
        encoded += encode_gtp_trgt_id_ie(&(value->trgt_enb_id), buf + encoded);

    return encoded;
}


/**
* Encodes detach_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    detach_notif_t
* @return
*   number of encoded bytes.
*/
int encode_detach_notif(detach_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->detach_type.header.len)
        encoded += encode_gtp_detach_type_ie(&(value->detach_type), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ctxt_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ctxt_response__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__bearer_ctxt_ie(gtp_ctxt_response__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->tft.header.len)
        encoded += encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(&(value->tft), buf + encoded);

if (value->sgw_s1s4s12s11_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s1s4s12s11_ip_addr_and_teid_user_plane), buf + encoded);

if (value->pgw_s5s8_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_ip_addr_and_teid_user_plane), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->bss_container.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->bss_container), buf + encoded);

if (value->trans_idnt.header.len)
        encoded += encode_gtp_trans_idnt_ie(&(value->trans_idnt), buf + encoded);

if (value->sgw_s11_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s11_ip_addr_and_teid_user_plane), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ctxt_response__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ctxt_response__remote_ue_ctxt_connected_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__remote_ue_ctxt_connected_ie(gtp_ctxt_response__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->remote_user_id.header.len)
        encoded += encode_gtp_remote_user_id_ie(&(value->remote_user_id), buf + encoded);

if (value->rmt_ue_ip_info.header.len)
        encoded += encode_gtp_rmt_ue_ip_info_ie(&(value->rmt_ue_ip_info), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_request_overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_request_overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_overload_ctl_info_ie(gtp_mod_bearer_request_overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_fwd_reloc_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fwd_reloc_request__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__bearer_ctxt_ie(gtp_fwd_reloc_request__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->tft.header.len)
        encoded += encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(&(value->tft), buf + encoded);

if (value->sgw_s1s4s12_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s1s4s12_ip_addr_and_teid_user_plane), buf + encoded);

if (value->pgw_s5s8_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_ip_addr_and_teid_user_plane), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->bss_container.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->bss_container), buf + encoded);

if (value->trans_idnt.header.len)
        encoded += encode_gtp_trans_idnt_ie(&(value->trans_idnt), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->sgw_s11_ip_addr_and_teid_user_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s11_ip_addr_and_teid_user_plane), buf + encoded);

    return encoded;
}


/**
* Encodes echo_request_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    echo_request_t
* @return
*   number of encoded bytes.
*/
int encode_echo_request(echo_request_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->sending_node_feat.header.len)
        encoded += encode_gtp_node_features_ie(&(value->sending_node_feat), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes rmt_ue_rpt_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    rmt_ue_rpt_notif_t
* @return
*   number of encoded bytes.
*/
int encode_rmt_ue_rpt_notif(rmt_ue_rpt_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->rmt_ue_ctxt_connected.header.len)
        encoded += encode_gtp_rmt_ue_ctxt_ie(&(value->rmt_ue_ctxt_connected), buf + encoded);

if (value->rmt_ue_ctxt_disconnected.header.len)
        encoded += encode_gtp_rmt_ue_ctxt_ie(&(value->rmt_ue_ctxt_disconnected), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes del_bearer_fail_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_bearer_fail_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_fail_indctn(del_bearer_fail_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->bearer_context.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_context), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes ctxt_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ctxt_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_ctxt_rsp(ctxt_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->mmesgsnamf_ue_eps_pdn_connections.header.len)
        encoded += encode_gtp_pdn_connection_ie(&(value->mmesgsnamf_ue_eps_pdn_connections), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->sgw_s11s4_ip_addr_and_teid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s11s4_ip_addr_and_teid_ctl_plane), buf + encoded);

if (value->sgw_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgw_node_name), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->trc_info.header.len)
        encoded += encode_gtp_trc_info_ie(&(value->trc_info), buf + encoded);

if (value->hrpd_acc_node_s101_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->hrpd_acc_node_s101_ip_addr), buf + encoded);

if (value->onexiws_sone02_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->onexiws_sone02_ip_addr), buf + encoded);

if (value->subscrbd_rfsp_idx.header.len)
        encoded += encode_gtp_rfsp_index_ie(&(value->subscrbd_rfsp_idx), buf + encoded);

if (value->rfsp_idx_in_use.header.len)
        encoded += encode_gtp_rfsp_index_ie(&(value->rfsp_idx_in_use), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->mdt_cfg.header.len)
        encoded += encode_gtp_mdt_cfg_ie(&(value->mdt_cfg), buf + encoded);

if (value->sgsn_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgsn_node_name), buf + encoded);

if (value->mme_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->mme_node_name), buf + encoded);

if (value->uci.header.len)
        encoded += encode_gtp_user_csg_info_ie(&(value->uci), buf + encoded);

if (value->mntrng_evnt_info.header.len)
        encoded += encode_gtp_mntrng_evnt_info_ie(&(value->mntrng_evnt_info), buf + encoded);

if (value->ue_usage_type.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->ue_usage_type), buf + encoded);

if (value->mmesgsn_ue_scef_pdn_connections.header.len)
        encoded += encode_gtp_scef_pdn_conn_ie(&(value->mmesgsn_ue_scef_pdn_connections), buf + encoded);

if (value->rat_type.header.len)
        encoded += encode_gtp_rat_type_ie(&(value->rat_type), buf + encoded);

if (value->srvng_plmn_rate_ctl.header.len)
        encoded += encode_gtp_srvng_plmn_rate_ctl_ie(&(value->srvng_plmn_rate_ctl), buf + encoded);

if (value->mo_exception_data_cntr.header.len)
        encoded += encode_gtp_counter_ie(&(value->mo_exception_data_cntr), buf + encoded);

if (value->rem_running_svc_gap_timer.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->rem_running_svc_gap_timer), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mod_bearer_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_bearer_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_rsp(mod_bearer_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->msisdn.header.len)
        encoded += encode_gtp_msisdn_ie(&(value->msisdn), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->apn_restriction.header.len)
        encoded += encode_gtp_apn_restriction_ie(&(value->apn_restriction), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->bearer_contexts_modified.header.len)
        encoded += encode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(&(value->bearer_contexts_modified), buf + encoded);

if (value->bearer_contexts_marked_removal.header.len)
        encoded += encode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(&(value->bearer_contexts_marked_removal), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->chrgng_gateway_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->chrgng_gateway_name), buf + encoded);

if (value->chrgng_gateway_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->chrgng_gateway_addr), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->sgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->sgw_ldn), buf + encoded);

if (value->pgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->pgw_ldn), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->pdn_conn_chrgng_id.header.len)
        encoded += encode_gtp_charging_id_ie(&(value->pdn_conn_chrgng_id), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_request__remote_ue_ctxt_connected_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request__remote_ue_ctxt_connected_ie(gtp_create_sess_request__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->remote_user_id.header.len)
        encoded += encode_gtp_remote_user_id_ie(&(value->remote_user_id), buf + encoded);

if (value->rmt_ue_ip_info.header.len)
        encoded += encode_gtp_rmt_ue_ip_info_ie(&(value->rmt_ue_ip_info), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_command__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_command__overload_ctl_info_ie(gtp_mod_bearer_command__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes mbms_sess_start_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mbms_sess_start_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_start_rsp(mbms_sess_start_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->mbms_dist_ack.header.len)
        encoded += encode_gtp_mbms_dist_ack_ie(&(value->mbms_dist_ack), buf + encoded);

if (value->sn_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sn_u_sgsn_fteid), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes context_request_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    context_request_t
* @return
*   number of encoded bytes.
*/
int encode_context_request(context_request_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->guti.header.len)
        encoded += encode_gtp_guti_ie(&(value->guti), buf + encoded);

if (value->rai.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->rai), buf + encoded);

if (value->ptmsi.header.len)
        encoded += encode_gtp_ptmsi_ie(&(value->ptmsi), buf + encoded);

if (value->ptmsi_signature.header.len)
        encoded += encode_gtp_ptmsi_signature_ie(&(value->ptmsi_signature), buf + encoded);

if (value->cmplt_tau_req_msg.header.len)
        encoded += encode_gtp_cmplt_req_msg_ie(&(value->cmplt_tau_req_msg), buf + encoded);

if (value->s3s16s10n26_addr_and_teid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s3s16s10n26_addr_and_teid_ctl_plane), buf + encoded);

if (value->udp_src_port_nbr.header.len)
        encoded += encode_gtp_port_number_ie(&(value->udp_src_port_nbr), buf + encoded);

if (value->rat_type.header.len)
        encoded += encode_gtp_rat_type_ie(&(value->rat_type), buf + encoded);

if (value->indication.header.len)
        encoded += encode_gtp_indication_ie(&(value->indication), buf + encoded);

if (value->hop_counter.header.len)
        encoded += encode_gtp_hop_counter_ie(&(value->hop_counter), buf + encoded);

if (value->target_plmn_id.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->target_plmn_id), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->sgsn_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgsn_node_name), buf + encoded);

if (value->mme_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->mme_node_name), buf + encoded);

if (value->sgsn_number.header.len)
        encoded += encode_gtp_node_number_ie(&(value->sgsn_number), buf + encoded);

if (value->sgsn_identifier.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->sgsn_identifier), buf + encoded);

if (value->mme_identifier.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->mme_identifier), buf + encoded);

if (value->ciot_optim_supp_indctn.header.len)
        encoded += encode_gtp_ciot_optim_supp_indctn_ie(&(value->ciot_optim_supp_indctn), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie(gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

if (value->dflt_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->dflt_eps_bearer_id), buf + encoded);

if (value->scef_id.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->scef_id), buf + encoded);

    return encoded;
}


/**
* Encodes mbms_sess_upd_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mbms_sess_upd_req_t
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_upd_req(mbms_sess_upd_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->mbms_svc_area.header.len)
        encoded += encode_gtp_mbms_svc_area_ie(&(value->mbms_svc_area), buf + encoded);

if (value->tmgi.header.len)
        encoded += encode_gtp_tmgi_ie(&(value->tmgi), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->mbms_sess_dur.header.len)
        encoded += encode_gtp_mbms_sess_dur_ie(&(value->mbms_sess_dur), buf + encoded);

if (value->qos_profile.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->qos_profile), buf + encoded);

if (value->mbms_sess_idnt.header.len)
        encoded += encode_gtp_mbms_sess_idnt_ie(&(value->mbms_sess_idnt), buf + encoded);

if (value->mbms_flow_idnt.header.len)
        encoded += encode_gtp_mbms_flow_idnt_ie(&(value->mbms_flow_idnt), buf + encoded);

if (value->mbms_time_to_data_xfer.header.len)
        encoded += encode_gtp_mbms_time_to_data_xfer_ie(&(value->mbms_time_to_data_xfer), buf + encoded);

if (value->mbms_data_xfer_start_upd_stop.header.len)
        encoded += encode_gtp_mbms_data_xfer_abs_time_ie(&(value->mbms_data_xfer_start_upd_stop), buf + encoded);

if (value->mbms_cell_list.header.len)
        encoded += encode_gtp_ecgi_list_ie(&(value->mbms_cell_list), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes create_sess_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_sess_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_create_sess_rsp(create_sess_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc), buf + encoded);

if (value->paa.header.len)
        encoded += encode_gtp_pdn_addr_alloc_ie(&(value->paa), buf + encoded);

if (value->apn_restriction.header.len)
        encoded += encode_gtp_apn_restriction_ie(&(value->apn_restriction), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->bearer_contexts_created.header.len)
        encoded += encode_gtp_create_sess_response_bearer_ctxt_created_ie(&(value->bearer_contexts_created), buf + encoded);

if (value->bearer_contexts_marked_removal.header.len)
        encoded += encode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(&(value->bearer_contexts_marked_removal), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->chrgng_gateway_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->chrgng_gateway_name), buf + encoded);

if (value->chrgng_gateway_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->chrgng_gateway_addr), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->sgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->sgw_ldn), buf + encoded);

if (value->pgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->pgw_ldn), buf + encoded);

if (value->pgw_back_off_time.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->pgw_back_off_time), buf + encoded);

if (value->apco.header.len)
        encoded += encode_gtp_addtl_prot_cfg_opts_ie(&(value->apco), buf + encoded);

if (value->trstd_wlan_ipv4_parms.header.len)
        encoded += encode_gtp_ipv4_cfg_parms_ie(&(value->trstd_wlan_ipv4_parms), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->pdn_conn_chrgng_id.header.len)
        encoded += encode_gtp_charging_id_ie(&(value->pdn_conn_chrgng_id), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_acc_ctxt_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_acc_ctxt_ack_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_acc_ctxt_ack(fwd_acc_ctxt_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_response_bearer_ctxt_created_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_response_bearer_ctxt_created_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response_bearer_ctxt_created_ie(gtp_create_sess_response_bearer_ctxt_created_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid), buf + encoded);

if (value->s4_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgw_fteid), buf + encoded);

if (value->s5s8_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s5s8_u_pgw_fteid), buf + encoded);

if (value->s12_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_sgw_fteid), buf + encoded);

if (value->s2b_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2b_u_pgw_fteid), buf + encoded);

if (value->s2a_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2a_u_pgw_fteid), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->charging_id.header.len)
        encoded += encode_gtp_charging_id_ie(&(value->charging_id), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->s11_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_sgw_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_bearer_request__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request__load_ctl_info_ie(gtp_create_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes create_bearer_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_bearer_req_t
* @return
*   number of encoded bytes.
*/
int encode_create_bearer_req(create_bearer_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->pti.header.len)
        encoded += encode_gtp_proc_trans_id_ie(&(value->pti), buf + encoded);

if (value->lbi.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->lbi), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_create_bearer_request_bearer_ctxt_ie(&(value->bearer_contexts), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_request__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request__overload_ctl_info_ie(gtp_create_sess_request__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes bearer_rsrc_fail_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    bearer_rsrc_fail_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_bearer_rsrc_fail_indctn(bearer_rsrc_fail_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->pti.header.len)
        encoded += encode_gtp_proc_trans_id_ie(&(value->pti), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_bearer_request__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request_bearer_ctxt_ie(gtp_create_bearer_request_bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->tft.header.len)
        encoded += encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(&(value->tft), buf + encoded);

if (value->s1u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid), buf + encoded);

if (value->s58_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s58_u_pgw_fteid), buf + encoded);

if (value->s12_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_sgw_fteid), buf + encoded);

if (value->s4_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgw_fteid), buf + encoded);

if (value->s2b_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2b_u_pgw_fteid), buf + encoded);

if (value->s2a_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2a_u_pgw_fteid), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->charging_id.header.len)
        encoded += encode_gtp_charging_id_ie(&(value->charging_id), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->max_pckt_loss_rate.header.len)
        encoded += encode_gtp_max_pckt_loss_rate_ie(&(value->max_pckt_loss_rate), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response__overload_ctl_info_ie(gtp_create_sess_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes pgw_dnlnk_trigrng_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pgw_dnlnk_trigrng_ack_t
* @return
*   number of encoded bytes.
*/
int encode_pgw_dnlnk_trigrng_ack(pgw_dnlnk_trigrng_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_bearer_request__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request__overload_ctl_info_ie(gtp_create_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_sess_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_sess_request__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_request__overload_ctl_info_ie(gtp_del_sess_request__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes echo_response_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    echo_response_t
* @return
*   number of encoded bytes.
*/
int encode_echo_response(echo_response_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->sending_node_feat.header.len)
        encoded += encode_gtp_node_features_ie(&(value->sending_node_feat), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mbms_sess_upd_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mbms_sess_upd_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_upd_rsp(mbms_sess_upd_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->mbms_dist_ack.header.len)
        encoded += encode_gtp_mbms_dist_ack_ie(&(value->mbms_dist_ack), buf + encoded);

if (value->sn_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sn_u_sgsn_fteid), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_fail_indication__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_fail_indication__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_fail_indication__bearer_ctxt_ie(gtp_del_bearer_fail_indication__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_command__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_command__overload_ctl_info_ie(gtp_del_bearer_command__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie(gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->remote_user_id.header.len)
        encoded += encode_gtp_remote_user_id_ie(&(value->remote_user_id), buf + encoded);

if (value->rmt_ue_ip_info.header.len)
        encoded += encode_gtp_rmt_ue_ip_info_ie(&(value->rmt_ue_ip_info), buf + encoded);

    return encoded;
}


/**
* Encodes mod_acc_bearers_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_acc_bearers_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_mod_acc_bearers_rsp(mod_acc_bearers_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->bearer_contexts_modified.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts_modified), buf + encoded);

if (value->bearer_contexts_marked_removal.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts_marked_removal), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__overload_ctl_info_ie(gtp_mod_acc_bearers_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes mod_bearer_fail_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_bearer_fail_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_fail_indctn(mod_bearer_fail_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes pgw_rstrt_notif_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pgw_rstrt_notif_ack_t
* @return
*   number of encoded bytes.
*/
int encode_pgw_rstrt_notif_ack(pgw_rstrt_notif_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie(gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

if (value->apn_restriction.header.len)
        encoded += encode_gtp_apn_restriction_ie(&(value->apn_restriction), buf + encoded);

if (value->selection_mode.header.len)
        encoded += encode_gtp_selection_mode_ie(&(value->selection_mode), buf + encoded);

if (value->ipv4_address.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ipv4_address), buf + encoded);

if (value->ipv6_address.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ipv6_address), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->pgw_s5s8_ip_addr_ctl_plane_or_pmip.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_ip_addr_ctl_plane_or_pmip), buf + encoded);

if (value->pgw_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->pgw_node_name), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->chrgng_char.header.len)
        encoded += encode_gtp_chrgng_char_ie(&(value->chrgng_char), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sgnllng_priority_indctn.header.len)
        encoded += encode_gtp_sgnllng_priority_indctn_ie(&(value->sgnllng_priority_indctn), buf + encoded);

if (value->chg_to_rpt_flgs.header.len)
        encoded += encode_gtp_chg_to_rpt_flgs_ie(&(value->chg_to_rpt_flgs), buf + encoded);

if (value->local_home_ntwk_id.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->local_home_ntwk_id), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->wlan_offldblty_indctn.header.len)
        encoded += encode_gtp_wlan_offldblty_indctn_ie(&(value->wlan_offldblty_indctn), buf + encoded);

if (value->rmt_ue_ctxt_connected.header.len)
        encoded += encode_gtp_rmt_ue_ctxt_ie(&(value->rmt_ue_ctxt_connected), buf + encoded);

if (value->pdn_type.header.len)
        encoded += encode_gtp_pdn_type_ie(&(value->pdn_type), buf + encoded);

if (value->hdr_comp_cfg.header.len)
        encoded += encode_gtp_hdr_comp_cfg_ie(&(value->hdr_comp_cfg), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_command__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_command__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_command__bearer_ctxt_ie(gtp_del_bearer_command__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->ran_nas_release_cause.header.len)
        encoded += encode_gtp_ran_nas_cause_ie(&(value->ran_nas_release_cause), buf + encoded);

    return encoded;
}


/**
* Encodes pgw_dnlnk_trigrng_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pgw_dnlnk_trigrng_notif_t
* @return
*   number of encoded bytes.
*/
int encode_pgw_dnlnk_trigrng_notif(pgw_dnlnk_trigrng_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->pgw_s5_fteid_gtp_or_pmip_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5_fteid_gtp_or_pmip_ctl_plane), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response__overload_ctl_info_ie(gtp_mod_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes id_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    id_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_id_rsp(id_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

// if (value->mmesgsn_ue_mm_ctxt.header.len)
//         encoded += encode_gtp_mm_context(&(value->mmesgsn_ue_mm_ctxt), buf + encoded);

if (value->trc_info.header.len)
        encoded += encode_gtp_trc_info_ie(&(value->trc_info), buf + encoded);

if (value->ue_usage_type.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->ue_usage_type), buf + encoded);

if (value->mntrng_evnt_info.header.len)
        encoded += encode_gtp_mntrng_evnt_info_ie(&(value->mntrng_evnt_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie(gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->enb_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->enb_fteid_dl_data_fwdng), buf + encoded);

if (value->sgsn_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgsn_fteid_dl_data_fwdng), buf + encoded);

if (value->rnc_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->rnc_fteid_dl_data_fwdng), buf + encoded);

if (value->enb_fteid_ul_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->enb_fteid_ul_data_fwdng), buf + encoded);

if (value->sgw_fteid_ul_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_fteid_ul_data_fwdng), buf + encoded);

if (value->mme_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->mme_fteid_dl_data_fwdng), buf + encoded);

    return encoded;
}


/**
* Encodes create_sess_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_sess_req_t
* @return
*   number of encoded bytes.
*/
int encode_create_sess_req(create_sess_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->msisdn.header.len)
        encoded += encode_gtp_msisdn_ie(&(value->msisdn), buf + encoded);

if (value->mei.header.len)
        encoded += encode_gtp_mbl_equip_idnty_ie(&(value->mei), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->serving_network.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->serving_network), buf + encoded);

if (value->rat_type.header.len)
        encoded += encode_gtp_rat_type_ie(&(value->rat_type), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->pgw_s5s8_addr_ctl_plane_or_pmip.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->pgw_s5s8_addr_ctl_plane_or_pmip), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

if (value->selection_mode.header.len)
        encoded += encode_gtp_selection_mode_ie(&(value->selection_mode), buf + encoded);

if (value->pdn_type.header.len)
        encoded += encode_gtp_pdn_type_ie(&(value->pdn_type), buf + encoded);

if (value->paa.header.len)
        encoded += encode_gtp_pdn_addr_alloc_ie(&(value->paa), buf + encoded);

if (value->max_apn_rstrct.header.len)
        encoded += encode_gtp_apn_restriction_ie(&(value->max_apn_rstrct), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->linked_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->linked_eps_bearer_id), buf + encoded);

if (value->trstd_wlan_mode_indctn.header.len)
        encoded += encode_gtp_trstd_wlan_mode_indctn_ie(&(value->trstd_wlan_mode_indctn), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->bearer_contexts_to_be_created.header.len)
        encoded += encode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(&(value->bearer_contexts_to_be_created), buf + encoded);

if (value->bearer_contexts_to_be_removed.header.len)
        encoded += encode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(&(value->bearer_contexts_to_be_removed), buf + encoded);

if (value->trc_info.header.len)
        encoded += encode_gtp_trc_info_ie(&(value->trc_info), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->epdg_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->epdg_fqcsid), buf + encoded);

if (value->twan_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->twan_fqcsid), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->uci.header.len)
        encoded += encode_gtp_user_csg_info_ie(&(value->uci), buf + encoded);

if (value->chrgng_char.header.len)
        encoded += encode_gtp_chrgng_char_ie(&(value->chrgng_char), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->sgw_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->sgw_ldn), buf + encoded);

if (value->epdg_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->epdg_ldn), buf + encoded);

if (value->twan_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->twan_ldn), buf + encoded);

if (value->sgnllng_priority_indctn.header.len)
        encoded += encode_gtp_sgnllng_priority_indctn_ie(&(value->sgnllng_priority_indctn), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->apco.header.len)
        encoded += encode_gtp_addtl_prot_cfg_opts_ie(&(value->apco), buf + encoded);

if (value->henb_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->henb_local_ip_addr), buf + encoded);

if (value->henb_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->henb_udp_port), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->twan_identifier.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->twan_identifier), buf + encoded);

if (value->epdg_ip_address.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->epdg_ip_address), buf + encoded);

if (value->cn_oper_sel_entity.header.len)
        encoded += encode_gtp_cn_oper_sel_entity_ie(&(value->cn_oper_sel_entity), buf + encoded);

if (value->pres_rptng_area_info.header.len)
        encoded += encode_gtp_pres_rptng_area_info_ie(&(value->pres_rptng_area_info), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->origination_time_stmp.header.len)
        encoded += encode_gtp_msec_time_stmp_ie(&(value->origination_time_stmp), buf + encoded);

if (value->max_wait_time.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->max_wait_time), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->rmt_ue_ctxt_connected.header.len)
        encoded += encode_gtp_rmt_ue_ctxt_ie(&(value->rmt_ue_ctxt_connected), buf + encoded);

if (value->threegpp_aaa_server_idnt.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->threegpp_aaa_server_idnt), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->srvng_plmn_rate_ctl.header.len)
        encoded += encode_gtp_srvng_plmn_rate_ctl_ie(&(value->srvng_plmn_rate_ctl), buf + encoded);

if (value->mo_exception_data_cntr.header.len)
        encoded += encode_gtp_counter_ie(&(value->mo_exception_data_cntr), buf + encoded);

if (value->ue_tcp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_tcp_port), buf + encoded);

if (value->mapped_ue_usage_type.header.len)
        encoded += encode_gtp_mapped_ue_usage_type_ie(&(value->mapped_ue_usage_type), buf + encoded);

if (value->user_loc_info_sgw.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->user_loc_info_sgw), buf + encoded);

if (value->sgw_u_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgw_u_node_name), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->up_func_sel_indctn_flgs.header.len)
        encoded += encode_gtp_up_func_sel_indctn_flgs_ie(&(value->up_func_sel_indctn_flgs), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

//if (value->serving_network.header.len)
//        encoded += encode_gtp_serving_network_ie(&(value->serving_network), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes upd_bearer_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    upd_bearer_req_t
* @return
*   number of encoded bytes.
*/
int encode_upd_bearer_req(upd_bearer_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->pti.header.len)
        encoded += encode_gtp_proc_trans_id_ie(&(value->pti), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->apn_ambr.header.len)
        encoded += encode_gtp_agg_max_bit_rate_ie(&(value->apn_ambr), buf + encoded);

if (value->chg_rptng_act.header.len)
        encoded += encode_gtp_chg_rptng_act_ie(&(value->chg_rptng_act), buf + encoded);

if (value->csg_info_rptng_act.header.len)
        encoded += encode_gtp_csg_info_rptng_act_ie(&(value->csg_info_rptng_act), buf + encoded);

if (value->henb_info_rptng.header.len)
        encoded += encode_gtp_henb_info_rptng_ie(&(value->henb_info_rptng), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->pres_rptng_area_act.header.len)
        encoded += encode_gtp_pres_rptng_area_act_ie(&(value->pres_rptng_area_act), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes del_bearer_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_bearer_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_rsp(del_bearer_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->lbi.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->lbi), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->epdg_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->epdg_fqcsid), buf + encoded);

if (value->twan_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->twan_fqcsid), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->uli_timestamp.header.len)
        encoded += encode_gtp_uli_timestamp_ie(&(value->uli_timestamp), buf + encoded);

if (value->twan_identifier.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->twan_identifier), buf + encoded);

if (value->twan_idnt_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->twan_idnt_ts), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->ue_tcp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_tcp_port), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

    return encoded;
}


/**
* Encodes pgw_rstrt_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    pgw_rstrt_notif_t
* @return
*   number of encoded bytes.
*/
int encode_pgw_rstrt_notif(pgw_rstrt_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->pgw_s5s8_ip_addr_ctl_plane_or_pmip.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->pgw_s5s8_ip_addr_ctl_plane_or_pmip), buf + encoded);

if (value->sgw_s11s4_ip_addr_ctl_plane.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->sgw_s11s4_ip_addr_ctl_plane), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes reloc_cncl_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    reloc_cncl_req_t
* @return
*   number of encoded bytes.
*/
int encode_reloc_cncl_req(reloc_cncl_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->mei.header.len)
        encoded += encode_gtp_mbl_equip_idnty_ie(&(value->mei), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->ranap_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->ranap_cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_sess_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_sess_response__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_response__load_ctl_info_ie(gtp_del_sess_response__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_upd_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_upd_bearer_request__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__load_ctl_info_ie(gtp_upd_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_upd_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_upd_bearer_response__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_response__bearer_ctxt_ie(gtp_upd_bearer_response__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

if (value->s12_rnc_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_rnc_fteid), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->ran_nas_cause.header.len)
        encoded += encode_gtp_ran_nas_cause_ie(&(value->ran_nas_cause), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_bearer_response__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_response_bearer_ctxt_ie(gtp_create_bearer_response_bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_enb_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_enb_fteid), buf + encoded);

if (value->s1u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid), buf + encoded);

if (value->s58_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s58_u_sgw_fteid), buf + encoded);

if (value->s58_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s58_u_pgw_fteid), buf + encoded);

if (value->s12_rnc_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_rnc_fteid), buf + encoded);

if (value->s12_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_sgw_fteid), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

if (value->s4_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgw_fteid), buf + encoded);

if (value->s2b_u_epdg_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2b_u_epdg_fteid), buf + encoded);

if (value->s2b_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2b_u_pgw_fteid), buf + encoded);

if (value->s2a_u_twan_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2a_u_twan_fteid), buf + encoded);

if (value->s2a_u_pgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s2a_u_pgw_fteid), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->ran_nas_cause.header.len)
        encoded += encode_gtp_ran_nas_cause_ie(&(value->ran_nas_cause), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie(gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_upd_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_upd_bearer_request__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__bearer_ctxt_ie(gtp_upd_bearer_request__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->tft.header.len)
        encoded += encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(&(value->tft), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->apco.header.len)
        encoded += encode_gtp_addtl_prot_cfg_opts_ie(&(value->apco), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->max_pckt_loss_rate.header.len)
        encoded += encode_gtp_max_pckt_loss_rate_ie(&(value->max_pckt_loss_rate), buf + encoded);

    return encoded;
}


/**
* Encodes upd_bearer_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    upd_bearer_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_upd_bearer_rsp(upd_bearer_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->epdg_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->epdg_fqcsid), buf + encoded);

if (value->twan_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->twan_fqcsid), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->twan_identifier.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->twan_identifier), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->pres_rptng_area_info.header.len)
        encoded += encode_gtp_pres_rptng_area_info_ie(&(value->pres_rptng_area_info), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->ue_tcp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_tcp_port), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_response_bearer_ctxt_modified_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_response_bearer_ctxt_modified_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(gtp_mod_bearer_response_bearer_ctxt_modified_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid), buf + encoded);

if (value->s12_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_sgw_fteid), buf + encoded);

if (value->s4_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgw_fteid), buf + encoded);

if (value->charging_id.header.len)
        encoded += encode_gtp_charging_id_ie(&(value->charging_id), buf + encoded);

if (value->bearer_flags.header.len)
        encoded += encode_gtp_bearer_flags_ie(&(value->bearer_flags), buf + encoded);

if (value->s11_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_sgw_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_sess_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_sess_response__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response__load_ctl_info_ie(gtp_create_sess_response__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes mod_acc_bearers_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mod_acc_bearers_req_t
* @return
*   number of encoded bytes.
*/
int encode_mod_acc_bearers_req(mod_acc_bearers_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->delay_dnlnk_pckt_notif_req.header.len)
        encoded += encode_gtp_delay_value_ie(&(value->delay_dnlnk_pckt_notif_req), buf + encoded);

if (value->bearer_contexts_to_be_modified.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts_to_be_modified), buf + encoded);

if (value->bearer_contexts_to_be_removed.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts_to_be_removed), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mbms_sess_stop_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mbms_sess_stop_req_t
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_stop_req(mbms_sess_stop_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->mbms_flow_idnt.header.len)
        encoded += encode_gtp_mbms_flow_idnt_ie(&(value->mbms_flow_idnt), buf + encoded);

if (value->mbms_data_xfer_stop.header.len)
        encoded += encode_gtp_mbms_data_xfer_abs_time_ie(&(value->mbms_data_xfer_stop), buf + encoded);

if (value->mbms_flags.header.len)
        encoded += encode_gtp_mbms_flags_ie(&(value->mbms_flags), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie(gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid), buf + encoded);

if (value->s11_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_sgw_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes del_pdn_conn_set_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_pdn_conn_set_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_del_pdn_conn_set_rsp(del_pdn_conn_set_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_acc_ctxt_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_acc_ctxt_notif_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_acc_ctxt_notif(fwd_acc_ctxt_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->rab_contexts.header.len)
        encoded += encode_gtp_rab_context_ie(&(value->rab_contexts), buf + encoded);

if (value->src_rnc_pdcp_ctxt_info.header.len)
        encoded += encode_gtp_src_rnc_pdcp_ctxt_info_ie(&(value->src_rnc_pdcp_ctxt_info), buf + encoded);

if (value->pdu_numbers.header.len)
        encoded += encode_gtp_pdu_numbers_ie(&(value->pdu_numbers), buf + encoded);

if (value->e_utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->e_utran_transparent_cntnr), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_request__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__load_ctl_info_ie(gtp_del_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_response__overload_ctl_info_ie(gtp_del_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_dnlnk_data_notification__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_dnlnk_data_notification__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_dnlnk_data_notification__overload_ctl_info_ie(gtp_dnlnk_data_notification__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_release_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_release_acc_bearers_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_release_acc_bearers_response__overload_ctl_info_ie(gtp_release_acc_bearers_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_fail_indication__overload_ctl_info_ie(gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes ctxt_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ctxt_ack_t
* @return
*   number of encoded bytes.
*/
int encode_ctxt_ack(ctxt_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->fwdng_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->fwdng_fteid), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->sgsn_number.header.len)
        encoded += encode_gtp_node_number_ie(&(value->sgsn_number), buf + encoded);

if (value->mme_nbr_mt_sms.header.len)
        encoded += encode_gtp_node_number_ie(&(value->mme_nbr_mt_sms), buf + encoded);

if (value->sgsn_idnt_mt_sms.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->sgsn_idnt_mt_sms), buf + encoded);

if (value->mme_idnt_mt_sms.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->mme_idnt_mt_sms), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes alert_mme_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    alert_mme_ack_t
* @return
*   number of encoded bytes.
*/
int encode_alert_mme_ack(alert_mme_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes create_fwdng_tunn_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_fwdng_tunn_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_create_fwdng_tunn_rsp(create_fwdng_tunn_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_data_fwdng.header.len)
        encoded += encode_gtp_s1u_data_fwdng_ie(&(value->s1u_data_fwdng), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes dnlnk_data_notif_fail_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    dnlnk_data_notif_fail_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif_fail_indctn(dnlnk_data_notif_fail_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->originating_node.header.len)
        encoded += encode_gtp_node_type_ie(&(value->originating_node), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->s1_enodeb_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1_enodeb_fteid), buf + encoded);

if (value->s58_u_sgw_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s58_u_sgw_fteid), buf + encoded);

if (value->s12_rnc_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_rnc_fteid), buf + encoded);

if (value->s4_u_sgsn_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgsn_fteid), buf + encoded);

if (value->s11_u_mme_fteid.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s11_u_mme_fteid), buf + encoded);

    return encoded;
}


/**
* Encodes ue_actvty_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ue_actvty_ack_t
* @return
*   number of encoded bytes.
*/
int encode_ue_actvty_ack(ue_actvty_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_command__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_command__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_command__bearer_ctxt_ie(gtp_mod_bearer_command__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->bearer_lvl_qos.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->bearer_lvl_qos), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie(gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

if (value->dflt_eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->dflt_eps_bearer_id), buf + encoded);

if (value->scef_id.header.len)
        encoded += encode_gtp_node_identifier_ie(&(value->scef_id), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_release_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_release_acc_bearers_response__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_release_acc_bearers_response__load_ctl_info_ie(gtp_release_acc_bearers_response__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

    return encoded;
}


/**
* Encodes trc_sess_deact_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trc_sess_deact_t
* @return
*   number of encoded bytes.
*/
int encode_trc_sess_deact(trc_sess_deact_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->trace_reference.header.len)
        encoded += encode_gtp_trace_reference_ie(&(value->trace_reference), buf + encoded);

    return encoded;
}


/**
* Encodes dnlnk_data_notif_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    dnlnk_data_notif_t
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif(dnlnk_data_notif_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->alloc_reten_priority.header.len)
        encoded += encode_gtp_alloc_reten_priority_ie(&(value->alloc_reten_priority), buf + encoded);

if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->paging_and_svc_info.header.len)
        encoded += encode_gtp_paging_and_svc_info_ie(&(value->paging_and_svc_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes create_indir_data_fwdng_tunn_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_indir_data_fwdng_tunn_req_t
* @return
*   number of encoded bytes.
*/
int encode_create_indir_data_fwdng_tunn_req(create_indir_data_fwdng_tunn_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->mei.header.len)
        encoded += encode_gtp_mbl_equip_idnty_ie(&(value->mei), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->bearer_contexts), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes mbms_sess_start_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mbms_sess_start_req_t
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_start_req(mbms_sess_start_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->tmgi.header.len)
        encoded += encode_gtp_tmgi_ie(&(value->tmgi), buf + encoded);

if (value->mbms_sess_dur.header.len)
        encoded += encode_gtp_mbms_sess_dur_ie(&(value->mbms_sess_dur), buf + encoded);

if (value->mbms_svc_area.header.len)
        encoded += encode_gtp_mbms_svc_area_ie(&(value->mbms_svc_area), buf + encoded);

if (value->mbms_sess_idnt.header.len)
        encoded += encode_gtp_mbms_sess_idnt_ie(&(value->mbms_sess_idnt), buf + encoded);

if (value->mbms_flow_idnt.header.len)
        encoded += encode_gtp_mbms_flow_idnt_ie(&(value->mbms_flow_idnt), buf + encoded);

if (value->qos_profile.header.len)
        encoded += encode_gtp_bearer_qlty_of_svc_ie(&(value->qos_profile), buf + encoded);

if (value->mbms_ip_multcst_dist.header.len)
        encoded += encode_gtp_mbms_ip_multcst_dist_ie(&(value->mbms_ip_multcst_dist), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->mbms_time_to_data_xfer.header.len)
        encoded += encode_gtp_mbms_time_to_data_xfer_ie(&(value->mbms_time_to_data_xfer), buf + encoded);

if (value->mbms_data_xfer_start.header.len)
        encoded += encode_gtp_mbms_data_xfer_abs_time_ie(&(value->mbms_data_xfer_start), buf + encoded);

if (value->mbms_flags.header.len)
        encoded += encode_gtp_mbms_flags_ie(&(value->mbms_flags), buf + encoded);

if (value->mbms_alternative_ip_multcst_dist.header.len)
        encoded += encode_gtp_mbms_ip_multcst_dist_ie(&(value->mbms_alternative_ip_multcst_dist), buf + encoded);

if (value->mbms_cell_list.header.len)
        encoded += encode_gtp_ecgi_list_ie(&(value->mbms_cell_list), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes del_bearer_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_bearer_req_t
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_req(del_bearer_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->eps_bearer_ids.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_ids), buf + encoded);

if (value->failed_bearer_contexts.header.len)
        encoded += encode_gtp_bearer_context_ie(&(value->failed_bearer_contexts), buf + encoded);

if (value->pti.header.len)
        encoded += encode_gtp_proc_trans_id_ie(&(value->pti), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_apn_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->pgws_apn_lvl_load_ctl_info), buf + encoded);

if (value->sgws_node_lvl_load_ctl_info.header.len)
        encoded += encode_gtp_load_ctl_info_ie(&(value->sgws_node_lvl_load_ctl_info), buf + encoded);

if (value->pgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->pgws_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes fwd_reloc_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    fwd_reloc_req_t
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_req(fwd_reloc_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->senders_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->senders_fteid_ctl_plane), buf + encoded);

if (value->mmesgsnamf_ue_eps_pdn_connections.header.len)
        encoded += encode_gtp_pdn_connection_ie(&(value->mmesgsnamf_ue_eps_pdn_connections), buf + encoded);

if (value->sgw_s11s4_ip_addr_and_teid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_s11s4_ip_addr_and_teid_ctl_plane), buf + encoded);

if (value->sgw_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgw_node_name), buf + encoded);

// if (value->mmesgsnamf_ue_mm_ctxt.header.len)
        // encoded += encode_gtp_mm_context(&(value->mmesgsnamf_ue_mm_ctxt), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->e_utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->e_utran_transparent_cntnr), buf + encoded);

if (value->utran_transparent_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->utran_transparent_cntnr), buf + encoded);

if (value->bss_container.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->bss_container), buf + encoded);

if (value->trgt_id.header.len)
        encoded += encode_gtp_trgt_id_ie(&(value->trgt_id), buf + encoded);

if (value->hrpd_acc_node_s101_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->hrpd_acc_node_s101_ip_addr), buf + encoded);

if (value->onexiws_sone02_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->onexiws_sone02_ip_addr), buf + encoded);

if (value->s1_ap_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->s1_ap_cause), buf + encoded);

if (value->ranap_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->ranap_cause), buf + encoded);

if (value->bssgp_cause.header.len)
        encoded += encode_gtp_full_qual_cause_ie(&(value->bssgp_cause), buf + encoded);

if (value->src_id.header.len)
        encoded += encode_gtp_src_id_ie(&(value->src_id), buf + encoded);

if (value->selected_plmn_id.header.len)
        encoded += encode_gtp_plmn_id_ie(&(value->selected_plmn_id), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->trc_info.header.len)
        encoded += encode_gtp_trc_info_ie(&(value->trc_info), buf + encoded);

if (value->subscrbd_rfsp_idx.header.len)
        encoded += encode_gtp_rfsp_index_ie(&(value->subscrbd_rfsp_idx), buf + encoded);

if (value->rfsp_idx_in_use.header.len)
        encoded += encode_gtp_rfsp_index_ie(&(value->rfsp_idx_in_use), buf + encoded);

if (value->csg_id.header.len)
        encoded += encode_gtp_csg_id_ie(&(value->csg_id), buf + encoded);

if (value->csg_memb_indctn.header.len)
        encoded += encode_gtp_csg_memb_indctn_ie(&(value->csg_memb_indctn), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->serving_network.header.len)
        encoded += encode_gtp_serving_network_ie(&(value->serving_network), buf + encoded);

if (value->mmes4_sgsn_ldn.header.len)
        encoded += encode_gtp_local_distgsd_name_ie(&(value->mmes4_sgsn_ldn), buf + encoded);

if (value->addtl_mm_ctxt_srvcc.header.len)
        encoded += encode_gtp_addtl_mm_ctxt_srvcc_ie(&(value->addtl_mm_ctxt_srvcc), buf + encoded);

if (value->addtl_flgs_srvcc.header.len)
        encoded += encode_gtp_addtl_flgs_srvcc_ie(&(value->addtl_flgs_srvcc), buf + encoded);

if (value->stn_sr.header.len)
        encoded += encode_gtp_stn_sr_ie(&(value->stn_sr), buf + encoded);

if (value->c_msisdn.header.len)
        encoded += encode_gtp_msisdn_ie(&(value->c_msisdn), buf + encoded);

if (value->mdt_cfg.header.len)
        encoded += encode_gtp_mdt_cfg_ie(&(value->mdt_cfg), buf + encoded);

if (value->sgsn_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->sgsn_node_name), buf + encoded);

if (value->mme_node_name.header.len)
        encoded += encode_gtp_fully_qual_domain_name_ie(&(value->mme_node_name), buf + encoded);

if (value->uci.header.len)
        encoded += encode_gtp_user_csg_info_ie(&(value->uci), buf + encoded);

if (value->mntrng_evnt_info.header.len)
        encoded += encode_gtp_mntrng_evnt_info_ie(&(value->mntrng_evnt_info), buf + encoded);

if (value->ue_usage_type.header.len)
        encoded += encode_gtp_integer_number_ie(&(value->ue_usage_type), buf + encoded);

if (value->mmesgsn_ue_scef_pdn_connections.header.len)
        encoded += encode_gtp_scef_pdn_conn_ie(&(value->mmesgsn_ue_scef_pdn_connections), buf + encoded);

if (value->msisdn.header.len)
        encoded += encode_gtp_msisdn_ie(&(value->msisdn), buf + encoded);

if (value->src_udp_port_nbr.header.len)
        encoded += encode_gtp_port_number_ie(&(value->src_udp_port_nbr), buf + encoded);

if (value->srvng_plmn_rate_ctl.header.len)
        encoded += encode_gtp_srvng_plmn_rate_ctl_ie(&(value->srvng_plmn_rate_ctl), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie(gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes del_sess_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    del_sess_req_t
* @return
*   number of encoded bytes.
*/
int encode_del_sess_req(del_sess_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->lbi.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->lbi), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->indctn_flgs.header.len)
        encoded += encode_gtp_indication_ie(&(value->indctn_flgs), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->originating_node.header.len)
        encoded += encode_gtp_node_type_ie(&(value->originating_node), buf + encoded);

if (value->sender_fteid_ctl_plane.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sender_fteid_ctl_plane), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->uli_timestamp.header.len)
        encoded += encode_gtp_uli_timestamp_ie(&(value->uli_timestamp), buf + encoded);

if (value->ran_nas_release_cause.header.len)
        encoded += encode_gtp_ran_nas_cause_ie(&(value->ran_nas_release_cause), buf + encoded);

if (value->twan_identifier.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->twan_identifier), buf + encoded);

if (value->twan_idnt_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->twan_idnt_ts), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

if (value->ue_tcp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_tcp_port), buf + encoded);

if (value->secdry_rat_usage_data_rpt.header.len)
        encoded += encode_gtp_secdry_rat_usage_data_rpt_ie(&(value->secdry_rat_usage_data_rpt), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_bearer_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_bearer_response__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response__load_ctl_info_ie(gtp_mod_bearer_response__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

if (value->list_of_apn_and_rltv_cap.header.len)
        encoded += encode_gtp_apn_and_rltv_cap_ie(&(value->list_of_apn_and_rltv_cap), buf + encoded);

    return encoded;
}


/**
* Encodes upd_pdn_conn_set_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    upd_pdn_conn_set_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_upd_pdn_conn_set_rsp(upd_pdn_conn_set_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->pgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->pgw_fqcsid), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_bearer_rsrc_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_bearer_rsrc_command__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_rsrc_command__overload_ctl_info_ie(gtp_bearer_rsrc_command__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

    return encoded;
}


/**
* Encodes stop_paging_indctn_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    stop_paging_indctn_t
* @return
*   number of encoded bytes.
*/
int encode_stop_paging_indctn(stop_paging_indctn_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->imsi.header.len)
        encoded += encode_gtp_imsi_ie(&(value->imsi), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes create_bearer_rsp_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_bearer_rsp_t
* @return
*   number of encoded bytes.
*/
int encode_create_bearer_rsp(create_bearer_rsp_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->bearer_contexts.header.len)
        encoded += encode_gtp_create_bearer_response_bearer_ctxt_ie(&(value->bearer_contexts), buf + encoded);

if (value->recovery.header.len)
        encoded += encode_gtp_recovery_ie(&(value->recovery), buf + encoded);

if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->epdg_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->epdg_fqcsid), buf + encoded);

if (value->twan_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->twan_fqcsid), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->ue_time_zone.header.len)
        encoded += encode_gtp_ue_time_zone_ie(&(value->ue_time_zone), buf + encoded);

if (value->uli.header.len)
        encoded += encode_gtp_user_loc_info_ie(&(value->uli), buf + encoded);

if (value->twan_identifier.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->twan_identifier), buf + encoded);

if (value->mmes4_sgsns_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->mmes4_sgsns_ovrld_ctl_info), buf + encoded);

if (value->sgws_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->sgws_ovrld_ctl_info), buf + encoded);

if (value->pres_rptng_area_info.header.len)
        encoded += encode_gtp_pres_rptng_area_info_ie(&(value->pres_rptng_area_info), buf + encoded);

if (value->mmes4_sgsn_idnt.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->mmes4_sgsn_idnt), buf + encoded);

if (value->twanepdgs_ovrld_ctl_info.header.len)
        encoded += encode_gtp_ovrld_ctl_info_ie(&(value->twanepdgs_ovrld_ctl_info), buf + encoded);

if (value->wlan_loc_info.header.len)
        encoded += encode_gtp_twan_identifier_ie(&(value->wlan_loc_info), buf + encoded);

if (value->wlan_loc_ts.header.len)
        encoded += encode_gtp_twan_idnt_ts_ie(&(value->wlan_loc_ts), buf + encoded);

if (value->ue_local_ip_addr.header.len)
        encoded += encode_gtp_ip_address_ie(&(value->ue_local_ip_addr), buf + encoded);

if (value->ue_udp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_udp_port), buf + encoded);

if (value->nbifom_cntnr.header.len)
        encoded += encode_gtp_full_qual_cntnr_ie(&(value->nbifom_cntnr), buf + encoded);

if (value->ue_tcp_port.header.len)
        encoded += encode_gtp_port_number_ie(&(value->ue_tcp_port), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_response__load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__load_ctl_info_ie(gtp_mod_acc_bearers_response__load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->load_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->load_ctl_seqn_nbr), buf + encoded);

if (value->load_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->load_metric), buf + encoded);

    return encoded;
}


/**
* Encodes rmt_ue_rpt_ack_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    rmt_ue_rpt_ack_t
* @return
*   number of encoded bytes.
*/
int encode_rmt_ue_rpt_ack(rmt_ue_rpt_ack_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_bearer_response__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_response__bearer_ctxt_ie(gtp_del_bearer_response__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->pco.header.len)
        encoded += encode_gtp_prot_cfg_opts_ie(&(value->pco), buf + encoded);

if (value->ran_nas_cause.header.len)
        encoded += encode_gtp_ran_nas_cause_ie(&(value->ran_nas_cause), buf + encoded);

if (value->epco.header.len)
        encoded += encode_gtp_extnded_prot_cfg_opts_ie(&(value->epco), buf + encoded);

    return encoded;
}


/**
* Encodes create_fwdng_tunn_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    create_fwdng_tunn_req_t
* @return
*   number of encoded bytes.
*/
int encode_create_fwdng_tunn_req(create_fwdng_tunn_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->s103_pdn_data_fwdng_info.header.len)
        encoded += encode_gtp_s103_pdn_data_fwdng_info_ie(&(value->s103_pdn_data_fwdng_info), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes upd_pdn_conn_set_req_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    upd_pdn_conn_set_req_t
* @return
*   number of encoded bytes.
*/
int encode_upd_pdn_conn_set_req(upd_pdn_conn_set_req_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_gtpv2c_header_t(&value->header, buf +encoded);


if (value->mme_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->mme_fqcsid), buf + encoded);

if (value->sgw_fqcsid.header.len)
        encoded += encode_gtp_fqcsid_ie(&(value->sgw_fqcsid), buf + encoded);

if (value->priv_ext.header.len)
        encoded += encode_gtp_priv_ext_ie(&(value->priv_ext), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_del_sess_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_del_sess_response__overload_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_response__overload_ctl_info_ie(gtp_del_sess_response__overload_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->ovrld_ctl_seqn_nbr.header.len)
        encoded += encode_gtp_sequence_number_ie(&(value->ovrld_ctl_seqn_nbr), buf + encoded);

if (value->ovrld_reduction_metric.header.len)
        encoded += encode_gtp_metric_ie(&(value->ovrld_reduction_metric), buf + encoded);

if (value->prd_of_validity.header.len)
        encoded += encode_gtp_epc_timer_ie(&(value->prd_of_validity), buf + encoded);

if (value->apn.header.len)
        encoded += encode_gtp_acc_pt_name_ie(&(value->apn), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie(gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie(gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    encoded /= CHAR_SIZE;

if (value->eps_bearer_id.header.len)
        encoded += encode_gtp_eps_bearer_id_ie(&(value->eps_bearer_id), buf + encoded);

if (value->cause.header.len)
        encoded += encode_gtp_cause_ie(&(value->cause), buf + encoded);

if (value->s1u_sgw_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid_dl_data_fwdng), buf + encoded);

if (value->s12_sgw_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s12_sgw_fteid_dl_data_fwdng), buf + encoded);

if (value->s4_u_sgw_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s4_u_sgw_fteid_dl_data_fwdng), buf + encoded);

if (value->sgw_fteid_dl_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_fteid_dl_data_fwdng), buf + encoded);

if (value->s1u_sgw_fteid_ul_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->s1u_sgw_fteid_ul_data_fwdng), buf + encoded);

if (value->sgw_fteid_ul_data_fwdng.header.len)
        encoded += encode_gtp_fully_qual_tunn_endpt_idnt_ie(&(value->sgw_fteid_ul_data_fwdng), buf + encoded);

    return encoded;
}

