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

#include "../include/gtp_ies_decoder.h"
#include "../include/gtp_messages_decoder.h"
#include "../include/sv_ies_decoder.h"
#include "../include/enc_dec_bits.h"
#define IE_HEADER_SIZE sizeof(ie_header_t)
/**
* Decodes detach_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    detach_ack_t
* @return
*   number of decoded bytes.
*/
int decode_detach_ack(uint8_t *buf,
      detach_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes dnlnk_data_notif_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    dnlnk_data_notif_ack_t
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif_ack(uint8_t *buf,
      dnlnk_data_notif_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_DELAY_VALUE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_delay_value_ie(buf + count, &value->data_notif_delay);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_THROTTLING && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_throttling_ie(buf + count, &value->dl_low_priority_traffic_thrtlng);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->dl_buffering_dur);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_integer_number_ie(buf + count, &value->dl_buffering_suggested_pckt_cnt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes reloc_cncl_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    reloc_cncl_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_reloc_cncl_rsp(uint8_t *buf,
      reloc_cncl_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes bearer_rsrc_cmd_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    bearer_rsrc_cmd_t
* @return
*   number of decoded bytes.
*/
int decode_bearer_rsrc_cmd(uint8_t *buf,
      bearer_rsrc_cmd_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->lbi);
      }  else if (ie_header->type == GTP_IE_PROC_TRANS_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_proc_trans_id_ie(buf + count, &value->pti);
      }  else if (ie_header->type == GTP_IE_FLOW_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_flow_qlty_of_svc_ie(buf + count, &value->flow_qos);
      }  else if (ie_header->type == GTP_IE_TRAFFIC_AGG_DESC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_traffic_agg_desc_ie(buf + count, &value->tad);
      }  else if (ie_header->type == GTP_IE_RAT_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rat_type_ie(buf + count, &value->rat_type);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->serving_network);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_rnc_fteid);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_SGNLLNG_PRIORITY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sgnllng_priority_indctn_ie(buf + count, &value->sgnllng_priority_indctn);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_reloc_cmplt_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_reloc_cmplt_ack_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_cmplt_ack(uint8_t *buf,
      fwd_reloc_cmplt_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes isr_status_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    isr_status_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_isr_status_indctn(uint8_t *buf,
      isr_status_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_ACT_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_act_indctn_ie(buf + count, &value->act_indctn);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_ctxt_acknowledge__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_ctxt_acknowledge__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_acknowledge__bearer_ctxt_ie(uint8_t *buf,
      gtp_ctxt_acknowledge__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->fwdng_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_request__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_bearer_request__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_bearer_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_create_bearer_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie(uint8_t *buf,
      gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_enb_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_mme_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ran_info_rly_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ran_info_rly_t
* @return
*   number of decoded bytes.
*/
int decode_ran_info_rly(uint8_t *buf,
      ran_info_rly_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->bss_container);
      }  else if (ie_header->type == GTP_IE_TRGT_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trgt_id_ie(buf + count, &value->rim_rtng_addr);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ue_reg_qry_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ue_reg_qry_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_ue_reg_qry_rsp(uint8_t *buf,
      ue_reg_qry_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_PLMN_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_plmn_id_ie(buf + count, &value->selected_core_ntwk_oper_idnt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_indir_data_fwdng_tunn_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_indir_data_fwdng_tunn_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_create_indir_data_fwdng_tunn_rsp(uint8_t *buf,
      create_indir_data_fwdng_tunn_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie(uint8_t *buf,
      gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_REMOTE_USER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_remote_user_id_ie(buf + count, &value->remote_user_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie(uint8_t *buf,
      gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_REMOTE_USER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_remote_user_id_ie(buf + count, &value->remote_user_id);
      }  else if (ie_header->type == GTP_IE_RMT_UE_IP_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ip_info_ie(buf + count, &value->rmt_ue_ip_info);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_reloc_cmplt_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_reloc_cmplt_notif_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_cmplt_notif(uint8_t *buf,
      fwd_reloc_cmplt_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_fail_indication__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_fail_indication__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_bearer_fail_indication__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(uint8_t *buf,
      gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(buf + count, &value->tft);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_enb_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s5s8_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s5s8_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_rnc_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2b_u_epdg_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SIX) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2a_u_twan_fteid);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SEVEN) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_mme_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_bearer_cmd_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_bearer_cmd_t
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_cmd(uint8_t *buf,
      del_bearer_cmd_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_ULI_TIMESTAMP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_uli_timestamp_ie(buf + count, &value->uli_timestamp);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_bearer_cmd_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_bearer_cmd_t
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_cmd(uint8_t *buf,
      mod_bearer_cmd_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_context);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_bearer_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_bearer_req_t
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_req(uint8_t *buf,
      mod_bearer_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_MBL_EQUIP_IDNTY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbl_equip_idnty_ie(buf + count, &value->mei);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->serving_network);
      /*
	}  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {\
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
	*/
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_DELAY_VALUE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_delay_value_ie(buf + count, &value->delay_dnlnk_pckt_notif_req);
      }  else if (ie_header->type == GTP_IE_MOD_BEARER_REQUEST_BEARER_CTXT_TO_BE_MODIFIED && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(buf + count, &value->bearer_contexts_to_be_modified);
      }  else if (ie_header->type == GTP_IE_MOD_BEARER_REQUEST_BEARER_CTXT_TO_BE_REMOVED && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(buf + count, &value->bearer_contexts_to_be_removed);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_USER_CSG_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_csg_info_ie(buf + count, &value->uci);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->sgw_ldn);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->henb_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->henb_udp_port);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_CN_OPER_SEL_ENTITY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cn_oper_sel_entity_ie(buf + count, &value->cn_oper_sel_entity);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_info_ie(buf + count, &value->pres_rptng_area_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->epdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_SRVNG_PLMN_RATE_CTL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_srvng_plmn_rate_ctl_ie(buf + count, &value->srvng_plmn_rate_ctl);
      }  else if (ie_header->type == GTP_IE_COUNTER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_counter_ie(buf + count, &value->mo_exception_data_cntr);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->user_loc_info_sgw);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_upd_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_upd_bearer_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_upd_bearer_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_request__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__bearer_ctxt_ie(uint8_t *buf,
      gtp_del_bearer_request__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_upd_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_upd_bearer_request__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__overload_ctl_info_ie(uint8_t *buf,
      gtp_upd_bearer_request__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes id_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    id_req_t
* @return
*   number of decoded bytes.
*/
int decode_id_req(uint8_t *buf,
      id_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_GUTI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_guti_ie(buf + count, &value->guti);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->rai);
      }  else if (ie_header->type == GTP_IE_PTMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ptmsi_ie(buf + count, &value->ptmsi);
      }  else if (ie_header->type == GTP_IE_PTMSI_SIGNATURE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ptmsi_signature_ie(buf + count, &value->ptmsi_signature);
      }  else if (ie_header->type == GTP_IE_CMPLT_REQ_MSG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cmplt_req_msg_ie(buf + count, &value->cmplt_attach_req_msg);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->addr_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->udp_src_port_nbr);
      }  else if (ie_header->type == GTP_IE_HOP_COUNTER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_hop_counter_ie(buf + count, &value->hop_counter);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->target_plmn_id);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ue_reg_qry_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ue_reg_qry_req_t
* @return
*   number of decoded bytes.
*/
int decode_ue_reg_qry_req(uint8_t *buf,
      ue_reg_qry_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie(uint8_t *buf,
      gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else if (ie_header->type == GTP_IE_APN_RESTRICTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_restriction_ie(buf + count, &value->apn_restriction);
      }  else if (ie_header->type == GTP_IE_SELECTION_MODE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_selection_mode_ie(buf + count, &value->selection_mode);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ipv4_address);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ipv6_address);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_ip_addr_ctl_plane_or_pmip);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_CHRGNG_CHAR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chrgng_char_ie(buf + count, &value->chrgng_char);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_SGNLLNG_PRIORITY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sgnllng_priority_indctn_ie(buf + count, &value->sgnllng_priority_indctn);
      }  else if (ie_header->type == GTP_IE_CHG_TO_RPT_FLGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_to_rpt_flgs_ie(buf + count, &value->chg_to_rpt_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->local_home_ntwk_id);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_WLAN_OFFLDBLTY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_wlan_offldblty_indctn_ie(buf + count, &value->wlan_offldblty_indctn);
      }  else if (ie_header->type == GTP_IE_RMT_UE_CTXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ctxt_ie(buf + count, &value->rmt_ue_ctxt_connected);
      }  else if (ie_header->type == GTP_IE_PDN_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_type_ie(buf + count, &value->pdn_type);
      }  else if (ie_header->type == GTP_IE_HDR_COMP_CFG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_hdr_comp_cfg_ie(buf + count, &value->hdr_comp_cfg);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_dnlnk_data_notification__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_dnlnk_data_notification__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_dnlnk_data_notification__load_ctl_info_ie(uint8_t *buf,
      gtp_dnlnk_data_notification__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_sess_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_sess_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_del_sess_rsp(uint8_t *buf,
      del_sess_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
	/*
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
	*/
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_reloc_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_reloc_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_rsp(uint8_t *buf,
      fwd_reloc_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->senders_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
           count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->list_of_set_up_bearers);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->list_of_set_up_rabs);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->list_of_set_up_pfcs);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->s1_ap_cause);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->ranap_cause);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->bssgp_cause);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->e_utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->bss_container);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgsn_node_name);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->mme_node_name);
      }  else if (ie_header->type == GTP_IE_NODE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_number_ie(buf + count, &value->sgsn_number);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->sgsn_identifier);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->mme_identifier);
      }  else if (ie_header->type == GTP_IE_NODE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_node_number_ie(buf + count, &value->mme_nbr_mt_sms);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->sgsn_idnt_mt_sms);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->mme_idnt_mt_sms);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->list_of_set_up_bearers_scef_pdn_connections);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes trc_sess_actvn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    trc_sess_actvn_t
* @return
*   number of decoded bytes.
*/
int decode_trc_sess_actvn(uint8_t *buf,
      trc_sess_actvn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_TRC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trc_info_ie(buf + count, &value->trc_info);
      }  else if (ie_header->type == GTP_IE_MBL_EQUIP_IDNTY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbl_equip_idnty_ie(buf + count, &value->mei);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes cfg_xfer_tunn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    cfg_xfer_tunn_t
* @return
*   number of decoded bytes.
*/
int decode_cfg_xfer_tunn(uint8_t *buf,
      cfg_xfer_tunn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->e_utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_TRGT_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trgt_id_ie(buf + count, &value->trgt_enb_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes detach_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    detach_notif_t
* @return
*   number of decoded bytes.
*/
int decode_detach_notif(uint8_t *buf,
      detach_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_DETACH_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_detach_type_ie(buf + count, &value->detach_type);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_ctxt_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_ctxt_response__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__bearer_ctxt_ie(uint8_t *buf,
      gtp_ctxt_response__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(buf + count, &value->tft);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s1s4s12s11_ip_addr_and_teid_user_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_ip_addr_and_teid_user_plane);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->bss_container);
      }  else if (ie_header->type == GTP_IE_TRANS_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trans_idnt_ie(buf + count, &value->trans_idnt);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s11_ip_addr_and_teid_user_plane);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_ctxt_response__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_ctxt_response__remote_ue_ctxt_connected_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__remote_ue_ctxt_connected_ie(uint8_t *buf,
      gtp_ctxt_response__remote_ue_ctxt_connected_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_REMOTE_USER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_remote_user_id_ie(buf + count, &value->remote_user_id);
      }  else if (ie_header->type == GTP_IE_RMT_UE_IP_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ip_info_ie(buf + count, &value->rmt_ue_ip_info);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_request_overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_request_overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_overload_ctl_info_ie(uint8_t *buf,
      gtp_mod_bearer_request_overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_fwd_reloc_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_fwd_reloc_request__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__bearer_ctxt_ie(uint8_t *buf,
      gtp_fwd_reloc_request__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(buf + count, &value->tft);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s1s4s12_ip_addr_and_teid_user_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_ip_addr_and_teid_user_plane);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->bss_container);
      }  else if (ie_header->type == GTP_IE_TRANS_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trans_idnt_ie(buf + count, &value->trans_idnt);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s11_ip_addr_and_teid_user_plane);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes echo_request_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    echo_request_t
* @return
*   number of decoded bytes.
*/
int decode_echo_request(uint8_t *buf,
      echo_request_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_NODE_FEATURES && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_features_ie(buf + count, &value->sending_node_feat);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes rmt_ue_rpt_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    rmt_ue_rpt_notif_t
* @return
*   number of decoded bytes.
*/
int decode_rmt_ue_rpt_notif(uint8_t *buf,
      rmt_ue_rpt_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_RMT_UE_CTXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ctxt_ie(buf + count, &value->rmt_ue_ctxt_connected);
      }  else if (ie_header->type == GTP_IE_RMT_UE_CTXT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_rmt_ue_ctxt_ie(buf + count, &value->rmt_ue_ctxt_disconnected);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_bearer_fail_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_bearer_fail_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_fail_indctn(uint8_t *buf,
      del_bearer_fail_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_context);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
           count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ctxt_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ctxt_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_ctxt_rsp(uint8_t *buf,
      ctxt_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_PDN_CONNECTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_connection_ie(buf + count, &value->mmesgsnamf_ue_eps_pdn_connections);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s11s4_ip_addr_and_teid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgw_node_name);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_TRC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trc_info_ie(buf + count, &value->trc_info);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->hrpd_acc_node_s101_ip_addr);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->onexiws_sone02_ip_addr);
      }  else if (ie_header->type == GTP_IE_RFSP_INDEX && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rfsp_index_ie(buf + count, &value->subscrbd_rfsp_idx);
      }  else if (ie_header->type == GTP_IE_RFSP_INDEX && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_rfsp_index_ie(buf + count, &value->rfsp_idx_in_use);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_MDT_CFG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mdt_cfg_ie(buf + count, &value->mdt_cfg);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgsn_node_name);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->mme_node_name);
      }  else if (ie_header->type == GTP_IE_USER_CSG_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_csg_info_ie(buf + count, &value->uci);
      }  else if (ie_header->type == GTP_IE_MNTRNG_EVNT_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mntrng_evnt_info_ie(buf + count, &value->mntrng_evnt_info);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_integer_number_ie(buf + count, &value->ue_usage_type);
      }  else if (ie_header->type == GTP_IE_SCEF_PDN_CONN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_scef_pdn_conn_ie(buf + count, &value->mmesgsn_ue_scef_pdn_connections);
      }  else if (ie_header->type == GTP_IE_RAT_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rat_type_ie(buf + count, &value->rat_type);
      }  else if (ie_header->type == GTP_IE_SRVNG_PLMN_RATE_CTL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_srvng_plmn_rate_ctl_ie(buf + count, &value->srvng_plmn_rate_ctl);
      }  else if (ie_header->type == GTP_IE_COUNTER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_counter_ie(buf + count, &value->mo_exception_data_cntr);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_integer_number_ie(buf + count, &value->rem_running_svc_gap_timer);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_bearer_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_bearer_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_rsp(uint8_t *buf,
      mod_bearer_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_MSISDN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_msisdn_ie(buf + count, &value->msisdn);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_APN_RESTRICTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_restriction_ie(buf + count, &value->apn_restriction);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_MOD_BEARER_RESPONSE_BEARER_CTXT_MODIFIED && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(buf + count, &value->bearer_contexts_modified);
      }  else if (ie_header->type == GTP_IE_MOD_BEARER_RESPONSE_BEARER_CTXT_MARKED_REMOVAL && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(buf + count, &value->bearer_contexts_marked_removal);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->chrgng_gateway_name);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->chrgng_gateway_addr);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->sgw_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->pgw_ldn);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_CHARGING_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_charging_id_ie(buf + count, &value->pdn_conn_chrgng_id);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_request__remote_ue_ctxt_connected_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request__remote_ue_ctxt_connected_ie(uint8_t *buf,
      gtp_create_sess_request__remote_ue_ctxt_connected_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_REMOTE_USER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_remote_user_id_ie(buf + count, &value->remote_user_id);
      }  else if (ie_header->type == GTP_IE_RMT_UE_IP_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ip_info_ie(buf + count, &value->rmt_ue_ip_info);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_command__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_command__overload_ctl_info_ie(uint8_t *buf,
      gtp_mod_bearer_command__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mbms_sess_start_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mbms_sess_start_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_start_rsp(uint8_t *buf,
      mbms_sess_start_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_MBMS_DIST_ACK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_dist_ack_ie(buf + count, &value->mbms_dist_ack);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sn_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes context_request_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    context_request_t
* @return
*   number of decoded bytes.
*/
int decode_context_request(uint8_t *buf,
      context_request_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_GUTI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_guti_ie(buf + count, &value->guti);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->rai);
      }  else if (ie_header->type == GTP_IE_PTMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ptmsi_ie(buf + count, &value->ptmsi);
      }  else if (ie_header->type == GTP_IE_PTMSI_SIGNATURE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ptmsi_signature_ie(buf + count, &value->ptmsi_signature);
      }  else if (ie_header->type == GTP_IE_CMPLT_REQ_MSG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cmplt_req_msg_ie(buf + count, &value->cmplt_tau_req_msg);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s3s16s10n26_addr_and_teid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->udp_src_port_nbr);
      }  else if (ie_header->type == GTP_IE_RAT_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rat_type_ie(buf + count, &value->rat_type);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indication);
      }  else if (ie_header->type == GTP_IE_HOP_COUNTER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_hop_counter_ie(buf + count, &value->hop_counter);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->target_plmn_id);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgsn_node_name);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->mme_node_name);
      }  else if (ie_header->type == GTP_IE_NODE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_number_ie(buf + count, &value->sgsn_number);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->sgsn_identifier);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->mme_identifier);
      }  else if (ie_header->type == GTP_IE_CIOT_OPTIM_SUPP_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ciot_optim_supp_indctn_ie(buf + count, &value->ciot_optim_supp_indctn);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie(uint8_t *buf,
      gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->dflt_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->scef_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mbms_sess_upd_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mbms_sess_upd_req_t
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_upd_req(uint8_t *buf,
      mbms_sess_upd_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_MBMS_SVC_AREA && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_svc_area_ie(buf + count, &value->mbms_svc_area);
      }  else if (ie_header->type == GTP_IE_TMGI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_tmgi_ie(buf + count, &value->tmgi);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_MBMS_SESS_DUR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_sess_dur_ie(buf + count, &value->mbms_sess_dur);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->qos_profile);
      }  else if (ie_header->type == GTP_IE_MBMS_SESS_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_sess_idnt_ie(buf + count, &value->mbms_sess_idnt);
      }  else if (ie_header->type == GTP_IE_MBMS_FLOW_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_flow_idnt_ie(buf + count, &value->mbms_flow_idnt);
      }  else if (ie_header->type == GTP_IE_MBMS_TIME_TO_DATA_XFER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_time_to_data_xfer_ie(buf + count, &value->mbms_time_to_data_xfer);
      }  else if (ie_header->type == GTP_IE_MBMS_DATA_XFER_ABS_TIME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_data_xfer_abs_time_ie(buf + count, &value->mbms_data_xfer_start_upd_stop);
      }  else if (ie_header->type == GTP_IE_ECGI_LIST && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ecgi_list_ie(buf + count, &value->mbms_cell_list);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_sess_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_sess_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_create_sess_rsp(uint8_t *buf,
      create_sess_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc);
      }  else if (ie_header->type == GTP_IE_PDN_ADDR_ALLOC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_addr_alloc_ie(buf + count, &value->paa);
      }  else if (ie_header->type == GTP_IE_APN_RESTRICTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_restriction_ie(buf + count, &value->apn_restriction);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_CREATE_SESS_RESPONSE_BEARER_CTXT_CREATED && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_create_sess_response_bearer_ctxt_created_ie(buf + count, &value->bearer_contexts_created);
      }  else if (ie_header->type == GTP_IE_CREATE_SESS_RESPONSE_BEARER_CTXT_MARKED_REMOVAL && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(buf + count, &value->bearer_contexts_marked_removal);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->chrgng_gateway_name);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->chrgng_gateway_addr);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->sgw_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->pgw_ldn);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->pgw_back_off_time);
      }  else if (ie_header->type == GTP_IE_ADDTL_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_addtl_prot_cfg_opts_ie(buf + count, &value->apco);
      }  else if (ie_header->type == GTP_IE_IPV4_CFG_PARMS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ipv4_cfg_parms_ie(buf + count, &value->trstd_wlan_ipv4_parms);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
           count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_CHARGING_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_charging_id_ie(buf + count, &value->pdn_conn_chrgng_id);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_acc_ctxt_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_acc_ctxt_ack_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_acc_ctxt_ack(uint8_t *buf,
      fwd_acc_ctxt_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_response_bearer_ctxt_created_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_response_bearer_ctxt_created_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response_bearer_ctxt_created_ie(uint8_t *buf,
      gtp_create_sess_response_bearer_ctxt_created_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s5s8_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2b_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2a_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_CHARGING_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_charging_id_ie(buf + count, &value->charging_id);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SIX) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_sgw_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count + 4;
}
/**
* Decodes gtp_create_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_bearer_request__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request__load_ctl_info_ie(uint8_t *buf,
      gtp_create_bearer_request__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_bearer_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_bearer_req_t
* @return
*   number of decoded bytes.
*/
int decode_create_bearer_req(uint8_t *buf,
      create_bearer_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_PROC_TRANS_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_proc_trans_id_ie(buf + count, &value->pti);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->lbi);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_create_bearer_request_bearer_ctxt_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
           count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_request__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request__overload_ctl_info_ie(uint8_t *buf,
      gtp_create_sess_request__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes bearer_rsrc_fail_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    bearer_rsrc_fail_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_bearer_rsrc_fail_indctn(uint8_t *buf,
      bearer_rsrc_fail_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_PROC_TRANS_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_proc_trans_id_ie(buf + count, &value->pti);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_bearer_request__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request_bearer_ctxt_ie(uint8_t *buf,
      gtp_create_bearer_request_bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(buf + count, &value->tft);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s58_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2b_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2a_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_CHARGING_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_charging_id_ie(buf + count, &value->charging_id);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_MAX_PCKT_LOSS_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_max_pckt_loss_rate_ie(buf + count, &value->max_pckt_loss_rate);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(uint8_t *buf,
      gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_create_sess_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pgw_dnlnk_trigrng_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pgw_dnlnk_trigrng_ack_t
* @return
*   number of decoded bytes.
*/
int decode_pgw_dnlnk_trigrng_ack(uint8_t *buf,
      pgw_dnlnk_trigrng_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_bearer_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_bearer_request__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request__overload_ctl_info_ie(uint8_t *buf,
      gtp_create_bearer_request__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_sess_request__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_sess_request__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_request__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_sess_request__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes echo_response_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    echo_response_t
* @return
*   number of decoded bytes.
*/
int decode_echo_response(uint8_t *buf,
      echo_response_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_NODE_FEATURES && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_features_ie(buf + count, &value->sending_node_feat);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mbms_sess_upd_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mbms_sess_upd_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_upd_rsp(uint8_t *buf,
      mbms_sess_upd_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_MBMS_DIST_ACK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_dist_ack_ie(buf + count, &value->mbms_dist_ack);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sn_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_fail_indication__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_fail_indication__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_fail_indication__bearer_ctxt_ie(uint8_t *buf,
      gtp_del_bearer_fail_indication__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_command__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_command__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_bearer_command__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie(uint8_t *buf,
      gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_REMOTE_USER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_remote_user_id_ie(buf + count, &value->remote_user_id);
      }  else if (ie_header->type == GTP_IE_RMT_UE_IP_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ip_info_ie(buf + count, &value->rmt_ue_ip_info);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_acc_bearers_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_acc_bearers_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_mod_acc_bearers_rsp(uint8_t *buf,
      mod_acc_bearers_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts_modified);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts_marked_removal);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_mod_acc_bearers_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_bearer_fail_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_bearer_fail_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_fail_indctn(uint8_t *buf,
      mod_bearer_fail_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pgw_rstrt_notif_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pgw_rstrt_notif_ack_t
* @return
*   number of decoded bytes.
*/
int decode_pgw_rstrt_notif_ack(uint8_t *buf,
      pgw_rstrt_notif_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie(uint8_t *buf,
      gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else if (ie_header->type == GTP_IE_APN_RESTRICTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_restriction_ie(buf + count, &value->apn_restriction);
      }  else if (ie_header->type == GTP_IE_SELECTION_MODE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_selection_mode_ie(buf + count, &value->selection_mode);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ipv4_address);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ipv6_address);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_ip_addr_ctl_plane_or_pmip);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->pgw_node_name);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_CHRGNG_CHAR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chrgng_char_ie(buf + count, &value->chrgng_char);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
           count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_SGNLLNG_PRIORITY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sgnllng_priority_indctn_ie(buf + count, &value->sgnllng_priority_indctn);
      }  else if (ie_header->type == GTP_IE_CHG_TO_RPT_FLGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_to_rpt_flgs_ie(buf + count, &value->chg_to_rpt_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->local_home_ntwk_id);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_WLAN_OFFLDBLTY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_wlan_offldblty_indctn_ie(buf + count, &value->wlan_offldblty_indctn);
      }  else if (ie_header->type == GTP_IE_RMT_UE_CTXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ctxt_ie(buf + count, &value->rmt_ue_ctxt_connected);
      }  else if (ie_header->type == GTP_IE_PDN_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_type_ie(buf + count, &value->pdn_type);
      }  else if (ie_header->type == GTP_IE_HDR_COMP_CFG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_hdr_comp_cfg_ie(buf + count, &value->hdr_comp_cfg);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_command__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_command__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_command__bearer_ctxt_ie(uint8_t *buf,
      gtp_del_bearer_command__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_RAN_NAS_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ran_nas_cause_ie(buf + count, &value->ran_nas_release_cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pgw_dnlnk_trigrng_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pgw_dnlnk_trigrng_notif_t
* @return
*   number of decoded bytes.
*/
int decode_pgw_dnlnk_trigrng_notif(uint8_t *buf,
      pgw_dnlnk_trigrng_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5_fteid_gtp_or_pmip_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_mod_bearer_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes id_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    id_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_id_rsp(uint8_t *buf,
      id_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == 'CTXT') {
            count += decode_gtp_mm_context(buf + count, &value->mmesgsn_ue_mm_ctxt);
      }  else if (ie_header->type == GTP_IE_TRC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trc_info_ie(buf + count, &value->trc_info);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_integer_number_ie(buf + count, &value->ue_usage_type);
      }  else if (ie_header->type == GTP_IE_MNTRNG_EVNT_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mntrng_evnt_info_ie(buf + count, &value->mntrng_evnt_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie(uint8_t *buf,
      gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->enb_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgsn_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->rnc_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->enb_fteid_ul_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_fteid_ul_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SIX) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->mme_fteid_dl_data_fwdng);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_sess_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_sess_req_t
* @return
*   number of decoded bytes.
*/
int decode_create_sess_req(uint8_t *buf,
      create_sess_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_MSISDN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_msisdn_ie(buf + count, &value->msisdn);
      }  else if (ie_header->type == GTP_IE_MBL_EQUIP_IDNTY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbl_equip_idnty_ie(buf + count, &value->mei);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_RAT_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rat_type_ie(buf + count, &value->rat_type);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->pgw_s5s8_addr_ctl_plane_or_pmip);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else if (ie_header->type == GTP_IE_SELECTION_MODE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_selection_mode_ie(buf + count, &value->selection_mode);
      }  else if (ie_header->type == GTP_IE_PDN_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_type_ie(buf + count, &value->pdn_type);
      }  else if (ie_header->type == GTP_IE_PDN_ADDR_ALLOC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_addr_alloc_ie(buf + count, &value->paa);
      }  else if (ie_header->type == GTP_IE_APN_RESTRICTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_restriction_ie(buf + count, &value->max_apn_rstrct);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->linked_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_TRSTD_WLAN_MODE_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trstd_wlan_mode_indctn_ie(buf + count, &value->trstd_wlan_mode_indctn);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_CREATED && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(buf + count, &value->bearer_contexts_to_be_created);
      }  else if (ie_header->type == GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_REMOVED && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(buf + count, &value->bearer_contexts_to_be_removed);
      }  else if (ie_header->type == GTP_IE_TRC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trc_info_ie(buf + count, &value->trc_info);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->epdg_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->twan_fqcsid);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_USER_CSG_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_csg_info_ie(buf + count, &value->uci);
      }  else if (ie_header->type == GTP_IE_CHRGNG_CHAR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chrgng_char_ie(buf + count, &value->chrgng_char);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->sgw_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->epdg_ldn);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->twan_ldn);
      }  else if (ie_header->type == GTP_IE_SGNLLNG_PRIORITY_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sgnllng_priority_indctn_ie(buf + count, &value->sgnllng_priority_indctn);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_ADDTL_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_addtl_prot_cfg_opts_ie(buf + count, &value->apco);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->henb_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->henb_udp_port);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->twan_identifier);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->epdg_ip_address);
      }  else if (ie_header->type == GTP_IE_CN_OPER_SEL_ENTITY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cn_oper_sel_entity_ie(buf + count, &value->cn_oper_sel_entity);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_info_ie(buf + count, &value->pres_rptng_area_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_MSEC_TIME_STMP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_msec_time_stmp_ie(buf + count, &value->origination_time_stmp);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_integer_number_ie(buf + count, &value->max_wait_time);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_RMT_UE_CTXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rmt_ue_ctxt_ie(buf + count, &value->rmt_ue_ctxt_connected);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->threegpp_aaa_server_idnt);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_SRVNG_PLMN_RATE_CTL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_srvng_plmn_rate_ctl_ie(buf + count, &value->srvng_plmn_rate_ctl);
      }  else if (ie_header->type == GTP_IE_COUNTER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_counter_ie(buf + count, &value->mo_exception_data_cntr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_tcp_port);
      }  else if (ie_header->type == GTP_IE_MAPPED_UE_USAGE_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mapped_ue_usage_type_ie(buf + count, &value->mapped_ue_usage_type);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->user_loc_info_sgw);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgw_u_node_name);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_UP_FUNC_SEL_INDCTN_FLGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_up_func_sel_indctn_flgs_ie(buf + count, &value->up_func_sel_indctn_flgs);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->serving_network);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
		  	count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
	  } else {
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
	}
      return count;
}
/**
* Decodes gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(uint8_t *buf,
      gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes upd_bearer_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    upd_bearer_req_t
* @return
*   number of decoded bytes.
*/
int decode_upd_bearer_req(uint8_t *buf,
      upd_bearer_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_PROC_TRANS_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_proc_trans_id_ie(buf + count, &value->pti);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_AGG_MAX_BIT_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_agg_max_bit_rate_ie(buf + count, &value->apn_ambr);
      }  else if (ie_header->type == GTP_IE_CHG_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_chg_rptng_act_ie(buf + count, &value->chg_rptng_act);
      }  else if (ie_header->type == GTP_IE_CSG_INFO_RPTNG_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_info_rptng_act_ie(buf + count, &value->csg_info_rptng_act);
      }  else if (ie_header->type == GTP_IE_HENB_INFO_RPTNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_henb_info_rptng_ie(buf + count, &value->henb_info_rptng);
      /*
	}  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
	*/
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_ACT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_act_ie(buf + count, &value->pres_rptng_area_act);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_bearer_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_bearer_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_rsp(uint8_t *buf,
      del_bearer_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->lbi);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->epdg_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->twan_fqcsid);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_ULI_TIMESTAMP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_uli_timestamp_ie(buf + count, &value->uli_timestamp);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->twan_identifier);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->twan_idnt_ts);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_tcp_port);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(uint8_t *buf,
      gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes pgw_rstrt_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    pgw_rstrt_notif_t
* @return
*   number of decoded bytes.
*/
int decode_pgw_rstrt_notif(uint8_t *buf,
      pgw_rstrt_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->pgw_s5s8_ip_addr_ctl_plane_or_pmip);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->sgw_s11s4_ip_addr_ctl_plane);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes reloc_cncl_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    reloc_cncl_req_t
* @return
*   number of decoded bytes.
*/
int decode_reloc_cncl_req(uint8_t *buf,
      reloc_cncl_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_MBL_EQUIP_IDNTY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbl_equip_idnty_ie(buf + count, &value->mei);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->ranap_cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_sess_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_sess_response__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_response__load_ctl_info_ie(uint8_t *buf,
      gtp_del_sess_response__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_upd_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_upd_bearer_request__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__load_ctl_info_ie(uint8_t *buf,
      gtp_upd_bearer_request__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_upd_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_upd_bearer_response__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_response__bearer_ctxt_ie(uint8_t *buf,
      gtp_upd_bearer_response__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_rnc_fteid);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_RAN_NAS_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ran_nas_cause_ie(buf + count, &value->ran_nas_cause);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_bearer_response__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_response_bearer_ctxt_ie(uint8_t *buf,
      gtp_create_bearer_response_bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_enb_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s58_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s58_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_rnc_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SIX) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_SEVEN) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_EIGHT) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2b_u_epdg_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_NINE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2b_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TEN) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2a_u_twan_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ELEVEN) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s2a_u_pgw_fteid);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_RAN_NAS_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ran_nas_cause_ie(buf + count, &value->ran_nas_cause);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie(uint8_t *buf,
      gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_upd_bearer_request__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_upd_bearer_request__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__bearer_ctxt_ie(uint8_t *buf,
      gtp_upd_bearer_request__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(buf + count, &value->tft);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_ADDTL_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_addtl_prot_cfg_opts_ie(buf + count, &value->apco);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_MAX_PCKT_LOSS_RATE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_max_pckt_loss_rate_ie(buf + count, &value->max_pckt_loss_rate);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes upd_bearer_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    upd_bearer_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_upd_bearer_rsp(uint8_t *buf,
      upd_bearer_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->epdg_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->twan_fqcsid);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->twan_identifier);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_info_ie(buf + count, &value->pres_rptng_area_info);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_tcp_port);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_response_bearer_ctxt_modified_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_response_bearer_ctxt_modified_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(uint8_t *buf,
      gtp_mod_bearer_response_bearer_ctxt_modified_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_CHARGING_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_charging_id_ie(buf + count, &value->charging_id);
      }  else if (ie_header->type == GTP_IE_BEARER_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_flags_ie(buf + count, &value->bearer_flags);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_sgw_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_sess_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_sess_response__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response__load_ctl_info_ie(uint8_t *buf,
      gtp_create_sess_response__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mod_acc_bearers_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mod_acc_bearers_req_t
* @return
*   number of decoded bytes.
*/
int decode_mod_acc_bearers_req(uint8_t *buf,
      mod_acc_bearers_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_DELAY_VALUE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_delay_value_ie(buf + count, &value->delay_dnlnk_pckt_notif_req);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts_to_be_modified);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts_to_be_removed);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mbms_sess_stop_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mbms_sess_stop_req_t
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_stop_req(uint8_t *buf,
      mbms_sess_stop_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_MBMS_FLOW_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_flow_idnt_ie(buf + count, &value->mbms_flow_idnt);
      }  else if (ie_header->type == GTP_IE_MBMS_DATA_XFER_ABS_TIME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_data_xfer_abs_time_ie(buf + count, &value->mbms_data_xfer_stop);
      }  else if (ie_header->type == GTP_IE_MBMS_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_flags_ie(buf + count, &value->mbms_flags);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie(uint8_t *buf,
      gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_sgw_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_pdn_conn_set_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_pdn_conn_set_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_del_pdn_conn_set_rsp(uint8_t *buf,
      del_pdn_conn_set_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_acc_ctxt_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_acc_ctxt_notif_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_acc_ctxt_notif(uint8_t *buf,
      fwd_acc_ctxt_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_RAB_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rab_context_ie(buf + count, &value->rab_contexts);
      }  else if (ie_header->type == GTP_IE_SRC_RNC_PDCP_CTXT_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_src_rnc_pdcp_ctxt_info_ie(buf + count, &value->src_rnc_pdcp_ctxt_info);
      }  else if (ie_header->type == GTP_IE_PDU_NUMBERS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdu_numbers_ie(buf + count, &value->pdu_numbers);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->e_utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_request__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_request__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__load_ctl_info_ie(uint8_t *buf,
      gtp_del_bearer_request__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_bearer_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_dnlnk_data_notification__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_dnlnk_data_notification__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_dnlnk_data_notification__overload_ctl_info_ie(uint8_t *buf,
      gtp_dnlnk_data_notification__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_release_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_release_acc_bearers_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_release_acc_bearers_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_release_acc_bearers_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_fail_indication__overload_ctl_info_ie(uint8_t *buf,
      gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ctxt_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ctxt_ack_t
* @return
*   number of decoded bytes.
*/
int decode_ctxt_ack(uint8_t *buf,
      ctxt_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->fwdng_fteid);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_NODE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_number_ie(buf + count, &value->sgsn_number);
      }  else if (ie_header->type == GTP_IE_NODE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_node_number_ie(buf + count, &value->mme_nbr_mt_sms);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->sgsn_idnt_mt_sms);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->mme_idnt_mt_sms);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes alert_mme_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    alert_mme_ack_t
* @return
*   number of decoded bytes.
*/
int decode_alert_mme_ack(uint8_t *buf,
      alert_mme_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_fwdng_tunn_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_fwdng_tunn_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_create_fwdng_tunn_rsp(uint8_t *buf,
      create_fwdng_tunn_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_S1U_DATA_FWDNG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_s1u_data_fwdng_ie(buf + count, &value->s1u_data_fwdng);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes dnlnk_data_notif_fail_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    dnlnk_data_notif_fail_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif_fail_indctn(uint8_t *buf,
      dnlnk_data_notif_fail_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_NODE_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_type_ie(buf + count, &value->originating_node);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(uint8_t *buf,
      gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1_enodeb_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s58_u_sgw_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_rnc_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgsn_fteid);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s11_u_mme_fteid);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes ue_actvty_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    ue_actvty_ack_t
* @return
*   number of decoded bytes.
*/
int decode_ue_actvty_ack(uint8_t *buf,
      ue_actvty_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_command__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_command__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_command__bearer_ctxt_ie(uint8_t *buf,
      gtp_mod_bearer_command__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->bearer_lvl_qos);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie(uint8_t *buf,
      gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->dflt_eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_NODE_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_identifier_ie(buf + count, &value->scef_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_release_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_release_acc_bearers_response__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_release_acc_bearers_response__load_ctl_info_ie(uint8_t *buf,
      gtp_release_acc_bearers_response__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes trc_sess_deact_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    trc_sess_deact_t
* @return
*   number of decoded bytes.
*/
int decode_trc_sess_deact(uint8_t *buf,
      trc_sess_deact_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_TRACE_REFERENCE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trace_reference_ie(buf + count, &value->trace_reference);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes dnlnk_data_notif_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    dnlnk_data_notif_t
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif(uint8_t *buf,
      dnlnk_data_notif_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_ALLOC_RETEN_PRIORITY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_alloc_reten_priority_ie(buf + count, &value->alloc_reten_priority);
      }  else if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PAGING_AND_SVC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_paging_and_svc_info_ie(buf + count, &value->paging_and_svc_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_indir_data_fwdng_tunn_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_indir_data_fwdng_tunn_req_t
* @return
*   number of decoded bytes.
*/
int decode_create_indir_data_fwdng_tunn_req(uint8_t *buf,
      create_indir_data_fwdng_tunn_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_MBL_EQUIP_IDNTY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbl_equip_idnty_ie(buf + count, &value->mei);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes mbms_sess_start_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    mbms_sess_start_req_t
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_start_req(uint8_t *buf,
      mbms_sess_start_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_TMGI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_tmgi_ie(buf + count, &value->tmgi);
      }  else if (ie_header->type == GTP_IE_MBMS_SESS_DUR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_sess_dur_ie(buf + count, &value->mbms_sess_dur);
      }  else if (ie_header->type == GTP_IE_MBMS_SVC_AREA && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_svc_area_ie(buf + count, &value->mbms_svc_area);
      }  else if (ie_header->type == GTP_IE_MBMS_SESS_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_sess_idnt_ie(buf + count, &value->mbms_sess_idnt);
      }  else if (ie_header->type == GTP_IE_MBMS_FLOW_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_flow_idnt_ie(buf + count, &value->mbms_flow_idnt);
      }  else if (ie_header->type == GTP_IE_BEARER_QLTY_OF_SVC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_qlty_of_svc_ie(buf + count, &value->qos_profile);
      }  else if (ie_header->type == GTP_IE_MBMS_IP_MULTCST_DIST && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_ip_multcst_dist_ie(buf + count, &value->mbms_ip_multcst_dist);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_MBMS_TIME_TO_DATA_XFER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_time_to_data_xfer_ie(buf + count, &value->mbms_time_to_data_xfer);
      }  else if (ie_header->type == GTP_IE_MBMS_DATA_XFER_ABS_TIME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_data_xfer_abs_time_ie(buf + count, &value->mbms_data_xfer_start);
      }  else if (ie_header->type == GTP_IE_MBMS_FLAGS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mbms_flags_ie(buf + count, &value->mbms_flags);
      }  else if (ie_header->type == GTP_IE_MBMS_IP_MULTCST_DIST && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_mbms_ip_multcst_dist_ie(buf + count, &value->mbms_alternative_ip_multcst_dist);
      }  else if (ie_header->type == GTP_IE_ECGI_LIST && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ecgi_list_ie(buf + count, &value->mbms_cell_list);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_bearer_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_bearer_req_t
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_req(uint8_t *buf,
      del_bearer_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_ids);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_bearer_context_ie(buf + count, &value->failed_bearer_contexts);
      }  else if (ie_header->type == GTP_IE_PROC_TRANS_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_proc_trans_id_ie(buf + count, &value->pti);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->pgws_apn_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_LOAD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_load_ctl_info_ie(buf + count, &value->sgws_node_lvl_load_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->pgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes fwd_reloc_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    fwd_reloc_req_t
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_req(uint8_t *buf,
      fwd_reloc_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->senders_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_PDN_CONNECTION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pdn_connection_ie(buf + count, &value->mmesgsnamf_ue_eps_pdn_connections);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_s11s4_ip_addr_and_teid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgw_node_name);
      }  else if (ie_header->type == 'CTXT') {
            count += decode_gtp_mm_context(buf + count, &value->mmesgsnamf_ue_mm_ctxt);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->e_utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->utran_transparent_cntnr);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->bss_container);
      }  else if (ie_header->type == GTP_IE_TRGT_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trgt_id_ie(buf + count, &value->trgt_id);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->hrpd_acc_node_s101_ip_addr);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ip_address_ie(buf + count, &value->onexiws_sone02_ip_addr);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->s1_ap_cause);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->ranap_cause);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CAUSE && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_full_qual_cause_ie(buf + count, &value->bssgp_cause);
      }  else if (ie_header->type == GTP_IE_SRC_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_src_id_ie(buf + count, &value->src_id);
      }  else if (ie_header->type == GTP_IE_PLMN_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_plmn_id_ie(buf + count, &value->selected_plmn_id);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_TRC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_trc_info_ie(buf + count, &value->trc_info);
      }  else if (ie_header->type == GTP_IE_RFSP_INDEX && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_rfsp_index_ie(buf + count, &value->subscrbd_rfsp_idx);
      }  else if (ie_header->type == GTP_IE_RFSP_INDEX && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_rfsp_index_ie(buf + count, &value->rfsp_idx_in_use);
      }  else if (ie_header->type == GTP_IE_CSG_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_id_ie(buf + count, &value->csg_id);
      }  else if (ie_header->type == GTP_IE_CSG_MEMB_INDCTN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_csg_memb_indctn_ie(buf + count, &value->csg_memb_indctn);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_SERVING_NETWORK && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_serving_network_ie(buf + count, &value->serving_network);
      }  else if (ie_header->type == GTP_IE_LOCAL_DISTGSD_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_local_distgsd_name_ie(buf + count, &value->mmes4_sgsn_ldn);
      }  else if (ie_header->type == GTP_IE_ADDTL_MM_CTXT_SRVCC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_addtl_mm_ctxt_srvcc_ie(buf + count, &value->addtl_mm_ctxt_srvcc);
      }  else if (ie_header->type == GTP_IE_ADDTL_FLGS_SRVCC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_addtl_flgs_srvcc_ie(buf + count, &value->addtl_flgs_srvcc);
      }  else if (ie_header->type == GTP_IE_STN_SR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_stn_sr_ie(buf + count, &value->stn_sr);
      }  else if (ie_header->type == GTP_IE_MSISDN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_msisdn_ie(buf + count, &value->c_msisdn);
      }  else if (ie_header->type == GTP_IE_MDT_CFG && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mdt_cfg_ie(buf + count, &value->mdt_cfg);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->sgsn_node_name);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_DOMAIN_NAME && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_domain_name_ie(buf + count, &value->mme_node_name);
      }  else if (ie_header->type == GTP_IE_USER_CSG_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_csg_info_ie(buf + count, &value->uci);
      }  else if (ie_header->type == GTP_IE_MNTRNG_EVNT_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_mntrng_evnt_info_ie(buf + count, &value->mntrng_evnt_info);
      }  else if (ie_header->type == GTP_IE_INTEGER_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_integer_number_ie(buf + count, &value->ue_usage_type);
      }  else if (ie_header->type == GTP_IE_SCEF_PDN_CONN && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_scef_pdn_conn_ie(buf + count, &value->mmesgsn_ue_scef_pdn_connections);
      }  else if (ie_header->type == GTP_IE_MSISDN && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_msisdn_ie(buf + count, &value->msisdn);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->src_udp_port_nbr);
      }  else if (ie_header->type == GTP_IE_SRVNG_PLMN_RATE_CTL && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_srvng_plmn_rate_ctl_ie(buf + count, &value->srvng_plmn_rate_ctl);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(uint8_t *buf,
      gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie(uint8_t *buf,
      gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes del_sess_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    del_sess_req_t
* @return
*   number of decoded bytes.
*/
int decode_del_sess_req(uint8_t *buf,
      del_sess_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->lbi);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_INDICATION && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_indication_ie(buf + count, &value->indctn_flgs);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_NODE_TYPE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_node_type_ie(buf + count, &value->originating_node);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sender_fteid_ctl_plane);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_ULI_TIMESTAMP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_uli_timestamp_ie(buf + count, &value->uli_timestamp);
      }  else if (ie_header->type == GTP_IE_RAN_NAS_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ran_nas_cause_ie(buf + count, &value->ran_nas_release_cause);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->twan_identifier);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->twan_idnt_ts);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_tcp_port);
      }  else if (ie_header->type == GTP_IE_SECDRY_RAT_USAGE_DATA_RPT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_secdry_rat_usage_data_rpt_ie(buf + count, &value->secdry_rat_usage_data_rpt);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_bearer_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_bearer_response__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response__load_ctl_info_ie(uint8_t *buf,
      gtp_mod_bearer_response__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else if (ie_header->type == GTP_IE_APN_AND_RLTV_CAP && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_apn_and_rltv_cap_ie(buf + count, &value->list_of_apn_and_rltv_cap);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes upd_pdn_conn_set_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    upd_pdn_conn_set_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_upd_pdn_conn_set_rsp(uint8_t *buf,
      upd_pdn_conn_set_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->pgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_bearer_rsrc_command__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_bearer_rsrc_command__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_rsrc_command__overload_ctl_info_ie(uint8_t *buf,
      gtp_bearer_rsrc_command__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes stop_paging_indctn_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    stop_paging_indctn_t
* @return
*   number of decoded bytes.
*/
int decode_stop_paging_indctn(uint8_t *buf,
      stop_paging_indctn_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_IMSI && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_imsi_ie(buf + count, &value->imsi);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_bearer_rsp_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_bearer_rsp_t
* @return
*   number of decoded bytes.
*/
int decode_create_bearer_rsp(uint8_t *buf,
      create_bearer_rsp_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_BEARER_CONTEXT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_create_bearer_response_bearer_ctxt_ie(buf + count, &value->bearer_contexts);
      }  else if (ie_header->type == GTP_IE_RECOVERY && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_recovery_ie(buf + count, &value->recovery);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->epdg_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->twan_fqcsid);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_UE_TIME_ZONE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ue_time_zone_ie(buf + count, &value->ue_time_zone);
      }  else if (ie_header->type == GTP_IE_USER_LOC_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_user_loc_info_ie(buf + count, &value->uli);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->twan_identifier);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->mmes4_sgsns_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->sgws_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_PRES_RPTNG_AREA_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_pres_rptng_area_info_ie(buf + count, &value->pres_rptng_area_info);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->mmes4_sgsn_idnt);
      }  else if (ie_header->type == GTP_IE_OVRLD_CTL_INFO && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_ovrld_ctl_info_ie(buf + count, &value->twanepdgs_ovrld_ctl_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDENTIFIER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_identifier_ie(buf + count, &value->wlan_loc_info);
      }  else if (ie_header->type == GTP_IE_TWAN_IDNT_TS && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_twan_idnt_ts_ie(buf + count, &value->wlan_loc_ts);
      }  else if (ie_header->type == GTP_IE_IP_ADDRESS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ip_address_ie(buf + count, &value->ue_local_ip_addr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_udp_port);
      }  else if (ie_header->type == GTP_IE_FULL_QUAL_CNTNR && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_full_qual_cntnr_ie(buf + count, &value->nbifom_cntnr);
      }  else if (ie_header->type == GTP_IE_PORT_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_port_number_ie(buf + count, &value->ue_tcp_port);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_response__load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__load_ctl_info_ie(uint8_t *buf,
      gtp_mod_acc_bearers_response__load_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->load_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->load_metric);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes rmt_ue_rpt_ack_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    rmt_ue_rpt_ack_t
* @return
*   number of decoded bytes.
*/
int decode_rmt_ue_rpt_ack(uint8_t *buf,
      rmt_ue_rpt_ack_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_bearer_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_bearer_response__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_response__bearer_ctxt_ie(uint8_t *buf,
      gtp_del_bearer_response__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_prot_cfg_opts_ie(buf + count, &value->pco);
      }  else if (ie_header->type == GTP_IE_RAN_NAS_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_ran_nas_cause_ie(buf + count, &value->ran_nas_cause);
      }  else if (ie_header->type == GTP_IE_EXTNDED_PROT_CFG_OPTS && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_extnded_prot_cfg_opts_ie(buf + count, &value->epco);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes create_fwdng_tunn_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    create_fwdng_tunn_req_t
* @return
*   number of decoded bytes.
*/
int decode_create_fwdng_tunn_req(uint8_t *buf,
      create_fwdng_tunn_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_S103_PDN_DATA_FWDNG_INFO && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_s103_pdn_data_fwdng_info_ie(buf + count, &value->s103_pdn_data_fwdng_info);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes upd_pdn_conn_set_req_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    upd_pdn_conn_set_req_t
* @return
*   number of decoded bytes.
*/
int decode_upd_pdn_conn_set_req(uint8_t *buf,
      upd_pdn_conn_set_req_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_gtpv2c_header_t(buf + count, &value->header);
    if (value->header.gtpc.teid_flag)
      buf_len = value->header.gtpc.message_len - 8;
      else
      buf_len = value->header.gtpc.message_len - 4;
      buf = buf + count;
      count = 0;
            while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->mme_fqcsid);
      }  else if (ie_header->type == GTP_IE_FQCSID && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fqcsid_ie(buf + count, &value->sgw_fqcsid);
      }  else if (ie_header->type == GTP_IE_PRIV_EXT) {
            count += decode_gtp_priv_ext_ie(buf + count, &value->priv_ext);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_del_sess_response__overload_ctl_info_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_del_sess_response__overload_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_response__overload_ctl_info_ie(uint8_t *buf,
      gtp_del_sess_response__overload_ctl_info_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_SEQUENCE_NUMBER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_sequence_number_ie(buf + count, &value->ovrld_ctl_seqn_nbr);
      }  else if (ie_header->type == GTP_IE_METRIC && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_metric_ie(buf + count, &value->ovrld_reduction_metric);
      }  else if (ie_header->type == GTP_IE_EPC_TIMER && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_epc_timer_ie(buf + count, &value->prd_of_validity);
      }  else if (ie_header->type == GTP_IE_ACC_PT_NAME && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_acc_pt_name_ie(buf + count, &value->apn);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie(uint8_t *buf,
      gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
/**
* Decodes gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t to buffer.
* @param buf
*   buffer to store decoded values.
* @param value
    gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie(uint8_t *buf,
      gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t *value)
{
      uint16_t count = 0;
      uint16_t buf_len = 0;

    count += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    buf = buf + count/CHAR_SIZE;
    buf_len = value->header.len;
    count = 0;
      while (count < buf_len) {

          ie_header_t *ie_header = (ie_header_t *) (buf + count);

          if (ie_header->type == GTP_IE_EPS_BEARER_ID && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_eps_bearer_id_ie(buf + count, &value->eps_bearer_id);
      }  else if (ie_header->type == GTP_IE_CAUSE && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_cause_ie(buf + count, &value->cause);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ZERO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_ONE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s12_sgw_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_TWO) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s4_u_sgw_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_THREE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_fteid_dl_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FOUR) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->s1u_sgw_fteid_ul_data_fwdng);
      }  else if (ie_header->type == GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT && ie_header->instance == GTP_IE_INSTANCE_FIVE) {
            count += decode_gtp_fully_qual_tunn_endpt_idnt_ie(buf + count, &value->sgw_fteid_ul_data_fwdng);
      }  else
            count += sizeof(ie_header_t) + ntohs(ie_header->len);
      }
      return count;
}
