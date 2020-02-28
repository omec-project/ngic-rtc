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

#include "../include/enc_dec_bits.h"

/**
 * Encodes gtpv2c header to buffer.
 * @param val
 *   gtpv2c header value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_gtpv2c_header_t(gtpv2c_header_t *value,
	uint8_t *buf)
{
    uint16_t encoded = 0;

    encoded += encode_bits(value->gtpc.version, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gtpc.piggyback, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gtpc.teid_flag, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gtpc.spare, 3, buf + (encoded/8), encoded % CHAR_SIZE);

    encoded += encode_bits(value->gtpc.message_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gtpc.message_len, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    if (value->gtpc.teid_flag == 1) {
	encoded += encode_bits(value->teid.has_teid.teid, 32, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid.has_teid.seq, 24, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid.has_teid.spare, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    } else {
	encoded += encode_bits(value->teid.no_teid.seq, 24, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded += encode_bits(value->teid.no_teid.spare, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    }

    return encoded/CHAR_SIZE;
}

/**
 * Encodes ie header to buffer.
 * @param val
 *   ie header
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ie_header_t(ie_header_t *value,
	uint8_t *buf)
{
    uint16_t encoded = 0;

    encoded += encode_bits(value->type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->instance, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    /*return encoded/CHAR_SIZE;*/
    return encoded;
}

/**
* Encodes macro_enb_id_fld to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    macro_enb_id_fld_t
* @return
*   number of encoded bytes.
*/
int encode_macro_enb_id_fld(macro_enb_id_fld_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->menbid_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_macro_enodeb_id, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->menbid_macro_enb_id2, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_umts_key_and_quintuplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_umts_key_and_quintuplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_and_quintuplets_ie(gtp_umts_key_and_quintuplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ksi, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quintuplets, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->iovi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gupii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ugipai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_gprs_intgrty_protctn_algo, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->ck,CK_LEN);
    encoded += CK_LEN * CHAR_SIZE;
    memcpy(buf + (encoded/8), &value->ik,IK_LEN);
    encoded += IK_LEN * CHAR_SIZE;
    encoded += encode_bits(value->auth_quintuplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->iov_updts_cntr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_extnded_acc_rstrct_data, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nrsrna, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_channel_needed_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_channel_needed_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_channel_needed_ie(gtp_channel_needed_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->channel_needed, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_rfsp_index_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rfsp_index_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rfsp_index_ie(gtp_rfsp_index_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rfsp_index, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_guti_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_guti_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_guti_ie(gtp_guti_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mme_group_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mme_code, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->m_tmsi, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_imsi_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_imsi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_imsi_ie(gtp_imsi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    //encoded += encode_bits(value->imsi_number_digits, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/CHAR_SIZE), &value->imsi_number_digits, value->header.len);
    encoded += value->header.len * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_eps_bearer_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_eps_bearer_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_bearer_id_ie(gtp_eps_bearer_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ebi_spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ebi_ebi, 4, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_emlpp_priority_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_emlpp_priority_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_emlpp_priority_ie(gtp_emlpp_priority_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->emlpp_priority, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_prot_cfg_opts_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_prot_cfg_opts_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_prot_cfg_opts_ie(gtp_prot_cfg_opts_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pco, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mdt_cfg_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mdt_cfg_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mdt_cfg_ie(gtp_mdt_cfg_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->job_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->measrmnts_lsts, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rptng_trig, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->report_interval, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->report_amount, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rsrp_evnt_thresh, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rsrq_evnt_thresh, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_area_scop, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->area_scope, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pli, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mpi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->crrmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->coll_prd_rrm_lte, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->meas_prd_lte, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pos_mthd, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_mdt_plmns, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mdt_plmn_list, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_src_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_src_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_src_id_ie(gtp_src_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->target_cell_id, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->source_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->source_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes auth_quintuplet to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    auth_quintuplet_t
* @return
*   number of encoded bytes.
*/
int encode_auth_quintuplet(auth_quintuplet_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    memcpy(buf + (encoded/8), &value->rand,RAND_LEN);
    encoded += RAND_LEN * CHAR_SIZE;
    encoded += encode_bits(value->xres_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->xres, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->ck,CK_LEN);
    encoded += CK_LEN * CHAR_SIZE;
    memcpy(buf + (encoded/8), &value->ik,IK_LEN);
    encoded += IK_LEN * CHAR_SIZE;
    encoded += encode_bits(value->autn_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->autn, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_macro_ng_enb to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_macro_ng_enb_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_macro_ng_enb(trgt_id_type_macro_ng_enb_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macro_ng_enb_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fivegs_tac, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ran_nas_cause_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ran_nas_cause_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ran_nas_cause_ie(gtp_ran_nas_cause_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->protocol_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cause_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cause_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_rnc_id to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_rnc_id_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_rnc_id(trgt_id_type_rnc_id_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lac, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rac, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rnc_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->extended_rnc_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pdn_type_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pdn_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_type_ie(gtp_pdn_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pdn_type_spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pdn_type_pdn_type, 3, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_eps_secur_ctxt_and_quadruplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_eps_secur_ctxt_and_quadruplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_secur_ctxt_and_quadruplets_ie(gtp_eps_secur_ctxt_and_quadruplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nhi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ksiasme, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quintuplets, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quadruplet, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->osci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_nas_intgrty_protctn_algo, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_nas_cipher, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nas_dnlnk_cnt, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nas_uplnk_cnt, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->kasme,KASME_LEN);
    encoded += KASME_LEN * CHAR_SIZE;
    encoded += encode_bits(value->auth_quadruplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->auth_quintuplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->nh,NH_LEN);
    encoded += NH_LEN * CHAR_SIZE;
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ncc, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->s, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nhi_old, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->old_ksiasme, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->old_ncc, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->old_kasme,OLD_KASME_LEN);
    encoded += OLD_KASME_LEN * CHAR_SIZE;
    memcpy(buf + (encoded/8), &value->old_nh,OLD_NH_LEN);
    encoded += OLD_NH_LEN * CHAR_SIZE;
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_ue_radio_capblty_paging_info, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_radio_capblty_paging_info, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_extnded_acc_rstrct_data, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ussrna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nrsrna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_addtl_secur_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_addtl_secur_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_ue_nr_secur_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_nr_secur_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_s103_pdn_data_fwdng_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_s103_pdn_data_fwdng_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_s103_pdn_data_fwdng_info_ie(gtp_s103_pdn_data_fwdng_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->hsgw_addr_fwdng_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hsgw_addr_fwdng, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gre_key, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->eps_bearer_id_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_fully_qual_domain_name_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fully_qual_domain_name_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fully_qual_domain_name_ie(gtp_fully_qual_domain_name_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->fqdn, value->header.len);
    encoded += value->header.len * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_traffic_agg_desc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_traffic_agg_desc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_traffic_agg_desc_ie(gtp_traffic_agg_desc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->traffic_agg_desc, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_flow_qlty_of_svc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_flow_qlty_of_svc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_flow_qlty_of_svc_ie(gtp_flow_qlty_of_svc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->qci, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_bit_rate_uplnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_bit_rate_dnlnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->guarntd_bit_rate_uplnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->guarntd_bit_rate_dnlnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_fully_qual_tunn_endpt_idnt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fully_qual_tunn_endpt_idnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fully_qual_tunn_endpt_idnt_ie(gtp_fully_qual_tunn_endpt_idnt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->v4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->v6, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->interface_type, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->teid_gre_key, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ipv4_address, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    if (value->v6) {
    	memcpy(buf + (encoded/8), &value->ipv6_address, IPV6_ADDRESS_LEN);
    	encoded += IPV6_ADDRESS_LEN * CHAR_SIZE;
    }

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_recovery_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_recovery_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_recovery_ie(gtp_recovery_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->recovery, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_srvng_plmn_rate_ctl_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_srvng_plmn_rate_ctl_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_srvng_plmn_rate_ctl_ie(gtp_srvng_plmn_rate_ctl_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->uplnk_rate_lmt, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_rate_lmt, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_dist_ack_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_dist_ack_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_dist_ack_ie(gtp_mbms_dist_ack_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->distr_ind, 2, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ue_time_zone_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ue_time_zone_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ue_time_zone_ie(gtp_ue_time_zone_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->time_zone, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->daylt_svng_time, 2, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_s1u_data_fwdng_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_s1u_data_fwdng_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_s1u_data_fwdng_ie(gtp_s1u_data_fwdng_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sgw_addr_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sgw_address, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sgw_s1u_teid, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pres_rptng_area_act_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pres_rptng_area_act_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pres_rptng_area_act_ie(gtp_pres_rptng_area_act_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->inapra, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->action, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pres_rptng_area_idnt, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_tai, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_rai, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_macro_enb, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_home_enb, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare5, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_ecgi, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare6, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_sai, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare7, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_cgi, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tais, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macro_enb_ids, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->home_enb_ids, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgis, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rais, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sais, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgis, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare8, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_extnded_macro_enb, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->extnded_macro_enb_ids, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_trstd_wlan_mode_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_trstd_wlan_mode_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_trstd_wlan_mode_indctn_ie(gtp_trstd_wlan_mode_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcm, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->scm, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_proc_trans_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_proc_trans_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_proc_trans_id_ie(gtp_proc_trans_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->proc_trans_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_wlan_offldblty_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_wlan_offldblty_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_wlan_offldblty_indctn_ie(gtp_wlan_offldblty_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->eutran_indctn, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->utran_indctn, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_uli_timestamp_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_uli_timestamp_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_uli_timestamp_ie(gtp_uli_timestamp_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->uli_ts_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_max_pckt_loss_rate_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_max_pckt_loss_rate_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_max_pckt_loss_rate_ie(gtp_max_pckt_loss_rate_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ul, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_pckt_loss_rate_ul, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_pckt_loss_rate_dl, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_cn_oper_sel_entity_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_cn_oper_sel_entity_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_cn_oper_sel_entity_ie(gtp_cn_oper_sel_entity_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sel_entity, 2, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes rai_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    rai_field_t
* @return
*   number of encoded bytes.
*/
int encode_rai_field(rai_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->ria_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_lac, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ria_rac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_alloc_reten_priority_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_alloc_reten_priority_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_alloc_reten_priority_ie(gtp_alloc_reten_priority_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pl, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pvi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_apn_restriction_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_apn_restriction_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_apn_restriction_ie(gtp_apn_restriction_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rstrct_type_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes sai_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    sai_field_t
* @return
*   number of encoded bytes.
*/
int encode_sai_field(sai_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->sai_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_lac, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai_sac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_extnded_macro_ng_enb to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_extnded_macro_ng_enb_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_extnded_macro_ng_enb(trgt_id_type_extnded_macro_ng_enb_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->smenb, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->extnded_macro_ng_enb_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fivegs_tac, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ptmsi_signature_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ptmsi_signature_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ptmsi_signature_ie(gtp_ptmsi_signature_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ptmsi_signature, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_paging_and_svc_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_paging_and_svc_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_paging_and_svc_info_ie(gtp_paging_and_svc_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ebi, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ppi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->paging_plcy_indctn_val, 6, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ovrld_ctl_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ovrld_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ovrld_ctl_info_ie(gtp_ovrld_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->overload_control_information,OVERLOAD_CONTROL_INFORMATION_LEN);
    encoded += OVERLOAD_CONTROL_INFORMATION_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ecgi_list_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ecgi_list_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ecgi_list_ie(gtp_ecgi_list_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->nbr_of_ecgi_flds, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_list_of_m_ecgi_flds, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_agg_max_bit_rate_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_agg_max_bit_rate_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_agg_max_bit_rate_ie(gtp_agg_max_bit_rate_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->apn_ambr_uplnk, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->apn_ambr_dnlnk, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes tai_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    tai_field_t
* @return
*   number of encoded bytes.
*/
int encode_tai_field(tai_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->tai_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai_tac, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_acc_pt_name_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_acc_pt_name_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_acc_pt_name_ie(gtp_acc_pt_name_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->apn, value->header.len);
    encoded += value->header.len * CHAR_SIZE ;

    return encoded/CHAR_SIZE;
}


/**
* Encodes bss_container to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    bss_container_t
* @return
*   number of encoded bytes.
*/
int encode_bss_container(bss_container_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->phx, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sapi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rp, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pfi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sapi2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->radio_priority, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->xid_parms_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->xid_parameters, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_gnode_id to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_gnode_id_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_gnode_id(trgt_id_type_gnode_id_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gnb_id_len, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gnodeb_id, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fivegs_tac, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_umts_key_quadruplets_and_quintuplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_umts_key_quadruplets_and_quintuplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_quadruplets_and_quintuplets_ie(gtp_umts_key_quadruplets_and_quintuplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ksiasme, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quintuplets, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quadruplet, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->ck,CK_LEN);
    encoded += CK_LEN * CHAR_SIZE;
    memcpy(buf + (encoded/8), &value->ik,IK_LEN);
    encoded += IK_LEN * CHAR_SIZE;
    encoded += encode_bits(value->auth_quadruplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->auth_quintuplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_cmplt_req_msg_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_cmplt_req_msg_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_cmplt_req_msg_ie(gtp_cmplt_req_msg_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->cmplt_req_msg_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cmplt_req_msg, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_epc_timer_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_epc_timer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_epc_timer_ie(gtp_epc_timer_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->timer_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->timer_value, 5, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_csg_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_csg_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_id_ie(gtp_csg_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->csg_id_spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->csg_id_csg_id, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->csg_id_csg_id2, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_extnded_macro_enb to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_extnded_macro_enb_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_extnded_macro_enb(trgt_id_type_extnded_macro_enb_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->smenb, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->extnded_macro_enb_id_field2, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_packet_flow_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_packet_flow_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_packet_flow_id_ie(gtp_packet_flow_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->packet_flow_id_spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->packet_flow_id_ebi, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->packet_flow_id_packet_flow_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_tmgi_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_tmgi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_tmgi_ie(gtp_tmgi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->tmgi, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mntrng_evnt_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mntrng_evnt_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mntrng_evnt_info_ie(gtp_mntrng_evnt_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->scef_ref_id, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->scef_id_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->scef_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rem_nbr_of_rpts, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_rmt_ue_ip_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rmt_ue_ip_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_ip_info_ie(gtp_rmt_ue_ip_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rmt_ue_ip_info, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes ecgi_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    ecgi_field_t
* @return
*   number of encoded bytes.
*/
int encode_ecgi_field(ecgi_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->ecgi_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi_spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->eci, 28, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_bearer_qlty_of_svc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_bearer_qlty_of_svc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_qlty_of_svc_ie(gtp_bearer_qlty_of_svc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pl, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pvi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->qci, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_bit_rate_uplnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_bit_rate_dnlnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->guarntd_bit_rate_uplnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->guarntd_bit_rate_dnlnk, 40, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mapped_ue_usage_type_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mapped_ue_usage_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mapped_ue_usage_type_ie(gtp_mapped_ue_usage_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mapped_ue_usage_type, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_svc_indctr_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_svc_indctr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_svc_indctr_ie(gtp_svc_indctr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->svc_indctr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_umts_key_used_cipher_and_quintuplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_umts_key_used_cipher_and_quintuplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_umts_key_used_cipher_and_quintuplets_ie(gtp_umts_key_used_cipher_and_quintuplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cksnksi, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quintuplets, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->iovi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gupii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ugipai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_gprs_intgrty_protctn_algo, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_cipher, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->ck,CK_LEN);
    encoded += CK_LEN * CHAR_SIZE;
    memcpy(buf + (encoded/8), &value->ik,IK_LEN);
    encoded += IK_LEN * CHAR_SIZE;
    encoded += encode_bits(value->auth_quintuplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->iov_updts_cntr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes auth_triplet to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    auth_triplet_t
* @return
*   number of encoded bytes.
*/
int encode_auth_triplet(auth_triplet_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    memcpy(buf + (encoded/8), &value->rand,RAND_LEN);
    encoded += RAND_LEN * CHAR_SIZE;
    encoded += encode_bits(value->sres, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->kc, 64, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_local_distgsd_name_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_local_distgsd_name_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_local_distgsd_name_ie(gtp_local_distgsd_name_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ldn, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_csg_info_rptng_act_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_csg_info_rptng_act_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_info_rptng_act_ie(gtp_csg_info_rptng_act_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uciuhc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ucishc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ucicsg, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_secdry_rat_usage_data_rpt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_secdry_rat_usage_data_rpt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_secdry_rat_usage_data_rpt_ie(gtp_secdry_rat_usage_data_rpt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->irsgw, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->irpgw, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->secdry_rat_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ebi, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->start_timestamp, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->end_timestamp, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->usage_data_dl, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->usage_data_ul, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_rat_type_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rat_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rat_type_ie(gtp_rat_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rat_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_macro_enb to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_macro_enb_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_macro_enb(trgt_id_type_macro_enb_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macro_enb_id_field2, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_global_cn_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_global_cn_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_global_cn_id_ie(gtp_global_cn_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cn, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_charging_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_charging_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_charging_id_ie(gtp_charging_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->chrgng_id_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_counter_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_counter_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_counter_ie(gtp_counter_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->timestamp_value, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->counter_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_serving_network_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_serving_network_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_serving_network_ie(gtp_serving_network_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_node_identifier_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_node_identifier_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_identifier_ie(gtp_node_identifier_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->len_of_node_name, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->node_name, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_node_realm, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->node_realm, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes extnded_macro_enb_id_fld to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    extnded_macro_enb_id_fld_t
* @return
*   number of encoded bytes.
*/
int encode_extnded_macro_enb_id_fld(extnded_macro_enb_id_fld_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->emenbid_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_smenb, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_spare, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_extnded_macro_enb_id, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->emenbid_extnded_macro_enb_id2, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_trc_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_trc_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_trc_info_ie(gtp_trc_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->trace_id, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->trigrng_evnts,TRIGRNG_EVNTS_LEN);
    encoded += TRIGRNG_EVNTS_LEN * CHAR_SIZE;
    encoded += encode_bits(value->list_of_ne_types, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sess_trc_depth, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->list_of_intfcs,LIST_OF_INTFCS_LEN);
    encoded += LIST_OF_INTFCS_LEN * CHAR_SIZE;
    encoded += encode_bits(value->ip_addr_of_trc_coll_entity, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_ip_multcst_dist_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_ip_multcst_dist_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_ip_multcst_dist_ie(gtp_mbms_ip_multcst_dist_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->cmn_tunn_endpt_idnt, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->address_type, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->address_length, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ip_multcst_dist_addr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->address_type2, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->address_length2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ip_multcst_src_addr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mbms_hc_indctr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_full_qual_cntnr_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_full_qual_cntnr_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_full_qual_cntnr_ie(gtp_full_qual_cntnr_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->container_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fcontainer_fld, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_data_xfer_abs_time_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_data_xfer_abs_time_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_data_xfer_abs_time_ie(gtp_mbms_data_xfer_abs_time_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_data_xfer_abs_time_val_prt, 64, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes auth_quadruplet to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    auth_quadruplet_t
* @return
*   number of encoded bytes.
*/
int encode_auth_quadruplet(auth_quadruplet_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    memcpy(buf + (encoded/8), &value->rand,RAND_LEN);
    encoded += RAND_LEN * CHAR_SIZE;
    encoded += encode_bits(value->xres_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->xres, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->autn_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->autn, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->kasme,KASME_LEN);
    encoded += KASME_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_gsm_key_used_cipher_and_quintuplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_gsm_key_used_cipher_and_quintuplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_gsm_key_used_cipher_and_quintuplets_ie(gtp_gsm_key_used_cipher_and_quintuplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cksnksi, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_quintuplets, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_cipher, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->kc, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->auth_quintuplets, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->higher_bitrates_flg, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_twan_idnt_ts_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_twan_idnt_ts_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_twan_idnt_ts_ie(gtp_twan_idnt_ts_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->twan_idnt_ts_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_tmsi_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_tmsi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_tmsi_ie(gtp_tmsi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->tmsi, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pdn_addr_alloc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pdn_addr_alloc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_addr_alloc_ie(gtp_pdn_addr_alloc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pdn_type, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->pdn_addr_and_pfx, value->header.len - 1);
    encoded += (value->header.len - 1) * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_twan_identifier_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_twan_identifier_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_twan_identifier_ie(gtp_twan_identifier_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->laii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->opnai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->plmni, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->civai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bssidi, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ssid_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ssid, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bssid, 48, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->civic_addr_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->civic_addr_info, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->twan_plmn_id, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->twan_oper_name_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->twan_oper_name, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rly_idnty_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rly_idnty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->relay_identity, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->circuit_id_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->circuit_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes cgi_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    cgi_field_t
* @return
*   number of encoded bytes.
*/
int encode_cgi_field(cgi_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->cgi_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_lac, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi_ci, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_user_loc_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_user_loc_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_user_loc_info_ie(gtp_user_loc_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->extnded_macro_enb_id, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->macro_enodeb_id, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecgi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cgi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
	encoded = encoded/CHAR_SIZE;
    if (value->cgi)
    	encoded += encode_cgi_field(&(value->cgi2), buf + encoded);
    if (value->sai)
    	encoded += encode_sai_field(&(value->sai2), buf + encoded);
    if (value->rai)
    	encoded += encode_rai_field(&(value->rai2), buf + encoded);
    if (value->tai)
    	encoded += encode_tai_field(&(value->tai2), buf + encoded);
    if (value->ecgi)
    	encoded += encode_ecgi_field(&(value->ecgi2), buf + encoded);
    if (value->lai)
    	encoded += encode_lai_field(&(value->lai2), buf + encoded);
    if (value->macro_enodeb_id)
    	encoded += encode_macro_enb_id_fld(&(value->macro_enodeb_id2), buf + encoded);
    if (value->extnded_macro_enb_id)
    	encoded += encode_extnded_macro_enb_id_fld(&(value->extended_macro_enodeb_id2), buf + encoded);

    return encoded;
}


/**
* Encodes gtp_ptmsi_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ptmsi_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ptmsi_ie(gtp_ptmsi_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ptmsi, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_node_type_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_node_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_type_ie(gtp_node_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->node_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_user_csg_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_user_csg_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_user_csg_info_ie(gtp_user_csg_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->csg_id2, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->access_mode, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lcsg, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_integer_number_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_integer_number_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_integer_number_ie(gtp_integer_number_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->int_nbr_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_sess_dur_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_sess_dur_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_sess_dur_ie(gtp_mbms_sess_dur_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_sess_dur, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_msisdn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_msisdn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_msisdn_ie(gtp_msisdn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    //encoded += encode_bits(value->msisdn_number_digits, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/CHAR_SIZE), &value->msisdn_number_digits, value->header.len);
    encoded += value->header.len * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_metric_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_metric_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_metric_ie(gtp_metric_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->metric, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_bearer_context_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_bearer_context_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_context_ie(gtp_bearer_context_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->bearer_context,BEARER_CONTEXT_LEN);
    encoded += BEARER_CONTEXT_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ciot_optim_supp_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ciot_optim_supp_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ciot_optim_supp_indctn_ie(gtp_ciot_optim_supp_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare5, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ihcsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->awopdn, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->scnipdn, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sgnipdn, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pdu_numbers_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pdu_numbers_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdu_numbers_ie(gtp_pdu_numbers_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nsapi, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_gtpu_seqn_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ul_gtpu_seqn_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->snd_npdu_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->rcv_npdu_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_rab_context_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rab_context_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rab_context_ie(gtp_rab_context_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nsapi, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_gtpu_seqn_nbr, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ul_gtpu_seqn_nbr, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dl_pdcp_seqn_nbr, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ul_pdcp_seqn_nbr, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_addtl_flgs_srvcc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_addtl_flgs_srvcc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_flgs_srvcc_ie(gtp_addtl_flgs_srvcc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ics, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_gsm_key_and_triplets_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_gsm_key_and_triplets_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_gsm_key_and_triplets_ie(gtp_gsm_key_and_triplets_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->security_mode, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drxi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cksn, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbr_of_triplet, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare3, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sambri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare4, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->used_cipher, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->kc, 64, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->auth_triplet, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->drx_parameter, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_subscrbd_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->uplnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dnlnk_used_ue_ambr, 32, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ue_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_ntwk_capblty, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ecna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->nbna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->hnna, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ina, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gana, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->gena, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->una, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vdom_pref_ue_usage_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->voice_domain_pref_and_ues_usage_setting, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_node_number_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_node_number_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_number_ie(gtp_node_number_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->len_of_node_nbr, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->node_number, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_load_ctl_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_load_ctl_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_load_ctl_info_ie(gtp_load_ctl_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->load_control_information,LOAD_CONTROL_INFORMATION_LEN);
    encoded += LOAD_CONTROL_INFORMATION_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_rmt_ue_ctxt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_rmt_ue_ctxt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_ctxt_ie(gtp_rmt_ue_ctxt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->remote_ue_context,REMOTE_UE_CONTEXT_LEN);
    encoded += REMOTE_UE_CONTEXT_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_full_qual_cause_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_full_qual_cause_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_full_qual_cause_ie(gtp_full_qual_cause_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cause_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fcause_field, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_indication_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_indication_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_indication_ie(gtp_indication_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->indication_daf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_dtf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_hi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_dfi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_oi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_isrsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_israi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_sgwci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_sqci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_uimsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_cfsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_crsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_p, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_pt, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_si, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_msv, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_retloc, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_pbic, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_srni, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_s6af, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_s4af, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_mbmdt, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_israu, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ccrsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_cprai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_arrl, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ppof, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ppon_ppei, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ppsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_csfbi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_clii, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_cpsr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_nsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_uasi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_dtci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_bdwi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_psci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_pcri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_aosi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_aopi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_roaai, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_epcosi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_cpopci, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_pmtsmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_s11tf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_pnsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_unaccsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_wpmsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_spare2, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_spare3, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_spare4, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_eevrsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ltemui, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_ltempi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_enbcrsi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->indication_tspcmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ipv4_cfg_parms_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ipv4_cfg_parms_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ipv4_cfg_parms_ie(gtp_ipv4_cfg_parms_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->subnet_pfx_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ipv4_dflt_rtr_addr, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_trace_reference_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_trace_reference_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_trace_reference_ie(gtp_trace_reference_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->trace_id, 24, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_node_features_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_node_features_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_node_features_ie(gtp_node_features_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sup_feat, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_remote_user_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_remote_user_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_remote_user_id_ie(gtp_remote_user_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->imeif, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->msisdnf, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->length_of_imsi, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->len_of_msisdn, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->length_of_imei, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->imei, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_fqcsid_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_fqcsid_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_fqcsid_ie(gtp_fqcsid_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->node_id_type, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->number_of_csids, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->node_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    memcpy(buf + (encoded/8), &value->pdn_csid,PDN_CSID_LEN);
    encoded += PDN_CSID_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_port_number_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_port_number_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_port_number_ie(gtp_port_number_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->port_number, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_addtl_mm_ctxt_srvcc_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_addtl_mm_ctxt_srvcc_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_mm_ctxt_srvcc_ie(gtp_addtl_mm_ctxt_srvcc_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ms_classmark_2_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_classmark_2, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_classmark_3_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ms_classmark_3, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sup_codec_list_len, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sup_codec_list, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_act_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_act_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_act_indctn_ie(gtp_act_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_plmn_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_plmn_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_plmn_id_ie(gtp_plmn_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_flow_idnt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_flow_idnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_flow_idnt_ie(gtp_mbms_flow_idnt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_flow_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_hdr_comp_cfg_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_hdr_comp_cfg_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_hdr_comp_cfg_ie(gtp_hdr_comp_cfg_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rohc_profiles, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->max_cid, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_sgnllng_priority_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_sgnllng_priority_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_sgnllng_priority_indctn_ie(gtp_sgnllng_priority_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lapi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_cause_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_cause_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_cause_ie(gtp_cause_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->cause_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->pce, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->bce, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->cs, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    if (value->header.len != 2){
        encoded += encode_bits(value->offend_ie_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->offend_ie_len, 16, buf + (encoded/8), encoded % CHAR_SIZE);
        encoded += encode_bits(value->spareinstance, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    }
    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_time_to_data_xfer_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_time_to_data_xfer_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_time_to_data_xfer_ie(gtp_mbms_time_to_data_xfer_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_time_to_data_xfer_val_prt, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_addtl_prot_cfg_opts_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_addtl_prot_cfg_opts_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_addtl_prot_cfg_opts_ie(gtp_addtl_prot_cfg_opts_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->apco, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_trgt_id_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_trgt_id_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_trgt_id_ie(gtp_trgt_id_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->target_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->target_id, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_flags_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_flags_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_flags_ie(gtp_mbms_flags_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lmri, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->msri, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_trans_idnt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_trans_idnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_trans_idnt_ie(gtp_trans_idnt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->trans_idnt, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes trgt_id_type_home_enb to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    trgt_id_type_home_enb_t
* @return
*   number of encoded bytes.
*/
int encode_trgt_id_type_home_enb(trgt_id_type_home_enb_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->home_enodeb_id, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->home_enodeb_id2, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_bearer_flags_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_bearer_flags_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_flags_ie(gtp_bearer_flags_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->asi, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vind, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->vb, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ppc, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes lai_field to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    lai_field_t
* @return
*   number of encoded bytes.
*/
int encode_lai_field(lai_field_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_bits(value->lai_mcc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_mcc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_mnc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_mcc_digit_3, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_mnc_digit_2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_mnc_digit_1, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->lai_lac, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_msec_time_stmp_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_msec_time_stmp_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_msec_time_stmp_ie(gtp_msec_time_stmp_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->msec_time_stmp_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_chg_to_rpt_flgs_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_chg_to_rpt_flgs_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_chg_to_rpt_flgs_ie(gtp_chg_to_rpt_flgs_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->tzcr, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->sncr, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_scef_pdn_conn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_scef_pdn_conn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_scef_pdn_conn_ie(gtp_scef_pdn_conn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->scef_pdn_connection,SCEF_PDN_CONNECTION_LEN);
    encoded += SCEF_PDN_CONNECTION_LEN * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_chg_rptng_act_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_chg_rptng_act_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_chg_rptng_act_ie(gtp_chg_rptng_act_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->action, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_extnded_prot_cfg_opts_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_extnded_prot_cfg_opts_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_extnded_prot_cfg_opts_ie(gtp_extnded_prot_cfg_opts_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->epco, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_delay_value_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_delay_value_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_delay_value_ie(gtp_delay_value_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->delay_value, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pdn_connection_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pdn_connection_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pdn_connection_ie(gtp_pdn_connection_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_detach_type_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_detach_type_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_detach_type_ie(gtp_detach_type_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->detach_type, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_svc_area_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_svc_area_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_svc_area_ie(gtp_mbms_svc_area_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_svc_area, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_chrgng_char_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_chrgng_char_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_chrgng_char_ie(gtp_chrgng_char_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->chrgng_char_val, 16, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_henb_info_rptng_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_henb_info_rptng_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_henb_info_rptng_ie(gtp_henb_info_rptng_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->fti, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes mm_context to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    mm_context_t
* @return
*   number of encoded bytes.
*/
int encode_mm_context(mm_context_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_throttling_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_throttling_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_throttling_ie(gtp_throttling_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->thrtlng_delay_unit, 3, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->thrtlng_delay_val, 5, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->thrtlng_factor, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_csg_memb_indctn_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_csg_memb_indctn_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_csg_memb_indctn_ie(gtp_csg_memb_indctn_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->csg_memb_indctn_spare2, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->csg_memb_indctn_cmi, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_ip_address_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_ip_address_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_ip_address_ie(gtp_ip_address_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->ipv4_ipv6_addr, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_src_rnc_pdcp_ctxt_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_src_rnc_pdcp_ctxt_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_src_rnc_pdcp_ctxt_info_ie(gtp_src_rnc_pdcp_ctxt_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rrc_container, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_hop_counter_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_hop_counter_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_hop_counter_ie(gtp_hop_counter_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->hop_counter, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_pres_rptng_area_info_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_pres_rptng_area_info_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_pres_rptng_area_info_ie(gtp_pres_rptng_area_info_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->pra_identifier, 24, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->spare2, 4, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->inapra, 2, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->apra, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->opra, 1, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->ipra, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbms_sess_idnt_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbms_sess_idnt_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbms_sess_idnt_ie(gtp_mbms_sess_idnt_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mbms_sess_idnt, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_apn_and_rltv_cap_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_apn_and_rltv_cap_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_apn_and_rltv_cap_ie(gtp_apn_and_rltv_cap_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->rltv_cap, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->apn_length, 8, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->apn, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_selection_mode_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_selection_mode_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_selection_mode_ie(gtp_selection_mode_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 6, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->selec_mode, 2, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_up_func_sel_indctn_flgs_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_up_func_sel_indctn_flgs_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_up_func_sel_indctn_flgs_ie(gtp_up_func_sel_indctn_flgs_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->spare2, 7, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->dcnr, 1, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_mbl_equip_idnty_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_mbl_equip_idnty_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_mbl_equip_idnty_ie(gtp_mbl_equip_idnty_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->mei, 64, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_priv_ext_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_priv_ext_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_priv_ext_ie(gtp_priv_ext_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->enterprise_id, 16, buf + (encoded/8), encoded % CHAR_SIZE);
    encoded += encode_bits(value->prop_val, 8, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_eps_bearer_lvl_traffic_flow_tmpl_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    memcpy(buf + (encoded/8), &value->eps_bearer_lvl_tft, value->header.len);
    encoded += value->header.len * CHAR_SIZE;

    return encoded/CHAR_SIZE;
}


/**
* Encodes gtp_sequence_number_ie to buffer.
* @param buf
*   buffer to store encoded values.
* @param value
    gtp_sequence_number_ie_t
* @return
*   number of encoded bytes.
*/
int encode_gtp_sequence_number_ie(gtp_sequence_number_ie_t *value,
    uint8_t *buf)
{
    uint16_t encoded = 0;
    encoded += encode_ie_header_t(&value->header, buf + (encoded/CHAR_SIZE));
    encoded += encode_bits(value->sequence_number, 32, buf + (encoded/8), encoded % CHAR_SIZE);

    return encoded/CHAR_SIZE;
}

