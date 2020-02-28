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

#include "../include/enc_dec_bits.h"

#define IE_HEADER_SIZE sizeof(ie_header_t)


/**
 * decodes buffer to ie header.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   decoded ie header
 * @return
 *   number of decoded bytes.
 */
int decode_ie_header_t(uint8_t *buf, ie_header_t *val,
		uint16_t val_len)
{
	memcpy(val, buf, IE_HEADER_SIZE);
	val->len = ntohs(val->len);

	return val_len * CHAR_SIZE;
}

/**
 * decodes buffer to gtpv2c header.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   gtpv2c header
 * @return
 *   number of decoded bytes.
 */
int decode_gtpv2c_header_t(uint8_t *buf, gtpv2c_header_t *header)
{
	uint16_t count = 0;

	memcpy(&header->gtpc, buf, sizeof(header->gtpc));
	count += sizeof(header->gtpc);

	header->gtpc.message_len = ntohs(header->gtpc.message_len);

	if (header->gtpc.teid_flag) {
		memcpy(&header->teid.has_teid.teid, buf + count,
				sizeof(header->teid.has_teid.teid));
		count += sizeof(header->teid.has_teid.teid);

		header->teid.has_teid.teid = ntohl(header->teid.has_teid.teid);

		header->teid.has_teid.seq = (((uint32_t) (buf + count)[0]) << 16) |
				(((uint32_t) (buf + count)[1]) << 8) | (((uint32_t) (buf + count)[2]));

		count += sizeof(uint32_t);
	} else {
		header->teid.no_teid.seq = (((uint32_t) (buf + count)[0]) << 16) |
				(((uint32_t) (buf + count)[1]) << 8) | (((uint32_t) (buf + count)[2]));

		count += sizeof(uint32_t);
	}

	return count;
}
/**
* decodes macro_enb_id_fld_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    macro_enb_id_fld_t
* @return
*   number of decoded bytes.
*/
int decode_macro_enb_id_fld(uint8_t *buf,
        macro_enb_id_fld_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->menbid_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_macro_enodeb_id = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->menbid_macro_enb_id2 = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_umts_key_and_quintuplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_umts_key_and_quintuplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_and_quintuplets_ie(uint8_t *buf,
        gtp_umts_key_and_quintuplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ksi = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quintuplets = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->iovi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gupii = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ugipai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->used_gprs_intgrty_protctn_algo = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
    total_decoded +=  CK_LEN * CHAR_SIZE;
    memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
    total_decoded +=  IK_LEN * CHAR_SIZE;
    value->auth_quintuplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->iov_updts_cntr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_extnded_acc_rstrct_data = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->nrsrna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_channel_needed_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_channel_needed_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_channel_needed_ie(uint8_t *buf,
        gtp_channel_needed_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->channel_needed = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_rfsp_index_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_rfsp_index_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rfsp_index_ie(uint8_t *buf,
        gtp_rfsp_index_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rfsp_index = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_guti_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_guti_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_guti_ie(uint8_t *buf,
        gtp_guti_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    value->mme_group_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->mme_code = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->m_tmsi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_imsi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_imsi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_imsi_ie(uint8_t *buf,
        gtp_imsi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    // value->imsi_number_digits = decode_bits(buf, total_decoded, 64, &decoded);
    // total_decoded += decoded;
    /* TODO: Revisit this for change in yang */
    memcpy(&value->imsi_number_digits, (uint8_t *)buf + total_decoded/CHAR_SIZE, value->header.len);
    total_decoded += value->header.len * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_eps_bearer_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_eps_bearer_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_bearer_id_ie(uint8_t *buf,
        gtp_eps_bearer_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ebi_spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ebi_ebi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_emlpp_priority_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_emlpp_priority_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_emlpp_priority_ie(uint8_t *buf,
        gtp_emlpp_priority_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->emlpp_priority = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_prot_cfg_opts_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_prot_cfg_opts_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_prot_cfg_opts_ie(uint8_t *buf,
        gtp_prot_cfg_opts_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->pco = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mdt_cfg_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mdt_cfg_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mdt_cfg_ie(uint8_t *buf,
        gtp_mdt_cfg_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->job_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->measrmnts_lsts = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->rptng_trig = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->report_interval = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->report_amount = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rsrp_evnt_thresh = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rsrq_evnt_thresh = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_area_scop = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->area_scope = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->pli = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pmi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->mpi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->crrmi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->coll_prd_rrm_lte = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->meas_prd_lte = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->pos_mthd = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->nbr_of_mdt_plmns = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mdt_plmn_list = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_src_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_src_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_src_id_ie(uint8_t *buf,
        gtp_src_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->target_cell_id = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    value->source_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->source_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes auth_quintuplet_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    auth_quintuplet_t
* @return
*   number of decoded bytes.
*/
int decode_auth_quintuplet(uint8_t *buf,
        auth_quintuplet_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    memcpy(&value->rand, buf + (total_decoded/CHAR_SIZE), RAND_LEN);
    total_decoded +=  RAND_LEN * CHAR_SIZE;
    value->xres_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->xres = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
    total_decoded +=  CK_LEN * CHAR_SIZE;
    memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
    total_decoded +=  IK_LEN * CHAR_SIZE;
    value->autn_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->autn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes trgt_id_type_macro_ng_enb_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_macro_ng_enb_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_macro_ng_enb(uint8_t *buf,
        trgt_id_type_macro_ng_enb_t *value)
{
    uint16_t total_decoded = 0;
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
    value->spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->macro_ng_enb_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->fivegs_tac = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_ran_nas_cause_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ran_nas_cause_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ran_nas_cause_ie(uint8_t *buf,
        gtp_ran_nas_cause_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->protocol_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cause_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cause_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes trgt_id_type_rnc_id_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_rnc_id_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_rnc_id(uint8_t *buf,
        trgt_id_type_rnc_id_t *value)
{
    uint16_t total_decoded = 0;
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
    value->lac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->rac = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rnc_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->extended_rnc_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_pdn_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pdn_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_type_ie(uint8_t *buf,
        gtp_pdn_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->pdn_type_spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->pdn_type_pdn_type = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_eps_secur_ctxt_and_quadruplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_eps_secur_ctxt_and_quadruplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_secur_ctxt_and_quadruplets_ie(uint8_t *buf,
        gtp_eps_secur_ctxt_and_quadruplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nhi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ksiasme = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quintuplets = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quadruplet = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->osci = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->used_nas_intgrty_protctn_algo = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->used_nas_cipher = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->nas_dnlnk_cnt = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->nas_uplnk_cnt = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    memcpy(&value->kasme, buf + (total_decoded/CHAR_SIZE), KASME_LEN);
    total_decoded +=  KASME_LEN * CHAR_SIZE;
    value->auth_quadruplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->auth_quintuplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    memcpy(&value->nh, buf + (total_decoded/CHAR_SIZE), NH_LEN);
    total_decoded +=  NH_LEN * CHAR_SIZE;
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->ncc = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->s = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->nhi_old = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->old_ksiasme = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->old_ncc = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    memcpy(&value->old_kasme, buf + (total_decoded/CHAR_SIZE), OLD_KASME_LEN);
    total_decoded +=  OLD_KASME_LEN * CHAR_SIZE;
    memcpy(&value->old_nh, buf + (total_decoded/CHAR_SIZE), OLD_NH_LEN);
    total_decoded +=  OLD_NH_LEN * CHAR_SIZE;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_ue_radio_capblty_paging_info = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->ue_radio_capblty_paging_info = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_extnded_acc_rstrct_data = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->ussrna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nrsrna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ue_addtl_secur_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_addtl_secur_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_ue_nr_secur_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_nr_secur_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_s103_pdn_data_fwdng_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_s103_pdn_data_fwdng_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_s103_pdn_data_fwdng_info_ie(uint8_t *buf,
        gtp_s103_pdn_data_fwdng_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->hsgw_addr_fwdng_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->hsgw_addr_fwdng = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->gre_key = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->eps_bearer_id_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_fully_qual_domain_name_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_fully_qual_domain_name_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fully_qual_domain_name_ie(uint8_t *buf,
        gtp_fully_qual_domain_name_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->fqdn, buf + (total_decoded/CHAR_SIZE), value->header.len);
    total_decoded +=  value->header.len * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_traffic_agg_desc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_traffic_agg_desc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_traffic_agg_desc_ie(uint8_t *buf,
        gtp_traffic_agg_desc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->traffic_agg_desc = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_flow_qlty_of_svc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_flow_qlty_of_svc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_flow_qlty_of_svc_ie(uint8_t *buf,
        gtp_flow_qlty_of_svc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->qci = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->max_bit_rate_uplnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->max_bit_rate_dnlnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->guarntd_bit_rate_uplnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->guarntd_bit_rate_dnlnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_fully_qual_tunn_endpt_idnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_fully_qual_tunn_endpt_idnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fully_qual_tunn_endpt_idnt_ie(uint8_t *buf,
        gtp_fully_qual_tunn_endpt_idnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->v4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->v6 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->interface_type = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->teid_gre_key = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    if (value->v4 == 1) {
    value->ipv4_address = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    }
    if (value->v6 == 1) {
    	memcpy(&value->ipv6_address, buf + (total_decoded/CHAR_SIZE), IPV6_ADDRESS_LEN);
    	total_decoded +=  IPV6_ADDRESS_LEN * CHAR_SIZE;
    }
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_recovery_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_recovery_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_recovery_ie(uint8_t *buf,
        gtp_recovery_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->recovery = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_srvng_plmn_rate_ctl_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_srvng_plmn_rate_ctl_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_srvng_plmn_rate_ctl_ie(uint8_t *buf,
        gtp_srvng_plmn_rate_ctl_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->uplnk_rate_lmt = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->dnlnk_rate_lmt = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_dist_ack_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_dist_ack_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_dist_ack_ie(uint8_t *buf,
        gtp_mbms_dist_ack_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->distr_ind = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ue_time_zone_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ue_time_zone_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ue_time_zone_ie(uint8_t *buf,
        gtp_ue_time_zone_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->time_zone = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->daylt_svng_time = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_s1u_data_fwdng_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_s1u_data_fwdng_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_s1u_data_fwdng_ie(uint8_t *buf,
        gtp_s1u_data_fwdng_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sgw_addr_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sgw_address = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sgw_s1u_teid = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_pres_rptng_area_act_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pres_rptng_area_act_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pres_rptng_area_act_ie(uint8_t *buf,
        gtp_pres_rptng_area_act_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->inapra = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->action = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->pres_rptng_area_idnt = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->number_of_tai = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->number_of_rai = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->nbr_of_macro_enb = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->nbr_of_home_enb = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->spare5 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->number_of_ecgi = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->spare6 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->number_of_sai = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->spare7 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->number_of_cgi = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->tais = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->macro_enb_ids = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->home_enb_ids = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecgis = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rais = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sais = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->cgis = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare8 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->nbr_of_extnded_macro_enb = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->extnded_macro_enb_ids = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_trstd_wlan_mode_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_trstd_wlan_mode_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_trstd_wlan_mode_indctn_ie(uint8_t *buf,
        gtp_trstd_wlan_mode_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->mcm = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->scm = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_proc_trans_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_proc_trans_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_proc_trans_id_ie(uint8_t *buf,
        gtp_proc_trans_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->proc_trans_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_wlan_offldblty_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_wlan_offldblty_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_wlan_offldblty_indctn_ie(uint8_t *buf,
        gtp_wlan_offldblty_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->eutran_indctn = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->utran_indctn = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_uli_timestamp_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_uli_timestamp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_uli_timestamp_ie(uint8_t *buf,
        gtp_uli_timestamp_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->uli_ts_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_max_pckt_loss_rate_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_max_pckt_loss_rate_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_max_pckt_loss_rate_ie(uint8_t *buf,
        gtp_max_pckt_loss_rate_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->dl = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ul = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->max_pckt_loss_rate_ul = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->max_pckt_loss_rate_dl = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_cn_oper_sel_entity_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_cn_oper_sel_entity_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_cn_oper_sel_entity_ie(uint8_t *buf,
        gtp_cn_oper_sel_entity_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->sel_entity = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes rai_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    rai_field_t
* @return
*   number of decoded bytes.
*/
int decode_rai_field(uint8_t *buf,
        rai_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->ria_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ria_lac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->ria_rac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_alloc_reten_priority_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_alloc_reten_priority_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_alloc_reten_priority_ie(uint8_t *buf,
        gtp_alloc_reten_priority_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pci = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pl = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pvi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_apn_restriction_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_apn_restriction_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_apn_restriction_ie(uint8_t *buf,
        gtp_apn_restriction_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rstrct_type_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes sai_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    sai_field_t
* @return
*   number of decoded bytes.
*/
int decode_sai_field(uint8_t *buf,
        sai_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->sai_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->sai_lac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->sai_sac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes trgt_id_type_extnded_macro_ng_enb_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_extnded_macro_ng_enb_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_extnded_macro_ng_enb(uint8_t *buf,
        trgt_id_type_extnded_macro_ng_enb_t *value)
{
    uint16_t total_decoded = 0;
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
    value->smenb = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->extnded_macro_ng_enb_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->fivegs_tac = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_ptmsi_signature_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ptmsi_signature_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ptmsi_signature_ie(uint8_t *buf,
        gtp_ptmsi_signature_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ptmsi_signature = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_paging_and_svc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_paging_and_svc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_paging_and_svc_info_ie(uint8_t *buf,
        gtp_paging_and_svc_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ebi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->ppi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->paging_plcy_indctn_val = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ovrld_ctl_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ovrld_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ovrld_ctl_info_ie(uint8_t *buf,
        gtp_ovrld_ctl_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->overload_control_information, buf + (total_decoded/CHAR_SIZE), OVERLOAD_CONTROL_INFORMATION_LEN);
    total_decoded +=  OVERLOAD_CONTROL_INFORMATION_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ecgi_list_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ecgi_list_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ecgi_list_ie(uint8_t *buf,
        gtp_ecgi_list_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->nbr_of_ecgi_flds = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->ecgi_list_of_m_ecgi_flds = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_agg_max_bit_rate_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_agg_max_bit_rate_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_agg_max_bit_rate_ie(uint8_t *buf,
        gtp_agg_max_bit_rate_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->apn_ambr_uplnk = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->apn_ambr_dnlnk = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes tai_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    tai_field_t
* @return
*   number of decoded bytes.
*/
int decode_tai_field(uint8_t *buf,
        tai_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->tai_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->tai_tac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_acc_pt_name_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_acc_pt_name_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_acc_pt_name_ie(uint8_t *buf,
        gtp_acc_pt_name_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->apn, buf + (total_decoded/CHAR_SIZE),  value->header.len);
    total_decoded +=   value->header.len * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes bss_container_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    bss_container_t
* @return
*   number of decoded bytes.
*/
int decode_bss_container(uint8_t *buf,
        bss_container_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->phx = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sapi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->rp = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pfi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sapi2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->radio_priority = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->xid_parms_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->xid_parameters = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes trgt_id_type_gnode_id_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_gnode_id_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_gnode_id(uint8_t *buf,
        trgt_id_type_gnode_id_t *value)
{
    uint16_t total_decoded = 0;
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
    value->spare = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->gnb_id_len = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->gnodeb_id = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->fivegs_tac = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_umts_key_quadruplets_and_quintuplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_umts_key_quadruplets_and_quintuplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_quadruplets_and_quintuplets_ie(uint8_t *buf,
        gtp_umts_key_quadruplets_and_quintuplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ksiasme = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quintuplets = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quadruplet = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
    total_decoded +=  CK_LEN * CHAR_SIZE;
    memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
    total_decoded +=  IK_LEN * CHAR_SIZE;
    value->auth_quadruplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->auth_quintuplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_cmplt_req_msg_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_cmplt_req_msg_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_cmplt_req_msg_ie(uint8_t *buf,
        gtp_cmplt_req_msg_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->cmplt_req_msg_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->cmplt_req_msg = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_epc_timer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_epc_timer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_epc_timer_ie(uint8_t *buf,
        gtp_epc_timer_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->timer_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->timer_value = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_csg_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_csg_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_id_ie(uint8_t *buf,
        gtp_csg_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->csg_id_spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->csg_id_csg_id = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->csg_id_csg_id2 = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes trgt_id_type_extnded_macro_enb_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_extnded_macro_enb_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_extnded_macro_enb(uint8_t *buf,
        trgt_id_type_extnded_macro_enb_t *value)
{
    uint16_t total_decoded = 0;
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
    value->smenb = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->extnded_macro_enb_id_field2 = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->tac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_packet_flow_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_packet_flow_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_packet_flow_id_ie(uint8_t *buf,
        gtp_packet_flow_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->packet_flow_id_spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->packet_flow_id_ebi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->packet_flow_id_packet_flow_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_tmgi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_tmgi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_tmgi_ie(uint8_t *buf,
        gtp_tmgi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->tmgi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mntrng_evnt_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mntrng_evnt_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mntrng_evnt_info_ie(uint8_t *buf,
        gtp_mntrng_evnt_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->scef_ref_id = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->scef_id_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->scef_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rem_nbr_of_rpts = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_rmt_ue_ip_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_rmt_ue_ip_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_ip_info_ie(uint8_t *buf,
        gtp_rmt_ue_ip_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rmt_ue_ip_info = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes ecgi_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    ecgi_field_t
* @return
*   number of decoded bytes.
*/
int decode_ecgi_field(uint8_t *buf,
        ecgi_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->ecgi_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ecgi_spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->eci = decode_bits(buf, total_decoded, 28, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_bearer_qlty_of_svc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_bearer_qlty_of_svc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_qlty_of_svc_ie(uint8_t *buf,
        gtp_bearer_qlty_of_svc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pci = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pl = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->pvi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->qci = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->max_bit_rate_uplnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->max_bit_rate_dnlnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->guarntd_bit_rate_uplnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    value->guarntd_bit_rate_dnlnk = decode_bits(buf, total_decoded, 40, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mapped_ue_usage_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mapped_ue_usage_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mapped_ue_usage_type_ie(uint8_t *buf,
        gtp_mapped_ue_usage_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mapped_ue_usage_type = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_svc_indctr_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_svc_indctr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_svc_indctr_ie(uint8_t *buf,
        gtp_svc_indctr_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->svc_indctr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_umts_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_umts_key_used_cipher_and_quintuplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_umts_key_used_cipher_and_quintuplets_ie(uint8_t *buf,
        gtp_umts_key_used_cipher_and_quintuplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cksnksi = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quintuplets = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->iovi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gupii = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ugipai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->used_gprs_intgrty_protctn_algo = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    memcpy(&value->ck, buf + (total_decoded/CHAR_SIZE), CK_LEN);
    total_decoded +=  CK_LEN * CHAR_SIZE;
    memcpy(&value->ik, buf + (total_decoded/CHAR_SIZE), IK_LEN);
    total_decoded +=  IK_LEN * CHAR_SIZE;
    value->auth_quintuplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->iov_updts_cntr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes auth_triplet_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    auth_triplet_t
* @return
*   number of decoded bytes.
*/
int decode_auth_triplet(uint8_t *buf,
        auth_triplet_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    memcpy(&value->rand, buf + (total_decoded/CHAR_SIZE), RAND_LEN);
    total_decoded +=  RAND_LEN * CHAR_SIZE;
    value->sres = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->kc = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_local_distgsd_name_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_local_distgsd_name_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_local_distgsd_name_ie(uint8_t *buf,
        gtp_local_distgsd_name_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ldn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_csg_info_rptng_act_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_csg_info_rptng_act_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_info_rptng_act_ie(uint8_t *buf,
        gtp_csg_info_rptng_act_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->uciuhc = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ucishc = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ucicsg = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_secdry_rat_usage_data_rpt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_secdry_rat_usage_data_rpt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_secdry_rat_usage_data_rpt_ie(uint8_t *buf,
        gtp_secdry_rat_usage_data_rpt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->irsgw = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->irpgw = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->secdry_rat_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->ebi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->start_timestamp = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->end_timestamp = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->usage_data_dl = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->usage_data_ul = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_rat_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_rat_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rat_type_ie(uint8_t *buf,
        gtp_rat_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rat_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes trgt_id_type_macro_enb_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_macro_enb_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_macro_enb(uint8_t *buf,
        trgt_id_type_macro_enb_t *value)
{
    uint16_t total_decoded = 0;
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
    value->spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->macro_enb_id_field2 = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->tac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_global_cn_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_global_cn_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_global_cn_id_ie(uint8_t *buf,
        gtp_global_cn_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    value->cn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_charging_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_charging_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_charging_id_ie(uint8_t *buf,
        gtp_charging_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->chrgng_id_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_counter_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_counter_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_counter_ie(uint8_t *buf,
        gtp_counter_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->timestamp_value = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->counter_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_serving_network_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_serving_network_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_serving_network_ie(uint8_t *buf,
        gtp_serving_network_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_node_identifier_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_node_identifier_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_identifier_ie(uint8_t *buf,
        gtp_node_identifier_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->len_of_node_name = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->node_name = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_node_realm = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->node_realm = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes extnded_macro_enb_id_fld_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    extnded_macro_enb_id_fld_t
* @return
*   number of decoded bytes.
*/
int decode_extnded_macro_enb_id_fld(uint8_t *buf,
        extnded_macro_enb_id_fld_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->emenbid_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->emenbid_smenb = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->emenbid_spare = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->emenbid_extnded_macro_enb_id = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->emenbid_extnded_macro_enb_id2 = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
	return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_trc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_trc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_trc_info_ie(uint8_t *buf,
        gtp_trc_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    memcpy(&value->trigrng_evnts, buf + (total_decoded/CHAR_SIZE), TRIGRNG_EVNTS_LEN);
    total_decoded +=  TRIGRNG_EVNTS_LEN * CHAR_SIZE;
    value->list_of_ne_types = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->sess_trc_depth = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->list_of_intfcs, buf + (total_decoded/CHAR_SIZE), LIST_OF_INTFCS_LEN);
    total_decoded +=  LIST_OF_INTFCS_LEN * CHAR_SIZE;
    value->ip_addr_of_trc_coll_entity = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_ip_multcst_dist_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_ip_multcst_dist_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_ip_multcst_dist_ie(uint8_t *buf,
        gtp_mbms_ip_multcst_dist_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->cmn_tunn_endpt_idnt = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->address_type = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->address_length = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->ip_multcst_dist_addr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->address_type2 = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->address_length2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->ip_multcst_src_addr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mbms_hc_indctr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_full_qual_cntnr_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_full_qual_cntnr_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_full_qual_cntnr_ie(uint8_t *buf,
        gtp_full_qual_cntnr_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->container_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->fcontainer_fld = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_data_xfer_abs_time_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_data_xfer_abs_time_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_data_xfer_abs_time_ie(uint8_t *buf,
        gtp_mbms_data_xfer_abs_time_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_data_xfer_abs_time_val_prt = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes auth_quadruplet_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    auth_quadruplet_t
* @return
*   number of decoded bytes.
*/
int decode_auth_quadruplet(uint8_t *buf,
        auth_quadruplet_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    memcpy(&value->rand, buf + (total_decoded/CHAR_SIZE), RAND_LEN);
    total_decoded +=  RAND_LEN * CHAR_SIZE;
    value->xres_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->xres = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->autn_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->autn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->kasme, buf + (total_decoded/CHAR_SIZE), KASME_LEN);
    total_decoded +=  KASME_LEN * CHAR_SIZE;
    return total_decoded;
}

/**
* decodes gtp_gsm_key_used_cipher_and_quintuplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_gsm_key_used_cipher_and_quintuplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_gsm_key_used_cipher_and_quintuplets_ie(uint8_t *buf,
        gtp_gsm_key_used_cipher_and_quintuplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cksnksi = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_quintuplets = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->kc = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    value->auth_quintuplets = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->higher_bitrates_flg = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_twan_idnt_ts_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_twan_idnt_ts_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_twan_idnt_ts_ie(uint8_t *buf,
        gtp_twan_idnt_ts_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->twan_idnt_ts_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_tmsi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_tmsi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_tmsi_ie(uint8_t *buf,
        gtp_tmsi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->tmsi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_pdn_addr_alloc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pdn_addr_alloc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_addr_alloc_ie(uint8_t *buf,
        gtp_pdn_addr_alloc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->pdn_type = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    memcpy(&value->pdn_addr_and_pfx, buf + (total_decoded/CHAR_SIZE),  value->header.len - 1);
    total_decoded +=  ( value->header.len - 1) * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_twan_identifier_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_twan_identifier_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_twan_identifier_ie(uint8_t *buf,
        gtp_twan_identifier_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->laii = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->opnai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->plmni = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->civai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->bssidi = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->ssid_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ssid = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->bssid = decode_bits(buf, total_decoded, 48, &decoded);
    total_decoded += decoded;
    value->civic_addr_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->civic_addr_info = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->twan_plmn_id = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->twan_oper_name_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->twan_oper_name = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rly_idnty_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rly_idnty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->relay_identity = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->circuit_id_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->circuit_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes cgi_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    cgi_field_t
* @return
*   number of decoded bytes.
*/
int decode_cgi_field(uint8_t *buf,
        cgi_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->cgi_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cgi_lac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->cgi_ci = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_user_loc_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_user_loc_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_user_loc_info_ie(uint8_t *buf,
        gtp_user_loc_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->extnded_macro_enb_id = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->macro_enodeb_id = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->lai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ecgi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->tai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->rai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sai = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cgi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    // total_decoded += decode_cgi_field(buf + total_decoded, &value->cgi2);
    // total_decoded += decode_sai_field(buf + total_decoded, &value->sai2);
    // total_decoded += decode_rai_field(buf + total_decoded, &value->rai2);
    // total_decoded += decode_tai_field(buf + total_decoded, &value->tai2);
    // total_decoded += decode_ecgi_field(buf + total_decoded, &value->ecgi2);
    // total_decoded += decode_lai_field(buf + total_decoded, &value->lai2);
    // total_decoded += decode_macro_enb_id_fld(buf + total_decoded, &value->macro_enodeb_id2);
    // total_decoded += decode_extnded_macro_enb_id_fld(buf + total_decoded, &value->extended_macro_enodeb_id2);
    /* TODO: Revisit this for change in yang */
	total_decoded = total_decoded/CHAR_SIZE;
    if (value->cgi) {
        total_decoded += decode_cgi_field(buf + total_decoded, &value->cgi2);
    }
    if (value->sai) {
        total_decoded += decode_sai_field(buf + total_decoded, &value->sai2);
    }
    if (value->rai) {
        total_decoded += decode_rai_field(buf + total_decoded, &value->rai2);
    }
    if (value->tai) {
        total_decoded += decode_tai_field(buf + total_decoded, &value->tai2);
    }
    if (value->ecgi) {
        total_decoded += decode_ecgi_field(buf + total_decoded, &value->ecgi2);
    }
    if (value->lai) {
        total_decoded += decode_lai_field(buf + total_decoded, &value->lai2);
    }
    if (value->macro_enodeb_id) {
        total_decoded += decode_macro_enb_id_fld(buf + total_decoded, &value->macro_enodeb_id2);
    }
    if (value->extnded_macro_enb_id) {
        total_decoded += decode_extnded_macro_enb_id_fld(buf + total_decoded, &value->extended_macro_enodeb_id2);
    }
    return total_decoded;
}

/**
* decodes gtp_ptmsi_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ptmsi_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ptmsi_ie(uint8_t *buf,
        gtp_ptmsi_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ptmsi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_node_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_node_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_type_ie(uint8_t *buf,
        gtp_node_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->node_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_user_csg_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_user_csg_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_user_csg_info_ie(uint8_t *buf,
        gtp_user_csg_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->csg_id2 = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->access_mode = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lcsg = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cmi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_integer_number_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_integer_number_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_integer_number_ie(uint8_t *buf,
        gtp_integer_number_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->int_nbr_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_sess_dur_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_sess_dur_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_sess_dur_ie(uint8_t *buf,
        gtp_mbms_sess_dur_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_sess_dur = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_msisdn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_msisdn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_msisdn_ie(uint8_t *buf,
        gtp_msisdn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    // value->msisdn_number_digits = decode_bits(buf, total_decoded, 64, &decoded);
    // total_decoded += decoded;
    memcpy(&value->msisdn_number_digits, (uint8_t *)buf + total_decoded/CHAR_SIZE, value->header.len);
    total_decoded += value->header.len * CHAR_SIZE;

    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_metric_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_metric_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_metric_ie(uint8_t *buf,
        gtp_metric_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->metric = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_bearer_context_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_bearer_context_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_context_ie(uint8_t *buf,
        gtp_bearer_context_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->bearer_context, buf + (total_decoded/CHAR_SIZE), BEARER_CONTEXT_LEN);
    total_decoded +=  BEARER_CONTEXT_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ciot_optim_supp_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ciot_optim_supp_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ciot_optim_supp_indctn_ie(uint8_t *buf,
        gtp_ciot_optim_supp_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare5 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ihcsi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->awopdn = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->scnipdn = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sgnipdn = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_pdu_numbers_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pdu_numbers_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdu_numbers_ie(uint8_t *buf,
        gtp_pdu_numbers_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->dl_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ul_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->snd_npdu_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->rcv_npdu_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_rab_context_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_rab_context_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rab_context_ie(uint8_t *buf,
        gtp_rab_context_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->nsapi = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->dl_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->ul_gtpu_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->dl_pdcp_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->ul_pdcp_seqn_nbr = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_addtl_flgs_srvcc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_addtl_flgs_srvcc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_flgs_srvcc_ie(uint8_t *buf,
        gtp_addtl_flgs_srvcc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->vf = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ics = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_gsm_key_and_triplets_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_gsm_key_and_triplets_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_gsm_key_and_triplets_ie(uint8_t *buf,
        gtp_gsm_key_and_triplets_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->security_mode = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->drxi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cksn = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->nbr_of_triplet = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->spare3 = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->uambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sambri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->spare4 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->used_cipher = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->kc = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    value->auth_triplet = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->drx_parameter = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->uplnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_subscrbd_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->uplnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->dnlnk_used_ue_ambr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ue_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_ntwk_capblty = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->mei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ecna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->nbna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->hnna = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ina = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gana = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->gena = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->una = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vdom_pref_ue_usage_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->voice_domain_pref_and_ues_usage_setting = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_node_number_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_node_number_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_number_ie(uint8_t *buf,
        gtp_node_number_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->len_of_node_nbr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->node_number = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_load_ctl_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_load_ctl_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_load_ctl_info_ie(uint8_t *buf,
        gtp_load_ctl_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->load_control_information, buf + (total_decoded/CHAR_SIZE), LOAD_CONTROL_INFORMATION_LEN);
    total_decoded +=  LOAD_CONTROL_INFORMATION_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_rmt_ue_ctxt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_rmt_ue_ctxt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_ctxt_ie(uint8_t *buf,
        gtp_rmt_ue_ctxt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->remote_ue_context, buf + (total_decoded/CHAR_SIZE), REMOTE_UE_CONTEXT_LEN);
    total_decoded +=  REMOTE_UE_CONTEXT_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_full_qual_cause_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_full_qual_cause_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_full_qual_cause_ie(uint8_t *buf,
        gtp_full_qual_cause_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->cause_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->fcause_field = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_indication_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_indication_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_indication_ie(uint8_t *buf,
		gtp_indication_ie_t *value)
{
	uint16_t total_decoded = 0;
	total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
	uint16_t decoded = 0;
	uint8_t indic_len = value->header.len;

	if(indic_len == INDICATION_OCT_5 || indic_len > INDICATION_OCT_5)
	{
		value->indication_daf = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_dtf = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_hi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_dfi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_oi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_isrsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_israi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_sgwci = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_6 || indic_len > INDICATION_OCT_6)
	{
		value->indication_sqci = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_uimsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_cfsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_crsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_p = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_pt = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_si = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_msv = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_7 || indic_len > INDICATION_OCT_7)
	{
		value->indication_retloc = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_pbic = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_srni = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_s6af = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_s4af = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_mbmdt = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_israu = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ccrsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_8 || indic_len > INDICATION_OCT_8)
	{
		value->indication_cprai = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_arrl = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ppof = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ppon_ppei = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ppsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_csfbi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_clii = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_cpsr = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_9 || indic_len > INDICATION_OCT_9)
	{
		value->indication_nsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_uasi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_dtci = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_bdwi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_psci = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_pcri = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_aosi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_aopi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_10 || indic_len > INDICATION_OCT_10)
	{
		value->indication_roaai = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_epcosi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_cpopci = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_pmtsmi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_s11tf = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_pnsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_unaccsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_wpmsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	if(indic_len == INDICATION_OCT_11)
	{
		value->indication_spare2 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_spare3 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_spare4 = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_eevrsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ltemui = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_ltempi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_enbcrsi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
		value->indication_tspcmi = decode_bits(buf, total_decoded, 1, &decoded);
		total_decoded += decoded;
	}

	return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ipv4_cfg_parms_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ipv4_cfg_parms_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ipv4_cfg_parms_ie(uint8_t *buf,
        gtp_ipv4_cfg_parms_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->subnet_pfx_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ipv4_dflt_rtr_addr = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_trace_reference_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_trace_reference_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_trace_reference_ie(uint8_t *buf,
        gtp_trace_reference_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
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
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_node_features_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_node_features_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_node_features_ie(uint8_t *buf,
        gtp_node_features_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->sup_feat = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_remote_user_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_remote_user_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_remote_user_id_ie(uint8_t *buf,
        gtp_remote_user_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->imeif = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->msisdnf = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->length_of_imsi = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->len_of_msisdn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->length_of_imei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->imei = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_fqcsid_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_fqcsid_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_fqcsid_ie(uint8_t *buf,
        gtp_fqcsid_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->node_id_type = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->number_of_csids = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->node_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    memcpy(&value->pdn_csid, buf + (total_decoded/CHAR_SIZE), PDN_CSID_LEN);
    total_decoded +=  PDN_CSID_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_port_number_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_port_number_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_port_number_ie(uint8_t *buf,
        gtp_port_number_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->port_number = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_addtl_mm_ctxt_srvcc_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_addtl_mm_ctxt_srvcc_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_mm_ctxt_srvcc_ie(uint8_t *buf,
        gtp_addtl_mm_ctxt_srvcc_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ms_classmark_2_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_classmark_2 = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_classmark_3_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->ms_classmark_3 = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sup_codec_list_len = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->sup_codec_list = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_act_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_act_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_act_indctn_ie(uint8_t *buf,
        gtp_act_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_plmn_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_plmn_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_plmn_id_ie(uint8_t *buf,
        gtp_plmn_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_flow_idnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_flow_idnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_flow_idnt_ie(uint8_t *buf,
        gtp_mbms_flow_idnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_flow_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_hdr_comp_cfg_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_hdr_comp_cfg_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_hdr_comp_cfg_ie(uint8_t *buf,
        gtp_hdr_comp_cfg_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rohc_profiles = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->max_cid = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_sgnllng_priority_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_sgnllng_priority_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_sgnllng_priority_indctn_ie(uint8_t *buf,
        gtp_sgnllng_priority_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->lapi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_cause_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_cause_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_cause_ie(uint8_t *buf,
        gtp_cause_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->cause_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->pce = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->bce = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->cs = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    if (value->header.len != 2){
        value->offend_ie_type = decode_bits(buf, total_decoded, 8, &decoded);
        total_decoded += decoded;
        value->offend_ie_len = decode_bits(buf, total_decoded, 16, &decoded);
        total_decoded += decoded;
        value->spareinstance = decode_bits(buf, total_decoded, 8, &decoded);
        total_decoded += decoded;
    }
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_time_to_data_xfer_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_time_to_data_xfer_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_time_to_data_xfer_ie(uint8_t *buf,
        gtp_mbms_time_to_data_xfer_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_time_to_data_xfer_val_prt = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_addtl_prot_cfg_opts_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_addtl_prot_cfg_opts_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_addtl_prot_cfg_opts_ie(uint8_t *buf,
        gtp_addtl_prot_cfg_opts_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->apco = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_trgt_id_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_trgt_id_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_trgt_id_ie(uint8_t *buf,
        gtp_trgt_id_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->target_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->target_id = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_flags_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_flags_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_flags_ie(uint8_t *buf,
        gtp_mbms_flags_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->lmri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->msri = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_trans_idnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_trans_idnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_trans_idnt_ie(uint8_t *buf,
        gtp_trans_idnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->trans_idnt = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes trgt_id_type_home_enb_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    trgt_id_type_home_enb_t
* @return
*   number of decoded bytes.
*/
int decode_trgt_id_type_home_enb(uint8_t *buf,
        trgt_id_type_home_enb_t *value)
{
    uint16_t total_decoded = 0;
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
    value->spare = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->home_enodeb_id = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->home_enodeb_id2 = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->tac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded;
}

/**
* decodes gtp_bearer_flags_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_bearer_flags_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_flags_ie(uint8_t *buf,
        gtp_bearer_flags_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->asi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vind = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->vb = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ppc = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes lai_field_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    lai_field_t
* @return
*   number of decoded bytes.
*/
int decode_lai_field(uint8_t *buf,
        lai_field_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    value->lai_mcc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_mcc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_mnc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_mcc_digit_3 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_mnc_digit_2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_mnc_digit_1 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->lai_lac = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_msec_time_stmp_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_msec_time_stmp_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_msec_time_stmp_ie(uint8_t *buf,
        gtp_msec_time_stmp_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->msec_time_stmp_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_chg_to_rpt_flgs_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_chg_to_rpt_flgs_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_chg_to_rpt_flgs_ie(uint8_t *buf,
        gtp_chg_to_rpt_flgs_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->tzcr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->sncr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_scef_pdn_conn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_scef_pdn_conn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_scef_pdn_conn_ie(uint8_t *buf,
        gtp_scef_pdn_conn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    memcpy(&value->scef_pdn_connection, buf + (total_decoded/CHAR_SIZE), SCEF_PDN_CONNECTION_LEN);
    total_decoded +=  SCEF_PDN_CONNECTION_LEN * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_chg_rptng_act_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_chg_rptng_act_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_chg_rptng_act_ie(uint8_t *buf,
        gtp_chg_rptng_act_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->action = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_extnded_prot_cfg_opts_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_extnded_prot_cfg_opts_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_extnded_prot_cfg_opts_ie(uint8_t *buf,
        gtp_extnded_prot_cfg_opts_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->epco = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_delay_value_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_delay_value_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_delay_value_ie(uint8_t *buf,
        gtp_delay_value_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->delay_value = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_pdn_connection_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pdn_connection_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pdn_connection_ie(uint8_t *buf,
        gtp_pdn_connection_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_detach_type_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_detach_type_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_detach_type_ie(uint8_t *buf,
        gtp_detach_type_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->detach_type = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_svc_area_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_svc_area_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_svc_area_ie(uint8_t *buf,
        gtp_mbms_svc_area_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_svc_area = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_chrgng_char_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_chrgng_char_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_chrgng_char_ie(uint8_t *buf,
        gtp_chrgng_char_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->chrgng_char_val = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_henb_info_rptng_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_henb_info_rptng_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_henb_info_rptng_ie(uint8_t *buf,
        gtp_henb_info_rptng_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->fti = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes mm_context_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    mm_context_t
* @return
*   number of decoded bytes.
*/
int decode_mm_context(uint8_t *buf,
        mm_context_t *value)
{
    uint16_t total_decoded = 0;
    uint16_t decoded = 0;
    return total_decoded;
}

/**
* decodes gtp_throttling_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_throttling_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_throttling_ie(uint8_t *buf,
        gtp_throttling_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->thrtlng_delay_unit = decode_bits(buf, total_decoded, 3, &decoded);
    total_decoded += decoded;
    value->thrtlng_delay_val = decode_bits(buf, total_decoded, 5, &decoded);
    total_decoded += decoded;
    value->thrtlng_factor = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_csg_memb_indctn_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_csg_memb_indctn_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_csg_memb_indctn_ie(uint8_t *buf,
        gtp_csg_memb_indctn_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->csg_memb_indctn_spare2 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->csg_memb_indctn_cmi = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_ip_address_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_ip_address_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_ip_address_ie(uint8_t *buf,
        gtp_ip_address_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->ipv4_ipv6_addr = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_src_rnc_pdcp_ctxt_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_src_rnc_pdcp_ctxt_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_src_rnc_pdcp_ctxt_info_ie(uint8_t *buf,
        gtp_src_rnc_pdcp_ctxt_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rrc_container = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_hop_counter_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_hop_counter_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_hop_counter_ie(uint8_t *buf,
        gtp_hop_counter_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->hop_counter = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_pres_rptng_area_info_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_pres_rptng_area_info_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_pres_rptng_area_info_ie(uint8_t *buf,
        gtp_pres_rptng_area_info_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->pra_identifier = decode_bits(buf, total_decoded, 24, &decoded);
    total_decoded += decoded;
    value->spare2 = decode_bits(buf, total_decoded, 4, &decoded);
    total_decoded += decoded;
    value->inapra = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    value->apra = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->opra = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    value->ipra = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbms_sess_idnt_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbms_sess_idnt_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbms_sess_idnt_ie(uint8_t *buf,
        gtp_mbms_sess_idnt_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mbms_sess_idnt = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_apn_and_rltv_cap_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_apn_and_rltv_cap_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_apn_and_rltv_cap_ie(uint8_t *buf,
        gtp_apn_and_rltv_cap_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->rltv_cap = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->apn_length = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    value->apn = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_selection_mode_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_selection_mode_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_selection_mode_ie(uint8_t *buf,
        gtp_selection_mode_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 6, &decoded);
    total_decoded += decoded;
    value->selec_mode = decode_bits(buf, total_decoded, 2, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_up_func_sel_indctn_flgs_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_up_func_sel_indctn_flgs_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_up_func_sel_indctn_flgs_ie(uint8_t *buf,
        gtp_up_func_sel_indctn_flgs_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->spare2 = decode_bits(buf, total_decoded, 7, &decoded);
    total_decoded += decoded;
    value->dcnr = decode_bits(buf, total_decoded, 1, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_mbl_equip_idnty_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_mbl_equip_idnty_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_mbl_equip_idnty_ie(uint8_t *buf,
        gtp_mbl_equip_idnty_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->mei = decode_bits(buf, total_decoded, 64, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_priv_ext_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_priv_ext_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_priv_ext_ie(uint8_t *buf,
        gtp_priv_ext_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->enterprise_id = decode_bits(buf, total_decoded, 16, &decoded);
    total_decoded += decoded;
    value->prop_val = decode_bits(buf, total_decoded, 8, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_eps_bearer_lvl_traffic_flow_tmpl_ie(uint8_t *buf,
        gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    /* value->eps_bearer_lvl_tft = decode_bits(buf, total_decoded, 8, &decoded); */
    memcpy(&value->eps_bearer_lvl_tft, buf + (total_decoded/CHAR_SIZE), value->header.len);
    total_decoded +=  value->header.len * CHAR_SIZE;
    return total_decoded/CHAR_SIZE;
}

/**
* decodes gtp_sequence_number_ie_t to buffer.
* @param buf
* buffer to store decoded values.
* @param value
    gtp_sequence_number_ie_t
* @return
*   number of decoded bytes.
*/
int decode_gtp_sequence_number_ie(uint8_t *buf,
        gtp_sequence_number_ie_t *value)
{
    uint16_t total_decoded = 0;
    total_decoded += decode_ie_header_t(buf, &(value->header), IE_HEADER_SIZE);
    uint16_t decoded = 0;
    value->sequence_number = decode_bits(buf, total_decoded, 32, &decoded);
    total_decoded += decoded;
    return total_decoded/CHAR_SIZE;
}

