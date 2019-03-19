/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "req_resp.h"
#include "util.h"
#include "gtpv2c_messages.h"

/**
 * Encodes uint8_t value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uint8_t(uint8_t val, gtpv2c_buffer_t *buf)
{
	gtpv2c_buf_memcpy(buf, &val, sizeof(uint8_t));
	return sizeof(uint8_t);
}

/**
 * Encodes uint16_t value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uint16_t(uint16_t val, gtpv2c_buffer_t *buf)
{
	val = htons(val);
	gtpv2c_buf_memcpy(buf, &val, sizeof(uint16_t));
	return sizeof(uint16_t);
}

/**
 * Encodes uint32_t value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uint32_t(uint32_t val, gtpv2c_buffer_t *buf)
{
	val = htonl(val);
	gtpv2c_buf_memcpy(buf, &val, sizeof(uint32_t));

	return sizeof(uint32_t);
}

/**
 * Encodes seq number value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uint32_t_seq_no(uint32_t val, gtpv2c_buffer_t *buf)
{
	uint8_t tmp[4];
	tmp[0] = (val >> 16) & 0xff;
	tmp[1] = (val >> 8) & 0xff;
	tmp[2] = val & 0xff;
	tmp[3] = 0;
	gtpv2c_buf_memcpy(buf, &tmp, sizeof(uint32_t));
	return sizeof(uint32_t);
}

/**
 * Encodes mbr value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uint64_t_mbr(uint64_t *val, gtpv2c_buffer_t *buf)
{
	uint8_t tmp[MBR_BUF_SIZE];
	tmp[0] = (*val >> 32) & 0xff;
	tmp[1] = (*val >> 24) & 0xff;
	tmp[2] = (*val >> 16) & 0xff;
	tmp[3] = (*val >> 8) & 0Xff;
	tmp[4] = (*val & 0Xff);

	gtpv2c_buf_memcpy(buf, tmp, MBR_BUF_SIZE);

	return MBR_BUF_SIZE;
}

/**
 * Encodes uint8_t array value to buffer.
 * @param val
 *   value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_common_type(void *val, gtpv2c_buffer_t *buf, uint16_t val_len)
{
	gtpv2c_buf_memcpy(buf, val, val_len);
	return val_len;
}

/**
 * Encodes gtpv2c header to buffer.
 * @param val
 *   gtpv2c header value to be encoded
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_gtpv2c_header_t(gtpv2c_header_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	val->gtpc.message_len = htons(val->gtpc.message_len);
	gtpv2c_buf_memcpy(buf, &val->gtpc, sizeof(val->gtpc));
	val->gtpc.message_len = ntohs(val->gtpc.message_len);


	if (val->gtpc.teid_flag) {
		encode_uint32_t(val->teid.has_teid.teid, buf);
		encode_uint32_t_seq_no(val->teid.has_teid.seq, buf);
		enc_len = GTPV2C_HEADER_LEN;
	} else {
		encode_uint32_t_seq_no(val->teid.has_teid.seq, buf);
		enc_len = GTPV2C_HEADER_LEN - sizeof(uint32_t);
	}

	return enc_len;
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
static int
encode_ie_header_t(ie_header_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_uint8_t(val->type, buf);
	enc_len += encode_uint16_t(val->len, buf);
	enc_len += encode_uint8_t(val->instance, buf);
	return enc_len;
}

/**
 * Encodes imsi to buffer.
 * @param val
 *   imsi value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_imsi_ie_t(imsi_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;
	enc_len += encode_ie_header_t(&val->header, buf);

	/* TODO : Covert IMSI to tbcd format */
	enc_len += encode_common_type(&val->imsi, buf, val->header.len);
	return enc_len;
}

/**
 * Encodes msisdn to buffer.
 * @param val
 *   msisdn value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_msisdn_ie_t(msisdn_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;
	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_common_type(&val->msisdn, buf, val->header.len);
	return enc_len;
}

/**
 * Encodes mei to buffer.
 * @param val
 *   mei value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_mei_ie_t(mei_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;
	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_common_type(&val->mei, buf, val->header.len);
	return enc_len;
}

/**
 * Encodes mcc-mnc to buffer.
 * @param val
 *   mcc-mnc value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_mcc_mnc_t(mcc_mnc_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;
	uint8_t tmp[MNC_MCC_BUF_SIZE] = {0};

	tmp[0] = val->mcc_digit_2 << 4 | val->mcc_digit_1;
	tmp[1] = val->mnc_digit_3 << 4 | val->mcc_digit_3;
	tmp[2] = val->mnc_digit_2 << 4 | val->mnc_digit_1;

	enc_len += encode_common_type(tmp, buf, MNC_MCC_BUF_SIZE);
	return enc_len;
}

/**
 * Encodes uli flags to buffer.
 * @param val
 *   uli flags value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uli_flags_t(uli_flags_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_common_type(val, buf, sizeof(*val));
	return enc_len;
}

/**
 * Encodes ecgi to buffer.
 * @param val
 *   ecgi value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_ecgi_t(ecgi_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_mcc_mnc_t(&(val->mcc_mnc), buf);
	enc_len += encode_uint32_t(val->eci, buf);
	return enc_len;
}

/**
 * Encodes tai to buffer.
 * @param val
 *   tai value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_tai_t(tai_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_mcc_mnc_t(&(val->mcc_mnc), buf);
	enc_len += encode_uint16_t(val->tac, buf);
	return enc_len;
}

/**
 * Encodes uli to buffer.
 * @param val
 *   uli value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_uli_ie_t(uli_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uli_flags_t(&val->flags, buf);

	if (val->flags.tai)
			enc_len += encode_tai_t(&val->tai, buf);

	if (val->flags.ecgi)
			enc_len += encode_ecgi_t(&val->ecgi, buf);

	/* TODO: Add handling for cgi, lai, sai, rai */

	return enc_len;
}

/**
 * Encodes serving network to buffer.
 * @param val
 *   serving network value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_serving_network_ie_t(serving_network_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_mcc_mnc_t(&(val->mcc_mnc), buf);
	return enc_len;
}

/**
 * Encodes rat type to buffer.
 * @param val
 *   rat type value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_rat_type_ie_t(rat_type_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->rat_type, buf);
	return enc_len;
}

/*
static int
encode_indication_t(indication_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_common_type(val, buf, sizeof(*val));
	return enc_len;
}
*/

/**
 * Encodes indication to buffer.
 * @param val
 *   indication value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_indication_ie_t(indication_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_common_type(&val->indication_value, buf, val->header.len);
	return enc_len;
}

/**
 * Encodes fteid to buffer.
 * @param val
 *   fteid value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_ftied_ie_t(fteid_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);

	val->teid_gre = htonl(val->teid_gre);

	if (val->v4 == 1 && val->v6 == 1) {
		val->ip.ipv4.s_addr = htonl(val->ip.ipv4.s_addr);
		/* TODO: Covert ipv6 to network order */
	} else if (val->v4 == 1) {
		val->ip.ipv4.s_addr = htonl(val->ip.ipv4.s_addr);
	} else if (val->v6 == 1) {
		 /* TODO: Covert ipv6 to network order */
	}

	enc_len += encode_common_type((uint8_t *)val + enc_len,
			buf, val->header.len);

	if (val->v4 == 1 && val->v6 == 1) {
		val->ip.ipv4.s_addr = ntohl(val->ip.ipv4.s_addr);
		/* TODO: Covert ipv6 to network order */
	} else if (val->v4 == 1) {
		val->ip.ipv4.s_addr = ntohl(val->ip.ipv4.s_addr);
	} else if (val->v6 == 1) {
		 /* TODO: Covert ipv6 to network order */
	}

	return enc_len;
}

/**
 * Encodes apn to buffer.
 * @param val
 *   apn value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_apn_ie_t(apn_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_common_type(&val->apn, buf, val->header.len);
	return enc_len;
}

/**
 * Encodes ambr to buffer.
 * @param val
 *   ambr value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_ambr_ie_t(ambr_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint32_t(val->apn_ambr_ul, buf);
	enc_len += encode_uint32_t(val->apn_ambr_dl, buf);
	return enc_len;
}

/**
 * Encodes selection mode to buffer.
 * @param val
 *   selection mode value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_selection_mode_ie_t(selection_mode_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->selec_mode, buf);
	return enc_len;
}

/**
 * Encodes pdn type to buffer.
 * @param val
 *   pdn type value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_pdn_type_ie_t(pdn_type_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->pdn_type, buf);
	return enc_len;
}

/**
 * Encodes PAA to buffer.
 * @param val
 *   PAA value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_paa_ie_t(paa_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);

	if (val->pdn_type == PDN_TYPE_IPV4) {
		val->ip_type.ipv4.s_addr = htonl(val->ip_type.ipv4.s_addr);
	} else if (val->pdn_type == PDN_TYPE_IPV6) {
		 /* TODO: Covert ipv6 to network order */
	} else if (val->pdn_type == PDN_TYPE_IPV4_IPV6) {
		val->ip_type.ipv4.s_addr = htonl(val->ip_type.ipv4.s_addr);
		 /* TODO: Covert ipv6 to network order */
	}

	enc_len += encode_common_type((uint8_t *)val + enc_len, buf, val->header.len);

	if (val->pdn_type == PDN_TYPE_IPV4) {
		val->ip_type.ipv4.s_addr = ntohl(val->ip_type.ipv4.s_addr);
	} else if (val->pdn_type == PDN_TYPE_IPV6) {
		 /* TODO: Covert ipv6 to network order */
	} else if (val->pdn_type == PDN_TYPE_IPV4_IPV6) {
		val->ip_type.ipv4.s_addr = ntohl(val->ip_type.ipv4.s_addr);
		 /* TODO: Covert ipv6 to network order */
	}

	return enc_len;
}

/**
 * Encodes apn restriction to buffer.
 * @param val
 *   apn restriction value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_apn_restriction_ie_t(apn_restriction_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->restriction_type, buf);
	return enc_len;
}

/**
 * Encodes recovery to buffer.
 * @param val
 *   recovery value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_recovery_ie_t(recovery_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->restart_counter, buf);
	return enc_len;
}

/**
 * Encodes ue timezone to buffer.
 * @param val
 *   ue timezone value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_ue_timezone_ie_t(ue_timezone_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->timezone, buf);
	enc_len += encode_uint8_t(val->ds_time, buf);
	return enc_len;
}

/**
 * Encodes eps bearer id to buffer.
 * @param val
 *   eps bearer id value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_eps_bearer_id_ie_t(eps_bearer_id_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint8_t(val->eps_bearer_id, buf);
	return enc_len;
}

/**
 * Encodes pci,pl,pvi value to buffer.
 * @param val
 *   pci, pl, pvi value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_pci_pl_pvi_t(pci_pl_pvi_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_common_type(val, buf, sizeof(*val));
	return enc_len;
}

/**
 * Encodes charging characteristics to buffer.
 * @param val
 *   charging characteristics value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_charging_char_ie_t(charging_char_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_uint16_t(val->value, buf);
	return enc_len;
}

/**
 * Encodes bearer qos to buffer.
 * @param val
 *   bearer qos value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_bearer_qos_ie_t(bearer_qos_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_pci_pl_pvi_t(&(val->pci_pl_pvi), buf);
	enc_len += encode_uint8_t(val->label_qci, buf);
	enc_len += encode_uint64_t_mbr(&(val->maximum_bit_rate_for_uplink), buf);
	enc_len += encode_uint64_t_mbr(&(val->maximum_bit_rate_for_downlink), buf);
	enc_len += encode_uint64_t_mbr(&(val->guaranteed_bit_rate_for_uplink), buf);
	enc_len += encode_uint64_t_mbr(&(val->guaranteed_bit_rate_for_downlink), buf);
	return enc_len;
}

/**
 * Encodes bearer context to be created to buffer.
 * @param val
 *   bearer context value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_bearer_context_to_be_created_ie_t(
		bearer_context_to_be_created_ie_t *val,
		gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_eps_bearer_id_ie_t(&(val->ebi), buf);
	if (val->s11u_mme_fteid.header.len)
		enc_len += encode_ftied_ie_t(&(val->s11u_mme_fteid), buf);
	enc_len += encode_bearer_qos_ie_t(&(val->bearer_qos), buf);
	return enc_len;
}

/**
 * Encodes cause to buffer.
 * @param val
 *   cause value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_cause_ie_t(cause_ie_t *val, gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_common_type((uint8_t *)val + enc_len, buf,
			val->header.len);
	return enc_len;
}

/**
 * Encodes bearer context created to buffer.
 * @param val
 *   bearer context value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_bearer_context_created_ie_t(bearer_context_created_ie_t *val,
		gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_eps_bearer_id_ie_t(&(val->ebi), buf);
	enc_len += encode_cause_ie_t(&(val->cause), buf);
	enc_len += encode_ftied_ie_t(&(val->s1u_sgw_ftied), buf);
	enc_len += encode_ftied_ie_t(&(val->s5s8_pgw), buf);
	return enc_len;
}

/**
 * Encodes bearer context to be modified to buffer.
 * @param val
 *   bearer context value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_bearer_context_to_be_modified_ie_t(
		bearer_context_to_be_modified_ie_t *val,
		gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_eps_bearer_id_ie_t(&(val->ebi), buf);
	enc_len += encode_ftied_ie_t(&(val->s1u_enodeb_ftied), buf);
	return enc_len;
}

/**
 * Encodes bearer context modified to buffer.
 * @param val
 *   bearer context value
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
static int
encode_bearer_context_modified_ie_t(bearer_context_modified_ie_t *val,
		gtpv2c_buffer_t *buf)
{
	uint16_t enc_len = 0;

	enc_len += encode_ie_header_t(&val->header, buf);
	enc_len += encode_cause_ie_t(&(val->cause), buf);
	enc_len += encode_eps_bearer_id_ie_t(&(val->ebi), buf);
	enc_len += encode_ftied_ie_t(&(val->s1u_sgw_ftied), buf);
	return enc_len;
}

/**
 * Encodes create session request to buffer.
 * @param val
 *   create session request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_create_session_request_t(create_session_request_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&val->header, &buf);

	if (val->imsi.header.len)
		enc_len += encode_imsi_ie_t(&(val->imsi), &buf);

	if (val->msisdn.header.len)
		enc_len += encode_msisdn_ie_t(&(val->msisdn), &buf);

	if (val->mei.header.len)
		enc_len += encode_mei_ie_t(&(val->mei), &buf);

	if (val->uli.header.len)
		enc_len += encode_uli_ie_t(&(val->uli), &buf);

	if (val->serving_nw.header.len)
		enc_len += encode_serving_network_ie_t(&(val->serving_nw), &buf);

	if (val->rat_type.header.len)
		enc_len += encode_rat_type_ie_t(&(val->rat_type), &buf);

	if (val->indication.header.len)
		enc_len += encode_indication_ie_t(&(val->indication), &buf);

	if (val->sender_ftied.header.len)
		enc_len += encode_ftied_ie_t(&(val->sender_ftied), &buf);

	if (val->s5s8pgw_pmip.header.len)
		enc_len += encode_ftied_ie_t(&(val->s5s8pgw_pmip), &buf);

	if (val->apn.header.len)
		enc_len += encode_apn_ie_t(&(val->apn), &buf);

	if (val->seletion_mode.header.len)
		enc_len += encode_selection_mode_ie_t(&(val->seletion_mode), &buf);

	if (val->charging_characteristics.header.len)
		enc_len += encode_charging_char_ie_t(&(val->charging_characteristics),
				&buf);

	if (val->pdn_type.header.len)
		enc_len += encode_pdn_type_ie_t(&(val->pdn_type), &buf);

	if (val->paa.header.len)
		enc_len += encode_paa_ie_t(&(val->paa), &buf);

	if (val->apn_restriction.header.len)
		enc_len += encode_apn_restriction_ie_t(&(val->apn_restriction), &buf);

	if (val->ambr.header.len)
		enc_len += encode_ambr_ie_t(&(val->ambr), &buf);

	if (val->bearer_context.header.len)
		enc_len += encode_bearer_context_to_be_created_ie_t(&(val->bearer_context),
				&buf);

	if (val->recovery.header.len)
		enc_len += encode_recovery_ie_t(&(val->recovery), &buf);

	if (val->ue_timezone.header.len)
		enc_len += encode_ue_timezone_ie_t(&(val->ue_timezone), &buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}

/**
 * Encodes create session response to buffer.
 * @param val
 *   create session response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_create_session_response_t(create_session_response_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&(val->header), &buf);

	if (val->cause.header.len)
		enc_len += encode_cause_ie_t(&(val->cause), &buf);

	if (val->s11_ftied.header.len)
		enc_len += encode_ftied_ie_t(&(val->s11_ftied), &buf);

	if (val->pgws5s8_pmip.header.len)
		enc_len += encode_ftied_ie_t(&(val->pgws5s8_pmip), &buf);

	if (val->paa.header.len)
		enc_len += encode_paa_ie_t(&(val->paa), &buf);

	if (val->apn_restriction.header.len)
		enc_len += encode_apn_restriction_ie_t(&(val->apn_restriction), &buf);

	if (val->bearer_context.header.len)
		enc_len += encode_bearer_context_created_ie_t(&(val->bearer_context), &buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}

/**
 * Encodes modify bearer request to buffer.
 * @param val
 *   modify bearer request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_modify_bearer_request_t(modify_bearer_request_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&(val->header), &buf);

	if (val->indication.header.len)
		enc_len += encode_indication_ie_t(&(val->indication), &buf);

	if (val->s11_mme_fteid.header.len)
		enc_len += encode_ftied_ie_t(&(val->s11_mme_fteid), &buf);

	if (val->bearer_context.header.len)
		enc_len += encode_bearer_context_to_be_modified_ie_t(
				&(val->bearer_context),	&buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}

/**
 * Encodes modify bearer response to buffer.
 * @param val
 *   modify bearer response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_modify_bearer_response_t(modify_bearer_response_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&(val->header), &buf);

	if (val->cause.header.len)
		enc_len += encode_cause_ie_t(&(val->cause), &buf);

	if (val->bearer_context.header.len)
		enc_len += encode_bearer_context_modified_ie_t(&(val->bearer_context), &buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}

/**
 * Encodes delete session request to buffer.
 * @param val
 *   delete session request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_delete_session_request_t(delete_session_request_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&(val->header), &buf);

	if (val->linked_ebi.header.len)
		enc_len += encode_eps_bearer_id_ie_t(&(val->linked_ebi), &buf);

	if (val->indication_flags.header.len)
		enc_len += encode_indication_ie_t(&(val->indication_flags), &buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}

/**
 * Encodes delete session response to buffer.
 * @param val
 *   delete session response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_delete_session_response_t(delete_session_response_t *val,
		uint8_t *msg, uint16_t *msg_len)
{
	uint16_t enc_len = 0;
	gtpv2c_buffer_t buf = {0};

	enc_len += encode_gtpv2c_header_t(&(val->header), &buf);

	if (val->cause.header.len)
		enc_len += encode_cause_ie_t(&(val->cause), &buf);

	*msg_len = enc_len;
	memcpy(msg, buf.val, buf.len);

	return enc_len;
}
