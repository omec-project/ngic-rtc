/*
 * Copyright (c) 2017 Intel Corporation
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "req_resp.h"
#include "util.h"
#include "gtpv2c_messages.h"


#define IE_HEADER_SIZE sizeof(ie_header_t)
#define MBR_SIZE 5

/*
static int
decode_uint8_t(uint8_t *buf, uint8_t *val)
{
	memcpy(buf, val, sizeof(uint8_t));
	return sizeof(uint8_t);
}

static int
decode_uint16_t(uint8_t *buf, uint16_t *val)
{
	memcpy(val, buf, sizeof(uint16_t));
	*val = ntohs(*val);
	return sizeof(uint16_t);
}


static int
decode_uint32_t(uint8_t *buf, uint32_t *val)
{
	memcpy(val, buf, sizeof(uint32_t));
	*val = ntohl(*val);
	return sizeof(uint32_t);
}
*/

/**
 * decodes buffer to mbr value.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   mbr value
 * @return
 *   number of decoded bytes.
 */
static int
decode_uint64_mbr_t(uint8_t *buf, uint64_t *val)
{
	*val = (uint64_t)(buf[4]) | (uint64_t)(buf[3]) << 8  |
		   (uint64_t)(buf[2]) << 16 | (uint64_t)(buf[1]) << 24 |
		   (uint64_t)(buf[0]) << 32;

	return 5;
}

/**
 * decodes buffer to void pointer.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   decoded value
 * @return
 *   number of decoded bytes.
 */
static int
decode_common_type(uint8_t *buf, void *val,
		uint16_t val_len)
{
	memcpy(val, buf, val_len);
	return val_len;
}

/**
 * decodes buffer to ie header.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   decoded ie header
 * @return
 *   number of decoded bytes.
 */
static int
decode_ie_header_t(uint8_t *buf, ie_header_t *val,
		uint16_t val_len)
{
	memcpy(val, buf,IE_HEADER_SIZE);
	val->len = ntohs(val->len);

	return val_len;
}

/**
 * decodes buffer to imsi.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   imsi value
 * @return
 *   number of decoded bytes.
 */
static int
decode_imsi_ie_t(uint8_t *buf, imsi_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	/* TODO : Covert IMSI to tbcd format */
	memcpy(val->imsi, (uint8_t *)buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to msisdn.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   msisdn value
 * @return
 *   number of decoded bytes.
 */
static int
decode_msisdn_ie_t(uint8_t *buf, msisdn_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(val->msisdn, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to mei.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   mei value
 * @return
 *   number of decoded bytes.
 */
static int
decode_mei_ie_t(uint8_t *buf, mei_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(val->mei, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to mcc-mnc.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   mcc-mnc value
 * @return
 *   number of decoded bytes.
 */
static int
decode_mcc_mnc_t(uint8_t *buf, mcc_mnc_t *val)
{
	uint16_t count = 0;

	val->mcc_digit_2 = (buf[0] & 0xf0) >> 4;
	val->mcc_digit_1 = (buf[0] & 0x0f);
	val->mnc_digit_3 = (buf[1] & 0xf0) >> 4;
	val->mcc_digit_3 = (buf[1] & 0x0f);
	val->mnc_digit_2 = (buf[2] & 0xf0) >> 4;
	val->mnc_digit_1 = (buf[2] & 0x0f);

	count += sizeof(mcc_mnc_t);

	return count;
}

/*
static int
decode_uli_flags_t(uint8_t *buf, uli_flags_t *val)
{
	uint16_t count = 0;
	memcpy(val, buf, sizeof(uli_flags_t));
	count += sizeof(uli_flags_t);

	return count;
}
*/

/**
 * decodes buffer to ecgi.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   ecgi value
 * @return
 *   number of decoded bytes.
 */
static int
decode_ecgi_t(uint8_t *buf, ecgi_t *val)
{
	uint16_t count = 0;
	decode_mcc_mnc_t(buf, &val->mcc_mnc);
	count += sizeof(mcc_mnc_t);

	uint32_t tmp;
	memcpy(&tmp, buf + count, sizeof(uint32_t));
	count += sizeof(ecgi_t);

	val->eci = ntohl(tmp);

	return count;
}

/**
 * decodes buffer to tai.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   tai value
 * @return
 *   number of decoded bytes.
 */
static int
decode_tai_t(uint8_t *buf, tai_t *val)
{
	uint16_t count = 0;
	decode_mcc_mnc_t(buf, &val->mcc_mnc);
	count += sizeof(mcc_mnc_t);

	memcpy(&val->tac, buf + count, sizeof(uint16_t));
	count += sizeof(uint16_t);

	val->tac = ntohs(val->tac);

	return count;
}

/**
 * decodes buffer to uli.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   uli value
 * @return
 *   number of decoded bytes.
 */
static int
decode_uli_ie_t(uint8_t *buf, uli_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->flags), (uint8_t * )buf + count, sizeof(uli_flags_t));
	count += sizeof(uli_flags_t);

	if (val->flags.tai) {
		decode_tai_t(buf + count, &(val->tai));
		count += sizeof(tai_t);
	}

	if (val->flags.ecgi) {
		decode_ecgi_t(buf + count, &(val->ecgi));
		count += sizeof(ecgi_t);
	}

	/* TODO: Add handling for cgi, lai, sai, rai */

	return count;
}

/**
 * decodes buffer to serving network.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   serving network value
 * @return
 *   number of decoded bytes.
 */
static int
decode_serving_network_ie_t(uint8_t *buf, serving_network_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	decode_mcc_mnc_t(buf + count, &val->mcc_mnc);
	count += sizeof(mcc_mnc_t);

	return count;
}

/**
 * decodes buffer to msisdn.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   msisdn value
 * @return
 *   number of decoded bytes.
 */
static int
decode_rat_type_ie_t(uint8_t *buf, rat_type_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->rat_type), (uint8_t * )buf + count, sizeof(rat_type_ie_t));
	count += sizeof(val->rat_type);

	return count;
}

/*
static int
decode_indication_t(uint8_t *buf, indication_t *val)
{
	uint16_t count = 0;

	memcpy(val, (uint8_t * )buf + count, sizeof(indication_t));
	count += sizeof(indication_t);

	return count;
}
*/

/**
 * decodes buffer to indication.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   indication value
 * @return
 *   number of decoded bytes.
 */
static int
decode_indication_ie_t(uint8_t *buf, indication_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_common_type((uint8_t * )buf + count,
			&(val->indication_value), val->header.len);

	return count;
}

/**
 * decodes buffer to fteid.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   fteid value
 * @return
 *   number of decoded bytes.
 */
static int
decode_fteid_ie_t(uint8_t *buf, fteid_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&val->header + 1, buf + count, val->header.len);
	count += val->header.len;

	val->teid_gre = ntohl(val->teid_gre);

	if (val->v4 == 1 && val->v6 == 1) {
		val->ip.ipv4.s_addr = ntohl(val->ip.ipv4.s_addr);
		/* TODO: Covert ipv6 to network order */
	} else if (val->v4 == 1) {
		val->ip.ipv4.s_addr = ntohl(val->ip.ipv4.s_addr);
	} else if (val->v6 == 1) {
		 /* TODO: Covert ipv6 to network order */
	}

	return count;
}

/**
 * decodes buffer to apn.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   apn value
 * @return
 *   number of decoded bytes.
 */
static int
decode_apn_ie_t(uint8_t *buf, apn_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->apn), (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to ambr.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   ambr value
 * @return
 *   number of decoded bytes.
 */
static int
decode_ambr_ie_t(uint8_t *buf, ambr_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&val->header + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	val->apn_ambr_ul = ntohl(val->apn_ambr_ul);
	val->apn_ambr_dl = ntohl(val->apn_ambr_dl);

	return count;
}

/**
 * decodes buffer to selection mode.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   selection mode value
 * @return
 *   number of decoded bytes.
 */
static int
decode_selection_mode_ie_t(uint8_t *buf, selection_mode_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to pdn type.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   pdn type value
 * @return
 *   number of decoded bytes.
 */
static int
decode_pdn_type_ie_t(uint8_t *buf, pdn_type_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to PAA.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   PAA value
 * @return
 *   number of decoded bytes.
 */
static int
decode_paa_ie_t(uint8_t *buf, paa_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	if (val->pdn_type == PDN_TYPE_IPV4) {
		val->ip_type.ipv4.s_addr = htonl(val->ip_type.ipv4.s_addr);
	} else if (val->pdn_type == PDN_TYPE_IPV6) {
		 /* TODO: Covert ipv6 to network order */
	} else if (val->pdn_type == PDN_TYPE_IPV4_IPV6) {
		val->ip_type.ipv4.s_addr = htonl(val->ip_type.ipv4.s_addr);
		 /* TODO: Covert ipv6 to network order */
	}

	return count;
}

/**
 * decodes buffer to apn restriction.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   apn restriction value
 * @return
 *   number of decoded bytes.
 */
static int
decode_apn_restriction_ie_t(uint8_t *buf, apn_restriction_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to restart counter.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   restart counter value
 * @return
 *   number of decoded bytes.
 */
static int
decode_recover_ie_t(uint8_t *buf, recovery_ie_t *val)
{
	uint16_t count = 0;

	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to ue timezone.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   ue timezone value
 * @return
 *   number of decoded bytes.
 */
static int
decode_ue_timezone_ie_t(uint8_t *buf, ue_timezone_ie_t *val)
{
	uint16_t count = 0;

	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to eps bearer id.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   eps bearer id value
 * @return
 *   number of decoded bytes.
 */
static int
decode_eps_bearer_id_ie_t(uint8_t *buf, eps_bearer_id_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to pci, pl, pvi.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   pci,pl,pvi value
 * @return
 *   number of decoded bytes.
 */
static int
decode_pci_pl_pvi_t(uint8_t *buf, pci_pl_pvi_t *val)
{
	uint16_t count = 0;

	memcpy(val, buf, sizeof(uint8_t));
	count += sizeof(pci_pl_pvi_t);

	return count;
}

/**
 * decodes buffer to charging characteristics.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   charging characteristics value
 * @return
 *   number of decoded bytes.
 */
static int
decode_charging_char_ie_t(uint8_t *buf, charging_char_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to bearer qos.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   bearer qos value
 * @return
 *   number of decoded bytes.
 */
static int
decode_bearer_qos_ie_t(uint8_t *buf, bearer_qos_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	decode_pci_pl_pvi_t(buf + count, &(val->pci_pl_pvi));
	count += sizeof(pci_pl_pvi_t);

	memcpy(&val->label_qci, buf + count, sizeof(uint8_t));
	count += sizeof(uint8_t);

	decode_uint64_mbr_t(buf + count, &val->maximum_bit_rate_for_uplink);
	count += MBR_SIZE;

	decode_uint64_mbr_t(buf + count, &val->maximum_bit_rate_for_downlink);
	count += MBR_SIZE;

	decode_uint64_mbr_t(buf + count, &val->guaranteed_bit_rate_for_uplink);
	count += MBR_SIZE;

	decode_uint64_mbr_t(buf + count, &val->guaranteed_bit_rate_for_downlink);
	count += MBR_SIZE;

	return count;
}

/**
 * decodes buffer to bearer context to be created.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   bearer context value
 * @return
 *   number of decoded bytes.
 */
static int
decode_bearer_context_to_be_created_ie_t(uint8_t *buf,
		bearer_context_to_be_created_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);
	ie_header_t *header = (ie_header_t *) (buf + count);
	if (header->type == IE_FTEID && header->instance == IE_INSTANCE_ZERO)
		count += decode_fteid_ie_t(buf + count, &val->s11u_mme_fteid);
	count += decode_bearer_qos_ie_t(buf + count, &val->bearer_qos);

	return count;
}

/**
 * decodes buffer to cause.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   cause value
 * @return
 *   number of decoded bytes.
 */
static int
decode_cause_ie_t(uint8_t *buf, cause_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	memcpy(&(val->header) + 1, (uint8_t * )buf + count, val->header.len);
	count += val->header.len;

	return count;
}

/**
 * decodes buffer to bearer context created.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   bearer context value
 * @return
 *   number of decoded bytes.
 */
static int
decode_bearer_context_created_ie_t(uint8_t *buf,
		bearer_context_created_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);
	count += decode_cause_ie_t(buf + count, &val->cause);
	count += decode_fteid_ie_t(buf + count, &val->s1u_sgw_ftied);
	count += decode_fteid_ie_t(buf + count, &val->s5s8_pgw);

	return count;
}

/*
static int
decode_bearer_context_to_be_removed_ie_t(uint8_t *buf,
		bearer_context_to_be_removed_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);

	return count;
}
*/

/*
static int
decode_bearer_context_marked_for_removal_ie_t(uint8_t *buf,
		bearer_context_marked_for_removal_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);
	count += decode_cause_ie_t(buf + count, &val->cause);

	return count;
}
*/

/**
 * decodes buffer to bearer context to be modified.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   bearer context value
 * @return
 *   number of decoded bytes.
 */
static int
decode_bearer_context_to_be_modified_ie_t(uint8_t *buf,
		bearer_context_to_be_modified_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);
	count += decode_fteid_ie_t(buf + count, &val->s1u_enodeb_ftied);

	return count;
}

/**
 * decodes buffer to bearer context modified.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   bearer context value
 * @return
 *   number of decoded bytes.
 */
static int
decode_bearer_context_modified_ie_t(uint8_t *buf,
		bearer_context_modified_ie_t *val)
{
	uint16_t count = 0;
	decode_ie_header_t(buf, &(val->header), IE_HEADER_SIZE);
	count += IE_HEADER_SIZE;

	count += decode_cause_ie_t(buf + count, &val->cause);
	count += decode_eps_bearer_id_ie_t(buf + count, &val->ebi);
	count += decode_fteid_ie_t(buf + count, &val->s1u_sgw_ftied);

	return count;
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
static int
decode_gtpv2c_header_t(uint8_t *buf, gtpv2c_header_t *header)
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
 * decodes buffer to create session request.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   create session request
 * @return
 *   number of decoded bytes.
 */
int
decode_create_session_request_t(uint8_t *msg,
		create_session_request_t *cs_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &cs_req->header);

	if (cs_req->header.gtpc.teid_flag)
		msg_len = cs_req->header.gtpc.message_len - 8;
	else
		msg_len = cs_req->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_IMSI &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_imsi_ie_t(msg + count, &cs_req->imsi);
		} else if (ie_header->type == IE_MSISDN &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_msisdn_ie_t(msg + count, &cs_req->msisdn);
		} else if (ie_header->type == IE_MEI &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_mei_ie_t(msg + count, &cs_req->mei);
		} else if (ie_header->type == IE_ULI &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_uli_ie_t(msg + count, &cs_req->uli);
		} else if (ie_header->type == IE_SERVING_NETWORK &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_serving_network_ie_t(msg + count,
					&cs_req->serving_nw);
		} else if (ie_header->type == IE_RAT_TYPE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_rat_type_ie_t(msg + count,
					&cs_req->rat_type);
		} else if (ie_header->type == IE_INDICATION &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_indication_ie_t(msg + count,
								&cs_req->indication);
		} else if (ie_header->type == IE_FTEID &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_fteid_ie_t(msg + count,
								&cs_req->sender_ftied);
		} else if (ie_header->type == IE_FTEID &&
				ie_header->instance == IE_INSTANCE_ONE) {
			count += decode_fteid_ie_t(msg + count,
								&cs_req->s5s8pgw_pmip);
		} else if (ie_header->type == IE_APN &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_apn_ie_t(msg + count,
								&cs_req->apn);
		} else if (ie_header->type == IE_AMBR &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_ambr_ie_t(msg + count,
								&cs_req->ambr);
		} else if (ie_header->type == IE_SELECTION_MODE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_selection_mode_ie_t(msg + count,
								&cs_req->seletion_mode);
		} else if (ie_header->type == IE_PDN_TYPE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_pdn_type_ie_t(msg + count,
								&cs_req->pdn_type);
		} else if (ie_header->type == IE_PAA &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_paa_ie_t(msg + count,
								&cs_req->paa);
		} else if (ie_header->type == IE_APN_RESTRICTION &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_apn_restriction_ie_t(msg + count,
								&cs_req->apn_restriction);
		} else if (ie_header->type == IE_CHARGING_CHARACTERISTICS &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_charging_char_ie_t(msg + count,
								&cs_req->charging_characteristics);
		} else if (ie_header->type == IE_BEARER_CONTEXT &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_bearer_context_to_be_created_ie_t(msg + count,
								&cs_req->bearer_context);
		} else if (ie_header->type == IE_RECOVERY &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_recover_ie_t(msg + count,
								&cs_req->recovery);
		} else if (ie_header->type == IE_UE_TIME_ZONE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_ue_timezone_ie_t(msg + count,
								&cs_req->ue_timezone);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * decodes buffer to create session response.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   create session response
 * @return
 *   number of decoded bytes.
 */
int
decode_create_session_response_t(uint8_t *msg,
		create_session_response_t *cs_resp)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &cs_resp->header);

	if (cs_resp->header.gtpc.teid_flag)
		msg_len = cs_resp->header.gtpc.message_len - 8;
	else
		msg_len = cs_resp->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_CAUSE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_cause_ie_t(msg + count, &cs_resp->cause);
		} else if (ie_header->type == IE_FTEID &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_fteid_ie_t(msg + count,
								&cs_resp->s11_ftied);
		} else if (ie_header->type == IE_FTEID &&
				ie_header->instance == IE_INSTANCE_ONE) {
			count += decode_fteid_ie_t(msg + count,
								&cs_resp->pgws5s8_pmip);
		} else if (ie_header->type == IE_PAA &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_paa_ie_t(msg + count,
								&cs_resp->paa);
		} else if (ie_header->type == IE_APN_RESTRICTION &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_apn_restriction_ie_t(msg + count,
								&cs_resp->apn_restriction);
		} else if (ie_header->type == IE_BEARER_CONTEXT &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_bearer_context_created_ie_t(msg + count,
								&cs_resp->bearer_context);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * decodes buffer to modify bearer request.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   modify bearer request
 * @return
 *   number of decoded bytes.
 */
int
decode_modify_bearer_request_t(uint8_t *msg,
		modify_bearer_request_t *mb_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &mb_req->header);

	if (mb_req->header.gtpc.teid_flag)
		msg_len = mb_req->header.gtpc.message_len - 8;
	else
		msg_len = mb_req->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_INDICATION &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_indication_ie_t(msg + count, &mb_req->indication);
		} else if (ie_header->type == IE_FTEID &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_fteid_ie_t(msg + count,
								&mb_req->s11_mme_fteid);
		} else if (ie_header->type == IE_BEARER_CONTEXT &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_bearer_context_to_be_modified_ie_t(msg + count,
					&mb_req->bearer_context);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * decodes buffer to modify bearer response.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   modify bearer response
 * @return
 *   number of decoded bytes.
 */
int
decode_modify_bearer_response_t(uint8_t *msg,
		modify_bearer_response_t *mb_resp)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &mb_resp->header);

	if (mb_resp->header.gtpc.teid_flag)
		msg_len = mb_resp->header.gtpc.message_len - 8;
	else
		msg_len = mb_resp->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_CAUSE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_cause_ie_t(msg + count, &mb_resp->cause);
		} else if (ie_header->type == IE_BEARER_CONTEXT &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_bearer_context_modified_ie_t(msg + count,
								&mb_resp->bearer_context);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * decodes buffer to delete session request.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   modify delete session request
 * @return
 *   number of decoded bytes.
 */
int
decode_delete_session_request_t(uint8_t *msg,
		delete_session_request_t *ds_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &ds_req->header);

	if (ds_req->header.gtpc.teid_flag)
		msg_len = ds_req->header.gtpc.message_len - 8;
	else
		msg_len = ds_req->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_EBI &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_eps_bearer_id_ie_t(msg + count,
					&ds_req->linked_ebi);
		} else if (ie_header->type == IE_INDICATION &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_indication_ie_t(msg + count,
					&ds_req->indication_flags);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * decodes buffer to delete session response.
 * @param buf
 *   buffer to be decoded
 * @param val
 *   modify delete session response
 * @return
 *   number of decoded bytes.
 */
int
decode_delete_session_response_t(uint8_t *msg,
		delete_session_response_t *ds_resp)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_gtpv2c_header_t(msg + count, &ds_resp->header);

	if (ds_resp->header.gtpc.teid_flag)
		msg_len = ds_resp->header.gtpc.message_len - 8;
	else
		msg_len = ds_resp->header.gtpc.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		ie_header_t *ie_header = (ie_header_t *) (msg + count);

		if (ie_header->type == IE_CAUSE &&
				ie_header->instance == IE_INSTANCE_ZERO) {
			count += decode_cause_ie_t(msg + count,
					&ds_resp->cause);
		} else {
			count += sizeof(ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}
