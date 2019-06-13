/*
 * Copyright (c) 2019 Sprint
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

#include "../include/pfcp_ies_decoder.h"
#include "../include/pfcp_messages_decoder.h"

/**
 * Decodes pfcp association setup request to buffer.
 * @param pas_req
 *     pfcp association setup request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_association_setup_request(uint8_t *msg,
	pfcp_association_setup_request_t *pas_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pas_req->header);

	if (pas_req->header.s)
		msg_len = pas_req->header.message_len - 12;
	else
		msg_len = pas_req->header.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pas_req->node_id);
		} else if (ie_type == IE_RECOVERY_TIME_STAMP) {
			count += decode_recovery_time_stamp_ie_t(msg + count, &pas_req->recovery_time_stamp);
		} else if (ie_type == IE_UP_FUNCTION_FEATURES) {
			count += decode_up_function_features_ie_t(msg + count, &pas_req->up_function_features);
		} else if (ie_type == IE_CP_FUNCTION_FEATURES) {
			count += decode_cp_function_features_ie_t(msg + count, &pas_req->cp_function_features);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * Decodes pfcp association setup response to buffer.
 * @param pas_req
 *     pfcp association setup request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_association_setup_response(uint8_t *msg,
	pfcp_association_setup_response_t *pas_resp)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pas_resp->header);
	if (pas_resp->header.s)
		msg_len = pas_resp->header.message_len - 12;
	else
		msg_len = pas_resp->header.message_len - 4;

	msg = msg + count;
	count = 0;

	pas_resp->user_plane_ip_resource_information_count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pas_resp->node_id);
		} else if (ie_type == IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &pas_resp->cause);
		} else if (ie_type == IE_RECOVERY_TIME_STAMP) {
			count += decode_recovery_time_stamp_ie_t(msg + count, &pas_resp->recovery_time_stamp);
		} else if (ie_type == IE_UP_FUNCTION_FEATURES) {
			count += decode_up_function_features_ie_t(msg + count, &pas_resp->up_function_features);
		} else if (ie_type == IE_CP_FUNCTION_FEATURES) {
			count += decode_cp_function_features_ie_t(msg + count, &pas_resp->cp_function_features);
		} else if (ie_type == IE_UP_IP_RESOURCE_INFORMATION) {
				count += decode_user_plane_ip_resource_information_ie_t(msg + count, &pas_resp->up_ip_resource_info[pas_resp->user_plane_ip_resource_information_count++]);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}

/**
 * Decodes pfcp session establishment response to buffer.
 * @param pse_res
 *     pfcp session establishment response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_session_establishment_response(uint8_t *msg,
		pfcp_session_establishment_response_t *pse_res)
{
	uint16_t count = 0;
	uint16_t msg_len;

	pse_res->created_pdr_count = 0;

	count = decode_pfcp_header_t(msg + count, &pse_res->header);

	if (pse_res->header.s)
		msg_len = pse_res->header.message_len - 12;
	else
		msg_len = pse_res->header.message_len - 4;

	msg = msg + count;
	count = 0;
	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type== IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pse_res->node_id);
		} else if (ie_type == IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &pse_res->cause);
		} else if (ie_type == IE_OFFENDING_IE) {
			count += decode_offending_ie_t(msg + count, &pse_res->offending_ie);
		} else if (ie_type == IE_F_SEID) {
			count += decode_f_seid_ie_t(msg + count, &pse_res->up_fseid);
		} else if ( ie_type == IE_CREATED_PDR) {
			count += decode_created_pdr_ie_t(msg + count, &pse_res->created_pdr[pse_res->created_pdr_count++]);
		} else if (ie_type == IE_LOAD_CONTROL_INFORMATION) {
			count += decode_load_control_information_ie_t(msg + count, &pse_res->load_control_information);
		} else if (ie_type == IE_OVERLOAD_CONTROL_INFORMATION) {
			count += decode_overload_control_information_ie_t(msg + count, &pse_res->overload_control_information);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pse_res->sgwu_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pse_res->pgwu_fqcsid);
		} else if (ie_type == IE_FAILED_RULE_ID) {
			count += decode_failed_rule_id_ie_t(msg + count, &pse_res->failed_rule_id);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}



/**
 * Decodes pfcp session establishment request to buffer.
 * @param pse_req
 *     pfcp session establishment request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */


int decode_pfcp_session_establishment_request(uint8_t *msg,
	pfcp_session_establishment_request_t *pse_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pse_req->header);

	if (pse_req->header.s)
		msg_len = pse_req->header.message_len - 12;
	else
		msg_len = pse_req->header.message_len - 4;

	msg = msg + count;
	count = 0;
	pse_req->create_pdr_count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = ( pfcp_ie_header_t*) (msg + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_NODE_ID ) {
			count += decode_node_id_ie_t(msg + count, &pse_req->node_id);
		} else if (ie_type == IE_F_SEID ) {
			count += decode_f_seid_ie_t(msg + count, &pse_req->cp_fseid);
		} else if(ie_type == IE_CREATE_PDR) {
			count += decode_create_pdr_ie_t(msg + count, &pse_req->create_pdr[pse_req->create_pdr_count++]);
		} else if (ie_type == IE_CREATE_BAR ) {
			count += decode_create_bar_ie_t(msg + count, &pse_req->create_bar);
		} else if (ie_type == IE_PFCP_PDN_TYPE ) {
			count += decode_pdn_type_ie_t(msg + count, &pse_req->pdn_type);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pse_req->sgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pse_req->mme_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pse_req->pgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pse_req->epdg_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pse_req->twan_fqcsid);
		} else if (ie_type == IE_USER_PLANE_INACTIVITY_TIMER ) {
			count += decode_user_plane_inactivity_timer_ie_t(msg + count, &pse_req->user_plane_inactivity_timer);
		} else if (ie_type == IE_USER_ID ) {
			count += decode_user_id_ie_t(msg + count, &pse_req->user_id);
		} else if (ie_type == IE_PFCP_TRACE_INFORMATION ) {
			count += decode_trace_information_ie_t(msg + count, &pse_req->trace_information);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}



/**
 * Decodes pfcp session modification request to buffer.
 * @param psm_req
 *     pfcp session modification request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_session_modification_request(uint8_t *msg,
		pfcp_session_modification_request_t *psm_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &psm_req->header);

	if (psm_req->header.s)
		msg_len = psm_req->header.message_len - 12;
	else
		msg_len = psm_req->header.message_len - 4;

	msg = msg + count;
	count = 0;

	psm_req->create_pdr_count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);

		uint16_t ie_type = ntohs(ie_header->type);

		if ( ie_type == IE_F_SEID ) {
			count += decode_f_seid_ie_t(msg + count, &psm_req->cp_fseid);
		} else if (ie_type == IE_REMOVE_BAR ) {
			count += decode_remove_bar_ie_t(msg + count, &psm_req->remove_bar);
		} else if (ie_type == IE_REMOVE_TRAFFIC_ENDPOINT) {
			count += decode_remove_traffic_endpoint_ie_t(msg + count, &psm_req->remove_traffic_endpoint);
		} else if(ie_type == IE_CREATE_PDR) {
			count += decode_create_pdr_ie_t(msg + count, &psm_req->create_pdr[psm_req->create_pdr_count++]);
		} else if (ie_type == IE_CREATE_BAR ) {
			count += decode_create_bar_ie_t(msg + count, &psm_req->create_bar);
		} else if (ie_type == IE_CREATE_TRAFFIC_ENDPOINT) {
			count += decode_create_traffic_endpoint_ie_t(msg + count, &psm_req->create_traffic_endpoint);
		} else if (ie_type == IE_UPDATE_QER) {
			count += decode_update_qer_ie_t(msg + count, &psm_req->update_qer);
		} else if (ie_type == IE_UPDATE_BAR ) {
			count += decode_update_bar_ie_t(msg + count, &psm_req->update_bar);
		} else if (ie_type == IE_UPDATE_TRAFFIC_ENDPOINT) {
			count += decode_update_traffic_endpoint_ie_t(msg + count, &psm_req->update_traffic_endpoint);
		} else if (ie_type == IE_PFCPSMREQ_FLAGS) {
			count += decode_pfcpsmreq_flags_ie_t(msg + count, &psm_req->pfcpsmreqflags);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &psm_req->pgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &psm_req->sgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &psm_req->mme_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &psm_req->epdg_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &psm_req->twan_fqcsid);
		} else if (ie_type == IE_USER_PLANE_INACTIVITY_TIMER) {
			count += decode_user_plane_inactivity_timer_ie_t(msg + count, &psm_req->user_plane_inactivity_timer);
		} else if (ie_type == IE_QUERY_URR_REFERENCE) {
			count += decode_query_urr_reference_ie_t(msg + count, &psm_req->query_urr_reference);
		} else if (ie_type == IE_PFCP_TRACE_INFORMATION ) {
			count += decode_trace_information_ie_t(msg + count, &psm_req->trace_information);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}



/**
 * Decodes pfcp session modification response to buffer.
 * @param psm_res
 *     pfcp session modification response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_pfcp_session_modification_response(uint8_t *msg,
		pfcp_session_modification_response_t *psm_res)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &psm_res->header);

	if (psm_res->header.s)
		msg_len = psm_res->header.message_len - 12;
	else
		msg_len = psm_res->header.message_len - 4;

	msg = msg + count;
	count = 0;

	psm_res->created_pdr_count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);


		if (ie_type== IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &psm_res->cause);
		} else if (ie_type == IE_OFFENDING_IE) {
			count += decode_offending_ie_t(msg + count, &psm_res->offending_ie);
		} else if (ie_type == IE_CREATED_PDR) {
			count += decode_created_pdr_ie_t(msg + count, &psm_res->created_pdr[psm_res->created_pdr_count++]);
		} else if (ie_type == IE_LOAD_CONTROL_INFORMATION) {
			count += decode_load_control_information_ie_t(msg + count, &psm_res->load_control_information);
		} else if (ie_type == IE_OVERLOAD_CONTROL_INFORMATION) {
			count += decode_overload_control_information_ie_t(msg + count, &psm_res->overload_control_information);
		} else if (ie_type == IE_FAILED_RULE_ID) {
			count += decode_failed_rule_id_ie_t(msg + count, &psm_res->failed_rule_id);
		} else if (ie_type == IE_ADDITIONAL_USAGE_REPORTS_INFORMATION) {
			count += decode_additional_usage_reports_information_ie_t(msg + count, &psm_res->additional_usage_reports_information);
		} else if (ie_type == IE_CREATE_TRAFFIC_ENDPOINT) {
			count += decode_created_traffic_endpoint_ie_t(msg + count, &psm_res->createdupdated_traffic_endpoint);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}
	return count;
}



/**
 * Decodes pfcp session deletion request to buffer.
 * @param psd_req
 *     pfcp session deletion request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_pfcp_session_deletion_request(uint8_t *msg,
		pfcp_session_deletion_request_t *psd_req)
{
	uint16_t count = 0;
	//uint16_t msg_len = 0;

	count = decode_pfcp_header_t(msg + count, &psd_req->header);
/*
	if (psd_req->header.s)
		msg_len = psd_req->header.message_len - 12;
	else
		msg_len = psd_req->header.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
	}
*/

	return count;
}


/**
 * Decodes pfcp session deletion response to buffer.
 * @param psd_res
 *     pfcp session deletion response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_session_deletion_response(uint8_t *msg,
		pfcp_session_deletion_response_t *psd_res)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &psd_res->header);

	if (psd_res->header.s)
		msg_len = psd_res->header.message_len - 12;
	else
		msg_len = psd_res->header.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type == IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &psd_res->cause);
		} else if (ie_type == IE_OFFENDING_IE ) {
			count += decode_offending_ie_t(msg + count, &psd_res->offending_ie);
		} else if (ie_type == IE_LOAD_CONTROL_INFORMATION ) {
			count += decode_load_control_information_ie_t(msg + count, &psd_res->load_control_information);
		} else if (ie_type == IE_OVERLOAD_CONTROL_INFORMATION ) {
			count += decode_overload_control_information_ie_t(msg + count, &psd_res->overload_control_information);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}


/**
 * Decodes pfcp session set deletion request to buffer.
 * @param pssd_req
 *     pfcp session set deletion request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

int decode_pfcp_session_set_deletion_request(uint8_t *msg,
		pfcp_session_set_deletion_request_t *pssd_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pssd_req->header);

	if (pssd_req->header.s)
		msg_len = pssd_req->header.message_len - 12;
	else
		msg_len = pssd_req->header.message_len - 4;

	msg = msg + count;
	count = 0;
	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type== IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pssd_req->node_id);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->sgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->pgwc_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->sgwu_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->pgwu_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->twan_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->epdg_fqcsid);
		} else if (ie_type == IE_PFCP_FQ_CSID ) {
			count += decode_fq_csid_ie_t(msg + count, &pssd_req->mme_fqcsid);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}


/**
 * Decodes pfcp session set deletion response to buffer.
 * @param pssd_res
 *     pfcp session set deletion response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_session_set_deletion_response(uint8_t *msg,
		pfcp_session_set_deletion_response_t *pssd_res)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pssd_res->header);

	if (pssd_res->header.s)
		msg_len = pssd_res->header.message_len - 12;
	else
		msg_len = pssd_res->header.message_len - 4;

	msg = msg + count;
	count = 0;


	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type== IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pssd_res->node_id);
		} else if (ie_type == IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &pssd_res->cause);
		} else if (ie_type == IE_OFFENDING_IE) {
			count += decode_offending_ie_t(msg + count, &pssd_res->offending_ie);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}





/**
 * Decodes pfcp association update request to buffer.
 * @param pau_req
 *     pfcp association update request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_association_update_request(uint8_t *msg,
		pfcp_association_update_request_t *pau_req)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pau_req->header);

	if (pau_req->header.s)
		msg_len = pau_req->header.message_len - 12;
	else
		msg_len = pau_req->header.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type== IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pau_req->node_id);
		} else if (ie_type == IE_UP_FUNCTION_FEATURES ) {
			count += decode_up_function_features_ie_t(msg + count, &pau_req->up_function_features);
		} else if (ie_type == IE_CP_FUNCTION_FEATURES) {
			count += decode_cp_function_features_ie_t(msg + count, &pau_req->cp_function_features);
		} else if (ie_type == IE_PFCP_ASSOCIATION_RELEASE_REQUEST) {
			count += decode_pfcp_association_release_request_ie_t(msg + count, &pau_req->pfcp_association_release_request);
		} else if (ie_type == IE_GRACEFUL_RELEASE_PERIOD) {
			count += decode_graceful_release_period_ie_t(msg + count, &pau_req->graceful_release_period);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}


/**
 * Decodes pfcp association update response to buffer.
 * @param pau_res
 *     pfcp association update response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_association_update_response(uint8_t *msg,
		pfcp_association_update_response_t *pau_res)
{
	uint16_t count = 0;
	uint16_t msg_len;

	count = decode_pfcp_header_t(msg + count, &pau_res->header);

	if (pau_res->header.s)
		msg_len = pau_res->header.message_len - 12;
	else
		msg_len = pau_res->header.message_len - 4;

	msg = msg + count;
	count = 0;

	while (count < msg_len) {

		pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
		uint16_t ie_type = ntohs(ie_header->type);

		if (ie_type== IE_NODE_ID) {
			count += decode_node_id_ie_t(msg + count, &pau_res->node_id);
		} else if (ie_type == IE_CAUSE_ID) {
			count += decode_cause_id_ie_t(msg + count, &pau_res->cause);
		} else if (ie_type == IE_UP_FUNCTION_FEATURES) {
			count += decode_up_function_features_ie_t(msg + count, &pau_res->up_function_features);
		} else if (ie_type == IE_CP_FUNCTION_FEATURES) {
			count += decode_cp_function_features_ie_t(msg + count, &pau_res->cp_function_features);
		} else {
			count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
		}
	}

	return count;
}



/**
 * Decodes pfcp association release request to buffer.
 * @param par_req
 *     pfcp association release request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 
 int decode_pfcp_association_release_request(uint8_t *msg,
    pfcp_association_release_request_t *par_req)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &par_req->header);

    if (par_req->header.s)
        msg_len = par_req->header.message_len - 12;
    else
        msg_len = par_req->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_NODE_ID) {
            count += decode_node_id_ie_t(msg + count, &par_req->node_id);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}

/**
 * Decodes pfcp association release response to buffer.
 * @param par_res
 *     pfcp association release response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 int decode_pfcp_association_release_response(uint8_t *msg,
    pfcp_association_release_response_t *par_res)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &par_res->header);

    if (par_res->header.s)
        msg_len = par_res->header.message_len - 12;
    else
        msg_len = par_res->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_NODE_ID) {
            count += decode_node_id_ie_t(msg + count, &par_res->node_id);
        } else if (ie_type == IE_CAUSE_ID) {
            count += decode_cause_id_ie_t(msg + count, &par_res->cause);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}

 

/**
 * Decodes pfcp node report request to buffer.
 * @param pnr_req
 *     pfcp node report request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 int decode_pfcp_node_report_request(uint8_t *msg,
    pfcp_node_report_request_t *pnr_req)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &pnr_req->header);

    if (pnr_req->header.s)
        msg_len = pnr_req->header.message_len - 12;
    else
        msg_len = pnr_req->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_NODE_ID) {
            count += decode_node_id_ie_t(msg + count, &pnr_req->node_id);
        } else if (ie_type == IE_NODE_REPORT_TYPE) {
            count += decode_node_report_type_ie_t(msg + count, &pnr_req->node_report_type);
        } else if (ie_type == IE_USER_PLANE_PATH_FAILURE_REPORT) {
            count += decode_user_plane_path_failure_report_ie_t(msg + count, &pnr_req->user_plane_path_failure_report);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}

/**
 * Decodes pfcp node report response to buffer.
 * @param pnr_res
 *     pfcp node report response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 int decode_pfcp_node_report_response(uint8_t *msg,
    pfcp_node_report_response_t *pnr_res)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &pnr_res->header);

    if (pnr_res->header.s)
        msg_len = pnr_res->header.message_len - 8;
    else
        msg_len = pnr_res->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_NODE_ID) {
            count += decode_node_id_ie_t(msg + count, &pnr_res->node_id);
        } else if (ie_type == IE_CAUSE_ID) {
            count += decode_cause_id_ie_t(msg + count, &pnr_res->cause);
        } else if (ie_type == IE_OFFENDING_IE) {
            count += decode_offending_ie_t(msg + count, &pnr_res->offending_ie);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}




/**
 * Decodes pfcp heartbeat request to buffer.
 * @param ph_req
 *     pfcp heartbeat request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 int decode_pfcp_heartbeat_request(uint8_t *msg,
    pfcp_heartbeat_request_t *ph_req)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &ph_req->header);

    if (ph_req->header.s)
        msg_len = ph_req->header.message_len - 12;
    else
        msg_len = ph_req->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type == IE_RECOVERY_TIME_STAMP) {
            count += decode_recovery_time_stamp_ie_t(msg + count, &ph_req->recovery_time_stamp);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}

/**
 * Decodes pfcp heartbeat response to buffer.
 * @param ph_res
 *     pfcp heartbeat response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_heartbeat_response(uint8_t *msg,
    pfcp_heartbeat_response_t *ph_res)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &ph_res->header);

    if (ph_res->header.s)
        msg_len = ph_res->header.message_len - 12;
    else
        msg_len = ph_res->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_RECOVERY_TIME_STAMP) {
            count += decode_recovery_time_stamp_ie_t(msg + count, &ph_res->recovery_time_stamp);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
}

/**
 * Decodes pfcp session report request to buffer.
 * @param psr_req
 *     pfcp session report request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_pfcp_session_report_request(uint8_t *msg,
    pfcp_session_report_request_t *psr_req)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &psr_req->header);

    if (psr_req->header.s)
        msg_len = psr_req->header.message_len - 12;
    else
        msg_len = psr_req->header.message_len - 4;

    msg = msg + count;
    count = 0;
  while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_REPORT_TYPE) {
            count += decode_report_type_ie_t(msg + count, &psr_req->report_type);
        } else if (ie_type == IE_DOWNLINK_DATA_REPORT) {
            count += decode_downlink_data_report_ie_t(msg + count, &psr_req->downlink_data_report);
        } else if (ie_type == IE_SESSION_REPORT_USAGE_REPORT) {
            count += decode_session_report_usage_report_ie_t(msg + count, &psr_req->usage_report);
        } else if (ie_type == IE_ERROR_INDICATION_REPORT) {
            count += decode_error_indication_report_ie_t(msg + count, &psr_req->error_indication_report);
        } else if (ie_type == IE_LOAD_CONTROL_INFORMATION) {
            count += decode_load_control_information_ie_t(msg + count, &psr_req->load_control_information);
        } else if (ie_type == IE_OVERLOAD_CONTROL_INFORMATION) {
            count += decode_overload_control_information_ie_t(msg + count, &psr_req->overload_control_information);
        } else if (ie_type == IE_ADDITIONAL_USAGE_REPORTS_INFORMATION) {
            count += decode_additional_usage_reports_information_ie_t(msg + count, &psr_req->additional_usage_reports_information);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }
    return count;
}

/**
 * Decodes pfcp session report response to buffer.
 * @param psr_res
 *     pfcp session report response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */

 int decode_pfcp_session_report_response(uint8_t *msg,
    pfcp_session_report_response_t *psr_res)
{
    uint16_t count = 0;
    uint16_t msg_len;

    count = decode_pfcp_header_t(msg + count, &psr_res->header);

    if (psr_res->header.s)
        msg_len = psr_res->header.message_len - 12;
    else
        msg_len = psr_res->header.message_len - 4;

    msg = msg + count;
    count = 0;

    while (count < msg_len) {

        pfcp_ie_header_t *ie_header = (pfcp_ie_header_t *) (msg + count);
	uint16_t ie_type = ntohs(ie_header->type);

        if (ie_type== IE_CAUSE_ID) {
            count += decode_cause_id_ie_t(msg + count, &psr_res->cause);
        } else if (ie_type == IE_OFFENDING_IE) {
            count += decode_offending_ie_t(msg + count, &psr_res->offending_ie);
        } else if (ie_type == IE_SESSION_REPORT_RESPONSE_UPDATE_BAR) {
            count += decode_session_report_response_update_bar_ie_t(msg + count, &psr_res->update_bar);
        } else if (ie_type == IE_PFCPSRRSP_FLAGS) {
            count += decode_pfcpsrrsp_flags_ie_t(msg + count, &psr_res->sxsrrspflags);
        } else {
            count += sizeof(pfcp_ie_header_t) + ntohs(ie_header->len);
        }
    }

    return count;
	
}


