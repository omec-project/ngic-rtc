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

#include "../include/pfcp_ies_encoder.h"
#include "../include/pfcp_messages_encoder.h"


void print_buf(uint8_t *buf, uint16_t len) {
	for (int i=0; i< len; i++)
			printf("%02x ", buf[i]);
		printf("\n");
}

/**
 * Encodes pfcp association setup request to buffer.
 * @param pas_req
 *     pfcp association setup request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_setup_request(pfcp_association_setup_request_t *pas_req,
	uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pas_req->header, msg);



	if (pas_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pas_req->node_id), msg + enc_len);


	if (pas_req->recovery_time_stamp.header.len)
		enc_len += encode_recovery_time_stamp_ie_t(&(pas_req->recovery_time_stamp), msg + enc_len);

	//print_buf(msg, enc_len);

	if (pas_req->up_function_features.header.len)
		enc_len += encode_up_function_features_ie_t(&(pas_req->up_function_features), msg + enc_len);

	//print_buf(msg, enc_len);

	if (pas_req->cp_function_features.header.len)
		enc_len += encode_cp_function_features_ie_t(&(pas_req->cp_function_features), msg + enc_len);

	//print_buf(msg, enc_len);

	return enc_len;
}

/**
 * Encodes pfcp association setup response to buffer.
 * @param pas_res
 *     pfcp association setup response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_setup_response(pfcp_association_setup_response_t *pas_res,
	uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pas_res->header, msg);

	if (pas_res->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pas_res->node_id), msg  + enc_len);

	if (pas_res->cause.header.len)
		enc_len += encode_pfcp_cause_ie_t(&(pas_res->cause), msg + enc_len);

	if (pas_res->recovery_time_stamp.header.len)
		enc_len += encode_recovery_time_stamp_ie_t(&(pas_res->recovery_time_stamp), msg + enc_len);

	if (pas_res->up_function_features.header.len)
		enc_len += encode_up_function_features_ie_t(&(pas_res->up_function_features), msg + enc_len);

	if (pas_res->cp_function_features.header.len)
		enc_len += encode_cp_function_features_ie_t(&(pas_res->cp_function_features), msg + enc_len);

	if (pas_res->up_ip_resource_info.header.len)
		enc_len += encode_user_plane_ip_resource_information_ie_t(&(pas_res->up_ip_resource_info), msg + enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session establishment request to buffer.
 * @param pse_req
 *     pfcp session establishment request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_establishment_request(pfcp_session_establishment_request_t *pse_req,
	uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pse_req->header, msg);

	if (pse_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pse_req->node_id), msg + enc_len);

	if (pse_req->cp_fseid.header.len)
		enc_len += encode_f_seid_ie_t(&(pse_req->cp_fseid), msg + enc_len);

	if (pse_req->create_pdr.header.len)
		enc_len += encode_create_pdr_ie_t(&(pse_req->create_pdr), msg + enc_len);

	if (pse_req->create_bar.header.len)
		enc_len += encode_create_bar_ie_t(&(pse_req->create_bar), msg + enc_len);

	if (pse_req->pdn_type.header.len)
		enc_len += encode_pdn_type_ie_t(&(pse_req->pdn_type), msg + enc_len);

	if (pse_req->sgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_req->sgwc_fqcsid), msg + enc_len);

	if (pse_req->mme_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_req->mme_fqcsid), msg + enc_len);

	if (pse_req->pgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_req->pgwc_fqcsid), msg + enc_len);

	if (pse_req->epdg_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_req->epdg_fqcsid), msg + enc_len);

	if (pse_req->twan_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_req->twan_fqcsid), msg + enc_len);

	if (pse_req->user_plane_inactivity_timer.header.len)
		enc_len += encode_user_plane_inactivity_timer_ie_t(&(pse_req->user_plane_inactivity_timer), msg + enc_len);

	if (pse_req->user_id.header.len)
		enc_len += encode_user_id_ie_t(&(pse_req->user_id), msg + enc_len);

	if (pse_req->trace_information.header.len)
		enc_len += encode_trace_information_ie_t(&(pse_req->trace_information), msg + enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session establishment response to buffer.
 * @param pse_res
 *     pfcp session establishment response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_establishment_response(pfcp_session_establishment_response_t *pse_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pse_res->header, msg);

	if (pse_res->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pse_res->node_id), msg+enc_len);

	if (pse_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(pse_res->cause), msg +enc_len);

	if (pse_res->offending_ie.header.len)
		enc_len += encode_offending_ie_ie_t(&(pse_res->offending_ie), msg +enc_len);

	if (pse_res->up_fseid.header.len)
		enc_len += encode_f_seid_ie_t(&(pse_res->up_fseid), msg+enc_len);

	if (pse_res->created_pdr.header.len)
		enc_len += encode_created_pdr_ie_t(&(pse_res->created_pdr), msg + enc_len);

	if (pse_res->load_control_information.header.len)
		enc_len += encode_load_control_information_ie_t(&(pse_res->load_control_information), msg+enc_len);

	if (pse_res->overload_control_information.header.len)
		enc_len += encode_overload_control_information_ie_t(&(pse_res->overload_control_information), msg+enc_len);

	if (pse_res->sgwu_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_res->sgwu_fqcsid), msg+enc_len);

	if (pse_res->pgwu_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pse_res->pgwu_fqcsid), msg+enc_len);

	if (pse_res->failed_rule_id.header.len)
		enc_len += encode_failed_rule_id_ie_t(&(pse_res->failed_rule_id), msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session modification request to buffer.
 * @param psm_req
 *     pfcp session modification request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_modification_request(pfcp_session_modification_request_t *psm_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;
	enc_len += encode_pfcp_header_t(&psm_req->header, msg);

	if (psm_req->cp_fseid.header.len)
		enc_len += encode_f_seid_ie_t(&(psm_req->cp_fseid), msg + enc_len);

	if (psm_req->remove_bar.header.len)
		enc_len += encode_remove_bar_ie_t(&(psm_req->remove_bar), msg+ enc_len);

	if (psm_req->remove_traffic_endpoint.header.len)
		enc_len += encode_remove_traffic_endpoint_ie_t(&(psm_req->remove_traffic_endpoint), msg+ enc_len);

	if (psm_req->create_pdr.header.len)
		enc_len += encode_create_pdr_ie_t(&(psm_req->create_pdr), msg + enc_len);

	if (psm_req->create_bar.header.len)
		enc_len += encode_create_bar_ie_t(&(psm_req->create_bar), msg + enc_len);

	if (psm_req->create_traffic_endpoint.header.len)
		enc_len += encode_create_traffic_endpoint_ie_t(&(psm_req->create_traffic_endpoint), msg+ enc_len);

	if (psm_req->update_qer.header.len)
		enc_len += encode_update_qer_ie_t(&(psm_req->update_qer), msg+ enc_len);

	if (psm_req->update_bar.header.len)
		enc_len += encode_update_bar_ie_t(&(psm_req->update_bar), msg+ enc_len);

	if (psm_req->update_traffic_endpoint.header.len)
		enc_len += encode_update_traffic_endpoint_ie_t(&(psm_req->update_traffic_endpoint), msg+ enc_len);

	if (psm_req->pfcpsmreqflags.header.len)
		enc_len += encode_pfcpsmreq_flags_ie_t(&(psm_req->pfcpsmreqflags), msg+ enc_len);

	if (psm_req->pgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(psm_req->pgwc_fqcsid), msg+ enc_len);

	if (psm_req->sgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(psm_req->sgwc_fqcsid), msg+ enc_len);


	if (psm_req->mme_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(psm_req->mme_fqcsid), msg+ enc_len);

	if (psm_req->epdg_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(psm_req->epdg_fqcsid), msg+ enc_len);

	if (psm_req->twan_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(psm_req->twan_fqcsid), msg+ enc_len);

	if (psm_req->user_plane_inactivity_timer.header.len)
		enc_len += encode_user_plane_inactivity_timer_ie_t(&(psm_req->user_plane_inactivity_timer), msg + enc_len);

	if (psm_req->query_urr_reference.header.len)
		enc_len += encode_query_urr_reference_ie_t(&(psm_req->query_urr_reference), msg+ enc_len);

	if (psm_req->trace_information.header.len)
		enc_len += encode_trace_information_ie_t(&(psm_req->trace_information), msg+ enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session modification response to buffer.
 * @param psm_res
 *     pfcp session modification response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_modification_response(pfcp_session_modification_response_t *psm_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&psm_res->header, msg);

	if (psm_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(psm_res->cause), msg + enc_len);

	if (psm_res->offending_ie.header.len)
		enc_len += encode_offending_ie_ie_t(&(psm_res->offending_ie), msg + enc_len);

	if (psm_res->created_pdr.header.len)
		enc_len += encode_created_pdr_ie_t(&(psm_res->created_pdr), msg + enc_len);

	if (psm_res->load_control_information.header.len)
		enc_len += encode_load_control_information_ie_t(&(psm_res->load_control_information), msg + enc_len);

	if (psm_res->overload_control_information.header.len)
		enc_len += encode_overload_control_information_ie_t(&(psm_res->overload_control_information), msg + enc_len);

	if (psm_res->failed_rule_id.header.len)
		enc_len += encode_failed_rule_id_ie_t(&(psm_res->failed_rule_id), msg + enc_len);

	if (psm_res->additional_usage_reports_information.header.len)
		enc_len += encode_additional_usage_reports_information_ie_t(&(psm_res->additional_usage_reports_information), msg + enc_len);

	if (psm_res->createdupdated_traffic_endpoint.header.len)
		enc_len += encode_created_traffic_endpoint_ie_t(&(psm_res->createdupdated_traffic_endpoint), msg + enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session deletion request to buffer.
 * @param psd_req
 *     pfcp session deletion request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_deletion_request(pfcp_session_deletion_request_t *psd_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&psd_req->header, msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session set deletion request to buffer.
 * @param pssd_req
 *     pfcp session set deletion request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_set_deletion_request(pfcp_session_set_deletion_request_t *pssd_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pssd_req->header, msg +enc_len);

	if (pssd_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pssd_req->node_id), msg +enc_len);

	if (pssd_req->sgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->sgwc_fqcsid), msg+enc_len);

	if (pssd_req->pgwc_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->pgwc_fqcsid), msg+enc_len);

	if (pssd_req->sgwu_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->sgwu_fqcsid), msg+enc_len);

	if (pssd_req->pgwu_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->pgwu_fqcsid), msg+enc_len);

	if (pssd_req->twan_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->twan_fqcsid), msg+enc_len);

	if (pssd_req->epdg_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->epdg_fqcsid), msg+enc_len);

	if (pssd_req->mme_fqcsid.header.len)
		enc_len += encode_fq_csid_ie_t(&(pssd_req->mme_fqcsid), msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session set deletion response to buffer.
 * @param pssd_res
 *     pfcp session set deletion response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_set_deletion_response(pfcp_session_set_deletion_response_t *pssd_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pssd_res->header, msg +enc_len);

	if (pssd_res->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pssd_res->node_id), msg+enc_len);

	if (pssd_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(pssd_res->cause), msg+enc_len);

	if (pssd_res->offending_ie.header.len)
		enc_len += encode_offending_ie_ie_t(&(pssd_res->offending_ie), msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp association update request to buffer.
 * @param pau_req
 *     pfcp association update request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_update_request(pfcp_association_update_request_t *pau_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pau_req->header, msg + enc_len);

	if (pau_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pau_req->node_id), msg + enc_len);

	if (pau_req->up_function_features.header.len)
		enc_len += encode_up_function_features_ie_t(&(pau_req->up_function_features), msg + enc_len);

	if (pau_req->cp_function_features.header.len)
		enc_len += encode_cp_function_features_ie_t(&(pau_req->cp_function_features), msg + enc_len);

	if (pau_req->pfcp_association_release_request.header.len)
		enc_len += encode_pfcp_association_release_request_ie_t(&(pau_req->pfcp_association_release_request), msg + enc_len);

	if (pau_req->graceful_release_period.header.len + enc_len)
		enc_len += encode_graceful_release_period_ie_t(&(pau_req->graceful_release_period), msg + enc_len);
	return enc_len;
}

/**
 * Encodes pfcp association update response to buffer.
 * @param pau_res
 *     pfcp association update response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_update_response(pfcp_association_update_response_t *pau_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pau_res->header, msg + enc_len);

	if (pau_res->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pau_res->node_id), msg + enc_len);

	if (pau_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(pau_res->cause), msg + enc_len);

	if (pau_res->up_function_features.header.len)
		enc_len += encode_up_function_features_ie_t(&(pau_res->up_function_features), msg + enc_len);

	if (pau_res->cp_function_features.header.len)
		enc_len += encode_cp_function_features_ie_t(&(pau_res->cp_function_features), msg + enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session deletion response to buffer.
 * @param psd_res
 *     pfcp session deletion response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_deletion_response(pfcp_session_deletion_response_t *psd_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&psd_res->header, msg +enc_len);

	if (psd_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(psd_res->cause), msg +enc_len);

	if (psd_res->offending_ie.header.len)
		enc_len += encode_offending_ie_ie_t(&(psd_res->offending_ie), msg +enc_len);

	if (psd_res->load_control_information.header.len)
		enc_len += encode_load_control_information_ie_t(&(psd_res->load_control_information), msg +enc_len);

	if (psd_res->overload_control_information.header.len)
		enc_len +=encode_overload_control_information_ie_t(&(psd_res->overload_control_information), msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp association release request to buffer.
 * @param par_req
 *     pfcp association release request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_release_request(pfcp_association_release_request_t *par_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&par_req->header, msg +enc_len);

	if (par_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(par_req->node_id), msg +enc_len);

	return enc_len;
}

/**
 * Encodes pfcp association release response to buffer.
 * @param par_res
 *     pfcp association release response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_association_release_response(pfcp_association_release_response_t *par_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&par_res->header, msg +enc_len);

	if (par_res->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(par_res->node_id), msg +enc_len);

	if (par_res->cause.header.len)
		enc_len += encode_cause_ie_t(&(par_res->cause), msg +enc_len);

	return enc_len;
}

/**
 * Encodes pfcp node report request to buffer.
 * @param pnr_req
 *     pfcp node report request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_node_report_request(pfcp_node_report_request_t *pnr_req,
        uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&pnr_req->header, msg +enc_len);

	if (pnr_req->node_id.header.len)
		enc_len += encode_node_id_ie_t(&(pnr_req->node_id), msg+enc_len);

	if (pnr_req->node_report_type.header.len)
		enc_len += encode_node_report_type_ie_t(&(pnr_req->node_report_type), msg+enc_len);

	if (pnr_req->user_plane_path_failure_report.header.len)
		enc_len += encode_user_plane_path_failure_report_ie_t(&(pnr_req->user_plane_path_failure_report), msg+enc_len);

	return enc_len;
}

/**
 * Encodes pfcp node report response to buffer.
 * @param pnr_res
 *     pfcp node report response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_node_report_response(pfcp_node_report_response_t *pnr_res,
        uint8_t *msg)
{
        uint16_t enc_len = 0;

        enc_len += encode_pfcp_header_t(&pnr_res->header, msg +enc_len);

        if (pnr_res->node_id.header.len)
                enc_len += encode_node_id_ie_t(&(pnr_res->node_id), msg +enc_len);

        if (pnr_res->cause.header.len)
                enc_len += encode_cause_ie_t(&(pnr_res->cause), msg +enc_len);

        if (pnr_res->offending_ie.header.len)
                enc_len += encode_offending_ie_ie_t(&(pnr_res->offending_ie), msg +enc_len);

        return enc_len;
}


/**
 * Encodes pfcp heartbeat request to buffer.
 * @param ph_req
 *     pfcp heartbeat request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_heartbeat_request(pfcp_heartbeat_request_t *ph_req,
        uint8_t *msg)
{
        uint16_t enc_len = 0;

        enc_len += encode_pfcp_header_t(&ph_req->header, msg +enc_len);

        if (ph_req->recovery_time_stamp.header.len)
                enc_len += encode_recovery_time_stamp_ie_t(&(ph_req->recovery_time_stamp), msg +enc_len);

        return enc_len;
}

/**
 * Encodes pfcp heartbeat response to buffer.
 * @param ph_res
 *     pfcp heartbeat response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_heartbeat_response(pfcp_heartbeat_response_t *ph_res,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&ph_res->header, msg + enc_len);

	if (ph_res->recovery_time_stamp.header.len)
		enc_len += encode_recovery_time_stamp_ie_t(&(ph_res->recovery_time_stamp), msg + enc_len);

	return enc_len;

}

/**
 * Encodes pfcp session report request to buffer.
 * @param psr_req
 *     pfcp session report request
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_report_request(pfcp_session_report_request_t *psr_req,
		uint8_t *msg)
{
	uint16_t enc_len = 0;

	enc_len += encode_pfcp_header_t(&psr_req->header, msg + enc_len);

	if (psr_req->report_type.header.len)
		enc_len += encode_report_type_ie_t(&(psr_req->report_type), msg + enc_len);

	if (psr_req->downlink_data_report.header.len)
		enc_len += encode_downlink_data_report_ie_t(&(psr_req->downlink_data_report), msg + enc_len);

	if (psr_req->usage_report.header.len)
		enc_len += encode_session_report_usage_report_ie_t(&(psr_req->usage_report), msg + enc_len);

	if (psr_req->error_indication_report.header.len)
		enc_len += encode_error_indication_report_ie_t(&(psr_req->error_indication_report), msg + enc_len);

	if (psr_req->load_control_information.header.len)
		enc_len += encode_load_control_information_ie_t(&(psr_req->load_control_information), msg + enc_len);

	if (psr_req->overload_control_information.header.len)
		enc_len += encode_overload_control_information_ie_t(&(psr_req->overload_control_information), msg + enc_len);

	if (psr_req->additional_usage_reports_information.header.len)
		enc_len += encode_additional_usage_reports_information_ie_t(&(psr_req->additional_usage_reports_information), msg + enc_len);

	return enc_len;
}

/**
 * Encodes pfcp session report response to buffer.
 * @param psr_res
 *     pfcp session report response
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcp_session_report_response(pfcp_session_report_response_t *psr_res,
        uint8_t *msg)
{
        uint16_t enc_len = 0;

        enc_len += encode_pfcp_header_t(&psr_res->header, msg);

        if (psr_res->cause.header.len)
                enc_len += encode_cause_ie_t(&(psr_res->cause), msg);

        if (psr_res->offending_ie.header.len)
                enc_len += encode_offending_ie_ie_t(&(psr_res->offending_ie), msg);

        if (psr_res->update_bar.header.len)
                enc_len += encode_session_report_response_update_bar_ie_t(&(psr_res->update_bar), msg);
				
	if (psr_res->sxsrrspflags.header.len)
                enc_len += encode_pfcpsrrsp_flags_ie_t(&(psr_res->sxsrrspflags), msg);

        return enc_len;
}

