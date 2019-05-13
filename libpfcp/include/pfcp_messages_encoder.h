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

#ifndef _LIBPFCP_ENCODER_H_
#define _LIBPFCP_ENCODER_H_

#include "pfcp_messages.h"


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
	uint8_t *msg);



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
	uint8_t *msg);


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
	uint8_t *msg);



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
	uint8_t *msg);

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
		uint8_t *msg);

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
		uint8_t *msg);

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
		uint8_t *msg);

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
		uint8_t *msg);


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
		uint8_t *msg);

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
		uint8_t *msg);


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
		uint8_t *msg);

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
		uint8_t *msg);

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
		uint8_t *msg);

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
        uint8_t *msg);

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
        uint8_t *msg);

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
        uint8_t *msg);

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
                uint8_t *msg);


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
		uint8_t *msg);
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
        uint8_t *msg);
/**
 * Encodes pfcpsrrsp flags ie to buffer.
 * @param value
 *     pfcpsrrsp flags ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_pfcpsrrsp_flags_ie_t(pfcpsrrsp_flags_ie_t *value,
        uint8_t *buf);
/**
 * Encodes session report response update bar to buffer.
 * @param value
 *     session report response update bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_session_report_response_update_bar_ie_t(session_report_response_update_bar_ie_t *value,
        uint8_t *buf);
/**
 * Encodes dl buffering suggested packet count ie to buffer.
 * @param value
 *     dl buffering suggested packet count ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_dl_buffering_suggested_packet_count_ie_t(dl_buffering_suggested_packet_count_ie_t *value,
        uint8_t *buf);
/**
 * Encodes dl buffering duration ie to buffer.
 * @param value
 *     dl buffering duration ie
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_dl_buffering_duration_ie_t(dl_buffering_duration_ie_t *value,
        uint8_t *buf);
#endif
 /* _LIBPFCP_ENCODER_H_ */
