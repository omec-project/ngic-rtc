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

#ifndef _LIBPFCP_DECODER_H_
#define _LIBPFCP_DECODER_H_

#include "pfcp_messages.h"


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
	pfcp_association_setup_request_t *pas_req);


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
	pfcp_association_setup_response_t *pas_resp);

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
 pfcp_session_establishment_response_t *pse_res);



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
	pfcp_session_establishment_request_t *pse_req);



/**
 * Decodes create bar to buffer.
 * @param c_bar
 *     create bar
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */


int decode_create_bar(uint8_t *msg,
	create_bar_ie_t *c_bar);


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
	pfcp_session_modification_request_t *psm_req);



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
	pfcp_session_modification_response_t *psm_res);



/**
 * Decodes createdraffic endpoint to buffer.
 * @param ct_end
 *     createdraffic endpoint
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of decoded bytes.
 */
int decode_created_traffic_endpoint_ie_t(uint8_t *msg,
		created_traffic_endpoint_ie_t *ct_end);



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
		pfcp_session_deletion_request_t *psd_req);


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
		pfcp_session_deletion_response_t *psd_res);

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
		pfcp_session_set_deletion_request_t *pssd_req);


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
		pfcp_session_set_deletion_response_t *pssd_res);


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
	pfcp_association_update_request_t *pau_req);


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
	pfcp_association_update_response_t *pau_res);



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
 	pfcp_association_release_request_t *par_req);


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
	pfcp_association_release_response_t *par_res);

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
 	pfcp_node_report_request_t *pnr_req);


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
 	pfcp_node_report_response_t *pnr_res);



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
	pfcp_session_report_request_t *psr_req);


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
 	pfcp_session_report_response_t *psr_res);



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
	pfcp_heartbeat_request_t *ph_req);

int decode_pfcp_heartbeat_response(uint8_t *msg,
	pfcp_heartbeat_response_t *ph_resp);
#endif /* _LIBPFCP_DECODER_H_ */
