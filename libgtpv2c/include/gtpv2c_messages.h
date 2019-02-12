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

#ifndef _LIBGTPV2C_MESSAGES_H_
#define _LIBGTPV2C_MESSAGES_H_

#include "req_resp.h"

/**
 * Encodes the create session rquest structure to buffer.
 * @param val
 *   create session request structure pre-populated
 * @param msg
 *   buffer containing encoded create session request values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_create_session_request_t(create_session_request_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Encodes the create session response structure to buffer.
 * @param val
 *   create session response structure pre-populated
 * @param msg
 *   buffer containing encoded create session response values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_create_session_response_t(create_session_response_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Encodes the modify bearer rquest structure to buffer.
 * @param val
 *   modify bearer request structure pre-populated
 * @param msg
 *   buffer containing encoded modify bearer request values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_modify_bearer_request_t(modify_bearer_request_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Encodes the modify bearer response structure to buffer.
 * @param val
 *   modify bearer response structure pre-populated
 * @param msg
 *   buffer containing encoded modify bearer response values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_modify_bearer_response_t(modify_bearer_response_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Encodes the delete session rquest structure to buffer.
 * @param val
 *   delete session request structure pre-populated
 * @param msg
 *   buffer containing encoded delete session request values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_delete_session_request_t(delete_session_request_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Encodes the delete session response structure to buffer.
 * @param val
 *   delete session response structure pre-populated
 * @param msg
 *   buffer containing encoded delete session response values.
 * @param msg_len
 *   length of buffer containing encoded values.
 * @return
 *   number of encoded bytes.
 */
int
encode_delete_session_response_t(delete_session_response_t *val,
		uint8_t *msg, uint16_t *msg_len);

/**
 * Decodes received buffer to create session request structure.
 * @param msg
 *   buffer containing encoded create session request values.
 * @param val
 *   create session request structure
 * @return
 *   number of decoded bytes.
 */
int
decode_create_session_request_t(uint8_t *msg,
		create_session_request_t *cs_req);

/**
 * Decodes received buffer to create session response structure.
 * @param msg
 *   buffer containing encoded create session response values.
 * @param val
 *   create session response structure
 * @return
 *   number of decoded bytes.
 */
int
decode_create_session_response_t(uint8_t *msg,
		create_session_response_t *cs_resp);

/**
 * Decodes received buffer to modify bearer request structure.
 * @param msg
 *   buffer containing encoded modify bearer request values.
 * @param val
 *   modify bearer request structure
 * @return
 *   number of decoded bytes.
 */
int
decode_modify_bearer_request_t(uint8_t *msg,
		modify_bearer_request_t *mb_req);

/**
 * Decodes received buffer to modify bearer response structure.
 * @param msg
 *   buffer containing encoded modify bearer response values.
 * @param val
 *   modify bearer response structure
 * @return
 *   number of decoded bytes.
 */
int
decode_modify_bearer_response_t(uint8_t *msg,
		modify_bearer_response_t *mb_resp);

/**
 * Decodes received buffer to delete session request structure.
 * @param msg
 *   buffer containing encoded delete session request values.
 * @param val
 *   delete session request structure
 * @return
 *   number of decoded bytes.
 */
int
decode_delete_session_request_t(uint8_t *msg,
		delete_session_request_t *ds_req);

/**
 * Decodes received buffer to delete session response structure.
 * @param msg
 *   buffer containing encoded delete session response values.
 * @param val
 *   delete session response structure
 * @return
 *   number of decoded bytes.
 */
int
decode_delete_session_response_t(uint8_t *msg,
		delete_session_response_t *ds_resp);

#endif /* _LIBGTPV2C_MESSAGES_H_ */
