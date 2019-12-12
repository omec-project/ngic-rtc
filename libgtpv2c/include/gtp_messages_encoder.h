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

#ifndef __GTP_MESSAGES_ENCODE_H__
#define __GTP_MESSAGES_ENCODE_H__


#include "gtp_messages.h"

#define MBR_BUF_SIZE 5

/**
 * Encodes gtpv2c_header_t to buffer.
 * @param value
 *    gtpv2c_header_t
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_gtpv2c_header_t(gtpv2c_header_t *value,
	uint8_t *buf);

/**
 * Encodes ie_header_t to buffer.
 * @param value
 *     ie_header_t
 * @param buf
 *   buffer to store encoded values.
 * @return
 *   number of encoded bytes.
 */
int encode_ie_header_t(ie_header_t *value,
	uint8_t *buf);

/**
* Encodes echo_request_t to buffer.
* @param value 
*    echo_request_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_echo_request(echo_request_t *value,
    uint8_t *buf);

/**
* Encodes echo_response_t to buffer.
* @param value 
*    echo_response_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_echo_response(echo_response_t *value,
    uint8_t *buf);

/**
* Encodes create_sess_req_t to buffer.
* @param value 
*    create_sess_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_sess_req(create_sess_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t to buffer.
* @param value 
*    gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request__overload_ctl_info_ie(gtp_create_sess_request__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_create_sess_request__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_request__remote_ue_ctxt_connected_ie(gtp_create_sess_request__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf);

/**
* Encodes create_sess_rsp_t to buffer.
* @param value 
*    create_sess_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_sess_rsp(create_sess_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_response_bearer_ctxt_created_ie_t to buffer.
* @param value 
*    gtp_create_sess_response_bearer_ctxt_created_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response_bearer_ctxt_created_ie(gtp_create_sess_response_bearer_ctxt_created_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_response__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response__load_ctl_info_ie(gtp_create_sess_response__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_sess_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_sess_response__overload_ctl_info_ie(gtp_create_sess_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes create_bearer_req_t to buffer.
* @param value 
*    create_bearer_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_bearer_req(create_bearer_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request_bearer_ctxt_ie(gtp_create_bearer_request_bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request__load_ctl_info_ie(gtp_create_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_request__overload_ctl_info_ie(gtp_create_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes create_bearer_rsp_t to buffer.
* @param value 
*    create_bearer_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_bearer_rsp(create_bearer_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_response_bearer_ctxt_ie(gtp_create_bearer_response_bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_bearer_response__overload_ctl_info_ie(gtp_create_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes bearer_rsrc_cmd_t to buffer.
* @param value 
*    bearer_rsrc_cmd_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_bearer_rsrc_cmd(bearer_rsrc_cmd_t *value,
    uint8_t *buf);

/**
* Encodes gtp_bearer_rsrc_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_bearer_rsrc_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_rsrc_command__overload_ctl_info_ie(gtp_bearer_rsrc_command__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes bearer_rsrc_fail_indctn_t to buffer.
* @param value 
*    bearer_rsrc_fail_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_bearer_rsrc_fail_indctn(bearer_rsrc_fail_indctn_t *value,
    uint8_t *buf);

/**
* Encodes gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie(gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes mod_bearer_req_t to buffer.
* @param value 
*    mod_bearer_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_req(mod_bearer_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_request_overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_request_overload_ctl_info_ie(gtp_mod_bearer_request_overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes mod_bearer_rsp_t to buffer.
* @param value 
*    mod_bearer_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_rsp(mod_bearer_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_response_bearer_ctxt_modified_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response_bearer_ctxt_modified_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(gtp_mod_bearer_response_bearer_ctxt_modified_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response__load_ctl_info_ie(gtp_mod_bearer_response__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_response__overload_ctl_info_ie(gtp_mod_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_sess_req_t to buffer.
* @param value 
*    del_sess_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_sess_req(del_sess_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_sess_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_request__overload_ctl_info_ie(gtp_del_sess_request__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_bearer_req_t to buffer.
* @param value 
*    del_bearer_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_req(del_bearer_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__bearer_ctxt_ie(gtp_del_bearer_request__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__load_ctl_info_ie(gtp_del_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_request__overload_ctl_info_ie(gtp_del_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_sess_rsp_t to buffer.
* @param value 
*    del_sess_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_sess_rsp(del_sess_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_sess_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_response__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_response__load_ctl_info_ie(gtp_del_sess_response__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_sess_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_sess_response__overload_ctl_info_ie(gtp_del_sess_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_bearer_rsp_t to buffer.
* @param value 
*    del_bearer_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_rsp(del_bearer_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_response__bearer_ctxt_ie(gtp_del_bearer_response__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_response__overload_ctl_info_ie(gtp_del_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes dnlnk_data_notif_t to buffer.
* @param value 
*    dnlnk_data_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif(dnlnk_data_notif_t *value,
    uint8_t *buf);

/**
* Encodes gtp_dnlnk_data_notification__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_dnlnk_data_notification__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_dnlnk_data_notification__load_ctl_info_ie(gtp_dnlnk_data_notification__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_dnlnk_data_notification__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_dnlnk_data_notification__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_dnlnk_data_notification__overload_ctl_info_ie(gtp_dnlnk_data_notification__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes dnlnk_data_notif_ack_t to buffer.
* @param value 
*    dnlnk_data_notif_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif_ack(dnlnk_data_notif_ack_t *value,
    uint8_t *buf);

/**
* Encodes dnlnk_data_notif_fail_indctn_t to buffer.
* @param value 
*    dnlnk_data_notif_fail_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_dnlnk_data_notif_fail_indctn(dnlnk_data_notif_fail_indctn_t *value,
    uint8_t *buf);

/**
* Encodes mod_bearer_cmd_t to buffer.
* @param value 
*    mod_bearer_cmd_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_cmd(mod_bearer_cmd_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_command__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_command__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_command__bearer_ctxt_ie(gtp_mod_bearer_command__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_command__overload_ctl_info_ie(gtp_mod_bearer_command__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes mod_bearer_fail_indctn_t to buffer.
* @param value 
*    mod_bearer_fail_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_bearer_fail_indctn(mod_bearer_fail_indctn_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_bearer_fail_indication__overload_ctl_info_ie(gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes upd_bearer_req_t to buffer.
* @param value 
*    upd_bearer_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_upd_bearer_req(upd_bearer_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_upd_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__bearer_ctxt_ie(gtp_upd_bearer_request__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_upd_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__load_ctl_info_ie(gtp_upd_bearer_request__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_upd_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_request__overload_ctl_info_ie(gtp_upd_bearer_request__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes upd_bearer_rsp_t to buffer.
* @param value 
*    upd_bearer_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_upd_bearer_rsp(upd_bearer_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_upd_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_response__bearer_ctxt_ie(gtp_upd_bearer_response__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_upd_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_upd_bearer_response__overload_ctl_info_ie(gtp_upd_bearer_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_bearer_cmd_t to buffer.
* @param value 
*    del_bearer_cmd_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_cmd(del_bearer_cmd_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_command__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_command__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_command__bearer_ctxt_ie(gtp_del_bearer_command__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_command__overload_ctl_info_ie(gtp_del_bearer_command__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes del_bearer_fail_indctn_t to buffer.
* @param value 
*    del_bearer_fail_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_bearer_fail_indctn(del_bearer_fail_indctn_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_fail_indication__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_fail_indication__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_fail_indication__bearer_ctxt_ie(gtp_del_bearer_fail_indication__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_del_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_del_bearer_fail_indication__overload_ctl_info_ie(gtp_del_bearer_fail_indication__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes create_indir_data_fwdng_tunn_req_t to buffer.
* @param value 
*    create_indir_data_fwdng_tunn_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_indir_data_fwdng_tunn_req(create_indir_data_fwdng_tunn_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie(gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes create_indir_data_fwdng_tunn_rsp_t to buffer.
* @param value 
*    create_indir_data_fwdng_tunn_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_indir_data_fwdng_tunn_rsp(create_indir_data_fwdng_tunn_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie(gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_release_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_release_acc_bearers_response__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_release_acc_bearers_response__load_ctl_info_ie(gtp_release_acc_bearers_response__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_release_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_release_acc_bearers_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_release_acc_bearers_response__overload_ctl_info_ie(gtp_release_acc_bearers_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes stop_paging_indctn_t to buffer.
* @param value 
*    stop_paging_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_stop_paging_indctn(stop_paging_indctn_t *value,
    uint8_t *buf);

/**
* Encodes mod_acc_bearers_req_t to buffer.
* @param value 
*    mod_acc_bearers_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_acc_bearers_req(mod_acc_bearers_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie(gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie(gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t *value,
    uint8_t *buf);

/**
* Encodes mod_acc_bearers_rsp_t to buffer.
* @param value 
*    mod_acc_bearers_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mod_acc_bearers_rsp(mod_acc_bearers_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie(gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie(gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__load_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__load_ctl_info_ie(gtp_mod_acc_bearers_response__load_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_mod_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_mod_acc_bearers_response__overload_ctl_info_ie(gtp_mod_acc_bearers_response__overload_ctl_info_ie_t *value,
    uint8_t *buf);

/**
* Encodes rmt_ue_rpt_notif_t to buffer.
* @param value 
*    rmt_ue_rpt_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_rmt_ue_rpt_notif(rmt_ue_rpt_notif_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie(gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie(gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t *value,
    uint8_t *buf);

/**
* Encodes rmt_ue_rpt_ack_t to buffer.
* @param value 
*    rmt_ue_rpt_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_rmt_ue_rpt_ack(rmt_ue_rpt_ack_t *value,
    uint8_t *buf);

/**
* Encodes fwd_reloc_req_t to buffer.
* @param value 
*    fwd_reloc_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_req(fwd_reloc_req_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie(gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fwd_reloc_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__bearer_ctxt_ie(gtp_fwd_reloc_request__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie(gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie(gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t *value,
    uint8_t *buf);

/**
* Encodes fwd_reloc_rsp_t to buffer.
* @param value 
*    fwd_reloc_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_rsp(fwd_reloc_rsp_t *value,
    uint8_t *buf);

/**
* Encodes fwd_reloc_cmplt_notif_t to buffer.
* @param value 
*    fwd_reloc_cmplt_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_cmplt_notif(fwd_reloc_cmplt_notif_t *value,
    uint8_t *buf);

/**
* Encodes fwd_reloc_cmplt_ack_t to buffer.
* @param value 
*    fwd_reloc_cmplt_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_reloc_cmplt_ack(fwd_reloc_cmplt_ack_t *value,
    uint8_t *buf);

/**
* Encodes context_request_t to buffer.
* @param value 
*    context_request_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_context_request(context_request_t *value,
    uint8_t *buf);

/**
* Encodes ctxt_rsp_t to buffer.
* @param value 
*    ctxt_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ctxt_rsp(ctxt_rsp_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie(gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ctxt_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__bearer_ctxt_ie(gtp_ctxt_response__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ctxt_response__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__remote_ue_ctxt_connected_ie(gtp_ctxt_response__remote_ue_ctxt_connected_ie_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie(gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t *value,
    uint8_t *buf);

/**
* Encodes ctxt_ack_t to buffer.
* @param value 
*    ctxt_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ctxt_ack(ctxt_ack_t *value,
    uint8_t *buf);

/**
* Encodes gtp_ctxt_acknowledge__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_ctxt_acknowledge__bearer_ctxt_ie_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_gtp_ctxt_acknowledge__bearer_ctxt_ie(gtp_ctxt_acknowledge__bearer_ctxt_ie_t *value,
    uint8_t *buf);

/**
* Encodes id_req_t to buffer.
* @param value 
*    id_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_id_req(id_req_t *value,
    uint8_t *buf);

/**
* Encodes id_rsp_t to buffer.
* @param value 
*    id_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_id_rsp(id_rsp_t *value,
    uint8_t *buf);

/**
* Encodes fwd_acc_ctxt_notif_t to buffer.
* @param value 
*    fwd_acc_ctxt_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_acc_ctxt_notif(fwd_acc_ctxt_notif_t *value,
    uint8_t *buf);

/**
* Encodes fwd_acc_ctxt_ack_t to buffer.
* @param value 
*    fwd_acc_ctxt_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_fwd_acc_ctxt_ack(fwd_acc_ctxt_ack_t *value,
    uint8_t *buf);

/**
* Encodes detach_notif_t to buffer.
* @param value 
*    detach_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_detach_notif(detach_notif_t *value,
    uint8_t *buf);

/**
* Encodes detach_ack_t to buffer.
* @param value 
*    detach_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_detach_ack(detach_ack_t *value,
    uint8_t *buf);

/**
* Encodes reloc_cncl_req_t to buffer.
* @param value 
*    reloc_cncl_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_reloc_cncl_req(reloc_cncl_req_t *value,
    uint8_t *buf);

/**
* Encodes reloc_cncl_rsp_t to buffer.
* @param value 
*    reloc_cncl_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_reloc_cncl_rsp(reloc_cncl_rsp_t *value,
    uint8_t *buf);

/**
* Encodes cfg_xfer_tunn_t to buffer.
* @param value 
*    cfg_xfer_tunn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_cfg_xfer_tunn(cfg_xfer_tunn_t *value,
    uint8_t *buf);

/**
* Encodes ran_info_rly_t to buffer.
* @param value 
*    ran_info_rly_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ran_info_rly(ran_info_rly_t *value,
    uint8_t *buf);

/**
* Encodes isr_status_indctn_t to buffer.
* @param value 
*    isr_status_indctn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_isr_status_indctn(isr_status_indctn_t *value,
    uint8_t *buf);

/**
* Encodes ue_reg_qry_req_t to buffer.
* @param value 
*    ue_reg_qry_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ue_reg_qry_req(ue_reg_qry_req_t *value,
    uint8_t *buf);

/**
* Encodes ue_reg_qry_rsp_t to buffer.
* @param value 
*    ue_reg_qry_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ue_reg_qry_rsp(ue_reg_qry_rsp_t *value,
    uint8_t *buf);

/**
* Encodes alert_mme_ack_t to buffer.
* @param value 
*    alert_mme_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_alert_mme_ack(alert_mme_ack_t *value,
    uint8_t *buf);

/**
* Encodes ue_actvty_ack_t to buffer.
* @param value 
*    ue_actvty_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_ue_actvty_ack(ue_actvty_ack_t *value,
    uint8_t *buf);

/**
* Encodes create_fwdng_tunn_req_t to buffer.
* @param value 
*    create_fwdng_tunn_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_fwdng_tunn_req(create_fwdng_tunn_req_t *value,
    uint8_t *buf);

/**
* Encodes create_fwdng_tunn_rsp_t to buffer.
* @param value 
*    create_fwdng_tunn_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_create_fwdng_tunn_rsp(create_fwdng_tunn_rsp_t *value,
    uint8_t *buf);

/**
* Encodes del_pdn_conn_set_rsp_t to buffer.
* @param value 
*    del_pdn_conn_set_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_del_pdn_conn_set_rsp(del_pdn_conn_set_rsp_t *value,
    uint8_t *buf);

/**
* Encodes upd_pdn_conn_set_req_t to buffer.
* @param value 
*    upd_pdn_conn_set_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_upd_pdn_conn_set_req(upd_pdn_conn_set_req_t *value,
    uint8_t *buf);

/**
* Encodes upd_pdn_conn_set_rsp_t to buffer.
* @param value 
*    upd_pdn_conn_set_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_upd_pdn_conn_set_rsp(upd_pdn_conn_set_rsp_t *value,
    uint8_t *buf);

/**
* Encodes pgw_rstrt_notif_t to buffer.
* @param value 
*    pgw_rstrt_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pgw_rstrt_notif(pgw_rstrt_notif_t *value,
    uint8_t *buf);

/**
* Encodes pgw_rstrt_notif_ack_t to buffer.
* @param value 
*    pgw_rstrt_notif_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pgw_rstrt_notif_ack(pgw_rstrt_notif_ack_t *value,
    uint8_t *buf);

/**
* Encodes pgw_dnlnk_trigrng_notif_t to buffer.
* @param value 
*    pgw_dnlnk_trigrng_notif_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pgw_dnlnk_trigrng_notif(pgw_dnlnk_trigrng_notif_t *value,
    uint8_t *buf);

/**
* Encodes pgw_dnlnk_trigrng_ack_t to buffer.
* @param value 
*    pgw_dnlnk_trigrng_ack_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_pgw_dnlnk_trigrng_ack(pgw_dnlnk_trigrng_ack_t *value,
    uint8_t *buf);

/**
* Encodes trc_sess_actvn_t to buffer.
* @param value 
*    trc_sess_actvn_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trc_sess_actvn(trc_sess_actvn_t *value,
    uint8_t *buf);

/**
* Encodes trc_sess_deact_t to buffer.
* @param value 
*    trc_sess_deact_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_trc_sess_deact(trc_sess_deact_t *value,
    uint8_t *buf);

/**
* Encodes mbms_sess_start_req_t to buffer.
* @param value 
*    mbms_sess_start_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_start_req(mbms_sess_start_req_t *value,
    uint8_t *buf);

/**
* Encodes mbms_sess_start_rsp_t to buffer.
* @param value 
*    mbms_sess_start_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_start_rsp(mbms_sess_start_rsp_t *value,
    uint8_t *buf);

/**
* Encodes mbms_sess_upd_req_t to buffer.
* @param value 
*    mbms_sess_upd_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_upd_req(mbms_sess_upd_req_t *value,
    uint8_t *buf);

/**
* Encodes mbms_sess_upd_rsp_t to buffer.
* @param value 
*    mbms_sess_upd_rsp_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_upd_rsp(mbms_sess_upd_rsp_t *value,
    uint8_t *buf);

/**
* Encodes mbms_sess_stop_req_t to buffer.
* @param value 
*    mbms_sess_stop_req_t
* @param buf
*   buffer to store encoded values.
* @return
*   number of encoded bytes.
*/
int encode_mbms_sess_stop_req(mbms_sess_stop_req_t *value,
    uint8_t *buf);


#endif /*__GTP_MESSAGES_ENCODE_H__*/
