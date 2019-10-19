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

#ifndef __GTP_MESSAGES_DECODE_H__
#define __GTP_MESSAGES_DECODE_H__


#include "gtp_messages.h"

/**
 * decodes gtpv2c_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     gtpv2c_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_gtpv2c_header_t(uint8_t *buf, gtpv2c_header_t *value);

/**
 * decodes ie_header_t to buffer.
 * @param buf
 *   buffer to store decoded values.
 * @param value
 *     ie_header_t
 * @return
 *   number of decoded bytes.
 */
int decode_ie_header_t(uint8_t *buf,
	ie_header_t *value, uint16_t val_len);

/**
* Decodes echo_request_t to buffer.
* @param value 
*    echo_request_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_echo_request(uint8_t *buf,
    echo_request_t *value);

/**
* Decodes echo_response_t to buffer.
* @param value 
*    echo_response_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_echo_response(uint8_t *buf,
    echo_response_t *value);

/**
* Decodes create_sess_req_t to buffer.
* @param value 
*    create_sess_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_sess_req(uint8_t *buf,
    create_sess_req_t *value);

/**
* Decodes gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t to buffer.
* @param value 
*    gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request_bearer_ctxt_to_be_created_ie(uint8_t *buf,
    gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t *value);

/**
* Decodes gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request_bearer_ctxt_to_be_removed_ie(uint8_t *buf,
    gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t *value);

/**
* Decodes gtp_create_sess_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request__overload_ctl_info_ie(uint8_t *buf,
    gtp_create_sess_request__overload_ctl_info_ie_t *value);

/**
* Decodes gtp_create_sess_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_create_sess_request__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_request__remote_ue_ctxt_connected_ie(uint8_t *buf,
    gtp_create_sess_request__remote_ue_ctxt_connected_ie_t *value);

/**
* Decodes create_sess_rsp_t to buffer.
* @param value 
*    create_sess_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_sess_rsp(uint8_t *buf,
    create_sess_rsp_t *value);

/**
* Decodes gtp_create_sess_response_bearer_ctxt_created_ie_t to buffer.
* @param value 
*    gtp_create_sess_response_bearer_ctxt_created_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response_bearer_ctxt_created_ie(uint8_t *buf,
    gtp_create_sess_response_bearer_ctxt_created_ie_t *value);

/**
* Decodes gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response_bearer_ctxt_marked_removal_ie(uint8_t *buf,
    gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t *value);

/**
* Decodes gtp_create_sess_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_response__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response__load_ctl_info_ie(uint8_t *buf,
    gtp_create_sess_response__load_ctl_info_ie_t *value);

/**
* Decodes gtp_create_sess_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_sess_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_sess_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_create_sess_response__overload_ctl_info_ie_t *value);

/**
* Decodes create_bearer_req_t to buffer.
* @param value 
*    create_bearer_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_bearer_req(uint8_t *buf,
    create_bearer_req_t *value);

/**
* Decodes gtp_create_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request_bearer_ctxt_ie(uint8_t *buf,
    gtp_create_bearer_request_bearer_ctxt_ie_t *value);

/**
* Decodes gtp_create_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request__load_ctl_info_ie(uint8_t *buf,
    gtp_create_bearer_request__load_ctl_info_ie_t *value);

/**
* Decodes gtp_create_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_request__overload_ctl_info_ie(uint8_t *buf,
    gtp_create_bearer_request__overload_ctl_info_ie_t *value);

/**
* Decodes create_bearer_rsp_t to buffer.
* @param value 
*    create_bearer_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_bearer_rsp(uint8_t *buf,
    create_bearer_rsp_t *value);

/**
* Decodes gtp_create_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_response_bearer_ctxt_ie(uint8_t *buf,
    gtp_create_bearer_response_bearer_ctxt_ie_t *value);

/**
* Decodes gtp_create_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_create_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_bearer_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_create_bearer_response__overload_ctl_info_ie_t *value);

/**
* Decodes bearer_rsrc_cmd_t to buffer.
* @param value 
*    bearer_rsrc_cmd_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_bearer_rsrc_cmd(uint8_t *buf,
    bearer_rsrc_cmd_t *value);

/**
* Decodes gtp_bearer_rsrc_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_bearer_rsrc_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_rsrc_command__overload_ctl_info_ie(uint8_t *buf,
    gtp_bearer_rsrc_command__overload_ctl_info_ie_t *value);

/**
* Decodes bearer_rsrc_fail_indctn_t to buffer.
* @param value 
*    bearer_rsrc_fail_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_bearer_rsrc_fail_indctn(uint8_t *buf,
    bearer_rsrc_fail_indctn_t *value);

/**
* Decodes gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie(uint8_t *buf,
    gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t *value);

/**
* Decodes mod_bearer_req_t to buffer.
* @param value 
*    mod_bearer_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_req(uint8_t *buf,
    mod_bearer_req_t *value);

/**
* Decodes gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie(uint8_t *buf,
    gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t *value);

/**
* Decodes gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie(uint8_t *buf,
    gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t *value);

/**
* Decodes gtp_mod_bearer_request_overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_request_overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_request_overload_ctl_info_ie(uint8_t *buf,
    gtp_mod_bearer_request_overload_ctl_info_ie_t *value);

/**
* Decodes mod_bearer_rsp_t to buffer.
* @param value 
*    mod_bearer_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_rsp(uint8_t *buf,
    mod_bearer_rsp_t *value);

/**
* Decodes gtp_mod_bearer_response_bearer_ctxt_modified_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response_bearer_ctxt_modified_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response_bearer_ctxt_modified_ie(uint8_t *buf,
    gtp_mod_bearer_response_bearer_ctxt_modified_ie_t *value);

/**
* Decodes gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie(uint8_t *buf,
    gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t *value);

/**
* Decodes gtp_mod_bearer_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response__load_ctl_info_ie(uint8_t *buf,
    gtp_mod_bearer_response__load_ctl_info_ie_t *value);

/**
* Decodes gtp_mod_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_mod_bearer_response__overload_ctl_info_ie_t *value);

/**
* Decodes del_sess_req_t to buffer.
* @param value 
*    del_sess_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_sess_req(uint8_t *buf,
    del_sess_req_t *value);

/**
* Decodes gtp_del_sess_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_request__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_sess_request__overload_ctl_info_ie_t *value);

/**
* Decodes del_bearer_req_t to buffer.
* @param value 
*    del_bearer_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_req(uint8_t *buf,
    del_bearer_req_t *value);

/**
* Decodes gtp_del_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__bearer_ctxt_ie(uint8_t *buf,
    gtp_del_bearer_request__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_del_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__load_ctl_info_ie(uint8_t *buf,
    gtp_del_bearer_request__load_ctl_info_ie_t *value);

/**
* Decodes gtp_del_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_request__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_bearer_request__overload_ctl_info_ie_t *value);

/**
* Decodes del_sess_rsp_t to buffer.
* @param value 
*    del_sess_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_sess_rsp(uint8_t *buf,
    del_sess_rsp_t *value);

/**
* Decodes gtp_del_sess_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_response__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_response__load_ctl_info_ie(uint8_t *buf,
    gtp_del_sess_response__load_ctl_info_ie_t *value);

/**
* Decodes gtp_del_sess_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_sess_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_sess_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_sess_response__overload_ctl_info_ie_t *value);

/**
* Decodes del_bearer_rsp_t to buffer.
* @param value 
*    del_bearer_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_rsp(uint8_t *buf,
    del_bearer_rsp_t *value);

/**
* Decodes gtp_del_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_response__bearer_ctxt_ie(uint8_t *buf,
    gtp_del_bearer_response__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_del_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_bearer_response__overload_ctl_info_ie_t *value);

/**
* Decodes dnlnk_data_notif_t to buffer.
* @param value 
*    dnlnk_data_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif(uint8_t *buf,
    dnlnk_data_notif_t *value);

/**
* Decodes gtp_dnlnk_data_notification__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_dnlnk_data_notification__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_dnlnk_data_notification__load_ctl_info_ie(uint8_t *buf,
    gtp_dnlnk_data_notification__load_ctl_info_ie_t *value);

/**
* Decodes gtp_dnlnk_data_notification__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_dnlnk_data_notification__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_dnlnk_data_notification__overload_ctl_info_ie(uint8_t *buf,
    gtp_dnlnk_data_notification__overload_ctl_info_ie_t *value);

/**
* Decodes dnlnk_data_notif_ack_t to buffer.
* @param value 
*    dnlnk_data_notif_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif_ack(uint8_t *buf,
    dnlnk_data_notif_ack_t *value);

/**
* Decodes dnlnk_data_notif_fail_indctn_t to buffer.
* @param value 
*    dnlnk_data_notif_fail_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_dnlnk_data_notif_fail_indctn(uint8_t *buf,
    dnlnk_data_notif_fail_indctn_t *value);

/**
* Decodes mod_bearer_cmd_t to buffer.
* @param value 
*    mod_bearer_cmd_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_cmd(uint8_t *buf,
    mod_bearer_cmd_t *value);

/**
* Decodes gtp_mod_bearer_command__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_command__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_command__bearer_ctxt_ie(uint8_t *buf,
    gtp_mod_bearer_command__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_mod_bearer_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_command__overload_ctl_info_ie(uint8_t *buf,
    gtp_mod_bearer_command__overload_ctl_info_ie_t *value);

/**
* Decodes mod_bearer_fail_indctn_t to buffer.
* @param value 
*    mod_bearer_fail_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_bearer_fail_indctn(uint8_t *buf,
    mod_bearer_fail_indctn_t *value);

/**
* Decodes gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_bearer_fail_indication__overload_ctl_info_ie(uint8_t *buf,
    gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t *value);

/**
* Decodes upd_bearer_req_t to buffer.
* @param value 
*    upd_bearer_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_upd_bearer_req(uint8_t *buf,
    upd_bearer_req_t *value);

/**
* Decodes gtp_upd_bearer_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__bearer_ctxt_ie(uint8_t *buf,
    gtp_upd_bearer_request__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_upd_bearer_request__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__load_ctl_info_ie(uint8_t *buf,
    gtp_upd_bearer_request__load_ctl_info_ie_t *value);

/**
* Decodes gtp_upd_bearer_request__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_request__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_request__overload_ctl_info_ie(uint8_t *buf,
    gtp_upd_bearer_request__overload_ctl_info_ie_t *value);

/**
* Decodes upd_bearer_rsp_t to buffer.
* @param value 
*    upd_bearer_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_upd_bearer_rsp(uint8_t *buf,
    upd_bearer_rsp_t *value);

/**
* Decodes gtp_upd_bearer_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_response__bearer_ctxt_ie(uint8_t *buf,
    gtp_upd_bearer_response__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_upd_bearer_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_upd_bearer_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_upd_bearer_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_upd_bearer_response__overload_ctl_info_ie_t *value);

/**
* Decodes del_bearer_cmd_t to buffer.
* @param value 
*    del_bearer_cmd_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_cmd(uint8_t *buf,
    del_bearer_cmd_t *value);

/**
* Decodes gtp_del_bearer_command__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_command__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_command__bearer_ctxt_ie(uint8_t *buf,
    gtp_del_bearer_command__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_del_bearer_command__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_command__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_command__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_bearer_command__overload_ctl_info_ie_t *value);

/**
* Decodes del_bearer_fail_indctn_t to buffer.
* @param value 
*    del_bearer_fail_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_bearer_fail_indctn(uint8_t *buf,
    del_bearer_fail_indctn_t *value);

/**
* Decodes gtp_del_bearer_fail_indication__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_del_bearer_fail_indication__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_fail_indication__bearer_ctxt_ie(uint8_t *buf,
    gtp_del_bearer_fail_indication__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_del_bearer_fail_indication__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_del_bearer_fail_indication__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_del_bearer_fail_indication__overload_ctl_info_ie(uint8_t *buf,
    gtp_del_bearer_fail_indication__overload_ctl_info_ie_t *value);

/**
* Decodes create_indir_data_fwdng_tunn_req_t to buffer.
* @param value 
*    create_indir_data_fwdng_tunn_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_indir_data_fwdng_tunn_req(uint8_t *buf,
    create_indir_data_fwdng_tunn_req_t *value);

/**
* Decodes gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie(uint8_t *buf,
    gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t *value);

/**
* Decodes create_indir_data_fwdng_tunn_rsp_t to buffer.
* @param value 
*    create_indir_data_fwdng_tunn_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_indir_data_fwdng_tunn_rsp(uint8_t *buf,
    create_indir_data_fwdng_tunn_rsp_t *value);

/**
* Decodes gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie(uint8_t *buf,
    gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_release_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_release_acc_bearers_response__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_release_acc_bearers_response__load_ctl_info_ie(uint8_t *buf,
    gtp_release_acc_bearers_response__load_ctl_info_ie_t *value);

/**
* Decodes gtp_release_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_release_acc_bearers_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_release_acc_bearers_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_release_acc_bearers_response__overload_ctl_info_ie_t *value);

/**
* Decodes stop_paging_indctn_t to buffer.
* @param value 
*    stop_paging_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_stop_paging_indctn(uint8_t *buf,
    stop_paging_indctn_t *value);

/**
* Decodes mod_acc_bearers_req_t to buffer.
* @param value 
*    mod_acc_bearers_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_acc_bearers_req(uint8_t *buf,
    mod_acc_bearers_req_t *value);

/**
* Decodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie(uint8_t *buf,
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t *value);

/**
* Decodes gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie(uint8_t *buf,
    gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t *value);

/**
* Decodes mod_acc_bearers_rsp_t to buffer.
* @param value 
*    mod_acc_bearers_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mod_acc_bearers_rsp(uint8_t *buf,
    mod_acc_bearers_rsp_t *value);

/**
* Decodes gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie(uint8_t *buf,
    gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t *value);

/**
* Decodes gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie(uint8_t *buf,
    gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t *value);

/**
* Decodes gtp_mod_acc_bearers_response__load_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__load_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__load_ctl_info_ie(uint8_t *buf,
    gtp_mod_acc_bearers_response__load_ctl_info_ie_t *value);

/**
* Decodes gtp_mod_acc_bearers_response__overload_ctl_info_ie_t to buffer.
* @param value 
*    gtp_mod_acc_bearers_response__overload_ctl_info_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_mod_acc_bearers_response__overload_ctl_info_ie(uint8_t *buf,
    gtp_mod_acc_bearers_response__overload_ctl_info_ie_t *value);

/**
* Decodes rmt_ue_rpt_notif_t to buffer.
* @param value 
*    rmt_ue_rpt_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_rmt_ue_rpt_notif(uint8_t *buf,
    rmt_ue_rpt_notif_t *value);

/**
* Decodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie(uint8_t *buf,
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t *value);

/**
* Decodes gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t to buffer.
* @param value 
*    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie(uint8_t *buf,
    gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t *value);

/**
* Decodes rmt_ue_rpt_ack_t to buffer.
* @param value 
*    rmt_ue_rpt_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_rmt_ue_rpt_ack(uint8_t *buf,
    rmt_ue_rpt_ack_t *value);

/**
* Decodes fwd_reloc_req_t to buffer.
* @param value 
*    fwd_reloc_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_req(uint8_t *buf,
    fwd_reloc_req_t *value);

/**
* Decodes gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie(uint8_t *buf,
    gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t *value);

/**
* Decodes gtp_fwd_reloc_request__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__bearer_ctxt_ie(uint8_t *buf,
    gtp_fwd_reloc_request__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie(uint8_t *buf,
    gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t *value);

/**
* Decodes gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie(uint8_t *buf,
    gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t *value);

/**
* Decodes fwd_reloc_rsp_t to buffer.
* @param value 
*    fwd_reloc_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_rsp(uint8_t *buf,
    fwd_reloc_rsp_t *value);

/**
* Decodes fwd_reloc_cmplt_notif_t to buffer.
* @param value 
*    fwd_reloc_cmplt_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_cmplt_notif(uint8_t *buf,
    fwd_reloc_cmplt_notif_t *value);

/**
* Decodes fwd_reloc_cmplt_ack_t to buffer.
* @param value 
*    fwd_reloc_cmplt_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_reloc_cmplt_ack(uint8_t *buf,
    fwd_reloc_cmplt_ack_t *value);

/**
* Decodes context_request_t to buffer.
* @param value 
*    context_request_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_context_request(uint8_t *buf,
    context_request_t *value);

/**
* Decodes ctxt_rsp_t to buffer.
* @param value 
*    ctxt_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ctxt_rsp(uint8_t *buf,
    ctxt_rsp_t *value);

/**
* Decodes gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie(uint8_t *buf,
    gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t *value);

/**
* Decodes gtp_ctxt_response__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__bearer_ctxt_ie(uint8_t *buf,
    gtp_ctxt_response__bearer_ctxt_ie_t *value);

/**
* Decodes gtp_ctxt_response__remote_ue_ctxt_connected_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__remote_ue_ctxt_connected_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__remote_ue_ctxt_connected_ie(uint8_t *buf,
    gtp_ctxt_response__remote_ue_ctxt_connected_ie_t *value);

/**
* Decodes gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t to buffer.
* @param value 
*    gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie(uint8_t *buf,
    gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t *value);

/**
* Decodes ctxt_ack_t to buffer.
* @param value 
*    ctxt_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ctxt_ack(uint8_t *buf,
    ctxt_ack_t *value);

/**
* Decodes gtp_ctxt_acknowledge__bearer_ctxt_ie_t to buffer.
* @param value 
*    gtp_ctxt_acknowledge__bearer_ctxt_ie_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_gtp_ctxt_acknowledge__bearer_ctxt_ie(uint8_t *buf,
    gtp_ctxt_acknowledge__bearer_ctxt_ie_t *value);

/**
* Decodes id_req_t to buffer.
* @param value 
*    id_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_id_req(uint8_t *buf,
    id_req_t *value);

/**
* Decodes id_rsp_t to buffer.
* @param value 
*    id_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_id_rsp(uint8_t *buf,
    id_rsp_t *value);

/**
* Decodes fwd_acc_ctxt_notif_t to buffer.
* @param value 
*    fwd_acc_ctxt_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_acc_ctxt_notif(uint8_t *buf,
    fwd_acc_ctxt_notif_t *value);

/**
* Decodes fwd_acc_ctxt_ack_t to buffer.
* @param value 
*    fwd_acc_ctxt_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_fwd_acc_ctxt_ack(uint8_t *buf,
    fwd_acc_ctxt_ack_t *value);

/**
* Decodes detach_notif_t to buffer.
* @param value 
*    detach_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_detach_notif(uint8_t *buf,
    detach_notif_t *value);

/**
* Decodes detach_ack_t to buffer.
* @param value 
*    detach_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_detach_ack(uint8_t *buf,
    detach_ack_t *value);

/**
* Decodes reloc_cncl_req_t to buffer.
* @param value 
*    reloc_cncl_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_reloc_cncl_req(uint8_t *buf,
    reloc_cncl_req_t *value);

/**
* Decodes reloc_cncl_rsp_t to buffer.
* @param value 
*    reloc_cncl_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_reloc_cncl_rsp(uint8_t *buf,
    reloc_cncl_rsp_t *value);

/**
* Decodes cfg_xfer_tunn_t to buffer.
* @param value 
*    cfg_xfer_tunn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_cfg_xfer_tunn(uint8_t *buf,
    cfg_xfer_tunn_t *value);

/**
* Decodes ran_info_rly_t to buffer.
* @param value 
*    ran_info_rly_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ran_info_rly(uint8_t *buf,
    ran_info_rly_t *value);

/**
* Decodes isr_status_indctn_t to buffer.
* @param value 
*    isr_status_indctn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_isr_status_indctn(uint8_t *buf,
    isr_status_indctn_t *value);

/**
* Decodes ue_reg_qry_req_t to buffer.
* @param value 
*    ue_reg_qry_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ue_reg_qry_req(uint8_t *buf,
    ue_reg_qry_req_t *value);

/**
* Decodes ue_reg_qry_rsp_t to buffer.
* @param value 
*    ue_reg_qry_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ue_reg_qry_rsp(uint8_t *buf,
    ue_reg_qry_rsp_t *value);

/**
* Decodes alert_mme_ack_t to buffer.
* @param value 
*    alert_mme_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_alert_mme_ack(uint8_t *buf,
    alert_mme_ack_t *value);

/**
* Decodes ue_actvty_ack_t to buffer.
* @param value 
*    ue_actvty_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_ue_actvty_ack(uint8_t *buf,
    ue_actvty_ack_t *value);

/**
* Decodes create_fwdng_tunn_req_t to buffer.
* @param value 
*    create_fwdng_tunn_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_fwdng_tunn_req(uint8_t *buf,
    create_fwdng_tunn_req_t *value);

/**
* Decodes create_fwdng_tunn_rsp_t to buffer.
* @param value 
*    create_fwdng_tunn_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_create_fwdng_tunn_rsp(uint8_t *buf,
    create_fwdng_tunn_rsp_t *value);

/**
* Decodes del_pdn_conn_set_rsp_t to buffer.
* @param value 
*    del_pdn_conn_set_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_del_pdn_conn_set_rsp(uint8_t *buf,
    del_pdn_conn_set_rsp_t *value);

/**
* Decodes upd_pdn_conn_set_req_t to buffer.
* @param value 
*    upd_pdn_conn_set_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_upd_pdn_conn_set_req(uint8_t *buf,
    upd_pdn_conn_set_req_t *value);

/**
* Decodes upd_pdn_conn_set_rsp_t to buffer.
* @param value 
*    upd_pdn_conn_set_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_upd_pdn_conn_set_rsp(uint8_t *buf,
    upd_pdn_conn_set_rsp_t *value);

/**
* Decodes pgw_rstrt_notif_t to buffer.
* @param value 
*    pgw_rstrt_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pgw_rstrt_notif(uint8_t *buf,
    pgw_rstrt_notif_t *value);

/**
* Decodes pgw_rstrt_notif_ack_t to buffer.
* @param value 
*    pgw_rstrt_notif_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pgw_rstrt_notif_ack(uint8_t *buf,
    pgw_rstrt_notif_ack_t *value);

/**
* Decodes pgw_dnlnk_trigrng_notif_t to buffer.
* @param value 
*    pgw_dnlnk_trigrng_notif_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pgw_dnlnk_trigrng_notif(uint8_t *buf,
    pgw_dnlnk_trigrng_notif_t *value);

/**
* Decodes pgw_dnlnk_trigrng_ack_t to buffer.
* @param value 
*    pgw_dnlnk_trigrng_ack_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_pgw_dnlnk_trigrng_ack(uint8_t *buf,
    pgw_dnlnk_trigrng_ack_t *value);

/**
* Decodes trc_sess_actvn_t to buffer.
* @param value 
*    trc_sess_actvn_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trc_sess_actvn(uint8_t *buf,
    trc_sess_actvn_t *value);

/**
* Decodes trc_sess_deact_t to buffer.
* @param value 
*    trc_sess_deact_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_trc_sess_deact(uint8_t *buf,
    trc_sess_deact_t *value);

/**
* Decodes mbms_sess_start_req_t to buffer.
* @param value 
*    mbms_sess_start_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_start_req(uint8_t *buf,
    mbms_sess_start_req_t *value);

/**
* Decodes mbms_sess_start_rsp_t to buffer.
* @param value 
*    mbms_sess_start_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_start_rsp(uint8_t *buf,
    mbms_sess_start_rsp_t *value);

/**
* Decodes mbms_sess_upd_req_t to buffer.
* @param value 
*    mbms_sess_upd_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_upd_req(uint8_t *buf,
    mbms_sess_upd_req_t *value);

/**
* Decodes mbms_sess_upd_rsp_t to buffer.
* @param value 
*    mbms_sess_upd_rsp_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_upd_rsp(uint8_t *buf,
    mbms_sess_upd_rsp_t *value);

/**
* Decodes mbms_sess_stop_req_t to buffer.
* @param value 
*    mbms_sess_stop_req_t
* @param buf
*   buffer to store decoded values.
* @return
*   number of decoded bytes.
*/
int decode_mbms_sess_stop_req(uint8_t *buf,
    mbms_sess_stop_req_t *value);


#endif /*__GTP_MESSAGES_DECODE_H__*/
