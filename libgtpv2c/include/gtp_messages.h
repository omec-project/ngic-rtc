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


#ifndef __GTP_MESSAGES_H
#define __GTP_MESSAGES_H


#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#include "gtp_ies.h"
#include "sv_ies.h"
#define CHAR_SIZE 8
#define ECHO_REQUEST (1)
#define ECHO_RESPONSE (2)
#define CREATE_SESS_REQ (32)
#define GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_CREATED (93)
#define GTP_IE_CREATE_SESS_REQUEST_BEARER_CTXT_TO_BE_REMOVED (93)
#define GTP_IE_CREATE_SESS_REQUEST__OVERLOAD_CTL_INFO (180)
#define GTP_IE_CREATE_SESS_REQUEST__REMOTE_UE_CTXT_CONNECTED (191)
#define CREATE_SESS_RSP (33)
#define GTP_IE_CREATE_SESS_RESPONSE_BEARER_CTXT_CREATED (93)
#define GTP_IE_CREATE_SESS_RESPONSE_BEARER_CTXT_MARKED_REMOVAL (93)
#define GTP_IE_CREATE_SESS_RESPONSE__LOAD_CTL_INFO (181)
#define GTP_IE_CREATE_SESS_RESPONSE__OVERLOAD_CTL_INFO (180)
#define CREATE_BEARER_REQ (95)
#define GTP_IE_CREATE_BEARER_REQUEST__BEARER_CTXT (93)
#define GTP_IE_CREATE_BEARER_REQUEST__LOAD_CTL_INFO (181)
#define GTP_IE_CREATE_BEARER_REQUEST__OVERLOAD_CTL_INFO (181)
#define CREATE_BEARER_RSP (96)
#define GTP_IE_CREATE_BEARER_RESPONSE__BEARER_CTXT (93)
#define GTP_IE_CREATE_BEARER_RESPONSE__OVERLOAD_CTL_INFO (180)
#define BEARER_RSRC_CMD (68)
#define GTP_IE_BEARER_RSRC_COMMAND__OVERLOAD_CTL_INFO (180)
#define BEARER_RSRC_FAIL_INDCTN (69)
#define GTP_IE_BEARER_RSRC_FAIL_INDICATION__OVERLOAD_CTL_INFO (180)
#define MOD_BEARER_REQ (34)
#define GTP_IE_MOD_BEARER_REQUEST_BEARER_CTXT_TO_BE_MODIFIED (93)
#define GTP_IE_MOD_BEARER_REQUEST_BEARER_CTXT_TO_BE_REMOVED (93)
#define GTP_IE_MOD_BEARER_REQUEST_OVERLOAD_CTL_INFO (180)
#define MOD_BEARER_RSP (35)
#define GTP_IE_MOD_BEARER_RESPONSE_BEARER_CTXT_MODIFIED (93)
#define GTP_IE_MOD_BEARER_RESPONSE_BEARER_CTXT_MARKED_REMOVAL (93)
#define GTP_IE_MOD_BEARER_RESPONSE__LOAD_CTL_INFO (181)
#define GTP_IE_MOD_BEARER_RESPONSE__OVERLOAD_CTL_INFO (180)
#define DEL_SESS_REQ (36)
#define GTP_IE_DEL_SESS_REQUEST__OVERLOAD_CTL_INFO (180)
#define DEL_BEARER_REQ (99)
#define GTP_IE_DEL_BEARER_REQUEST__BEARER_CTXT (93)
#define GTP_IE_DEL_BEARER_REQUEST__LOAD_CTL_INFO (181)
#define GTP_IE_DEL_BEARER_REQUEST__OVERLOAD_CTL_INFO (180)
#define DEL_SESS_RSP (37)
#define GTP_IE_DEL_SESS_RESPONSE__LOAD_CTL_INFO (181)
#define GTP_IE_DEL_SESS_RESPONSE__OVERLOAD_CTL_INFO (180)
#define DEL_BEARER_RSP (100)
#define GTP_IE_DEL_BEARER_RESPONSE__BEARER_CTXT (93)
#define GTP_IE_DEL_BEARER_RESPONSE__OVERLOAD_CTL_INFO (180)
#define DNLNK_DATA_NOTIF (176)
#define GTP_IE_DNLNK_DATA_NOTIFICATION__LOAD_CTL_INFO (181)
#define GTP_IE_DNLNK_DATA_NOTIFICATION__OVERLOAD_CTL_INFO (180)
#define DNLNK_DATA_NOTIF_ACK (177)
#define DNLNK_DATA_NOTIF_FAIL_INDCTN (70)
#define MOD_BEARER_CMD (64)
#define GTP_IE_MOD_BEARER_COMMAND__BEARER_CTXT (93)
#define GTP_IE_MOD_BEARER_COMMAND__OVERLOAD_CTL_INFO (181)
#define MOD_BEARER_FAIL_INDCTN (65)
#define GTP_IE_MOD_BEARER_FAIL_INDICATION__OVERLOAD_CTL_INFO (180)
#define UPD_BEARER_REQ (97)
#define GTP_IE_UPD_BEARER_REQUEST__BEARER_CTXT (93)
#define GTP_IE_UPD_BEARER_REQUEST__LOAD_CTL_INFO (181)
#define GTP_IE_UPD_BEARER_REQUEST__OVERLOAD_CTL_INFO (180)
#define UPD_BEARER_RSP (98)
#define GTP_IE_UPD_BEARER_RESPONSE__BEARER_CTXT (93)
#define GTP_IE_UPD_BEARER_RESPONSE__OVERLOAD_CTL_INFO (180)
#define DEL_BEARER_CMD (66)
#define GTP_IE_DEL_BEARER_COMMAND__BEARER_CTXT (93)
#define GTP_IE_DEL_BEARER_COMMAND__OVERLOAD_CTL_INFO (180)
#define DEL_BEARER_FAIL_INDCTN (67)
#define GTP_IE_DEL_BEARER_FAIL_INDICATION__BEARER_CTXT (93)
#define GTP_IE_DEL_BEARER_FAIL_INDICATION__OVERLOAD_CTL_INFO (180)
#define CREATE_INDIR_DATA_FWDNG_TUNN_REQ (166)
#define GTP_IE_CREATE_INDIR_DATA_FWDNG_TUNN_REQUEST__BEARER_CTXT (93)
#define CREATE_INDIR_DATA_FWDNG_TUNN_RSP (167)
#define GTP_IE_CREATE_INDIR_DATA_FWDNG_TUNN_RESPONSE__BEARER_CTXT (93)
#define GTP_IE_RELEASE_ACC_BEARERS_RESPONSE__LOAD_CTL_INFO (181)
#define GTP_IE_RELEASE_ACC_BEARERS_RESPONSE__OVERLOAD_CTL_INFO (180)
#define STOP_PAGING_INDCTN (73)
#define MOD_ACC_BEARERS_REQ (211)
#define GTP_IE_MOD_ACC_BEARERS_REQUEST__BEARER_CTXT_TO_BE_MODIFIED (93)
#define GTP_IE_MOD_ACC_BEARERS_REQUEST__BEARER_CTXT_TO_BE_REMOVED (93)
#define MOD_ACC_BEARERS_RSP (212)
#define GTP_IE_MOD_ACC_BEARERS_RESPONSE__BEARER_CTXT_MODIFIED (93)
#define GTP_IE_MOD_ACC_BEARERS_RESPONSE__BEARER_CTXT_MARKED_REMOVAL (93)
#define GTP_IE_MOD_ACC_BEARERS_RESPONSE__LOAD_CTL_INFO (181)
#define GTP_IE_MOD_ACC_BEARERS_RESPONSE__OVERLOAD_CTL_INFO (180)
#define RMT_UE_RPT_NOTIF (40)
#define GTP_IE_RMT_UE_RPT_NOTIFICATION__REMOTE_UE_CTXT_CONNECTED (191)
#define GTP_IE_RMT_UE_RPT_NOTIFICATION__REMOTE_UE_CTXT_DISCONNECTED (191)
#define RMT_UE_RPT_ACK (41)
#define FWD_RELOC_REQ (133)
#define GTP_IE_FWD_RELOC_REQUEST__MMESGSNAMF_UE_EPS_PDN_CONNECTIONS (109)
#define GTP_IE_FWD_RELOC_REQUEST__BEARER_CTXT (93)
#define GTP_IE_FWD_RELOC_REQUEST__REMOTE_UE_CTXT_CONNECTED (191)
#define GTP_IE_FWD_RELOC_REQUEST__MME_UE_SCEF_PDN_CONNECTIONS (195)
#define FWD_RELOC_RSP (134)
#define FWD_RELOC_CMPLT_NOTIF (135)
#define FWD_RELOC_CMPLT_ACK (136)
#define CONTEXT_REQUEST (130)
#define CTXT_RSP (131)
#define GTP_IE_CTXT_RESPONSE__MMESGSN_UE_EPS_PDN_CONNECTIONS (109)
#define GTP_IE_CTXT_RESPONSE__BEARER_CTXT (93)
#define GTP_IE_CTXT_RESPONSE__REMOTE_UE_CTXT_CONNECTED (191)
#define GTP_IE_CTXT_RESPONSE__MMESGSN_UE_SCEF_PDN_CONNECTIONS (x)
#define CTXT_ACK (132)
#define GTP_IE_CTXT_ACKNOWLEDGE__BEARER_CTXT (93)
#define ID_REQ (128)
#define ID_RSP (129)
#define FWD_ACC_CTXT_NOTIF (137)
#define FWD_ACC_CTXT_ACK (138)
#define DETACH_NOTIF (149)
#define DETACH_ACK (150)
#define RELOC_CNCL_REQ (139)
#define RELOC_CNCL_RSP (140)
#define CFG_XFER_TUNN (141)
#define RAN_INFO_RLY (152)
#define ISR_STATUS_INDCTN (157)
#define UE_REG_QRY_REQ (158)
#define UE_REG_QRY_RSP (159)
#define ALERT_MME_ACK (154)
#define UE_ACTVTY_ACK (156)
#define CREATE_FWDNG_TUNN_REQ (160)
#define CREATE_FWDNG_TUNN_RSP (161)
#define DEL_PDN_CONN_SET_RSP (102)
#define UPD_PDN_CONN_SET_REQ (200)
#define UPD_PDN_CONN_SET_RSP (201)
#define PGW_RSTRT_NOTIF (179)
#define PGW_RSTRT_NOTIF_ACK (180)
#define PGW_DNLNK_TRIGRNG_NOTIF (103)
#define PGW_DNLNK_TRIGRNG_ACK (104)
#define TRC_SESS_ACTVN (71)
#define TRC_SESS_DEACT (72)
#define MBMS_SESS_START_REQ (231)
#define MBMS_SESS_START_RSP (232)
#define MBMS_SESS_UPD_REQ (233)
#define MBMS_SESS_UPD_RSP (234)
#define MBMS_SESS_STOP_REQ (235)
#pragma pack(1)
/**
Description -Create Session Request.Bearer Context to be created
*/
typedef struct gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t tft;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_enb_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s5s8_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s5s8_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_rnc_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2b_u_epdg_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2a_u_twan_fteid;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_mme_fteid;
} gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t;

/**
Description -Create Session Request.Bearer Context to be removed
*/
typedef struct gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
} gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t;

/**
Description -Create Session Request.Overload Control Information
*/
typedef struct gtp_create_sess_request__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_create_sess_request__overload_ctl_info_ie_t;

/**
Description -Create Session Request.Remote UE Context Connected
*/
typedef struct gtp_create_sess_request__remote_ue_ctxt_connected_ie_t {
  ie_header_t header;
  gtp_remote_user_id_ie_t remote_user_id;
  gtp_rmt_ue_ip_info_ie_t rmt_ue_ip_info;
} gtp_create_sess_request__remote_ue_ctxt_connected_ie_t;

/**
Description -Create Session Response.Bearer Context Created
*/
typedef struct gtp_create_sess_response_bearer_ctxt_created_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s5s8_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2b_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2a_u_pgw_fteid;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_charging_id_ie_t charging_id;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_sgw_fteid;
} gtp_create_sess_response_bearer_ctxt_created_ie_t;

/**
Description -Create Session Response.Bearer Context marked for removal
*/
typedef struct gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
} gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t;

/**
Description -Create Session Response.Load Control Information
*/
typedef struct gtp_create_sess_response__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_create_sess_response__load_ctl_info_ie_t;

/**
Description -Create Session Response.Overload Control Information
*/
typedef struct gtp_create_sess_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_create_sess_response__overload_ctl_info_ie_t;

/**
Description -Create Bearer Request.Bearer Context
*/
typedef struct gtp_create_bearer_request_bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t tft;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s58_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2b_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2a_u_pgw_fteid;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_charging_id_ie_t charging_id;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_max_pckt_loss_rate_ie_t max_pckt_loss_rate;
} gtp_create_bearer_request_bearer_ctxt_ie_t;

/**
Description -Create Bearer Request.Load Control Information
*/
typedef struct gtp_create_bearer_request__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_create_bearer_request__load_ctl_info_ie_t;

/**
Description -Create Bearer Request.Overload Control Information
*/
typedef struct gtp_create_bearer_request__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_create_bearer_request__overload_ctl_info_ie_t;

/**
Description -Create Bearer Response.Bearer Context
*/
typedef struct gtp_create_bearer_response_bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_enb_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s58_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s58_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_rnc_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2b_u_epdg_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2b_u_pgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2a_u_twan_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s2a_u_pgw_fteid;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_ran_nas_cause_ie_t ran_nas_cause;
  gtp_extnded_prot_cfg_opts_ie_t epco;
} gtp_create_bearer_response_bearer_ctxt_ie_t;

/**
Description -Create Bearer Response.Overload Control Information
*/
typedef struct gtp_create_bearer_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_create_bearer_response__overload_ctl_info_ie_t;

/**
Description -Bearer Resource Command.Overload Control Information
*/
typedef struct gtp_bearer_rsrc_command__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_bearer_rsrc_command__overload_ctl_info_ie_t;

/**
Description -Bearer Resource Failure Indication.Overload Control Information
*/
typedef struct gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_bearer_rsrc_fail_indication__overload_ctl_info_ie_t;

/**
Description -Modify Bearer Request.Bearer Context to be modified
*/
typedef struct gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1_enodeb_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s58_u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_rnc_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_mme_fteid;
} gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t;

/**
Description -Modify Bearer Request.Bearer Context to be removed
*/
typedef struct gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
} gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t;

/**
Description -Modify Bearer Request.Overload Control Information
*/
typedef struct gtp_mod_bearer_request_overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_mod_bearer_request_overload_ctl_info_ie_t;

/**
Description -Modify Bearer Response.Bearer Context modified
*/
typedef struct gtp_mod_bearer_response_bearer_ctxt_modified_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgw_fteid;
  gtp_charging_id_ie_t charging_id;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_sgw_fteid;
} gtp_mod_bearer_response_bearer_ctxt_modified_ie_t;

/**
Description -Modify Bearer Response.Bearer Context marked for removal
*/
typedef struct gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
} gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t;

/**
Description -Modify Bearer Response.Load Control Information
*/
typedef struct gtp_mod_bearer_response__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_mod_bearer_response__load_ctl_info_ie_t;

/**
Description -Modify Bearer Response.Overload Control Information
*/
typedef struct gtp_mod_bearer_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_mod_bearer_response__overload_ctl_info_ie_t;

/**
Description -Delete Session Request.Overload Control Information
*/
typedef struct gtp_del_sess_request__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_del_sess_request__overload_ctl_info_ie_t;

/**
Description -Delete Bearer Request.Bearer Context
*/
typedef struct gtp_del_bearer_request__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
} gtp_del_bearer_request__bearer_ctxt_ie_t;

/**
Description -Delete Bearer Request.Load Control Information
*/
typedef struct gtp_del_bearer_request__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_del_bearer_request__load_ctl_info_ie_t;

/**
Description -Delete Bearer Request.Overload Control Information
*/
typedef struct gtp_del_bearer_request__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_del_bearer_request__overload_ctl_info_ie_t;

/**
Description -Delete Session Response.Load Control Information
*/
typedef struct gtp_del_sess_response__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_del_sess_response__load_ctl_info_ie_t;

/**
Description -Delete Session Response.Overload Control Information
*/
typedef struct gtp_del_sess_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_del_sess_response__overload_ctl_info_ie_t;

/**
Description -Delete Bearer Response.Bearer Context
*/
typedef struct gtp_del_bearer_response__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_ran_nas_cause_ie_t ran_nas_cause;
  gtp_extnded_prot_cfg_opts_ie_t epco;
} gtp_del_bearer_response__bearer_ctxt_ie_t;

/**
Description -Delete Bearer Response.Overload Control Information
*/
typedef struct gtp_del_bearer_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_del_bearer_response__overload_ctl_info_ie_t;

/**
Description -Downlink Data Notification.Load Control Information
*/
typedef struct gtp_dnlnk_data_notification__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
} gtp_dnlnk_data_notification__load_ctl_info_ie_t;

/**
Description -Downlink Data Notification.Overload Control Information
*/
typedef struct gtp_dnlnk_data_notification__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_dnlnk_data_notification__overload_ctl_info_ie_t;

/**
Description -Modify Bearer Command.Bearer Context
*/
typedef struct gtp_mod_bearer_command__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
} gtp_mod_bearer_command__bearer_ctxt_ie_t;

/**
Description -Modify Bearer Command.Overload Control Information
*/
typedef struct gtp_mod_bearer_command__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_mod_bearer_command__overload_ctl_info_ie_t;

/**
Description -Modify Bearer Failure Indication.Overload Control Information
*/
typedef struct gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_mod_bearer_fail_indication__overload_ctl_info_ie_t;

/**
Description -Update Bearer Request.Bearer Context
*/
typedef struct gtp_upd_bearer_request__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t tft;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_addtl_prot_cfg_opts_ie_t apco;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_max_pckt_loss_rate_ie_t max_pckt_loss_rate;
} gtp_upd_bearer_request__bearer_ctxt_ie_t;

/**
Description -Update Bearer Request.Load Control Information
*/
typedef struct gtp_upd_bearer_request__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
  gtp_apn_and_rltv_cap_ie_t list_of_apn_and_rltv_cap;
} gtp_upd_bearer_request__load_ctl_info_ie_t;

/**
Description -Update Bearer Request.Overload Control Information
*/
typedef struct gtp_upd_bearer_request__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_upd_bearer_request__overload_ctl_info_ie_t;

/**
Description -Update Bearer Response.Bearer Context
*/
typedef struct gtp_upd_bearer_response__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_rnc_fteid;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_ran_nas_cause_ie_t ran_nas_cause;
  gtp_extnded_prot_cfg_opts_ie_t epco;
} gtp_upd_bearer_response__bearer_ctxt_ie_t;

/**
Description -Update Bearer Response.Overload Control Information
*/
typedef struct gtp_upd_bearer_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_upd_bearer_response__overload_ctl_info_ie_t;

/**
Description -Delete Bearer Command.Bearer Context
*/
typedef struct gtp_del_bearer_command__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_ran_nas_cause_ie_t ran_nas_release_cause;
} gtp_del_bearer_command__bearer_ctxt_ie_t;

/**
Description -Delete Bearer Command.Overload Control Information
*/
typedef struct gtp_del_bearer_command__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_del_bearer_command__overload_ctl_info_ie_t;

/**
Description -Delete Bearer Failure Indication.Bearer Context
*/
typedef struct gtp_del_bearer_fail_indication__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
} gtp_del_bearer_fail_indication__bearer_ctxt_ie_t;

/**
Description -Delete Bearer Failure Indication.Overload Control Information
*/
typedef struct gtp_del_bearer_fail_indication__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
  gtp_acc_pt_name_ie_t apn;
} gtp_del_bearer_fail_indication__overload_ctl_info_ie_t;

/**
Description -Create Indirect Data Forwarding Tunnel Request.Bearer Context
*/
typedef struct gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t enb_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgsn_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t rnc_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t enb_fteid_ul_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_fteid_ul_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t mme_fteid_dl_data_fwdng;
} gtp_create_indir_data_fwdng_tunn_request__bearer_ctxt_ie_t;

/**
Description -Create Indirect Data Forwarding Tunnel Response.Bearer Context
*/
typedef struct gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_sgw_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgw_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_fteid_dl_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid_ul_data_fwdng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_fteid_ul_data_fwdng;
} gtp_create_indir_data_fwdng_tunn_response__bearer_ctxt_ie_t;

/**
Description -Release Access Bearers Response.Load Control Information
*/
typedef struct gtp_release_acc_bearers_response__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
} gtp_release_acc_bearers_response__load_ctl_info_ie_t;

/**
Description -Release Access Bearers Response.Overload Control Information
*/
typedef struct gtp_release_acc_bearers_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_release_acc_bearers_response__overload_ctl_info_ie_t;

/**
Description -Modify Access Bearers Request.Bearer Context to be modified
*/
typedef struct gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_enb_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_mme_fteid;
} gtp_mod_acc_bearers_request__bearer_ctxt_to_be_modified_ie_t;

/**
Description -Modify Access Bearers Request.Bearer Context to be removed
*/
typedef struct gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
} gtp_mod_acc_bearers_request__bearer_ctxt_to_be_removed_ie_t;

/**
Description -Modify Access Bearers Response.Bearer Context modified
*/
typedef struct gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s1u_sgw_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s11_u_sgw_fteid;
} gtp_mod_acc_bearers_response__bearer_ctxt_modified_ie_t;

/**
Description -Modify Access Bearers Response.Bearer Context marked for removal
*/
typedef struct gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_cause_ie_t cause;
} gtp_mod_acc_bearers_response__bearer_ctxt_marked_removal_ie_t;

/**
Description -Modify Access Bearers Response.Load Control Information
*/
typedef struct gtp_mod_acc_bearers_response__load_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t load_ctl_seqn_nbr;
  gtp_metric_ie_t load_metric;
} gtp_mod_acc_bearers_response__load_ctl_info_ie_t;

/**
Description -Modify Access Bearers Response.Overload Control Information
*/
typedef struct gtp_mod_acc_bearers_response__overload_ctl_info_ie_t {
  ie_header_t header;
  gtp_sequence_number_ie_t ovrld_ctl_seqn_nbr;
  gtp_metric_ie_t ovrld_reduction_metric;
  gtp_epc_timer_ie_t prd_of_validity;
} gtp_mod_acc_bearers_response__overload_ctl_info_ie_t;

/**
Description -Remote UE Report Notification.Remote UE Context Connected
*/
typedef struct gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t {
  ie_header_t header;
  gtp_remote_user_id_ie_t remote_user_id;
  gtp_rmt_ue_ip_info_ie_t rmt_ue_ip_info;
} gtp_rmt_ue_rpt_notification__remote_ue_ctxt_connected_ie_t;

/**
Description -Remote UE Report Notification.Remote UE Context Disconnected
*/
typedef struct gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t {
  ie_header_t header;
  gtp_remote_user_id_ie_t remote_user_id;
} gtp_rmt_ue_rpt_notification__remote_ue_ctxt_disconnected_ie_t;

/**
Description -Forward Relocation Request.MME/SGSN/AMF UE EPS PDN Connections
*/
typedef struct gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t {
  ie_header_t header;
  gtp_acc_pt_name_ie_t apn;
  gtp_apn_restriction_ie_t apn_restriction;
  gtp_selection_mode_ie_t selection_mode;
  gtp_ip_address_ie_t ipv4_address;
  gtp_ip_address_ie_t ipv6_address;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_ip_addr_ctl_plane_or_pmip;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_chrgng_char_ie_t chrgng_char;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_indication_ie_t indctn_flgs;
  gtp_sgnllng_priority_indctn_ie_t sgnllng_priority_indctn;
  gtp_chg_to_rpt_flgs_ie_t chg_to_rpt_flgs;
  gtp_fully_qual_domain_name_ie_t local_home_ntwk_id;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_wlan_offldblty_indctn_ie_t wlan_offldblty_indctn;
  gtp_rmt_ue_ctxt_ie_t rmt_ue_ctxt_connected;
  gtp_pdn_type_ie_t pdn_type;
  gtp_hdr_comp_cfg_ie_t hdr_comp_cfg;
} gtp_fwd_reloc_request__mmesgsnamf_ue_eps_pdn_connections_ie_t;

/**
Description -Forward Relocation Request.Bearer Context
*/
typedef struct gtp_fwd_reloc_request__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t tft;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s1s4s12_ip_addr_and_teid_user_plane;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_ip_addr_and_teid_user_plane;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_full_qual_cntnr_ie_t bss_container;
  gtp_trans_idnt_ie_t trans_idnt;
  gtp_bearer_flags_ie_t bearer_flags;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s11_ip_addr_and_teid_user_plane;
} gtp_fwd_reloc_request__bearer_ctxt_ie_t;

/**
Description -Forward Relocation Request.Remote UE Context Connected
*/
typedef struct gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t {
  ie_header_t header;
  gtp_remote_user_id_ie_t remote_user_id;
  gtp_rmt_ue_ip_info_ie_t rmt_ue_ip_info;
} gtp_fwd_reloc_request__remote_ue_ctxt_connected_ie_t;

/**
Description -Forward Relocation Request.MME UE SCEF PDN Connections
*/
typedef struct gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t {
  ie_header_t header;
  gtp_acc_pt_name_ie_t apn;
  gtp_eps_bearer_id_ie_t dflt_eps_bearer_id;
  gtp_node_identifier_ie_t scef_id;
} gtp_fwd_reloc_request__mme_ue_scef_pdn_connections_ie_t;

/**
Description -Context Response.MME/SGSN UE EPS PDN Connections
*/
typedef struct gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t {
  ie_header_t header;
  gtp_acc_pt_name_ie_t apn;
  gtp_apn_restriction_ie_t apn_restriction;
  gtp_selection_mode_ie_t selection_mode;
  gtp_ip_address_ie_t ipv4_address;
  gtp_ip_address_ie_t ipv6_address;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_ip_addr_ctl_plane_or_pmip;
  gtp_fully_qual_domain_name_ie_t pgw_node_name;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_chrgng_char_ie_t chrgng_char;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_indication_ie_t indctn_flgs;
  gtp_sgnllng_priority_indctn_ie_t sgnllng_priority_indctn;
  gtp_chg_to_rpt_flgs_ie_t chg_to_rpt_flgs;
  gtp_fully_qual_domain_name_ie_t local_home_ntwk_id;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_wlan_offldblty_indctn_ie_t wlan_offldblty_indctn;
  gtp_rmt_ue_ctxt_ie_t rmt_ue_ctxt_connected;
  gtp_pdn_type_ie_t pdn_type;
  gtp_hdr_comp_cfg_ie_t hdr_comp_cfg;
} gtp_ctxt_response__mmesgsn_ue_eps_pdn_connections_ie_t;

/**
Description -Context Response.Bearer Context
*/
typedef struct gtp_ctxt_response__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t tft;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s1s4s12s11_ip_addr_and_teid_user_plane;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_ip_addr_and_teid_user_plane;
  gtp_bearer_qlty_of_svc_ie_t bearer_lvl_qos;
  gtp_full_qual_cntnr_ie_t bss_container;
  gtp_trans_idnt_ie_t trans_idnt;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s11_ip_addr_and_teid_user_plane;
} gtp_ctxt_response__bearer_ctxt_ie_t;

/**
Description -Context Response.Remote UE Context Connected
*/
typedef struct gtp_ctxt_response__remote_ue_ctxt_connected_ie_t {
  ie_header_t header;
  gtp_remote_user_id_ie_t remote_user_id;
  gtp_rmt_ue_ip_info_ie_t rmt_ue_ip_info;
} gtp_ctxt_response__remote_ue_ctxt_connected_ie_t;

/**
Description -Context Response.MME/SGSN UE SCEF PDN Connections
*/
typedef struct gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t {
  ie_header_t header;
  gtp_acc_pt_name_ie_t apn;
  gtp_eps_bearer_id_ie_t dflt_eps_bearer_id;
  gtp_node_identifier_ie_t scef_id;
} gtp_ctxt_response__mmesgsn_ue_scef_pdn_connections_ie_t;

/**
Description -Context Acknowledge.Bearer Context
*/
typedef struct gtp_ctxt_acknowledge__bearer_ctxt_ie_t {
  ie_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_fully_qual_tunn_endpt_idnt_ie_t fwdng_fteid;
} gtp_ctxt_acknowledge__bearer_ctxt_ie_t;

typedef struct echo_request_t {
  gtpv2c_header_t header;
  gtp_recovery_ie_t recovery;
  gtp_node_features_ie_t sending_node_feat;
  gtp_priv_ext_ie_t priv_ext;
} echo_request_t;

typedef struct echo_response_t {
  gtpv2c_header_t header;
  gtp_recovery_ie_t recovery;
  gtp_node_features_ie_t sending_node_feat;
  gtp_priv_ext_ie_t priv_ext;
} echo_response_t;

typedef struct create_sess_req_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_msisdn_ie_t msisdn;
  gtp_mbl_equip_idnty_ie_t mei;
  gtp_user_loc_info_ie_t uli;
  gtp_rat_type_ie_t rat_type;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_addr_ctl_plane_or_pmip;
  gtp_acc_pt_name_ie_t apn;
  gtp_selection_mode_ie_t selection_mode;
  gtp_pdn_type_ie_t pdn_type;
  gtp_pdn_addr_alloc_ie_t paa;
  gtp_apn_restriction_ie_t max_apn_rstrct;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_trstd_wlan_mode_indctn_ie_t trstd_wlan_mode_indctn;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_create_sess_request_bearer_ctxt_to_be_created_ie_t bearer_contexts_to_be_created;
  gtp_create_sess_request_bearer_ctxt_to_be_removed_ie_t bearer_contexts_to_be_removed;
  gtp_trc_info_ie_t trc_info;
  gtp_recovery_ie_t recovery;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_fqcsid_ie_t epdg_fqcsid;
  gtp_fqcsid_ie_t twan_fqcsid;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_user_csg_info_ie_t uci;
  gtp_chrgng_char_ie_t chrgng_char;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_local_distgsd_name_ie_t sgw_ldn;
  gtp_local_distgsd_name_ie_t epdg_ldn;
  gtp_local_distgsd_name_ie_t twan_ldn;
  gtp_sgnllng_priority_indctn_ie_t sgnllng_priority_indctn;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_addtl_prot_cfg_opts_ie_t apco;
  gtp_ip_address_ie_t henb_local_ip_addr;
  gtp_port_number_ie_t henb_udp_port;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_twan_identifier_ie_t twan_identifier;
  gtp_ip_address_ie_t epdg_ip_address;
  gtp_cn_oper_sel_entity_ie_t cn_oper_sel_entity;
  gtp_pres_rptng_area_info_ie_t pres_rptng_area_info;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_msec_time_stmp_ie_t origination_time_stmp;
  gtp_integer_number_ie_t max_wait_time;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_rmt_ue_ctxt_ie_t rmt_ue_ctxt_connected;
  gtp_node_identifier_ie_t threegpp_aaa_server_idnt;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_srvng_plmn_rate_ctl_ie_t srvng_plmn_rate_ctl;
  gtp_counter_ie_t mo_exception_data_cntr;
  gtp_port_number_ie_t ue_tcp_port;
  gtp_mapped_ue_usage_type_ie_t mapped_ue_usage_type;
  gtp_user_loc_info_ie_t user_loc_info_sgw;
  gtp_fully_qual_domain_name_ie_t sgw_u_node_name;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_up_func_sel_indctn_flgs_ie_t up_func_sel_indctn_flgs;
  gtp_priv_ext_ie_t priv_ext;
  gtp_serving_network_ie_t serving_network;
} create_sess_req_t;

typedef struct create_sess_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5s8_s2as2b_fteid_pmip_based_intfc_or_gtp_based_ctl_plane_intfc;
  gtp_pdn_addr_alloc_ie_t paa;
  gtp_apn_restriction_ie_t apn_restriction;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_create_sess_response_bearer_ctxt_created_ie_t bearer_contexts_created;
  gtp_create_sess_response_bearer_ctxt_marked_removal_ie_t bearer_contexts_marked_removal;
  gtp_recovery_ie_t recovery;
  gtp_fully_qual_domain_name_ie_t chrgng_gateway_name;
  gtp_ip_address_ie_t chrgng_gateway_addr;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_local_distgsd_name_ie_t sgw_ldn;
  gtp_local_distgsd_name_ie_t pgw_ldn;
  gtp_epc_timer_ie_t pgw_back_off_time;
  gtp_addtl_prot_cfg_opts_ie_t apco;
  gtp_ipv4_cfg_parms_ie_t trstd_wlan_ipv4_parms;
  gtp_indication_ie_t indctn_flgs;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_charging_id_ie_t pdn_conn_chrgng_id;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_priv_ext_ie_t priv_ext;
} create_sess_rsp_t;

typedef struct create_bearer_req_t {
  gtpv2c_header_t header;
  gtp_proc_trans_id_ie_t pti;
  gtp_eps_bearer_id_ie_t lbi;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_create_bearer_request_bearer_ctxt_ie_t bearer_contexts;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_indication_ie_t indctn_flgs;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_priv_ext_ie_t priv_ext;
} create_bearer_req_t;

typedef struct create_bearer_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_create_bearer_response_bearer_ctxt_ie_t bearer_contexts;
  gtp_recovery_ie_t recovery;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_fqcsid_ie_t epdg_fqcsid;
  gtp_fqcsid_ie_t twan_fqcsid;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_user_loc_info_ie_t uli;
  gtp_twan_identifier_ie_t twan_identifier;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_pres_rptng_area_info_ie_t pres_rptng_area_info;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_port_number_ie_t ue_tcp_port;
  gtp_priv_ext_ie_t priv_ext;
} create_bearer_rsp_t;

typedef struct bearer_rsrc_cmd_t {
  gtpv2c_header_t header;
  gtp_eps_bearer_id_ie_t lbi;
  gtp_proc_trans_id_ie_t pti;
  gtp_flow_qlty_of_svc_ie_t flow_qos;
  gtp_traffic_agg_desc_ie_t tad;
  gtp_rat_type_ie_t rat_type;
  gtp_serving_network_ie_t serving_network;
  gtp_user_loc_info_ie_t uli;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s4_u_sgsn_fteid;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s12_rnc_fteid;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_sgnllng_priority_indctn_ie_t sgnllng_priority_indctn;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_priv_ext_ie_t priv_ext;
} bearer_rsrc_cmd_t;

typedef struct bearer_rsrc_fail_indctn_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_proc_trans_id_ie_t pti;
  gtp_indication_ie_t indctn_flgs;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_recovery_ie_t recovery;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_priv_ext_ie_t priv_ext;
} bearer_rsrc_fail_indctn_t;

typedef struct mod_bearer_req_t {
  gtpv2c_header_t header;
  gtp_mbl_equip_idnty_ie_t mei;
  gtp_user_loc_info_ie_t uli;
  gtp_serving_network_ie_t serving_network;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_delay_value_ie_t delay_dnlnk_pckt_notif_req;
  gtp_mod_bearer_request_bearer_ctxt_to_be_modified_ie_t bearer_contexts_to_be_modified;
  gtp_mod_bearer_request_bearer_ctxt_to_be_removed_ie_t bearer_contexts_to_be_removed;
  gtp_recovery_ie_t recovery;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_user_csg_info_ie_t uci;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_local_distgsd_name_ie_t sgw_ldn;
  gtp_ip_address_ie_t henb_local_ip_addr;
  gtp_port_number_ie_t henb_udp_port;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_cn_oper_sel_entity_ie_t cn_oper_sel_entity;
  gtp_pres_rptng_area_info_ie_t pres_rptng_area_info;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t epdgs_ovrld_ctl_info;
  gtp_srvng_plmn_rate_ctl_ie_t srvng_plmn_rate_ctl;
  gtp_counter_ie_t mo_exception_data_cntr;
  gtp_imsi_ie_t imsi;
  gtp_user_loc_info_ie_t user_loc_info_sgw;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} mod_bearer_req_t;

typedef struct mod_bearer_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_msisdn_ie_t msisdn;
  gtp_eps_bearer_id_ie_t linked_eps_bearer_id;
  gtp_apn_restriction_ie_t apn_restriction;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_mod_bearer_response_bearer_ctxt_modified_ie_t bearer_contexts_modified;
  gtp_mod_bearer_response_bearer_ctxt_marked_removal_ie_t bearer_contexts_marked_removal;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_fully_qual_domain_name_ie_t chrgng_gateway_name;
  gtp_ip_address_ie_t chrgng_gateway_addr;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_recovery_ie_t recovery;
  gtp_local_distgsd_name_ie_t sgw_ldn;
  gtp_local_distgsd_name_ie_t pgw_ldn;
  gtp_indication_ie_t indctn_flgs;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_charging_id_ie_t pdn_conn_chrgng_id;
  gtp_priv_ext_ie_t priv_ext;
} mod_bearer_rsp_t;

typedef struct del_sess_req_t {
  gtpv2c_header_t header;
  gtp_eps_bearer_id_ie_t lbi;
  gtp_user_loc_info_ie_t uli;
  gtp_indication_ie_t indctn_flgs;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_node_type_ie_t originating_node;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_uli_timestamp_ie_t uli_timestamp;
  gtp_ran_nas_cause_ie_t ran_nas_release_cause;
  gtp_twan_identifier_ie_t twan_identifier;
  gtp_twan_idnt_ts_ie_t twan_idnt_ts;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_port_number_ie_t ue_tcp_port;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} del_sess_req_t;

typedef struct del_bearer_req_t {
  gtpv2c_header_t header;
  gtp_eps_bearer_id_ie_t eps_bearer_ids;
  gtp_bearer_context_ie_t failed_bearer_contexts;
  gtp_proc_trans_id_ie_t pti;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_indication_ie_t indctn_flgs;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_priv_ext_ie_t priv_ext;
} del_bearer_req_t;

typedef struct del_sess_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_recovery_ie_t recovery;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_indication_ie_t indctn_flgs;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_extnded_prot_cfg_opts_ie_t epco;
  gtp_priv_ext_ie_t priv_ext;
} del_sess_rsp_t;

typedef struct del_bearer_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_eps_bearer_id_ie_t lbi;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_recovery_ie_t recovery;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_fqcsid_ie_t epdg_fqcsid;
  gtp_fqcsid_ie_t twan_fqcsid;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_user_loc_info_ie_t uli;
  gtp_uli_timestamp_ie_t uli_timestamp;
  gtp_twan_identifier_ie_t twan_identifier;
  gtp_twan_idnt_ts_ie_t twan_idnt_ts;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_port_number_ie_t ue_tcp_port;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} del_bearer_rsp_t;

typedef struct dnlnk_data_notif_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_eps_bearer_id_ie_t eps_bearer_id;
  gtp_alloc_reten_priority_ie_t alloc_reten_priority;
  gtp_imsi_ie_t imsi;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_indication_ie_t indctn_flgs;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_paging_and_svc_info_ie_t paging_and_svc_info;
  gtp_priv_ext_ie_t priv_ext;
} dnlnk_data_notif_t;

typedef struct dnlnk_data_notif_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_delay_value_ie_t data_notif_delay;
  gtp_recovery_ie_t recovery;
  gtp_throttling_ie_t dl_low_priority_traffic_thrtlng;
  gtp_imsi_ie_t imsi;
  gtp_epc_timer_ie_t dl_buffering_dur;
  gtp_integer_number_ie_t dl_buffering_suggested_pckt_cnt;
  gtp_priv_ext_ie_t priv_ext;
} dnlnk_data_notif_ack_t;

typedef struct dnlnk_data_notif_fail_indctn_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_node_type_ie_t originating_node;
  gtp_imsi_ie_t imsi;
  gtp_priv_ext_ie_t priv_ext;
} dnlnk_data_notif_fail_indctn_t;

typedef struct mod_bearer_cmd_t {
  gtpv2c_header_t header;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_bearer_context_ie_t bearer_context;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_priv_ext_ie_t priv_ext;
} mod_bearer_cmd_t;

typedef struct mod_bearer_fail_indctn_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_recovery_ie_t recovery;
  gtp_indication_ie_t indctn_flgs;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_priv_ext_ie_t priv_ext;
} mod_bearer_fail_indctn_t;

typedef struct upd_bearer_req_t {
  gtpv2c_header_t header;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_proc_trans_id_ie_t pti;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_agg_max_bit_rate_ie_t apn_ambr;
  gtp_chg_rptng_act_ie_t chg_rptng_act;
  gtp_csg_info_rptng_act_ie_t csg_info_rptng_act;
  gtp_henb_info_rptng_ie_t henb_info_rptng;
  gtp_indication_ie_t indctn_flgs;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_pres_rptng_area_act_ie_t pres_rptng_area_act;
  gtp_load_ctl_info_ie_t pgws_node_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t pgws_apn_lvl_load_ctl_info;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_priv_ext_ie_t priv_ext;
} upd_bearer_req_t;

typedef struct upd_bearer_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_prot_cfg_opts_ie_t pco;
  gtp_recovery_ie_t recovery;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_fqcsid_ie_t epdg_fqcsid;
  gtp_fqcsid_ie_t twan_fqcsid;
  gtp_indication_ie_t indctn_flgs;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_user_loc_info_ie_t uli;
  gtp_twan_identifier_ie_t twan_identifier;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_pres_rptng_area_info_ie_t pres_rptng_area_info;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_ovrld_ctl_info_ie_t twanepdgs_ovrld_ctl_info;
  gtp_twan_identifier_ie_t wlan_loc_info;
  gtp_twan_idnt_ts_ie_t wlan_loc_ts;
  gtp_ip_address_ie_t ue_local_ip_addr;
  gtp_port_number_ie_t ue_udp_port;
  gtp_full_qual_cntnr_ie_t nbifom_cntnr;
  gtp_port_number_ie_t ue_tcp_port;
  gtp_priv_ext_ie_t priv_ext;
} upd_bearer_rsp_t;

typedef struct del_bearer_cmd_t {
  gtpv2c_header_t header;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_user_loc_info_ie_t uli;
  gtp_uli_timestamp_ie_t uli_timestamp;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_ovrld_ctl_info_ie_t mmes4_sgsns_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} del_bearer_cmd_t;

typedef struct del_bearer_fail_indctn_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_bearer_context_ie_t bearer_context;
  gtp_recovery_ie_t recovery;
  gtp_indication_ie_t indctn_flgs;
  gtp_ovrld_ctl_info_ie_t pgws_ovrld_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_priv_ext_ie_t priv_ext;
} del_bearer_fail_indctn_t;

typedef struct create_indir_data_fwdng_tunn_req_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_mbl_equip_idnty_ie_t mei;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} create_indir_data_fwdng_tunn_req_t;

typedef struct create_indir_data_fwdng_tunn_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} create_indir_data_fwdng_tunn_rsp_t;

typedef struct stop_paging_indctn_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_priv_ext_ie_t priv_ext;
} stop_paging_indctn_t;

typedef struct mod_acc_bearers_req_t {
  gtpv2c_header_t header;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_delay_value_ie_t delay_dnlnk_pckt_notif_req;
  gtp_bearer_context_ie_t bearer_contexts_to_be_modified;
  gtp_bearer_context_ie_t bearer_contexts_to_be_removed;
  gtp_recovery_ie_t recovery;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} mod_acc_bearers_req_t;

typedef struct mod_acc_bearers_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_bearer_context_ie_t bearer_contexts_modified;
  gtp_bearer_context_ie_t bearer_contexts_marked_removal;
  gtp_recovery_ie_t recovery;
  gtp_indication_ie_t indctn_flgs;
  gtp_load_ctl_info_ie_t sgws_node_lvl_load_ctl_info;
  gtp_ovrld_ctl_info_ie_t sgws_ovrld_ctl_info;
  gtp_priv_ext_ie_t priv_ext;
} mod_acc_bearers_rsp_t;

typedef struct rmt_ue_rpt_notif_t {
  gtpv2c_header_t header;
  gtp_rmt_ue_ctxt_ie_t rmt_ue_ctxt_connected;
  gtp_rmt_ue_ctxt_ie_t rmt_ue_ctxt_disconnected;
  gtp_priv_ext_ie_t priv_ext;
} rmt_ue_rpt_notif_t;

typedef struct rmt_ue_rpt_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} rmt_ue_rpt_ack_t;

typedef struct fwd_reloc_req_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_fully_qual_tunn_endpt_idnt_ie_t senders_fteid_ctl_plane;
  gtp_pdn_connection_ie_t mmesgsnamf_ue_eps_pdn_connections;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s11s4_ip_addr_and_teid_ctl_plane;
  gtp_fully_qual_domain_name_ie_t sgw_node_name;
  mm_context_t mmesgsnamf_ue_mm_ctxt;
  gtp_indication_ie_t indctn_flgs;
  gtp_full_qual_cntnr_ie_t e_utran_transparent_cntnr;
  gtp_full_qual_cntnr_ie_t utran_transparent_cntnr;
  gtp_full_qual_cntnr_ie_t bss_container;
  gtp_trgt_id_ie_t trgt_id;
  gtp_ip_address_ie_t hrpd_acc_node_s101_ip_addr;
  gtp_ip_address_ie_t onexiws_sone02_ip_addr;
  gtp_full_qual_cause_ie_t s1_ap_cause;
  gtp_full_qual_cause_ie_t ranap_cause;
  gtp_full_qual_cause_ie_t bssgp_cause;
  gtp_src_id_ie_t src_id;
  gtp_plmn_id_ie_t selected_plmn_id;
  gtp_recovery_ie_t recovery;
  gtp_trc_info_ie_t trc_info;
  gtp_rfsp_index_ie_t subscrbd_rfsp_idx;
  gtp_rfsp_index_ie_t rfsp_idx_in_use;
  gtp_csg_id_ie_t csg_id;
  gtp_csg_memb_indctn_ie_t csg_memb_indctn;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_serving_network_ie_t serving_network;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_addtl_mm_ctxt_srvcc_ie_t addtl_mm_ctxt_srvcc;
  gtp_addtl_flgs_srvcc_ie_t addtl_flgs_srvcc;
  gtp_stn_sr_ie_t stn_sr;
  gtp_msisdn_ie_t c_msisdn;
  gtp_mdt_cfg_ie_t mdt_cfg;
  gtp_fully_qual_domain_name_ie_t sgsn_node_name;
  gtp_fully_qual_domain_name_ie_t mme_node_name;
  gtp_user_csg_info_ie_t uci;
  gtp_mntrng_evnt_info_ie_t mntrng_evnt_info;
  gtp_integer_number_ie_t ue_usage_type;
  gtp_scef_pdn_conn_ie_t mmesgsn_ue_scef_pdn_connections;
  gtp_msisdn_ie_t msisdn;
  gtp_port_number_ie_t src_udp_port_nbr;
  gtp_srvng_plmn_rate_ctl_ie_t srvng_plmn_rate_ctl;
  gtp_priv_ext_ie_t priv_ext;
} fwd_reloc_req_t;

typedef struct fwd_reloc_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t senders_fteid_ctl_plane;
  gtp_indication_ie_t indctn_flgs;
  gtp_bearer_context_ie_t list_of_set_up_bearers;
  gtp_bearer_context_ie_t list_of_set_up_rabs;
  gtp_bearer_context_ie_t list_of_set_up_pfcs;
  gtp_full_qual_cause_ie_t s1_ap_cause;
  gtp_full_qual_cause_ie_t ranap_cause;
  gtp_full_qual_cause_ie_t bssgp_cause;
  gtp_full_qual_cntnr_ie_t e_utran_transparent_cntnr;
  gtp_full_qual_cntnr_ie_t utran_transparent_cntnr;
  gtp_full_qual_cntnr_ie_t bss_container;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_fully_qual_domain_name_ie_t sgsn_node_name;
  gtp_fully_qual_domain_name_ie_t mme_node_name;
  gtp_node_number_ie_t sgsn_number;
  gtp_node_identifier_ie_t sgsn_identifier;
  gtp_node_identifier_ie_t mme_identifier;
  gtp_node_number_ie_t mme_nbr_mt_sms;
  gtp_node_identifier_ie_t sgsn_idnt_mt_sms;
  gtp_node_identifier_ie_t mme_idnt_mt_sms;
  gtp_bearer_context_ie_t list_of_set_up_bearers_scef_pdn_connections;
  gtp_priv_ext_ie_t priv_ext;
} fwd_reloc_rsp_t;

typedef struct fwd_reloc_cmplt_notif_t {
  gtpv2c_header_t header;
  gtp_indication_ie_t indctn_flgs;
  gtp_priv_ext_ie_t priv_ext;
} fwd_reloc_cmplt_notif_t;

typedef struct fwd_reloc_cmplt_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_recovery_ie_t recovery;
  gtp_secdry_rat_usage_data_rpt_ie_t secdry_rat_usage_data_rpt;
  gtp_priv_ext_ie_t priv_ext;
} fwd_reloc_cmplt_ack_t;

typedef struct context_request_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_guti_ie_t guti;
  gtp_user_loc_info_ie_t rai;
  gtp_ptmsi_ie_t ptmsi;
  gtp_ptmsi_signature_ie_t ptmsi_signature;
  gtp_cmplt_req_msg_ie_t cmplt_tau_req_msg;
  gtp_fully_qual_tunn_endpt_idnt_ie_t s3s16s10n26_addr_and_teid_ctl_plane;
  gtp_port_number_ie_t udp_src_port_nbr;
  gtp_rat_type_ie_t rat_type;
  gtp_indication_ie_t indication;
  gtp_hop_counter_ie_t hop_counter;
  gtp_serving_network_ie_t target_plmn_id;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_fully_qual_domain_name_ie_t sgsn_node_name;
  gtp_fully_qual_domain_name_ie_t mme_node_name;
  gtp_node_number_ie_t sgsn_number;
  gtp_node_identifier_ie_t sgsn_identifier;
  gtp_node_identifier_ie_t mme_identifier;
  gtp_ciot_optim_supp_indctn_ie_t ciot_optim_supp_indctn;
  gtp_priv_ext_ie_t priv_ext;
} context_request_t;

typedef struct ctxt_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_imsi_ie_t imsi;
  gtp_pdn_connection_ie_t mmesgsnamf_ue_eps_pdn_connections;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sgw_s11s4_ip_addr_and_teid_ctl_plane;
  gtp_fully_qual_domain_name_ie_t sgw_node_name;
  gtp_indication_ie_t indctn_flgs;
  gtp_trc_info_ie_t trc_info;
  gtp_ip_address_ie_t hrpd_acc_node_s101_ip_addr;
  gtp_ip_address_ie_t onexiws_sone02_ip_addr;
  gtp_rfsp_index_ie_t subscrbd_rfsp_idx;
  gtp_rfsp_index_ie_t rfsp_idx_in_use;
  gtp_ue_time_zone_ie_t ue_time_zone;
  gtp_local_distgsd_name_ie_t mmes4_sgsn_ldn;
  gtp_mdt_cfg_ie_t mdt_cfg;
  gtp_fully_qual_domain_name_ie_t sgsn_node_name;
  gtp_fully_qual_domain_name_ie_t mme_node_name;
  gtp_user_csg_info_ie_t uci;
  gtp_mntrng_evnt_info_ie_t mntrng_evnt_info;
  gtp_integer_number_ie_t ue_usage_type;
  gtp_scef_pdn_conn_ie_t mmesgsn_ue_scef_pdn_connections;
  gtp_rat_type_ie_t rat_type;
  gtp_srvng_plmn_rate_ctl_ie_t srvng_plmn_rate_ctl;
  gtp_counter_ie_t mo_exception_data_cntr;
  gtp_integer_number_ie_t rem_running_svc_gap_timer;
  gtp_priv_ext_ie_t priv_ext;
} ctxt_rsp_t;

typedef struct ctxt_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_indication_ie_t indctn_flgs;
  gtp_fully_qual_tunn_endpt_idnt_ie_t fwdng_fteid;
  gtp_bearer_context_ie_t bearer_contexts;
  gtp_node_number_ie_t sgsn_number;
  gtp_node_number_ie_t mme_nbr_mt_sms;
  gtp_node_identifier_ie_t sgsn_idnt_mt_sms;
  gtp_node_identifier_ie_t mme_idnt_mt_sms;
  gtp_priv_ext_ie_t priv_ext;
} ctxt_ack_t;

typedef struct id_req_t {
  gtpv2c_header_t header;
  gtp_guti_ie_t guti;
  gtp_user_loc_info_ie_t rai;
  gtp_ptmsi_ie_t ptmsi;
  gtp_ptmsi_signature_ie_t ptmsi_signature;
  gtp_cmplt_req_msg_ie_t cmplt_attach_req_msg;
  gtp_ip_address_ie_t addr_ctl_plane;
  gtp_port_number_ie_t udp_src_port_nbr;
  gtp_hop_counter_ie_t hop_counter;
  gtp_serving_network_ie_t target_plmn_id;
  gtp_priv_ext_ie_t priv_ext;
} id_req_t;

typedef struct id_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_imsi_ie_t imsi;
  mm_context_t mmesgsn_ue_mm_ctxt;
  gtp_trc_info_ie_t trc_info;
  gtp_integer_number_ie_t ue_usage_type;
  gtp_mntrng_evnt_info_ie_t mntrng_evnt_info;
  gtp_priv_ext_ie_t priv_ext;
} id_rsp_t;

typedef struct fwd_acc_ctxt_notif_t {
  gtpv2c_header_t header;
  gtp_rab_context_ie_t rab_contexts;
  gtp_src_rnc_pdcp_ctxt_info_ie_t src_rnc_pdcp_ctxt_info;
  gtp_pdu_numbers_ie_t pdu_numbers;
  gtp_full_qual_cntnr_ie_t e_utran_transparent_cntnr;
  gtp_priv_ext_ie_t priv_ext;
} fwd_acc_ctxt_notif_t;

typedef struct fwd_acc_ctxt_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} fwd_acc_ctxt_ack_t;

typedef struct detach_notif_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_detach_type_ie_t detach_type;
  gtp_priv_ext_ie_t priv_ext;
} detach_notif_t;

typedef struct detach_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} detach_ack_t;

typedef struct reloc_cncl_req_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_mbl_equip_idnty_ie_t mei;
  gtp_indication_ie_t indctn_flgs;
  gtp_full_qual_cause_ie_t ranap_cause;
  gtp_priv_ext_ie_t priv_ext;
} reloc_cncl_req_t;

typedef struct reloc_cncl_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} reloc_cncl_rsp_t;

typedef struct cfg_xfer_tunn_t {
  gtpv2c_header_t header;
  gtp_full_qual_cntnr_ie_t e_utran_transparent_cntnr;
  gtp_trgt_id_ie_t trgt_enb_id;
} cfg_xfer_tunn_t;

typedef struct ran_info_rly_t {
  gtpv2c_header_t header;
  gtp_full_qual_cntnr_ie_t bss_container;
  gtp_trgt_id_ie_t rim_rtng_addr;
  gtp_priv_ext_ie_t priv_ext;
} ran_info_rly_t;

typedef struct isr_status_indctn_t {
  gtpv2c_header_t header;
  gtp_act_indctn_ie_t act_indctn;
  gtp_priv_ext_ie_t priv_ext;
} isr_status_indctn_t;

typedef struct ue_reg_qry_req_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_priv_ext_ie_t priv_ext;
} ue_reg_qry_req_t;

typedef struct ue_reg_qry_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_imsi_ie_t imsi;
  gtp_plmn_id_ie_t selected_core_ntwk_oper_idnt;
  gtp_priv_ext_ie_t priv_ext;
} ue_reg_qry_rsp_t;

typedef struct alert_mme_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} alert_mme_ack_t;

typedef struct ue_actvty_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} ue_actvty_ack_t;

typedef struct create_fwdng_tunn_req_t {
  gtpv2c_header_t header;
  gtp_s103_pdn_data_fwdng_info_ie_t s103_pdn_data_fwdng_info;
  gtp_priv_ext_ie_t priv_ext;
} create_fwdng_tunn_req_t;

typedef struct create_fwdng_tunn_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_s1u_data_fwdng_ie_t s1u_data_fwdng;
  gtp_priv_ext_ie_t priv_ext;
} create_fwdng_tunn_rsp_t;

typedef struct del_pdn_conn_set_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} del_pdn_conn_set_rsp_t;

typedef struct upd_pdn_conn_set_req_t {
  gtpv2c_header_t header;
  gtp_fqcsid_ie_t mme_fqcsid;
  gtp_fqcsid_ie_t sgw_fqcsid;
  gtp_priv_ext_ie_t priv_ext;
} upd_pdn_conn_set_req_t;

typedef struct upd_pdn_conn_set_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_fqcsid_ie_t pgw_fqcsid;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} upd_pdn_conn_set_rsp_t;

typedef struct pgw_rstrt_notif_t {
  gtpv2c_header_t header;
  gtp_ip_address_ie_t pgw_s5s8_ip_addr_ctl_plane_or_pmip;
  gtp_ip_address_ie_t sgw_s11s4_ip_addr_ctl_plane;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} pgw_rstrt_notif_t;

typedef struct pgw_rstrt_notif_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_priv_ext_ie_t priv_ext;
} pgw_rstrt_notif_ack_t;

typedef struct pgw_dnlnk_trigrng_notif_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_fully_qual_tunn_endpt_idnt_ie_t pgw_s5_fteid_gtp_or_pmip_ctl_plane;
  gtp_priv_ext_ie_t priv_ext;
} pgw_dnlnk_trigrng_notif_t;

typedef struct pgw_dnlnk_trigrng_ack_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_imsi_ie_t imsi;
  gtp_ip_address_ie_t mmes4_sgsn_idnt;
  gtp_priv_ext_ie_t priv_ext;
} pgw_dnlnk_trigrng_ack_t;

typedef struct trc_sess_actvn_t {
  gtpv2c_header_t header;
  gtp_imsi_ie_t imsi;
  gtp_trc_info_ie_t trc_info;
  gtp_mbl_equip_idnty_ie_t mei;
} trc_sess_actvn_t;

typedef struct trc_sess_deact_t {
  gtpv2c_header_t header;
  gtp_trace_reference_ie_t trace_reference;
} trc_sess_deact_t;

typedef struct mbms_sess_start_req_t {
  gtpv2c_header_t header;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_tmgi_ie_t tmgi;
  gtp_mbms_sess_dur_ie_t mbms_sess_dur;
  gtp_mbms_svc_area_ie_t mbms_svc_area;
  gtp_mbms_sess_idnt_ie_t mbms_sess_idnt;
  gtp_mbms_flow_idnt_ie_t mbms_flow_idnt;
  gtp_bearer_qlty_of_svc_ie_t qos_profile;
  gtp_mbms_ip_multcst_dist_ie_t mbms_ip_multcst_dist;
  gtp_recovery_ie_t recovery;
  gtp_mbms_time_to_data_xfer_ie_t mbms_time_to_data_xfer;
  gtp_mbms_data_xfer_abs_time_ie_t mbms_data_xfer_start;
  gtp_mbms_flags_ie_t mbms_flags;
  gtp_mbms_ip_multcst_dist_ie_t mbms_alternative_ip_multcst_dist;
  gtp_ecgi_list_ie_t mbms_cell_list;
  gtp_priv_ext_ie_t priv_ext;
} mbms_sess_start_req_t;

typedef struct mbms_sess_start_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_mbms_dist_ack_ie_t mbms_dist_ack;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sn_u_sgsn_fteid;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} mbms_sess_start_rsp_t;

typedef struct mbms_sess_upd_req_t {
  gtpv2c_header_t header;
  gtp_mbms_svc_area_ie_t mbms_svc_area;
  gtp_tmgi_ie_t tmgi;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sender_fteid_ctl_plane;
  gtp_mbms_sess_dur_ie_t mbms_sess_dur;
  gtp_bearer_qlty_of_svc_ie_t qos_profile;
  gtp_mbms_sess_idnt_ie_t mbms_sess_idnt;
  gtp_mbms_flow_idnt_ie_t mbms_flow_idnt;
  gtp_mbms_time_to_data_xfer_ie_t mbms_time_to_data_xfer;
  gtp_mbms_data_xfer_abs_time_ie_t mbms_data_xfer_start_upd_stop;
  gtp_ecgi_list_ie_t mbms_cell_list;
  gtp_priv_ext_ie_t priv_ext;
} mbms_sess_upd_req_t;

typedef struct mbms_sess_upd_rsp_t {
  gtpv2c_header_t header;
  gtp_cause_ie_t cause;
  gtp_mbms_dist_ack_ie_t mbms_dist_ack;
  gtp_fully_qual_tunn_endpt_idnt_ie_t sn_u_sgsn_fteid;
  gtp_recovery_ie_t recovery;
  gtp_priv_ext_ie_t priv_ext;
} mbms_sess_upd_rsp_t;

typedef struct mbms_sess_stop_req_t {
  gtpv2c_header_t header;
  gtp_mbms_flow_idnt_ie_t mbms_flow_idnt;
  gtp_mbms_data_xfer_abs_time_ie_t mbms_data_xfer_stop;
  gtp_mbms_flags_ie_t mbms_flags;
  gtp_priv_ext_ie_t priv_ext;
} mbms_sess_stop_req_t;

#pragma pack()
#endif
