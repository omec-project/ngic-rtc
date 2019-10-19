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


#ifndef __PFCP_IES_H
#define __PFCP_IES_H


#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define CHAR_SIZE 8
#define PFCP_IE_CAUSE (19)
#define PFCP_IE_SRC_INTFC (20)
#define PFCP_IE_FTEID (21)
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_NTWK_INST (22)
#define PFCP_IE_SDF_FILTER (23)
#define PFCP_IE_APPLICATION_ID (24)
#define PFCP_IE_GATE_STATUS (25)
#define PFCP_IE_MBR (26)
#define PFCP_IE_GBR (27)
#define PFCP_IE_QER_CORR_ID (28)
#define PFCP_IE_PRECEDENCE (29)
#define PFCP_IE_TRNSPT_LVL_MARKING (30)
#define PFCP_IE_VOL_THRESH (31)
#define PFCP_IE_TIME_THRESHOLD (32)
#define PFCP_IE_MONITORING_TIME (33)
#define PFCP_IE_SBSQNT_VOL_THRESH (34)
#define PFCP_IE_SBSQNT_TIME_THRESH (35)
#define PFCP_IE_INACT_DET_TIME (36)
#define PFCP_IE_RPTNG_TRIGGERS (37)
#define PFCP_IE_REDIR_INFO (38)
#define PFCP_IE_REPORT_TYPE (39)
#define PFCP_IE_OFFENDING_IE (40)
#define PFCP_IE_FRWDNG_PLCY (41)
#define PFCP_IE_DST_INTFC (42)
#define PFCP_IE_UP_FUNC_FEAT (43)
#define PFCP_IE_APPLY_ACTION (44)
#define PFCP_IE_DNLNK_DATA_SVC_INFO (45)
#define PFCP_IE_DNLNK_DATA_NOTIF_DELAY (46)
#define PFCP_IE_DL_BUF_DUR (47)
#define PFCP_IE_DL_BUF_SUGGSTD_PCKT_CNT (48)
#define PFCP_IE_PFCPSMREQ_FLAGS (49)
#define PFCP_IE_PFCPSRRSP_FLAGS (50)
#define PFCP_IE_SEQUENCE_NUMBER (52)
#define PFCP_IE_METRIC (53)
#define PFCP_IE_TIMER (55)
#define PFCP_IE_PDR_ID (56)
#define PFCP_IE_FSEID (57)
/* TODO: Revisit this for change in yang */
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_NODE_ID (60)
#define NODE_ID_VALUE_LEN 8
#define PFCP_IE_PFD_CONTENTS (61)
#define PFCP_IE_MEAS_MTHD (62)
#define PFCP_IE_USAGE_RPT_TRIG (63)
#define PFCP_IE_MEAS_PERIOD (64)
#define PFCP_IE_FQCSID (65)
#define PDN_CONN_SET_IDENT_LEN 8
#define PFCP_IE_VOL_MEAS (66)
#define PFCP_IE_DUR_MEAS (67)
#define PFCP_IE_TIME_OF_FRST_PCKT (69)
#define PFCP_IE_TIME_OF_LST_PCKT (70)
#define PFCP_IE_QUOTA_HLDNG_TIME (71)
#define PFCP_IE_DRPD_DL_TRAFFIC_THRESH (72)
#define PFCP_IE_VOLUME_QUOTA (73)
#define PFCP_IE_TIME_QUOTA (74)
#define PFCP_IE_START_TIME (75)
#define PFCP_IE_END_TIME (76)
#define PFCP_IE_URR_ID (81)
#define PFCP_IE_LINKED_URR_ID (82)
#define PFCP_IE_OUTER_HDR_CREATION (84)
/* TODO: Revisit this for change in yang */
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_BAR_ID (88)
#define PFCP_IE_CP_FUNC_FEAT (89)
#define PFCP_IE_USAGE_INFO (90)
#define PFCP_IE_APP_INST_ID (91)
#define PFCP_IE_FLOW_INFO (92)
#define PFCP_IE_UE_IP_ADDRESS (93)
/* TODO: Revisit this for change in yang */
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_PACKET_RATE (94)
#define PFCP_IE_OUTER_HDR_REMOVAL (95)
#define PFCP_IE_RCVRY_TIME_STMP (96)
#define PFCP_IE_DL_FLOW_LVL_MARKING (97)
#define PFCP_IE_HDR_ENRCHMT (98)
#define PFCP_IE_MEAS_INFO (100)
#define PFCP_IE_NODE_RPT_TYPE (101)
#define PFCP_IE_RMT_GTPU_PEER (103)
/* TODO: Revisit this for change in yang */
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_URSEQN (104)
#define PFCP_IE_ACTVT_PREDEF_RULES (106)
#define PFCP_IE_DEACT_PREDEF_RULES (107)
#define PFCP_IE_FAR_ID (108)
#define PFCP_IE_QER_ID (109)
#define PFCP_IE_OCI_FLAGS (110)
#define PFCP_IE_UP_ASSN_REL_REQ (111)
#define PFCP_IE_GRACEFUL_REL_PERIOD (112)
#define PFCP_IE_PDN_TYPE (113)
#define PFCP_IE_FAILED_RULE_ID (114)
#define PFCP_IE_TIME_QUOTA_MECH (115)
#define PFCP_IE_USER_PLANE_IP_RSRC_INFO (116)
/* TODO: Revisit this for change in yang */
#define IPV6_ADDRESS_LEN 16
#define PFCP_IE_USER_PLANE_INACT_TIMER (117)
#define PFCP_IE_MULTIPLIER (119)
#define PFCP_IE_AGG_URR_ID (120)
#define PFCP_IE_SBSQNT_VOL_QUOTA (121)
#define PFCP_IE_SBSQNT_TIME_QUOTA (122)
#define PFCP_IE_RQI (123)
#define PFCP_IE_QFI (124)
#define PFCP_IE_QUERY_URR_REF (125)
#define PFCP_IE_ADD_USAGE_RPTS_INFO (126)
#define PFCP_IE_TRAFFIC_ENDPT_ID (131)
#define PFCP_IE_MAC_ADDRESS (133)
#define PFCP_IE_CTAG (134)
#define PFCP_IE_STAG (135)
#define PFCP_IE_ETHERTYPE (136)
#define PFCP_IE_PROXYING (137)
#define PFCP_IE_ETH_FLTR_ID (138)
#define PFCP_IE_ETH_FLTR_PROPS (139)
#define PFCP_IE_SUGGSTD_BUF_PCKTS_CNT (140)
#define PFCP_IE_USER_ID (141)
#define PFCP_IE_ETH_PDU_SESS_INFO (142)
#define PFCP_IE_MAC_ADDRS_DETCTD (144)
#define MAC_ADDR_VAL_LEN 8
#define PFCP_IE_MAC_ADDRS_RMVD (145)
#define MAC_ADDR_VAL_LEN 8
#define PFCP_IE_ETH_INACT_TIMER (146)
#define PFCP_IE_SBSQNT_EVNT_QUOTA (150)
#define PFCP_IE_SBSQNT_EVNT_THRESH (151)
#define PFCP_IE_TRC_INFO (152)
#define PFCP_IE_FRAMED_ROUTE (153)
#define PFCP_IE_FRAMED_ROUTING (154)
#define PFCP_IE_FRMD_IPV6_RTE (155)
#define PFCP_IE_EVENT_QUOTA (148)
#define PFCP_IE_EVENT_THRESHOLD (149)
#define PFCP_IE_EVNT_TIME_STMP (156)
#define PFCP_IE_AVGNG_WND (157)
#define PFCP_IE_PAGING_PLCY_INDCTR (158)

#pragma pack(1)

typedef struct pfcp_ie_header_t {
    uint16_t type;
    uint16_t len;
} pfcp_ie_header_t;

typedef struct pfcp_header_t {
    uint8_t s :1;
    uint8_t mp :1;
    uint8_t spare :3;
    uint8_t version :3;
    uint8_t message_type;
    uint16_t message_len;

    union seid_seqno {
        struct has_seid {
            uint64_t seid;
            uint32_t seq_no :24;
            uint8_t message_prio :4;
            uint8_t spare :4;
        } has_seid;
        struct no_seid {
            uint32_t seq_no :24;
            uint8_t spare :8;
        } no_seid;
    } seid_seqno;
} pfcp_header_t;

/**
Description -Cause
*/
typedef struct pfcp_cause_ie_t {
  pfcp_ie_header_t header;
  uint8_t cause_value;
} pfcp_cause_ie_t;

/**
Description -Source Interface
*/
typedef struct pfcp_src_intfc_ie_t {
  pfcp_ie_header_t header;
  uint8_t src_intfc_spare :4;
  uint8_t interface_value :4;
} pfcp_src_intfc_ie_t;

/**
Description -F-TEID
*/
typedef struct pfcp_fteid_ie_t {
  pfcp_ie_header_t header;
  uint8_t fteid_spare :4;
  uint8_t chid :1;
  uint8_t ch :1;
  uint8_t v6 :1;
  uint8_t v4 :1;
  uint32_t teid;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
  uint8_t choose_id;
} pfcp_fteid_ie_t;

/**
Description -Network Instance
*/
typedef struct pfcp_ntwk_inst_ie_t {
  pfcp_ie_header_t header;
/* TODO: Revisit this for change in yang */
  uint8_t ntwk_inst[32];
} pfcp_ntwk_inst_ie_t;

/**
Description -SDF Filter
*/
typedef struct pfcp_sdf_filter_ie_t {
	pfcp_ie_header_t header;
	uint8_t sdf_fltr_spare :3;
	uint8_t bid :1;
	uint8_t fl :1;
	uint8_t spi :1;
	uint8_t ttc :1;
	uint8_t fd :1;
	uint8_t sdf_fltr_spare2;
	uint16_t len_of_flow_desc;
	uint8_t flow_desc[255];
	uint16_t tos_traffic_cls;
	uint32_t secur_parm_idx;
	uint32_t flow_label :24;
	uint32_t sdf_filter_id;
} pfcp_sdf_filter_ie_t;

/**
Description -Application ID
*/
typedef struct pfcp_application_id_ie_t {
  pfcp_ie_header_t header;
  /* TODO: Revisit this for change in yang */
  uint8_t app_ident[8];
} pfcp_application_id_ie_t;

/**
Description -Gate Status
*/
typedef struct pfcp_gate_status_ie_t {
  pfcp_ie_header_t header;
  uint8_t gate_status_spare :4;
  uint8_t ul_gate :2;
  uint8_t dl_gate :2;
} pfcp_gate_status_ie_t;

/**
Description -MBR
*/
typedef struct pfcp_mbr_ie_t {
  pfcp_ie_header_t header;
  uint64_t ul_mbr :40;
  uint64_t dl_mbr :40;
} pfcp_mbr_ie_t;

/**
Description -GBR
*/
typedef struct pfcp_gbr_ie_t {
  pfcp_ie_header_t header;
  uint64_t ul_gbr :40;
  uint64_t dl_gbr :40;
} pfcp_gbr_ie_t;

/**
Description -QER Correlation ID
*/
typedef struct pfcp_qer_corr_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t qer_corr_id_val;
} pfcp_qer_corr_id_ie_t;

/**
Description -Precedence
*/
typedef struct pfcp_precedence_ie_t {
	pfcp_ie_header_t header;
	uint32_t prcdnc_val;
} pfcp_precedence_ie_t;

/**
Description -Transport Level Marking
*/
typedef struct pfcp_trnspt_lvl_marking_ie_t {
  pfcp_ie_header_t header;
  uint16_t tostraffic_cls;
} pfcp_trnspt_lvl_marking_ie_t;

/**
Description -Volume Threshold
*/
typedef struct pfcp_vol_thresh_ie_t {
  pfcp_ie_header_t header;
  uint8_t vol_thresh_spare :5;
  uint8_t dlvol :1;
  uint8_t ulvol :1;
  uint8_t tovol :1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
} pfcp_vol_thresh_ie_t;

/**
Description -Time Threshold
*/
typedef struct pfcp_time_threshold_ie_t {
  pfcp_ie_header_t header;
  uint32_t time_threshold;
} pfcp_time_threshold_ie_t;

/**
Description -Monitoring Time
*/
typedef struct pfcp_monitoring_time_ie_t {
  pfcp_ie_header_t header;
  uint32_t monitoring_time;
} pfcp_monitoring_time_ie_t;

/**
Description -Subsequent Volume Threshold
*/
typedef struct pfcp_sbsqnt_vol_thresh_ie_t {
  pfcp_ie_header_t header;
  uint8_t sbsqnt_vol_thresh_spare :5;
  uint8_t dlvol :1;
  uint8_t ulvol :1;
  uint8_t tovol :1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
} pfcp_sbsqnt_vol_thresh_ie_t;

/**
Description -Subsequent Time Threshold
*/
typedef struct pfcp_sbsqnt_time_thresh_ie_t {
  pfcp_ie_header_t header;
  uint32_t sbsqnt_time_thresh;
} pfcp_sbsqnt_time_thresh_ie_t;

/**
Description -Inactivity Detection Time
*/
typedef struct pfcp_inact_det_time_ie_t {
  pfcp_ie_header_t header;
  uint32_t inact_det_time;
} pfcp_inact_det_time_ie_t;

/**
Description -Reporting Triggers
*/
typedef struct pfcp_rptng_triggers_ie_t {
  pfcp_ie_header_t header;
  uint8_t liusa :1;
  uint8_t droth :1;
  uint8_t stopt :1;
  uint8_t start :1;
  uint8_t quhti :1;
  uint8_t timth :1;
  uint8_t volth :1;
  uint8_t perio :1;
  uint8_t rptng_triggers_spare :1;
  uint8_t rptng_triggers_spare2 :1;
  uint8_t evequ :1;
  uint8_t eveth :1;
  uint8_t macar :1;
  uint8_t envcl :1;
  uint8_t timqu :1;
  uint8_t volqu :1;
} pfcp_rptng_triggers_ie_t;

/**
Description -Redirect Information
*/
typedef struct pfcp_redir_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t redir_info_spare :4;
  uint8_t redir_addr_type :4;
  uint8_t redir_svr_addr_len;
  uint8_t redir_svr_addr;
} pfcp_redir_info_ie_t;

/**
Description -Report Type
*/
typedef struct pfcp_report_type_ie_t {
  pfcp_ie_header_t header;
  uint8_t rpt_type_spare :4;
  uint8_t upir :1;
  uint8_t erir :1;
  uint8_t usar :1;
  uint8_t dldr :1;
} pfcp_report_type_ie_t;

/**
Description -Offending IE
*/
typedef struct pfcp_offending_ie_ie_t {
  pfcp_ie_header_t header;
  uint16_t type_of_the_offending_ie;
} pfcp_offending_ie_ie_t;

/**
Description -Forwarding Policy
*/
typedef struct pfcp_frwdng_plcy_ie_t {
  pfcp_ie_header_t header;
  uint8_t frwdng_plcy_ident_len;
  uint8_t frwdng_plcy_ident;
} pfcp_frwdng_plcy_ie_t;

/**
Description -Destination Interface
*/
typedef struct pfcp_dst_intfc_ie_t {
  pfcp_ie_header_t header;
  uint8_t dst_intfc_spare :4;
  uint8_t interface_value :4;
} pfcp_dst_intfc_ie_t;

/**
Description -UP Function Features
*/
typedef struct pfcp_up_func_feat_ie_t {
  pfcp_ie_header_t header;
  uint16_t sup_feat;
} pfcp_up_func_feat_ie_t;

/**
Description -Apply Action
*/
typedef struct pfcp_apply_action_ie_t {
  pfcp_ie_header_t header;
  uint8_t apply_act_spare :1;
  uint8_t apply_act_spare2 :1;
  uint8_t apply_act_spare3 :1;
  uint8_t dupl :1;
  uint8_t nocp :1;
  uint8_t buff :1;
  uint8_t forw :1;
  uint8_t drop :1;
} pfcp_apply_action_ie_t;

/**
Description -Downlink Data Service Information
*/
typedef struct pfcp_dnlnk_data_svc_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t dnlnk_data_svc_info_spare :6;
  uint8_t qfii :1;
  uint8_t ppi :1;
  uint8_t dnlnk_data_svc_info_spare2 :2;
  uint8_t paging_plcy_indctn_val :6;
  uint8_t dnlnk_data_svc_info_spare3 :2;
  uint8_t qfi :6;
} pfcp_dnlnk_data_svc_info_ie_t;

/**
Description -Downlink Data Notification Delay
*/
typedef struct pfcp_dnlnk_data_notif_delay_ie_t {
  pfcp_ie_header_t header;
  uint8_t delay_val_in_integer_multiples_of_50_millisecs_or_zero;
} pfcp_dnlnk_data_notif_delay_ie_t;

/**
Description -DL Buffering Duration
*/
typedef struct pfcp_dl_buf_dur_ie_t {
  pfcp_ie_header_t header;
  uint8_t timer_unit :3;
  uint8_t timer_value :5;
} pfcp_dl_buf_dur_ie_t;

/**
Description -DL Buffering Suggested Packet Count
*/
typedef struct pfcp_dl_buf_suggstd_pckt_cnt_ie_t {
  pfcp_ie_header_t header;
  uint8_t pckt_cnt_val;
} pfcp_dl_buf_suggstd_pckt_cnt_ie_t;

/**
Description -PFCPSMReq-Flags
*/
typedef struct pfcp_pfcpsmreq_flags_ie_t {
  pfcp_ie_header_t header;
  uint8_t pfcpsmreq_flgs_spare :1;
  uint8_t pfcpsmreq_flgs_spare2 :1;
  uint8_t pfcpsmreq_flgs_spare3 :1;
  uint8_t pfcpsmreq_flgs_spare4 :1;
  uint8_t pfcpsmreq_flgs_spare5 :1;
  uint8_t qaurr :1;
  uint8_t sndem :1;
  uint8_t drobu :1;
} pfcp_pfcpsmreq_flags_ie_t;

/**
Description -PFCPSRRsp-Flags
*/
typedef struct pfcp_pfcpsrrsp_flags_ie_t {
  pfcp_ie_header_t header;
  uint8_t pfcpsrrsp_flgs_spare :1;
  uint8_t pfcpsrrsp_flgs_spare2 :1;
  uint8_t pfcpsrrsp_flgs_spare3 :1;
  uint8_t pfcpsrrsp_flgs_spare4 :1;
  uint8_t pfcpsrrsp_flgs_spare5 :1;
  uint8_t pfcpsrrsp_flgs_spare6 :1;
  uint8_t pfcpsrrsp_flgs_spare7 :1;
  uint8_t drobu :1;
} pfcp_pfcpsrrsp_flags_ie_t;

/**
Description -Sequence Number
*/
typedef struct pfcp_sequence_number_ie_t {
  pfcp_ie_header_t header;
  uint32_t sequence_number;
} pfcp_sequence_number_ie_t;

/**
Description -Metric
*/
typedef struct pfcp_metric_ie_t {
  pfcp_ie_header_t header;
  uint8_t metric;
} pfcp_metric_ie_t;

/**
Description -Timer
*/
typedef struct pfcp_timer_ie_t {
  pfcp_ie_header_t header;
  uint8_t timer_unit :3;
  uint8_t timer_value :5;
} pfcp_timer_ie_t;

/**
Description -PDR ID
*/
typedef struct pfcp_pdr_id_ie_t {
	pfcp_ie_header_t header;
	uint16_t rule_id;
} pfcp_pdr_id_ie_t;

/**
	Description -F-SEID
*/
typedef struct pfcp_fseid_ie_t {
	pfcp_ie_header_t header;
	uint8_t fseid_spare :1;
	uint8_t fseid_spare2 :1;
	uint8_t fseid_spare3 :1;
	uint8_t fseid_spare4 :1;
	uint8_t fseid_spare5 :1;
	uint8_t fseid_spare6 :1;
	uint8_t v4 :1;
	uint8_t v6 :1;
	uint64_t seid;
	uint32_t ipv4_address;
	uint8_t ipv6_address[IPV6_ADDRESS_LEN];
} pfcp_fseid_ie_t;

/**
Description -Node ID
*/
typedef struct pfcp_node_id_ie_t {
  pfcp_ie_header_t header;
  uint8_t node_id_spare :4;
  uint8_t node_id_type :4;
  uint8_t node_id_value[NODE_ID_VALUE_LEN];
} pfcp_node_id_ie_t;

/**
Description -PFD contents
*/
typedef struct pfcp_pfd_contents_ie_t {
  pfcp_ie_header_t header;
  uint8_t pfd_contents_spare :4;
  uint8_t pfd_contents_cp :1;
  uint8_t dn :1;
  uint8_t url :1;
  uint8_t fd :1;
  uint8_t pfd_contents_spare2;
  uint16_t len_of_flow_desc;
  uint8_t flow_desc;
  uint16_t length_of_url;
  uint8_t url2;
  uint16_t len_of_domain_nm;
  uint8_t domain_name;
  uint16_t len_of_cstm_pfd_cntnt;
  uint8_t  *cstm_pfd_cntnt;
} pfcp_pfd_contents_ie_t;

/**
Description -Measurement Method
*/
typedef struct pfcp_meas_mthd_ie_t {
  pfcp_ie_header_t header;
  uint8_t meas_mthd_spare :1;
  uint8_t meas_mthd_spare2 :1;
  uint8_t meas_mthd_spare3 :1;
  uint8_t meas_mthd_spare4 :1;
  uint8_t meas_mthd_spare5 :1;
  uint8_t event :1;
  uint8_t volum :1;
  uint8_t durat :1;
} pfcp_meas_mthd_ie_t;

/**
	Description -Usage Report Trigger
*/
typedef struct pfcp_usage_rpt_trig_ie_t {
	pfcp_ie_header_t header;
	uint8_t immer :1;
	uint8_t droth :1;
	uint8_t stopt :1;
	uint8_t start :1;
	uint8_t quhti :1;
	uint8_t timth :1;
	uint8_t volth :1;
	uint8_t perio :1;
	uint8_t eveth :1;
	uint8_t macar :1;
	uint8_t envcl :1;
	uint8_t monit :1;
	uint8_t termr :1;
	uint8_t liusa :1;
	uint8_t timqu :1;
	uint8_t volqu :1;
	uint8_t usage_rpt_trig_spare :7;
	uint8_t evequ :1;
} pfcp_usage_rpt_trig_ie_t;

/**
Description -Measurement Period
*/
typedef struct pfcp_meas_period_ie_t {
  pfcp_ie_header_t header;
  uint32_t meas_period;
} pfcp_meas_period_ie_t;

/**
Description -FQ-CSID
*/
typedef struct pfcp_fqcsid_ie_t {
	pfcp_ie_header_t header;
	uint8_t fqcsid_node_id_type :4;
	uint8_t number_of_csids :4;
	//TODO: Revisit this for change in yang
	uint8_t node_address[IPV6_ADDRESS_LEN];
	uint16_t pdn_conn_set_ident[PDN_CONN_SET_IDENT_LEN];
} pfcp_fqcsid_ie_t;

/**
Description -Volume Measurement
*/
typedef struct pfcp_vol_meas_ie_t {
  pfcp_ie_header_t header;
  uint8_t vol_meas_spare :5;
  uint8_t dlvol :1;
  uint8_t ulvol :1;
  uint8_t tovol :1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
} pfcp_vol_meas_ie_t;

/**
Description -Duration Measurement
*/
typedef struct pfcp_dur_meas_ie_t {
  pfcp_ie_header_t header;
  uint32_t duration_value;
} pfcp_dur_meas_ie_t;

/**
Description -Time of First Packet
*/
typedef struct pfcp_time_of_frst_pckt_ie_t {
  pfcp_ie_header_t header;
  uint32_t time_of_frst_pckt;
} pfcp_time_of_frst_pckt_ie_t;

/**
Description -Time of Last Packet
*/
typedef struct pfcp_time_of_lst_pckt_ie_t {
  pfcp_ie_header_t header;
  uint32_t time_of_lst_pckt;
} pfcp_time_of_lst_pckt_ie_t;

/**
Description -Quota Holding Time
*/
typedef struct pfcp_quota_hldng_time_ie_t {
  pfcp_ie_header_t header;
  uint32_t quota_hldng_time_val;
} pfcp_quota_hldng_time_ie_t;

/**
Description -Dropped DL Traffic Threshold
*/
typedef struct pfcp_drpd_dl_traffic_thresh_ie_t {
  pfcp_ie_header_t header;
  uint8_t drpd_dl_traffic_thresh_spare :6;
  uint8_t dlby :1;
  uint8_t dlpa :1;
  uint64_t dnlnk_pckts;
  uint64_t nbr_of_bytes_of_dnlnk_data;
} pfcp_drpd_dl_traffic_thresh_ie_t;

/**
Description -Volume Quota
*/
typedef struct pfcp_volume_quota_ie_t {
  pfcp_ie_header_t header;
  uint8_t vol_quota_spare :5;
  uint8_t dlvol :1;
  uint8_t ulvol :1;
  uint8_t tovol :1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
} pfcp_volume_quota_ie_t;

/**
Description -Time Quota
*/
typedef struct pfcp_time_quota_ie_t {
  pfcp_ie_header_t header;
  uint32_t time_quota_val;
} pfcp_time_quota_ie_t;

/**
Description -Start Time
*/
typedef struct pfcp_start_time_ie_t {
  pfcp_ie_header_t header;
  uint32_t start_time;
} pfcp_start_time_ie_t;

/**
Description -End Time
*/
typedef struct pfcp_end_time_ie_t {
  pfcp_ie_header_t header;
  uint32_t end_time;
} pfcp_end_time_ie_t;

/**
Description -URR ID
*/
typedef struct pfcp_urr_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t urr_id_value;
} pfcp_urr_id_ie_t;

/**
Description -Linked URR ID
*/
typedef struct pfcp_linked_urr_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t lnkd_urr_id_val;
} pfcp_linked_urr_id_ie_t;

/**
Description -Outer Header Creation
*/
typedef struct pfcp_outer_hdr_creation_ie_t {
  pfcp_ie_header_t header;
  uint16_t outer_hdr_creation_desc;
  uint32_t teid;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
  uint16_t port_number;
  uint32_t ctag :24;
  uint32_t stag :24;
} pfcp_outer_hdr_creation_ie_t;

/**
Description -BAR ID
*/
typedef struct pfcp_bar_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t bar_id_value;
} pfcp_bar_id_ie_t;

/**
Description -CP Function Features
*/
typedef struct pfcp_cp_func_feat_ie_t {
  pfcp_ie_header_t header;
  uint8_t sup_feat;
} pfcp_cp_func_feat_ie_t;

/**
Description -Usage Information
*/
typedef struct pfcp_usage_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t usage_info_spare :5;
  uint8_t ube :1;
  uint8_t uae :1;
  uint8_t aft :1;
  uint8_t bef :1;
} pfcp_usage_info_ie_t;

/**
Description -Application Instance ID
*/
typedef struct pfcp_app_inst_id_ie_t {
  pfcp_ie_header_t header;
  uint8_t app_inst_ident;
} pfcp_app_inst_id_ie_t;

/**
Description -Flow Information
*/
typedef struct pfcp_flow_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t flow_info_spare :5;
  uint8_t flow_direction :3;
  uint16_t len_of_flow_desc;
  uint8_t flow_desc;
} pfcp_flow_info_ie_t;

/**
Description -UE IP Address
*/
typedef struct pfcp_ue_ip_address_ie_t {
  pfcp_ie_header_t header;
  uint8_t ue_ip_addr_spare :4;
  uint8_t ipv6d :1;
  uint8_t sd :1;
  uint8_t v4 :1;
  uint8_t v6 :1;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
  uint8_t ipv6_pfx_dlgtn_bits;
} pfcp_ue_ip_address_ie_t;

/**
Description -Packet Rate
*/
typedef struct pfcp_packet_rate_ie_t {
  pfcp_ie_header_t header;
  uint8_t pckt_rate_spare :6;
  uint8_t dlpr :1;
  uint8_t ulpr :1;
  uint8_t pckt_rate_spare2 :5;
  uint8_t uplnk_time_unit :3;
  uint16_t max_uplnk_pckt_rate;
  uint8_t pckt_rate_spare3 :5;
  uint8_t dnlnk_time_unit :3;
  uint16_t max_dnlnk_pckt_rate;
} pfcp_packet_rate_ie_t;

/**
Description -Outer Header Removal
*/
typedef struct pfcp_outer_hdr_removal_ie_t {
  pfcp_ie_header_t header;
  uint8_t outer_hdr_removal_desc;
/* TODO: Revisit this for change in yang */
//  uint8_t gtpu_ext_hdr_del;
} pfcp_outer_hdr_removal_ie_t;

/**
Description -Recovery Time Stamp
*/
typedef struct pfcp_rcvry_time_stmp_ie_t {
  pfcp_ie_header_t header;
  uint32_t rcvry_time_stmp_val;
} pfcp_rcvry_time_stmp_ie_t;

/**
Description -DL Flow Level Marking
*/
typedef struct pfcp_dl_flow_lvl_marking_ie_t {
  pfcp_ie_header_t header;
  uint8_t dl_flow_lvl_marking_spare :6;
  uint8_t sci :1;
  uint8_t ttc :1;
  uint16_t tostraffic_cls;
  uint16_t svc_cls_indctr;
} pfcp_dl_flow_lvl_marking_ie_t;

/**
Description -Header Enrichment
*/
typedef struct pfcp_hdr_enrchmt_ie_t {
  pfcp_ie_header_t header;
  uint8_t hdr_enrchmt_spare :3;
  uint8_t header_type :5;
  uint8_t len_of_hdr_fld_nm;
  uint8_t hdr_fld_nm;
  uint8_t len_of_hdr_fld_val;
  uint8_t hdr_fld_val;
} pfcp_hdr_enrchmt_ie_t;

/**
Description -Measurement Information
*/
typedef struct pfcp_meas_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t meas_info_spare :4;
  uint8_t istm :1;
  uint8_t radi :1;
  uint8_t inam :1;
  uint8_t mbqe :1;
} pfcp_meas_info_ie_t;

/**
Description -Node Report Type
*/
typedef struct pfcp_node_rpt_type_ie_t {
  pfcp_ie_header_t header;
  uint8_t node_rpt_type_spare :7;
  uint8_t upfr :1;
} pfcp_node_rpt_type_ie_t;

/**
Description -Remote GTP-U Peer
*/
typedef struct pfcp_rmt_gtpu_peer_ie_t {
  pfcp_ie_header_t header;
  uint8_t rmt_gtpu_peer_spare :6;
  uint8_t v4 :1;
  uint8_t v6 :1;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
} pfcp_rmt_gtpu_peer_ie_t;

/**
Description -UR-SEQN
*/
typedef struct pfcp_urseqn_ie_t {
  pfcp_ie_header_t header;
  uint32_t urseqn;
} pfcp_urseqn_ie_t;

/**
Description -Activate Predefined Rules
*/
typedef struct pfcp_actvt_predef_rules_ie_t {
  pfcp_ie_header_t header;
  /* TODO: Revisit this for change in yang */
  uint8_t predef_rules_nm[8];
} pfcp_actvt_predef_rules_ie_t;

/**
Description -Deactivate Predefined Rules
*/
typedef struct pfcp_deact_predef_rules_ie_t {
  pfcp_ie_header_t header;
  uint8_t predef_rules_nm;
} pfcp_deact_predef_rules_ie_t;

/**
Description -FAR ID
*/
typedef struct pfcp_far_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t far_id_value;
} pfcp_far_id_ie_t;

/**
Description -QER ID
*/
typedef struct pfcp_qer_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t qer_id_value;
} pfcp_qer_id_ie_t;

/**
Description -OCI Flags
*/
typedef struct pfcp_oci_flags_ie_t {
  pfcp_ie_header_t header;
  uint8_t oci_flags_spare :7;
  uint8_t aoci :1;
} pfcp_oci_flags_ie_t;

/**
Description -UP Association Release Request
*/
typedef struct pfcp_up_assn_rel_req_ie_t {
  pfcp_ie_header_t header;
  uint8_t up_assn_rel_req_spare :7;
  uint8_t sarr :1;
} pfcp_up_assn_rel_req_ie_t;

/**
Description -Graceful Release Period
*/
typedef struct pfcp_graceful_rel_period_ie_t {
  pfcp_ie_header_t header;
  uint8_t timer_unit :3;
  uint8_t timer_value :5;
} pfcp_graceful_rel_period_ie_t;

/**
Description -PDN Type
*/
typedef struct pfcp_pdn_type_ie_t {
  pfcp_ie_header_t header;
  uint8_t pdn_type_spare :5;
  uint8_t pdn_type :3;
} pfcp_pdn_type_ie_t;

/**
Description -Failed Rule ID
*/
typedef struct pfcp_failed_rule_id_ie_t {
  pfcp_ie_header_t header;
  uint8_t failed_rule_id_spare :3;
  uint8_t rule_id_type :5;
/* TODO: Revisit this for change in yang */
  uint8_t rule_id_value[8];
} pfcp_failed_rule_id_ie_t;

/**
Description -Time Quota Mechanism
*/
typedef struct pfcp_time_quota_mech_ie_t {
  pfcp_ie_header_t header;
  uint8_t time_quota_mech_spare :6;
  uint8_t btit :2;
  uint32_t base_time_int;
} pfcp_time_quota_mech_ie_t;

/**
Description -User Plane IP Resource Information
*/
typedef struct pfcp_user_plane_ip_rsrc_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t user_plane_ip_rsrc_info_spare :1;
  uint8_t assosi :1;
  uint8_t assoni :1;
  uint8_t teidri :3;
  uint8_t v6 :1;
  uint8_t v4 :1;
  uint8_t teid_range;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
  uint8_t ntwk_inst;
  uint8_t user_plane_ip_rsrc_info_spare2 :4;
  uint8_t src_intfc :4;
} pfcp_user_plane_ip_rsrc_info_ie_t;

/**
Description -User Plane Inactivity Timer
*/
typedef struct pfcp_user_plane_inact_timer_ie_t {
	pfcp_ie_header_t header;
	uint32_t user_plane_inact_timer;
} pfcp_user_plane_inact_timer_ie_t;

/**
Description -Multiplier
*/
typedef struct pfcp_multiplier_ie_t {
  pfcp_ie_header_t header;
  uint64_t value_digits;
  uint32_t exponent;
} pfcp_multiplier_ie_t;

/**
Description -Aggregated URR ID
*/
typedef struct pfcp_agg_urr_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t urr_id_value;
} pfcp_agg_urr_id_ie_t;

/**
Description -Subsequent Volume Quota
*/
typedef struct pfcp_sbsqnt_vol_quota_ie_t {
  pfcp_ie_header_t header;
  uint8_t sbsqnt_vol_quota_spare :5;
  uint8_t dlvol :1;
  uint8_t ulvol :1;
  uint8_t tovol :1;
  uint64_t total_volume;
  uint64_t uplink_volume;
  uint64_t downlink_volume;
} pfcp_sbsqnt_vol_quota_ie_t;

/**
Description -Subsequent Time Quota
*/
typedef struct pfcp_sbsqnt_time_quota_ie_t {
  pfcp_ie_header_t header;
  uint32_t time_quota_val;
} pfcp_sbsqnt_time_quota_ie_t;

/**
Description -RQI
*/
typedef struct pfcp_rqi_ie_t {
  pfcp_ie_header_t header;
  uint8_t rqi_spare :7;
  uint8_t rqi :1;
} pfcp_rqi_ie_t;

/**
Description -QFI
*/
typedef struct pfcp_qfi_ie_t {
  pfcp_ie_header_t header;
  uint8_t qfi_spare :2;
  uint8_t qfi_value :6;
} pfcp_qfi_ie_t;

/**
Description -Query URR Reference
*/
typedef struct pfcp_query_urr_ref_ie_t {
	pfcp_ie_header_t header;
	uint32_t query_urr_ref_val;
} pfcp_query_urr_ref_ie_t;

/**
Description -Additional Usage Reports Information
*/
typedef struct pfcp_add_usage_rpts_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t auri :1;
  uint8_t nbr_of_add_usage_rpts_val :7;
  uint8_t nbr_of_add_usage_rpts_value2;
} pfcp_add_usage_rpts_info_ie_t;

/**
Description -Traffic Endpoint ID
*/
typedef struct pfcp_traffic_endpt_id_ie_t {
  pfcp_ie_header_t header;
  uint8_t traffic_endpt_id_val;
} pfcp_traffic_endpt_id_ie_t;

/**
Description -MAC address
*/
typedef struct pfcp_mac_address_ie_t {
  pfcp_ie_header_t header;
  uint8_t spare :5;
  uint8_t udes :1;
  uint8_t usou :1;
  uint8_t dest :1;
  uint8_t sour :1;
  uint64_t src_mac_addr_val :48;
  uint64_t dst_mac_addr_val :48;
  uint64_t upr_src_mac_addr_val :48;
  uint64_t upr_dst_mac_addr_val :48;
} pfcp_mac_address_ie_t;

/**
Description -C-TAG
*/
typedef struct pfcp_ctag_ie_t {
  pfcp_ie_header_t header;
  uint8_t ctag_spare :5;
  uint8_t ctag_vid :1;
  uint8_t ctag_dei :1;
  uint8_t ctag_pcp :1;
  uint8_t cvid_value :4;
  uint8_t ctag_dei_flag :1;
  uint8_t ctag_pcp_value :3;
  uint8_t cvid_value2;
} pfcp_ctag_ie_t;

/**
Description -S-TAG
*/
typedef struct pfcp_stag_ie_t {
  pfcp_ie_header_t header;
  uint8_t stag_spare :5;
  uint8_t stag_vid :1;
  uint8_t stag_dei :1;
  uint8_t stag_pcp :1;
  uint8_t svid_value :4;
  uint8_t stag_dei_flag :1;
  uint8_t stag_pcp_value :3;
  uint8_t svid_value2;
} pfcp_stag_ie_t;

/**
Description -Ethertype
*/
typedef struct pfcp_ethertype_ie_t {
  pfcp_ie_header_t header;
  uint16_t ethertype;
} pfcp_ethertype_ie_t;

/**
Description -Proxying
*/
typedef struct pfcp_proxying_ie_t {
  pfcp_ie_header_t header;
  uint8_t proxying_spare :6;
  uint8_t ins :1;
  uint8_t arp :1;
} pfcp_proxying_ie_t;

/**
Description -Ethernet Filter ID
*/
typedef struct pfcp_eth_fltr_id_ie_t {
  pfcp_ie_header_t header;
  uint32_t eth_fltr_id_val;
} pfcp_eth_fltr_id_ie_t;

/**
Description -Ethernet Filter Properties
*/
typedef struct pfcp_eth_fltr_props_ie_t {
  pfcp_ie_header_t header;
  uint8_t eth_fltr_props_spare :7;
  uint8_t bide :1;
} pfcp_eth_fltr_props_ie_t;

/**
Description -Suggested Buffering Packets Count
*/
typedef struct pfcp_suggstd_buf_pckts_cnt_ie_t {
  pfcp_ie_header_t header;
  uint8_t pckt_cnt_val;
} pfcp_suggstd_buf_pckts_cnt_ie_t;

/**
Description -User ID
*/
typedef struct pfcp_user_id_ie_t {
	pfcp_ie_header_t header;
	uint8_t user_id_spare :4;
	uint8_t naif :1;
	uint8_t msisdnf :1;
	uint8_t imeif :1;
	uint8_t imsif :1;
	uint8_t length_of_imsi;
	/* TODO: Revisit this for change in yang */
	uint8_t imsi[8];
	uint8_t length_of_imei;
	/* TODO: Revisit this for change in yang */
	uint8_t imei[8];
	uint8_t len_of_msisdn;
	/* TODO: Revisit this for change in yang */
	uint8_t msisdn[8];
	uint8_t length_of_nai;
	/* TODO: Revisit this for change in yang */
	uint8_t nai[8];
} pfcp_user_id_ie_t;

/**
Description -Ethernet PDU Session Information
*/
typedef struct pfcp_eth_pdu_sess_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t eth_pdu_sess_info_spare :7;
  uint8_t ethi :1;
} pfcp_eth_pdu_sess_info_ie_t;

/**
Description -MAC Addresses Detected
*/
typedef struct pfcp_mac_addrs_detctd_ie_t {
  pfcp_ie_header_t header;
  uint8_t nbr_of_mac_addrs;
  uint64_t mac_addr_val[MAC_ADDR_VAL_LEN];
} pfcp_mac_addrs_detctd_ie_t;

/**
Description -MAC Addresses Removed
*/
typedef struct pfcp_mac_addrs_rmvd_ie_t {
  pfcp_ie_header_t header;
  uint8_t nbr_of_mac_addrs;
  uint64_t mac_addr_val[MAC_ADDR_VAL_LEN];
} pfcp_mac_addrs_rmvd_ie_t;

/**
Description -Ethernet Inactivity Timer
*/
typedef struct pfcp_eth_inact_timer_ie_t {
  pfcp_ie_header_t header;
  uint32_t eth_inact_timer;
} pfcp_eth_inact_timer_ie_t;

/**
Description -Subsequent Event Quota
*/
typedef struct pfcp_sbsqnt_evnt_quota_ie_t {
  pfcp_ie_header_t header;
  uint32_t sbsqnt_evnt_quota;
} pfcp_sbsqnt_evnt_quota_ie_t;

/**
Description -Subsequent Event Threshold
*/
typedef struct pfcp_sbsqnt_evnt_thresh_ie_t {
  pfcp_ie_header_t header;
  uint32_t sbsqnt_evnt_thresh;
} pfcp_sbsqnt_evnt_thresh_ie_t;

/**
Description -Trace Information
*/
typedef struct pfcp_trc_info_ie_t {
  pfcp_ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint32_t trace_id :24;
  uint8_t len_of_trigrng_evnts;
  uint8_t trigrng_evnts;
  uint8_t sess_trc_depth;
  uint8_t len_of_list_of_intfcs;
  uint8_t list_of_intfcs;
  uint8_t len_of_ip_addr_of_trc_coll_ent;
  uint8_t ip_addr_of_trc_coll_ent;
} pfcp_trc_info_ie_t;

/**
Description -Framed-Route
*/
typedef struct pfcp_framed_route_ie_t {
  pfcp_ie_header_t header;
  uint8_t framed_route;
} pfcp_framed_route_ie_t;

/**
Description -Framed-Routing
*/
typedef struct pfcp_framed_routing_ie_t {
  pfcp_ie_header_t header;
  uint32_t framed_routing;
} pfcp_framed_routing_ie_t;

/**
Description -Framed-IPv6-Route
*/
typedef struct pfcp_frmd_ipv6_rte_ie_t {
  pfcp_ie_header_t header;
  uint8_t frmd_ipv6_rte;
} pfcp_frmd_ipv6_rte_ie_t;

/**
Description -Event Quota
*/
typedef struct pfcp_event_quota_ie_t {
  pfcp_ie_header_t header;
  uint32_t sbsqnt_evnt_quota;
} pfcp_event_quota_ie_t;

/**
Description -Event Threshold
*/
typedef struct pfcp_event_threshold_ie_t {
  pfcp_ie_header_t header;
  uint32_t event_threshold;
} pfcp_event_threshold_ie_t;

/**
Description -Event Time Stamp
*/
typedef struct pfcp_evnt_time_stmp_ie_t {
  pfcp_ie_header_t header;
  uint32_t evnt_time_stmp;
} pfcp_evnt_time_stmp_ie_t;

/**
Description -Averaging Window
*/
typedef struct pfcp_avgng_wnd_ie_t {
  pfcp_ie_header_t header;
  uint32_t avgng_wnd;
} pfcp_avgng_wnd_ie_t;

/**
Description -Paging Policy Indicator
*/
typedef struct pfcp_paging_plcy_indctr_ie_t {
  pfcp_ie_header_t header;
  uint8_t paging_plcy_indctr_spare :5;
  uint8_t ppi_value :3;
} pfcp_paging_plcy_indctr_ie_t;

enum cause_values_type {
  REQUESTACCEPTED =1,
  REQUESTREJECTED =64,
  SESSIONCONTEXTNOTFOUND =65,
  MANDATORYIEMISSING =66,
  CONDITIONALIEMISSING =67,
  INVALIDLENGTH =68,
  MANDATORYIEINCORRECT =69,
  INVALIDFORWARDINGPOLICY =70,
  INVALIDFTEIDALLOCATIONOPTION =71,
  NOESTABLISHEDPFCPASSOCIATION =72,
  RULECREATION_MODIFICATIONFAILURE =73,
  PFCPENTITYINCONGESTION =74,
  NORESOURCESAVAILABLE =75,
  SERVICENOTSUPPORTED =76,
  SYSTEMFAILURE =77,
};

struct src_intfc_intfc_valType_t {
  uint8_t zero :1;
  uint8_t one :1;
  uint8_t two :1;
  uint8_t three :1;
  uint8_t fourto15 :1;
} src_intfc_intfc_valType_t;

enum redir_addr_type_type {
  IPV4ADDRESS =0,
  IPV6ADDRESS =1,
  URL =2,
  SIPURI =3,
};

struct dst_intfc_intfc_valType_t {
  uint8_t zero :1;
  uint8_t one :1;
  uint8_t two :1;
  uint8_t three :1;
  uint8_t four :1;
  uint8_t fiveto15 :1;
} dst_intfc_intfc_valType_t;

struct up_func_featType_t {
  uint8_t bucp :1;
  uint8_t ddnd :1;
  uint8_t dlbd :1;
  uint8_t trst :1;
  uint8_t ftup :1;
  uint8_t pfdm :1;
  uint8_t heeu :1;
  uint8_t treu :1;
  uint8_t empu :1;
  uint8_t pdiu :1;
  uint8_t udbc :1;
  uint8_t quoac :1;
  uint8_t trace :1;
  uint8_t frrt :1;
} up_func_featType_t;

enum node_id_type_type {
  NODE_ID_TYPE_TYPE_IPV4ADDRESS =0,
  NODE_ID_TYPE_TYPE_IPV6ADDRESS =1,
  FQDN =2,
};

struct outer_hdr_creation_descType_t {
  uint8_t gtpu_udp_ipv4 :1;
  uint8_t gtpu_udp_ipv6 :1;
  uint8_t udp_ipv4 :1;
  uint8_t udp_ipv6 :1;
  uint8_t ipv4 :1;
  uint8_t ipv6 :1;
  uint8_t ctag :1;
  uint8_t stag :1;
} outer_hdr_creation_descType_t;

struct cp_func_featType_t {
  uint8_t load :1;
  uint8_t ovrl :1;
} cp_func_featType_t;

enum flow_direction_type {
  UNSPECIFIED =0,
  DOWNLINK =1,
  UPLINK =2,
  BIDIRECTIONAL =3,
};

enum outer_hdr_removal_desc_type {
  GTPU_UDP_IPV4 =0,
  GTPU_UDP_IPV6 =1,
  UDP_IPV4 =2,
  UDP_IPV6 =3,
  IPV4 =4,
  IPV6 =5,
  GTPU_UDP_IP =6,
  VLANSTAG =7,
  STAGANDCTAG =8,
};

enum header_type_type {
  HTTP =0,
  HEADER_TYPE_TYPE_HTTP =0,
};

enum base_time_int_type_type {
  CTP =0,
  DTP =1,
};

#pragma pack()
#endif
