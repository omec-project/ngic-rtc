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


#ifndef __GTP_IES_H
#define __GTP_IES_H


#include <stdint.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

#define IE_HEADER_SIZE sizeof(ie_header_t)

#define CHAR_SIZE 8
#define GTP_IE_IMSI (1)
#define GTP_IE_CAUSE (2)
#define GTP_IE_RECOVERY (3)
#define GTP_IE_ACC_PT_NAME (71)
#define APN_LEN 128
#define GTP_IE_AGG_MAX_BIT_RATE (72)
#define GTP_IE_EPS_BEARER_ID (73)
#define GTP_IE_IP_ADDRESS (74)
#define GTP_IE_MBL_EQUIP_IDNTY (75)
#define GTP_IE_MSISDN (76)
#define GTP_IE_INDICATION (77)
#define GTP_IE_PROT_CFG_OPTS (78)
#define GTP_IE_PDN_ADDR_ALLOC (79)
#define PDN_ADDR_AND_PFX_LEN 21
#define GTP_IE_BEARER_QLTY_OF_SVC (80)
#define GTP_IE_FLOW_QLTY_OF_SVC (81)
#define GTP_IE_RAT_TYPE (82)
#define GTP_IE_SERVING_NETWORK (83)
#define GTP_IE_EPS_BEARER_LVL_TRAFFIC_FLOW_TMPL (84)
#define GTP_IE_TRAFFIC_AGG_DESC (85)
#define GTP_IE_USER_LOC_INFO (86)
#define GTP_IE_FULLY_QUAL_TUNN_ENDPT_IDNT (87)
#define IPV6_ADDRESS_LEN 16
#define GTP_IE_TMSI (88)
#define GTP_IE_GLOBAL_CN_ID (89)
#define GTP_IE_S103_PDN_DATA_FWDNG_INFO (90)
#define GTP_IE_S1U_DATA_FWDNG (91)
#define GTP_IE_DELAY_VALUE (92)
#define GTP_IE_BEARER_CONTEXT (93)
#define BEARER_CONTEXT_LEN 8
#define GTP_IE_CHARGING_ID (94)
#define GTP_IE_CHRGNG_CHAR (95)
#define GTP_IE_TRC_INFO (96)
#define TRIGRNG_EVNTS_LEN 9
#define LIST_OF_INTFCS_LEN 12
#define GTP_IE_BEARER_FLAGS (97)
#define GTP_IE_PDN_TYPE (99)
#define GTP_IE_PROC_TRANS_ID (100)
#define GTP_IE_GSM_KEY_AND_TRIPLETS (103)
#define GTP_IE_UMTS_KEY_USED_CIPHER_AND_QUINTUPLETS (104)
#define CK_LEN 16
#define IK_LEN 16
#define GTP_IE_GSM_KEY_USED_CIPHER_AND_QUINTUPLETS (105)
#define GTP_IE_UMTS_KEY_AND_QUINTUPLETS (106)
#define CK_LEN 16
#define IK_LEN 16
#define GTP_IE_EPS_SECUR_CTXT_AND_QUADRUPLETS (107)
#define KASME_LEN 32
#define NH_LEN 32
#define OLD_KASME_LEN 32
#define OLD_NH_LEN 32
#define GTP_IE_UMTS_KEY_QUADRUPLETS_AND_QUINTUPLETS (108)
#define CK_LEN 16
#define IK_LEN 16
#define RAND_LEN 16
#define RAND_LEN 16
#define CK_LEN 16
#define IK_LEN 16
#define RAND_LEN 16
#define KASME_LEN 32
#define GTP_IE_PDN_CONNECTION (109)
#define GTP_IE_PDU_NUMBERS (110)
#define GTP_IE_PTMSI (111)
#define GTP_IE_PTMSI_SIGNATURE (112)
#define GTP_IE_HOP_COUNTER (113)
#define GTP_IE_UE_TIME_ZONE (114)
#define GTP_IE_TRACE_REFERENCE (115)
#define GTP_IE_CMPLT_REQ_MSG (116)
#define GTP_IE_GUTI (117)
#define GTP_IE_FULL_QUAL_CNTNR (118)
#define GTP_IE_FULL_QUAL_CAUSE (119)
#define GTP_IE_PLMN_ID (120)
#define GTP_IE_TRGT_ID (121)
#define GTP_IE_PACKET_FLOW_ID (123)
#define GTP_IE_RAB_CONTEXT (124)
#define GTP_IE_SRC_RNC_PDCP_CTXT_INFO (125)
#define GTP_IE_PORT_NUMBER (126)
#define GTP_IE_APN_RESTRICTION (127)
#define GTP_IE_SELECTION_MODE (128)
#define GTP_IE_SRC_ID (129)
#define GTP_IE_CHG_RPTNG_ACT (131)
#define GTP_IE_FQCSID (132)
#define PDN_CSID_LEN 8
#define GTP_IE_CHANNEL_NEEDED (133)
#define GTP_IE_EMLPP_PRIORITY (134)
#define GTP_IE_NODE_TYPE (135)
#define GTP_IE_FULLY_QUAL_DOMAIN_NAME (136)
#define FQDN_LEN 256
#define GTP_IE_PRIV_EXT (255)
#define GTP_IE_TRANS_IDNT (137)
#define GTP_IE_MBMS_SESS_DUR (138)
#define GTP_IE_MBMS_SVC_AREA (139)
#define GTP_IE_MBMS_SESS_IDNT (140)
#define GTP_IE_MBMS_FLOW_IDNT (141)
#define GTP_IE_MBMS_IP_MULTCST_DIST (142)
#define GTP_IE_MBMS_DIST_ACK (143)
#define GTP_IE_USER_CSG_INFO (145)
#define GTP_IE_CSG_INFO_RPTNG_ACT (146)
#define GTP_IE_RFSP_INDEX (144)
#define GTP_IE_CSG_ID (147)
#define GTP_IE_CSG_MEMB_INDCTN (148)
#define GTP_IE_SVC_INDCTR (149)
#define GTP_IE_DETACH_TYPE (150)
#define GTP_IE_LOCAL_DISTGSD_NAME (151)
#define GTP_IE_NODE_FEATURES (152)
#define GTP_IE_MBMS_TIME_TO_DATA_XFER (153)
#define GTP_IE_THROTTLING (154)
#define GTP_IE_ALLOC_RETEN_PRIORITY (155)
#define GTP_IE_EPC_TIMER (156)
#define GTP_IE_SGNLLNG_PRIORITY_INDCTN (157)
#define GTP_IE_TMGI (158)
#define GTP_IE_ADDTL_MM_CTXT_SRVCC (159)
#define GTP_IE_ADDTL_FLGS_SRVCC (160)
#define GTP_IE_MDT_CFG (162)
#define GTP_IE_ADDTL_PROT_CFG_OPTS (163)
#define GTP_IE_MBMS_DATA_XFER_ABS_TIME (164)
#define GTP_IE_HENB_INFO_RPTNG (165)
#define GTP_IE_IPV4_CFG_PARMS (166)
#define GTP_IE_CHG_TO_RPT_FLGS (167)
#define GTP_IE_ACT_INDCTN (168)
#define GTP_IE_TWAN_IDENTIFIER (169)
#define GTP_IE_ULI_TIMESTAMP (170)
#define GTP_IE_MBMS_FLAGS (171)
#define GTP_IE_RAN_NAS_CAUSE (172)
#define GTP_IE_CN_OPER_SEL_ENTITY (173)
#define GTP_IE_TRSTD_WLAN_MODE_INDCTN (174)
#define GTP_IE_NODE_NUMBER (175)
#define GTP_IE_NODE_IDENTIFIER (176)
#define GTP_IE_PRES_RPTNG_AREA_ACT (177)
#define GTP_IE_PRES_RPTNG_AREA_INFO (178)
#define GTP_IE_TWAN_IDNT_TS (179)
#define GTP_IE_OVRLD_CTL_INFO (180)
#define OVERLOAD_CONTROL_INFORMATION_LEN 8
#define GTP_IE_LOAD_CTL_INFO (181)
#define LOAD_CONTROL_INFORMATION_LEN 8
#define GTP_IE_METRIC (182)
#define GTP_IE_SEQUENCE_NUMBER (183)
#define GTP_IE_APN_AND_RLTV_CAP (184)
#define GTP_IE_WLAN_OFFLDBLTY_INDCTN (206)
#define GTP_IE_PAGING_AND_SVC_INFO (186)
#define GTP_IE_INTEGER_NUMBER (187)
#define GTP_IE_MSEC_TIME_STMP (188)
#define GTP_IE_MNTRNG_EVNT_INFO (189)
#define GTP_IE_ECGI_LIST (190)
#define GTP_IE_RMT_UE_CTXT (191)
#define REMOTE_UE_CONTEXT_LEN 8
#define GTP_IE_REMOTE_USER_ID (192)
#define GTP_IE_RMT_UE_IP_INFO (193)
#define GTP_IE_CIOT_OPTIM_SUPP_INDCTN (194)
#define GTP_IE_SCEF_PDN_CONN (195)
#define SCEF_PDN_CONNECTION_LEN 8
#define GTP_IE_HDR_COMP_CFG (196)
#define GTP_IE_EXTNDED_PROT_CFG_OPTS (197)
#define GTP_IE_SRVNG_PLMN_RATE_CTL (198)
#define GTP_IE_COUNTER (199)
#define GTP_IE_MAPPED_UE_USAGE_TYPE (200)
#define GTP_IE_SECDRY_RAT_USAGE_DATA_RPT (201)
#define GTP_IE_UP_FUNC_SEL_INDCTN_FLGS (202)
#define GTP_IE_MAX_PCKT_LOSS_RATE (206)
/*Indication Flag Length*/
#define INDICATION_OCT_5  1
#define INDICATION_OCT_6  2
#define INDICATION_OCT_7  3
#define INDICATION_OCT_8  4
#define INDICATION_OCT_9  5
#define INDICATION_OCT_10 6
#define INDICATION_OCT_11 7


#pragma pack(1)


enum gtp_ie_instance {
	GTP_IE_INSTANCE_ZERO = 0,
	GTP_IE_INSTANCE_ONE = 1,
	GTP_IE_INSTANCE_TWO = 2,
	GTP_IE_INSTANCE_THREE = 3,
	GTP_IE_INSTANCE_FOUR = 4,
	GTP_IE_INSTANCE_FIVE = 5,
	GTP_IE_INSTANCE_SIX = 6,
	GTP_IE_INSTANCE_SEVEN = 7,
	GTP_IE_INSTANCE_EIGHT = 8,
	GTP_IE_INSTANCE_NINE = 9,
	GTP_IE_INSTANCE_TEN = 10,
	GTP_IE_INSTANCE_ELEVEN = 11
};

typedef struct gtpv2c_header_t {
	struct gtpc {
		uint8_t spare :3;
		uint8_t teid_flag :1;
		uint8_t piggyback :1;
		uint8_t version :3;
		uint8_t message_type;
		uint16_t message_len;
	} gtpc;
	union teid {
		struct has_teid_t {
			uint32_t teid;
			uint32_t seq :24;
			uint32_t spare :8;
		} has_teid;
		struct no_teid_t {
			uint32_t seq :24;
			uint32_t spare :8;
		} no_teid;
	} teid;
} gtpv2c_header_t;

typedef struct ie_header_t {
	uint8_t type;
	uint16_t len;
	uint8_t instance;
} ie_header_t;

typedef struct cgi_field_t {
  uint8_t cgi_mcc_digit_2 :4;
  uint8_t cgi_mcc_digit_1 :4;
  uint8_t cgi_mnc_digit_3 :4;
  uint8_t cgi_mcc_digit_3 :4;
  uint8_t cgi_mnc_digit_2 :4;
  uint8_t cgi_mnc_digit_1 :4;
  uint16_t cgi_lac;
  uint16_t cgi_ci;
} cgi_field_t;

typedef struct sai_field_t {
  uint8_t sai_mcc_digit_2 :4;
  uint8_t sai_mcc_digit_1 :4;
  uint8_t sai_mnc_digit_3 :4;
  uint8_t sai_mcc_digit_3 :4;
  uint8_t sai_mnc_digit_2 :4;
  uint8_t sai_mnc_digit_1 :4;
  uint16_t sai_lac;
  uint16_t sai_sac;
} sai_field_t;

/* VS: Check and correct the spellings */
typedef struct rai_field_t {
  uint8_t ria_mcc_digit_2 :4;
  uint8_t ria_mcc_digit_1 :4;
  uint8_t ria_mnc_digit_3 :4;
  uint8_t ria_mcc_digit_3 :4;
  uint8_t ria_mnc_digit_2 :4;
  uint8_t ria_mnc_digit_1 :4;
  uint16_t ria_lac;
  uint16_t ria_rac;
} rai_field_t;

typedef struct tai_field_t {
  uint8_t tai_mcc_digit_2 :4;
  uint8_t tai_mcc_digit_1 :4;
  uint8_t tai_mnc_digit_3 :4;
  uint8_t tai_mcc_digit_3 :4;
  uint8_t tai_mnc_digit_2 :4;
  uint8_t tai_mnc_digit_1 :4;
  uint16_t tai_tac;
} tai_field_t;

typedef struct ecgi_field_t {
  uint8_t ecgi_mcc_digit_2 :4;
  uint8_t ecgi_mcc_digit_1 :4;
  uint8_t ecgi_mnc_digit_3 :4;
  uint8_t ecgi_mcc_digit_3 :4;
  uint8_t ecgi_mnc_digit_2 :4;
  uint8_t ecgi_mnc_digit_1 :4;
  uint8_t ecgi_spare :4;
  uint32_t eci :28;
} ecgi_field_t;

typedef struct lai_field_t {
  uint8_t lai_mcc_digit_2 :4;
  uint8_t lai_mcc_digit_1 :4;
  uint8_t lai_mnc_digit_3 :4;
  uint8_t lai_mcc_digit_3 :4;
  uint8_t lai_mnc_digit_2 :4;
  uint8_t lai_mnc_digit_1 :4;
  uint16_t lai_lac;
} lai_field_t;

typedef struct macro_enb_id_fld_t {
  uint8_t menbid_mcc_digit_2 :4;
  uint8_t menbid_mcc_digit_1 :4;
  uint8_t menbid_mnc_digit_3 :4;
  uint8_t menbid_mcc_digit_3 :4;
  uint8_t menbid_mnc_digit_2 :4;
  uint8_t menbid_mnc_digit_1 :4;
  uint8_t menbid_spare :4;
  uint8_t menbid_macro_enodeb_id :4;
  uint16_t menbid_macro_enb_id2;
} macro_enb_id_fld_t;

typedef struct extnded_macro_enb_id_fld_t {
  uint8_t emenbid_mcc_digit_2 :4;
  uint8_t emenbid_mcc_digit_1 :4;
  uint8_t emenbid_mnc_digit_3 :4;
  uint8_t emenbid_mcc_digit_3 :4;
  uint8_t emenbid_mnc_digit_2 :4;
  uint8_t emenbid_mnc_digit_1 :4;
  uint8_t emenbid_smenb :1;
  uint8_t emenbid_spare :2;
  uint8_t emenbid_extnded_macro_enb_id :5;
  uint16_t emenbid_extnded_macro_enb_id2;
} extnded_macro_enb_id_fld_t;

typedef struct mm_context_t {
  // union mm_context {
  //   gtp_gsm_key_and_triplets_ie_t gsm_key_and_triplets;
  //   gtp_umts_key_used_cipher_and_quintuplets_ie_t umts_key_used_cipher_and_quintuplet;
  //   gtp_gsm_key_used_cipher_and_quintuplets_ie_t gsm_key_used_cipher_and_quintuplets;
  //   gtp_umts_key_and_quintuplets_ie_t umts_key_and_quintuplets;
  //   gtp_eps_secur_ctxt_and_quadruplets_ie_t eps_secur_ctxt_and_quadruplets;
  //   gtp_umts_key_quadruplets_and_quintuplets_ie_t umts_key_quadruplets_and_quintuplets;
  // } mm_context;
} mm_context_t;

typedef struct auth_triplet_t {
  uint8_t rand[RAND_LEN];
  uint32_t sres;
  uint64_t kc;
} auth_triplet_t;

typedef struct auth_quintuplet_t {
  uint8_t rand[RAND_LEN];
  uint8_t xres_length;
  uint8_t xres;
  uint8_t ck[CK_LEN];
  uint8_t ik[IK_LEN];
  uint8_t autn_length;
  uint8_t autn;
} auth_quintuplet_t;

typedef struct auth_quadruplet_t {
  uint8_t rand[RAND_LEN];
  uint8_t xres_length;
  uint8_t xres;
  uint8_t autn_length;
  uint8_t autn;
  uint8_t kasme[KASME_LEN];
} auth_quadruplet_t;

typedef struct bss_container_t {
  uint8_t spare :4;
  uint8_t phx :1;
  uint8_t sapi :1;
  uint8_t rp :1;
  uint8_t pfi :1;
  uint8_t sapi2 :4;
  uint8_t spare2 :1;
  uint8_t radio_priority :3;
  uint8_t xid_parms_len;
  uint8_t xid_parameters;
} bss_container_t;

typedef struct trgt_id_type_rnc_id_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint16_t lac;
  uint8_t rac;
  uint16_t rnc_id;
  uint16_t extended_rnc_id;
} trgt_id_type_rnc_id_t;

typedef struct trgt_id_type_macro_enb_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t spare :4;
  uint16_t macro_enb_id_field2;
  uint16_t tac;
} trgt_id_type_macro_enb_t;

typedef struct trgt_id_type_home_enb_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t spare :4;
  uint8_t home_enodeb_id :4;
  uint32_t home_enodeb_id2 :24;
  uint16_t tac;
} trgt_id_type_home_enb_t;

typedef struct trgt_id_type_extnded_macro_enb_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t smenb :1;
  uint8_t spare :2;
  uint16_t extnded_macro_enb_id_field2;
  uint16_t tac;
} trgt_id_type_extnded_macro_enb_t;

typedef struct trgt_id_type_gnode_id_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t spare :2;
  uint8_t gnb_id_len :6;
  uint32_t gnodeb_id;
  uint32_t fivegs_tac :24;
} trgt_id_type_gnode_id_t;

typedef struct trgt_id_type_macro_ng_enb_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t spare :4;
  uint16_t macro_ng_enb_id;
  uint32_t fivegs_tac :24;
} trgt_id_type_macro_ng_enb_t;

typedef struct trgt_id_type_extnded_macro_ng_enb_t {
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t smenb :1;
  uint8_t spare :2;
  uint16_t extnded_macro_ng_enb_id;
  uint32_t fivegs_tac :24;
} trgt_id_type_extnded_macro_ng_enb_t;

typedef struct gtp_imsi_ie_t {
  ie_header_t header;
  uint64_t imsi_number_digits;
} gtp_imsi_ie_t;

typedef struct gtp_cause_ie_t {
  ie_header_t header;
  uint8_t cause_value;
  uint8_t spare2 :5;
  uint8_t pce :1;
  uint8_t bce :1;
  uint8_t cs :1;
  uint8_t offend_ie_type;
  uint16_t offend_ie_len;
  uint8_t spareinstance;
} gtp_cause_ie_t;

typedef struct gtp_recovery_ie_t {
  ie_header_t header;
  uint8_t recovery;
} gtp_recovery_ie_t;

typedef struct gtp_acc_pt_name_ie_t {
  ie_header_t header;
  uint8_t apn[APN_LEN];
} gtp_acc_pt_name_ie_t;

typedef struct gtp_agg_max_bit_rate_ie_t {
  ie_header_t header;
  uint32_t apn_ambr_uplnk;
  uint32_t apn_ambr_dnlnk;
} gtp_agg_max_bit_rate_ie_t;

typedef struct gtp_eps_bearer_id_ie_t {
  ie_header_t header;
  uint8_t ebi_spare2 :4;
  uint8_t ebi_ebi :4;
} gtp_eps_bearer_id_ie_t;

typedef struct gtp_ip_address_ie_t {
  ie_header_t header;
  uint8_t ipv4_ipv6_addr;
} gtp_ip_address_ie_t;

typedef struct gtp_mbl_equip_idnty_ie_t {
  ie_header_t header;
  uint64_t mei;
} gtp_mbl_equip_idnty_ie_t;

typedef struct gtp_msisdn_ie_t {
  ie_header_t header;
  uint64_t msisdn_number_digits;
} gtp_msisdn_ie_t;

typedef struct gtp_indication_ie_t {
  ie_header_t header;
  uint8_t indication_daf :1;
  uint8_t indication_dtf :1;
  uint8_t indication_hi :1;
  uint8_t indication_dfi :1;
  uint8_t indication_oi :1;
  uint8_t indication_isrsi :1;
  uint8_t indication_israi :1;
  uint8_t indication_sgwci :1;
  uint8_t indication_sqci :1;
  uint8_t indication_uimsi :1;
  uint8_t indication_cfsi :1;
  uint8_t indication_crsi :1;
  uint8_t indication_p :1;
  uint8_t indication_pt :1;
  uint8_t indication_si :1;
  uint8_t indication_msv :1;
  uint8_t indication_retloc :1;
  uint8_t indication_pbic :1;
  uint8_t indication_srni :1;
  uint8_t indication_s6af :1;
  uint8_t indication_s4af :1;
  uint8_t indication_mbmdt :1;
  uint8_t indication_israu :1;
  uint8_t indication_ccrsi :1;
  uint8_t indication_cprai :1;
  uint8_t indication_arrl :1;
  uint8_t indication_ppof :1;
  uint8_t indication_ppon_ppei :1;
  uint8_t indication_ppsi :1;
  uint8_t indication_csfbi :1;
  uint8_t indication_clii :1;
  uint8_t indication_cpsr :1;
  uint8_t indication_nsi :1;
  uint8_t indication_uasi :1;
  uint8_t indication_dtci :1;
  uint8_t indication_bdwi :1;
  uint8_t indication_psci :1;
  uint8_t indication_pcri :1;
  uint8_t indication_aosi :1;
  uint8_t indication_aopi :1;
  uint8_t indication_roaai :1;
  uint8_t indication_epcosi :1;
  uint8_t indication_cpopci :1;
  uint8_t indication_pmtsmi :1;
  uint8_t indication_s11tf :1;
  uint8_t indication_pnsi :1;
  uint8_t indication_unaccsi :1;
  uint8_t indication_wpmsi :1;
  uint8_t indication_spare2 :1;
  uint8_t indication_spare3 :1;
  uint8_t indication_spare4 :1;
  uint8_t indication_eevrsi :1;
  uint8_t indication_ltemui :1;
  uint8_t indication_ltempi :1;
  uint8_t indication_enbcrsi :1;
  uint8_t indication_tspcmi :1;
} gtp_indication_ie_t;

typedef struct gtp_prot_cfg_opts_ie_t {
  ie_header_t header;
  uint8_t pco;
} gtp_prot_cfg_opts_ie_t;

typedef struct gtp_pdn_addr_alloc_ie_t {
  ie_header_t header;
  uint8_t spare2 :5;
  uint8_t pdn_type :3;
  uint8_t pdn_addr_and_pfx[PDN_ADDR_AND_PFX_LEN];
} gtp_pdn_addr_alloc_ie_t;

typedef struct gtp_bearer_qlty_of_svc_ie_t {
  ie_header_t header;
  uint8_t spare2 :1;
  uint8_t pci :1;
  uint8_t pl :4;
  uint8_t spare3 :1;
  uint8_t pvi :1;
  uint8_t qci;
  uint64_t max_bit_rate_uplnk :40;
  uint64_t max_bit_rate_dnlnk :40;
  uint64_t guarntd_bit_rate_uplnk :40;
  uint64_t guarntd_bit_rate_dnlnk :40;
} gtp_bearer_qlty_of_svc_ie_t;

typedef struct gtp_flow_qlty_of_svc_ie_t {
  ie_header_t header;
  uint8_t qci;
  uint64_t max_bit_rate_uplnk :40;
  uint64_t max_bit_rate_dnlnk :40;
  uint64_t guarntd_bit_rate_uplnk :40;
  uint64_t guarntd_bit_rate_dnlnk :40;
} gtp_flow_qlty_of_svc_ie_t;

typedef struct gtp_rat_type_ie_t {
  ie_header_t header;
  uint8_t rat_type;
} gtp_rat_type_ie_t;

typedef struct gtp_serving_network_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
} gtp_serving_network_ie_t;

typedef struct gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t {
  ie_header_t header;
  uint8_t eps_bearer_lvl_tft[257];
} gtp_eps_bearer_lvl_traffic_flow_tmpl_ie_t;

typedef struct gtp_traffic_agg_desc_ie_t {
  ie_header_t header;
  uint8_t traffic_agg_desc;
} gtp_traffic_agg_desc_ie_t;

typedef struct gtp_user_loc_info_ie_t {
  ie_header_t header;
  uint8_t extnded_macro_enb_id :1;
  uint8_t macro_enodeb_id :1;
  uint8_t lai :1;
  uint8_t ecgi :1;
  uint8_t tai :1;
  uint8_t rai :1;
  uint8_t sai :1;
  uint8_t cgi :1;
  cgi_field_t cgi2;
  sai_field_t sai2;
  rai_field_t rai2;
  tai_field_t tai2;
  ecgi_field_t ecgi2;
  lai_field_t lai2;
  macro_enb_id_fld_t macro_enodeb_id2;
  extnded_macro_enb_id_fld_t extended_macro_enodeb_id2;
} gtp_user_loc_info_ie_t;

typedef struct gtp_fully_qual_tunn_endpt_idnt_ie_t {
  ie_header_t header;
  uint8_t v4 :1;
  uint8_t v6 :1;
  uint8_t interface_type :6;
  uint32_t teid_gre_key;
  uint32_t ipv4_address;
  uint8_t ipv6_address[IPV6_ADDRESS_LEN];
} gtp_fully_qual_tunn_endpt_idnt_ie_t;

typedef struct gtp_tmsi_ie_t {
  ie_header_t header;
  uint8_t tmsi;
} gtp_tmsi_ie_t;

typedef struct gtp_global_cn_id_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t cn;
} gtp_global_cn_id_ie_t;

typedef struct gtp_s103_pdn_data_fwdng_info_ie_t {
  ie_header_t header;
  uint8_t hsgw_addr_fwdng_len;
  uint8_t hsgw_addr_fwdng;
  uint32_t gre_key;
  uint8_t eps_bearer_id_nbr;
  uint8_t spare2 :4;
} gtp_s103_pdn_data_fwdng_info_ie_t;

typedef struct gtp_s1u_data_fwdng_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t sgw_addr_len;
  uint8_t sgw_address;
  uint32_t sgw_s1u_teid;
} gtp_s1u_data_fwdng_ie_t;

typedef struct gtp_delay_value_ie_t {
  ie_header_t header;
  uint8_t delay_value;
} gtp_delay_value_ie_t;

typedef struct gtp_bearer_context_ie_t {
  ie_header_t header;
  uint8_t bearer_context[BEARER_CONTEXT_LEN];
} gtp_bearer_context_ie_t;

typedef struct gtp_charging_id_ie_t {
  ie_header_t header;
  uint8_t chrgng_id_val;
} gtp_charging_id_ie_t;

typedef struct gtp_chrgng_char_ie_t {
  ie_header_t header;
  uint16_t chrgng_char_val;
} gtp_chrgng_char_ie_t;

typedef struct gtp_trc_info_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint32_t trace_id :24;
  uint8_t trigrng_evnts[TRIGRNG_EVNTS_LEN];
  uint16_t list_of_ne_types;
  uint8_t sess_trc_depth;
  uint8_t list_of_intfcs[LIST_OF_INTFCS_LEN];
  uint8_t ip_addr_of_trc_coll_entity;
} gtp_trc_info_ie_t;

typedef struct gtp_bearer_flags_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t asi :1;
  uint8_t vind :1;
  uint8_t vb :1;
  uint8_t ppc :1;
} gtp_bearer_flags_ie_t;

typedef struct gtp_pdn_type_ie_t {
  ie_header_t header;
  uint8_t pdn_type_spare2 :5;
  uint8_t pdn_type_pdn_type :3;
} gtp_pdn_type_ie_t;

typedef struct gtp_proc_trans_id_ie_t {
  ie_header_t header;
  uint8_t proc_trans_id;
} gtp_proc_trans_id_ie_t;

typedef struct gtp_gsm_key_and_triplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t spare2 :1;
  uint8_t drxi :1;
  uint8_t cksn :3;
  uint8_t nbr_of_triplet :3;
  uint8_t spare3 :3;
  uint8_t uambri :1;
  uint8_t sambri :1;
  uint8_t spare4 :5;
  uint8_t used_cipher :3;
  uint64_t kc;
  uint8_t auth_triplet;
  uint16_t drx_parameter;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint32_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
} gtp_gsm_key_and_triplets_ie_t;

typedef struct gtp_umts_key_used_cipher_and_quintuplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t spare2 :1;
  uint8_t drxi :1;
  uint8_t cksnksi :3;
  uint8_t nbr_of_quintuplets :3;
  uint8_t iovi :1;
  uint8_t gupii :1;
  uint8_t ugipai :1;
  uint8_t uambri :1;
  uint8_t sambri :1;
  uint8_t spare3 :2;
  uint8_t used_gprs_intgrty_protctn_algo :3;
  uint8_t used_cipher :3;
  uint8_t ck[CK_LEN];
  uint8_t ik[IK_LEN];
  uint8_t auth_quintuplet;
  uint16_t drx_parameter;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint8_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
  uint8_t higher_bitrates_flg_len;
  uint8_t higher_bitrates_flg;
  uint8_t iov_updts_cntr;
} gtp_umts_key_used_cipher_and_quintuplets_ie_t;

typedef struct gtp_gsm_key_used_cipher_and_quintuplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t spare2 :1;
  uint8_t drxi :1;
  uint8_t cksnksi :3;
  uint8_t nbr_of_quintuplets :3;
  uint8_t spare3 :3;
  uint8_t uambri :1;
  uint8_t sambri :1;
  uint8_t spare4 :5;
  uint8_t used_cipher :3;
  uint64_t kc;
  uint8_t auth_quintuplets;
  uint16_t drx_parameter;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint32_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
  uint8_t higher_bitrates_flg_len;
  uint8_t higher_bitrates_flg;
} gtp_gsm_key_used_cipher_and_quintuplets_ie_t;

typedef struct gtp_umts_key_and_quintuplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t spare2 :1;
  uint8_t drxi :1;
  uint8_t ksi :3;
  uint8_t nbr_of_quintuplets :3;
  uint8_t iovi :1;
  uint8_t gupii :1;
  uint8_t ugipai :1;
  uint8_t uambri :1;
  uint8_t sambri :1;
  uint8_t spare3 :5;
  uint8_t used_gprs_intgrty_protctn_algo :3;
  uint8_t ck[CK_LEN];
  uint8_t ik[IK_LEN];
  uint8_t auth_quintuplet;
  uint16_t drx_parameter;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint32_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
  uint8_t higher_bitrates_flg_len;
  uint8_t higher_bitrates_flg;
  uint8_t iov_updts_cntr;
  uint8_t len_of_extnded_acc_rstrct_data;
  uint8_t spare4 :7;
  uint8_t nrsrna :1;
} gtp_umts_key_and_quintuplets_ie_t;

typedef struct gtp_eps_secur_ctxt_and_quadruplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t nhi :1;
  uint8_t drxi :1;
  uint8_t ksiasme :3;
  uint8_t nbr_of_quintuplets :3;
  uint8_t nbr_of_quadruplet :3;
  uint8_t uambri :1;
  uint8_t osci :1;
  uint8_t sambri :1;
  uint8_t used_nas_intgrty_protctn_algo :3;
  uint8_t used_nas_cipher :4;
  uint32_t nas_dnlnk_cnt :24;
  uint32_t nas_uplnk_cnt :24;
  uint8_t kasme[KASME_LEN];
  uint8_t auth_quadruplet;
  uint8_t auth_quintuplet;
  uint16_t drx_parameter;
  uint8_t nh[NH_LEN];
  uint8_t spare2 :5;
  uint8_t ncc :3;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint32_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t s :2;
  uint8_t nhi_old :1;
  uint8_t spare3 :1;
  uint8_t old_ksiasme :3;
  uint8_t old_ncc :3;
  uint8_t old_kasme[OLD_KASME_LEN];
  uint8_t old_nh[OLD_NH_LEN];
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
  uint16_t len_of_ue_radio_capblty_paging_info;
  uint8_t ue_radio_capblty_paging_info;
  uint8_t len_of_extnded_acc_rstrct_data;
  uint8_t spare4 :6;
  uint8_t ussrna :1;
  uint8_t nrsrna :1;
  uint8_t ue_addtl_secur_capblty_len;
  uint8_t ue_addtl_secur_capblty;
  uint8_t len_of_ue_nr_secur_capblty;
  uint8_t ue_nr_secur_capblty;
} gtp_eps_secur_ctxt_and_quadruplets_ie_t;

typedef struct gtp_umts_key_quadruplets_and_quintuplets_ie_t {
  ie_header_t header;
  uint8_t security_mode :3;
  uint8_t spare2 :1;
  uint8_t drxi :1;
  uint8_t ksiasme :3;
  uint8_t nbr_of_quintuplets :3;
  uint8_t nbr_of_quadruplet :3;
  uint8_t uambri :1;
  uint8_t sambri :1;
  uint8_t spare3;
  uint8_t ck[CK_LEN];
  uint8_t ik[IK_LEN];
  uint8_t auth_quadruplet;
  uint8_t auth_quintuplet;
  uint16_t drx_parameter;
  uint32_t uplnk_subscrbd_ue_ambr;
  uint32_t dnlnk_subscrbd_ue_ambr;
  uint32_t uplnk_used_ue_ambr;
  uint32_t dnlnk_used_ue_ambr;
  uint8_t ue_ntwk_capblty_len;
  uint8_t ue_ntwk_capblty;
  uint8_t ms_ntwk_capblty_len;
  uint8_t ms_ntwk_capblty;
  uint8_t mei_length;
  uint8_t mei;
  uint8_t ecna :1;
  uint8_t nbna :1;
  uint8_t hnna :1;
  uint8_t ena :1;
  uint8_t ina :1;
  uint8_t gana :1;
  uint8_t gena :1;
  uint8_t una :1;
  uint8_t vdom_pref_ue_usage_len;
  uint8_t voice_domain_pref_and_ues_usage_setting;
} gtp_umts_key_quadruplets_and_quintuplets_ie_t;

typedef struct gtp_pdn_connection_ie_t {
  ie_header_t header;
} gtp_pdn_connection_ie_t;

typedef struct gtp_pdu_numbers_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t nsapi :4;
  uint8_t dl_gtpu_seqn_nbr;
  uint8_t ul_gtpu_seqn_nbr;
  uint8_t snd_npdu_nbr;
  uint8_t rcv_npdu_nbr;
} gtp_pdu_numbers_ie_t;

typedef struct gtp_ptmsi_ie_t {
  ie_header_t header;
  uint8_t ptmsi;
} gtp_ptmsi_ie_t;

typedef struct gtp_ptmsi_signature_ie_t {
  ie_header_t header;
  uint8_t ptmsi_signature;
} gtp_ptmsi_signature_ie_t;

typedef struct gtp_hop_counter_ie_t {
  ie_header_t header;
  uint8_t hop_counter;
} gtp_hop_counter_ie_t;

typedef struct gtp_ue_time_zone_ie_t {
  ie_header_t header;
  uint8_t time_zone;
  uint8_t spare2 :6;
  uint8_t daylt_svng_time :2;
} gtp_ue_time_zone_ie_t;

typedef struct gtp_trace_reference_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint32_t trace_id :24;
} gtp_trace_reference_ie_t;

typedef struct gtp_cmplt_req_msg_ie_t {
  ie_header_t header;
  uint8_t cmplt_req_msg_type;
  uint8_t cmplt_req_msg;
} gtp_cmplt_req_msg_ie_t;

typedef struct gtp_guti_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint16_t mme_group_id;
  uint8_t mme_code;
  uint8_t m_tmsi;
} gtp_guti_ie_t;

typedef struct gtp_full_qual_cntnr_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t container_type :4;
  uint8_t fcontainer_fld;
} gtp_full_qual_cntnr_ie_t;

typedef struct gtp_full_qual_cause_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t cause_type :4;
  uint8_t fcause_field;
} gtp_full_qual_cause_ie_t;

typedef struct gtp_plmn_id_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
} gtp_plmn_id_ie_t;

typedef struct gtp_trgt_id_ie_t {
  ie_header_t header;
  uint8_t target_type;
  uint8_t target_id;
} gtp_trgt_id_ie_t;

typedef struct gtp_packet_flow_id_ie_t {
  ie_header_t header;
  uint8_t packet_flow_id_spare2 :4;
  uint8_t packet_flow_id_ebi :4;
  uint8_t packet_flow_id_packet_flow_id;
} gtp_packet_flow_id_ie_t;

typedef struct gtp_rab_context_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t nsapi :4;
  uint16_t dl_gtpu_seqn_nbr;
  uint16_t ul_gtpu_seqn_nbr;
  uint16_t dl_pdcp_seqn_nbr;
  uint16_t ul_pdcp_seqn_nbr;
} gtp_rab_context_ie_t;

typedef struct gtp_src_rnc_pdcp_ctxt_info_ie_t {
  ie_header_t header;
  uint8_t rrc_container;
} gtp_src_rnc_pdcp_ctxt_info_ie_t;

typedef struct gtp_port_number_ie_t {
  ie_header_t header;
  uint16_t port_number;
} gtp_port_number_ie_t;

typedef struct gtp_apn_restriction_ie_t {
  ie_header_t header;
  uint8_t rstrct_type_val;
} gtp_apn_restriction_ie_t;

typedef struct gtp_selection_mode_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t selec_mode :2;
} gtp_selection_mode_ie_t;

typedef struct gtp_src_id_ie_t {
  ie_header_t header;
  uint64_t target_cell_id;
  uint8_t source_type;
  uint8_t source_id;
} gtp_src_id_ie_t;

typedef struct gtp_chg_rptng_act_ie_t {
  ie_header_t header;
  uint8_t action;
} gtp_chg_rptng_act_ie_t;

typedef struct gtp_fqcsid_ie_t {
  ie_header_t header;
  uint8_t node_id_type :4;
  uint8_t number_of_csids :4;
  uint8_t node_id;
  uint16_t pdn_csid[PDN_CSID_LEN];
} gtp_fqcsid_ie_t;

typedef struct gtp_channel_needed_ie_t {
  ie_header_t header;
  uint8_t channel_needed;
} gtp_channel_needed_ie_t;

typedef struct gtp_emlpp_priority_ie_t {
  ie_header_t header;
  uint8_t emlpp_priority;
} gtp_emlpp_priority_ie_t;

typedef struct gtp_node_type_ie_t {
  ie_header_t header;
  uint8_t node_type;
} gtp_node_type_ie_t;

typedef struct gtp_fully_qual_domain_name_ie_t {
  ie_header_t header;
  uint8_t fqdn[FQDN_LEN];
} gtp_fully_qual_domain_name_ie_t;

typedef struct gtp_priv_ext_ie_t {
  ie_header_t header;
  uint16_t enterprise_id;
  uint8_t prop_val;
} gtp_priv_ext_ie_t;

typedef struct gtp_trans_idnt_ie_t {
  ie_header_t header;
  uint8_t trans_idnt;
} gtp_trans_idnt_ie_t;

typedef struct gtp_mbms_sess_dur_ie_t {
  ie_header_t header;
  uint32_t mbms_sess_dur :24;
} gtp_mbms_sess_dur_ie_t;

typedef struct gtp_mbms_svc_area_ie_t {
  ie_header_t header;
  uint8_t mbms_svc_area;
} gtp_mbms_svc_area_ie_t;

typedef struct gtp_mbms_sess_idnt_ie_t {
  ie_header_t header;
  uint8_t mbms_sess_idnt;
} gtp_mbms_sess_idnt_ie_t;

typedef struct gtp_mbms_flow_idnt_ie_t {
  ie_header_t header;
  uint16_t mbms_flow_id;
} gtp_mbms_flow_idnt_ie_t;

typedef struct gtp_mbms_ip_multcst_dist_ie_t {
  ie_header_t header;
  uint32_t cmn_tunn_endpt_idnt;
  uint8_t address_type :2;
  uint8_t address_length :6;
  uint8_t ip_multcst_dist_addr;
  uint8_t address_type2 :2;
  uint8_t address_length2 :6;
  uint8_t ip_multcst_src_addr;
  uint8_t mbms_hc_indctr;
} gtp_mbms_ip_multcst_dist_ie_t;

typedef struct gtp_mbms_dist_ack_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t distr_ind :2;
} gtp_mbms_dist_ack_ie_t;

typedef struct gtp_user_csg_info_ie_t {
  ie_header_t header;
  uint8_t mcc_digit_2 :4;
  uint8_t mcc_digit_1 :4;
  uint8_t mnc_digit_3 :4;
  uint8_t mcc_digit_3 :4;
  uint8_t mnc_digit_2 :4;
  uint8_t mnc_digit_1 :4;
  uint8_t spare2 :5;
  uint32_t csg_id2 :24;
  uint8_t access_mode :2;
  uint8_t spare3 :4;
  uint8_t lcsg :1;
  uint8_t cmi :1;
} gtp_user_csg_info_ie_t;

typedef struct gtp_csg_info_rptng_act_ie_t {
  ie_header_t header;
  uint8_t spare2 :5;
  uint8_t uciuhc :1;
  uint8_t ucishc :1;
  uint8_t ucicsg :1;
} gtp_csg_info_rptng_act_ie_t;

typedef struct gtp_rfsp_index_ie_t {
  ie_header_t header;
  uint16_t rfsp_index;
} gtp_rfsp_index_ie_t;

typedef struct gtp_csg_id_ie_t {
  ie_header_t header;
  uint8_t csg_id_spare2 :5;
  uint8_t csg_id_csg_id :3;
  uint32_t csg_id_csg_id2 :24;
} gtp_csg_id_ie_t;

typedef struct gtp_csg_memb_indctn_ie_t {
  ie_header_t header;
  uint8_t csg_memb_indctn_spare2 :7;
  uint8_t csg_memb_indctn_cmi :1;
} gtp_csg_memb_indctn_ie_t;

typedef struct gtp_svc_indctr_ie_t {
  ie_header_t header;
  uint8_t svc_indctr;
} gtp_svc_indctr_ie_t;

typedef struct gtp_detach_type_ie_t {
  ie_header_t header;
  uint8_t detach_type;
} gtp_detach_type_ie_t;

typedef struct gtp_local_distgsd_name_ie_t {
  ie_header_t header;
  uint8_t ldn;
} gtp_local_distgsd_name_ie_t;

typedef struct gtp_node_features_ie_t {
  ie_header_t header;
  uint8_t sup_feat;
} gtp_node_features_ie_t;

typedef struct gtp_mbms_time_to_data_xfer_ie_t {
  ie_header_t header;
  uint8_t mbms_time_to_data_xfer_val_prt;
} gtp_mbms_time_to_data_xfer_ie_t;

typedef struct gtp_throttling_ie_t {
  ie_header_t header;
  uint8_t thrtlng_delay_unit :3;
  uint8_t thrtlng_delay_val :5;
  uint8_t thrtlng_factor;
} gtp_throttling_ie_t;

typedef struct gtp_alloc_reten_priority_ie_t {
  ie_header_t header;
  uint8_t spare2 :1;
  uint8_t pci :1;
  uint8_t pl :4;
  uint8_t spare3 :1;
  uint8_t pvi :1;
} gtp_alloc_reten_priority_ie_t;

typedef struct gtp_epc_timer_ie_t {
  ie_header_t header;
  uint8_t timer_unit :3;
  uint8_t timer_value :5;
} gtp_epc_timer_ie_t;

typedef struct gtp_sgnllng_priority_indctn_ie_t {
  ie_header_t header;
  uint8_t spare2 :7;
  uint8_t lapi :1;
} gtp_sgnllng_priority_indctn_ie_t;

typedef struct gtp_tmgi_ie_t {
  ie_header_t header;
  uint8_t tmgi;
} gtp_tmgi_ie_t;

typedef struct gtp_addtl_mm_ctxt_srvcc_ie_t {
  ie_header_t header;
  uint8_t ms_classmark_2_len;
  uint8_t ms_classmark_2;
  uint8_t ms_classmark_3_len;
  uint8_t ms_classmark_3;
  uint8_t sup_codec_list_len;
  uint8_t sup_codec_list;
} gtp_addtl_mm_ctxt_srvcc_ie_t;

typedef struct gtp_addtl_flgs_srvcc_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t vf :1;
  uint8_t ics :1;
} gtp_addtl_flgs_srvcc_ie_t;

typedef struct gtp_mdt_cfg_ie_t {
  ie_header_t header;
  uint8_t job_type;
  uint32_t measrmnts_lsts;
  uint8_t rptng_trig;
  uint8_t report_interval;
  uint8_t report_amount;
  uint8_t rsrp_evnt_thresh;
  uint8_t rsrq_evnt_thresh;
  uint8_t len_of_area_scop;
  uint8_t area_scope;
  uint8_t spare2 :4;
  uint8_t pli :1;
  uint8_t pmi :1;
  uint8_t mpi :1;
  uint8_t crrmi :1;
  uint8_t coll_prd_rrm_lte;
  uint8_t meas_prd_lte;
  uint8_t pos_mthd;
  uint8_t nbr_of_mdt_plmns;
  uint8_t mdt_plmn_list;
} gtp_mdt_cfg_ie_t;

typedef struct gtp_addtl_prot_cfg_opts_ie_t {
  ie_header_t header;
  uint8_t apco;
} gtp_addtl_prot_cfg_opts_ie_t;

typedef struct gtp_mbms_data_xfer_abs_time_ie_t {
  ie_header_t header;
  uint64_t mbms_data_xfer_abs_time_val_prt;
} gtp_mbms_data_xfer_abs_time_ie_t;

typedef struct gtp_henb_info_rptng_ie_t {
  ie_header_t header;
  uint8_t spare2 :7;
  uint8_t fti :1;
} gtp_henb_info_rptng_ie_t;

typedef struct gtp_ipv4_cfg_parms_ie_t {
  ie_header_t header;
  uint8_t subnet_pfx_len;
  uint32_t ipv4_dflt_rtr_addr;
} gtp_ipv4_cfg_parms_ie_t;

typedef struct gtp_chg_to_rpt_flgs_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t tzcr :1;
  uint8_t sncr :1;
} gtp_chg_to_rpt_flgs_ie_t;

typedef struct gtp_act_indctn_ie_t {
  ie_header_t header;
  uint8_t spare2 :5;
} gtp_act_indctn_ie_t;

typedef struct gtp_twan_identifier_ie_t {
  ie_header_t header;
  uint8_t spare2 :3;
  uint8_t laii :1;
  uint8_t opnai :1;
  uint8_t plmni :1;
  uint8_t civai :1;
  uint8_t bssidi :2;
  uint8_t ssid_length;
  uint8_t ssid;
  uint64_t bssid :48;
  uint8_t civic_addr_len;
  uint8_t civic_addr_info;
  uint32_t twan_plmn_id :24;
  uint8_t twan_oper_name_len;
  uint8_t twan_oper_name;
  uint8_t rly_idnty_type;
  uint8_t rly_idnty_len;
  uint8_t relay_identity;
  uint8_t circuit_id_len;
  uint8_t circuit_id;
} gtp_twan_identifier_ie_t;

typedef struct gtp_uli_timestamp_ie_t {
  ie_header_t header;
  uint8_t uli_ts_val;
} gtp_uli_timestamp_ie_t;

typedef struct gtp_mbms_flags_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t lmri :1;
  uint8_t msri :1;
} gtp_mbms_flags_ie_t;

typedef struct gtp_ran_nas_cause_ie_t {
  ie_header_t header;
  uint8_t protocol_type :4;
  uint8_t cause_type :4;
  uint8_t cause_value;
} gtp_ran_nas_cause_ie_t;

typedef struct gtp_cn_oper_sel_entity_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t sel_entity :2;
} gtp_cn_oper_sel_entity_ie_t;

typedef struct gtp_trstd_wlan_mode_indctn_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t mcm :2;
  uint8_t scm :1;
} gtp_trstd_wlan_mode_indctn_ie_t;

typedef struct gtp_node_number_ie_t {
  ie_header_t header;
  uint8_t len_of_node_nbr;
  uint8_t node_number;
} gtp_node_number_ie_t;

typedef struct gtp_node_identifier_ie_t {
  ie_header_t header;
  uint8_t len_of_node_name;
  uint8_t node_name;
  uint8_t len_of_node_realm;
  uint8_t node_realm;
} gtp_node_identifier_ie_t;

typedef struct gtp_pres_rptng_area_act_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t inapra :1;
  uint8_t action :3;
  uint32_t pres_rptng_area_idnt :24;
  uint8_t number_of_tai :4;
  uint8_t number_of_rai :4;
  uint8_t spare3 :2;
  uint8_t nbr_of_macro_enb :6;
  uint8_t spare4 :2;
  uint8_t nbr_of_home_enb :6;
  uint8_t spare5 :2;
  uint8_t number_of_ecgi :6;
  uint8_t spare6 :2;
  uint8_t number_of_sai :6;
  uint8_t spare7 :2;
  uint8_t number_of_cgi :6;
  uint8_t tais;
  uint8_t macro_enb_ids;
  uint8_t home_enb_ids;
  uint8_t ecgis;
  uint8_t rais;
  uint8_t sais;
  uint8_t cgis;
  uint8_t spare8 :2;
  uint8_t nbr_of_extnded_macro_enb :6;
  uint8_t extnded_macro_enb_ids;
} gtp_pres_rptng_area_act_ie_t;

typedef struct gtp_pres_rptng_area_info_ie_t {
  ie_header_t header;
  uint32_t pra_identifier :24;
  uint8_t spare2 :4;
  uint8_t inapra :2;
  uint8_t apra :1;
  uint8_t opra :1;
  uint8_t ipra :1;
} gtp_pres_rptng_area_info_ie_t;

typedef struct gtp_twan_idnt_ts_ie_t {
  ie_header_t header;
  uint8_t twan_idnt_ts_val;
} gtp_twan_idnt_ts_ie_t;

typedef struct gtp_ovrld_ctl_info_ie_t {
  ie_header_t header;
  uint8_t overload_control_information[OVERLOAD_CONTROL_INFORMATION_LEN];
} gtp_ovrld_ctl_info_ie_t;

typedef struct gtp_load_ctl_info_ie_t {
  ie_header_t header;
  uint8_t load_control_information[LOAD_CONTROL_INFORMATION_LEN];
} gtp_load_ctl_info_ie_t;

typedef struct gtp_metric_ie_t {
  ie_header_t header;
  uint8_t metric;
} gtp_metric_ie_t;

typedef struct gtp_sequence_number_ie_t {
  ie_header_t header;
  uint32_t sequence_number;
} gtp_sequence_number_ie_t;

typedef struct gtp_apn_and_rltv_cap_ie_t {
  ie_header_t header;
  uint8_t rltv_cap;
  uint8_t apn_length;
  uint8_t apn;
} gtp_apn_and_rltv_cap_ie_t;

typedef struct gtp_wlan_offldblty_indctn_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t eutran_indctn :1;
  uint8_t utran_indctn :1;
} gtp_wlan_offldblty_indctn_ie_t;

typedef struct gtp_paging_and_svc_info_ie_t {
  ie_header_t header;
  uint8_t spare2 :4;
  uint8_t ebi :4;
  uint8_t spare3 :7;
  uint8_t ppi :1;
  uint8_t spare4 :2;
  uint8_t paging_plcy_indctn_val :6;
} gtp_paging_and_svc_info_ie_t;

typedef struct gtp_integer_number_ie_t {
  ie_header_t header;
  uint8_t int_nbr_val;
} gtp_integer_number_ie_t;

typedef struct gtp_msec_time_stmp_ie_t {
  ie_header_t header;
  uint8_t msec_time_stmp_val;
} gtp_msec_time_stmp_ie_t;

typedef struct gtp_mntrng_evnt_info_ie_t {
  ie_header_t header;
  uint32_t scef_ref_id;
  uint8_t scef_id_length;
  uint8_t scef_id;
  uint16_t rem_nbr_of_rpts;
} gtp_mntrng_evnt_info_ie_t;

typedef struct gtp_ecgi_list_ie_t {
  ie_header_t header;
  uint16_t nbr_of_ecgi_flds;
  uint8_t ecgi_list_of_m_ecgi_flds;
} gtp_ecgi_list_ie_t;

typedef struct gtp_rmt_ue_ctxt_ie_t {
  ie_header_t header;
  uint8_t remote_ue_context[REMOTE_UE_CONTEXT_LEN];
} gtp_rmt_ue_ctxt_ie_t;

typedef struct gtp_remote_user_id_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t imeif :1;
  uint8_t msisdnf :1;
  uint8_t length_of_imsi;
  uint8_t len_of_msisdn;
  uint8_t length_of_imei;
  uint8_t imei;
} gtp_remote_user_id_ie_t;

typedef struct gtp_rmt_ue_ip_info_ie_t {
  ie_header_t header;
  uint8_t rmt_ue_ip_info;
} gtp_rmt_ue_ip_info_ie_t;

typedef struct gtp_ciot_optim_supp_indctn_ie_t {
  ie_header_t header;
  uint8_t spare2 :1;
  uint8_t spare3 :1;
  uint8_t spare4 :1;
  uint8_t spare5 :1;
  uint8_t ihcsi :1;
  uint8_t awopdn :1;
  uint8_t scnipdn :1;
  uint8_t sgnipdn :1;
} gtp_ciot_optim_supp_indctn_ie_t;

typedef struct gtp_scef_pdn_conn_ie_t {
  ie_header_t header;
  uint8_t scef_pdn_connection[SCEF_PDN_CONNECTION_LEN];
} gtp_scef_pdn_conn_ie_t;

typedef struct gtp_hdr_comp_cfg_ie_t {
  ie_header_t header;
  uint16_t rohc_profiles;
  uint16_t max_cid;
} gtp_hdr_comp_cfg_ie_t;

typedef struct gtp_extnded_prot_cfg_opts_ie_t {
  ie_header_t header;
  uint8_t epco;
} gtp_extnded_prot_cfg_opts_ie_t;

typedef struct gtp_srvng_plmn_rate_ctl_ie_t {
  ie_header_t header;
  uint16_t uplnk_rate_lmt;
  uint16_t dnlnk_rate_lmt;
} gtp_srvng_plmn_rate_ctl_ie_t;

typedef struct gtp_counter_ie_t {
  ie_header_t header;
  uint32_t timestamp_value;
  uint8_t counter_value;
} gtp_counter_ie_t;

typedef struct gtp_mapped_ue_usage_type_ie_t {
  ie_header_t header;
  uint16_t mapped_ue_usage_type;
} gtp_mapped_ue_usage_type_ie_t;

typedef struct gtp_secdry_rat_usage_data_rpt_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t irsgw :1;
  uint8_t irpgw :1;
  uint8_t secdry_rat_type;
  uint8_t spare3 :4;
  uint8_t ebi :4;
  uint8_t start_timestamp;
  uint8_t end_timestamp;
  uint8_t usage_data_dl;
  uint8_t usage_data_ul;
} gtp_secdry_rat_usage_data_rpt_ie_t;

typedef struct gtp_up_func_sel_indctn_flgs_ie_t {
  ie_header_t header;
  uint8_t spare2 :7;
  uint8_t dcnr :1;
} gtp_up_func_sel_indctn_flgs_ie_t;

typedef struct gtp_max_pckt_loss_rate_ie_t {
  ie_header_t header;
  uint8_t spare2 :6;
  uint8_t dl :1;
  uint8_t ul :1;
  uint16_t max_pckt_loss_rate_ul;
  uint16_t max_pckt_loss_rate_dl;
} gtp_max_pckt_loss_rate_ie_t;

enum pdn_addr_alloc_type {
  GTP_IPV4 =1,
  GTP_IPV6 =2,
  IPV4V6 =3,
  NON_IP =4,
};

enum rat_type_values_type {
  UTRAN =1,
  GERAN =2,
  WLAN =3,
  GAN =4,
  HSPA_EVOLUTION =5,
  EUTRAN_ =6,
  VIRTUAL =7,
  EUTRAN_NB_IOT =8,
  LTE_M =9,
  NR =10,
};

enum pdn_type_type {
  PDN_TYPE_TYPE_IPV4 =1,
  PDN_TYPE_TYPE_IPV6 =2,
  PDN_TYPE_TYPE_IPV4V6 =3,
  PDN_TYPE_TYPE_NON_IP =4,
};

enum secur_mode_values_type {
  GSM_KEY_AND_TRIPLETS =0,
  UMTS_KEY_USED_CIPHER_AND_QUINTUPLETS =1,
  GSM_KEY_USED_CIPHER_AND_QUINTUPLETS =2,
  UMTS_KEY_AND_QUINTUPLETS =3,
  EPS_SECURITY_CONTEXT_AND_QUADRUPLETS =4,
  UMTS_KEY_QUADRUPLETS_AND_QUINTUPLETS =5,
};

enum used_nas_cipher_values_type {
  NO_CIPHERING =0,
  EEA1 =1,
  EEA2 =2,
  EEA3 =3,
  EEA4 =4,
  EEA5 =5,
  EEA6 =6,
  EEA7 =7,
};

enum used_cipher_values_type {
  USED_CIPHER_VALUES_TYPE_NO_CIPHERING =0,
  GEA_1 =1,
  GEA_2 =2,
  GEA_3 =3,
  GEA_4 =4,
  GEA_5 =5,
  GEA_6 =6,
  GEA_7 =7,
};

enum used_nas_intgrty_protctn_algo_values_type {
  NO_INTEGRITY_PROTECTION =0,
  EIA1 =1,
  EIA2 =2,
  EIA3 =3,
  EIA4 =4,
  EIA5 =5,
  EIA6 =6,
  EIA7 =7,
};

enum used_gprs_intgrty_protctn_algo_values_type {
  USED_GPRS_INTGRTY_PROTCTN_ALGO_VALUES_TYPE_NO_INTEGRITY_PROTECTION =0,
  GIA4 =4,
  GIA5 =5,
};

enum cmplt_req_msg_type_values_type {
  COMPLETE_ATTACH_REQUEST_MESSAGE =0,
  COMPLETE_TAU_REQUEST_MESSAGE =1,
};

enum cntnr_type_values_type {
  UTRAN_TRANSPARENT_CONTAINER =1,
  BSS_CONTAINER =2,
  E_UTRAN_TRANSPARENT_CONTAINER =3,
  NBIFOM_CONTAINER =4,
};

enum fcause_cause_type_values_type {
  RADIO_NETWORK_LAYER =0,
  TRANSPORT_LAYER =1,
  NAS =2,
  PROTOCOL =3,
  MISCELLANEOUS =4,
};

enum trgt_type_values_type {
  RNC_ID =0,
  MACRO_ENODEB_ID =1,
  CELL_IDENTIFIER =2,
  HOME_ENODEB_ID =3,
  EXTENDED_MACRO_ENODEB_ID =4,
  GNODEB_ID =5,
  MACRO_NG_ENODEB_ID =6,
  EXTENDED_NG_ENODEB_ID =7,
};

enum src_type_values_type {
  CELL_ID =0,
  SRC_TYPE_VALUES_TYPE_RNC_ID =1,
  RESERVED_ =2,
};

enum node_type_values_type {
  MME =0,
  SGSN =1,
};

enum dist_indctn_values_type {
  NO_RNCS_HAVE_ACCEPTED_IP_MULTICAST_DISTRIBUTION =0,
  ALL_RNCS_HAVE_ACCEPTED_IP_MULTICAST_DISTRIBUTION =1,
  SOME_RNCS_HAVE_ACCEPTED_IP_MULTICAST_DISTRIBUTION =2,
};

enum acc_mode_values_type {
  CLOSED_MODE =0,
  HYBRID_MODE =1,
};

enum cmi_type {
  NON_CSG_MEMBERSHIP =0,
  CSG_MEMBERSHIP =1,
};

enum svc_indctr_values_type {
  CS_CALL_INDICATOR =1,
  SMS_INDICATOR =2,
};

enum detach_type_values_type {
  PS_DETACH =1,
  COMBINED_PS_CS_DETACH =2,
};

enum rly_idnty_type_type {
  IPV4_OR_IPV6_ADDRESS =0,
  GTP_FQDN =1,
};

enum prot_type_values_type {
  S1AP_CAUSE =1,
  EMM_CAUSE =2,
  ESM_CAUSE =3,
  DIAMETER_CAUSE =4,
  IKEV2_CAUSE =5,
};

enum ran_nas_cause_type_values_type {
  RAN_NAS_CAUSE_TYPE_VALUES_TYPE_RADIO_NETWORK_LAYER =0,
  RAN_NAS_CAUSE_TYPE_VALUES_TYPE_TRANSPORT_LAYER =1,
  RAN_NAS_CAUSE_TYPE_VALUES_TYPE_NAS =2,
  RAN_NAS_CAUSE_TYPE_VALUES_TYPE_PROTOCOL =3,
  RAN_NAS_CAUSE_TYPE_VALUES_TYPE_MISCELLANEOUS =4,
};

enum hdr_comp_cfg_type {
  UDPIP_0X0002 =1,
  ESPIP_0X0003 =2,
  IP_0X0004 =4,
  TCPIP_0X0006 =8,
  UDPIP_0X0102 =16,
  ESPIP_0X0103 =32,
  IP_0X0104 =64,
};

enum secdry_rat_type_values_type {
  SECDRY_RAT_TYPE_VALUES_TYPE_NR =0,
  UNLICENSED_SPECTRUM =1,
};

#pragma pack()

#endif
