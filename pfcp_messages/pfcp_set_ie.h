/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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

#ifndef PFCP_SET_IE_H
#define PFCP_SET_IE_H

#include <stdbool.h>
#include <rte_hash_crc.h>

#include "pfcp_messages.h"
#include "interface.h"

#ifdef CP_BUILD
#include "ue.h"
#include "cp.h"
#include "gtp_ies.h"
#include "gtpv2c_set_ie.h"
#include "gtp_messages.h"
#include "../ipc/dp_ipc_api.h"
#include "ngic_timer.h"
#include "cp_app.h"
#else
#include "pfcp_struct.h"
#endif


/* TODO: Move following lines to another file */
#define HAS_SEID 1
#define NO_SEID  0
#define PRESENT 1
#define NO_FORW_ACTION	0

#define PFCP_VERSION                            (1)

#define OFFSET 2208988800ULL

/* PFCP Message Type Values */
/*NODE RELATED MESSAGED*/
#define PFCP_HEARTBEAT_REQUEST                      (1)
#define PFCP_HEARTBEAT_RESPONSE                     (2)
#define PFCP_PFD_MGMT_REQUEST                       (3)
#define PFCP_PFD_MANAGEMENT_RESPONSE                (4)
#define PFCP_ASSOCIATION_SETUP_REQUEST              (5)
#define PFCP_ASSOCIATION_SETUP_RESPONSE             (6)
#define PFCP_ASSOCIATION_UPDATE_REQUEST             (7)
#define PFCP_ASSOCIATION_UPDATE_RESPONSE            (8)
#define PFCP_ASSOCIATION_RELEASE_REQUEST            (9)
#define PFCP_ASSOCIATION_RELEASE_RESPONSE           (10)
#define PFCP_NODE_REPORT_REQUEST                    (12)
#define PFCP_NODE_REPORT_RESPONSE                   (13)
#define PFCP_SESSION_SET_DELETION_REQUEST           (14)
#define PFCP_SESSION_SET_DELETION_RESPONSE          (15)

/*SESSION RELATED MESSAGES*/
#define PFCP_SESSION_ESTABLISHMENT_REQUEST          (50)
#define PFCP_SESSION_ESTABLISHMENT_RESPONSE         (51)
#define PFCP_SESSION_MODIFICATION_REQUEST           (52)
#define PFCP_SESSION_MODIFICATION_RESPONSE          (53)
#define PFCP_SESSION_DELETION_REQUEST               (54)
#define PFCP_SESSION_DELETION_RESPONSE              (55)

/* SESSION REPORT RELATED MESSAGES*/
#define PFCP_SESSION_REPORT_REQUEST                 (56)
#define PFCP_SESSION_REPORT_RESPONSE                (57)

/* TODO: Move above lines to another file */

#define MAX_HOSTNAME_LENGTH							(256)

#define MAX_GTPV2C_LENGTH (MAX_GTPV2C_UDP_LEN-sizeof(struct gtpc_t))

#define ALL_CPF_FEATURES_SUPPORTED  (CP_LOAD | CP_OVRL)

/*UP FEATURES LIST*/
#define EMPU    (1 << 0)
#define PDIU    (1 << 1)
#define UDBC    (1 << 2)
#define QUOAC   (1 << 3)
#define TRACE   (1 << 4)
#define FRRT    (1 << 5)
#define BUCP    (1 << 6)
#define DDND    (1 << 9)
#define DLBD    (1 << 10)
#define TRST    (1 << 11)
#define FTUP    (1 << 12)
#define PFDM    (1 << 13)
#define HEEU    (1 << 14)
#define TREU    (1 << 15)


#define UINT8_SIZE sizeof(uint8_t)
#define UINT32_SIZE sizeof(uint32_t)
#define UINT16_SIZE sizeof(uint16_t)
#define IPV4_SIZE 4
#define IPV6_SIZE 16
#define BITRATE_SIZE 10

#define NUMBER_OF_HOSTS 16
#define UPF_ENTRIES_DEFAULT (1 << 16)
#define UPF_ENTRIES_BY_UE_DEFAULT (1 << 18)
#define BUFFERED_ENTRIES_DEFAULT (1024)
#define HEARTBEAT_ASSOCIATION_ENTRIES_DEFAULT  (1 << 6)
#define SWGC_S5S8_HANDOVER_ENTRIES_DEFAULT     (50)

#define USER_PLANE_IP_RESOURCE_INFO_COUNT_2   2
#define NO_CP_MODE_REQUIRED 0
#pragma pack(1)

/**
 * @brief  : Maintains the context of pfcp interface
 */
typedef struct pfcp_context_t{
	uint16_t up_supported_features;
	uint8_t  cp_supported_features;
	uint32_t s1u_ip[20];
	uint32_t s5s8_sgwu_ip;
	uint32_t s5s8_pgwu_ip;
	struct in_addr ava_ip;
	bool flag_ava_ip;

} pfcp_context_t;

pfcp_context_t pfcp_ctxt;

#ifdef CP_BUILD

typedef enum pfcp_assoc_status_en {
	ASSOC_IN_PROGRESS = 0,
	ASSOC_ESTABLISHED = 1,
} pfcp_assoc_status_en;


/* Need to use this for upf_context */
extern uint32_t	*g_gx_pending_csr[BUFFERED_ENTRIES_DEFAULT];
extern uint32_t	g_gx_pending_csr_cnt;

/**
 * @brief  : Maintains the Context for Gx interface
 */
typedef struct gx_context_t {
	/* CP Mode */
	uint8_t cp_mode;
	uint8_t state;
	uint8_t proc;
	char gx_sess_id[GX_SESS_ID_LEN];
	unsigned long  rqst_ptr; /*In Case of RAA, need to store RAR pointer*/
} gx_context_t;

/**
 * @brief  : Maintains context of upf
 */
typedef struct upf_context_t {
	pfcp_assoc_status_en	assoc_status;

	uint8_t cp_mode;
	uint32_t	csr_cnt;
	uint32_t	*pending_csr_teid[BUFFERED_ENTRIES_DEFAULT];
	char	fqdn[MAX_HOSTNAME_LENGTH];

	uint16_t up_supp_features;
	uint8_t  cp_supp_features;

	node_address_t s1u_ip;

	node_address_t s5s8_sgwu_ip;
	/* Indirect Tunnel: Logical Intf */
	node_address_t s5s8_li_sgwu_ip;

	node_address_t s5s8_pgwu_ip;

	uint8_t  state;
	uint8_t indir_tun_flag; /* flag for indirect tunnel */
	uint32_t sender_teid;    /*sender teid for indirect tunnel */
	/* TEDIRI base value */
	uint8_t  teidri;
	uint8_t  teid_range;
	/* Add timer_entry for pfcp assoc req */
	peerData *timer_entry;
} upf_context_t;

/**
 * @brief  : Maintains of upf_ip
 */
typedef struct upf_ip_t {
	struct in_addr ipv4;
	struct in6_addr ipv6;
} upf_ip_t;

/**
 * @brief  : Maintains results returnd via dns for upf
 */
typedef struct upfs_dnsres_t {
	uint8_t upf_count;
	uint8_t current_upf;
	uint8_t upf_ip_type;
	upf_ip_t upf_ip[NUMBER_OF_HOSTS];
	char upf_fqdn[NUMBER_OF_HOSTS][MAX_HOSTNAME_LENGTH];
} upfs_dnsres_t;

#pragma pack()

/* upflist returned via DNS query */
struct rte_hash *upflist_by_ue_hash;

struct rte_hash *upf_context_by_ip_hash;

struct rte_hash *gx_context_by_sess_id_hash;

#endif /* CP_BUILD */

/**
 * @brief  : Generates sequence number
 * @param  : No parameters
 * @return : Returns generated sequence number
 */
uint32_t
generate_seq_no(void);

/**
 * @brief  : Generates sequence number for pfcp requests
 * @param  : type , pfcp request type
 * @param  : seq , default seq number
 * @return : Returns generated sequence number
 */
uint32_t
get_pfcp_sequence_number(uint8_t type, uint32_t seq);

/**
 * @brief  : Set values in pfcp header
 * @param  : pfcp, pointer to pfcp header structure
 * @param  : type, pfcp message type
 * @param  : flag, pfcp flag
 * @return : Returns nothing
 */
void
set_pfcp_header(pfcp_header_t *pfcp, uint8_t type, bool flag );

/**
 * @brief  : Set values in pfcp header and seid value
 * @param  : pfcp, pointer to pfcp header structure
 * @param  : type, pfcp message type
 * @param  : flag, pfcp flag
 * @param  : seq, pfcp message sequence number
 * @param  : cp_type, [SGWC/SAEGWC/PGWC]
 * @return : Returns nothing
 */
void
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag, uint32_t seq,
		uint8_t cp_type);

/**
 * @brief  : Set values in ie header
 * @param  : header, pointer to pfcp ie header structure
 * @param  : type, pfcp message type
 * @param  : length, total length
 * @return : Returns nothing
 */
void
pfcp_set_ie_header(pfcp_ie_header_t *header, uint8_t type, uint16_t length);

/**
 * @brief  : Process pfcp heartbeat request
 * @param  : peer_addr, peer node address
 * @param  : seq, sequence number
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_heartbeat_req(peer_addr_t peer_addr, uint32_t seq);


#ifdef CP_BUILD
/**
 * @brief  : Process create session request, update ue context, bearer info
 * @param  : csr, holds information in csr
 * @param  : context, ue context structure pointer
 * @param  : upf_ipv4, upf ip
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_create_sess_req(create_sess_req_t *csr,
					ue_context **context, node_address_t upf_ipv4, uint8_t cp_mode);

/**
 * @brief  : Process pfcp session association request
 * @param  : context, ue context structure pointer
 * @param  : ebi_index, index of ebi in array
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_assoication_request(pdn_connection *pdn, int ebi_index);


/* TODO: Remove first param when autogenerated code for GTPV2-c
 * is integrated.
 */
/**
 * @brief  : Process pfcp session establishment request
 * @param  : teid
 * @param  : ebi_index, index of ebi in array
 * @param  : upf_ctx, upf information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_est_request(uint32_t teid, pdn_connection *pdn,  upf_context_t *upf_ctx);

/**
 * @brief  : Retrives far id associated with pdr
 * @param  : bearer, bearer struture
 * @param  : interface_value, interface type access or core
 * @return : Returns far id in case of success , 0 otherwise
 */
uint32_t get_far_id(eps_bearer *bearer, int interface_value);

/**
 * @brief  : Process pfcp session modification request
 * @param  : mbr, holds information in session modification request
 * @param  : context, ue_context
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_mod_request(mod_bearer_req_t *mbr, ue_context *context);

/**
 * @brief  : Process pfcp session modification request for SAEGWC and PGWC
 * @param  : mbr, holds information in session modification request
 * @param  : context, ue_context
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_mod_req_for_saegwc_pgwc(mod_bearer_req_t *mbr,
		ue_context *context);

/**
 * @brief  : Process pfcp session modification request
 * @param  : mod_acc, modify_access_bearer req.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_mod_req_modify_access_req(mod_acc_bearers_req_t *mod_acc);
/**
 * @brief  : Process pfcp session modification request for handover scenario
 * @param  : pdn, pdn connection informatio
 * @param  : bearer, bearer information
 * @param  : mbr, holds information in session modification request
 * @return : Returns 0 in case of success , -1 otherwise
 */

int
send_pfcp_sess_mod_req(pdn_connection *pdn, eps_bearer *bearer,
			mod_bearer_req_t *mbr);

/**
 * @brief  : Process Delete session request and send PFCP session deletion on Sx
 * @param  : ds_req, holds information in session deletion request
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_delete_session_request(del_sess_req_t *ds_req, ue_context *context);

/**
 * @brief  : Process chnage notification request on sgwc
 * @param  : change_not_req , holds information of
 *           change notification request received from
 *           MME.
 * @param  : context, ue context
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_change_noti_request(change_noti_req_t  *change_not_reqi, ue_context *context);

/**
 * @brief  : Process delete session request for delete bearer response case
 * @param  : db_rsp, holds information in deletion bearer response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_del_request(del_sess_req_t *db_rsp, ue_context *context);

/**
 * @brief  : Process delete session request for delete bearer response case
 * @param  : db_rsp, holds information in deletion bearer response
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_del_request_delete_bearer_rsp(del_bearer_rsp_t *db_rsp);

/**
 * @brief  : Process delete session request on sgwc
 * @param  : ds_req, holds information in session deletion request
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_delete_session_request(del_sess_req_t *ds_req, ue_context *context);

/**
 * @brief  : Set values in pdn type ie
 * @param  : pdn , pdn type ie structure pointer to be filled
 * @param  : pdn_mme, use values from this structure to fill
 * @return : Returns nothing
 */
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn, pdn_type_ie *pdn_mme);

/**
 * @brief  : Creates upf context hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_upf_context_hash(void);

/**
 * @brief  : Creates gx conetxt hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_gx_context_hash(void);

/**
 * @brief  : Creates upf hash using ue
 * @param  : No param
 * @return : Returns nothing
 */
void
create_upf_by_ue_hash(void);

/**
 * @brief  : Processes pfcp session report request
 * @param  : pfcp_sess_rep_req, holds information in pfcp session report request
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
process_pfcp_report_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req);
#else
/**
 * @brief  : Set values in pdn type ie
 * @param  : pdn, pdn type ie structure to be filled
 * @return : Returns nothing
 */
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn);

/**
 * @brief  : Set values in user plane ip resource info ie
 * @param  : up_ip_resource_info, ie structure to be filled
 * @param  : i, interface type access or core
 * @param  : teidri_flag, 0 - Generate teidir.
 *         : 1 - No action for TEIDRI.
 * @param  : logical_iface: WB:1, EB:2
 * @return : Returns nothing
 */
void
set_up_ip_resource_info(pfcp_user_plane_ip_rsrc_info_ie_t *up_ip_resource_info,
		uint8_t i, int8_t teid_range, uint8_t logical_iface);
#endif /* CP_BUILD */


/**
 * @brief  : Set values in node id ie
 * @param  : node_id, ie structure to be filled
 * @param  : nodeid_value structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_node_id(pfcp_node_id_ie_t *node_id, node_address_t node_value);

/**
 * @brief  : Create and set values in create bar ie
 * @param  : create_bar, ie structure to be filled
 * @return : Returns nothing
 */
void
creating_bar(pfcp_create_bar_ie_t *create_bar);

/**
 * @brief  : Set values in fq csid ie
 * @param  : fq_csid, ie structure to be filled
 * @param  : nodeid_value
 * @return : Returns nothing
 */
void
set_fq_csid(pfcp_fqcsid_ie_t *fq_csid, uint32_t nodeid_value);


/**
 * @brief  : Set values in bar id ie
 * @param  : bar_id, ie structure to be filled
 * @param  : bar_id_value, bar id
 * @return : Returns size of IE
 */
int
set_bar_id(pfcp_bar_id_ie_t *bar_id, uint8_t bar_id_value);

/**
 * @brief  : Set values in downlink data notification delay ie
 * @param  : dl_data_notification_delay, ie structure to be filled
 * @return : Returns nothing
 */
void
set_dl_data_notification_delay(pfcp_dnlnk_data_notif_delay_ie_t
		*dl_data_notification_delay);

/**
 * @brief  : Set values in buffer packets count ie
 * @param  : sgstd_buff_pkts_cnts, ie structure to be filled
 * @param  : pkt_cnt, suggested packet count
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_sgstd_buff_pkts_cnt(pfcp_suggstd_buf_pckts_cnt_ie_t *sgstd_buff_pkts_cnt,
		uint8_t pkt_cnt);

/**
 * @brief  : Set values in buffer packets count ie
 * @param  : dl_buf_sgstd_pkts_cnts, ie structure to be filled
 * @param  : pkt_cnt, suggested packet count
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_dl_buf_sgstd_pkts_cnt(pfcp_dl_buf_suggstd_pckt_cnt_ie_t *dl_buf_sgstd_pkts_cnt,
		uint8_t pkt_cnt);

#ifdef CP_BUILD
/**
 * @brief  : Set values in user id ie
 * @param  : user_id, ie structure to be filled
 * @param  : imsi, value to be set in user id structure to be filled
 * @return : Returns nothing
 */
void
set_user_id(pfcp_user_id_ie_t *user_id, uint64_t imsi);
#endif /* CP_BUILD */
/**
 * @brief  : Set values in fseid ie
 * @param  : fseid, ie structure to be filled
 * @param  : seid, seid value
 * @param  : node_value structure
 * @return : Returns nothing
 */
void
set_fseid(pfcp_fseid_ie_t *fseid, uint64_t seid, node_address_t node_value);

/**
 * @brief  : Set values in recovery time stamp ie
 * @param  : rec_time_stamp, ie structure to be filled
 * @return : Returns nothing
 */
void
set_recovery_time_stamp(pfcp_rcvry_time_stmp_ie_t *rec_time_stamp);

/**
 * @brief  : Set values in upf features ie
 * @param  : upf_feat, ie structure to be filled
 * @return : Returns nothing
 */
void
set_upf_features(pfcp_up_func_feat_ie_t *upf_feat);

/**
 * @brief  : Set values in control plane function feature ie
 * @param  : cpf_feat, ie structure to be filled
 * @return : Returns nothing
 */
void
set_cpf_features(pfcp_cp_func_feat_ie_t *cpf_feat);

/**
 * @brief  : Set values session report type ie
 * @param  : rt, structure to be filled
 * @return : Returns nothing
 */
void
set_sess_report_type(pfcp_report_type_ie_t *rt);

/**
 * @brief  : Set values in caues ie
 * @param  : cause, ie structure to be filled
 * @param  : cause_val, cause value to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val);

/**
 * @brief  : Set values in remove bar ie
 * @param  : remove_bar, ie structure to be filled
 * @param  : bar_id_value, value of bar identifier
 * @return : Returns nothing
 */
void
set_remove_bar(pfcp_remove_bar_ie_t *remove_bar, uint8_t bar_id_value);

/**
 * @brief  : Set values in remove pdr ie
 * @param  : remove_pdr, ie structure to be filled
 * @param  : pdr_id_value, pdr_id for which we need to send remve pdr
 * @return : Returns nothing
 */
void
set_remove_pdr( pfcp_remove_pdr_ie_t *remove_pdr, uint16_t pdr_id_value);

/**
 * @brief  : Set values in traffic endpoint ie
 * @param  : traffic_endpoint_id
 * @return : Returns nothing
 */
void
set_traffic_endpoint(pfcp_traffic_endpt_id_ie_t *traffic_endpoint_id);

/**
 * @brief  : Set values in fteid ie
 * @param  : local_fteid, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_fteid(pfcp_fteid_ie_t *local_fteid, fteid_ie_t *local_fteid_value);

/**
 * @brief  : Set values in network instance ie
 * @param  : network_instance, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_network_instance(pfcp_ntwk_inst_ie_t *network_instance,
						ntwk_inst_t *network_instance_value);

/**
 * @brief  : Set values in ue ip address ie
 * @param  : ue_ip, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_ue_ip(pfcp_ue_ip_address_ie_t *ue_ip, ue_ip_addr_t ue_addr);

/**
 * @brief  : Set values in qer id ie
 * @param  : qer_id, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_qer_id(pfcp_qer_id_ie_t *qer_id, uint32_t qer_id_value);

/**
 * @brief  : Set values in gate status ie
 * @param  : gate_status, ie structure to be filled
 * @param  : qer_gate_status, qer_gate_status to be fill
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_gate_status( pfcp_gate_status_ie_t *gate_status, gate_status_t *qer_gate_status);

/**
 * @brief  : Set values in mbr ie
 * @param  : mbr, ie structure to be filled
 * @param  : qer_mbr, information to be fill
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_mbr(pfcp_mbr_ie_t *mbr, mbr_t *qer_mbr);

/**
 * @brief  : Set values in gbr ie
 * @param  : gbr, ie structure to be filled
 * @param  : qer_gbr, information to be fill
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_gbr(pfcp_gbr_ie_t *gbr, gbr_t *qer_gbr);

/**
 * @brief  : Set values in update qer ie
 * @param  : up_qer, ie structure to be filled
 * @param  : bearer_qer, qer value to be fill in ie structure
 * @return : Returns nothing
 */
void
set_update_qer(pfcp_update_qer_ie_t *up_qer, qer_t *bearer_qer);

/**
 * @brief  : Set values in create qer ie
 * @param  : qer, ie structure to be filled
 * @param  : bearer_qer, information to be filled in ie's
 * @return : Returns nothing
 */
void
set_create_qer(pfcp_create_qer_ie_t *qer, qer_t *bearer_qer);

/**
 * @brief  : Set values in update bar ie
 * @param  : up_bar, ie structure to be filled
 * @return : Returns nothing
 */
void
updating_bar( pfcp_upd_bar_sess_mod_req_ie_t *up_bar);

/**
 * @brief  : Set values in update bar pfcp session report response ie
 * @param  : up_bar, ie structure to be filled
 * @param  : bearer_bar, stucture bar_t
 * @return : Returns nothing
 */
void
set_update_bar_sess_rpt_rsp(pfcp_upd_bar_sess_rpt_rsp_ie_t *up_bar, bar_t *bearer_bar);

/**
 * @brief  : Set values in pfcpsmreq flags ie
 * @param  : pfcp_sm_req_flags, ie structure to be filled
 * @return : Returns nothing
 */
void
set_pfcpsmreqflags(pfcp_pfcpsmreq_flags_ie_t *pfcp_sm_req_flags);

/**
 * @brief  : Set values in query urr refference ie
 * @param  : query_urr_ref, ie structure to be filled
 * @return : Returns nothing
 */
void
set_query_urr_refernce(pfcp_query_urr_ref_ie_t *query_urr_ref);


/**
 * @brief  : Set values in user plane association relation request ie
 * @param  : ass_rel_req, ie structure to be filled
 * @return : Returns nothing
 */
void
set_pfcp_ass_rel_req(pfcp_up_assn_rel_req_ie_t *ass_rel_req);

/**
 * @brief  : Set values in graceful relation period ie
 * @param  : graceful_rel_period, ie structure to be filled
 * @return : Returns nothing
 */
void
set_graceful_release_period(pfcp_graceful_rel_period_ie_t *graceful_rel_period);

/**
 * @brief  : Set values in sequence number ie
 * @param  : seq, ie structure to be filled
 * @return : Returns nothing
 */
void
set_sequence_num(pfcp_sequence_number_ie_t *seq);

/**
 * @brief  : Set values in metric ie
 * @param  : metric, ie structure to be filled
 * @return : Returns nothing
 */
void
set_metric(pfcp_metric_ie_t *metric);

/**
 * @brief  : Set values in timer ie
 * @param  : pov, ie structure to be filled
 * @return : Returns nothing
 */
void
set_period_of_validity(pfcp_timer_ie_t *pov);

/**
 * @brief  : Set values in oci flags ie
 * @param  : oci, ie structure to be filled
 * @return : Returns nothing
 */
void
set_oci_flag( pfcp_oci_flags_ie_t *oci);

/**
 * @brief  : Set values in offending ie
 * @param  : offending_ie, ie structure to be filled
 * @param  : offend,  offending ie type
 * @return : Returns nothing
 */
void
set_offending_ie( pfcp_offending_ie_ie_t *offending_ie, int offend);

/**
 * @brief  : Set values in load control info ie
 * @param  : lci, ie structure to be filled
 * @return : Returns nothing
 */
void
set_lci(pfcp_load_ctl_info_ie_t *lci);

/**
 * @brief  : Set values in overload control info ie
 * @param  : olci, ie structure to be filled
 * @return : Returns nothing
 */
void
set_olci(pfcp_ovrld_ctl_info_ie_t *olci);

/**
 * @brief  : Set values in failed rule id ie
 * @param  : rule, ie structure to be filled
 * @return : Returns nothing
 */
void
set_failed_rule_id(pfcp_failed_rule_id_ie_t *rule);

/**
 * @brief  : Set values in traffic endpoint id ie
 * @param  : tnp, ie structure to be filled
 * @return : Returns nothing
 */
void
set_traffic_endpoint_id(pfcp_traffic_endpt_id_ie_t *tnp);

/**
 * @brief  : Set values in pdr id ie
 * @param  : pdr, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_pdr_id_ie(pfcp_pdr_id_ie_t *pdr);

/**
 * @brief  : Set values in created pdr ie
 * @param  : pdr, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_created_pdr_ie(pfcp_created_pdr_ie_t *pdr);

/**
 * @brief  : Set values in created traffic endpoint ie
 * @param  : cte, ie structure to be filled
 * @return : Returns nothing
 */
void
set_created_traffic_endpoint(pfcp_created_traffic_endpt_ie_t *cte);

/**
 * @brief  : Set values in node report type ie
 * @param  : nrt, ie structure to be filled
 * @return : Returns nothing
 */
void
set_node_report_type(pfcp_node_rpt_type_ie_t *nrt);

/**
 * @brief  : Set values in user plane path failure report ie
 * @param  : uppfr, ie structure to be filled
 * @return : Returns nothing
 */
void
set_user_plane_path_failure_report(pfcp_user_plane_path_fail_rpt_ie_t *uppfr);

/**
 * @brief  : Calculates system  Seconds since boot
 * @param  : no param
 * @return : Returns uptime in case of success
 */
long
uptime(void);

/**
 * @brief  : valiadates pfcp session association setup request and set cause and offending ie accordingly
 * @param  : pfcp_ass_setup_req, hold information from pfcp session association setup request
 * @param  : cause_id , param to set cause id
 * @param  : offend_id, param to set offending ie id
 * @return : Returns nothing
 */
void
cause_check_association(pfcp_assn_setup_req_t *pfcp_ass_setup_req,
						uint8_t *cause_id, int *offend_id);

/**
 * @brief  : valiadates pfcp session establishment request and set cause and offending ie accordingly
 * @param  : pfcp_session_request, hold information from pfcp session establishment request
 * @param  : cause_id , param to set cause id
 * @param  : offend_id, param to set offending ie id
 * @return : Returns nothing
 */
void
cause_check_sess_estab(pfcp_sess_estab_req_t
			*pfcp_session_request, uint8_t *cause_id, int *offend_id);

/**
 * @brief  : valiadates pfcp session modification request and set cause and offending ie accordingly
 * @param  : pfcp_session_mod_req, hold information from pfcp session modification request
 * @param  : cause_id , param to set cause id
 * @param  : offend_id, param to set offending ie id
 * @return : Returns nothing
 */
void
cause_check_sess_modification(pfcp_sess_mod_req_t
		*pfcp_session_mod_req, uint8_t *cause_id, int *offend_id);

/**
 * @brief  : valiadates pfcp session deletion request and set cause and offending ie accordingly
 * @param  : pfcp_session_delete_req, hold information from pfcp session request
 * @param  : cause_id , param to set cause id
 * @param  : offend_id, param to set offending ie id
 * @return : Returns nothing
 */
void
cause_check_delete_session(pfcp_sess_del_req_t
		*pfcp_session_delete_req, uint8_t *cause_id, int *offend_id);
/**
 * @brief  : Create recovery time hash table
 * @param  : No param
 * @return : Returns nothing
 */
void
create_heartbeat_hash_table(void);

/**
 * @brief  : Add ip address to hearbeat hash
 * @param  : peer_addr, ip address to be added
 * @param  : recover_timei, recovery time stamp
 * @return : Returns nothing
 */
void
add_ip_to_heartbeat_hash(node_address_t *peer_addr, uint32_t recover_time);

/**
 * @brief  : Delete ip address from heartbeat hash
 * @param  : peer_addr, ip address to be removed
 * @return : Returns nothing
 */
void
delete_entry_heartbeat_hash(node_address_t *peer_addr);

/**
 * @brief  : Add data to hearbeat hash table
 * @param  : ip, ip address to be added
 * @param  : recov_time, recovery timestamp
 * @return : Returns nothing
 */
int
add_data_to_heartbeat_hash_table(node_address_t *ip, uint32_t *recov_time);

/**
 * @brief  : Delete hearbeat hash table
 * @param  : No param
 * @return : Returns nothing
 */
void
clear_heartbeat_hash_table(void);

/**
 * @brief  : Set values in create pdr ie
 * @param  : create_pdr, ie structure to be filled
 * @param  : source_iface_value, interface type
 * @param  : cp_type,[SGWC/SAEGWC/PGWC]
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_create_pdr(pfcp_create_pdr_ie_t *create_pdr, pdr_t *bearer_pdr,
		uint8_t cp_type);

/**
 * @brief  : Set values in create far ie
 * @param  : create_far, ie structure to be filled
 * @return : Returns nothing
 */
void
set_create_far(pfcp_create_far_ie_t *create_far, far_t  *bearer_pdr);

/**
 * @brief  : Set values in create urr ie
 * @param  : create_far, ie structure to be filled
 * @return : Returns nothing
 */
void
set_create_urr(pfcp_create_urr_ie_t *create_urr, pdr_t *bearer_pdr);

/**
 * @brief  : Set values in create bar ie
 * @param  : create_bar, ie structure to be filled
 * @return : Returns nothing
 */
void
set_create_bar(pfcp_create_bar_ie_t *create_bar, bar_t  *bearer_bar);

/**
 * @brief  : Set values in update pdr  ie
 * @param  : update_pdr, ie structure to be filled
 * @param  : source_iface_value
 * @param  : cp_type, [SGWC/SAEGWC/PGWC]
 * @return : Returns nothing
 */
int
set_update_pdr(pfcp_update_pdr_ie_t *update_pdr, pdr_t *bearer_pdr,
		uint8_t cp_type);

/**
 * @brief  : Set values in update far  ie
 * @param  : update_far, ie structure to be filled
 * @return : Returns nothing
 */
void
set_update_far(pfcp_update_far_ie_t *update_far, far_t  *bearer_pdr);

/**
 * @brief  : Set values in forwarding params ie
 * @param  : frwdng_parms, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_forwarding_param(pfcp_frwdng_parms_ie_t *frwdng_parms,
	node_address_t node_value, uint32_t teid, uint8_t interface_valuece);

/**
 * @brief  : Set values in duplicating params ie
 * @param  : dupng_parms, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_duplicating_param(pfcp_dupng_parms_ie_t *dupng_parms);

/**
 * @brief  : Set values in duplicating params ie in update far
 * @param  : upd_dupng_parms, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_upd_duplicating_param(pfcp_upd_dupng_parms_ie_t *dupng_parms);

/**
 * @brief  : Set values in upd forwarding params ie
 * @param  : upd_frwdng_parms, ie structure to be filled
 * @param  : node_value, node address structure to fill IP address
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_upd_forwarding_param(pfcp_upd_frwdng_parms_ie_t *upd_frwdng_parms,
											node_address_t node_value);

/**
 * @brief  : Set values in apply action ie
 * @param  : apply_action, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_apply_action(pfcp_apply_action_ie_t *apply_action_t, apply_action *bearer_action);

/**
 * @brief  : Set values in measurement method ie
 * @param  : apply_action, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_measurement_method(pfcp_meas_mthd_ie_t *meas_mthd, urr_t *bearer_urr);

/**
 * @brief  : Set values in reporting triggers ie
 * @param  : apply_action, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_reporting_trigger(pfcp_rptng_triggers_ie_t *rptng_triggers, urr_t *bearer_urr);

/**
 * @brief  : Set values in volume threshold ie
 * @param  : apply_action, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_volume_threshold(pfcp_vol_thresh_ie_t *vol_thresh, urr_t *bearer_urr, uint8_t interface_value);

/**
 * @brief  : Set values in volume measuremnt ie
 * @param  : vol_meas, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_volume_measurment(pfcp_vol_meas_ie_t *vol_meas);

/**
 * @brief  : Set values in duration measuremnt ie
 * @param  : dur_meas, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_duration_measurment(pfcp_dur_meas_ie_t *dur_meas);

/**
 * @brief  : Set values in start time ie
 * @param  : start_time, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_start_time(pfcp_start_time_ie_t *start_time);

/**
 * @brief  : Set values in end time ie
 * @param  : end_time, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_end_time(pfcp_end_time_ie_t *end_time);

/**
 * @brief  : Set values in first pkt time ie
 * @param  : first_pkt_time, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_first_pkt_time(pfcp_time_of_frst_pckt_ie_t *first_pkt_time);

/**
 * @brief  : Set values in last pkt time ie
 * @param  : last_pkt_time, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_last_pkt_time(pfcp_time_of_lst_pckt_ie_t *last_pkt_time);

/**
 * @brief  : Set values in Time threshold ie
 * @param  : apply_action, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_time_threshold(pfcp_time_threshold_ie_t *time_thresh, urr_t *bearer_urr);

/**
 * @brief  : Set values in outer header creation ie
 * @param  : outer_hdr_creation, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_outer_header_creation(pfcp_outer_hdr_creation_ie_t *outer_hdr_creation,
						node_address_t node_value, uint32_t teid);

/**
 * @brief  : Set values in forwarding policy ie
 * @param  : frwdng_plcy, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_frwding_policy(pfcp_frwdng_plcy_ie_t *frwdng_plcy);

/**
 * @brief  : Set values in destination interface ie
 * @param  : dst_intfc, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_destination_interface(pfcp_dst_intfc_ie_t *dst_intfc, uint8_t interface_value);

/**
 * @brief  : Set values in pdr id ie
 * @param  : pdr_id, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_pdr_id(pfcp_pdr_id_ie_t *pdr_id, uint16_t pdr_id_value);

/**
 * @brief  : Set values in far id ie
 * @param  : far_id, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_far_id(pfcp_far_id_ie_t *far_id, uint32_t far_id_value);


/**
 * @brief  : Set values in urr id ie
 * @param  : urr_id, ie structure to be filled
 * @return : Returns nothing
 */
int
set_urr_id(pfcp_urr_id_ie_t *urr_id, uint32_t urr_id_value);

/**
 * @brief  : Set values in outer header removal ie
 * @param  : out_hdr_rem, ie structure to be filled
 * @param  : outer_header_desc, outer header desciption
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_outer_hdr_removal(pfcp_outer_hdr_removal_ie_t *out_hdr_rem,
		uint8_t outer_header_desc);

/**
 * @brief  : Set values in precedence ie
 * @param  : prec, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_precedence(pfcp_precedence_ie_t *prec, uint32_t prec_value);

/**
 * @brief  : Set values in pdi ie
 * @param  : pdi, ie structure to be filled
 * @param  : cp_type, [SGWC/PGWC/SAEGWC]
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_pdi(pfcp_pdi_ie_t *pdi, pdi_t *bearer_pdi, uint8_t cp_type);

/**
 * @brief  : Set values in source interface ie
 * @param  : src_intf, ie structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
set_source_intf(pfcp_src_intfc_ie_t *src_intf, uint8_t src_intf_value);

/**
 * @brief  : Set peer node address
 * @param  : peer_addr, structure to contain address
 * @param  : node_addr, structure to fill node address.
 * @return : Returns void.
 */

void get_peer_node_addr(peer_addr_t *peer_addr, node_address_t *node_addr);
#ifdef CP_BUILD
/**
 * @brief  : Set values in pfd contents ie
 * @param  : pfd_conts, ie structure to be filled
 * @param  : cstm_buf, data to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint16_t
set_pfd_contents(pfcp_pfd_contents_ie_t *pfd_conts, struct msgbuf *cstm_buf);

/**
 * @brief  : Fill pfcp pfd management request
 * @param  : pfcp_pfd_req, pointer to structure to be filled
 * @param  : len, Total len
 * @return : Returns nothing
 */
void
fill_pfcp_pfd_mgmt_req(pfcp_pfd_mgmt_req_t *pfcp_pfd_req, uint16_t len);

/**
 * @brief  : Process pfcp pfd management request
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_pfd_mgmt_request(void);

/**
 * @brief  : Add entry to upflist hash
 * @param  : imsi_val, imsi value
 * @param  : imsi_len, imsi length
 * @param  : entry, entry to be added in hash
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
upflist_by_ue_hash_entry_add(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t *entry);

/**
 * @brief  : search entry in upflist hash
 * @param  : imsi_val, imsi value
 * @param  : imsi_len, imsi length
 * @param  : entry, entry to be filled with search result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
upflist_by_ue_hash_entry_lookup(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t **entry);

/**
 * @brief  : delete entry in upflist hash
 * @param  : imsi_val, imsi value
 * @param  : imsi_len, imsi length
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
upflist_by_ue_hash_entry_delete(uint64_t *imsi_val, uint16_t imsi_len);

/**
 * @brief  : Add entry to upf conetxt hash
 * @param  : upf_ip, up ip address
 * @param  : entry ,entry to be added
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
upf_context_entry_add(node_address_t *upf_ip, upf_context_t *entry);

/**
 * @brief  : search entry in upf hash using ip
 * @param  : upf_ip, key to search entry
 * @param  : entry, variable to store search result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
upf_context_entry_lookup(node_address_t upf_ip, upf_context_t **entry);

/**
 * @brief  : Add entry into gx context hash
 * @param  : sess_id , key to add entry
 * @param  : entry , entry to be added
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
gx_context_entry_add(char *sess_id, gx_context_t *entry);

/**
 * @brief  : search entry in gx context hash
 * @param  : sess_id , key to add entry
 * @param  : entry , entry to be added
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
gx_context_entry_lookup(char *sess_id, gx_context_t **entry);

/**
 * @brief  : Create s5s8 hash table in sgwc
 * @param  : No param
 * @return : Returns nothing
 */
void
create_s5s8_sgwc_hash_table(void);

/**
 * @brief  : Remove s5s8 hash table in sgwc
 * @param  : No param
 * @return : Returns nothing
 */
void
clear_s5s8_sgwc_hash_table(void);

/**
 * @brief  : Generate and Send CCRU message
 * @param  : Modify Bearer Request
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
send_ccr_u_msg(mod_bearer_req_t *mb_req);
#endif /* CP_BUILD */

/**
 * @brief  : get msg type from cstm ie string
 * @param  : pfd_conts, holds pfc contents data
 * @param  : idx, index in array
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint64_t
get_rule_type(pfcp_pfd_contents_ie_t *pfd_conts, uint16_t *idx);

/**
 *@brief  : Sets IP address for the node as per IP type
 *@param  : ipv4_addr, IPv4 address
 *@param  : ipv6_addr, IPv6 address
 *@param  : node_value, node value structure to store IP address
 *@return : returns -1 if no ip is assigned, otherwise 0
*/
int
set_node_address(uint32_t *ipv4_addr, uint8_t ipv6_addr[],
				node_address_t node_value);

/* @brief  : stores IPv4/IPv6 address into node value
 * @param  : ipv4_addr, ipv4 address
 * @param  : ipv6_addr, ipv6 address
 * @param  : node_value, ipv4 and ipv6 structure
 * @return : returns -1 if no ip is assigned, otherwise 0
 * */
int
fill_ip_addr(uint32_t ipv4_addr, uint8_t ipv6_addr[],
						node_address_t *node_value);

/* @brief  : checks if IPV6 address is zero or not
 * @param  : addr, ipv6 address
 * @param  : len, ipv6 address len
 * @return : returns -1 if IP is non-zero, otherwise 0
 * */
int
check_ipv6_zero(uint8_t addr[], uint8_t len);
#endif /* PFCP_SET_IE_H */
