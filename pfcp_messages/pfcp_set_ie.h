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

#ifndef PFCP_SET_IE_H
#define PFCP_SET_IE_H

#include <stdbool.h>
#include <rte_hash_crc.h>

#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "ue.h"
#include "cp.h"
#include "gtp_ies.h"
#include "gtpv2c_set_ie.h"
#include "gtp_messages.h"
#include "../ipc/dp_ipc_api.h"
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
#define IPV6_SIZE 8
#define PFCP_IE_HDR_SIZE sizeof(pfcp_ie_header_t)
#define BITRATE_SIZE 10

#define UPF_ENTRIES_DEFAULT (1 << 16)
#define BUFFERED_ENTRIES_DEFAULT (1024)
#define HEARTBEAT_ASSOCIATION_ENTRIES_DEFAULT  (1 << 6)
#define SWGC_S5S8_HANDOVER_ENTRIES_DEFAULT     (50)


#pragma pack(1)

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

/* VS: Maintain the Context for Gx interface */
typedef struct gx_context_t {
	uint8_t state;
	uint8_t proc;
	char gx_sess_id[MAX_LEN];
	unsigned long  rqst_ptr; /*In Case of RAA, need to store RAR pointer*/
} gx_context_t;

typedef struct upf_context_t {
	pfcp_assoc_status_en	assoc_status;

	uint32_t	csr_cnt;
	uint32_t	*pending_csr[BUFFERED_ENTRIES_DEFAULT];
	uint32_t	*pending_csr_teid[BUFFERED_ENTRIES_DEFAULT];
	char	fqdn[MAX_HOSTNAME_LENGTH];

	uint16_t up_supp_features;
	uint8_t  cp_supp_features;
	uint32_t s1u_ip;
	uint32_t s5s8_sgwu_ip;
	uint32_t s5s8_pgwu_ip;
	uint8_t  state;

} upf_context_t;

typedef struct upfs_dnsres_t {
	uint8_t upf_count;
	uint8_t current_upf;
	struct in_addr upf_ip[UPF_ENTRIES_DEFAULT];
	char upf_fqdn[UPF_ENTRIES_DEFAULT][MAX_HOSTNAME_LENGTH];
} upfs_dnsres_t;

#pragma pack()

/* upflist returned via DNS query */
struct rte_hash *upflist_by_ue_hash;

struct rte_hash *upf_context_by_ip_hash;

struct rte_hash *gx_context_by_sess_id_hash;

#endif /* CP_BUILD */

uint32_t
generate_seq_no(void);

uint32_t
get_pfcp_sequence_number(uint8_t type, uint32_t seq);

void
set_pfcp_header(pfcp_header_t *pfcp, uint8_t type, bool flag );

void
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag, uint32_t seq );

void
pfcp_set_ie_header(pfcp_ie_header_t *header, uint8_t type, uint16_t length);

int
process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr, uint32_t seq);


#ifdef CP_BUILD
int
process_create_sess_req(create_sess_req_t *csr,
					ue_context **context, struct in_addr *upf_ipv4);

int
process_pfcp_assoication_request(ue_context *context, uint8_t ebi_index);


/* TODO: Remove first param when autogenerated code for GTPV2-c
 * is integrated.
 */
int
process_pfcp_sess_est_request(uint32_t teid, uint8_t ebi_index);

int
process_pfcp_sess_mod_request(mod_bearer_req_t *mbr);

int
process_pfcp_sess_mod_req_handover(mod_bearer_req_t *mbr);

int
process_pfcp_sess_del_request(del_sess_req_t *ds_req);

int
process_sgwc_delete_session_request(del_sess_req_t *ds_req);

void
set_pdn_type(pfcp_pdn_type_ie_t *pdn, pdn_type_ie *pdn_mme);

void
create_upf_context_hash(void);

void
create_gx_context_hash(void);

void
create_upf_by_ue_hash(void);

uint8_t
process_pfcp_report_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req);
#else
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn);

void
set_up_ip_resource_info(pfcp_user_plane_ip_rsrc_info_ie_t *up_ip_resource_info,
					uint8_t i);
#endif /* CP_BUILD */


int
set_node_id(pfcp_node_id_ie_t *node_id, uint32_t nodeid_value);

void
creating_bar(pfcp_create_bar_ie_t *create_bar);

void
set_fq_csid(pfcp_fqcsid_ie_t *fq_csid, uint32_t nodeid_value);

void
set_trace_info(pfcp_trc_info_ie_t *trace_info);

void
set_bar_id(pfcp_bar_id_ie_t *bar_id);

void
set_dl_data_notification_delay(pfcp_dnlnk_data_notif_delay_ie_t
		*dl_data_notification_delay);

void
set_sgstd_buff_pkts_cnt( pfcp_suggstd_buf_pckts_cnt_ie_t
		*sgstd_buff_pkts_cnt);

void
set_up_inactivity_timer(pfcp_user_plane_inact_timer_ie_t *up_inact_timer);

void
set_user_id(pfcp_user_id_ie_t *user_id);

void
set_fseid(pfcp_fseid_ie_t *fseid, uint64_t seid, uint32_t nodeid_value);

void
set_recovery_time_stamp(pfcp_rcvry_time_stmp_ie_t *rec_time_stamp);

void
set_upf_features(pfcp_up_func_feat_ie_t *upf_feat);

void
set_cpf_features(pfcp_cp_func_feat_ie_t *cpf_feat);

int
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val);

void
removing_bar( pfcp_remove_bar_ie_t *remove_bar);

void
set_traffic_endpoint(pfcp_traffic_endpt_id_ie_t *traffic_endpoint_id);

void
removing_traffic_endpoint(pfcp_rmv_traffic_endpt_ie_t
		*remove_traffic_endpoint);
void
creating_traffic_endpoint(pfcp_create_traffic_endpt_ie_t  *
		create_traffic_endpoint);

int
set_fteid(pfcp_fteid_ie_t *local_fteid);

int
set_network_instance(pfcp_ntwk_inst_ie_t *network_instance);

int
set_ue_ip(pfcp_ue_ip_address_ie_t *ue_ip);

void
set_ethernet_pdu_sess_info( pfcp_eth_pdu_sess_info_ie_t
		*eth_pdu_sess_info);

void
set_framed_routing(pfcp_framed_routing_ie_t *framedrouting);


int
set_qer_id(pfcp_qer_id_ie_t *qer_id);

int
set_qer_correl_id(pfcp_qer_corr_id_ie_t *qer_correl_id);

int
set_gate_status( pfcp_gate_status_ie_t *gate_status);

int
set_mbr(pfcp_mbr_ie_t *mbr);

int
set_gbr(pfcp_gbr_ie_t *gbr);

int
set_packet_rate(pfcp_packet_rate_ie_t *pkt_rate);

int
set_dl_flow_level_mark(pfcp_dl_flow_lvl_marking_ie_t *dl_flow_level_marking);

int
set_qfi(pfcp_qfi_ie_t *qfi);

int
set_rqi(pfcp_rqi_ie_t *rqi);

void
creating_qer(pfcp_create_qer_ie_t *qer);

void
updating_qer(pfcp_update_qer_ie_t *up_qer);

void
updating_bar( pfcp_upd_bar_sess_mod_req_ie_t *up_bar);

void
updating_far(pfcp_update_far_ie_t *up_far);

void
updating_traffic_endpoint(pfcp_upd_traffic_endpt_ie_t *up_traffic_endpoint);

void
set_pfcpsmreqflags(pfcp_pfcpsmreq_flags_ie_t *pfcp_sm_req_flags);

void
set_query_urr_refernce(pfcp_query_urr_ref_ie_t *query_urr_ref);


void
set_pfcp_ass_rel_req(pfcp_up_assn_rel_req_ie_t *ass_rel_req);

void
set_graceful_release_period(pfcp_graceful_rel_period_ie_t *graceful_rel_period);

void
set_sequence_num(pfcp_sequence_number_ie_t *seq);

void
set_metric(pfcp_metric_ie_t *metric);

void
set_period_of_validity(pfcp_timer_ie_t *pov);

void
set_oci_flag( pfcp_oci_flags_ie_t *oci);

void
set_offending_ie( pfcp_offending_ie_ie_t *offending_ie, int offend);

void
set_lci(pfcp_load_ctl_info_ie_t *lci);

void
set_olci(pfcp_ovrld_ctl_info_ie_t *olci);

void
set_failed_rule_id(pfcp_failed_rule_id_ie_t *rule);

void
set_traffic_endpoint_id(pfcp_traffic_endpt_id_ie_t *tnp);

int
set_pdr_id_ie(pfcp_pdr_id_ie_t *pdr);

int
set_created_pdr_ie(pfcp_created_pdr_ie_t *pdr);

void
set_created_traffic_endpoint(pfcp_created_traffic_endpt_ie_t *cte);

void
set_additional_usage(pfcp_add_usage_rpts_info_ie_t *adr);

void
set_node_report_type(pfcp_node_rpt_type_ie_t *nrt);

void
set_user_plane_path_failure_report(pfcp_user_plane_path_fail_rpt_ie_t *uppfr);


void
set_remote_gtpu_peer_ip(pfcp_rmt_gtpu_peer_ie_t *remote_gtpu_peer);

long
uptime(void);

void
cause_check_association(pfcp_assn_setup_req_t *pfcp_ass_setup_req,
						uint8_t *cause_id, int *offend_id);


void
cause_check_sess_estab(pfcp_sess_estab_req_t
			*pfcp_session_request, uint8_t *cause_id, int *offend_id);


void
cause_check_sess_modification(pfcp_sess_mod_req_t
		*pfcp_session_mod_req, uint8_t *cause_id, int *offend_id);

void
cause_check_delete_session(pfcp_sess_del_req_t
		*pfcp_session_delete_req, uint8_t *cause_id, int *offend_id);

uint8_t
add_node_id_hash(uint32_t *nodeid, uint64_t *data);

void
create_heartbeat_hash_table(void);

void
add_ip_to_heartbeat_hash(struct sockaddr_in *peer_addr, uint32_t recover_time);

void
delete_entry_heartbeat_hash(struct sockaddr_in *peer_addr);
int
add_data_to_heartbeat_hash_table(uint32_t *ip, uint32_t *recov_time);

void
clear_heartbeat_hash_table(void);

int
creating_pdr(pfcp_create_pdr_ie_t *create_pdr, int source_iface_value);

void
creating_far(pfcp_create_far_ie_t *create_far);

uint16_t
set_forwarding_param(pfcp_frwdng_parms_ie_t *frwdng_parms);

uint16_t
set_upd_forwarding_param(pfcp_upd_frwdng_parms_ie_t *upd_frwdng_parms);

uint16_t
set_apply_action(pfcp_apply_action_ie_t *apply_action);

uint16_t
set_outer_header_creation(pfcp_outer_hdr_creation_ie_t *outer_hdr_creation);

uint16_t
set_destination_interface(pfcp_dst_intfc_ie_t *dst_intfc);

int
set_pdr_id(pfcp_pdr_id_ie_t *pdr_id);

int
set_far_id(pfcp_far_id_ie_t *far_id);

void
set_far_id_mbr(pfcp_far_id_ie_t *far_id);

void
set_urr_id(pfcp_urr_id_ie_t *urr_id);

int
set_outer_hdr_removal(pfcp_outer_hdr_removal_ie_t *out_hdr_rem);

int
set_precedence(pfcp_precedence_ie_t *prec);

int
set_pdi(pfcp_pdi_ie_t *pdi);

void
set_application_id(pfcp_application_id_ie_t *app_id);

int
set_source_intf(pfcp_src_intfc_ie_t *src_intf);

void
set_activate_predefined_rules(pfcp_actvt_predef_rules_ie_t *act_predef_rule);

#ifdef CP_BUILD
uint16_t
set_pfd_contents(pfcp_pfd_contents_ie_t *pfd_conts, struct msgbuf *cstm_buf);

void
fill_pfcp_pfd_mgmt_req(pfcp_pfd_mgmt_req_t *pfcp_pfd_req, uint16_t len);

int
process_pfcp_pfd_mgmt_request(void);

int
upflist_by_ue_hash_entry_add(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t *entry);

int
upflist_by_ue_hash_entry_lookup(uint64_t *imsi_val, uint16_t imsi_len,
		upfs_dnsres_t **entry);

uint8_t
upf_context_entry_add(uint32_t *upf_ip, upf_context_t *entry);

int
upf_context_entry_lookup(uint32_t upf_ip, upf_context_t **entry);

int
gx_context_entry_add(char *sess_id, gx_context_t *entry);

int
gx_context_entry_lookup(char *sess_id, gx_context_t **entry);
void
create_s5s8_sgwc_hash_table(void);

void
clear_s5s8_sgwc_hash_table(void);
#endif /* CP_BUILD */

uint64_t
get_rule_type(pfcp_pfd_contents_ie_t *pfd_conts, uint16_t *idx);

#endif /* PFCP_SET_IE_H */
