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

#include "ue.h"
#include "pfcp_messages.h"
#include "cp.h"
#include <arpa/inet.h>
#include <rte_errno.h>

#if defined(PFCP_COMM) && defined(CP_BUILD)
#include "../cp/gtpv2c.h"
#include "../cp/gtpv2c_ie.h"
#include "gtpv2c_messages.h"
#include "gtpv2c_set_ie.h"
#endif

/* TODO: Move following lines to another file */
#define HAS_SEID 1
#define NO_SEID  0

#define PFCP_VERSION                            (1)

#define OFFSET 2208988800ULL

/* PFCP Message Type Values */
/*NODE RELATED MESSAGED*/
#define PFCP_HEARTBEAT_REQUEST                      (1)
#define PFCP_HEARTBEAT_RESPONSE                     (2)
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

/* TODO: Move above lines to another file */

#define PFCP_ASSOC_ALREADY_ESTABLISHED				(1)

#define MAX_HOSTNAME_LENGTH							(256)

#define MAX_GTPV2C_LENGTH (MAX_GTPV2C_UDP_LEN-sizeof(struct gtpc_t))

#define ALL_UPF_FEATURES_SUPPORTED  ( UP_BUCP | UP_DDND | UP_DLBD |\
		UP_TRST | UP_FTUP | UP_PFDM | UP_HEEU | UP_TREU | UP_EMPU |\
		UP_PDIU | UP_UDBC | UP_QUOAC | UP_TRACE| UP_FRRT)
#define ALL_CPF_FEATURES_SUPPORTED  (CP_LOAD | CP_OVRL)

#define UINT8_SIZE sizeof(uint8_t)
#define UINT32_SIZE sizeof(uint32_t)
#define UINT16_SIZE sizeof(uint16_t)
#define IPV4_SIZE 4
#define IPV6_SIZE 8
#define PFCP_IE_HDR_SIZE sizeof(pfcp_ie_header_t)
#define BITRATE_SIZE 10
#pragma pack(1)
typedef struct pfcp_context_t{
	uint16_t up_supported_features;
	uint8_t  cp_supported_features;
	uint32_t s1u_ip[20];
	uint32_t s5s8_sgwu_ip;
	uint32_t s5s8_pgwu_ip;
	struct in_addr ava_ip;
	bool flag_ava_ip;

}pfcp_context_t;

#pragma pack()

extern pfcp_context_t pfcp_ctxt;

void
set_pfcp_header(pfcp_header_t *pfcp, uint8_t type, bool flag );

void
set_pfcp_seid_header(pfcp_header_t *pfcp, uint8_t type, bool flag, uint32_t seq );

void
pfcp_set_ie_header(pfcp_ie_header_t *header, uint8_t type, uint16_t length);

int
process_pfcp_heartbeat_req(struct sockaddr_in *peer_addr, uint32_t seq);


#if defined(PFCP_COMM)  && defined(CP_BUILD)
int
process_pfcp_assoication_request(gtpv2c_header *gtpv2c_rx,
		create_session_request_t *csr, char *sgwu_fqdn);
int
process_pfcp_sess_est_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx,
		char *sgwu_fqdn);
int
process_pfcp_sess_mod_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx);
int
process_pfcp_sess_del_request(gtpv2c_header *gtpv2c_rx,
		gtpv2c_header *gtpv2c_s11_tx, gtpv2c_header *gtpv2c_s5s8_tx);
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn, pdn_type_ie_t *pdn_mme);

#else
int
process_pfcp_sess_est_request(void);
int
process_pfcp_sess_mod_request(void);
int
process_pfcp_sess_del_request(void);
void
set_pdn_type(pfcp_pdn_type_ie_t *pdn);

#endif //PFCP_COMM


void
set_node_id(node_id_ie_t *node_id, uint32_t nodeid_value);

void
creating_bar(create_bar_ie_t *create_bar);

void
set_fq_csid(fq_csid_ie_t *fq_csid, uint32_t nodeid_value);

void
set_trace_info(trace_information_ie_t *trace_info);

void
set_bar_id(bar_id_ie_t *bar_id);

void
set_dl_data_notification_delay(downlink_data_notification_delay_ie_t
		*dl_data_notification_delay);

void
set_sgstd_buff_pkts_cnt( suggested_buffering_packets_count_ie_t
		*sgstd_buff_pkts_cnt);

void
set_up_inactivity_timer(user_plane_inactivity_timer_ie_t *up_inact_timer);

void
set_user_id(user_id_ie_t *user_id);

void
set_fseid(f_seid_ie_t *fseid, uint64_t seid, uint32_t nodeid_value);

void
set_recovery_time_stamp(recovery_time_stamp_ie_t *rec_time_stamp);

void
set_upf_features(up_function_features_ie_t *upf_feat);

void
set_cpf_features(cp_function_features_ie_t *cpf_feat);


void
set_cause(pfcp_cause_ie_t *cause, uint8_t cause_val);

void
removing_bar( remove_bar_ie_t *remove_bar);

void
set_traffic_endpoint(traffic_endpoint_id_ie_t *traffic_endpoint_id);

void
removing_traffic_endpoint(remove_traffic_endpoint_ie_t
		*remove_traffic_endpoint);
void
creating_traffic_endpoint(create_traffic_endpoint_ie_t  *
		create_traffic_endpoint);

void
set_fteid( f_teid_ie_t *local_fteid);

void
set_network_instance(network_instance_ie_t *network_instance);

void
set_ue_ip(ue_ip_address_ie_t *ue_ip);

void
set_ethernet_pdu_sess_info( ethernet_pdu_session_information_ie_t
		*eth_pdu_sess_info);

void
set_framed_routing(framed_routing_ie_t *framedrouting);


void
set_qer_id(qer_id_ie_t *qer_id);

void
set_qer_correl_id(qer_correlation_id_ie_t *qer_correl_id);

void
set_gate_status( gate_status_ie_t *gate_status);

void
set_mbr(mbr_ie_t *mbr);

void
set_gbr(gbr_ie_t *gbr);

void
set_packet_rate(packet_rate_ie_t *pkt_rate);

void
set_dl_flow_level_mark(dl_flow_level_marking_ie_t *dl_flow_level_marking);

void
set_qfi(qfi_ie_t *qfi);

void
set_rqi(rqi_ie_t *rqi);
void
updating_qer(update_qer_ie_t *up_qer);

void
updating_bar( update_bar_ie_t *up_bar);

void
updating_traffic_endpoint(update_traffic_endpoint_ie_t *up_traffic_endpoint);

void
set_pfcpsmreqflags(pfcpsmreq_flags_ie_t *pfcp_sm_req_flags);

void
set_query_urr_refernce( query_urr_reference_ie_t *query_urr_ref);


void
set_pfcp_ass_rel_req(pfcp_association_release_request_ie_t *ass_rel_req);

void
set_graceful_release_period(graceful_release_period_ie_t *graceful_rel_period);

void
set_sequence_num(sequence_number_ie_t *seq);

void
set_metric(metric_ie_t *metric);

void
set_period_of_validity(timer_ie_t *pov);

void
set_oci_flag( oci_flags_ie_t *oci);

void
set_offending_ie( offending_ie_ie_t *offending_ie, int offend);

void
set_lci(load_control_information_ie_t *lci);

void
set_olci(overload_control_information_ie_t *olci);

void
set_failed_rule_id(failed_rule_id_ie_t *rule);

void
set_traffic_endpoint_id(traffic_endpoint_id_ie_t *tnp);

void
set_pdr_id_ie(pdr_id_ie_t *pdr);

void
set_created_pdr_ie(created_pdr_ie_t *pdr);

void
set_created_traffic_endpoint(created_traffic_endpoint_ie_t *cte);

void
set_additional_usage(additional_usage_reports_information_ie_t *adr);

void
set_node_report_type( node_report_type_ie_t *nrt);

void
set_user_plane_path_failure_report(user_plane_path_failure_report_ie_t *uppfr);


void
set_remote_gtpu_peer_ip( remote_gtp_u_peer_ie_t *remote_gtpu_peer);

long
uptime(void);

void
cause_check_association(pfcp_association_setup_request_t *pfcp_ass_setup_req,
						uint8_t *cause_id, int *offend_id);


void
cause_check_sess_estab(pfcp_session_establishment_request_t
			*pfcp_session_request, uint8_t *cause_id, int *offend_id);


void
cause_check_sess_modification(pfcp_session_modification_request_t
		*pfcp_session_mod_req, uint8_t *cause_id, int *offend_id);

void
cause_check_delete_session(pfcp_session_deletion_request_t
		*pfcp_session_delete_req, uint8_t *cause_id, int *offend_id);

uint8_t
add_node_id_hash(uint32_t *nodeid, uint64_t *data);

uint8_t
add_associated_upf_ip_hash(uint32_t *nodeid, uint8_t *data);

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

void
creating_pdr(create_pdr_ie_t *create_pdr);

void
set_pdr_id(pdr_id_ie_t *pdr_id);

void
set_far_id(far_id_ie_t *far_id);

void
set_urr_id(urr_id_ie_t *urr_id);

void
set_outer_hdr_removal(outer_header_removal_ie_t *out_hdr_rem);

void
set_precedence(precedence_ie_t *prec);
void
set_pdi(pdi_ie_t *pdi);
void
set_application_id(application_id_ie_t *app_id);

void
set_source_intf(source_interface_ie_t *src_intf);
void
set_activate_predefined_rules(activate_predefined_rules_ie_t *act_predef_rule);
void
set_up_ip_resource_info(user_plane_ip_resource_information_ie_t *up_ip_resource_info,
  uint8_t i);

#endif /* PFCP_SET_IE_H */
