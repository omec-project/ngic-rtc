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

#ifndef PFCP_SESSION_H
#define PFCP_SESSION_H

#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "gtpv2c.h"
#include "sm_struct.h"
#include "gtpv2c_ie.h"
#include "pfcp_set_ie.h"
#include "gtpv2c_set_ie.h"
#include "gtp_messages.h"
#endif

#define NUM_UE 10000
#define NUM_DP 100
#define MAX_LI_POLICY_LIMIT				255
#define ADDR_BUF_SIZE 64
#define PCKT_BUF_SIZE 256

/**
 * @brief  : This structure holds data related to association with dp
 */
typedef struct association_context{
	uint8_t       rx_buf[NUM_DP][NUM_UE];
	char sgwu_fqdn[NUM_DP][MAX_HOSTNAME_LENGTH];
	uint32_t      upf_ip;
	uint32_t      csr_cnt;
}association_context_t;

#ifdef CP_BUILD

#define PKT_FLTR_CONTENT_INDEX 3
#define PKT_FLTR_LEN_INDEX 2
#define PKT_FLTR_COMP_TYPE_ID_LEN 4
#define IP_MASK 8
#define PORT_LEN 2
#define PARAMETER_LIST_LEN 3
#define NEXT_PKT_FLTR_COMP_INDEX 3
#define NUM_OF_PKT_FLTR_MASK 0x0f
#define E_BIT_MASK 0x01
#define PKT_FLTR_ID_SIZE 8
#define EBI_ABSENT 0
#define TFT_OP_CODE_SHIFT 5
#define TFT_OP_CODE_MASK 0x0f
#define PARAM_LIST_INDEX 4

/**
 * @brief  : This structure holds rule cnt which is
 *         : to be send in Charging-Rule-Report AVP
 *         : in BRC flow.
 *         : Also store rule index of pckt-filter-id
 *         : and num of packet filter in rule
 */
typedef struct rule_report_index {
	uint8_t rule_cnt;
	uint8_t rule_report[MAX_RULE_PER_BEARER];
	uint8_t num_fltr[MAX_FILTERS_PER_UE];
}rule_report_index_t;

typedef struct pro_ack_rule_status {
	char rule_name[RULE_NAME_LEN];
	uint8_t rule_status;
}pro_ack_rule_status_t;

typedef struct pro_ack_rule_array {
	uint8_t rule_cnt;
	pro_ack_rule_status_t rule[MAX_RULE_PER_BEARER];
}pro_ack_rule_array_t;

typedef struct tad_pkt_fltr {
	uint8_t proto_id;
	uint8_t pckt_fltr_dir;
	uint32_t local_ip_addr;
	uint8_t local_ip_mask ;
	uint32_t remote_ip_addr;
	uint8_t remote_ip_mask;
	uint16_t local_port_low ;
	uint16_t local_port_high;
	uint16_t remote_port_low;
	uint16_t remote_port_high;
	uint16_t single_remote_port;
	uint16_t single_local_port;
	uint8_t pckt_fltr_id ;
	uint8_t precedence ;
}tad_pkt_fltr_t;

extern pro_ack_rule_array_t pro_ack_rule_array;

/**
 * @brief  : Check presence of packet filter id in rules
 * @param  : pckt_id, packet filter id received in bearer resource cmd
 * @param  : bearer, pointer to bearer in which pckt_id is to be find.
 * @return : Returns rule index which contain packet id on success,else -1
 */
int
check_pckt_fltr_id_in_rule(uint8_t pckt_id, eps_bearer *bearer);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_gx_packet_filter_info(uint8_t pkt_fltr_buf[], tad_pkt_fltr_t *tad_pkt_fltr);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_create_new_tft_avp(gx_msg *ccr_request, bearer_rsrc_cmd_t *bearer_rsrc_cmd);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_delete_existing_tft_avp(gx_msg *ccr_request);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_delete_existing_filter_tft_avp(gx_msg *ccr_request,
						bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : ccr_request, ptr to ccr msg structure.
 * @param  : bearer_rsrc_cmd, ptr to bearer rsrc cmd msg
 * @param  : bearer, ptr to bearer for which bearer id is recv in BRC
 * @return : Returns 0 on success,else return error code.
 */
int
fill_no_tft_avp(gx_msg *ccr_request,
					bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : ccr_request, pointer to ccr msg buffer
 * @param  : bearer_rsrc_cmd, holds bearer resource cmd msg
 * @return : Returns 0 on success,else return error code
 */
int
fill_replace_filter_existing_tft_avp(gx_msg *ccr_request,
								bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_qos_avp_bearer_resource_cmd(gx_msg *ccr_request, bearer_rsrc_cmd_t *bearer_rsrc_cmd);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
fill_gx_packet_filter_id(uint8_t *pkt_fltr_buf, delete_pkt_filter *pkt_id);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : ccr_request, pointer to msg which is send in ccr-u.
 * @param  : bearer_rsrc_cmd, pointer to received bearer resource cmd
 * @return : Returns 0 on success,else err code.
 */
int
fill_add_filter_existing_tft_avp(gx_msg *ccr_request,
									bearer_rsrc_cmd_t *bearer_rsrc_cmd, eps_bearer *bearer);

/**
 * @brief  : Fill gx AVP corresponding to bearer resource cmd
 * @param  : pkt_fltr_buf,packet filter in bearer resource cmd
 * @param  : tad_pkt_fltr,structure used to fill AVP
 * @return : Returns 0 on success,else 0
 */
int
parse_parameter_list(uint8_t pkt_fltr_buf[], param_list *param_lst);

/**
 * @brief  : Generate CCR request for provision ack
 * @param  : pdn , pointer to pdn connection structure
 * @param  : bearer, pointer to eps bearer structure
 * @param  : rule_action, indicate bearer operartin ADD/MODIFY/DELETE
 * @param  : code, indicate failure code
 * @param  : rule_report, structure contain affected rules
 * @return : Returns 0 on success,else 0
 */
int
provision_ack_ccr(pdn_connection *pdn, eps_bearer *bearer,
					enum rule_action_t rule_action,
					enum rule_failure_code code, pro_ack_rule_array_t *rule_report);

typedef int(*rar_funtions)(pdn_connection *);


/**
 * @brief  : This function fills the csr in resp structure
 * @param  : sess_id , session id.
 * @param  : key, pointer of context_key structure.
 * @return : returns 0 on success.
 *
 * */
int
fill_response(uint64_t sess_id, context_key *key);

#endif

extern association_context_t assoc_ctxt[NUM_DP] ;

/**
 * @brief  : Update cli statistics
 * @param  : msg_type, msg for which cli stats to be updated
 * @return : Returns nothing
 */
void
stats_update(uint8_t msg_type);

/**
 * @brief  : Fill pfcp session establishment response
 * @param  : pfcp_sess_est_resp , structure to be filled
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , Offending ie type
 * @param  : dp_comm_ip , ip address of dp
 * @param  : pfcp_session_request, pfcp session establishment request data
 * @return : Returns nothing
 */
void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t
				*pfcp_sess_est_resp, uint8_t cause, int offend,
				struct in_addr dp_comm_ip,
				struct pfcp_sess_estab_req_t *pfcp_session_request);

/**
 * @brief  : Fill pfcp session delete response
 * @param  : pfcp_sess_del_resp , structure to be filled
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , Offending ie type
 * @return : Returns nothing
 */
void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t
			*pfcp_sess_del_resp, uint8_t cause, int offend);

/**
 * @brief  : Fill pfcp session modify response
 * @param  : pfcp_sess_modify_resp , structure to be filled
 * @param  : pfcp_session_mod_req , pfcp session modify request data
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , Offending ie type
 * @return : Returns nothing
 */
void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend);
#ifdef CP_BUILD
/**
 * @brief  : Fill pfcp session establishment request
 * @param  : pfcp_sess_est_req , structure to be filled
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index of bearer in array
 * @param  : seq, sequence number of request
 * @return : Returns nothing
 */
void
fill_pfcp_sess_est_req( pfcp_sess_estab_req_t *pfcp_sess_est_req,
		pdn_connection *pdn, uint32_t seq, struct ue_context_t *context);

/**
 * @brief  : Checks and returns interface type if it access or core
 * @param  : iface , interface type
 * @param  : cp_type, cp type [SGWC/PGWC/SAEGWC].
 * @retrun : Returns interface type in case of success , -1 otherwise
 */
int
check_interface_type(uint8_t iface, uint8_t cp_type);

/**
 * @brief  : Fill pfcp session modification request
 * @param  : pfcp_sess_mod_req , structure to be filled
 * @param  : header, holds info in gtpv2c header
 * @param  : bearer, pointer to bearer structure
 * @param  : pdn , pdn information
 * @param  : update_far ,  array of update far rules
 * @param  : handover_flag ,  flag to check if it is handover scenario or not
 * @param  : beaer_count , number of bearer to be modified.
 * @return : Returns nothing
 */
void
fill_pfcp_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		gtpv2c_header_t *header, eps_bearer **bearers,
		pdn_connection *pdn, pfcp_update_far_ie_t update_far[],  uint8_t handover_flag, uint8_t bearer_count, ue_context *context);

/**
 * @brief  : Add new PDRs in bearer as we recive a new rule
			to be add in existing bearer
 * @param  : bearer , bearer to be modify
 * @param  : prdef, signifies predefine or dynamic rule
 * @return : Returns nothing
 */
void
add_pdr_qer_for_rule(eps_bearer *bearer, bool prdef_rule);

/**
 * @brief  : Fill pfcp session modification request for delete session request
 * @param  : pfcp_sess_mod_req , structure to be filled
 * @param  : pdn , pdn information
 * @param  : action, action we will be taking either delete or create bearer
 * @param  : resp , resp information
 * @return : Returns nothing
 */
void
fill_pfcp_gx_sess_mod_req(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
				pdn_connection *pdn, uint16_t action, struct resp_info *resp);

/**
 * @brief  : Create and Send pfcp session modification request for LI scenario
 * @param  : imsi, imsi of ue
 * @return : Returns nothing
 */
void
send_pfcp_sess_mod_req_for_li(uint64_t imsi);

/**
 * @brief  : update far ie as per li configurations
 * @param  : imsi_id_config, imsi_id_hash_t
 * @param  : context, ue_context
 * @param  : far, far ie
 * @return : Returns -1 in case of error
 */
int
update_li_info_in_upd_dup_params(imsi_id_hash_t *imsi_id_config, ue_context *context, pfcp_update_far_ie_t *far);

/**
 * @brief  : create far ie as per li configurations
 * @param  : imsi_id_config, imsi_id_hash_t
 * @param  : context, ue_context
 * @param  : far, far ie
 * @return : Returns -1 in case of error
 */
int
update_li_info_in_dup_params(imsi_id_hash_t *imsi_id_config, ue_context *context, pfcp_create_far_ie_t *far);

/**
 * @brief  : fill li policy using li_df_config_t
 * @param  : li_policy, user plane li policies
 * @param  : li_config, li df config
 * @param  : cp_mode, control plane mode
 * @return : Returns li policy length
 */
uint8_t
fill_li_policy(uint8_t *li_policy, li_df_config_t *li_config, uint8_t cp_mode);

/**
 * @brief  : Fill pfcp session modification request for handover scenario
 * @param  : pfcp_sess_mod_req , structure to be filled
 * @param  : header, holds info in gtpv2c header
 * @param  : pdn , pdn information
 * @return : Returns nothing
 */
void
fill_pfcp_sess_mod_req_delete(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr);

/**
 * @brief  : Fill pfcp session modification request for delete bearer scenario
 *           to fill remove_pdr ie
 * @param  : pfcp_sess_mod_req , structure to be filled
 * @param  : pdn , pdn information
 * @param  : bearers, pointer to bearer structure
 * @param  : bearer_cntr , number of bearer to be modified.
 * @return : Returns nothing
 */
void
fill_pfcp_sess_mod_req_pgw_init_remove_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn, eps_bearer *bearers[], uint8_t bearer_cntr);

/**
 * @brief  : Process pfcp session establishment response
 * @param  : pfcp_sess_est_rsp, structure to be filled
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : is_piggybacked flag to indicate whether message is to piggybacked.
 * @retrun : Returns 0 in case of success
 */
int8_t
process_pfcp_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp,
		gtpv2c_header_t *gtpv2c_tx, uint8_t is_piggybacked);

/**
 * @brief  : Process pfcp session modification response for handover scenario
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : context, ue context
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		ue_context *context);

/**
 * @brief  : Process pfcp session modification response
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : resp, resp_info for that sx session
 * @param  : context, UE context for user
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp, gtpv2c_header_t *gtpv2c_tx,
													ue_context *context, struct resp_info *resp);

/**
 * @brief  : Process pfcp session modification response for modification procedure
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : is_handover, indicates if it is handover scenario or not
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_mod_resp_for_mod_proc(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Process pfcp session modification response
 * @param  : sess_id, session id
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_upd_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp);


/**
 * @brief  : Process pfcp session modification response for delete bearer scenario
 * @param  : sess_id, session id
 * @param  : context, structure for context information
 * @param  : gtpv2c_tx, buffer to hold incoming data
 * @param  : resp, structure for response information
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_delete_bearer_pfcp_sess_response(uint64_t sess_id, ue_context *context,
						gtpv2c_header_t *gtpv2c_tx, struct resp_info *resp);

/**
 * @brief  : Process pfcp session modification request for delete bearer scenario
 * @param  : pdn, details of pdn connection
 * @retrun : Returns 0 in case of success, -1 otherwise
 */
int
process_sess_mod_req_del_cmd(pdn_connection *pdn);

/**
* @brief  : Process pfcp session modification response
*           in case of attach with dedicated flow
* @param  : sess_id, session id
* @param  : gtpv2c_tx, holds info in gtpv2c header
* @param  : resp, response structure information
* @retrun : Returns 0 in case of success
*/

int
process_pfcp_sess_mod_resp_cs_cbr_request(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx, struct resp_info *resp);

/**
 * @brief  : Fill pdr entry
 * @param  : context , pointer to ue context structure
 * @param  : pdn , pdn information
 * @param  : bearer, pointer to bearer structure
 * @param  : iface , interface type access or core
 * @param  : itr, index in pdr array stored in bearer context
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
pdr_t*
fill_pdr_entry(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, uint8_t iface, uint8_t itr);

/**
 * @brief  : Process delete bearer command request
 * @param  : del_bearer_cmd, delete bearer command structure
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : context, structure for context information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_delete_bearer_cmd_request(del_bearer_cmd_t *del_bearer_cmd, gtpv2c_header_t *gtpv2c_tx, ue_context *context);

/**
 * @brief  : Process bearer bearer resource command request
 * @param  : bearer_rsrc_cmd
 * @param  : gtpv2c_tx
 * @param  : context, pointer to the ue context
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_bearer_rsrc_cmd(bearer_rsrc_cmd_t *bearer_rsrc_cmd,
							gtpv2c_header_t *gtpv2c_tx, ue_context *context);

/**
 * @brief  : Fill pfcp  entry
 * @param  : bearer, pointer to bearer structure
 * @param  : dyn_rule, rule information
 * @param  : rule_action
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_pfcp_entry(eps_bearer *bearer, dynamic_rule_t *dyn_rule);

/**
 * @brief  : Fill SDF and QER of PDR using dyn_rule
 * @param  : pdr_ctxt , pdr_ctxt whose SDF and QER to be fill
 * @param  : dyn_rule, The QER and SDF from dynamic rule should fill
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
void
fill_pdr_sdf_qer(pdr_t *pdr_ctxt, dynamic_rule_t *dyn_rule);
/**
 * @brief  : Fill qer entry
 * @param  : pdn , pdn information
 * @param  : bearer, pointer to bearer structure
 * @param  : dyn_rule, rule information
 * @param  : rule_action
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_qer_entry(pdn_connection *pdn, eps_bearer *bearer,uint8_t itr);

/**
 * @brief  : Process pfcp delete session response
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @param  : ccr_request, structure to be filled for ccr request
 * @param  : msglen, total length
 * @param  : ue_context
 * @retrun : Returns 0 in case of success
 */
int8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen, ue_context *context);

/**
 * @brief  : function to proces delete session request on SGWC
 * @param  : ds_rsp, holds information in delete session request
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_rsp);

/**
 * @brief  : Delete all pdr, far, qer entry from table
 * @param  : ebi_index, index of bearer in array
 * @param  : pdn , pointer to pdn connection structure
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
del_rule_entries(pdn_connection *pdn, int ebi_index);

/**
 * @brief  : Delete dedicated bearers entry
 * @param  : pdn , pdn information
 * @param  : bearer_ids, array of bearer ids
 * @param  : bearer_cntr , number of bearer to be modified.
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
delete_dedicated_bearers(pdn_connection *pdn, uint8_t bearer_ids[], uint8_t bearer_cntr);

/**
 * @brief  : Generate string using sdf packet filters
 * @param  : sdf_flow , sdf packect filter info
 * @param  : sdf_str , string to store output
 * @param  : direction, data flow direction
 * @return : Returns nothing
 */
void
sdf_pkt_filter_to_string(sdf_pkt_fltr *sdf_flow, char *sdf_str,uint8_t direction);

/**
 * @brief  : Fill sdf packet filters  in pfcp session establishment  request
 * @param  : pfcp_sess_est_req, structure to be filled
 * @param  : bearer, pointer to bearer structure
 * @param  : pdr_counter , index to pdr
 * @param  : sdf_filter_count
 * @param  : dynamic_filter_cnt
 * @param  : flow_cnt
 * @param  : direction, data flow direction
 * @return : Returns nothing
 */
int sdf_pkt_filter_add(pfcp_pdi_ie_t* pdi, dynamic_rule_t *dynamic_rules,
		int sdf_filter_count, int flow_cnt, uint8_t direction);

/**
 * @brief  : Fill sdf rules in pfcp session establishment  request
 * @param  : pfcp_sess_est_req, structure to be filled
 * @param  : bearer, pointer to bearer structure
 * @param  : pdr_counter , index to pdr
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_create_pdr_sdf_rules(pfcp_create_pdr_ie_t *create_pdr,
		dynamic_rule_t *dynamic_rules, int pdr_counter);


/**
 * @brief  : Fill pdr , far and qer in pfcp session mod request from bearer
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, pointer to bearer structure
 * @return : Returns nothing
 */
void
fill_pdr_far_qer_using_bearer(pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		eps_bearer *bearer, ue_context *context, uint8_t create_pdr_counter);

/**
 * @brief  : Fill dedicated bearer information
 * @param  : bearer, pointer to bearer structure
 * @param  : context , pointer to ue context structure
 * @param  : pdn , pointer to pdn connection structure
 * @param  : prdef_rule, specify its a predef rule or not
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_dedicated_bearer_info(eps_bearer *bearer, ue_context *context, pdn_connection *pdn, bool prdef_rule);

/**
 * @brief  : Fill gate status in pfcp session establishment request
 * @param  : pfcp_sess_est_req , structure to be filled
 * @param  : qer_counter , qer rule index
 * @param  : f_status , flow status
 * @return : Returns nothing
 */
void fill_gate_status(pfcp_sess_estab_req_t *pfcp_sess_est_req,int qer_counter,enum flow_status f_status);

/**
 * @brief  : Get bearer information
 * @param  : pdn , pointer to pdn connection structure
 * @param  : qos, qos information
 * @retrun : Returns bearer structure pointer in case of success , NULL otherwise
 */
eps_bearer *
get_bearer(pdn_connection *pdn, bearer_qos_ie *qos);

/**
 * @brief  : Get dedicated bearer information
 * @param  : pdn , pointer to pdn connection structure
 * @retrun : Returns bearer structure pointer in case of success , NULL  otherwise
 */
eps_bearer *
get_default_bearer(pdn_connection *pdn);

/**
 * @brief  : Fill create pfcp information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : dyn_rule, rule information
 * @param  : context , pointer to ue context structure
 * @param  : gen_cdr, boolean value for generation of CDR
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_create_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
		ue_context *context, uint8_t gen_cdr);

/**
 * @brief  : Fill update pfcp information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : dyn_rule, rule information
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_update_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
																	ue_context *contex);

/**
 * @brief  : Return a Function Pointer on basis of action to be taken on
 * rule received in RAR request
 * @param  : pdn, pdn structure
 * @param  : proc, procedure from which the function being called
 * @retrun : Returns function pointer in success , NULL otherwise
 */
rar_funtions
rar_process(pdn_connection *pdn, uint8_t proc);

/**
 * @brief  : Generate reauth response
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index in array where eps bearer is stored
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
gen_reauth_response(pdn_connection *pdn);

/**
 * @brief  : Fill remove pfcp information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, bearer information
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_remove_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer);

/**
 * @brief  : check if bearer index free or not
 * @param  : context, ue context
 * @param  : ebi_index, index which needs to be search
 * @retrun : Returns 0  in case of success , -1 otherwise
 */
int8_t check_if_bearer_index_free(ue_context *context, int ebi_index);
/**
 * @brief  : Create new bearer id
 * @param  : pdn_cntxt, pdn connection information
 * @retrun : Returns bearer_id  in case of success , -1 otherwise
 */
int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt);

/**
 * @brief  : Process pfcp sess setup for establish session
 * @param  : pdn, pdn connection information
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_setup(pdn_connection *pdn);

#else
#endif /* CP_BUILD */

/**
 * @brief  : Fill pfcp duplicating paramers IE of create FAR
 * @param  : dup_params , structure to be filled
 * @param  : li_policy, User Level Packet Copying Policy array
 * @param  : li_policy_len, User Level Packet Copying Policy array length
 * @return : Returns 0 for success and -1 for failure
 */
uint16_t fill_dup_param(pfcp_dupng_parms_ie_t *dup_params,
		uint8_t li_policy[], uint8_t li_policy_len);

/**
 * @brief  : Fill pfcp duplicating paramers IE of update FAR
 * @param  : dup_params , structure to be filled
 * @param  : li_policy, User Level Packet Copying Policy array
 * @param  : li_policy_len, User Level Packet Copying Policy array length
 * @return : Returns 0 for success and -1 for failure
 */
uint16_t fill_upd_dup_param(pfcp_upd_dupng_parms_ie_t *dup_params,
		uint8_t li_policy[], uint8_t li_policy_len);

/**
* @brief  : Fill pfcp session set delete request
* @param  : pfcp_sess_set_del_req , structure to be filled
 * @return : Returns nothing
*/
void
fill_pfcp_sess_set_del_req( pfcp_sess_set_del_req_t *pfcp_sess_set_del_req);


/**
 * @brief  : Fill pfcp session delete request
 * @param  : pfcp_sess_del_req , structure to be filled
 * @param  : cp_type, [SGWC/SAEGWC/PGWC]
 * @return : Returns nothing
 */
void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req, uint8_t cp_type);

#ifdef CP_BUILD
/**
 * @brief  : Update ue context information
 * @param  : mb_req, buffer which contains incoming request data, ue context
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int8_t
update_ue_context(mod_bearer_req_t *mb_req, ue_context *context);

/**
 * @brief  : Delete QER from bearer array
 * @param  : Bearer whose QER to be deleted
 * @param  : qer_id_value, QER id which is to be deleted
 * @retrun : Returns nothing
 */
void
remove_qer_from_bearer(eps_bearer *bearer, uint16_t qer_id_value);

/**
 * @brief  : Delete PDR from bearer array
 * @param  : bearer, Bearer whose PDR to be deleted
 * @param  : pdr_id_value, PDR id which is to be deleted
 * @retrun : Returns nothing
 */
void
remove_pdr_from_bearer(eps_bearer *bearer, uint16_t pdr_id_value);

/**
 * @brief  : Delete PDR entery and corresponding QER entery
 * @param  : bearer, Bearer whose PDR and QER to be deleted
 * @param  : pdr_id_value, PDR id which is to be deleted
 * @retrun : Returns nothing
 */
int
delete_pdr_qer_for_rule(eps_bearer *bearer, uint16_t pdr_id_value);


/**
 * @brief  : Fill ue context info from incoming data in create sess request
 * @param  : csr holds data in csr
 * @param  : context , pointer to ue context structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_context_info(create_sess_req_t *csr, ue_context *context, pdn_connection *pdn);
/**
 * @brief  : Fill pdn info from data in incoming csr
 * * @param  : csr holds data in csr
 * @param  : pdn , pointer to pdn connction structure
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
fill_pdn_info(create_sess_req_t *csr, pdn_connection *pdn,
	ue_context *context, eps_bearer *bearer);



/**
 * @brief  : Fill update pdr information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, bearer information
 * @retrun : Returns nothing
 *
 */
void
fill_update_bearer_sess_mod(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer);

/**
 * @brief  : Fill update pdr information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, bearer information
 * @param  : cp_type, [SWGC/SAEGWC/PGWC]
 * @retrun : Returns nothing
 */
void
fill_update_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer,
		uint8_t cp_type);


/**
 * @brief  : Fill update pdr information
 * @param  : update_pdr, structure to be filled
 * @param  : dyn_rule, dynamic rule information
 * @param  : pdr_counter, No of PDR
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int fill_update_pdr_sdf_rule(pfcp_update_pdr_ie_t* update_pdr,
								dynamic_rule_t *dyn_rule, int pdr_counter);

/* @brief  : clear the resp_info struct information
 * @param  : resp, pointer to resp_info structure needs to be cleaned up
 * @return : Returns nothing
 * */
void
reset_resp_info_structure(struct resp_info *resp);

/**
 * @brief  : Parse handover CSR request on Combined GW
 * @param  : csr holds data in csr
 * @param  : Context, pointer to UE context structure
 * @param  : CP_TYPE: changed gateway type, promotion PGWC --> SAEGWC
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
promotion_parse_cs_req(create_sess_req_t *csr, ue_context *context,
		uint8_t cp_type);

/**
 * @brief  : Send the PFCP Session Modification Request after promotion
 * @param  : Context, pointer to UE context structure
 * @param  : bearer, bearer to be deleted.
 * @param  : pdn , pointer to pdn connection structure
 * @param  : csr holds data in csr
 * @param  : ebi_index, bearer identifier
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
send_pfcp_modification_req(ue_context *context, pdn_connection *pdn,
		eps_bearer *bearer, create_sess_req_t *csr, uint8_t ebi_index);

/* @brief  : Check presense of LBI in ue context
 * @param  : bearer_id,bearer id receive in LBI of BRC
 * @param  : context, pointer to ue_context structure
 * @return : Returns 0 on success, else -1
 * */
int
check_default_bearer_id_presence_in_ue(uint8_t bearer_id,
					ue_context *context);

/* @brief  : Check presense of LBI in ue context
 * @param  : bearer_id,bearer id receive in LBI of BRC
 * @param  : context, pointer to ue_context structure
 * @return : Returns 0 on success, else -1
 * */
int
check_ebi_presence_in_ue(uint8_t bearer_id,
					ue_context *context);

/* @brief  : Store rule name & status for Delete bearer cmd
 * @param  : pro_ack_rule_array, array to store rule name & status
 * @param  : bearer, bearer to be deleted.
 * @return : Returns 0 on success, else -1
 * */
int
store_rule_status_for_del_bearer_cmd(pro_ack_rule_array_t *pro_ack_rule_array,
										eps_bearer *bearer);

/* @brief  : update the pdr actions flags
 * @param  : bearer, bearer for modify pdr actions flags
 * @return : Nothing
 * */
void update_pdr_actions_flags(eps_bearer *bearer);
#endif /* CP_BUILD */
#endif /* PFCP_SESSION_H */
