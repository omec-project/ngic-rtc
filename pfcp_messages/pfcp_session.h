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

/**
 * @brief  : This structure holds data related to association with dp
 */
typedef struct association_context{
	uint8_t       rx_buf[NUM_DP][NUM_UE];
	char sgwu_fqdn[NUM_DP][MAX_HOSTNAME_LENGTH];
	uint32_t      upf_ip;
	uint32_t      csr_cnt;
}association_context_t;

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
 * @retrun : Returns interface type in case of success , -1 otherwise
 */
int
check_interface_type(uint8_t iface);

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
 * @brief  : Fill pfcp session modification request for delete session request
 * @param  : pfcp_sess_mod_req , structure to be filled
 * @param  : header, holds info in gtpv2c header
 * @param  : context , pointer to ue context structure
 * @param  : pdn , pdn information
 * @return : Returns nothing
 */
void
fill_pfcp_gx_sess_mod_req( pfcp_sess_mod_req_t *pfcp_sess_mod_req,
		pdn_connection *pdn);

/**
 * @brief  : Create and Send pfcp session modification request for LI scenario
 * @param  : li_config, li structure
 * @return : Returns nothing
 */
void
send_pfcp_sess_mod_req_for_li(struct li_df_config_t *li_config);

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
process_pfcp_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, gtpv2c_header_t *gtpv2c_tx,  uint8_t is_piggybacked);

/**
 * @brief  : Process pfcp session modification response for handover scenario
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_mod_resp_handover(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Process pfcp session modification response
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_pfcp_sess_mod_resp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp, gtpv2c_header_t *gtpv2c_tx);

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
 * @param  : gtpv2c_tx, buffer to hold incoming data
 * @retrun : Returns 0 in case of success
 */
uint8_t
process_delete_bearer_pfcp_sess_response(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Process pfcp session modification response for delete bearer scenario
 * @param  : sess_id, session id
 * @param  : gtpv2c_tx, buffer to hold incoming data
 * @param  : flag, flag to differntiate parent request
 * @retrun : Returns 0 in case of success, -1 otherwise
 */
int
process_pfcp_sess_mod_resp_del_cmd(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx, uint8_t *flag);

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
* @retrun : Returns 0 in case of success
*/

int
process_pfcp_sess_mod_resp_cs_cbr_request(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx);

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
 * @param  : del_bearer_cmd
 * @param  : gtpv2c_tx
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_delete_bearer_cmd_request(del_bearer_cmd_t *del_bearer_cmd, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Fill pfcp  entry
 * @param  : bearer, pointer to bearer structure
 * @param  : dyn_rule, rule information
 * @param  : rule_action
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_pfcp_entry(eps_bearer *bearer, dynamic_rule_t *dyn_rule,
		enum rule_action_t rule_action);

/**
 * @brief  : Fill qer entry
 * @param  : pdn , pdn information
 * @param  : bearer, pointer to bearer structure
 * @param  : itr, index in qer array stored in bearer context
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
 * @param  : uiImsi, for lawful interception
 * @param  : li_sock_fd for lawful interception
 * @retrun : Returns 0 in case of success
 */
int8_t
process_pfcp_sess_del_resp(uint64_t sess_id, gtpv2c_header_t *gtpv2c_tx,
		gx_msg *ccr_request, uint16_t *msglen, uint64_t *uiImsi, int *li_sock_fd);

/**
 * @brief  : fill create session response on PGWC
 * @param  : cs_resp, structure to be filled
 * @param  : sequence, seq number of request
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index of bearer in array
 * @param  : is_piggybacked, piggybacked message
 * @return : Returns nothing
 */
void
fill_pgwc_create_session_response(create_sess_rsp_t *cs_resp,
				uint32_t sequence, struct ue_context_t *context, uint8_t ebi_index, uint8_t piggybacked);
/**
 * @brief  : function to proces create session response on SGWC received from PGWC
 * @param  : cs_rsp, holds information in create session response
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp);

/**
 * @brief  : function to proces delete session response on SGWC received from PGWC
 * @param  : ds_rsp, holds information in delete session response
 * @param  : gtpv2c_tx, holds info in gtpv2c header
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_delete_session_response(del_sess_rsp_t *ds_rsp, uint8_t *gtpv2c_tx);

/**
 * @brief  : function to proces delete session request on SGWC
 * @param  : ds_rsp, holds information in delete session request
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_rsp);

/**
 * @brief  : function to proces delete session request on PGWC
 * @param  : ds_req, holds information in delete session request
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
process_pgwc_s5s8_delete_session_request(del_sess_req_t *ds_req);

/**
 * @brief  : Delete all pdr, far, qer entry from table
 * @param  : ebi_index, index of bearer in array
 * @param  : context , pointer to ue context structure
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
del_rule_entries(ue_context *context, uint8_t ebi_index);

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
		eps_bearer *bearer, ue_context *context);

/**
 * @brief  : Fill dedicated bearer information
 * @param  : bearer, pointer to bearer structure
 * @param  : context , pointer to ue context structure
 * @param  : pdn , pointer to pdn connection structure
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_dedicated_bearer_info(eps_bearer *bearer, ue_context *context, pdn_connection *pdn);

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
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_create_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
																	ue_context *context);

/**
 * @brief  : Fill update pfcp information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : dyn_rule, rule information
 * @param  : context, ue_context
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_update_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, dynamic_rule_t *dyn_rule,
		ue_context *context);

#ifdef GX_BUILD
/**
 * @brief  : Generate reauth response
 * @param  : context , pointer to ue context structure
 * @param  : ebi_index, index in array where eps bearer is stored
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
gen_reauth_response(ue_context *context, uint8_t ebi_index);
#endif /* GX_BUILD */

/**
 * @brief  : Fill remove pfcp information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, bearer information
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int
fill_remove_pfcp_info(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer);

/**
 * @brief  : Create new bearer id
 * @param  : pdn_cntxt, pdn connection information
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int8_t
get_new_bearer_id(pdn_connection *pdn_cntxt);

#else
#endif /* CP_BUILD */

/**
 * @brief  : Fill pfcp duplicating paramers IE of create FAR
 * @param  : dup_params , structure to be filled
 * @param  : ipv4_address, ip address of source for dupilicating
 * @param  : port_number, port number of source for dupilicating
 * @return : Returns 0 for success and -1 for failure
 */
uint16_t fill_dup_param(pfcp_dupng_parms_ie_t *dup_params, uint32_t ipv4_address,
										uint16_t port_number, uint16_t li_policy);

/**
 * @brief  : Fill pfcp duplicating paramers IE of update FAR
 * @param  : dup_params , structure to be filled
 * @param  : ipv4_address, ip address of source for dupilicating
 * @param  : port_number, port number of source for dupilicating
 * @return : Returns 0 for success and -1 for failure
 */
uint16_t fill_upd_dup_param(pfcp_upd_dupng_parms_ie_t *dup_params, uint32_t ipv4_address,
										uint16_t port_number, uint16_t li_policy);

/**
 * @brief  : Fill pfcp session delete request
 * @param  : pfcp_sess_del_req , structure to be filled
 * @return : Returns nothing
 */
void
fill_pfcp_sess_del_req( pfcp_sess_del_req_t *pfcp_sess_del_req);
/**
 * @brief  : Fill pfcp session set delete request
 * @param  : pfcp_sess_set_del_req , structure to be filled
 * @return : Returns nothing
 */
void
fill_pfcp_sess_set_del_req( pfcp_sess_set_del_req_t *pfcp_sess_set_del_req);

#ifdef CP_BUILD
/**
 * @brief  : Update ue context information
 * @param  : mb_req, buffer which contains incoming request data
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int8_t
update_ue_context(mod_bearer_req_t *mb_req);

/**
 * @brief  : Fill update pdr information
 * @param  : pfcp_sess_mod_req, structure to be filled
 * @param  : bearer, bearer information
 * @retrun : Returns nothing
 */
void
fill_update_pdr(pfcp_sess_mod_req_t *pfcp_sess_mod_req, eps_bearer *bearer);


/**
 * @brief  : Fill update pdr information
 * @param  : update_pdr, structure to be filled
 * @param  : bearer, bearer information
 * @param  : pdr_counter, No of PDR
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int fill_update_pdr_sdf_rule(pfcp_update_pdr_ie_t* update_pdr,
								eps_bearer* bearer, int pdr_counter);

#endif /* CP_BUILD */
#endif /* PFCP_SESSION_H */
