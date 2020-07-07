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

#ifndef PFCP_UP_SESS_H
#define PFCP_UP_SESS_H

#include "pfcp_messages.h"

/**
 * @brief  : Process pfcp session association req at dp side
 * @param  : ass_setup_req, hold pfcp session association req data
 * @param  : ass_setup_resp, response structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_assoc_req(pfcp_assn_setup_req_t *ass_setup_req,
			pfcp_assn_setup_rsp_t *ass_setup_resp);
/**
 * @brief  : Process pfcp session establishment req at dp side
 * @param  : sess_req, hold pfcp session establishment req data
 * @param  : sess_resp, response structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_estab_req(pfcp_sess_estab_req_t *sess_req,
			pfcp_sess_estab_rsp_t *sess_resp);

/**
 * @brief  : Process pfcp session modification req at dp side
 * @param  : sess_mod_req, hold pfcp session modification req data
 * @param  : sess_mod_rsp, response structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_modification_req(pfcp_sess_mod_req_t *sess_mod_req,
			pfcp_sess_mod_rsp_t *sess_mod_rsp);

/**
 * @brief  : Deletes session entry at dp side
 * @param  : sess_del_req, hold pfcp session deletion req data
 * @param  : sess_del_rsp, response structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
up_delete_session_entry(pfcp_session_t *sess, pfcp_sess_del_rsp_t *sess_del_rsp);

/**
 * @brief  : Process pfcp session deletion req at dp side
 * @param  : sess_del_req, hold pfcp session deletion req data
 * @param  : sess_del_rsp, response structure to be filled
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_deletion_req(pfcp_sess_del_req_t *sess_del_req,
			pfcp_sess_del_rsp_t *sess_del_rsp);

/**
 * @brief  : Fill Process pfcp session establishment response
 * @param  : pfcp_sess_est_resp, structure to be filled
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , offending ie type if any
 * @param  : dp_comm_ip, ip address
 * @param  : pfcp_session_request, hold data from establishment request
 * @return : Returns nothing
 */
void
fill_pfcp_session_est_resp(pfcp_sess_estab_rsp_t
				*pfcp_sess_est_resp, uint8_t cause, int offend,
				struct in_addr dp_comm_ip,
				struct pfcp_sess_estab_req_t *pfcp_session_request);

/**
 * @brief  : Fill Process pfcp session delete response
 * @param  : pfcp_sess_del_resp, structure to be filled
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , offending ie type if any
 * @return : Returns nothing
 */
void
fill_pfcp_sess_del_resp(pfcp_sess_del_rsp_t
			*pfcp_sess_del_resp, uint8_t cause, int offend);

/**
 * @brief  : Fill Process pfcp session modification response
 * @param  : pfcp_sess_modify_resp, structure to be filled
 * @param  : pfcp_session_mod_req, holds information from modification request
 * @param  : cause , cause whether request is accepted or not
 * @param  : offend , offending ie type if any
 * @return : Returns nothing
 */
void
fill_pfcp_session_modify_resp(pfcp_sess_mod_rsp_t *pfcp_sess_modify_resp,
		pfcp_sess_mod_req_t *pfcp_session_mod_req, uint8_t cause, int offend);

/**
 * @brief  : Fill usage report for pfcp session modification response
 * @param  : usage_report, usage report to be fill
 * @param  : urr, urr strcute for which we are genrating usage report.
 * @return : Returns 0 for Success and -1 for failure
 */
int8_t
fill_sess_mod_usage_report(pfcp_usage_rpt_sess_mod_rsp_ie_t *usage_report,
															urr_info_t *urr);

/**
 * @brief  : Fill usage report for pfcp session deletion response
 * @param  : usage_report, usage report to be fill
 * @param  : urr, urr strcute for which we are genrating usage report.
 * @return : Returns 0 for Success and -1 for failure
 */
int8_t
fill_sess_del_usage_report(pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report,
															urr_info_t *urr);

/**
 * @brief  : Fill usage report for pfcp session report request
 * @param  : usage_report, usage report to be fill
 * @param  : urr, urr strcute for which we are genrating usage report.
 * @return : Returns 0 for Success and -1 for failure
 */
int8_t
fill_sess_rep_req_usage_report(pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report,
												urr_info_t *urr, uint32_t trig);

/*
* @brief  : add a timer entry for usage report
* @param  : conn_data, Peer node connection information
* @param  : urr, urr object
* @param  : cb, timer callback
* @return : Returns true or false
*/

bool
add_timer_entry_usage_report( peerEntry *conn_data, uint32_t timeout_ms, gstimercallback cb);



/*
* @brief  : fill a Peer node connection information
* @param  : peer_addr, dest sockect addr
* @param  : urr, urr object
* @param  : cp_seid, cp's session id
* @return : Returns pointer of peerEntry
*/
peerEntry *
fill_timer_entry_usage_report(struct sockaddr_in *peer_addr, urr_info_t *urr, uint64_t cp_seid);


/**
* @brief  : timer callback
* @param  : ti, timer information
* @param  : data_t, Peer node connection information
* @return : Returns nothing
*/
void
timer_callback(gstimerinfo_t *ti, const void *data_t);


/**
* @brief  : inittimer, initialize a timer
* @param  : md, Peer node connection infomation
* @param  : ptms, timer in milisec
* @param  : cb, callback function to call
* @return : Returns nothing
*/
bool inittimer(peerEntry *md, int ptms, gstimercallback cb);

/*
* @brief  : Send pfcp report request for periodic genration for CDR
* @param  : urr, URR info for which we need to generte PFCP rep Req
* @param  : cp_seid, seid of CP
* @param  : trig, Trig point of  PFCP rep Req(VOL based or Time Based)
* @return : Returns 0 for succes and -1 failure
*/
int send_usage_report_req(urr_info_t *urr, uint64_t cp_seid, uint32_t trig);



/*
 * @brief  : Get the PFCP recv msg and sent msg and Send it to required server
 * @param  : sess, The UE session for which we need to perform LI on EVENTS/IRI
 * @param  : buf_rx, PFCP msg recived in DP
 * @param  : buf_rx_size, Size of recived msgs
 * @param  : buf_tx, PFCP msg DP is sending
 * @param  : buf_tx_size, Size of PFCP msg DP is sending
 * @return : Returns nothing
 */
int32_t
process_event_li(pfcp_session_t *sess, uint8_t *buf_rx, int buf_rx_size,
	uint8_t *buf_tx, int buf_tx_size, uint32_t srcip, uint16_t srcport);

#endif /* PFCP_UP_SESS_H */
