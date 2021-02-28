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

/*DP-CDR related definations*/
#define PATH_TEMP		"./CDR_temp.csv"
#define VOLUME_LIMIT	"volume_limit"
#define TIME_LIMIT		"Time_limit"
#define CDR_TERMINATION	"Termination"
#define CDR_BUFF_SIZE 	256
#define CDR_TIME_BUFF 	16
#define MAX_SEQ_NO_LEN 32
#define UP_SEID_LEN 16
#define CDR_HEADER "seq_no,up_seid,cp_seid,imsi,dp_ip,cp_ip,ue_ip,cause_for_record_closing,uplink_volume,downlink_volume,total_volume,duration_measurement,start_time,end_time,data_start_time,data_end_time\n"

extern char CDR_FILE_PATH[CDR_BUFF_SIZE];
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
 * @param  : cp_ip, the SGWC/PGWC/SAEGWC IP
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_estab_req(pfcp_sess_estab_req_t *sess_req,
			pfcp_sess_estab_rsp_t *sess_resp, uint32_t cp_ip);

/**
 * @brief  : Process pfcp session modification req at dp side
 * @param  : sess_mod_req, hold pfcp session modification req data
 * @param  : sess_mod_rsp, response structure to be filled
 * @param  : cp_ip, the SGWC/PGWC/SAEGWC IP
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_modification_req(pfcp_sess_mod_req_t *sess_mod_req,
			pfcp_sess_mod_rsp_t *sess_mod_rsp, uint32_t cp_ip);

/**
 * @brief  : Deletes session entry at dp side
 * @param  : sess_del_req, hold pfcp session deletion req data
 * @param  : sess_del_rsp, response structure to be filled
 * @param  : cp_ip, ip address of peer node
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
up_delete_session_entry(pfcp_session_t *sess, pfcp_sess_del_rsp_t *sess_del_rsp, uint32_t cp_ip);

/**
 * @brief  : Process pfcp session deletion req at dp side
 * @param  : sess_del_req, hold pfcp session deletion req data
 * @param  : sess_del_rsp, response structure to be filled
 * @param  : cp_ip, ip address of peer node
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
process_up_session_deletion_req(pfcp_sess_del_req_t *sess_del_req,
			pfcp_sess_del_rsp_t *sess_del_rsp, uint32_t cp_ip);

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
* @param  : cp_seid, seid of CP
* @param  : up_seid, seid of UP
* @return : Returns pointer of peerEntry
*/
peerEntry *
fill_timer_entry_usage_report(struct sockaddr_in *peer_addr, urr_info_t *urr, uint64_t cp_seid, uint64_t up_seid);


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
* @param  : up_seid, seid of UP
* @param  : trig, Trig point of  PFCP rep Req(VOL based or Time Based)
* @return : Returns 0 for succes and -1 failure
*/
int send_usage_report_req(urr_info_t *urr, uint64_t cp_seid, uint64_t up_seid, uint32_t trig);

/*
 * @brief  : fill duplicating parameter ie for user level packet copying or LI
 * @param  : far, pfcp create far
 * @param  : far_t, far data structure
 * @return : Returns 0 on success -1 on failure
 */
int
fill_li_duplicating_params(pfcp_create_far_ie_t *far, far_info_t *far_t, pfcp_session_t *sess);

/*
 * @brief  : fill update duplicating parameter ie for user level packet copying or LI
 * @param  : far, pfcp create far
 * @param  : far_t, far data structure
 * @return : Returns 0 on success -1 on failure
 */
int
fill_li_update_duplicating_param(pfcp_update_far_ie_t *far, far_info_t *far_t, pfcp_session_t *sess);


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


/*
 * @brief  : checks the cause id for pfd management
 * @param  : cause_id, will store cause value
 * @param  : offend_id, will store offend_id ,if offending id present
 * @return : Returns nothing
 */
void
check_cause_id_pfd_mgmt(pfcp_pfd_contents_ie_t *pfd_content, uint8_t **cause_id, int **offend_id);

/**
* @brief  :Extracts the pcc rules from rule table.
* @param  :ip, cp_ip
* @return :returns pointer of pcc rules if success else retuns null
*/
struct pcc_rules * get_pcc_rule(uint32_t ip);

/*
 * @brief  : process the rule msg for pfd management
 * @param  : pfd_context, contains info for rules.
 * @param  : msg_type, contains type of msg need to process
 * @param  : cp_ip, contains cp ip address
 * @return : Returns nothing
 */
void
process_rule_msg(pfcp_pfd_contents_ie_t *pfd_content, uint64_t msg_type, uint32_t cp_ip, uint16_t idx);

/*
 * @brief  : process pfd management request
 * @param  : cause_id, will store cause value
 * @param  : offend_id, will store offen_id value
 * @param  : cp_ip, contains cp ip address
 * @return : Returns nothing.
 */
void
process_up_pfd_mgmt_request(pfcp_pfd_mgmt_req_t *pfcp_pfd_mgmt_req, uint8_t *cause_id,
							int *offend_id, uint32_t cp_ip);

/*
 * @brief  : remove cdr entry using seq no
 *           when receive response from CP
 * @param  : seq_no, seq_no in response as a key
 * @param  : up_seid, up seid as a key
 * @return  : 0 on success, else -1
 */
int
remove_cdr_entry(uint32_t seq_no, uint64_t up_seid);

/*
 * @brief  : dump CDR from usage report in
 *           pfcp-sess-rpt-req message
 * @param  : usage_report, usage report in pfcp-sess-rpt-req msg
 * @param  : up_seid, user plane session id
 * @param  : trig, cause for record close
 * @param  : seq_no, seq_no in msg used as a key to store CDR
 * @return : 0 on success,else -1
 */
int
store_cdr_into_file_pfcp_sess_rpt_req(pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report,
													uint64_t  up_seid, uint32_t trig,
																	uint32_t seq_no);
/*
 * @brief  : generate & store CDR from usage report
 *           when restoration begins
 * @param  : usage_report, to fill usage info from urr_t
 * @param  : up_seid, user plane session id
 * @param  : trig, cause for record close
 * @param  : seq_no, seq_no in msg used as a key to store CDR
 * @return : 0 on success,else -1
 */
int
store_cdr_for_restoration(pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report,
											uint64_t  up_seid, uint32_t trig,
											uint32_t seq_no, uint32_t ue_ip_addr);


/*
 * @brief  : Maintain CDR related info
 */

typedef struct dp_cdr {

	uint64_t uplink_volume;
	uint64_t downlink_volume;
	uint64_t total_volume;

	uint32_t duration_value;
	uint32_t start_time;
	uint32_t end_time;
	uint32_t time_of_frst_pckt;
	uint32_t time_of_lst_pckt;

}cdr_t;

#endif /* PFCP_UP_SESS_H */
