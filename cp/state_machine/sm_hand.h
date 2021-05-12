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

#include <stdio.h>
#include "sm_enum.h"
#include "cp_app.h"

/* Function */
/**
 * @brief  : Handles association setuo request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int association_setup_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfcp association response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_assoc_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create session response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_cs_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfcp session establishment response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_est_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mb_req_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of modify bearer request for modification procedure
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mb_req_for_mod_proc_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of pfcp session modification response for
 *           modification sent in li scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_mod_resp_li_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of release access bearer request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_rel_access_ber_req_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfcp session modification response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_mod_resp_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of pfcp session modification response for modification procedure
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mod_resp_for_mod_proc_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of delete session request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_ds_req_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of change notification request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_change_noti_req_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfcp session delete response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_del_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of delete session response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_ds_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of ddn acknowledge response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_ddn_ack_resp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of report request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_rpt_req_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Default handler
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_default_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing in case of error
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_error_occured_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing in case of create bearer error
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_cbr_error_occured_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing in case of ue req resource mod flow error
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_bearer_resource_cmd_error_handler(void *t1, void *t2);

/* Function */
/**
 * @brief  : Handles processing of cca message
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_dbr_error_occured_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of cca message
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int cca_msg_handler(void *arg1 , void *arg2);

/* Function */
/**
 * @brief  : Handles create session request if gx is enabled
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int gx_setup_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfcp session modification response in case bearer resource command
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_mod_resp_brc_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles provision ack CCA-U message
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int provision_ack_ccau_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create bearer response for pgwc
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_mod_resp_cbr_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create bearer response for sgwc
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_create_bearer_response_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create bearer request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_create_bearer_request_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of rar request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_rar_request_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of pfd management request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int pfd_management_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modification response received in case of delete request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mod_resp_delete_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of session modification response received in case of sgw relocation
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_mod_resp_sgw_reloc_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of session establishment response received in case of sgw relocation
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_est_resp_sgw_reloc_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer request received in case of sgw relocation
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mb_req_sgw_reloc_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of modify bearer response in handover scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mbr_resp_handover_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of modify bearer response for modification procedure
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mbr_resp_for_mod_proc_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of pfcp session delete response in handover scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_del_resp_handover_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of cca-t message
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int cca_t_msg_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : data, data contained in message
 * @param  : unused_param, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_mod_resp_dbr_handler(void *data, void *unused_param);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : data, data contained in message
 * @param  : unused_param, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_delete_bearer_request_handler(void *data, void *unused_param);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : data, data contained in message
 * @param  : unused_param, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_delete_bearer_resp_handler(void *data, void *unused_param);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : data, data contained in message
 * @param  : unused_param, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_del_resp_dbr_handler(void *data, void *unused_param);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_update_bearer_response_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_update_bearer_request_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_delete_bearer_command_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of bearer resource command
 * @param  : arg1, data contained in message (BRC)
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_bearer_resource_command_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of delete bearer cmd cca msg
 * @param  : arg1, data contained in message (BRC)
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int del_bearer_cmd_ccau_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : data, data contained in message
 * @param  : unused_param, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int provision_ack_ccau_handler(void *data, void *unused_param);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_mod_resp_ubr_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_del_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_s5s8_del_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_del_pdn_conn_set_rsp(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_upd_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_upd_pdn_conn_set_rsp(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pgw_rstrt_notif_ack(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_set_del_req(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_set_del_rsp(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : argu2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int cca_u_msg_handler(void *arg1, void *argu2);

/**
 * @brief  : Handles processing of modify bearer response
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_mb_resp_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles processing of session establishment if there's
 * creation of deciated bearer with deafult scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sess_est_resp_dedicated_handler(void *arg1, void  *arg2);

/**
 * @brief  : Handles processing of create session response if there's
 * creation of deciated bearer with deafult scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_cs_resp_dedicated_handler(void *arg1, void  *arg2);

/**
 * @brief  : Handles processing of session modification response while there's
 * creation of deciated bearer with deafult scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_mod_resp_cs_dedicated_handler(void *arg1, void  *arg2);


/**
 * @brief  : Handles processing of mbr request and create bearer response
 * while there's deciated bearer with deafult scenario
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_mb_request_cb_resp_handler(void *arg1, void *arg2);

/**
 * @brief  : Handles the processing of change notification
 *           response message received
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_change_noti_resp_handler(void *arg1, void *argu2);

/**
 * @brief  : Handles the processing of Pfcp Association setup response,
 *			 in Recovery mode.
 * @param  : arg1, data contained in message
 * @param  : arg2, Peer node address
 * @return : Returns 0 in case of success , -1 otherwise
 */

int process_recov_asso_resp_handler(void *data, void *addr);

/**
 * @brief  : Handles the processing of pfcp estblishment
 *           response message received, in Recovery mode.
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_recov_est_resp_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of UPDATE PDN SET CONNECTION
 *           RESPONSE Message.
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_upd_pdn_set_response_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of PFCP SESS MOD RESPONSE
 *           Message, on Receiving the UPDATE PDN SET CONN REQ.
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_mod_resp_upd_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of UPDATE PDN SET
 *           REQUEST  message received
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_update_pdn_set_req_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of modify bearer command
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_modify_bearer_command_handler(void *data, void *unused_param);
/**
 * @brief  : Handles the processing of pfcp session deletion response
 *           in case of context replacement message received
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_sess_del_resp_context_replacement_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of pfcp session deletion response
 *           in case of context replacement message received
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_create_indir_data_frwd_req_handler(void *data, void *unused_param);


/**
 * @brief  : Handles the processing of delete indirect tunnel request.
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_del_indirect_tunnel_req_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of PFCP Delete Response
 *           for delete indirect tunnel request.
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_pfcp_del_resp_del_indirect_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the processing of Modify ACCESS Bearer
 *           REQUEST  message received
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 *
 */
int
process_modify_access_bearer_handler(void *data, void *unused_param);

/* @brief  : Handles the ddn failure indication
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_ddn_failure_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the session modification response after dl_buffer_duration expires
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_sess_mod_resp_dl_buf_dur_handler(void *data, void *unused_param);

/**
 * @brief  : Handles the session modification response after ddn request failure
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
process_sess_mod_resp_ddn_fail_handler(void *data, void *unused_param);

