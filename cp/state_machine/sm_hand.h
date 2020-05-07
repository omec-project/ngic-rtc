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
int process_default_handler(void *t1, void *t2);

/* Function */
/**
 * @brief  : Handles processing in case of error
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_error_occured_handler(void *t1, void *t2);

/* Function */
/**
 * @brief  : Handles processing of cca message
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int cca_msg_handler(void *t1 , void *t2);

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
 * @brief  : Handles processing of pfcp session modification response in case create bearer request
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_pfcp_sess_mod_resp_cbr_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create bearer response for pgwc
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_cbresp_handler(void *arg1, void *arg2);

/* Function */
/**
 * @brief  : Handles processing of create bearer response for sgwc
 * @param  : arg1, data contained in message
 * @param  : arg2, optional parameter
 * @return : Returns 0 in case of success , -1 otherwise
 */
int process_create_bearer_resp_handler(void *arg1, void *arg2);

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
int process_pfcp_sess_mod_resp_dbr_handler(void *data, void *unused_param);

/* Function */
int process_delete_bearer_request_handler(void *data, void *unused_param);

/* Function */
int process_delete_bearer_resp_handler(void *data, void *unused_param);

/* Function */
int process_pfcp_sess_del_resp_dbr_handler(void *data, void *unused_param);

/* Function */
int process_update_bearer_response_handler(void *arg1, void *arg2);

/* Function */
int process_update_bearer_request_handler(void *arg1, void *arg2);

/* Function */
int process_delete_bearer_command_handler(void *arg1, void *arg2);

/* Function */
int del_bearer_cmd_ccau_handler(void *arg1, void *arg2);

/* Function */
int process_delete_bearer_response_handler(void *arg1, void *arg2);

/* Function */
int del_bearer_cmd_mbr_resp_handler(void *arg1, void *arg2);

/* Function */
int process_delete_bearer_req_handler(void *arg1, void *arg2);

/* Function */
int process_pfcp_sess_mod_resp_ubr_handler(void *arg1, void *arg2);

/* Function */
int process_del_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
int process_s5s8_del_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
int process_del_pdn_conn_set_rsp(void *arg1, void *arg2);

/* Function */
int process_upd_pdn_conn_set_req(void *arg1, void *arg2);

/* Function */
int process_upd_pdn_conn_set_rsp(void *arg1, void *arg2);

/* Function */
int process_pgw_rstrt_notif_ack(void *arg1, void *arg2);

/* Function */
int process_pfcp_sess_set_del_req(void *arg1, void *arg2);

/* Function */
int process_pfcp_sess_set_del_rsp(void *arg1, void *arg2);

/* Function */
int cca_u_msg_handler_handover(void *arg1, void *argu2);

