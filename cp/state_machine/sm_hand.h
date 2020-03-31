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
int association_setup_handler(void *arg1, void *arg2);

/* Function */
int process_assoc_resp_handler(void *arg1, void *arg2);

/* Function */
int process_cs_resp_handler(void *arg1, void *arg2);

/* Function */
int process_sess_est_resp_handler(void *arg1, void *arg2);

/* Function */
int process_mb_req_handler(void *arg1, void *arg2);

/* Function */
int process_rel_access_ber_req_handler(void *arg1, void *arg2);

/* Function */
int process_sess_mod_resp_handler(void *arg1, void *arg2);

/* Function */
int process_ds_req_handler(void *arg1, void *arg2);

/* Function */
int process_sess_del_resp_handler(void *arg1, void *arg2);

/* Function */
int process_ds_resp_handler(void *arg1, void *arg2);

/* Function */
int process_ddn_ack_resp_handler(void *arg1, void *arg2);

/* Function */
int process_rpt_req_handler(void *arg1, void *arg2);

/* Function */
int process_default_handler(void *t1, void *t2);


/* Function */
int process_error_occured_handler(void *t1, void *t2);

/* Function */
int cca_msg_handler(void *t1 , void *t2);

/* Function */
int gx_setup_handler(void *arg1, void *arg2);

/* Function */
int process_pfcp_sess_mod_resp_cbr_handler(void *arg1, void *arg2);

/* Function */
int process_cbresp_handler(void *arg1, void *arg2);

/* Function */
int process_create_bearer_resp_handler(void *arg1, void *arg2);

/* Function */
int process_create_bearer_request_handler(void *arg1, void *arg2);

/* Function */
int process_rar_request_handler(void *arg1, void *arg2);

/* Function */
int pfd_management_handler(void *arg1, void *arg2);

/* Function */
int process_mod_resp_delete_handler(void *arg1, void *arg2);

/* Function */
int process_sess_mod_resp_sgw_reloc_handler(void *arg1, void *arg2);

/* Function */
int process_sess_est_resp_sgw_reloc_handler(void *arg1, void *arg2);

/* Function */
int process_mb_req_sgw_reloc_handler(void *arg1, void *arg2);

int process_mbr_resp_handover_handler(void *arg1, void *arg2);

int process_sess_del_resp_handover_handler(void *arg1, void *arg2);

/* Function */
int cca_t_msg_handler(void *arg1, void *arg2);
