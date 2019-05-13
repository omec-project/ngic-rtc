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

#ifndef PFCP_H
#define PFCP_H

/**
 * @file
 *
 * PFCP definitions and helper macros.
 *
 * GTP Message type definition and GTP header definition according to 3GPP
 * TS 29.274; as well as IE parsing helper functions/macros, and message
 * processing function declarations.
 *
 */

#include "pfcp_ies.h"
#include "cp.h"

#include <stddef.h>
#include <arpa/inet.h>



//MME
extern struct in_addr s11_mme_ip_arr[MAX_NUM_MME];
extern struct sockaddr_in s11_mme_sockaddr_arr[MAX_NUM_MME];

//SGWC S11
extern in_port_t s11_sgwc_port_arr[MAX_NUM_SGWC];
extern struct sockaddr_in s11_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//SGWC S5S8
extern struct in_addr s5s8_sgwc_ip_arr[MAX_NUM_SGWC];
extern in_port_t s5s8_sgwc_port_arr[MAX_NUM_SGWC];
extern struct sockaddr_in s5s8_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//SGWC PFCP
in_port_t pfcp_sgwc_port_arr[MAX_NUM_SGWC];
struct sockaddr_in pfcp_sgwc_sockaddr_arr[MAX_NUM_SGWC];

//PGWC S5S8
extern struct in_addr s5s8_pgwc_ip_arr[MAX_NUM_SGWC];
extern in_port_t s5s8_pgwc_port_arr[MAX_NUM_SGWC];
extern struct sockaddr_in s5s8_pgwc_sockaddr_arr[MAX_NUM_SGWC];

//PGWC PFCP
extern struct in_addr pfcp_pgwc_ip_arr[MAX_NUM_PGWC];
extern in_port_t pfcp_pgwc_port_arr[MAX_NUM_PGWC];
extern struct sockaddr_in pfcp_pgwc_sockaddr_arr[MAX_NUM_PGWC];

//SGWU PFCP
extern in_port_t pfcp_sgwu_port_arr[MAX_NUM_SGWU];
extern struct sockaddr_in pfcp_sgwu_sockaddr_arr[MAX_NUM_SGWU];

//PGWU PFCP
extern in_port_t pfcp_pgwu_port_arr[MAX_NUM_PGWU];
extern struct sockaddr_in pfcp_pgwu_sockaddr_arr[MAX_NUM_PGWU];

//SPGWU PFCP
extern in_port_t pfcp_spgwu_port_arr[MAX_NUM_SPGWU];
extern struct sockaddr_in pfcp_spgwu_sockaddr_arr[MAX_NUM_SPGWU];


#endif /* PFCP_H */
