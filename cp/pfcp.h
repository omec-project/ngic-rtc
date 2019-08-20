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
extern struct in_addr s11_mme_ip;
extern struct sockaddr_in s11_mme_sockaddr;

extern in_port_t s11_port;
extern struct sockaddr_in s11_sockaddr;

extern struct in_addr s5s8_ip;
extern in_port_t s5s8_port;
extern struct sockaddr_in s5s8_sockaddr;

extern struct sockaddr_in s5s8_recv_sockaddr;

extern in_port_t pfcp_port;
extern struct sockaddr_in pfcp_sockaddr;

extern in_port_t upf_pfcp_port;
extern struct sockaddr_in upf_pfcp_sockaddr;

#endif /* PFCP_H */
