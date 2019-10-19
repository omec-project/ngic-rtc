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

struct rte_hash *pfcp_cntxt_hash;

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

/*
 *   PFCP context information for PDR, QER, BAR and FAR.
 */
struct pfcp_cntxt {

}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/* Create a pfcp context hash table to maintain the PDR, QER, FAR and BAR information.*/
void
init_pfcp_cntxt_hash(void);

/*
 * Add pfcp context information in the table.
 */
uint8_t
add_pfcp_cntxt_entry(uint16_t rule_id, struct pfcp_cntxt *resp);

/*
 * Retrive pfcp context entry.
 */
uint8_t
get_pfcp_cntxt_entry(uint16_t rule_id, struct pfcp_cntxt **resp);

/*
 * Delete context entry from pfcp context table.
 */
uint8_t
del_pfcp_cntxt_entry(uint16_t rule_id);

/*
 * Generate the PDR ID [RULE ID]
 */
uint16_t
generate_pdr_id(void);

/*
 * Generate the BAR ID
 */
uint8_t
generate_bar_id(void);

/*
 * Generate the FAR ID
 */
uint32_t
generate_far_id(void);

/*
 * Generate the FAR ID in case of mbr.
 * This is placeholder function to ensure far id is same in csr and mbr
 */
uint32_t
generate_far_id_mbr(void);
/*
 * Generate the QER ID
 */
uint32_t
generate_qer_id(void);

#endif /* PFCP_H */
