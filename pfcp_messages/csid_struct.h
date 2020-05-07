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

#ifndef _CSID_STRUCT_H
#define _CSID_STRUCT_H

#include "pfcp_messages.h"

#define ADD 1
#define MOD 0

/* Maximum possibility of the CSID per PDN connection */
#define MAX_CSID 15

/*TODO: Temp using this static value, later on need to implement linked list */
#define MAX_SESS_IDS 500

/* rte hash for local csid by peer node information data.
 * hash key: peer_node_info, data: CSID
 * Usage:
 *  1) SGW-C/U : Retrieve the local csids based on the peer nodes
 *  2) PGW-C/U : Retrieve the local csids based on the peer nodes
 */
struct rte_hash *csid_by_peer_node_hash;

/* rte hash for collection of peer node CSIDs by local CSID.
 * hash key: Local CSID, data: Peer node CSIDs
 */
struct rte_hash *peer_csids_by_csid_hash;

/* rte hash for session ids of CP/DP by local CSID.
 * hash key: csid, data: Session ids
 */
struct rte_hash *seids_by_csid_hash;

/* Interface mapping tables */
/* rte hash for collection of local csids by peer mme node address.
 * hash key: Node IP, data: Local CSIDs
 */
struct rte_hash *local_csids_by_node_addr_hash;

/* rte hash for collection of local csids by mme CSID.
 * hash key: MME CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_mmecsid_hash;

/* rte hash for collection of local csids by pgw CSID.
 * hash key: PGW CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_pgwcsid_hash;

/* rte hash for collection of local csids by sgw CSID
 * hash key: SGW CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_sgwcsid_hash;

/* Collection of the associated peer node informations */
typedef struct peer_node_info_t {
	/* MME IP Address */
	uint32_t mme_ip;
	/* S11 || Sx || S5/S8 IP Address */
	uint32_t sgwc_ip;
	/* eNB || Sx || S5/S8 IP Address */
	uint32_t sgwu_ip;
	/* Sx || S5/S8 IP Address */
	uint32_t pgwc_ip;
	/* Sx || S5/S8 IP Address */
	uint32_t pgwu_ip;
#ifdef CP_BUILD
	/* CP: eNB ID */
	uint32_t enodeb_id; /* Optional for UP */
#else
	/* Temp solution for multiple SGW and PGW */
	uint16_t peer_csid;
	/* UP: Used the enodeb ip address for peer node */
	uint32_t enodeb_ip; /* Optional for CP */
#endif /* CP_BUILD */
}csid_key;

/* Collection of the associated peer node CSIDs*/
typedef struct fq_csid_info {
	/* MME PDN connection set identifer */
	uint16_t mme_csid[MAX_CSID];
	/* SGWC/SAEGWC PDN connection set identifer */
	uint16_t sgwc_csid[MAX_CSID];
	/* SGWU/SAEGWU PDN connection set identifer */
	uint16_t sgwu_csid[MAX_CSID];
	/* PGWC PDN connection set identifer */
	uint16_t pgwc_csid[MAX_CSID];
	/* PGWU PDN connection set identifer */
	uint16_t pgwu_csid[MAX_CSID];
}fq_csids;

/* TODO: Implement the Linked List */
/* Collection of the associated session ids informations with csid*/
typedef struct sess_csid_info {
	/* Count the number of sessions are associated with peers */
	uint16_t seid_cnt;
	/* Control-Plane session identifiers */
	uint64_t cp_seid[MAX_SESS_IDS];
	/* User-Plane session identifiers */
	uint64_t up_seid[MAX_SESS_IDS];
}sess_csid;

/* Assigned the local csid */
typedef struct csid_info {
	/* SGWC, SAEGWC, SGWU, SAEGWU, PGWC, and PGWU local csid */
	uint16_t local_csid;
	/* SGWC, PGWC and MME IP Address */
	uint32_t node_addr;
}csid_t;

/* FQ-CSID structure*/
typedef struct fqcsid_info_t {
	uint8_t num_csid;
	/* SGWC and MME csid */
	uint16_t local_csid[MAX_CSID];
	/* SGWC and MME IP Address */
	uint32_t node_addr;
}fqcsid_t;

/* Init the hash tables for FQ-CSIDs */
int8_t
init_fqcsid_hash_tables(void);


				/********[ Hash table API's ]**********/

			/********[ csid_by_peer_node_hash ]*********/
/**
 * Add csid entry in csid hash table.
 *
 * @param struct peer_node_info csid_key
 * key.
 * @param csid
 * return 0 or 1.
 *
 */
int8_t
add_csid_entry(csid_key *key, uint16_t csid);

/**
 * Get csid entry from csid hash table.
 *
 * @param struct peer_node_info csid_key
 * key.
 * return csid or -1
 *
 */
int16_t
get_csid_entry(csid_key *key);

/**
 * Update csid key associated peer node with csid in csid hash table.
 *
 * @param struct peer_node_info csid_key
 * key.
 * @param struct peer_node_info csid_key
 * return 0 or 1.
 *
 */
int16_t
update_csid_entry(csid_key *old_key, csid_key *new_key);

/**
 * Compare the peer node information with exsting peer node entry.
 *
 * @param struct peer_node_info peer1
 * key.
 * @param struct peer_node_info peer
 * return 0 or -1.
 *
 */
int8_t
compare_peer_info(csid_key *peer1, csid_key *peer2);

/**
 * Delete csid entry from csid hash table.
 *
 * @param struct peer_node_info csid_key
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_csid_entry(csid_key *key);


		/********[ peer_csids_by_csid_hash ]*********/

/**
 * Add peer node csids entry in peer node csids hash table.
 *
 * @param local_csid
 * key.
 * @param struct fq_csid_info fq_csids
 * return 0 or 1.
 *
 */
int8_t
add_peer_csids_entry(uint16_t csid, fq_csids *csids);

/**
 * Get peer node csids entry from peer node csids hash table.
 *
 * @param local_csid
 * key.
 * return fq_csids or NULL
 *
 */
fq_csids*
get_peer_csids_entry(uint16_t csid);

/**
 * Delete peer node csid entry from peer node csid hash table.
 *
 * @param struct peer_node_info csid_key
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_peer_csids_entry(uint16_t csid);



			/********[ seids_by_csid_hash ]*********/
/**
 * Add session ids entry in sess csid hash table.
 *
 * @param csid
 * key.
 * @param struct sess_csid_info sess_csid
 * return 0 or 1.
 *
 */
int8_t
add_sess_csid_entry(uint16_t csid, sess_csid *seids);

/**
 * Get session ids entry from sess csid hash table.
 *
 * @param local_csid
 * key.
 * return sess_csid or NULL
 *
 */
sess_csid*
get_sess_csid_entry(uint16_t csid);

/**
 * Delete session ids entry from sess csid hash table.
 *
 * @param local_csid
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_csid_entry(uint16_t csid);


/**
 * Add local csid entry by peer csid in peer csid hash table.
 *
 * @param csid_t peer_csid_key
 * key.
 * @param csid_t local_csid
 * @param ifce S11/Sx/S5S8
 * return 0 or 1.
 *
 */
int8_t
add_peer_csid_entry(uint16_t *key, csid_t *csid, uint8_t iface);

/**
 * Get local csid entry by peer csid from csid hash table.
 *
 * @param csid_t csid_key
 * key.
 * @param iface
 * return csid or -1
 *
 */
csid_t*
get_peer_csid_entry(uint16_t *key, uint8_t iface);

/**
 * Delete local csid entry by peer csid from csid hash table.
 *
 * @param csid_t csid_key
 * key.
 * @param iface
 * return 0 or 1.
 *
 */
int8_t
del_peer_csid_entry(uint16_t *key, uint8_t iface);

/**
 * Add peer node csids entry by peer node address in peer node csids hash table.
 *
 * @param node address
 * key.
 * @param fqcsid_t csids
 * @param iface
 * return 0 or 1.
 *
 */
int8_t
add_peer_addr_csids_entry(uint32_t node_addr, fqcsid_t *csids);

/**
 * Get peer node csids entry by peer node addr from peer node csids hash table.
 *
 * @param node address
 * key.
 * return fqcsid_t or NULL
 *
 */
fqcsid_t*
get_peer_addr_csids_entry(uint32_t node_addr, uint8_t is_mod);

/**
 * Delete peer node csid entry by peer node addr from peer node csid hash table.
 *
 * @param node_address
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_peer_addr_csids_entry(uint32_t node_addr);

/* In partial failure support initiate the Request to cleanup peer node sessions based on FQ-CSID */
int8_t
gen_gtpc_sess_deletion_req(void);

/* In partial failure support initiate the Request to cleanup peer node sessions based on FQ-CSID */
int8_t
gen_pfcp_sess_deletion_req(void);

void
fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids, uint8_t iface);

void
set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids);

/* Fill PFCP SESSION SET SELETION RESPONSE */
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_del_resp,
			uint8_t cause_val, int offending_id);

int8_t
del_csid_entry_hash(fqcsid_t *peer_csids,
			fqcsid_t *local_csids, uint8_t iface);
#endif /* _CSID_STRUCT_H */
