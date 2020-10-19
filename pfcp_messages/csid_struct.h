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

#ifdef CP_BUILD
#include "gtp_ies.h"
#endif /*CP_BUILD*/

#define ADD_NODE    0
#define UPDATE_NODE 1
#define REMOVE_NODE 2

/* Maximum possibility of the CSID per PDN connection */
#define MAX_CSID 15


/* Temp using this static value, later on need to implement linked list */
#define MAX_SESS_IDS 500

/**
 * @brief :
 * rte hash for local csid by peer node information data.
 * hash key: peer_node_info, data: CSID
 * Usage:
 *  1) SGW-C/U : Retrieve the local csids based on the peer nodes
 *  2) PGW-C/U : Retrieve the local csids based on the peer nodes
 */
struct rte_hash *csid_by_peer_node_hash;

/**
 * @brief :
 * rte hash for collection of peer node CSIDs by local CSID.
 * hash key: Local CSID, data: Peer node CSIDs
 */
struct rte_hash *peer_csids_by_csid_hash;

/**
 * @brief :
 * rte hash for session ids of CP/DP by local CSID.
 * hash key: csid, data: Session ids
 */
struct rte_hash *seids_by_csid_hash;

/**
 * @brief : Interface mapping tables
 * rte hash for collection of local csids by peer mme node address.
 * hash key: Node IP, data: Local CSIDs
 */
struct rte_hash *local_csids_by_node_addr_hash;

/**
 * @brief :
 * rte hash for collection of local csids by mme CSID.
 * hash key: MME CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_mmecsid_hash;

/**
 * @brief :
 * rte hash for collection of local csids by pgw CSID.
 * hash key: PGW CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_pgwcsid_hash;

/**
 * @brief :
 * rte hash for collection of local csids by sgw CSID
 * hash key: SGW CSID, data: Local CSIDs
 */
struct rte_hash *local_csids_by_sgwcsid_hash;

#ifdef CP_BUILD
/**
 * @brief : Collection of the associated peer node informations
 */
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
	/* eNB Address */
	uint32_t enodeb_ip; /* Optional for CP */
}csid_key;

typedef struct peer_node_addr {
	/* Node type */
	uint8_t node_type;
	/* Count of the peer node address */
	uint8_t node_cnt;
	/* Peer Node Address */
	uint32_t node_addr[MAX_CSID];
}node_addr_t;

#else
/**
 * @brief : Collection of the associated peer node informations
 */
typedef struct peer_node_info_t {
	/* S11 || Sx || S5/S8 IP Address */
	uint32_t cp_ip;
	/* eNB || Sx || S5/S8 IP Address */
	uint32_t up_ip;
	/* eNB/SGWU Address*/
	uint32_t wb_peer_ip;
	/* PGWU Address*/
	uint32_t eb_peer_ip;
}csid_key;
#endif /* CP_BUILD */

/**
 * @brief : Collection of the associated peer node CSIDs
 */
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


/**
 * @brief : Collection of the associated session ids informations with csid
 */
typedef struct sess_csid_info {
	/* Control-Plane session identifiers */
	uint64_t cp_seid;
	/* User-Plane session identifiers */
	uint64_t up_seid;
	/* Pointing to next seid linked list node */
	struct sess_csid_info *next;
}sess_csid;

/**
 * @brief : Assigned the local csid
 */
typedef struct csid_info {
	uint8_t num_csid;
	/* SGWC, SAEGWC, SGWU, SAEGWU, PGWC, and PGWU local csid */
	uint16_t local_csid[MAX_CSID];
	/* SGWC, PGWC and MME IP Address */
	uint32_t node_addr;
}csid_t;

/**
 * @brief : Key the local csid
 */
struct csid_info_t {
	/* SGWC, SAEGWC, SGWU, SAEGWU, PGWC, and PGWU local csid */
	uint16_t local_csid;
	/* SGWC, PGWC and MME IP Address */
	uint32_t node_addr;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/* typecast key struct */
typedef struct csid_info_t csid_key_t;


/**
 * @brief : FQ-CSID structure
 */
typedef struct fqcsid_info_t {
	uint8_t instance;
	uint8_t num_csid;
	/* SGWC and MME csid */
	uint16_t local_csid[MAX_CSID];
	/* SGWC and MME IP Address */
	uint32_t node_addr;
}fqcsid_t;

/**
 * @brief : Init the hash tables for FQ-CSIDs \
 */
int8_t
init_fqcsid_hash_tables(void);


				/********[ Hash table API's ]**********/

			/********[ csid_by_peer_node_hash ]*********/
/**
 * @brief  : Add csid entry in csid hash table.
 * @param  : struct peer_node_info csid_key.
 * @param  : csid
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
add_csid_entry(csid_key *key, uint16_t csid);

/**
 * @brief  : Get csid entry from csid hash table.
 * @param  : struct peer_node_info csid_key
 * @return : Returns csid on success , -1 otherwise.
 */
int16_t
get_csid_entry(csid_key *key);

/**
 * @brief  : Update csid key associated peer node with csid in csid hash table.
 * @param  : struct peer_node_info csid_key
 * @param  : struct peer_node_info csid_key
 * @return : Returns 0 on success , 1 otherwise.
 */
int16_t
update_csid_entry(csid_key *old_key, csid_key *new_key);

#ifdef CP_BUILD
/* Linked the Peer CSID with local CSID */
int8_t
link_gtpc_peer_csids(fqcsid_t *peer_fqcsid, fqcsid_t *local_fqcsid,
		uint8_t iface);

/**
 * @brief  : Fills pfcp sess set delete request for cp
 * @param  : pfcp_sess_set_del_req , structure to be filled
 * @param  : local_csids
 * @return : Returns nothing
 */
void
cp_fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids);

/**
 * @brief  : Process session establishment respone
 * @param  : fqcsid, fqcsid to be filled in context
 * @param  : context_fqcsid, fqcsid pointer of context structure
 * @return : Returns 0 on success, -1 otherwise
 */
int
add_fqcsid_entry(gtp_fqcsid_ie_t *fqcsid, fqcsid_t *context_fqcsid);

/**
 * @brief  : Compare the peer node information with exsting peer node entry.
 * @param  : struct peer_node_info peer1
 * @param  : struct peer_node_info peer
 * @return : Returns 0 on success , -1 otherwise.
 */
int8_t
compare_peer_info(csid_key *peer1, csid_key *peer2);
#else

/**
 * @brief  : Linked Peer Csid With Local Csid
 * @param  : Peer CSID
 * @param  : Local CSID
 * @param  : iface
 * @return : Returns 0 on success, -1 otherwise
 */
int8_t
link_peer_csid_with_local_csid(fqcsid_t *peer_fqcsid,
		fqcsid_t *local_fqcsid, uint8_t iface);

/**
 * @brief  : Linked Peer Csid With Local Csid
 * @param  : Peer CSID
 * @param  : Local Memory location to stored CSID
 * @return : Returns 0 on success, -1 otherwise
 */
int8_t
stored_recvd_peer_fqcsid(pfcp_fqcsid_ie_t *peer_fqcsid, fqcsid_t *local_fqcsid);

#endif /* CP_BUILD */

/**
 * @brief  : Delete csid entry from csid hash table.
 * @param  : struct peer_node_info csid_key
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
del_csid_entry(csid_key *key);


		/********[ peer_csids_by_csid_hash ]*********/

/**
 * @brief  : Add peer node csids entry in peer node csids hash table.
 * @param  : local_csid
 * @param  : struct fq_csid_info fq_csids
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
add_peer_csids_entry(uint16_t csid, fq_csids *csids);

/**
 * @brief  : Get peer node csids entry from peer node csids hash table.
 * @param  : local_csid
 * @return : Returns fq_csids on success , NULL otherwise.
 */
fq_csids*
get_peer_csids_entry(uint16_t csid);

/**
 * @brief  : Delete peer node csid entry from peer node csid hash table.
 * @param  : struct peer_node_info csid_key
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
del_peer_csids_entry(uint16_t csid);



			/********[ seids_by_csid_hash ]*********/
/**
 * @brief  : Add session ids entry in sess csid hash table.
 * @param  : csid
 * @param  : struct sess_csid_info sess_csid
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
add_sess_csid_entry(uint16_t csid, sess_csid *seids);

/**
 * @brief  : Get session ids entry from sess csid hash table.
 * @param  : local_csid
 * @param  : mode [add , update , remove ]
 * @return : Returns sess_csid on success , NULL otherwise.
 */
sess_csid*
get_sess_csid_entry(uint16_t csid, uint8_t is_mod);

/**
 * @brief  : Delete session ids entry from sess csid hash table.
 * @param  : local_csid
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
del_sess_csid_entry(uint16_t csid);


/**
 * @brief  : Add local csid entry by peer csid in peer csid hash table.
 * @param  : csid_t peer_csid_key
 * @param  : csid_t local_csid
 * @param  : ifce S11/Sx/S5S8
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
add_peer_csid_entry(csid_key_t *key, csid_t *csid, uint8_t iface);

/**
 * @brief  : Get local csid entry by peer csid from csid hash table.
 * @param  : csid_t csid_key
 * @param  : iface
 * @return : Returns 0 on success , -1 otherwise.
 */
csid_t*
get_peer_csid_entry(csid_key_t *key, uint8_t iface);

/**
 * @brief  : Delete local csid entry by peer csid from csid hash table.
 * @param  : csid_t csid_key
 * @param  : iface
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
del_peer_csid_entry(csid_key_t *key, uint8_t iface);

/**
 * @brief  : Add peer node csids entry by peer node address in peer node csids hash table.
 * @param  : node address
 * @param  : fqcsid_t csids
 * @param  : iface
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
add_peer_addr_csids_entry(uint32_t node_addr, fqcsid_t *csids);

/**
 * @brief  : Get peer node csids entry by peer node addr from peer node csids hash table.
 * @param  : node address
 * @return : Returns fqcsid_t on success , NULL otherwise.
 */
fqcsid_t*
get_peer_addr_csids_entry(uint32_t node_addr, uint8_t is_mod);

/**
 * @brief  : Delete peer node csid entry by peer node addr from peer node csid hash table.
 * @param  : node_address
 * @return : Returns 0 on success , 1 otherwise.
 */
int8_t
del_peer_addr_csids_entry(uint32_t node_addr);

/**
 * @brief  : In partial failure support initiate the Request to cleanup peer node sessions based on FQ-CSID
 * @param  : No param
 * @return : Returns 0 on success , -1 otherwise.
 */
int8_t
gen_gtpc_sess_deletion_req(void);

/**
 * @brief  : In partial failure support initiate the Request to cleanup peer node sessions based on FQ-CSID
 * @param  : No param
 * @return : Returns 0 on success , -1 otherwise.
 */
int8_t
gen_pfcp_sess_deletion_req(void);

/**
 * @brief  : Fills pfcp sess set delete request
 * @param  : pfcp_sess_set_del_req , structure to be filled
 * @param  : local_csids
 * @param  : iface
 * @return : Returns nothing
 */
void
fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids, uint8_t iface);

/**
 * @brief  : Create and Fill the FQ-CSIDs
 * @param  : fq_csid, structure to be filled
 * @param  : csids
 * @return : Returns nothing
 */
void
set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids);

/**
 * @brief  : Fill pfcp set deletion response
 * @param  : pfcp_del_resp, structure to be filled
 * @param  : Cause value
 * @param  : offending_id
 * @return : Returns nothing
 */
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_del_resp,
			uint8_t cause_val, int offending_id);

/**
 * @brief  : Delete entry for csid
 * @param  : peer_csids
 * @param  : local_csids
 * @param  : iface
 * @return : Returns 0 on success, -1 otherwise
 */
int8_t
del_csid_entry_hash(fqcsid_t *peer_csids,
			fqcsid_t *local_csids, uint8_t iface);

/* recovery function */
/**
 * @brief  : Function to re-create affected session with peer node
 * @param  : node_addr , node address
 * @param  : iface
 * @return : Returns 0 on success, -1 otherwise
 */
int
create_peer_node_sess(uint32_t node_addr, uint8_t iface);

/**
 * @brief  : Process association setup request
 * @param  : node_addr, node address
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_aasociation_setup_req(uint32_t node_addr);

/**
 * @brief  : Process association setup response
 * @param  : msg
 * @param  : peer_addr
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_asso_resp(void *msg, struct sockaddr_in *peer_addr);

/**
 * @brief  : Process session establishment respone
 * @param  : pfcp_sess_est_rsp
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_sess_est_resp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp);

#endif /* _CSID_STRUCT_H */
