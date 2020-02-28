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

#ifndef PFCP_UP_STRUCT_H
#define PFCP_UP_STRUCT_H

#include "pfcp_ies.h"
#include "pfcp_struct.h"

/**
 * ipv4 address format.
 */
#define IPV4_ADDR "%u.%u.%u.%u"
#define IPV4_ADDR_HOST_FORMAT(a)	(uint8_t)(((a) & 0xff000000) >> 24), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)((a) & 0x000000ff)
/* Interface type define */
#define ACCESS	0
#define CORE	1

#define MAX_BEARERS 15
#define MAX_LIST_SIZE 16
#define ACL_TABLE_NAME_LEN 16

typedef struct pfcp_session_t pfcp_session_t;
typedef struct pfcp_session_datat_t pfcp_session_datat_t;
typedef struct pdr_info_t pdr_info_t;
typedef struct qer_info_t qer_info_t;
typedef struct urr_info_t urr_info_t;
typedef struct predef_rules_t predef_rules_t;

/* rte hash for pfcp context
 * hash key: pfcp sess id, data:  pfcp_session_t
 */
struct rte_hash *sess_ctx_by_sessid_hash;

/* rte hash for session data by teid.
 * hash key: teid, data:  pfcp_session_datat_t
 * Usage:
 * 	1) SGW-U : UL & DL packet detection (Check packet against sdf rules defined in acl_table_name and get matching PDR ID.
 * 	2) PGW-U : UL packet detection (Check against UE IP address and sdf rules defined in acl_table_name and get matching PDR ID.)
 */
struct rte_hash *sess_by_teid_hash;

/* rte hash for session data by ue ip addr.
 * hash key: ue ip addr, data:  pfcp_session_datat_t
 * Usage:
 * 	PGW-U : DL packet detection ()
 */
struct rte_hash *sess_by_ueip_hash;

/* rte hash for pdr by pdr id.
 * hash key: pdr id, data:  pdr_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t)
 */
struct rte_hash *pdr_by_id_hash;


/* rte hash for far by far id.
 * hash key: far id, data:  far_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:far_info_t)
 */
struct rte_hash *far_by_id_hash;

/* rte hash for qer by qer id.
 * hash key: qer id, data:  qer_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:qer_info_t)
 */
struct rte_hash *qer_by_id_hash;

/* rte hash for urr data by urr id.
 * hash key: urr id, data:  urr_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:urr_info_t)
 */
struct rte_hash *urr_by_id_hash;

enum up_session_state { CONNECTED, IDLE, IN_PROGRESS };

typedef struct predef_rules_t {
	/* VS:TODO: Revist this part */
	uint8_t predef_rules_nm[8];

	/* TODO: Need to Discuss */
	predef_rules_t *next;
}predef_rules_t;

typedef struct far_frwdng_parms_t {
	ntwk_inst_t ntwk_inst;						/* Network Instance */
	dst_intfc_t dst_intfc;						/* Destination Interface */
	outer_hdr_creation_t outer_hdr_creation;			/* Outer Header Creation */
	trnspt_lvl_marking_t trnspt_lvl_marking;			/* Transport Level Marking */
	frwdng_plcy_t frwdng_plcy;					/* Forwarding policy */
	/* pfcpsmreq_flags [sndem]*/
	hdr_enrchmt_t hdr_enrchmt;					/* Container for header enrichment */
} far_frwdng_parms_t;

typedef struct far_info_t {
	uint32_t far_id_value;						/* FAR ID */
	apply_action actions;						/* Apply Action parameters */
	far_frwdng_parms_t frwdng_parms;				/* Forwarding paramneters */

	//pfcp_session_t *session;					/* Pointer to session */
	pfcp_session_datat_t *session;					/* Pointer to session */
}far_info_t;


typedef struct qer_info_t {
	uint32_t qer_id;						/* FAR ID */
	uint32_t qer_corr_id_val;					/* QER Correlation ID */
	gate_status_t gate_status;					/* Gate Status UL/DL */
	mbr_t max_bitrate;						/* Maximum Bitrate */
	gbr_t guaranteed_bitrate;					/* Guaranteed Bitrate */
	packet_rate_t packet_rate;					/* Packet Rate */
	dl_flow_lvl_marking_t dl_flow_lvl_marking;			/* Downlink Flow Level Marking */
	qfi_t qos_flow_ident;						/* QOS Flow Ident */
	rqi_t reflective_qos;						/* RQI */
	paging_plcy_indctr_t paging_plcy_indctr;			/* Paging policy */
	avgng_wnd_t avgng_wnd;						/* Averaging Window */

	//pfcp_session_t *session;					/* Pointer to session */
	pfcp_session_datat_t *session;					/* Pointer to session */

	qer_info_t *next;
}qer_info_t;

typedef struct bar_info_t {
	uint8_t bar_id;				/* BAR ID */
	dnlnk_data_notif_delay_t ddn_delay;
	suggstd_buf_pckts_cnt_t suggstd_buf_pckts_cnt;
}bar_info_t;

/*VS:TODO: Revisit this part and update it. */
typedef struct urr_info_t {
	/* TODO: Add members */
	uint32_t urr_id;							/* URR ID */

	urr_info_t *next;
}urr_info_t;

typedef struct pdr_info_t {
	/* VS: Need to remove PDR ID or not */
	uint16_t rule_id;							/* PDR ID*/
	uint32_t prcdnc_val;							/* Precedence Value*/

	far_info_t *far;

	pdi_t pdi;								/* Packet Detection Information */
	outer_hdr_removal_t outer_hdr_removal;					/* Outer Header Removal */

	uint8_t qer_count;							/* Number of QER */
	qer_info_t *quer;							/* Collection of QER IDs */

	uint8_t urr_count;							/* Number of URR */
	urr_info_t *urr;							/* Collection of URR IDs */

	uint8_t predef_rules_count;						/* Number of predefine rules */
	predef_rules_t *predef_rules;						/* Collection of active predefined rules */

	/* Need to discuss on it: DDN*/
	pfcp_session_t *session;						/* Pointer to session */

	pdr_info_t *next;
}pdr_info_t;

typedef struct pfcp_session_datat_t {

	uint32_t ue_ip_addr;
	char acl_table_name[ACL_TABLE_NAME_LEN];
	int acl_table_indx;

	pdr_info_t *pdrs;
	//VS:TODO:NEED TO THINK ON IT
	/** Session state for use with downlink data processing*/
	enum up_session_state sess_state;

	/** Ring to hold the DL pkts for this session */
	struct rte_ring *dl_ring;
	//enum sess_pkt_action action;

	struct pfcp_session_datat_t *next;
} pfcp_session_datat_t;

typedef struct pfcp_session_t {
	uint64_t cp_seid;
	uint64_t up_seid;

	uint8_t ber_cnt;
	uint32_t teids[MAX_BEARERS];
	pfcp_session_datat_t *sessions;
} pfcp_session_t;

/**
 * Add session entry in session context hash table.
 *
 * @param up_sess_id
 * key.
 * @param pfcp_session_t sess_cntxt
 * return 0 or 1.
 *
 */
int8_t
add_sess_info_entry(uint64_t up_sess_id, pfcp_session_t *sess_cntxt);

/**
 * Get UP Session entry from session hash table.
 *
 * @param UP SESS ID
 * key.
 * return pfcp_session_t sess_cntxt or NULL
 *
 */

pfcp_session_t *
get_sess_info_entry(uint64_t up_sess_id, uint8_t is_mod);

/**
 * Delete Session entry from Session hash table.
 *
 * @param UP SESS ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_info_entry(uint64_t up_sess_id);

/**
 * Add session data entry based on teid in session data hash table.
 *
 * @param teid
 * key.
 * @param pfcp_session_datat_t sess_cntxt
 * return 0 or 1.
 *
 */
int8_t
add_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t *sess_cntxt);

/**
 * Get Session entry by teid from session hash table.
 *
 * @param teid
 * key.
 * @param pfcp_session_datat_t head
 * head pointer 
 * return pfcp_session_t sess_cntxt or NULL
 *
 */

pfcp_session_datat_t *
get_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t **head, uint8_t is_mod);

/**
 * Delete Session entry by teid from Session hash table.
 *
 * @param teid
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_by_teid_entry(uint32_t teid);

/**
 * Add session data entry based on UE IP in session data hash table.
 *
 * @param UE_IP
 * key.
 * @param pfcp_session_datat_t sess_cntxt
 * return 0 or 1.
 *
 */
int8_t
add_sess_by_ueip_entry(uint32_t ue_ip, pfcp_session_datat_t **sess_cntxt);

/**
 * Get Session entry by UE_IP from session hash table.
 *
 * @param UE_IP
 * key.
 * return pfcp_session_t sess_cntxt or NULL
 *
 */
pfcp_session_datat_t *
get_sess_by_ueip_entry(uint32_t ue_ip, pfcp_session_datat_t **head, uint8_t is_mod);

/**
 * Delete Session entry by UE_IP from Session hash table.
 *
 * @param UE_IP
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_sess_by_ueip_entry(uint32_t ue_ip);

/**
 * Add PDR entry in PDR hash table.
 *
 * @param rule_id/PDR_ID
 * key.
 * @param pdr_info_t pdr
 * return 0 or 1.
 *
 */
int8_t
add_pdr_info_entry(uint16_t rule_id, pdr_info_t *pdr);

/**
 * Get PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * @param pdr_info_t *head
 * head pointer 
 * return pdr_info_t pdr or NULL
 *
 */
pdr_info_t *
get_pdr_info_entry(uint16_t rule_id, pdr_info_t **head);

/**
 * Delete PDR entry from PDR hash table.
 *
 * @param PDR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_pdr_info_entry(uint16_t rule_id);

/**
 * Add FAR entry in FAR hash table.
 *
 * @param FAR_ID
 * key.
 * @param far_info_t far
 * return 0 or 1.
 *
 */
int8_t
add_far_info_entry(uint16_t far_id, far_info_t **far);

/**
 * Get FAR entry from FAR hash table.
 *
 * @param FAR ID
 * key.
 * return far_info_t pdr or NULL
 *
 */
far_info_t *
get_far_info_entry(uint16_t far_id);

/**
 * Delete FAR entry from FAR hash table.
 *
 * @param FAR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_far_info_entry(uint16_t far_id);

/**
 * Add QER entry in QER hash table.
 *
 * @param qer_id
 * key.
 * @param qer_info_t context
 * return 0 or 1.
 *
 */
int8_t
add_qer_info_entry(uint32_t qer_id, qer_info_t **cntxt);

/**
 * Get QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return qer_info_t cntxt or NULL
 *
 */
qer_info_t *
get_qer_info_entry(uint32_t qer_id, qer_info_t **head);

/**
 * Delete QER entry from QER hash table.
 *
 * @param QER ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_qer_info_entry(uint32_t qer_id);

/**
 * Add URR entry in URR hash table.
 *
 * @param urr_id
 * key.
 * @param urr_info_t context
 * return 0 or 1.
 *
 */
int8_t
add_urr_info_entry(uint32_t urr_id, urr_info_t **cntxt);

/**
 * Get URR entry from urr hash table.
 *
 * @param URR ID
 * key.
 * return urr_info_t cntxt or NULL
 *
 */
urr_info_t *
get_urr_info_entry(uint32_t urr_id);

/**
 * Delete URR entry from URR hash table.
 *
 * @param URR ID
 * key.
 * return 0 or 1.
 *
 */
int8_t
del_urr_info_entry(uint32_t urr_id);

/**
 * @brief Initializes the pfcp context hash table used to account for
 * PDR, QER, BAR and FAR rules information tables and Session tables based on sessid, teid and UE_IP.
 */
void
init_up_hash_tables(void);

/**
 * Generate the SESSION ID
 */
uint64_t
gen_up_sess_id(uint64_t cp_sess_id);
#endif /* PFCP_UP_STRUCT_H */
