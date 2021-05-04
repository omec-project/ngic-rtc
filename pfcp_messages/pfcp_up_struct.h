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

#ifndef PFCP_UP_STRUCT_H
#define PFCP_UP_STRUCT_H

#include <stdbool.h>
#include "pfcp_ies.h"
#include "pfcp_struct.h"
#include "vepc_cp_dp_api.h"
#include "../interface/interface.h"

#ifdef USE_CSID
#include "csid_struct.h"
#endif /* USE_CSID */

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
#define MAX_ACL_TABLES		1000
#define MAX_SDF_RULE_NUM	32
#define NAME_LEN			32

typedef struct pfcp_session_t pfcp_session_t;
typedef struct pfcp_session_datat_t pfcp_session_datat_t;
typedef struct pdr_info_t pdr_info_t;
typedef struct qer_info_t qer_info_t;
typedef struct urr_info_t urr_info_t;
typedef struct predef_rules_t predef_rules_t;

/**
 * @brief  : rte hash for pfcp context
 *           hash key: pfcp sess id, data:  pfcp_session_t
 */
struct rte_hash *sess_ctx_by_sessid_hash;

/**
 * @brief  : rte hash for session data by teid.
 * hash key: teid, data:  pfcp_session_datat_t
 * Usage:
 * 	1) SGW-U : UL & DL packet detection (Check packet against sdf rules defined in acl_table_name and get matching PDR ID.
 * 	2) PGW-U : UL packet detection (Check against UE IP address and sdf rules defined in acl_table_name and get matching PDR ID.)
 */
struct rte_hash *sess_by_teid_hash;

/**
 * @brief  : rte hash for session data by ue ip4 addr.
 * hash key: ue ip addr, data:  pfcp_session_datat_t
 * Usage:
 * 	PGW-U : DL packet detection ()
 */
struct rte_hash *sess_by_ueip_hash;

/**
 * @brief  : rte hash for pdr by pdr id.
 * hash key: pdr id, data:  pdr_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t)
 */
struct rte_hash *pdr_by_id_hash;


/**
 * @brief  : rte hash for far by far id.
 * hash key: far id, data:  far_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:far_info_t)
 */
struct rte_hash *far_by_id_hash;

/**
 * @brief  : rte hash for qer by qer id.
 * hash key: qer id, data:  qer_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:qer_info_t)
 */
struct rte_hash *qer_by_id_hash;

/**
 * @brief  : rte hash for urr data by urr id.
 * hash key: urr id, data:  urr_info_t (pointer to already allocated pfcp_session_datat_t:pdr_info_t:urr_info_t)
 */
struct rte_hash *urr_by_id_hash;

/**
 * @brief  : rte hash for timer data by urr id.
 * hash key: urr id, data:  peerData
 */
struct rte_hash *timer_by_id_hash;

/**
 * @brief  : rte hash for qer_id and rule name.
 * hash key: qer id, data: mtr_rule
 */
struct rte_hash *qer_rule_hash;

enum up_session_state { CONNECTED, IDLE, IN_PROGRESS };

/* Outer Header Removal/Creation */
enum outer_header_rvl_crt {
	GTPU_UDP_IPv4,
	GTPU_UDP_IPv6,
	UP_UDP_IPv4,
	UP_UDP_IPv6,
	NOT_SET_OUT_HDR_RVL_CRT
};

/* use both Ipv6 and Ipv4 IPs as key to store session data */
struct ue_ip {
	uint32_t ue_ipv4;
	uint8_t ue_ipv6[IPV6_ADDRESS_LEN];
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

typedef struct ue_ip ue_ip_t;


/**
 * @brief  : Maintains predefined rules list
 */
typedef struct predef_rules_t {
	uint8_t predef_rules_nm[RULE_NAME_LEN];

	/* TODO: Need to Discuss */
	predef_rules_t *next;
}predef_rules_t;

/**
 * @brief  : Maintains far related forwarding parameter info
 */
typedef struct far_frwdng_parms_t {
	ntwk_inst_t ntwk_inst;						/* Network Instance */
	dst_intfc_t dst_intfc;						/* Destination Interface */
	outer_hdr_creation_t outer_hdr_creation;			/* Outer Header Creation */
	trnspt_lvl_marking_t trnspt_lvl_marking;			/* Transport Level Marking */
	frwdng_plcy_t frwdng_plcy;					/* Forwarding policy */
	/* pfcpsmreq_flags [sndem]*/
	hdr_enrchmt_t hdr_enrchmt;					/* Container for header enrichment */
} far_frwdng_parms_t;

/**
 * @brief  : Maintains duplicating parameters
 */
typedef struct duplicating_parms_t {

	dst_intfc_t dst_intfc;
	outer_hdr_creation_t outer_hdr_creation;

}duplicating_parms_t;

/**
 * @brief  : Maintains li data
 */
typedef struct li_config_t {
	uint64_t id;
	uint8_t west_direction;
	uint8_t west_content;
	uint8_t east_direction;
	uint8_t east_content;
	uint8_t forward;
} li_config_t;

/**
 * @brief  : Maintains far related information
 */
typedef struct far_info_t {
	uint16_t pdr_count;							/*PDR using the FAR*/
	uint32_t far_id_value;						/* FAR ID */
	apply_action actions;						/* Apply Action parameters */
	far_frwdng_parms_t frwdng_parms;				/* Forwarding paramneters */

	uint8_t li_config_cnt;
	li_config_t li_config[MAX_LI_ENTRIES_PER_UE];			/* User Level Packet Copying configurations */

	uint32_t dup_parms_cnt;
	duplicating_parms_t dup_parms[MAX_LIST_SIZE];
	//pfcp_session_t *session;					/* Pointer to session */
	pfcp_session_datat_t *session;					/* Pointer to session */

	/* Mapping of FAR with BAR */
	uint8_t bar_id_value;
}far_info_t;


/**
 * @brief  : Maintains qer related information
 */
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

/**
 * @brief  : Maintains bar related information
 */
typedef struct bar_info_t {
	uint8_t bar_id;				/* BAR ID */
	dnlnk_data_notif_delay_t ddn_delay;
	suggstd_buf_pckts_cnt_t suggstd_buf_pckts_cnt;
	dl_buffering_suggested_packets_cnt_t dl_buf_suggstd_pckts_cnt;
}bar_info_t;

/**
 * @brief  : Maintains urr related information
 */
typedef struct urr_info_t {
	/* TODO: Add members */
	uint16_t pdr_count;							/*PDR using the URR*/
	uint32_t urr_id;							/* URR ID */
	uint32_t urr_seq_num;						/* URR seq num */
	uint16_t meas_method;                       /* Measurment Method */
	uint16_t rept_trigg;                        /* Reporting Trigger */
	uint32_t vol_thes_uplnk;                    /* Vol Threshold */
	uint32_t vol_thes_dwnlnk;                   /* Vol Threshold */
	uint32_t time_thes;                         /* Time Threshold */
	uint32_t uplnk_data;                        /* Uplink data usage */
	uint32_t dwnlnk_data;                       /* Downlink Data Usage */
	uint32_t start_time;                        /* Start Time */
	uint32_t end_time;                          /* End Time */
	uint32_t first_pkt_time;                    /* First Pkt Time */
	uint32_t last_pkt_time;                     /* Last Pkt Time */

	urr_info_t *next;
}urr_info_t;

/**
 * @brief  : Maintains pdr related information
 */
typedef struct pdr_info_t {
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
	predef_rules_t predef_rules[MAX_LIST_SIZE];						/* Collection of active predefined rules */

	/* Need to discuss on it: DDN*/
	pfcp_session_t *session;						/* Pointer to session */

	pdr_info_t *next;
}pdr_info_t;

/**
 * @brief  : Maintains pfcp session data related information
 */
typedef struct pfcp_session_datat_t
{
	uint8_t ipv4;
	uint8_t ipv6;
	/* UE Addr */
	uint32_t ue_ip_addr;
	uint8_t ue_ipv6_addr[IPV6_ADDRESS_LEN];
	/* West Bound eNB/SGWU Address*/
	node_address_t wb_peer_ip_addr;

	/* East Bound PGWU Address */
	node_address_t eb_peer_ip_addr;

	char acl_table_name[ACL_TABLE_NAME_LEN];
	int acl_table_indx[MAX_SDF_RULE_NUM];
	uint8_t acl_table_count;
	bool predef_rule;

	pdr_info_t *pdrs;
	/** Session state for use with downlink data processing*/
	enum up_session_state sess_state;

	/* Header Creation */
	enum outer_header_rvl_crt hdr_crt;
	/* Header Removal */
	enum outer_header_rvl_crt hdr_rvl;

	/** Ring to hold the DL pkts for this session */
	struct rte_ring *dl_ring;

	struct pfcp_session_datat_t *next;
} pfcp_session_datat_t;

/**
 * @brief  : Maintains sx li config
 */
typedef struct li_sx_config_t {
	uint64_t id;
	uint8_t sx;
	uint8_t forward;
} li_sx_config_t;

/**
 * @brief  : Maintains pfcp session related information
 */
typedef struct pfcp_session_t {
	uint64_t cp_seid;
	uint64_t up_seid;
	uint64_t imsi;

	/* TODO: Add the struct for peer_addr info*/
	peer_addr_t cp_ip;

	node_address_t cp_node_addr;
	uint8_t ber_cnt;
	uint32_t teids[MAX_BEARERS];

#ifdef USE_CSID
	/* West Bound eNB/SGWU FQ-CSID */
	fqcsid_t *wb_peer_fqcsid;
	/* East Bound PGWU FQ-CSID */
	fqcsid_t *eb_peer_fqcsid;
	/* MME FQ-CSID*/
	fqcsid_t *mme_fqcsid;
	/* SGW-C/SAEGW-C CSID */
	fqcsid_t *sgw_fqcsid;
	/* PGW-C FQ-CSID */
	fqcsid_t *pgw_fqcsid;
	/* SGW-U/PGW-U/SAEGW-U FQ-CSID */
	fqcsid_t *up_fqcsid;
#endif /* USE_REST */

	/* User Level Packet Copying Sx Configurations */
	uint8_t li_sx_config_cnt;
	li_sx_config_t li_sx_config[MAX_LI_ENTRIES_PER_UE];

	/* BAR ID Changes */
	bar_info_t bar;

	pfcp_session_datat_t *sessions;
} pfcp_session_t;


/**
 * @brief  : Maintains peer node address and type related information
 */
struct peer_ip_addr{
	uint8_t type;
	union{
		uint32_t ipv4_addr;
		uint8_t  ipv6_addr[IPV6_ADDRESS_LEN];
	}ip;
}__attribute__((packed));


/**
 * @brief  : Maintains information for hash key for rule
 */
typedef struct {
	struct peer_ip_addr cp_ip_addr;
	uint64_t cp_seid;
	uint32_t id;
}rule_key;

/**
 * @brief  : Add session entry in session context hash table.
 * @param  : up_sess_id , key
 * @param  : pfcp_session_t sess_cntxt
 * @return : 0 or 1.
 */
int8_t
add_sess_info_entry(uint64_t up_sess_id, pfcp_session_t *sess_cntxt);

/**
 * @brief  : Get UP Session entry from session hash table.
 * @param  : UP SESS ID  key.
 * @param  : is_mod
 * @return : pfcp_session_t sess_cntxt or NULL
 */

pfcp_session_t *
get_sess_info_entry(uint64_t up_sess_id, uint8_t is_mod);

/**
 * @brief  : Delete Session entry from Session hash table.
 * @param  : UP SESS ID, key.
 * @return : 0 or 1.
 */
int8_t
del_sess_info_entry(uint64_t up_sess_id);

/**
 * @brief  : Get Session entry by teid from session hash table.
 * @param  : teid, key.
 * @param  : pfcp_session_datat_t head, head pointer
 * @param  : is_mod
 * @return : pfcp_session_t sess_cntxt or NULL
 */

pfcp_session_datat_t *
get_sess_by_teid_entry(uint32_t teid, pfcp_session_datat_t **head, uint8_t is_mod);

/**
 * @brief  : Delete Session entry by teid from Session hash table.
 * @param  : teid, key.
 * @return : 0 or 1.
 */
int8_t
del_sess_by_teid_entry(uint32_t teid);

/**
 * @brief  : Get Session entry by UE_IP type V4 from session hash table.
 * @param  : UE_IP, key.
 * @param  : pfcp_session_datat_t head, head pointer
 * @param  : is_mod
 * @return : pfcp_session_t sess_cntxt or NULL
 */
pfcp_session_datat_t *
get_sess_by_ueip_entry(ue_ip_t ue_ip, pfcp_session_datat_t **head, uint8_t is_mod);

/**
 * @brief  : Delete Session entry by UE_IP from Session hash table.
 * @param  : UE_IP, key.
 * @return : 0 or 1.
 */
int8_t
del_sess_by_ueip_entry(ue_ip_t ue_ip);

/**
 * @brief  : Get PDR entry from PDR hash table.
 * @param  : PDR ID, key
 * @param  : pdr_info_t *head, head pointer
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : pdr_info_t pdr or NULL
 */
pdr_info_t *
get_pdr_info_entry(uint16_t rule_id,  pdr_info_t **head, uint16_t is_add,
								peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Delete PDR entry from PDR hash table.
 * @param  : PDR ID, key
 * @param  : peer_ip, ip address and type of peer node
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
del_pdr_info_entry(uint16_t rule_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Add FAR entry in FAR hash table.
 * @param  : FAR_ID, key
 * @param  : far_info_t far
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
add_far_info_entry(uint16_t far_id, far_info_t **far,
						peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Get FAR entry from FAR hash table.
 * @param  : FAR ID, key
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : far_info_t pdr or NULL
 */
far_info_t *
get_far_info_entry(uint16_t far_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Delete FAR entry from FAR hash table.
 * @param  : FAR ID, key.
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
del_far_info_entry(uint16_t far_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Add QER entry in QER hash table.
 * @param  : qer_id, key
 * @param  : qer_info_t context
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
add_qer_info_entry(uint32_t qer_id, qer_info_t **cntxt,
					peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Get QER entry from QER hash table.
 * @param  : QER ID, key.
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : qer_info_t cntxt or NULL
 */
qer_info_t *
get_qer_info_entry(uint32_t qer_id, qer_info_t **head,
					peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Delete QER entry from QER hash table.
 * @param  : QER ID, key
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
del_qer_info_entry(uint32_t qer_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Add URR entry in URR hash table.
 * @param  : urr_id, key
 * @param  : urr_info_t context
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
add_urr_info_entry(uint32_t urr_id, urr_info_t **cntxt,
					peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Get URR entry from urr hash table.
 * @param  : URR ID, key
 * @param  : cp_ip, peer node address
 * @param  : cp_seid, CP session ID of UE
 * @return : urr_info_t cntxt or NULL
 */
urr_info_t *
get_urr_info_entry(uint32_t urr_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Delete URR entry from URR hash table.
 * @param  : URR ID, key
 * @param  : cp_ip, ip address and type of peer node
 * @param  : cp_seid, CP session ID of UE
 * @return : 0 or 1.
 */
int8_t
del_urr_info_entry(uint32_t urr_id, peer_addr_t cp_ip, uint64_t cp_seid);

/**
 * @brief  : Initializes the pfcp context hash table used to account for
 *           PDR, QER, BAR and FAR rules information tables and Session tables based on sessid, teid and UE_IP.
 * @param  : No param
 * @return : Returns nothing
 */
void
init_up_hash_tables(void);

/**
 * @brief  : Generate the user plane SESSION ID
 * @param  : cp session id
 * @return : up session id
 */
uint64_t
gen_up_sess_id(uint64_t cp_sess_id);

/**
 * @brief  : Add entry for meter rule and qer_id
 * @param  : rule_name
 * @param  : qer_id
 * @return : Retuns 0 if success else -1
 */
qer_info_t *
add_rule_info_qer_hash(uint8_t *rule_name);

/**
 * @brief  : Allocates ring for buffering downlink packets
 *           Allocate downlink packet buffer ring from a set of
 *           rings from the ring container.
 * @param  : No param
 * @return : Returns rte_ring Allocated ring on success, NULL on failure
 */
struct
rte_ring *allocate_ring(unsigned int dl_ring_size);
#endif /* PFCP_UP_STRUCT_H */
