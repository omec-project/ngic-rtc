/*
 * Copyright (c) 2017 Intel Corporation
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

#ifndef _CP_H_
#define _CP_H_

#include <pcap.h>
#include <byteswap.h>
#include <rte_version.h>
#include <stdbool.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "main.h"
#include "ue.h"
#include "teid.h"
#include "gw_adapter.h"
#ifdef USE_REST
#include "ngic_timer.h"
#endif /* USE_REST */

#if defined(CP_BUILD)
#include "gtp_messages.h"
#endif

#define SLEEP_TIME (100)
#define UPD_PARAM_HEADER_SIZE (4)

/* Define the Micros for hash table operations */
#define ADD_ENTRY    0
#define UPDATE_ENTRY 1
#define DELETE_ENTRY 2
#ifndef PERF_TEST
/** Temp. work around for support debug log level into DP, DPDK version 16.11.4 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
#undef RTE_LOG_LEVEL
#define RTE_LOG_LEVEL RTE_LOG_DEBUG
#define RTE_LOG_DP RTE_LOG
#elif (RTE_VER_YEAR >= 18) && (RTE_VER_MONTH >= 02)
#undef RTE_LOG_DP_LEVEL
#define RTE_LOG_DP_LEVEL RTE_LOG_DEBUG
#endif
#else /* Work around for skip LOG statements at compile time in DP, DPDK 16.11.4 and 18.02 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
#undef RTE_LOG_LEVEL
#define RTE_LOG_LEVEL RTE_LOG_WARNING
#define RTE_LOG_DP_LEVEL RTE_LOG_LEVEL
#define RTE_LOG_DP RTE_LOG
#elif (RTE_VER_YEAR >= 18) && (RTE_VER_MONTH >= 02)
#undef RTE_LOG_DP_LEVEL
#define RTE_LOG_DP_LEVEL RTE_LOG_WARNING
#endif
#endif /* PERF_TEST */

#ifdef SYNC_STATS
#include <time.h>
#define DEFAULT_STATS_PATH  "./logs/"
#define STATS_HASH_SIZE     (1 << 21)
#define ACK       1
#define RESPONSE  2

typedef long long int _timer_t;

#define GET_CURRENT_TS(now)                                             \
({                                                                            \
	struct timespec ts;                                                          \
	now = clock_gettime(CLOCK_REALTIME,&ts) ?                                    \
		-1 : (((_timer_t)ts.tv_sec) * 1000000000) + ((_timer_t)ts.tv_nsec);   \
	now;                                                                         \
})

#endif /* SYNC_STATS */

#define MAX_UPF					10

#define S11_INTFC				0
#define S5S8_INTFC				1

#define DNSCACHE_CONCURRENT		2
#define DNSCACHE_PERCENTAGE		70
#define DNSCACHE_INTERVAL		4000
#define DNS_PORT				53

#define PIGGYBACKED     (1)
#define NOT_PIGGYBACKED (0)

#define CAUSE_SOURCE_SET_TO_1  (1)
#define CAUSE_SOURCE_SET_TO_0  (0)


#define CANCEL_S1_HO_INDICATION 2

#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/**
 * ipv4 address format.
 */
#define IPV4_ADDR "%u.%u.%u.%u"
#define IPV4_ADDR_HOST_FORMAT(a)	(uint8_t)(((a) & 0xff000000) >> 24), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)((a) & 0x000000ff)

/**
 * Control-Plane rte logs.
 */
#define RTE_LOGTYPE_CP  RTE_LOGTYPE_USER1
/**
 * @file
 *
 * Control Plane specific declarations
 */

/*
 * Define type of Control Plane (CP)
 * SGWC - Serving GW Control Plane
 * PGWC - PDN GW Control Plane
 * SAEGWC - Combined SAEGW Control Plane
 */
enum cp_config {
	SGWC = 01,
	PGWC = 02,
	SAEGWC = 03,
};

/*
 * Define type of Control Plane (CP)
 * IPv4 only
 * IPv6 only
 * IPv4v6 (priority based) - but GW will assign only one IP on basis of priority
 * IPv4v6 (Dual Mode) - GW will assign both IPs to UE
 */
enum ip_type {
	IP_V4 = 00,
	IP_V6 = 01,
	IPV4V6_PRIORITY = 02,
	IPV4V6_DUAL = 03
};

enum ip_priority {
	IP_V4_PRIORITY = 0,
	IP_V6_PRIORITY = 1
};

enum charging_characteristics {
	HOME = 03,
	VISITING = 04,
	ROAMING = 05,
};

enum cdr_config_values {
	CDR_OFF = 00,
	CDR_ON = 01,
	SGW_CC_CHECK = 02,
};

enum ip_config_values {
	IP_MODE = 01,
	IP_TYPE = 03,
	IP_PRIORITY = 01
};

#ifdef SYNC_STATS
/**
 * @brief  : statstics struct of control plane
 */
struct sync_stats {
	uint64_t op_id;
	uint64_t session_id;
	uint64_t req_init_time;
	uint64_t ack_rcv_time;
	uint64_t resp_recv_time;
	uint64_t req_resp_diff;
	uint8_t type;
};

extern struct sync_stats stats_info;
extern _timer_t _init_time;
struct rte_hash *stats_hash;
extern uint64_t entries;
#endif /* SYNC_STATS */

/**
 * @brief  : core identifiers for control plane threads
 */
struct cp_params {
	unsigned stats_core_id;
#ifdef SIMU_CP
	unsigned simu_core_id;
#endif
};

/**
 * @brief  : Structure to downlink data notification ack information struct.
 */
typedef struct downlink_data_notification {
	ue_context *context;

	gtpv2c_ie *cause_ie;
	uint8_t *delay;
	/* todo! more to implement... see table 7.2.11.2-1
	 * 'recovery: this ie shall be included if contacting the peer
	 * for the first time'
	 */
	/* */
	uint16_t dl_buff_cnt;
	uint8_t dl_buff_duration;
}downlink_data_notification_t;

extern pcap_dumper_t *pcap_dumper;
extern pcap_t *pcap_reader;

extern int s11_fd;
extern int s11_fd_v6;
extern int s11_pcap_fd;
extern int s5s8_sgwc_fd;
extern int s5s8_pgwc_fd;
extern int pfcp_sgwc_fd ;
extern struct cp_params cp_params;
extern teid_info *upf_teid_info_head;
extern cp_configuration_t cp_configuration;

#if defined (SYNC_STATS) || defined (SDN_ODL_BUILD)
extern uint64_t op_id;
#endif /* SDN_ODL_BUILD */
/**
 * @brief  : creates and sends downlink data notification according to session
 *           identifier
 * @param  : session_id - session identifier pertaining to downlink data packets
 *           arrived at data plane
 * @return : 0 - indicates success, failure otherwise
 */
int
ddn_by_session_id(uint64_t session_id, pdr_ids *pfcp_pdr_id);

/**
 * @brief  : initializes data plane by creating and adding default entries to
 *           various tables including session, pcc, metering, etc
 * @param  : No param
 * @return : Returns Nothing
 */
void
initialize_tables_on_dp(void);

#ifdef CP_BUILD

/**
 * @brief  : sets delete bearer request
 * @param  : gtpv2c_tx, transmision buffer
 * @param  : sequence, sequence number
 * @param  : pdn, pointer of pdn_connection structure
 * @param  : linked_eps_bearer_id, default bearer id
 * @param  : pti,Proc Trans Identifier
 * @param  : ded_eps_bearer_ids, array of dedicated bearers
 * @param  : ded_bearer_counter, count of dedicated bearers
 * @return : nothing
 */
void
set_delete_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	pdn_connection *pdn, uint8_t linked_eps_bearer_id, uint8_t pti,
	uint8_t ded_eps_bearer_ids[], uint8_t ded_bearer_counter);

/**
 * @brief  : sets delete bearer response
 * @param  : gtpv2c_tx, transmision buffer
 * @param  : sequence, sequence number
 * @param  : linked_eps_bearer_id, default bearer id
 * @param  : ded_eps_bearer_ids, array of dedicated bearers
 * @param  : ded_bearer_counter, count of dedicated bearers
 * @param  : s5s8_pgw_gtpc_teid, teid value
 * @return : nothing
 */
void
set_delete_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	uint8_t linked_eps_bearer_id, uint8_t ded_eps_bearer_ids[],
	uint8_t ded_bearer_counter, uint32_t s5s8_pgw_gtpc_teid);


/**
 * @brief  : sets delete bearer command
 * @param  : del_bearer_cmd, pointer of del_bearer_cmd_t structure
 * @param  : pdn, pointer of pdn_connection structure
 * @param  : gtpv2c_tx, transmission buffer
 * @return : nothing
 */
void
set_delete_bearer_command(del_bearer_cmd_t *del_bearer_cmd, pdn_connection *pdn, gtpv2c_header_t *gtpv2c_tx);

/**
 * @brief  : Fill bearer resource command to forward to PGWC
 * @param  : bearer_rsrc_cmd, decoded message receive on s11
 * @param  : pdn, pdn connection of bearer
 * @param  : gtpv2c_tx,transmission buffer
 * @return : nothing
 *
 */
void
set_bearer_resource_command(bearer_rsrc_cmd_t *bearer_rsrc_cmd, pdn_connection *pdn,
								gtpv2c_header_t *gtpv2c_tx);
/**
 * @brief  : Fill modify bearer command to forward to PGWC
 * @param  : mod_bearer_cmd_t, modify bearer cmd structure
 * @param  : pdn, pdn connection of bearer
 * @param  : gtpv2c_tx,transmission buffer
 * @return : nothing
 *
 */
void
set_modify_bearer_command(mod_bearer_cmd_t *mod_bearer_cmd, pdn_connection *pdn,
								gtpv2c_header_t *gtpv2c_tx);
/**
 * @brief  : To Downlink data notification ack of user.
 * @param  : dp_id, table identifier.
 * @param  : ddn_ack, Downlink data notification ack information
 * @return : - 0 on success
 *           -1 on failure
 */
int
send_ddn_ack(struct dp_id dp_id,
			struct downlink_data_notification ddn_ack);

#endif 	/* CP_BUILD */

#ifdef SYNC_STATS
/**
 * @file
 * This file contains function prototypes of cp request and response
 * statstics with sync way.
 */

/**
 * @brief  : Open Statstics record file.
 * @param  : No param
 * @return : Returns nothing
 */
void
stats_init(void);

/**
 * @brief  : Maintain stats in hash table.
 * @param  : sync_stats, sync_stats information
 * @return : Returns nothing
 */
void
add_stats_entry(struct sync_stats *stats);

/**
 * @brief  : Update the resp and ack time in hash table.
 * @param  : key, key for lookup entry in hash table
 * @param  : type, Update ack_recv_time/resp_recv_time
 * @return : Returns nothing
 */
void
update_stats_entry(uint64_t key, uint8_t type);

/**
 * @brief  : Retrive entries from stats hash table
 * @param  : void
 * @return : Void
 */
void
retrive_stats_entry(void);

/**
 * @brief  : Export stats reports to file.
 * @param  : sync_stats, sync_stats information
 * @return : Void
 */
void
export_stats_report(struct sync_stats stats_info);

/**
 * @brief  : Close current stats file and redirects any remaining output to stderr
 * @param  : void
 * @return : Void
 */
void
close_stats(void);
#endif   /* SYNC_STATS */

/*PFCP Config file*/
#define STATIC_CP_FILE "../config/cp.cfg"

#define MAX_DP_SIZE   5
#define MAX_CP_SIZE   1
#define MAX_NUM_MME   5
#define MAX_NUM_SGWC  5
#define MAX_NUM_PGWC  5
#define MAX_NUM_SGWU  5
#define MAX_NUM_PGWU  5
#define MAX_NUM_SAEGWU 5

#define MAX_NUM_APN   16

#define MAX_NUM_NAMESERVER 8

#define SGWU_PFCP_PORT   8805
#define PGWU_PFCP_PORT   8805
#define SAEGWU_PFCP_PORT   8805
#define REDIS_CERT_PATH_LEN  256

/**
 * @brief  : Maintains dns cache information
 */
typedef struct dns_cache_params_t {
	uint32_t concurrent;
	uint32_t sec;
	uint8_t percent;

	unsigned long timeoutms;
	uint32_t tries;
} dns_cache_params_t;

/**
 * @brief  : Maintains dns configuration
 */
typedef struct dns_config_t {
	uint8_t freq_sec;
	char filename[PATH_MAX];
	uint8_t nameserver_cnt;
	char nameserver_ip[MAX_NUM_NAMESERVER][IPV6_STR_LEN];
} dns_config_t;

/**
 * @brief  : Maintains pfcp configuration
 */
typedef struct pfcp_config_t {
	/* CP Configuration : SGWC=01; PGWC=02; SAEGWC=03 */
	uint8_t cp_type;

	char dadmf_local_addr[IPV6_STR_LEN];

	/* Control-Plane IPs and Ports Params. */
	uint16_t s11_port;
	uint16_t s5s8_port;
	uint16_t pfcp_port;
	uint16_t dadmf_port;
	uint16_t ddf2_port;
	struct in_addr s11_ip;
	struct in_addr s5s8_ip;
	struct in_addr pfcp_ip;
	char dadmf_ip[IPV6_STR_LEN];
	char ddf2_ip[IPV6_STR_LEN];
	char ddf2_local_ip[IPV6_STR_LEN];
	struct in6_addr s11_ip_v6;
	struct in6_addr s5s8_ip_v6;
	struct in6_addr pfcp_ip_v6;

	/*IP Type parameters for S11, S5S8,
	 * PFCP Interfaces and redis connection*/
	uint8_t s11_ip_type;
	uint8_t s5s8_ip_type;
	uint8_t pfcp_ip_type;
	uint8_t upf_pfcp_ip_type;
	uint8_t redis_server_ip_type;
	uint8_t cp_redis_ip_type;
	uint8_t cp_dns_ip_type;

	/* User-Plane IPs and Ports Params. */
	uint16_t upf_pfcp_port;
	struct in_addr upf_pfcp_ip;
	struct in6_addr upf_pfcp_ip_v6;

	/*Redis server config*/
	uint16_t redis_port;
	char redis_cert_path[REDIS_CERT_PATH_LEN];

	/*Store both ipv4 and ipv6 address*/
	char redis_ip_buff[IPV6_STR_LEN];
	char cp_redis_ip_buff[IPV6_STR_LEN];

	/* RESTORATION PARAMETERS */
	uint8_t transmit_cnt;
	int transmit_timer;
	int periodic_timer;

	/* CP Timer Parameters */
	uint8_t request_tries;
	int request_timeout;    /* Request time out in milisecond */

	uint8_t use_dns;        /*enable or disable dns query*/
	/* Store both ipv4 and ipv6 address*/
	char cp_dns_ip_buff[IPV6_STR_LEN];

	uint16_t cli_rest_port;
	char cli_rest_ip_buff[IPV6_STR_LEN];

	uint8_t use_gx;        /*enable or disable gx interface*/

	uint8_t ip_allocation_mode;  /*static or dynamic mode for IP allocation*/
	uint8_t ip_type_supported;   /*static or dynamic mode for IP allocation*/
	uint8_t ip_type_priority;    /*IPv6 or IPv4 priority type */

	/* APN */
	uint32_t num_apn;
	/* apn apn_list[MAX_NUM_APN]; */

	/*Default URR configuration*/
	int trigger_type;
	int uplink_volume_th;
	int downlink_volume_th;
	int time_th;

	dns_cache_params_t dns_cache;
	dns_config_t ops_dns;
	dns_config_t app_dns;

	/* IP_POOL_CONFIG Params */
	struct in_addr ip_pool_ip;
	struct in_addr ip_pool_mask;
	struct in6_addr ipv6_network_id;
	uint8_t ipv6_prefix_len;

	/* CP CDR generation Parameter */
	uint8_t generate_cdr;
	uint8_t generate_sgw_cdr;
	uint16_t sgw_cc;

	/* ADD_DEFAULT_RULE */
	uint8_t add_default_rule;

	/* Network Trigger Service Request Parameters */
	uint16_t dl_buf_suggested_pkt_cnt;
	uint16_t low_lvl_arp_priority;

	/* gx pcrf server ip */
	peer_addr_t gx_ip;

} pfcp_config_t;

/**
 * @brief  : Initialize pfcp interface details
 * @param  : void
 * @return : Void
 */
void
init_pfcp(void);

/**
 * @brief  : Initializes Control Plane data structures, packet filters, and calls for the
 *           Data Plane to create required tables
 * @param  : void
 * @return : Void
 */
void
init_cp(void);

/**
 * @brief  : Initializes redis node to send generated CDR
 * @param  : void
 * @return : 0 on success, -1 on failure
 */
int
init_redis(void);


/**
 * @brief  : Initialize dp rule table
 * @param  : void
 * @return : Void
 */
void
init_dp_rule_tables(void);

#ifdef SYNC_STATS
/**
 * @brief  : Initialize statistics hash table
 * @param  : void
 * @return : Void
 */
void
init_stats_hash(void);
#endif /* SYNC_STATS */

/**
 * @brief  : Function yet to be implemented
 * @param  : void
 * @return : Void
 */
void received_create_session_request(void);

#ifdef USE_CSID
/**
 * @brief  : Function to peer node address and generate unique csid identifier
 * @param  : pdn_connection, pdn connection info
 * @param  : eps_bearer, bearer info
 * @return : 0: Success, -1: otherwise
 */
int
fill_peer_node_info(pdn_connection *pdn, eps_bearer *bearer);

/**
 * @brief  : Function to Fill the FQ-CSID values in session est request
 * @param  : pfcp_sess_estab_req_t, Session Est Req obj
 * @param  : pdn_connection, pdn connection info
 * @return : 0: Success, -1: otherwise
 */
int8_t
fill_fqcsid_sess_est_req(pfcp_sess_estab_req_t *pfcp_sess_est_req, pdn_connection *pdn);

/**
 * @brief  : Function to Fill the FQ-CSID values in session modification request
 * @param  : pfcp_sess_mod_req_t
 * @param  : pdn_connection, pdn connection info
 * @return : 0: Success, -1: otherwise
 */
int8_t
fill_fqcsid_sess_mod_req(pfcp_sess_mod_req_t *pfcp_sess_mod_req, pdn_connection *pdn);

/**
 * @brief  : Function to Cleanup Session information by local csid
 * @param  : node_addr, peer node IP Address
 * @param  : iface, interface info
 * @return : 0: Success, -1: otherwise
 */
int8_t
del_peer_node_sess(node_address_t *node_addr, uint8_t iface);

/**
 * @brief  : Function to Cleanup Session information by local csid
 * @param  : node_addr, peer node IP Address
 * @param  : iface, interface info
 * @return : 0: Success, -1: otherwise
 */
int8_t
del_pfcp_peer_node_sess(node_address_t *node_addr, uint8_t iface);

/**
 * @brief  : Function to fill fqcsid into gtpv2c messages
 * @param  : fqcsid, gtpv2c fqcsid ie
 * @param  : ie_instance, info of instance
 * @param  : csids, csids info
 * @return : Nothing
 */
void
set_gtpc_fqcsid_t(gtp_fqcsid_ie_t *fqcsid,
		enum ie_instance instance, fqcsid_t *csids);

/**
 * @brief  : Function to fill PGW restart notification message
 * @param  : gtpv2c_tx, message
 * @param  : s11_sgw, SGW S11 interface IP Address
 * @param  : s5s8_pgw, PGW S5S8 interface IP Address
 * @return : 0: Success, -1: otherwise
 */
int8_t
fill_pgw_restart_notification(gtpv2c_header_t *gtpv2c_tx,
		node_address_t *s11_sgw, node_address_t *s5s8_pgw);

/**
 * @brief  : Function to link peer node csid with local csid
 * @param  : fqcsid, peer node csid
 * @param  : fqcsid_t, local csids
 * @return : 0: Success, -1: otherwise
 */
int8_t
update_peer_csid_link(fqcsid_t *fqcsid, fqcsid_t *fqcsid_t);

/**
 * @brief  : Function to process delete pdn connection set request
 * @param  : del_pdn_conn_set_req_t, request info
 * @return : 0: Success, -1: otherwise
 */
int8_t
process_del_pdn_conn_set_req_t(del_pdn_conn_set_req_t *del_pdn_req);

/**
 * @brief  : Function to process delete pdn connection set response
 * @param  : del_pdn_conn_set_rsp_t, response info
 * @return : 0: Success, -1: otherwise
 */
int8_t
process_del_pdn_conn_set_rsp_t(del_pdn_conn_set_rsp_t *del_pdn_rsp);

/**
 * @brief  : Function to process update pdn connection set request
 * @param  : upd_pdn_conn_set_req_t, request info
 * @return : 0: Success, -1: otherwise
 */
int8_t
process_upd_pdn_conn_set_req_t(upd_pdn_conn_set_req_t *upd_pdn_req);

/**
 * @brief  : Function to process update pdn connection set response
 * @param  : upd_pdn_conn_set_rsp_t, response info
 * @return : 0: Success, -1: otherwise
 */
int8_t
process_upd_pdn_conn_set_rsp_t(upd_pdn_conn_set_rsp_t *upd_pdn_rsp);

/**
 * @brief  : Function to process pfcp session set deletion request
 * @param  : pfcp_sess_set_del_req_t, request info
 * @param  : peer_addr, upf node address
 * @return : 0: Success, -1: otherwise
 */
int process_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *del_set_req, peer_addr_t *peer_addr);

/**
 * @brief  : Function to process pfcp session set deletion response
 * @param  : pfcp_sess_set_del_rsp_t, response info
 * @return : 0: Success, -1: otherwise
 */
int process_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *del_set_rsp);

/**
 * @brief  : Function to fill the gtpc delete set pdn connection response
 * @param  : gtpv2c_header_t, response buffer
 * @param  : seq_t, sequence number
 * @param  : casue_value
 * @return : 0: Success, -1: otherwise
 */
int8_t
fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_header_t *gtpv2c_tx, uint8_t seq_t,
		uint8_t casue_value);

/**
 * @brief  : Function to cleanup sessions based on the local csids
 * @param  : local_csid
 * @param  : pdn_connection, pdn connection info
 * @return : 0: Success, -1: otherwise
 */
int8_t
cleanup_session_entries(uint16_t local_csid, pdn_connection *pdn);

/*
 * @brief  : Remove Temporary Local CSID linked with peer node CSID
 * @param  : peer_fqcsid, structure to store peer node fqcsid info.
 * @param  : tmp_csid, Temporary Local CSID.
 * @param  : iface, Interface .
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
remove_peer_temp_csid(fqcsid_t *peer_fqcsid, uint16_t tmp_csid, uint8_t iface);

/*
 * @brief  : Remove Session entry linked with Local CSID .
 * @param  : seid, session id .
 * @param  : peer_fqcsid, st1ructure to store peer node fqcsid info.
 * @param  : pdn_connection, pdn connection info
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int
cleanup_csid_entry(uint64_t seid, fqcsid_t *peer_fqcsid, pdn_connection *pdn);

/**
 * @brief  : Match session CSID with Peer node CSID, if CSID match not found then add.
 * @param  : fqcsid, structure to store received msg fqcsid.
 * @param  : context_fqcsid, Structure to store session fqcsid.
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int
match_and_add_sess_fqcsid(gtp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid);

/**
 * @brief  : Add Peer node CSID.
 * @param  : fqcsid, structure to store received msg fqcsid.
 * @param  : context_fqcsid, Structure to store session fqcsid.
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
void
add_sess_fqcsid(gtp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid);

/**
 * @brief  : Update Peer node CSID.
 * @param  : pfcp_sess_mod_rsp_t, structure to store sess. mod. req.
 * @param  : pdn_connection, pdn connection info
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int
update_peer_node_csid(pfcp_sess_mod_rsp_t  *pfcp_sess_mod_rsp, pdn_connection *pdn);

/**
 * @brief  : Link session with CSID.
 * @param  : csid,
 * @param  : pdn_connection, pdn connection info
 * @return : Returns 0 in case of success, cause value otherwise.
 */
int
link_sess_with_peer_csid(fqcsid_t *peer_csid, pdn_connection *pdn, uint8_t iface);

/**
 * @brief  : Delete Link session with CSID.
 * @param  : pdn_connection, pdn connection info
 * @return : Returns 0 in case of success, cause value otherwise.
 */
int
del_session_csid_entry(pdn_connection *pdn);

/**
 * @brief  : Remove Link session from CSID hash.
 * @param  : head, link list node.
 * @param  : seid,
 * @param  : csid,
 * @return : Returns 0 in case of success, cause value otherwise.
 */
int
remove_sess_entry(sess_csid *head, uint64_t seid, peer_csid_key_t *key);

/**
 * @brief  : Match session CSID with Peer node CSID, if CSID match not found then add.
 * @param  : fqcsid, structure to store received msg fqcsid.
 * @param  : context_fqcsid, Structure to store session fqcsid.
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int
match_and_add_pfcp_sess_fqcsid(pfcp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid);

/**
 * @brief  : Add Peer node CSID.
 * @param  : fqcsid, structure to store received msg fqcsid.
 * @param  : context_fqcsid, Structure to store session fqcsid.
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
void
add_pfcp_sess_fqcsid(pfcp_fqcsid_ie_t *fqcsid, sess_fqcsid_t *context_fqcsid);

/**
 * @brief  : Remove CSID from UE context.
 * @param  : cntx_fqcsid, Structure to store fqcsid.
 * @param  : csid_t, Structure to store session fqcsid.
 * @return : Returns void.
 */
void
remove_csid_from_cntx(sess_fqcsid_t *cntx_fqcsid, fqcsid_t *csid_t);

/**
 * @brief  : fill pdn fqcsid from UE context fqcsid collection.
 * @param  : pdn_fqcsid, Structure to store session fqcsid.
 * @param  : cntx_fqcsid, Structure to store fqcsid.
 * @return : Returns void.
 */
void
fill_pdn_fqcsid_info(fqcsid_t *pdn_fqcsid, sess_fqcsid_t *cntx_fqcsid);
#endif /* USE_CSID */

/* SAEGWC --> PGWC demotion scenario, Cleanup the SGW related data structures */
/*
 * @brief  : Cleanup SGW Session Info
 * @param  : del_sess_req_t, TEID, Seq etc
 * @param  : context, Structure to store UE context,
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int8_t
cleanup_sgw_context(del_sess_req_t *ds_req, ue_context *context);

/* SAEGWC --> SGWC Promtion scenario, Cleanup the PGWC related data structures */
/*
 * @brief  : Cleanup PGW Session Info
 * @param  : del_sess_req_t, TEID, Seq etc
 * @param  : context, Structure to store UE context,
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int8_t
cleanup_pgw_context(del_sess_req_t *ds_req, ue_context *context);

/*
 * @brief  : Send the predefined rules SDF, MTR, ADC, and PCC on UP.
 * @param  : upf IP address.
 * @return : Returns 0 in case of success ,-1 or cause value otherwise.
 */
int8_t
dump_predefined_rules_on_up(node_address_t upf_ip);

/*
 * @brief  : Convert Int value of charging characteristic to string
 * @param  : cc_value, Int value of charging characteristic
 * @return : Returns string value of charging characteristic.
 */
const char *
get_cc_string(uint16_t cc_value);

/*
 * @brief  : fills and sends pfcp session report response
 * @param  : context, ue_context
 * @param  : sequence , sequence number
 * @param  : pdn, pdn_context
 * @param  : dl_buf_sugg_pkt_cnt, DL Buffering Suggested Packet Count
 * @param  : dldr_flag, represent whether ddn report response or cdr report response
 * @return : Returns nothing.
 */
void
fill_send_pfcp_sess_report_resp(ue_context *context, uint8_t sequence, pdn_connection *pdn,
		uint16_t dl_buf_sugg_pkt_cnt, bool dldr_flag);
/**
 * @brief  : fill cp configuration
 * @param  : cp configuration pointer
 * @return : Returns status code
 */
int8_t fill_cp_configuration(cp_configuration_t *cp_configuration);

/**
 * @brief  : post request timeout
 * @param  : request_timeout_value, Int
 * @return : Returns status code
 */
int8_t	post_request_timeout(const int request_timeout_value);

/**
 * @brief  : post request timeout
 * @param  : request_tries_value, Int
 * @return : Returns status code
 */
int8_t	post_request_tries(const int request_tries_value);

/**
 * @brief  : post periodic timer
 * @param  : periodic_timer_value, Int
 * @return : Returns status code
 */
int8_t	post_periodic_timer(const int periodic_timer_value);

/**
 * @brief  : post transmit timer
 * @param  : transmit_timer_value, Int
 * @return : Returns status code
 */
int8_t	post_transmit_timer(const int transmit_timer_value);

/**
 * @brief  : post transmit count
 * @param  : transmit_count, Int
 * @return : Returns status code
 */
int8_t	post_transmit_count(const int transmit_count);

/**
 * @brief  : get request timeout
 * @param  : void
 * @return : Returns request timeout
 */
int	get_request_timeout(void);

/**
 * @brief  : get request tries
 * @param  : void
 * @return : Returns request tries value
 */
int	get_request_tries(void);

/**
 * @brief  : get periodic timer value
 * @param  : void
 * @return : Returns periodic timer value
 */
int	get_periodic_timer(void);

/**
 * @brief  : get transmit timer value
 * @param  : void
 * @return : Returns transmit timer value
 */
int	get_transmit_timer(void);

/**
 * @brief  : get transmit count value
 * @param  : void
 * @return : Returns transmit count value
 */
int	get_transmit_count(void);

#endif

