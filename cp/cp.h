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

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#if defined(CP_BUILD)
#include "../libgtpv2c/include/gtp_messages.h"
#endif

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

#define MAX_UPF 10

#define DNSCACHE_CONCURRENT 2
#define DNSCACHE_PERCENTAGE 70
#define DNSCACHE_INTERVAL 4000
#define DNS_PORT 53

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
extern enum cp_config spgw_cfg;

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
extern int s11_pcap_fd;
extern int s5s8_sgwc_fd;
extern int s5s8_pgwc_fd;
extern int pfcp_sgwc_fd ;
extern struct cp_params cp_params;

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
ddn_by_session_id(uint64_t session_id);

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
 * @brief  : Set values in create bearer request
 * @param  : gtpv2c_tx, transmission buffer to contain 'create bearer request' message
 * @param  : sequence, sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context, UE Context data structure pertaining to the bearer to be created
 * @param  : bearer, EPS Bearer data structure to be created
 * @param  : lbi, 'Linked Bearer Identifier': indicates the default bearer identifier
 *           associated to the PDN connection to which the dedicated bearer is to be
 *           created
 * @param  : pti, 'Procedure Transaction Identifier' according to clause 8.35 3gpp 29.274,
 *           as specified by table 7.2.3-1 3gpp 29.274, 'shall be the same as the one
 *           used in the corresponding bearer resource command'
 * @param  : eps_bearer_lvl_tft
 * @param  : tft_len
 * @return : Returns nothing
 */
void
set_create_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
			  ue_context *context, eps_bearer *bearer,
			  uint8_t lbi, uint8_t pti, uint8_t eps_bearer_lvl_tft[],
			  uint8_t tft_len);

/**
 * @brief  : Set values in create bearer response
 * @param  : gtpv2c_tx, transmission buffer to contain 'create bearer response' message
 * @param  : sequence, sequence number as described by clause 7.6 3gpp 29.274
 * @param  : context, UE Context data structure pertaining to the bearer to be created
 * @param  : bearer, EPS Bearer data structure to be created
 * @param  : lbi, 'Linked Bearer Identifier': indicates the default bearer identifier
 *           associated to the PDN connection to which the dedicated bearer is to be
 *           created
 * @param  : pti, 'Procedure Transaction Identifier' according to clause 8.35 3gpp 29.274,
 *           as specified by table 7.2.3-1 3gpp 29.274, 'shall be the same as the one
 *           used in the corresponding bearer resource command'
 * @return : Returns nothing
 */
void
set_create_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
			  ue_context *context, eps_bearer *bearer,
			  uint8_t lbi, uint8_t pti);

void
set_delete_bearer_request(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	ue_context *context, uint8_t linked_eps_bearer_id,
	uint8_t ded_eps_bearer_ids[], uint8_t ded_bearer_counter);

void
set_delete_bearer_response(gtpv2c_header_t *gtpv2c_tx, uint32_t sequence,
	uint8_t linked_eps_bearer_id, uint8_t ded_eps_bearer_ids[],
	uint8_t ded_bearer_counter, uint32_t s5s8_pgw_gtpc_teid);


void
set_delete_bearer_command(del_bearer_cmd_t *del_bearer_cmd, pdn_connection *pdn, gtpv2c_header_t *gtpv2c_tx);
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
/* ================================================================================= */
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
/* ================================================================================= */

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
	char nameserver_ip[MAX_NUM_NAMESERVER][INET_ADDRSTRLEN];
} dns_config_t;

/**
 * @brief  : Maintains pfcp configuration
 */
typedef struct pfcp_config_t {
	/* CP Configuration : SGWC=01; PGWC=02; SAEGWC=03 */
	uint8_t cp_type;

	/* MME Params. */
	uint16_t s11_mme_port;
	struct in_addr s11_mme_ip;

	/* Control-Plane IPs and Ports Params. */
	uint16_t s11_port;
	uint16_t s5s8_port;
	uint16_t pfcp_port;
	struct in_addr s11_ip;
	struct in_addr s5s8_ip;
	struct in_addr pfcp_ip;

	/* User-Plane IPs and Ports Params. */
	uint16_t upf_pfcp_port;
	struct in_addr upf_pfcp_ip;

	/* RESTORATION PARAMETERS */
	uint8_t transmit_cnt;
	int transmit_timer;
	int periodic_timer;

	/* CP Timer Parameters */
	uint8_t request_tries;
	int request_timeout;    /* Request time out in milisecond */

	/* logger parameter */
	uint8_t cp_logger;

	/* APN */
	uint32_t num_apn;
	/* apn apn_list[MAX_NUM_APN]; */

	dns_cache_params_t dns_cache;
	dns_config_t ops_dns;
	dns_config_t app_dns;

	/* IP_POOL_CONFIG Params */
	struct in_addr ip_pool_ip;
	struct in_addr ip_pool_mask;

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
int
fill_peer_node_info(pdn_connection *pdn, eps_bearer *bearer);

/* Fill the FQ-CSID values in session est request */
int8_t
fill_fqcsid_sess_est_req(pfcp_sess_estab_req_t *pfcp_sess_est_req, ue_context *context);

/* Cleanup Session information by local csid*/
int8_t
del_peer_node_sess(uint32_t node_addr, uint8_t iface);

/* Cleanup Session information by local csid*/
int8_t
del_pfcp_peer_node_sess(uint32_t node_addr, uint8_t iface);

void
set_gtpc_fqcsid_t(gtp_fqcsid_ie_t *fqcsid,
		enum ie_instance instance, fqcsid_t *csids);
int
csrsp_fill_peer_node_info(create_sess_req_t *csr,
			pdn_connection *pdn, eps_bearer *bearer);
int8_t
fill_pgw_restart_notification(gtpv2c_header_t *gtpv2c_tx,
		uint32_t s11_sgw, uint32_t s5s8_pgw);

int8_t
update_peer_csid_link(fqcsid_t *fqcsid, fqcsid_t *fqcsid_t);

int8_t
process_del_pdn_conn_set_req_t(del_pdn_conn_set_req_t *del_pdn_req,
		gtpv2c_header_t *gtpv2c_tx);

int8_t
process_del_pdn_conn_set_rsp_t(del_pdn_conn_set_rsp_t *del_pdn_rsp);

int8_t
process_upd_pdn_conn_set_req_t(upd_pdn_conn_set_req_t *upd_pdn_req);

int8_t
process_upd_pdn_conn_set_rsp_t(upd_pdn_conn_set_rsp_t *upd_pdn_rsp);

/* Function */
int process_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *del_set_req,
		gtpv2c_header_t *gtpv2c_tx);

/* Function */
int process_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *del_set_rsp);

int8_t
fill_gtpc_del_set_pdn_conn_rsp(gtpv2c_header_t *gtpv2c_tx, uint8_t seq_t,
		uint8_t casue_value);
#endif /* USE_CSID */

#endif
