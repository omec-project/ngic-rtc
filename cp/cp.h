/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _CP_H_
#define _CP_H_

#include <pcap.h>
#include <ue.h>

#include <rte_version.h>

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

#ifndef RTE_LOGTYPE_CP
#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4
#endif

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
/**
 * @file
 *
 * Control Plane specific declarations
 */

/*
 * Define type of Control Plane (CP)
 * SGWC - Serving GW Control Plane
 * PGWC - PDN GW Control Plane
 * SPGWC - Combined SAEGW Control Plane
 */
enum cp_config {
	SGWC = 01,
	PGWC = 02,
	SPGWC = 03,
};
extern enum cp_config spgw_cfg;

#ifdef SYNC_STATS
/**
 * @brief statstics struct of control plane
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
 * @brief core identifiers for control plane threads
 */
struct cp_params {
	unsigned stats_core_id;
	unsigned nb_core_id;
#ifdef SIMU_CP
	unsigned simu_core_id;
#endif
};

/**
 * Structure to downlink data notification ack information struct.
 */
struct downlink_data_notification {
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
};

extern pcap_dumper_t *pcap_dumper;
extern pcap_t *pcap_reader;

extern int s11_fd;
extern int s11_pcap_fd;
extern int s5s8_sgwc_fd;
extern int s5s8_pgwc_fd;

extern struct cp_params cp_params;

#if defined(ZMQ_COMM) || defined(SDN_ODL_BUILD)
extern uint64_t op_id;
#endif /* ZMQ_COMM */
/**
 * @brief creates and sends downlink data notification according to session
 * identifier
 * @param session_id - session identifier pertaining to downlink data packets
 * arrived at data plane
 * @return
 * 0 - indicates success, failure otherwise
 */
int
ddn_by_session_id(uint64_t session_id);

/**
 * @brief initializes data plane by creating and adding default entries to
 * various tables including session, pcc, metering, etc
 */
void
initialize_tables_on_dp(void);

/**
 * Central working function of the control plane. Reads message from s11/pcap,
 * calls appropriate function to handle message, writes response
 * message (if any) to s11/pcap
 */
void
control_plane(void);

#ifdef ZMQ_COMM
/**
 * @brief Adds the current op_id to the hash table used to account for NB
 * Messages
 */
void
add_resp_op_id_hash(void);

/**
 * @brief Deletes the op_id from the hash table used to account for NB
 * Messages
 * @param nb_op_id
 * op_id received in process_resp_msg message to indicate message
 * was received and processed by the DPN
 */
void
del_resp_op_id(uint64_t resp_op_id);

#endif  /* ZMQ_COMM */

#ifdef CP_BUILD
#ifdef ZMQ_COMM
/**
 * @brief callback to handle downlink data notification messages from the
 * data plane
 * @param session id
 * session id received by control plane from the data plane
 * @return
 * 0 inicates success, error otherwise
 */
int
cb_ddn(uint64_t sess_id);

int
cb_keepalive(struct dp_id id);
#endif  /* ZMQ_COMM */

/**
 * @brief To Downlink data notification ack of user.
 * @param dp_id
 *	table identifier.
 * @param  ddn_ack
 *	Downlink data notification ack information
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
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
 * Open Statstics record file.
 */
void
stats_init(void);

/**
 * Maintain stats in hash table.
 * @param sync_stats
 * sync_stats information
 *
 * @return
 * Void
 */
void
add_stats_entry(struct sync_stats *stats);

/**
 * Update the resp and ack time in hash table.
 * @param key
 * key for lookup entry in hash table
 *
 * @param type
 * Update ack_recv_time/resp_recv_time
 * @return
 * Void
 */
void
update_stats_entry(uint64_t key, uint8_t type);

/**
 * Retrive entries from stats hash table
 * @param void
 *
 * @return
 * Void
 */
void
retrive_stats_entry(void);

/**
 * Export stats reports to file.
 * @param sync_stats
 * sync_stats information
 *
 * @return
 * Void
 */
void
export_stats_report(struct sync_stats stats_info);

/**
 * Close current stats file and redirects any remaining output to stderr
 */
void
close_stats(void);
#endif   /* SYNC_STATS */

/* Callback function which is received when config file is updated 
 * may be through helm Charts or any other means. 
 */
void config_change_cbk(char *config_file, uint32_t flags);

/**
 * Register for the watcher for the config update
 * @param file
 * filename
 *
 * @return
 * Void
 */
void register_config_updates(char *file);

/* ================================================================================= */
#endif
