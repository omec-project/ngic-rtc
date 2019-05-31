/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _MAIN_H_
#define _MAIN_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane initialization, user session
 * and rating group processing functions.
 */

#ifdef PCAP_GEN
#include <pcap.h>
#endif /* PCAP_GEN */

#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_meter.h>
#include <rte_jhash.h>
#include <rte_version.h>

#include "epc_packet_framework.h"
#include "vepc_cp_dp_api.h"
#include "dp_ipc_api.h"
#include "meter.h"
#include "structs.h"
#ifdef TIMER_STATS
#include "perf_timer.h"
#endif /* TIMER_STATS */
/**
 * dataplane rte logs.
 */
#define RTE_LOGTYPE_DP  RTE_LOGTYPE_USER1

/**
 * CP DP communication API rte logs.
 */
#define RTE_LOGTYPE_API   RTE_LOGTYPE_USER2

/**
 * rte notification log level.
 */
#define NOTICE 0

/**
 * rte information log level.
 */
#define INFO 1

/**
 * rte debug log level.
 */
#define DEBUG 2

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

/**
 * max prefetch.
 */
#define PREFETCH_OFFSET	8
/**
 * set nth bit.
 */
#define SET_BIT(mask, n)  ((mask) |= (1LLU << (n)))

/**
 * reset nth bit.
 */
#define SET_BIT(mask, n)  ((mask) |= (1LLU << (n)))

/**
 * reset nth bit.
 */
#define RESET_BIT(mask, n)  ((mask) &= ~(1LLU << (n)))

/**
 * check if nth bit is set.
 */
#define ISSET_BIT(mask, n)  (((mask) & (1LLU << (n))) ? 1 : 0)

/**
 * default ring size
 */
#define EPC_DEFAULT_RING_SZ	4096

/**
 * default burst size
 */
#define EPC_DEFAULT_BURST_SZ	32

/**
 * burst size of 64 pkts
 */
#define EPC_BURST_SZ_64		64

/**
 * max burst size
 */
#define MAX_BURST_SZ EPC_BURST_SZ_64
/**
 * Reserved ADC ruleids installed by DP during init.
 * example: DNS_RULE_ID to identify dns pkts. .
 */
#define RESVD_IDS 1

/**
 * Pre-defined DNS sdf filter rule id.
 */
#define DNS_RULE_ID (MAX_ADC_RULES + 1)

/**
 * max length of name string.
 */
#define MAX_LEN 128

/**
 * uplink flow.
 */
#define UL_FLOW 1

/**
 * downlink flow.
 */
#define DL_FLOW 2

/**
 * offset of meta data in headroom.
 */
#define META_DATA_OFFSET 128

/**
 * max records charging.
 */
#define MAX_SESSION_RECS  64

/**
 * Set DPN ID
 */
#define DPN_ID			(12345)

#define DEFAULT_HASH_FUNC rte_jhash

/*
 * To replace all old structures with the new one in code
 * TODO: Cleaner way.
 */
#define dp_pcc_rules pcc_rules

#ifdef HUGE_PAGE_16GB
#define HASH_SIZE_FACTOR 4
#else
#define HASH_SIZE_FACTOR 1
#endif

#define SDF_FILTER_TABLE "sdf_filter_table"
#define ADC_TABLE "adc_rule_table"
#define PCC_TABLE "pcc_table"
#define SESSION_TABLE "session_table"
#define METER_PROFILE_SDF_TABLE "meter_profile_sdf_table"
#define METER_PROFILE_APN_TABLE "meter_profile_apn_table"

#define SDF_FILTER_TABLE_SIZE        (1024)
#define ADC_TABLE_SIZE               (1024)
#define PCC_TABLE_SIZE               (1025)
#define METER_PROFILE_SDF_TABLE_SIZE (2048)
#define DPN_ID                       (12345)

#define LOGS_DIR "logs/"
#ifdef PCAP_GEN
/**
 * pcap filename length.
 */
#define PCAP_FILENAME_LEN 256

/**
 * pcap filenames.
 */
#define SPGW_S1U_PCAP_FILE LOGS_DIR "uplink.pcap"
#define SPGW_SGI_PCAP_FILE LOGS_DIR "downlink.pcap"

#define SGW_S1U_PCAP_FILE LOGS_DIR "sgw_s1u.pcap"
#define SGW_S5S8_PCAP_FILE LOGS_DIR "sgw_s5s8.pcap"

#define PGW_S5S8_PCAP_FILE LOGS_DIR "pgw_s5s8.pcap"
#define PGW_SGI_PCAP_FILE LOGS_DIR "pgw_sgi.pcap"

#endif /* PCAP_GEN */

#ifdef TIMER_STATS
/* Define global time struct variable. */
struct dl_timer_stats dl_stat_info;
struct ul_timer_stats ul_stat_info;

/* Timer struct define here */
struct dl_timer_stats {
	_timer_t sdf_acl_delta;
	_timer_t sdf_pcc_hash_delta;
	_timer_t adc_acl_delta;
	_timer_t adc_hash_delta;
	_timer_t adc_pcc_hash_delta;
	_timer_t dl_sess_hash_delta;
	_timer_t retrive_hash_delta;
	_timer_t update_dns_delta;
	_timer_t update_adc_delta;
	_timer_t pcc_gating_delta;
	_timer_t clone_dns_delta;
	_timer_t gtp_encap_delta;
	_timer_t sgi_handler_delta;
	_timer_t port_in_out_delta;

} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

struct ul_timer_stats {
	_timer_t sdf_acl_delta;
	_timer_t sdf_pcc_hash_delta;
	_timer_t adc_acl_delta;
	_timer_t adc_hash_delta;
	_timer_t update_adc_delta;
	_timer_t ue_info_lkup_delta;
	_timer_t adc_pcc_hash_delta;
	_timer_t pcc_gating_delta;
	_timer_t ul_sess_hash_delta;
	_timer_t gtp_decap_delta;
	_timer_t retrive_hash_delta;
	_timer_t s1u_handler_delta;
	_timer_t port_in_out_delta;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

#endif /* TIMER_STATS */

/* TODO: KNI releted parameters and struct define here */

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_SECOND_PER_DAY      86400

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32
#define KNI_MAX_KTHREAD 32

/* UDP socket port configure */
#define SOCKET_PORT 5556

/**
 * Structure of port parameters
 */
struct kni_port_params {
	uint8_t port_id;/* Port ID */
	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;

extern uint32_t nb_ports;

extern struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

#ifdef USE_AF_PACKET
/**
 * Initialize libmnl netlink subsystem
 */
void
init_mnl(void);

/**
 * Interface to burst rx and enqueue in to kernel
 */
void
kern_packet_ingress(int portid, struct rte_mbuf *pkts_burst[PKT_BURST_SZ], unsigned nb_rx);

/**
 * Interface to relay tx traffic out of the kernel and into the outgoing NIC
 */
void
kern_packet_egress(int portid);
#endif

/**
 * Interface to burst rx and enqueue mbufs into rx_q
 */
void
kni_ingress(struct kni_port_params *p,
		struct rte_mbuf *pkts_burst[PKT_BURST_SZ], unsigned nb_rx);

/**
 * Interface to dequeue mbufs from tx_q and burst tx
 */
void  kni_egress(struct kni_port_params *p);

/**
 * free mbufs after trasmited resp back on port.
 */
void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

/* Initialize KNI subsystem */
void
init_kni(void);

/* KNI interface allocatation */
int
kni_alloc(uint16_t port_id);

/* Check the link status of all ports in up to 9s, and print them finally */
void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask);

/* Validate dpdk interface are configure properly  */
int
validate_parameters(uint32_t portmask);

/* Free KNI allocation interface on ports */
void free_kni_ports(void);

//VS: Routing Discovery
/**
 * rte hash handler.
 */
extern struct rte_hash *gateway_arp_hash_handle;

/**
 * rte hash handler.
 */
extern struct rte_hash *route_hash_handle;

/**
 * Define type of DP
 * SGW - Service GW user plane
 * PGW - Packet GW user plane
 * SPGW - Combined userplane service for SGW an PGW
 */
enum dp_config {
	SGWU = 01,
	PGWU = 02,
	SPGWU = 03,
};

/**
 * Application configure structure .
 */
struct app_params {
	uint32_t s1u_ip;			/* s1u ipv4 address */
	uint32_t s1u_net;			/* s1u network address */
	uint32_t s1u_bcast_addr;	/* s1u broadcast ipv4 address */
	uint32_t s1u_gw_ip;			/* s1u gateway ipv4 address */
	uint32_t s1u_mask;			/* s1u network mask */
	uint32_t sgw_s5s8gw_ip;			/* SGW_S5S8 gateway ipv4 address */
	uint32_t sgw_s5s8gw_net;			/* SGW_S5S8 gateway network address */
	uint32_t sgw_s5s8gw_mask;			/* SGW_S5S8 network mask */
	uint32_t s5s8_sgwu_ip;		/* s5s8_sgwu gateway ipv4 address */
	uint32_t s5s8_pgwu_ip;		/* s5s8_pgwu gateway ipv4 address */
	uint32_t pgw_s5s8gw_ip;			/* PGW_S5S8 gateway ipv4 address */
	uint32_t pgw_s5s8gw_net;			/* PGW_S5S8 gateway network address */
	uint32_t pgw_s5s8gw_mask;			/* PGW_S5S8 network mask */
	uint32_t sgi_ip;			/* sgi ipv4 address */
	uint32_t sgi_net;			/* sgi network address */
	uint32_t sgi_bcast_addr;	/* sgi broadcast ipv4 address */
	uint32_t sgi_gw_ip;			/* sgi gateway ipv4 address */
	uint32_t sgi_mask;			/* sgi network mask */
	uint32_t s1u_port;			/* port no. to act as s1u */
	uint32_t s5s8_sgwu_port;	/* port no. to act as s5s8_sgwu */
	uint32_t s5s8_pgwu_port;	/* port no. to act as s5s8_pgwu */
	uint32_t sgi_port;			/* port no. to act as sgi */
	uint32_t log_level;			/* log level default - INFO,
						 * 1 - DEBUG	 */
	uint32_t numa_on;			/* Numa socket default 0 - disable,
						 * 1 - enable	 */
	uint32_t gtpu_seqnb_in;			/* incoming GTP sequence number
						 * 0 - dynamic (default)
						 * 1 - not included
						 * 2 - included  */
	uint32_t gtpu_seqnb_out;		/* outgoing GTP sequence number
						 * 0 - do not include (default)
						 * 1 - include */
	uint32_t ports_mask;
	char ul_iface_name[MAX_LEN];
	char dl_iface_name[MAX_LEN];
	enum dp_config spgw_cfg;
	struct ether_addr s1u_ether_addr;		/* s1u mac addr */
	struct ether_addr s5s8_sgwu_ether_addr;	/* s5s8_sgwu mac addr */
	struct ether_addr s5s8_pgwu_ether_addr;	/* s5s8_pgwu mac addr */
	struct ether_addr sgi_ether_addr;		/* sgi mac addr */

#ifdef SGX_CDR
	const char *dealer_in_ip;		/* dealerIn ip */
	/* TODO : Change type */
	const char *dealer_in_port;		/* dealerIn port */

	const char *dealer_in_mrenclave;	/* dealerIn mrenclave */
	const char *dealer_in_mrsigner;		/* dealerIn mrsigner */
	const char *dealer_in_isvsvn;		/* dealerIn isvsvn */

	const char *dp_cert_path;			/* dp cert path */
	const char *dp_pkey_path;			/* dp publickey path */
#endif /* SGX_CDR */
};

/** extern the app config struct */
extern struct app_params app;

/** ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

#ifdef USE_AF_PACKET
typedef struct dp_port_info {
	struct ether_addr *eth_addr;
	uint8_t ifup_state;
	uint16_t mtu_size;
	uint8_t promisc_state;
} dp_port_info;

struct dp_port_info dp_ports[RTE_MAX_ETHPORTS];
extern struct mnl_socket *mnl_sock;
#endif

/** ethernet addresses of ports */
extern struct ether_addr ports_eth_addr[];

/** ADC sponsored dns table msg payload */
struct msg_adc {
	uint32_t ipv4;
	uint32_t rule_id;
};

/** UL Bearer Map key for hash lookup.*/
struct ul_bm_key {
	/** s1u teid */
	uint32_t s1u_sgw_teid;
	/** rule id*/
	uint32_t rid;
};

/** CDR actions, N_A should never be accounted for */
enum pkt_action_t {CHARGED, DROPPED, N_A};

enum dp_session_state { CONNECTED, IDLE, IN_PROGRESS };

/**
 * Dataplane Application Detection and Control Rule structure.
 * This structure contains only parameters which are updated or refered
 * by dataplane. Fields which are common are removed to reduce struct size.
 * For complete information about ADC rule please refer
 * "struct adc_rules"
 */
struct dp_adc_rules {
	enum selector_type sel_type;	/* domain name, IP addr
					 * or IP addr prefix*/
	uint32_t rule_id;				/* Rule ID*/
	uint32_t rating_group;			/* Rating of Group*/
	uint8_t  gate_status;			/* Open/close*/
	uint8_t  report_level;			/* Report Level*/
	uint8_t  mute_notify;			/* Mute on/off*/
	struct tm rule_activation_time;		/* Rule Start time*/
	struct tm rule_deactivation_time;	/* Rule Stop time*/
	struct  redirect_info redirect_info;	/* Redirect  info*/
	uint64_t drop_pkt_count;		/* No. of pkts dropped */
	uint16_t mtr_profile_index;             /* index 0 to skip */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * Bearer Session information structure
 */
struct dp_session_info {
	struct ip_addr ue_addr;				/**< UE ip address*/
	struct ul_s1_info ul_s1_info;			/**< UpLink S1u info*/
	struct dl_s1_info dl_s1_info;			/**< DownLink S1u info*/
	uint8_t linked_bearer_id;				/**< Linked EPS Bearer ID (LBI)*/

	/* PCC rules related params*/
	uint32_t num_ul_pcc_rules;			/**< No. of UL PCC rule*/
	uint32_t ul_pcc_rule_id[MAX_PCC_RULES];		/**< PCC rule id supported in UL*/
	uint32_t num_dl_pcc_rules;			/**< No. of PCC rule*/
	uint32_t dl_pcc_rule_id[MAX_PCC_RULES];		/**< PCC rule id*/

	/* Charging Data Records*/
	struct ipcan_dp_bearer_cdr ipcan_dp_bearer_cdr;	/**< IP CAN bearer CDR*/

	uint32_t client_id;
	uint64_t sess_id;						/**< session id of this bearer
									 * last 4 bits of sess_id
									 * maps to bearer id*/
	uint32_t service_id;						/**< Type of service given
									 * to this session like
									 * Internet, Management, CIPA etc
									 */
	struct ue_session_info *ue_info_ptr;	/**< Pointer to UE info of this bearer */

	/** Session state for use with downlink data processing*/
	enum dp_session_state sess_state;
	/** Ring to hold the DL pkts for this session */
	struct rte_ring *dl_ring;
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * UE Session information structure
 */
struct ue_session_info {
	struct ip_addr ue_addr;			/**< UE ip address*/
	uint32_t bearer_count;			/**< Num. of bearers configured*/
	struct rte_meter_srtcm ul_apn_mtr_obj;
	/**< UL APN meter object pointer*/
	struct rte_meter_srtcm dl_apn_mtr_obj;
	/**< DL APN meter object pointer*/

	/* rating groups CDRs*/
	struct rating_group_index_map rg_idx_map[MAX_RATING_GRP]; /**< Rating group index*/
	struct ipcan_dp_bearer_cdr rating_grp[MAX_RATING_GRP];	/**< rating groups CDRs*/
	uint32_t ul_apn_mtr_idx;	/**< UL APN meter profile index*/
	uint32_t dl_apn_mtr_idx;	/**< DL APN meter profile index*/
	uint64_t ul_apn_mtr_drops;	/**< drop count due to ul apn metering*/
	uint64_t dl_apn_mtr_drops;	/**< drop count due to dl apn metering*/

	/* ADC rules related params*/
	uint32_t num_adc_rules;					/**< No. of ADC rule*/
	uint32_t adc_rule_id[MAX_ADC_RULES]; 	/**< list of ADC rule id*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * SDF and Bearer specific information structure
 */
struct dp_sdf_per_bearer_info {
	struct dp_pcc_rules pcc_info;						/**< PCC info of this bearer */
	struct rte_meter_srtcm sdf_mtr_obj;					/**< meter object for this SDF flow */
	struct ipcan_dp_bearer_cdr sdf_cdr;					/**< per SDF bearer CDR*/
	struct dp_session_info *bear_sess_info;  	/**< pointer to bearer this flow belongs to */
	uint64_t sdf_mtr_drops;								/**< drop count due to sdf metering*/
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

/**
 * per ADC, UE information structure
 */
struct dp_adc_ue_info {
	struct dp_adc_rules adc_info;		/**< ADC info of this bearer */
	struct ipcan_dp_bearer_cdr adc_cdr;	/**< per ADC bearer CDR*/
	struct rte_meter_srtcm mtr_obj;	/**< meter object for this SDF flow */
} __attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

#ifdef INSTMNT
extern uint32_t flag_wrkr_update_diff;
extern uint64_t total_wrkr_pkts_processed;
#endif				/* INSTMNT */

extern struct rte_ring *shared_ring[NUM_SPGW_PORTS];

#ifdef DP_DDN

/** Holds a set of rings to be used for downlink data buffering */
extern struct rte_ring *dl_ring_container;

/** Number of DL rings currently created */
extern uint32_t num_dl_rings;

/** For notification of modify_session so that buffered packets
 * can be dequeued
 */
extern struct rte_ring *notify_ring;

/** Pool for notification msg pkts */
extern struct rte_mempool *notify_msg_pool;

#endif /* DP_DDN */

extern int arp_icmp_get_dest_mac_address(const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr,
		uint32_t *nhip);

/**
 * Push DNS packets to DN queue from worker cores
 *
 * @param pkt
 *	pkt - DNS packet.
 *
 * @return
 *	0  on success
 *	-1 on failure
*/
int
push_dns_ring(struct rte_mbuf *);

/**
 * Pop DNS packets from ring and send to library for processing
 *
 * @param
 *  Unused
 *
 * @return
 *	None
 */
#ifdef NGCORE_SHRINK
void
scan_dns_ring(void);
#else
void
scan_dns_ring(__rte_unused void *args);
#endif
/**
 * Function to Initialize the Environment Abstraction Layer (EAL).
 *
 * @param void
 *	void.
 *
 * @return
 *	None
 */
void
dp_port_init(void);

/**
 * Function to initialize the dataplane application config.
 *
 * @param argc
 *	number of arguments.
 * @param argv
 *	list of arguments.
 *
 * @return
 *	None
 */
void
dp_init(int argc, char **argv);

/**
 * Decap gtpu header.
 *
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 * 	bit mask to process the pkts, reset bit to free the pkt.
 */
void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask);

/**
 * Encap gtpu header.
 *
 * @param sess_info
 *	pointer to session info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 */
void
gtpu_encap(struct dp_session_info **sess_info, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, uint64_t *pkts_queue_mask);

/*************************pkt_handler.ci functions start*********************/
/**
 * Function to handle incoming pkts on s1u interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index);

/**
 * Function to handle incoming pkts on s5s8 SGW interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
sgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index);

/**
 * Function to handle incoming pkts on s5s8 PGW interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
pgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index);

/**
 * Function to handle incoming pkts on sgi interface.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
sgi_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index);

/* ASR- NGCORE_SHRINK Notification handler temporarily defined out */
#ifndef NGCORE_SHRINK
/**
 * Function to handle notifications from CP which needs updates to
 * an active session. So worker core should process them.
 *
 * @param p
 *	pointer to pipeline.
 * @param pkts
 *	pointer to icontrol pkts.
 * @param n
 *	number of pkts.
 * @param arg
 *  Index of the current worker core in the worker params array.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */

int notification_handler(struct rte_pipeline *p,
	struct rte_mbuf **pkts,
	uint32_t n,
	void *arg);

#else
/**
 * Function to handle notifications from CP which needs updates to
 * an active session. So notification handler should process them.
 *
 * @param pkts
 *	pointer to icontrol pkts.
 * @param n
 *	number of pkts.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */

int notification_handler(struct rte_mbuf **pkts,
	uint32_t n);

#endif	/* NGCORE_SHRINK */

/*************************pkt_handler.c functions end***********************/

/**
 * Clone the DNS pkts and send to CP.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 */
void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask);

/**
 * If rule id is DNS, update the meta info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param rid
 *	sdf rule id to check the DNS pkts.
 */
void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid);

/**
 * Set checksum offload in meta,
 * Fwd based on nexthop info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param portid
 *	port id to forward the pkt.
 * @param sess_info
 *	pointer to session bear info
 */
void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid,
		struct dp_sdf_per_bearer_info **sess_info);

/************* ADC Rule Table function prototype***********/
/**
 * Given the ADC UE info struct, retrieve the ADC info.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param res
 *	list of adc rule ids, retrieved from adc filters.
 * @param adc_ue_info
 *	list of adc ue information structs to be returned.
 * @param flow
 *	this variable tells the caller is from UL_FLOW or DL_FLOW.
 *
 * @return
 * Void
 */
void
adc_ue_info_get(struct rte_mbuf **pkts, uint32_t n, uint32_t *res,
		void **adc_ue_info, uint32_t flow);

/**
 * Gate based on ADC filter entry.
 * @param rid
 *	ADC rule id.
 * @param adc_info
 *	ADC information.
 * @param  n
 *	num. of rule ids.
 * @param  adc_pkts_mask
 *	bit mask is set if adc rule is hit and gate is open.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 *
 * @return
 * Void
 */
void
adc_gating(uint32_t *rid, void **adc_info, uint32_t n,
			uint64_t *adc_pkts_mask, uint64_t *pkts_mask);

/************* Session information function prototype***********/
/**
 * Get the UL session info from table lookup.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_info
 *	session information returned after hash lookup.
 */
void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info);
/**
 * Get the DL session info from table lookup.
 * @param pkts
 *	pointer to mbuf of incoming packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_info
 *	session information returned after hash lookup.
 */
void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info,
		struct dp_session_info **si);

/**
 * Gate the incoming pkts based on PCC entry info.
 * @param pcc_info
 *	list of pcc id precedence struct pionters.
 *	pcc information.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  pcc_id
 *	array of pcc id.
 *
 * @return
 * Void
 */
void
pcc_gating(struct pcc_id_precedence *sdf_info, struct pcc_id_precedence *adc_info,
		uint32_t n, uint64_t *pkts_mask, uint32_t *pcc_id);
/**
 * Get ADC filter entry.
 * @param rid
 *	ADC rule id.
 * @param n
 *	num. of rule ids.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param adc_info
 *	ADC information.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
adc_rule_info_get(uint32_t *rid, uint32_t n, uint64_t *pkts_mask, void **adc_info);

/**
 * Get Meter profile index from sdf per bearer session info.
 * @param sess_info
 *	pointer to struct dp_sdf_per_bearer_info.
 * @param mtr_id
 *	meter profile index to be returned
 * @param mtr_drops
 *  pointer to stat to update drops due to metering.
 * @param n
 *	number of pkts.
 */
void
get_sdf_mtr_id(void **sess_info, void **mtr_id,
			uint64_t **mtr_drops, uint32_t n);

/**
 * Process APN metering based on meter index.
 *
 * @param sdf_info
 *     sdf info ptr.
 * @param adc_ue_info
 *     adc ue info ptr.
 * @param pkt
 *     mbuf pointer
 * @param n
 *     num. of pkts.
 * @param pkts_mask
 *     bit mask to process the pkts,
 *     reset bit to free the pkt.
 *
 * @return
 *     - 0 on success
 *     - -1 on failure
 */
int
sdf_mtr_process_pkt(struct dp_sdf_per_bearer_info **sdf_info,
			void **adc_ue_info, uint64_t *adc_pkts_mask,
			struct rte_mbuf **pkt, uint32_t n, uint64_t *pkts_mask);
/**
 * Process APN metering based on meter index.
 *
 * @param sdf_info
 *     sdf info ptr.
 * @param flow
 *     uplink or downlink.
 * @param pkt
 *     mbuf pointer
 * @param n
 *     num. of pkts.
 * @param pkts_mask
 *     bit mask to process the pkts,
 *     reset bit to free the pkt.
 *
 * @return
 *     - 0 on success
 *     - -1 on failure
 */
int
apn_mtr_process_pkt(struct dp_sdf_per_bearer_info **sdf_info, uint32_t flow,
			struct rte_mbuf **pkt, uint32_t n, uint64_t *pkts_mask);

/**
 * Update CDR records per adc per ue.
 * @param adc_ue_info
 *	list of per adc ue structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts
 * @param  adc_pkts_mask
 *	ADC bit mask to process the pkts,
 *	Bit is set to 0 if adc gating is closed.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_adc_cdr(void **adc_ue_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask,
		uint32_t flow);
/**
 * Update CDR records of per sdf per bearer.
 * @param adc_ue_info
 *	list of per adc ue structs pointer.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  adc_pkts_mask
 *	ADC bit mask to process the pkts,
 *	Bit is set to 0 if adc gating is closed.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_sdf_cdr(void **adc_ue_info,
		struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *adc_pkts_mask, uint64_t *pkts_mask, uint32_t flow);

/**
 * Update CDR records.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  pcc_rule
 *	array of pcc_rule id.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_pcc_cdr(struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
		uint32_t *pcc_rule, uint32_t flow);

/**
 * Update CDR records of bearer.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_bear_cdr(struct dp_sdf_per_bearer_info **sdf_bear_info,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow);

/**
 * Update CDR records per rating group.
 * @param sess_info
 *	list of per sdf bearer structs pointer.
 * @param  rgrp
 *	list of rating group ids, whose CDRs to be updated.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  flow
 *	direction of flow (UL_FLOW, DL_FLOW).
 *
 * @return
 * Void
 */
void
update_rating_grp_cdr(void **sess_info, uint32_t **rgrp,
		struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint32_t flow);

/**
 * Update Extended CDR records.
 * @param  pkts
 *	mbuf pkts.
 * @param  n
 *	number of pkts.
 * @param  pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param  pcc_rule
 *	array of pcc_rule id.
 *
 * @return
 * void
 */
void
update_extended_cdr(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *non_gtp_pkts_mask, uint32_t *pcc_rule,
		uint32_t direction);

/**
 * Get APN Meter profile index.
 * @param sess_info
 *	pointer to struct dp_sdf_per_bearer_info.
 * @param mtr_id
 *	meter profile index to be returned
 * @param mtr_drops
 *  pointer to stat to update drops due to metering.
 * @param n
 *	number of pkts.
 * @param flow
 *  UL_FLOW or DL_FLOW
 */
void
get_apn_mtr_id(void **sess_info, void **mtr_id,
		uint64_t **mtr_drops, uint32_t n, uint32_t flow);

/**
 * Function to process the ADC lookup with key of 32 bits.
 * @param  pkts
 *	mbuf pkts.
 * @param n
 *	number of pkts.
 * @param rid
 *	rule ids
 */
void
adc_hash_lookup(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid, uint8_t is_ul);

/**
 * Compare and update ADC rules in ADC ACL lookup results from hash lookup
 * If we have non-zero rule id in rc at nth location, replace nth value of rb
 * with that rule id.
 * @param rb
 *	list of rule ids.
 * @param rc
 *	list of rule ids.
 * @param n
 *	number of pkts.
 */
void
update_adc_rid_from_domain_lookup(uint32_t *rb, uint32_t *rc, uint32_t n);

/**
 * Get rating group from the adc and pcc info entries.
 * @param adc_ue_info
 *  list of pointers to adc_ue_info struct.
 * @param  sdf_info
 *	list of pointers to sdf flows.
 * @param  rgrp
 *	rating group list.
 * @param  n
 *	number of pkts.
 *
 * @return
 * Void
 */
void
get_rating_grp(void **adc_ue_info, void **sdf_info,
		uint32_t **rgrp, uint32_t n);

/**
 * Initialization of PCC Table Callback functions.
 */
void app_pcc_tbl_init(void);

/**
 * Initialization of ADC Table Callback functions.
 */
void app_adc_tbl_init(void);

/**
 * Initialization of Meter Table Callback functions.
 */
void app_mtr_tbl_init(void);

/**
 * Initialization of filter table callback functions.
 */
void app_filter_tbl_init(void);

/**
 * Initialization of Session Table Callback functions.
 */
void
app_sess_tbl_init(void);

/********************* ADC Rule Table ****************/
/**
 * Create ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy ADC Rule table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_table_delete(struct dp_id dp_id);

/**
 * Add entry in ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_entry_add(struct dp_id dp_id, struct adc_rules *entry);

/**
 * Delete entry in ADC Rule table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be deleted in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_adc_entry_delete(struct dp_id dp_id, struct adc_rules *entry);

/********************* PCC Table ****************/
/**
 * Create PCC table.
 * @param dp_id
 *	table identifier.
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_pcc_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy PCC table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_pcc_table_delete(struct dp_id dp_id);

/**
 * Add entry in PCC table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_pcc_entry_add(struct dp_id dp_id, struct pcc_rules *entry);

/**
 * Delete entry in PCC table.
 * @param dp_id
 *	table identifier.
 * @param entry
 *	element to be deleted in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_pcc_entry_delete(struct dp_id dp_id, struct pcc_rules *entry);

/********************* Bearer Session ****************/
/**
 * Create Bearer Session table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_session_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Destroy Bearer Session table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int dp_session_table_delete(struct dp_id dp_id);

/**
 * To create Bearer session information per user. The information
 * regarding uplink should be updated when passing session.
 * To update downlink related params please refer session_modify().
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_create(struct dp_id dp_id, struct session_info *session);

/**
 * To modify Bearer session information per user. The information
 * regarding uplink and downlink should be updated when passing session.
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_modify(struct dp_id dp_id, struct session_info *session);

/**
 * To Delete Bearer session information of user.
 * @param dp_id
 *	table identifier.
 * @param  session
 *	Session information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_session_delete(struct dp_id dp_id, struct session_info *session);

/********************* Meter Table ****************/
/**
 * Create Meter profile table.
 * @param dp_id
 *	table identifier.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_table_create(struct dp_id dp_id, uint32_t max_elements);

/**
 * Delete Meter profile table.
 * @param dp_id
 *	table identifier.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_table_delete(struct dp_id dp_id);

/**
 * Add Meter profile entry.
 * @param dp_id
 *	table identifier.
 * @param  mtr_entry
 *	meter entry
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_entry_add(struct dp_id dp_id, struct mtr_entry *mtr_entry);

/**
 * Delete Meter profile entry.
 * @param dp_id
 *	table identifier.
 * @param  mtr_entry
 *	meter entry
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_meter_profile_entry_delete(struct dp_id dp_id, struct mtr_entry *mtr_entry);

/**
 * @brief Called by CP to add to uplink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int
iface_add_uplink_data(struct ul_bm_key *key,
			struct dp_session_info *value);

/**
 * @brief Called by CP to add to downlink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int
iface_add_downlink_data(struct dl_bm_key *key,
			struct dp_session_info *value);

/**
 * @brief Called by CP to remove from uplink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int iface_del_uplink_data(struct ul_bm_key *key);

/**
 * @brief Called by CP to remove from downlink look up table.
 *
 * This function is thread safe due to message queue implementation.
 */
int iface_del_downlink_data(struct dl_bm_key *key);

/**
 * @brief Called by DP to lookup key-value pair in uplink look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value);

/**
 * @brief Called by DP to do bulk lookup of key-value pair in uplink
 * look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value pair in downlink look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value);
/**
 * @brief Called by DP to do bulk lookup of key-value pair in downlink
 * look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value pair in adc ue look up table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_adc_ue_data(struct dl_bm_key *key,
		void **value);
/**
 * @brief Function to return address of uplink hash table bucket, for the
 * 64 bits key.
 *
 * This function is thread safe (Read Only).
 */
struct rte_hash_bucket *bucket_ul_addr(uint64_t key);

/**
 * @brief Function to return address of downlink hash table
 * bucket, for the 64 bits key.
 *
 * This function is thread safe (Read Only).
 */
struct rte_hash_bucket *bucket_dl_addr(uint64_t key);

/**
 * @brief Function to create hash table..
 *
 */
int
hash_create(const char *name, struct rte_hash **rte_hash,
		uint32_t entries, uint32_t key_len);

/**
 * @brief initalizes data plane hash tables
 */
void
dp_table_init(void);

/**
 * @brief Called by DP to lookup key-value in ADC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_adc_data(const uint32_t key32,
		void **value);
/**
 * @brief Called by DP to Bulk lookup key-value in ADC table.
 *
 * This function is thread safe (Read Only).
 */
int
iface_lookup_adc_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);
/**
 * @brief Called by DP to lookup key-value in PCC table.
 *
 * This function is thread safe (Read Only).
 */
int iface_lookup_pcc_data(const uint32_t key32,
		struct dp_pcc_rules **value);

/********************* ADC SpondDNS Table ****************/
/**
 * Add entry in ADC dns table.
 * This function is thread safe due to message queue implementation.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
adc_dns_entry_add(struct msg_adc *entry);

/**
 * Delete entry in ADC dns table.
 * This function is thread safe due to message queue implementation.
 * @param entry
 *	element to be added in this table.
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
adc_dns_entry_delete(struct msg_adc *entry);

/**
 * To map rating group value to index
 * @param rg_val
 *	rating group.
 * @param  rg_idx_map
 *	index map structure.
 *
 * @return
 *	- 0  on success
 *	- -1 on failure
 */
int
add_rg_idx(uint32_t rg_val, struct rating_group_index_map *rg_idx_map);

/**
 * @brief Function to export UE CDR to file.
 *	This API takes the bearer session id and
 *	dumps the CDRs correspoinding to this session
 *	in "/var/log/dpn/session_cdr.csv".
 *	The cdrs will be dumped without reseting
 *	counters in DP.
 *
 * @param dp_id
 *  table identifier.
 * @param ue_cdr
 *	structre to flush UE CDR. This structure include
 *	session id of the bearer, cdr type - bearer, adc, pcc,
 *	rating group or all and action field to append or
 *	replace the logs.
 *
 * @return
 *  - 0 on success
 *  - -1 on failure
 */
int
dp_ue_cdr_flush(struct dp_id dp_id,	struct msg_ue_cdr *ue_cdr);

struct dp_session_info *
get_session_data(uint64_t sess_id, uint32_t is_mod);

/***********************ddn_utils.c functions start**********************/
#ifdef NGCORE_SHRINK
#ifdef DP_DDN

/**
 * Function to initialize/create shared ring, ring_container and mem_pool to
 * inter-communication between DL and iface core.
 *
 * @param void
 *	void.
 *
 * @return
 *	None
 */
void
dp_ddn_init(void);

/**
 * Downlink data notification ack information. The information
 * regarding downlink should be updated bearer info.
 * @param dp_id
 *	table identifier.
 * @param  ddn_ack
 *	Downlink data notification ack information
 *
 * @return
 *	- 0 - success
 *	- -1 - fail
 */
int
dp_ddn_ack(struct dp_id dp_id,
		struct downlink_data_notification_ack_t *ddn_ack);

/**
 * @brief Enqueue the downlink packets based upon the mask.
 *
 * @param sess_info
 * Session for which buffering needs to be performed
 * @param pkts
 * Set of incoming packets
 * @param pkts_queue_mask
 * Mask of packets which needs to be buffered
 *
 * @return
 *  void
 */
void
enqueue_dl_pkts(struct dp_sdf_per_bearer_info **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask );

#endif /* DP_DDN */
#else

/**
 * @brief Enqueue the downlink packets based upon the mask.
 *
 * @param sess_info
 * Session for which buffering needs to be performed
 * @param pkts
 * Set of incoming packets
 * @param pkts_queue_mask
 * Mask of packets which needs to be buffered
 * @param wk_index
 * Index of the worker core which is handling this session
 *
 * @return
 *  void
 */
void
enqueue_dl_pkts(struct dp_sdf_per_bearer_info **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask,
		int wk_index);
#endif /* NGCORE_SHRINK */
/**
 * Add entry into SDF-PCC or ADC-PCC association hash.
 * @param type
 *	Type of hash table, SDF/ADC.
 * @param pcc_id
 *	PCC rule id to be added.
 * @param precedence
 *	PCC rule precedence.
 * @param gate_status
 *	PCC rule gate status.
 * @param  n
 *	Number of SDF/ADC rules.
 * @param  rule_ids
 *	Pointer to SDF/ADC rule ids.
 *
 * @return
 *	0 - on success
 *	-1 - on failure
 */
int
filter_pcc_entry_add(enum filter_pcc_type type, uint32_t pcc_id,
		uint32_t precedence, uint8_t gate_status, uint32_t n, uint32_t *rule_ids);

/**
 * Modify entry into SDF-PCC or ADC-PCC association hash.
 * @param type
 *	Type of hash table, SDF/ADC.
 * @param pcc_id
 *	PCC rule id to be modified.
 * @param  n
 *	Number of SDF/ADC rules.
 * @param  rule_ids
 *	Pointer to SDF/ADC rule ids.
 *
 * @return
 *	0 - on success
 *	-1 - on failure
 */
int
filter_pcc_entry_modify(enum filter_pcc_type type, uint32_t pcc_id,
		uint32_t n, uint32_t *rule_ids);

/**
 * Delete entry from SDF-PCC or ADC-PCC association hash.
 * @param type
 *	Type of hash table, SDF/ADC.
 * @param pcc_id
 *	PCC rule id to be deleted.
 * @param  n
 *	Number of SDF/ADC rules.
 * @param  rule_ids
 *	Pointer to SDF/ADC rule ids.
 *
 * @return
 *	0 - on success
 *	-1 - on failure
 */
int
filter_pcc_entry_delete(enum filter_pcc_type type, uint32_t pcc_id,
		uint32_t n, uint32_t *rule_ids);

/**
 * Search SDF-PCC or ADC-PCC association hash for SDF/ADC ruleid as a key
 * @param type
 *	Type of hash table, SDF/ADC.
 * @param pcc_id
 *	SDF/ADC rule ids to be used for searching.
 * @param  n
 *	Number of SDF/ADC rules.
 * @param  pcc_info
 *	Pointer to matched PCC info.
 *
 * @return
 *	0 - on success
 *	-1 - on failure
 */
int
filter_pcc_entry_lookup(enum filter_pcc_type type, uint32_t *rule_ids,
		uint32_t n, struct pcc_id_precedence *pcc_info);

/**
 * update nexthop info.
 * @param pkts
 *	pointer to mbuf of packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sdf_bear_info
 *	pointer to session bear info
 */
void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
		struct dp_sdf_per_bearer_info **sdf_bear_info);

/**
 * update enb ip in ip header and s1u tied in gtp header.
 * @param pkts
 *	pointer to mbuf of packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sdf_bear_info
 *	pointer to session bear info
 */
void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, struct dp_sdf_per_bearer_info **sess_info);

#ifdef PCAP_GEN
/**
 * initialize pcap dumper.
 * @param pcap_filename
 *	pointer to pcap output filename.
 */
pcap_dumper_t *
init_pcap(char* pcap_filename);

/**
 * write into pcap file.
 * @param pkts
 *	pointer to mbuf of packets.
 * @param n
 *	number of pkts.
 * @param pcap_dumper
 *	pointer to pcap dumper.
 */
void dump_pcap(struct rte_mbuf **pkts, uint32_t n,
		pcap_dumper_t *pcap_dumper);

#endif /* PCAP_GEN */

#ifdef TIMER_STATS
/* update the DL timer stats*/
/**
 * Export timer stats record to file.
 * @param timer_stat
 *	timer stats information
 *
 * @return
 * Void
 */
void dl_timer_stats(uint32_t n, struct dl_timer_stats *stats);

/* update the UL timer stats*/
/**
 * Export timer stats record to file.
 * @param timer_stat
 *	timer stats information
 *
 * @return
 * Void
 */
void ul_timer_stats(uint32_t n, struct ul_timer_stats *stats);

#ifdef AUTO_ANALYSIS
/**
 * Print final per operation statistics on console
 * @param NONE
 *
 * @return
 * Void
 */
void print_perf_statistics(void);
#endif /* AUTO_AnaLYSIS */

#endif /* TIMER_STATS */

/***********************ddn_utils.c functions end**********************/
#endif /* _MAIN_H_ */
