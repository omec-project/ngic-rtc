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

#ifndef _UP_MAIN_H_
#define _UP_MAIN_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane initialization, user session
 * and rating group processing functions.
 */

#ifdef PCAP_GEN
#include <pcap.h>
#endif /* PCAP_GEN */

#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_meter.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_version.h>

#include "../pfcp_messages/pfcp_up_struct.h"

#include "structs.h"
#include "interface.h"
#include "vepc_cp_dp_api.h"
#include "epc_packet_framework.h"

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* use_rest */

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
#define NGIC_INFO 1

/**
 * rte debug log level.
 */
#define NGIC_DEBUG 2

/**
 * Session Creation.
 */
#define SESS_CREATE 0
/**
 * Session Modification.
 */
#define SESS_MODIFY 1
/**
 * Session Deletion.
 */
#define SESS_DEL 2

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

#define SDF_FILTER_TABLE_SIZE        (1024)
#define ADC_TABLE_SIZE               (1024)
#define PCC_TABLE_SIZE               (1025)
#define METER_PROFILE_SDF_TABLE_SIZE (2048)

#ifdef PCAP_GEN
/**
 * pcap filename length.
 */
#define PCAP_FILENAME_LEN 256

/**
 * pcap filenames.
 */
#define SPGW_S1U_PCAP_FILE "logs/saegw_uplnk.pcap"
#define SPGW_SGI_PCAP_FILE "logs/saegw_dwlnk.pcap"

#define SGW_S1U_PCAP_FILE "logs/sgwu_uplnk.pcap"
#define SGW_S5S8_PCAP_FILE "logs/sgwu_dwlnk.pcap"

#define PGW_S5S8_PCAP_FILE "logs/pgwu_uplnk.pcap"
#define PGW_SGI_PCAP_FILE "logs/pgwu_dwlnk.pcap"

#endif /* PCAP_GEN */

#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define FORMAT "%s:%s:%d:"
#define ERR_MSG __file__, __func__, __LINE__

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

#ifdef USE_REST

/* VS: Number of connection can maitain in the hash */
#define NUM_CONN	500

/**
 * no. of mbuf.
 */
#define NB_ECHO_MBUF  1024

struct rte_mempool *echo_mpool;

extern int32_t conn_cnt;

void rest_thread_init(void);

#ifdef CP_BUILD
uint8_t
add_node_conn_entry(uint32_t dstIp, uint8_t portId);


uint8_t
update_rstCnt(void);
#else
uint8_t
add_node_conn_entry(uint32_t dstIp, uint64_t sess_id, uint8_t portId);

/**
 * rte hash handler.
 *
 * hash handles connections for S1U, SGI and PFCP
 */
extern struct rte_hash *conn_hash_handle;

#endif /* CP_BUILD */

void
flush_eNB_session(peerData *data_t);

void
dp_flush_session(uint32_t ip_addr, uint64_t sess_id);
#endif  /* USE_REST */
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

#pragma pack(1)

/**
 * Define type of DP
 * SGW - Service GW user plane
 * PGW - Packet GW user plane
 * SPGW - Combined userplane service for SGW an PGW
 */
enum dp_config {
	UNKNOWN = 0,
	SGWU = 01,
	PGWU = 02,
	SAEGWU = 03,
};

/**
 * Application configure structure .
 */
struct app_params {
	enum	 dp_config spgw_cfg;

	uint32_t s1u_ip;			/* s1u ipv4 address */
	uint32_t s1u_net;			/* s1u network address */
	uint32_t s1u_bcast_addr;		/* s1u broadcast ipv4 address */
	uint32_t s1u_gw_ip;			/* s1u gateway ipv4 address */
	uint32_t s1u_mask;			/* s1u network mask */
	uint32_t sgw_s5s8gw_ip;			/* SGW_S5S8 gateway ipv4 address */
	uint32_t sgw_s5s8gw_net;		/* SGW_S5S8 gateway network address */
	uint32_t sgw_s5s8gw_mask;		/* SGW_S5S8 network mask */
	uint32_t s5s8_sgwu_ip;			/* s5s8_sgwu gateway ipv4 address */
	uint32_t s5s8_pgwu_ip;			/* s5s8_pgwu gateway ipv4 address */
	uint32_t pgw_s5s8gw_ip;			/* PGW_S5S8 gateway ipv4 address */
	uint32_t pgw_s5s8gw_net;		/* PGW_S5S8 gateway network address */
	uint32_t pgw_s5s8gw_mask;		/* PGW_S5S8 network mask */
	uint32_t sgi_ip;			/* sgi ipv4 address */
	uint32_t sgi_net;			/* sgi network address */
	uint32_t sgi_bcast_addr;		/* sgi broadcast ipv4 address */
	uint32_t sgi_gw_ip;			/* sgi gateway ipv4 address */
	uint32_t sgi_mask;			/* sgi network mask */
	uint32_t s1u_port;			/* port no. to act as s1u */
	uint32_t s5s8_sgwu_port;		/* port no. to act as s5s8_sgwu */
	uint32_t s5s8_pgwu_port;		/* port no. to act as s5s8_pgwu */
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
	uint8_t transmit_cnt;
	int transmit_timer;
	int periodic_timer;
	uint8_t teidri_val;
	char ul_iface_name[MAX_LEN];
	char dl_iface_name[MAX_LEN];
	struct ether_addr s1u_ether_addr;	/* s1u mac addr */
	struct ether_addr s5s8_sgwu_ether_addr;	/* s5s8_sgwu mac addr */
	struct ether_addr s5s8_pgwu_ether_addr;	/* s5s8_pgwu mac addr */
	struct ether_addr sgi_ether_addr;	/* sgi mac addr */

#ifdef SGX_CDR
	const char *dealer_in_ip;		/* dealerIn ip */
	/* TODO : Change type */
	const char *dealer_in_port;		/* dealerIn port */

	const char *dealer_in_mrenclave;	/* dealerIn mrenclave */
	const char *dealer_in_mrsigner;		/* dealerIn mrsigner */
	const char *dealer_in_isvsvn;		/* dealerIn isvsvn */

	const char *dp_cert_path;		/* dp cert path */
	const char *dp_pkey_path;		/* dp publickey path */
#endif /* SGX_CDR */
};

#pragma pack()

/** extern the app config struct */
struct app_params app;

/** ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/** ethernet addresses of ports */
extern struct ether_addr ports_eth_addr[];

/** ADC sponsored dns table msg payload */
struct msg_adc {
	uint32_t ipv4;
	uint32_t rule_id;
};

/** UL Bearer Map key for hash lookup.*/
struct ul_bm_key {
	/** s1u/s5s8u teid */
	uint32_t teid;
	/** rule id*/
	uint32_t rid;
};

typedef struct ddn_info_t {
	/* PDR ID */
	uint8_t pdr_id;
	/* CP Seid */
	uint64_t cp_seid;
	/* UP Seid */
	uint64_t up_seid;
}ddn_t;

/** CDR actions, N_A should never be accounted for */
enum pkt_action_t {CHARGED, DROPPED, N_A};

#ifdef INSTMNT
extern uint32_t flag_wrkr_update_diff;
extern uint64_t total_wrkr_pkts_processed;
#endif				/* INSTMNT */

extern struct rte_ring *shared_ring[NUM_SPGW_PORTS];

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

extern struct sockaddr_in dest_addr_t;

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
void
scan_dns_ring(void);

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
 * @param pdr information
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
gtpu_encap(pdr_info_t **pdrs, pfcp_session_datat_t **sess_info, struct rte_mbuf **pkts,
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
 * @param PDR
 *	pointer to pdr session info
 */
void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid,
		pdr_info_t **pdr);

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
		uint64_t *pkts_mask, pfcp_session_datat_t **sess_info);
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
		uint64_t *pkts_mask, pfcp_session_datat_t **si,
		uint64_t *pkts_queue_mask);


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
dl_get_sess_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask,
		pfcp_session_datat_t **sess_data, uint64_t *pkts_queue_mask);
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


/***********************ddn_utils.c functions start**********************/
#ifdef USE_REST
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
echo_table_init(void);

#ifndef CP_BUILD
void
build_echo_request(struct rte_mbuf *echo_pkt, peerData *entry, uint16_t gtpu_seqnb);
#endif /* CP_BUILD*/

#endif /* USE_REST */

#ifdef DP_BUILD
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
enqueue_dl_pkts(pdr_info_t **pdrs, pfcp_session_datat_t **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask );

uint8_t
process_pfcp_session_report_req(struct sockaddr_in *peer_addr,
			ddn_t *ddn);
#endif /* DP_BUILD */

/**
 * update nexthop info.
 * @param pkts
 *	pointer to mbuf of packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_data
 *	pointer to session bear info
 */
void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
		pfcp_session_datat_t **sess_data, pdr_info_t **pdrs);

/**
 * update enb ip in ip header and s1u tied in gtp header.
 * @param pkts
 *	pointer to mbuf of packets.
 * @param n
 *	number of pkts.
 * @param pkts_mask
 *	bit mask to process the pkts, reset bit to free the pkt.
 * @param sess_data
 *	pointer to session bear info
 */
void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, pfcp_session_datat_t **sess_info,
		pdr_info_t **pdr);


int sess_modify_with_endmarker(far_info_t *far);

#ifdef PCAP_GEN
/**
 * @brief initalizes user plane pcap feature
 */
void
up_pcap_init(void);

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

#ifdef PRINT_NEW_RULE_ENTRY
void
print_pcc_val(struct pcc_rules *pcc);

void
print_sel_type_val(struct adc_rules *adc);

void
print_adc_val(struct adc_rules *adc);

void
print_mtr_val(struct mtr_entry *mtr);

void
print_sdf_val(struct pkt_filter *sdf);
#endif /* PRINT_NEW_RULE_ENTRY */

int
parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc);

uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx);

/***********************ddn_utils.c functions end**********************/
#endif /* _MAIN_H_ */

