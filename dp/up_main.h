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

#ifndef _UP_MAIN_H_
#define _UP_MAIN_H_
/**
 * @file
 * This file contains macros, data structure definitions and function
 * prototypes of dataplane initialization, user session
 * and rating group processing functions.
 */

#include <pcap.h>
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
#include "teid_upf.h"
#include "gw_adapter.h"

#ifdef USE_REST
#include "ngic_timer.h"
#endif /* use_rest */

#ifdef USE_CSID
#include "../pfcp_messages/csid_struct.h"
#endif /* USE_CSID */

#define FILE_NAME "../config/dp_rstCnt.txt"
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

/**
 * pcap filename length.
 */
#define PCAP_FILENAME_LEN 256
/**
 * pcap filenames.
 */
#define UPLINK_PCAP_FILE   "logs/estbnd"
#define DOWNLINK_PCAP_FILE "logs/wstbnd"

#define PCAP_EXTENTION  ".pcap"


/* KNI releted parameters and struct define here */

/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define KNI_SECOND_PER_DAY      86400

/* User Level Packet Copying */
#define UPLINK_DIRECTION		1
#define DOWNLINK_DIRECTION		2
#define COPY_UP_PKTS			1
#define COPY_DOWN_PKTS			2
#define COPY_UP_DOWN_PKTS		3
#define COPY_HEADER_ONLY		1
#define COPY_HEADER_DATA_ONLY		2
#define COPY_DATA_ONLY			3

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

#define ARP_SEND_BUFF 512

#define WEST_INTFC	0
#define EAST_INTFC	1

#define FWD_MASK	0
#define ENCAP_MASK	1
#define DECAP_MASK	2

struct rte_mempool *echo_mpool;

extern int32_t conn_cnt;
extern udp_sock_t my_sock;
uint8_t dp_restart_cntr;
uint32_t li_seq_no;

extern teidri_info *upf_teidri_allocated_list;
extern teidri_info *upf_teidri_free_list;
extern teidri_info *upf_teidri_blocked_list;
extern dp_configuration_t dp_configuration;

/**
 * @brief : IP Type Info
 */
struct ip_type {
	/* IPv4 Flag */
	uint8_t ipv4;
	/* IPv6 Flag */
	uint8_t ipv6;
	/* IPv4IPv6 Flag */
	uint8_t ipv4_ipv6;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

typedef struct ip_type ip_type_t;

/**
 * @brief  : Initialize restoration thread
 * @param  : No param
 * @return : Returns nothing
 */
void rest_thread_init(void);

#ifdef CP_BUILD
/**
 * @brief  : Add node entry
 * @param  : dstIp, Ip address to be added
 * @param  : portId, port number
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
add_node_conn_entry(uint32_t dstIp, uint8_t portId);

/**
 * @brief  : Update rst count
 * @param  : No param
 * @return : Returns Updated restart counter Value
 */
uint8_t
update_rstCnt(void);

#else
/**
 * @brief  : Add node entry
 * @param  : dstIp, Ip address to be added its either ipv4 or ipv6
 * @param  : sess_id, session id
 * @param  : portId, port number
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
add_node_conn_entry(node_address_t dstIp, uint64_t sess_id, uint8_t portId);

#endif /* CP_BUILD */

#endif  /* USE_REST */

/**
 * @brief   :Structure of port parameters
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
 * @brief  : Interface to burst rx and enqueue mbufs into rx_q
 * @param  : p, kni parameters
 * @param  : pkts_burst, mbufs packets
 * @param  : nb_rs, number of packets
 * @return : Returns nothing
 */
void
kni_ingress(struct kni_port_params *p,
		struct rte_mbuf *pkts_burst[PKT_BURST_SZ], unsigned nb_rx);

/**
 * @brief  : Interface to dequeue mbufs from tx_q and burst tx
 * @param  : p, kni parameters
 * @return : Returns nothing
 */
void  kni_egress(struct kni_port_params *p);

/**
 * @brief  : free mbufs after trasmited resp back on port.
 * @param  : pkts_burst, mbufs packets
 * @param  : num, number of packets
 * @return : Returns nothing
 */
void
kni_burst_free_mbufs(struct rte_mbuf **pkts, unsigned num);

/**
 * @brief  : Initialize KNI subsystem
 * @param  : No param
 * @return : Returns nothing
 */
void
init_kni(void);

/**
 * @brief  : KNI interface allocatation
 * @param  : port_id, port number
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
kni_alloc(uint16_t port_id);

/**
 * @brief  : Check the link status of all ports in up to 9s, and print them finally
 * @param  : port_id, port number
 * @param  : port_mask, mask value
 * @return : Returns nothing
 */
void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask);

/**
 * @brief  : Validate dpdk interface are configure properly
 * @param  : port_mask, mask value
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
validate_parameters(uint32_t portmask);

/**
 * @brief  : Free KNI allocation interface on ports
 * @param  : No param
 * @return : Returns nothing
 */
void free_kni_ports(void);

//VS: Routing Discovery
/**
 * rte hash handler.
 */
extern struct rte_hash *gateway_arp_hash_handle;

/**
 *  @brief  :rte hash handler.
 */
extern struct rte_hash *route_hash_handle;

#pragma pack(1)

/**
 * @brief  : Application configure structure .
 */
struct app_params {
	/* Gateway Mode*/
	//enum dp_config spgw_cfg;
	/* Enable DP PCAPS Generation */
	/* Start: 1, Restart: 2, Default: 0 Stop*/
	uint8_t generate_pcap;
	/* Off: 0, On: 1*/
	uint8_t perf_flag;
	/* Numa Socket
	 * Default: 0:disable, 1:enable */
	uint8_t numa_on;
	/* incoming GTP sequence number, 0 - dynamic (default), 1 - not included,
	 * 2 - included */
	uint8_t gtpu_seqnb_in;
	/* outgoing GTP sequence number, 0 - do not include (default), 1 - include*/
	uint8_t gtpu_seqnb_out;
	/* pfcp ipv6 prefix len */
	uint8_t pfcp_ipv6_prefix_len;
	/* Transmit Count */
	uint8_t transmit_cnt;

	/* D-DF2 PORT */
	uint16_t ddf2_port;
	/* D-DF3 PORT */
	uint16_t ddf3_port;

	/* Transmit Timer*/
	int transmit_timer;
	/* Peridoic Timer */
	int periodic_timer;
	/* TEIDRI value */
	int teidri_val;
	/* TEIDRI Timeout */
	int teidri_timeout;
	/* cli rest port */
	uint16_t cli_rest_port;
	/* cli rest ip */
	char cli_rest_ip_buff[IPV6_STR_LEN];

	/* RTE Log Level*/
	uint32_t log_level;
	/* West Bound S1U/S5S8 Port */
	uint32_t wb_port;
	/* East Bound S5S8/SGI Port */
	uint32_t eb_port;
	/* West Bound S1U/S5S8 IPv4 and IPv6 Type */
	ip_type_t wb_ip_type;
	/* West Bound S1U/S5S8 IPv4 Address */
	uint32_t wb_ip;
	/* West Bound S1U/S5S8 IPV6 Link Local Layer Address */
	struct in6_addr wb_l3_ipv6;
	/* West Bound S1U/S5S8 IPV6 Address */
	struct in6_addr wb_ipv6;
	/* West Bound S1U/S5S8 IPV6 prefix Len */
	uint8_t wb_ipv6_prefix_len;
	/* West Bound S1U/S5S8 Logical Interface IPv4 and IPv6 Type */
	ip_type_t wb_li_ip_type;
	/* West Bound S5S8 Logical Interface IPv4 Address */
	uint32_t wb_li_ip;
	/* West Bound S5S8 Logical Interface IPV6 Address */
	struct in6_addr wb_li_ipv6;
	/* West Bound S5S8 Logical Interface IPV6 prefix Len */
	uint8_t wb_li_ipv6_prefix_len;
	/* East Bound S5S8/SGI IPv4 and IPv6 Type */
	ip_type_t eb_ip_type;
	/* East Bound S5S8/SGI IPv4 Address */
	uint32_t eb_ip;
	/* East Bound S5S8/SGI IPV6 Address */
	struct in6_addr eb_ipv6;
	/* East Bound S5S8/SGI IPV6 Link Local Layer Address */
	struct in6_addr eb_l3_ipv6;
	/* Eest Bound S5S8/SGI IPV6 prefix Len */
	uint8_t eb_ipv6_prefix_len;
	/* West Bound S1U/S5S8 IPv4 and IPv6 Type */
	ip_type_t eb_li_ip_type;
	/* East Bound S5S8 Logical Interface IPv4 Address */
	uint32_t eb_li_ip;
	/* East Bound S5S8 Logical Interface IPv6 Address */
	struct in6_addr eb_li_ipv6;
	/* East Bound S5S8 Logical Interface IPv6 Address prefix len */
	uint8_t eb_li_ipv6_prefix_len;
	/* Ports Masks */
	uint32_t ports_mask;
	/* West Bound Gateway IP Address */
	uint32_t wb_gw_ip;
	/* East Bound Gateway IP Address */
	uint32_t eb_gw_ip;
	/* West Bound S1U/S5S8 Subnet Mask */
	uint32_t wb_mask;
	/* West Bound S5S8 Logical iface Subnet Mask*/
	uint32_t wb_li_mask;
	/* East Bound S5S8/SGI Subnet Mask */
	uint32_t eb_mask;
	/* East Bound S5S8 Logical iface Subnet Mask*/
	uint32_t eb_li_mask;
	/* West Bound S1U/S5S8 subnet */
	uint32_t wb_net;
	/* West Bound S5S8 Logical iface Subnet*/
	uint32_t wb_li_net;
	/* East Bound S5S8/SGI subnet */
	uint32_t eb_net;
	/* East Bound S5S8 Logical iface Subnet*/
	uint32_t eb_li_net;
	/* West Bound Gateway Broadcast Address*/
	uint32_t wb_bcast_addr;
	/* West Bound logical iface Gateway Broadcast Address*/
	uint32_t wb_li_bcast_addr;
	/* East Bound Gateway Broadcast Address*/
	uint32_t eb_bcast_addr;
	/* East Bound logical iface Gateway Broadcast Address*/
	uint32_t eb_li_bcast_addr;
	/* D-DF2 IP Address */
	char ddf2_ip[IPV6_STR_LEN];
	/* D-DF3 IP Address */
	char ddf3_ip[IPV6_STR_LEN];

	/* D-DF2 Local IP Address */
	char ddf2_local_ip[IPV6_STR_LEN];
	/* D-DF3 Local IP Address */
	char ddf3_local_ip[IPV6_STR_LEN];
	/* West Bound Interface Name */
	char wb_iface_name[MAX_LEN];
	/* West Bound Logical Interface Name */
	char wb_li_iface_name[MAX_LEN];
	/* East Bound Interface Name */
	char eb_iface_name[MAX_LEN];
	/* East Bound Logical Interface Name */
	char eb_li_iface_name[MAX_LEN];
	/* West Bound S1U/S5S8 physical address MAC */
	struct ether_addr wb_ether_addr;
	/* East Bound S5S8/SGI physical address MAC */
	struct ether_addr eb_ether_addr;

};

#pragma pack()

/** extern the app config struct */
struct app_params app;

/* file descriptor of ddf2 */
void *ddf2_fd;

/* file descriptor of ddf3 */
void *ddf3_fd;

/** ethernet addresses of ports */
struct ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/** ethernet addresses of ports */
extern struct ether_addr ports_eth_addr[];

/**
 * @brief  : ADC sponsored dns table msg payload
 */
struct msg_adc {
	uint32_t ipv4;
	uint32_t rule_id;
};

/**
 * @brief  : UL Bearer Map key for hash lookup.
 */
struct ul_bm_key {
	/** s1u/s5s8u teid */
	uint32_t teid;
	/** rule id*/
	uint32_t rid;
};

/**
 * @brief  : Maintains ddn information
 */
typedef struct ddn_info_t {
	/* PDR ID */
	uint8_t pdr_id;
	/* CP Seid */
	uint64_t cp_seid;
	/* UP Seid */
	uint64_t up_seid;
}ddn_t;

#pragma pack(push, 1)
typedef struct li_data_ring
{
	uint64_t id;
	uint64_t imsi;
	int size;
	uint8_t forward;
	uint8_t *pkts;
} li_data_t;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct cdr_rpt_req {
	pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report;
	uint64_t  up_seid;
	uint32_t seq_no;
} cdr_rpt_req_t;
#pragma pack(pop)

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

extern peer_addr_t dest_addr_t;

extern int arp_icmp_get_dest_mac_address(const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr,
		uint32_t *nhip);

/**
 * @brief  : Push DNS packets to DN queue from worker cores
 * @param  :pkt, DNS packet.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
push_dns_ring(struct rte_mbuf *);

/**
 * @brief  : Pop DNS packets from ring and send to library for processing
 * @param  : No param
 * @return : Returns nothing
 */
void
scan_dns_ring(void);

/**
 * @brief  : Function to Initialize the Environment Abstraction Layer (EAL).
 * @param  : No param
 * @return : Returns nothing
 */
void
dp_port_init(void);

/**
 * @brief  : Function to initialize the dataplane application config.
 * @param  : argc, number of arguments.
 * @param  : argv, list of arguments.
 * @return : Returns nothing
 */
void
dp_init(int argc, char **argv);

/**
 * @brief  : Decap gtpu header.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : fd_pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @return : Returns nothing
 */
void
gtpu_decap(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *fd_pkts_mask);

/**
 * @brief  : Encap gtpu header.
 * @param  : pdrs, pdr information
 * @param  : sess_info, pointer to session info.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : fd_pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
void
gtpu_encap(pdr_info_t **pdrs, pfcp_session_datat_t **sess_info, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, uint64_t *fd_pkts_mask, uint64_t *pkts_queue_mask);

/*************************pkt_handler.ci functions start*********************/
/**
 * @brief  : Function to handle incoming pkts on west bound interface.
 * @param  : p, pointer to pipeline.
 * @param  : pkts, pointer to pkts.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : wk_index,
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
wb_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, int wk_index);
/**
 * @brief  : Function to handle incoming pkts on east bound interface.
 * @param  : p, pointer to pipeline.
 * @param  : pkts, pointer to pkts.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : wk_index,
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
eb_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, int wk_index);

/**
 * @brief  : Function to handle notifications from CP which needs updates to
 *           an active session. So notification handler should process them.
 * @param  : pkts, pointer to icontrol pkts.
 * @param  : n, number of pkts.
 * @return : Returns 0 in case of success , -1 otherwise
 */

int notification_handler(struct rte_mbuf **pkts,
	uint32_t n);

/*************************pkt_handler.c functions end***********************/

/**
 * @brief  : Clone the DNS pkts and send to CP.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @return : Returns nothing
 */
void
clone_dns_pkts(struct rte_mbuf **pkts, uint32_t n, uint64_t pkts_mask);

/**
 * @brief  : If rule id is DNS, update the meta info.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : rid, sdf rule id to check the DNS pkts.
 * @return : Returns nothing
 */
void
update_dns_meta(struct rte_mbuf **pkts, uint32_t n, uint32_t *rid);

/**
 * @brief  : Set checksum offload in meta, Fwd based on nexthop info.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : portid, port id to forward the pkt.
 * @param  : PDR, pointer to pdr session info
 * @param  : Loopback_flag, Indication flag for loopback
 * @return : Returns nothing
 */
void
update_nexthop_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint8_t portid,
		pdr_info_t **pdr, uint8_t loopback_flag);

/************* Session information function prototype***********/
/**
 * @brief  : Get the UL session info from table lookup.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : snd_err_pkts_mask, bit mask to send the error indication.
 * @param  : fwd_pkts_mask, bit mask to forward that packet.
 * @param  : decap_pkts_mask, bit mask to decap that packet.
 * @param  : sess_info, session information returned after hash lookup.
 * @return : Returns nothing
 */
void
ul_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *snd_err_pkts_mask,
		uint64_t *fwd_pkts_mask, uint64_t *decap_pkts_mask,
		pfcp_session_datat_t **sess_info);
/**
 * @brief  : Get the DL session info from table lookup.
 * @param  : pkts, pointer to mbuf of incoming packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : snd_err_pkts_mask, bit mask to send the error indication.
 * @param  : sess_info, session information returned after hash lookup.
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
void
dl_sess_info_get(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, pfcp_session_datat_t **si,
		uint64_t *pkts_queue_mask, uint64_t *snd_err_pkts_mask,
		uint64_t *fwd_pkts_mask, uint64_t *encap_pkts_mask);

/**
 * @brief  : Gate the incoming pkts based on PCC entry info.
 * @param  : sdf_info, list of pcc id precedence struct pionters.
 * @param  : adc_info, list of pcc id precedence struct pionters.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : pcc_id, array of pcc id.
 * @return : Returns nothing
 */
void
pcc_gating(struct pcc_id_precedence *sdf_info, struct pcc_id_precedence *adc_info,
		uint32_t n, uint64_t *pkts_mask, uint32_t *pcc_id);

/**
 * @brief  : Called by CP to remove from uplink look up table.
 *           Note-This function is thread safe due to message queue implementation.
 * @param  : key
 * @return : Returns 0 in case of success , -1 otherwise
 */
int iface_del_uplink_data(struct ul_bm_key *key);

/**
 * @brief  : Called by CP to remove from downlink look up table.
 *           Note-This function is thread safe due to message queue implementation.
 * @param  : key
 * @return : Returns 0 in case of success , -1 otherwise
 */
int iface_del_downlink_data(struct dl_bm_key *key);

/**
 * @brief  : Called by DP to lookup key-value pair in uplink look up table.
 *           Note-This function is thread safe (Read Only).
 * @param  : key
 * @param  : value, buffer to store to result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
iface_lookup_uplink_data(struct ul_bm_key *key,
		void **value);

/**
 * @brief  : Called by DP to do bulk lookup of key-value pair in uplink
 *           look up table.
 *           Note-This function is thread safe (Read Only).
 * @param  : key, keys
 * @param  : n, nuber of keys
 * @param  : hit_mask
 * @param  : value, buffer to store to result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
iface_lookup_uplink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);

/**
 * @brief  : Called by DP to lookup key-value pair in downlink look up table.
 *           Note-This function is thread safe (Read Only).
 * @param  : key
 * @param  : value, buffer to store to result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
iface_lookup_downlink_data(struct dl_bm_key *key,
		void **value);
/**
 * @brief  : Called by DP to do bulk lookup of key-value pair in downlink
 *           look up table.
 *           Note-This function is thread safe (Read Only).
 * @param  : key, keys
 * @param  : n, nuber of keys
 * @param  : hit_mask
 * @param  : value, buffer to store to result
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
iface_lookup_downlink_bulk_data(const void **key, uint32_t n,
		uint64_t *hit_mask, void **value);


/***********************ddn_utils.c functions start**********************/
#ifdef USE_REST
/**
 * @brief  : Function to initialize/create shared ring, ring_container and mem_pool to
 *           inter-communication between DL and iface core.
 * @param  : No param
 * @return : Returns nothing
 */
void
echo_table_init(void);

#ifndef CP_BUILD
/**
 * @brief  : Function to build GTP-U echo request
 * @param  : echo_pkt, rte_mbuf pointer
 * @param  : gtppu_seqnb, sequence number
 * @return : Returns nothing
 */
void
build_echo_request(struct rte_mbuf *echo_pkt, peerData *entry, uint16_t gtpu_seqnb);
#endif /* CP_BUILD*/

#endif /* USE_REST */

#ifdef DP_BUILD
/**
 * @brief  : Function to initialize/create shared ring, ring_container and mem_pool to
 *           inter-communication between DL and iface core.
 * @param  : No param
 * @return : Returns nothing
 */
void
dp_ddn_init(void);

/**
 * @brief  : Downlink data notification ack information. The information
 *           regarding downlink should be updated bearer info.
 * @param  : dp_id, table identifier.
 * @param  : ddn_ack, Downlink data notification ack information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
dp_ddn_ack(struct dp_id dp_id,
		struct downlink_data_notification_ack_t *ddn_ack);

/**
 * @brief  : Enqueue the downlink packets based upon the mask.
 * @param  : pdrs, pdr information
 * @param  : sess_info, Session for which buffering needs to be performed
 * @param  : pkts, Set of incoming packets
 * @param  : pkts_queue_mask,  Mask of packets which needs to be buffered
 * @return : Returns nothing
 */
void
enqueue_dl_pkts(pdr_info_t **pdrs, pfcp_session_datat_t **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask );

/**
 * @brief  : Process pfcp session report request
 * @param  : peer_addr, peer node information
 * @param  : ddn, ddn information
 * @return : Returns 0 in case of success , -1 otherwise
 */
uint8_t
process_pfcp_session_report_req(peer_addr_t peer_addr,
			ddn_t *ddn);
#endif /* DP_BUILD */

/**
 * @brief  : update nexthop info.
 * @param  : pkts, pointer to mbuf of packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : fd_pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : loopback_pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : sess_data, pointer to session bear info
 * @param  : pdrs, pdr information
 * @return : Returns nothing
 */
void
update_nexts5s8_info(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
		uint64_t *fd_pkts_mask, uint64_t *loopback_pkts_mask,
		pfcp_session_datat_t **sess_data, pdr_info_t **pdrs);

/**
 * @brief  : update enb ip in ip header and s1u tied in gtp header.
 * @param  : pkts, pointer to mbuf of packets.
 * @param  : n, number of pkts.
 * @param  : pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : fd_pkts_mask, bit mask to process the pkts, reset bit to free the pkt.
 * @param  : sess_data, pointer to session bear info
 * @param  : pdrs, pdr information
 * @return : Returns nothing
 */
void
update_enb_info(struct rte_mbuf **pkts, uint32_t n,
		uint64_t *pkts_mask, uint64_t *fd_pkts_mask, pfcp_session_datat_t **sess_info,
		pdr_info_t **pdr);


/**
 * @brief  : Process endmarker data received in session modify request
 * @param  : far, far information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int sess_modify_with_endmarker(far_info_t *far);

/**
 * @brief  : initalizes user plane pcap feature
 * @param  : No param
 * @return : Returns nothing
 */
void
up_pcap_init(void);


/**
 * @brief  : initalizes user plane pcap feature
 * @param  : command, content pcap generation command.
 * @param  : pcap_dumper, pointer to pcap dumper.
 * @param  : pkts, pointer to mbuf of packets.
 * @param  : n,number of pkts.
 * @return : Returns nothing
 */
void
up_pcap_dumper(pcap_dumper_t *pcap_dumper,
		struct rte_mbuf **pkts, uint32_t n);
/**
 * @brief  : initalizes user plane pcap feature
 * @param  : command, content pcap generation command.
 * @param  : pcap_dumper, pointer to pcap dumper.
 * @param  : pkts, pointer to mbuf of packets.
 * @param  : n,number of pkts.
 * @param  : pkts_mask, set of the pkts collections.
 * @return : Returns nothing
 */
void
up_core_pcap_dumper(pcap_dumper_t *pcap_dumper,
		struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask);

/**
 * @brief  : initialize pcap dumper.
 * @param  : pcap_filename, pointer to pcap output filename.
 * @return : Returns pointer to pcap dumper
 */
pcap_dumper_t *
init_pcap(char* pcap_filename);

/**
 * @brief  : write into pcap file.
 * @param  : pkts, pointer to mbuf of packets.
 * @param  : n,number of pkts.
 * @param  : pcap_dumper, pointer to pcap dumper.
 * @return : Returns nothing
 */
void dump_pcap(struct rte_mbuf **pkts, uint32_t n,
		pcap_dumper_t *pcap_dumper);

/**
 * @brief  : get dp restart counter value.
 * @param  : No Param.
 * @return : Returns
 *           dp restart counter value.
 */
uint8_t
get_dp_restart_cntr(void);

/**
 * @brief  : update dp restart counter value.
 * @param  : No Param.
 * @return : Nothing
 */
void
update_dp_restart_cntr(void);

#ifdef USE_CSID
/**
 * @brief  : Function to fill the peer node address and generate unique CSID.
 * @param  : pfcp_session_t session info.
 * @param  : Control-Plane node address.
 * @return : Returns 0 sucess -1 otherwise
 */
int
fill_peer_node_info_t(pfcp_session_t *sess, node_address_t *cp_node_addr);

/**
 * @brief  : Function to fill the FQ-CSID in session establishment response.
 * @param  : pfcp_sess_est_rsp, Session EST Resp Obj
 * @param  : pfcp_session_t session info.
 * @return : Returns 0 sucess -1 otherwise
 */
int8_t
fill_fqcsid_sess_est_rsp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, pfcp_session_t *sess);

/**
 * @brief  : Function to process received pfcp session set deletion request.
 * @param  : pfcp_sess_set_del_req, decoded request info
 * @return : Returns 0 sucess -1 otherwise
 */
int8_t
process_up_sess_set_del_req(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req);

/**
 * @brief  : Function to Cleanup Session information by local csid.
 * @param  : node_addr, peer node address
 * @param  : iface, interface info.
 * @return : Returns 0 sucess -1 otherwise
 */
int8_t
up_del_pfcp_peer_node_sess(node_address_t *node_addr, uint8_t iface);

/**
 * @brief  : Function to cleanup session by linked CSID.
 * @param  : pfcp_session_t session info.
 * @param  : csids, local csids list
 * @param  : iface, interface info
 * @return : Returns 0 sucess -1 otherwise
 */
int8_t
del_sess_by_csid_entry(pfcp_session_t *sess, fqcsid_t *csids, uint8_t iface);

#endif /* USE_CSID */

#ifdef PRINT_NEW_RULE_ENTRY
/**
 * @brief  : Function to print received pcc rule information.
 * @param  : pcc, pcc rule info
 * @return : Nothing
 */
void
print_pcc_val(struct pcc_rules *pcc);

/**
 * @brief  : Function to print adc received rule type.
 * @param  : adc, adc rule info
 * @return : Nothing
 */
void
print_sel_type_val(struct adc_rules *adc);

/**
 * @brief  : Function to print the received adc rule info.
 * @param  : adc, adc info
 * @return : Nothing
 */
void
print_adc_val(struct adc_rules *adc);

/**
 * @brief  : Function to print the meter rule info.
 * @param  : mtr, meter info
 * @return : Nothing
 */
void
print_mtr_val(struct mtr_entry *mtr);

/**
 * @brief  : Function to print the sdf rule info.
 * @param  : sdf, sdf info
 * @return : Nothing
 */
void
print_sdf_val(struct pkt_filter *sdf);
#endif /* PRINT_NEW_RULE_ENTRY */

/**
 * @brief  : Function to process received adc type info.
 * @param  : sel_type, adce rule info
 * @param  : arm, string pointer
 * @param  : adc, adc info
 * @return : 0: Success, -1: otherwise
 */
void dp_sig_handler(int signo);

/**
 * @brief  : Function to process received adc type info.
 * @param  : sel_type, adce rule info
 * @param  : arm, string pointer
 * @param  : adc, adc info
 * @return : 0: Success, -1: otherwise
 */
int
parse_adc_buf(int sel_type, char *arm, struct adc_rules *adc);

/**
 * @Name : get_sdf_indices
 * @argument :
 * [IN] sdf_idx : String containing comma separater SDF index values
 * [OUT] out_sdf_idx : Array of integers converted from sdf_idx
 * @return : 0 - success, -1 fail
 * @Description : Convert sdf_idx array in to array of integers for SDF index
 * values.
 * Sample input : "[0, 1, 2, 3]"
 */
uint32_t
get_sdf_indices(char *sdf_idx, uint32_t *out_sdf_idx);

/***********************ddn_utils.c functions end**********************/

/**
 * @brief  : Start Timer for flush inactive TEIDRI value and peer addr.
 * @param  : No Param.
 * @return : Returns
 *           true - on success.
 *           false - on fail.
 */
bool
start_dp_teidri_timer(void);

/**
 * @brief  : TEIDRI Timer Callback.
 * @param  : ti, holds information about timer
 * @param  : data_t, Peer node related information
 * @return : Returns nothing
 */
void
teidri_timer_cb(gstimerinfo_t *ti, const void *data_t );

/**
 * @brief  : fill dp configuration
 * @param  : dp configuration pointer
 * @return : Return status code
 */
int8_t fill_dp_configuration(dp_configuration_t *dp_configuration);

/**
 * @brief  : post periodic timer
 * @param  : periodic_timer_value, Int
 * @return : Returns status code
 */
int8_t post_periodic_timer(const int periodic_timer_value);

/**
 * @brief  : post transmit timer
 * @param  : transmit_timer_value, Int
 * @return : Returns status code
 */
int8_t post_transmit_timer(const int transmit_timer_value);

/**
 * @brief  : post transmit count
 * @param  : transmit_count, Int
 * @return : Returns status code
 */
int8_t post_transmit_count(const int transmit_count);

/**
 * @brief  : post pcap generation status
 * @param  : pcap_status, Int
 * @return : Returns status code
 */
int8_t post_pcap_status(const int pcap_status);
/**
 * @brief  : get periodic timer value
 * @param  : void
 * @return : Returns periodic timer value
 */
int get_periodic_timer(void);

/**
 * @brief  : update perf flag
 * @param  : perf_flag, Int
 * @return : Returns status code
 */
int8_t	update_perf_flag(const int perf_flag);

/**
 * @brief  : get transmit timer value
 * @param  : void
 * @return : Returns transmit timer value
 */
int get_transmit_timer(void);

/**
 * @brief  : get transmit count value
 * @param  : void
 * @return : Returns transmit count value
 */
int get_transmit_count(void);

/**
 * @brief  : get pcap status
 * @param  : void
 * @return : Returns pcap status value
 */
int8_t get_pcap_status(void);

/**
 * @brief  : get perf flag value
 * @param  : void
 * @return : Returns perf flag value
 */
uint8_t	get_perf_flag(void);

/**
 * @brief  : check IPv6 address is NULL or not
 * @param  : IPv6 Address
 * @return : Returns 0 or bytes
 */
int
isIPv6Present(struct in6_addr *ipv6_addr);

/**
 * @brief  : Update and send the error indicaion pkts to peer node
 * @param  : gtpu_pkt, data pkt
 * @param  : port id
 * @return : NULL
 */
void send_error_indication_pkt(struct rte_mbuf *gtpu_pkt, uint8_t port_id);
#endif /* _MAIN_H_ */

