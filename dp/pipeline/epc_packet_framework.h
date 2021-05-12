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

#ifndef __EPC_PACKET_FRAMEWORK_H__
#define __EPC_PACKET_FRAMEWORK_H__

/**
 * @file
 * This file contains data structure definitions to describe Data Plane
 * pipeline and function prototypes used to initialize pipeline.
 */
#include <rte_pipeline.h>
#include <rte_hash_crc.h>

extern uint64_t num_dns_processed;

/**
 * RTE Log type.
 */
#define RTE_LOGTYPE_EPC	RTE_LOGTYPE_USER1

/**
 * Number of ports.
 */
#define NUM_SPGW_PORTS		2

/**
 * Pipeline name size.
 */
#define PIPE_NAME_SIZE		80

/**
 * S1U port id.
 */
#define S1U_PORT_ID   0
#define WEST_PORT_ID   0

/**
 * SGI port id.
 */

#define SGI_PORT_ID   1
#define EAST_PORT_ID   1

/* Per worker macros for DDN */
/* Macro to specify size of DDN notify_ring */
#define NOTIFY_RING_SIZE 2048
/* Macro to specify size of DDN notify_ring */
#define DL_RING_CONTAINER_SIZE (2048 * 2)
#define DL_PKT_POOL_SIZE (1024 * 32)
#define DL_PKT_POOL_CACHE_SIZE 32
#define DL_PKTS_BUF_RING_SIZE 1024

/* TODO: Define the appropriate ring size based on the PPS value, Temp Set to 65K approx */
#define DL_PKTS_RING_SIZE (1 << 16)
#define UL_PKTS_RING_SIZE (1 << 16)

/* Borrowed from dpdk ip_frag_internal.c */
#define PRIME_VALUE	0xeaad8405

/**
 * @brief  : DL Bearer Map key for hash lookup
 */
struct dl_bm_key {
	/** Ue ip */
	ue_ip_t ue_ip;
	/** Rule id */
	uint32_t rid;
};

/**
 * @brief  : Meta data used for directing packets to cores
 */
struct epc_meta_data {
	/** pipeline output port ID */
	uint32_t port_id;
	/** UE IPv4 hash for load balancing */
	uint32_t ue_ipv4_hash;
	/** flag for DNS pkt */
	uint32_t dns;
	union {
		/** eNB IPv4 from GTP-U */
		uint32_t enb_ipv4;
		/** eNB IPv6 from GTP-U */
		struct in6_addr enb_ipv6;
	} ip_type_t;
	/** Teid from GTP-U */
	uint32_t teid;
	/** DL Bearer Map key */
	struct dl_bm_key key;
};

/*
 * Defines the frequency when each pipeline stage should be flushed.
 * For example,
 * 1 = flush the pipeline stage each time it is executed
 * 4 = flush the pipeline stage every four times it is executed
 * Generally "1" gives the best value for both performance
 * and latency, but under
 * certain circumstances (i.e. very small packets resulting in
 * very high packet rate)
 * a larger number may provide better overall CPU efficiency.
 */
#define EPC_PIPELINE_FLUSH_MAX	1

/*
 * Can only support as many lcores as the number of ports allowed in
 * a pipeline block
 */

#define DP_MAX_LCORE RTE_PIPELINE_PORT_OUT_MAX

/** UL pipeline parameters - Per input port */
uint32_t dl_ndata_pkts;
uint32_t ul_ndata_pkts;
uint32_t ul_arp_pkt;
uint32_t ul_gtpu_pkt;

uint32_t ul_pkts_nbrst;
uint32_t ul_pkts_nbrst_prv;

/**
 * @brief  : Maintains epc uplink parameters
 */
struct epc_ul_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id;
	/** Output port IDs  [0]-> load balance, [1]-> master
	  * control thr
	  */
	uint32_t port_out_id[2];
	/** Table ID - ports connect to this table */
	uint32_t table_id;
	/** Notify port id */
	uint32_t notify_port;
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
	/** Number of dns packets cloned by this worker */
	uint64_t num_dns_packets;
	/** Holds a set of rings to be used for downlink data buffering */
	struct rte_ring *dl_ring_container;
	/** Number of DL rings currently created */
	uint32_t num_dl_rings;
	/** For notification of modify_session so that buffered packets
	 * can be dequeued*/
	struct rte_ring *notify_ring;
	/** Pool for notification msg pkts */
	struct rte_mempool *notify_msg_pool;
	/** Holds number of packets received by uplink */
	uint32_t pkts_in;
	/** Holds number of packets sent out after uplink processing */
	uint32_t pkts_out;
	/** Holds number of echo packets received by uplink */
	uint32_t pkts_echo;
	/** Holds number of router solicitation packets received by uplink */
	uint32_t pkts_rs_in;
	/** Holds number of router advertisement packets sent out after uplink processed */
	uint32_t pkts_rs_out;
	/** Holds number of error indication packets received */
	uint32_t pkts_err_in;
	/** Holds number of error indication packets sent out */
	uint32_t pkts_err_out;
} __rte_cache_aligned;
typedef int (*epc_ul_handler) (struct rte_pipeline*, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, int wk_index);

/** DL pipeline parameters - Per input port */
uint32_t dl_arp_pkt;
uint32_t dl_sgi_pkt;

uint32_t dl_pkts_nbrst;
uint32_t dl_pkts_nbrst_prv;

/**
 * @brief  : Maintains epc downlink parameters
 */
struct epc_dl_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id;
	/** Output port IDs  [0]-> load balance, [1]-> master
	  * control thr
	  */
	uint32_t port_out_id[2];
	/** Table ID - ports connect to this table */
	uint32_t table_id;
	/** Notify port id */
	uint32_t notify_port;
	/** RTE pipeline */
	struct rte_pipeline *pipeline;
	/** pipeline name */
	char name[PIPE_NAME_SIZE];
	/** Number of dns packets cloned by this worker */
	uint64_t num_dns_packets;
	/** Holds a set of rings to be used for downlink data buffering */
	struct rte_ring *dl_ring_container;
	/** Number of DL rings currently created */
	uint32_t num_dl_rings;
	/** For notification of modify_session so that buffered packets
	 * can be dequeued*/
	struct rte_ring *notify_ring;
	/** Pool for notification msg pkts */
	struct rte_mempool *notify_msg_pool;
	/** Holds number of packets received by downlink */
	uint32_t pkts_in;
	/** Holds number of packets sent out after downlink processing */
	uint32_t pkts_out;
	/** Holds number of packets queued for until DDN ACK not received */
	uint32_t ddn_buf_pkts;
	/** Holds number of ddn request sends */
	uint32_t ddn;
	/** Holds number of error indication packets received */
	uint32_t pkts_err_in;
	/** Holds number of error indication packets sent out */
	uint32_t pkts_err_out;
} __rte_cache_aligned;
typedef int (*epc_dl_handler) (struct rte_pipeline*, struct rte_mbuf **pkts,
		uint32_t n, uint64_t *pkts_mask, int wk_index);

/* defines max number of pipelines per core */
#define EPC_PIPELINE_MAX	4

/**
 * @brief  : pipeline function
 * @param  : No param
 * @return : Returns nothing
 */
typedef void pipeline_func_t(void *param);

/**
 * @brief  : Maintains pipeline function pointer and argument
 */
struct pipeline_launch {
	pipeline_func_t *func;	/* pipeline function called */
	void *arg;		/* pipeline function argument */
};

/**
 * @brief  : Maintains epc lcore configuration parameter
 */
struct epc_lcore_config {
	int allocated;		/* indicates a number of pipelines enebled */
	struct pipeline_launch launch[EPC_PIPELINE_MAX];
};

/**
 * @brief  : Maintains epc parameter
 */
struct epc_app_params {
	/* CPU cores */
	struct epc_lcore_config lcores[DP_MAX_LCORE];
	int core_mct;
	int core_iface;
	int core_stats;
	int core_spns_dns;
	int core_ul[NUM_SPGW_PORTS];
	int core_dl[NUM_SPGW_PORTS];
	/* NGCORE_SHRINK::NUM_WORKER = 1 */
	unsigned num_workers;
	unsigned worker_cores[DP_MAX_LCORE];
	unsigned worker_core_mapping[DP_MAX_LCORE];

	/* Ports */
	uint32_t ports[NUM_SPGW_PORTS];
	uint32_t n_ports;
	uint32_t port_rx_ring_size;
	uint32_t port_tx_ring_size;

	/* Rx rings */
	struct rte_ring *epc_lb_rx[NUM_SPGW_PORTS];
	struct rte_ring *epc_mct_rx[NUM_SPGW_PORTS];
	struct rte_ring *epc_mct_spns_dns_rx;
	struct rte_ring *epc_work_rx[DP_MAX_LCORE][NUM_SPGW_PORTS];

	/* Tx rings */
	struct rte_ring *ring_tx[DP_MAX_LCORE][NUM_SPGW_PORTS];

	uint32_t ring_rx_size;
	uint32_t ring_tx_size;

	/* Burst sizes */
	uint32_t burst_size_rx_read;
	uint32_t burst_size_rx_write;
	uint32_t burst_size_worker_read;
	uint32_t burst_size_worker_write;
	uint32_t burst_size_tx_read;
	uint32_t burst_size_tx_write;

	/* Pipeline params */
	struct epc_ul_params ul_params[NUM_SPGW_PORTS];
	struct epc_dl_params dl_params[NUM_SPGW_PORTS];
} __rte_cache_aligned;

extern struct epc_app_params epc_app;

/**
 * @brief  : Adds pipeline function to core's list of pipelines to run
 * @param  : func, Function to run
 * @param  : arg, Argument to pipeline function
 * @param  : core, Core to run pipeline function on
 * @return : Returns nothing
 */
void epc_alloc_lcore(pipeline_func_t func, void *arg, int core);

/**
 * @brief  : Initializes arp icmp pipeline
 * @param  : No param
 * @return : Returns nothing
 */
void epc_arp_init(void);

/**
 * @brief  : Returns the mac address for an IP address, currently works only for directly
 *           connected neighbours
 * @param  : ipaddr, IP address to lookup
 * @param  : phy_port, Identifies the port to which the IP address is connected to
 * @param  : hw_addr, Ethernet address returned
 * @param  : nhip, next-hop IP address
 *           Note - Same as ip addr (for now)
 * @return : Returns 0 in case of success , -1 otherwise
 */
int arp_icmp_get_dest_mac_address(const uint32_t ipaddr,
		const uint32_t phy_port,
		struct ether_addr *hw_addr, uint32_t *nhip);

/**
 * @brief  : ARP/ICMP pipeline function
 * @param  : arg, unused parameter
 * @return : Returns nothing
 */
void epc_arp(__rte_unused void *arg);

void process_li_data();

/**
 * @brief  : Initializes DNS processing resources
 * @param  : No param
 * @return : Returns nothing
 */
void epc_spns_dns_init(void);

/**
 * @brief  : Initialize EPC packet framework
 * @param  : s1u_port_id, Port id for s1u interface assigned by rte
 * @param  : sgi_port_id, Port id for sgi interface assigned by rte
 * @return : Returns nothing
 */
void epc_init_packet_framework(uint8_t east_port_id, uint8_t west_port_id);

/**
 * @brief  : Launches data plane threads to execute pipeline funcs
 * @param  : No param
 * @return : Returns nothing
 */
void packet_framework_launch(void);

/**
 * @brief  : Initializes UL pipeline
 * @param  : param, Pipeline parameters passed on to pipeline at runtime
 * @param  : core, Core to run Rx pipeline, used to warn if this core and the NIC port_id
 *           are in different NUMA domains
 * @param  : in_port_id, Input Port ID
 * @param  : out_port_id, Input Port ID & Output Port ID
 * @return : Returns nothing
 */
void epc_ul_init(struct epc_ul_params *param, int core, uint8_t in_port_id, uint8_t out_port_id);

/**
 * @brief  : Initializes DL pipeline
 * @param  : param, Pipeline parameters passed on to pipeline at runtime
 * @param  : core, Core to run Rx pipeline, used to warn if this core and the NIC port_id
 *           are in different NUMA domains
 * @param  : in_port_id, Input Port ID
 * @param  : out_port_id, Input Port ID & Output Port ID
 * @return : Returns nothing
 *
 */
void epc_dl_init(struct epc_dl_params *param, int core, uint8_t in_port_id, uint8_t out_port_id);

/**
 * @brief  : UL pipeline function
 * @param  : args, Pipeline parameters
 * @return : Returns nothing
 */
void epc_ul(void *args);

/**
 * @brief  : DL pipeline function
 * @param  : args, Pipeline parameters
 * @return : Returns nothing
 */
void epc_dl(void *args);

/**
 * @brief  : Registers uplink worker function that is executed from the pipeline
 * @param  : f, Function handler for packet processing
 * @param  : port, Port to register the worker function for
 * @return : Returns nothing
 */
void register_ul_worker(epc_ul_handler f, int port);

/**
 * @brief  : Registers downlink worker function that is executed from the pipeline
 * @param  : f, Function handler for packet processing
 * @param  : port, Port to register the worker function for
 * @return : Returns nothing
 */
void register_dl_worker(epc_dl_handler f, int port);

#endif /* __EPC_PACKET_FRAMEWORK_H__ */
