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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_ip.h>
#include <rte_byteorder.h>
#include <rte_table_lpm.h>
#include <rte_table_hash.h>
#include <rte_pipeline.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_port_ring.h>
#include <rte_table_stub.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_ethdev.h>
#include <rte_port_ethdev.h>
#include <rte_kni.h>

#ifdef STATIC_ARP
#include <rte_cfgfile.h>
#endif	/* STATIC_ARP */


/* VS: Routing Discovery */
#include <fcntl.h>
#include "linux/netlink.h"
#include "linux/rtnetlink.h"
#include "net/if.h"
#include "net/if_arp.h"
#include "sys/ioctl.h"
#include "net/route.h"


#include "util.h"
#include "gtpu.h"
#include "ipv4.h"
#include "stats.h"
#include "up_main.h"
#include "epc_arp.h"
#include "epc_packet_framework.h"

#ifdef use_rest
#include "../rest_timer/gstimer.h"
#endif /* use_rest */

#ifdef DP_BUILD
#include "gw_adapter.h"
#include "clogger.h"
#endif


#ifdef STATIC_ARP
#define STATIC_ARP_FILE "../config/static_arp.cfg"
#endif	/* STATIC_ARP */

#if (RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN)
/* x86 == little endian
 * network  == big endian
 */
#define CHECK_ENDIAN_16(x) rte_be_to_cpu_16(x)
#define CHECK_ENDIAN_32(x) rte_be_to_cpu_32(x)
#else
#define CHECK_ENDIAN_16(x) (x)
#define CHECK_ENDIAN_32(x) (x)
#endif
/**
 * no. of mbuf.
 */
#define NB_ARP_MBUF  1024
/**
 * ipv4 version
 */
#define IP_VERSION_4 0x40
/**
 * default IP header length == five 32-bits words.
 */
#define IP_HDRLEN  0x05
/**
 * header def.
 */
#define IP_VHL_DEF (IP_VERSION_4 | IP_HDRLEN)
/**
 * check multicast ipv4 address.
 */
#define is_multicast_ipv4_addr(ipv4_addr) \
	(((rte_be_to_cpu_32((ipv4_addr)) >> 24) & 0x000000FF) == 0xE0)
/**
 * pipeline port out action handler
 */
#define PIPELINE_PORT_OUT_AH(f_ah, f_pkt_work, f_pkt4_work) \
static int							\
f_ah(                    			\
		struct rte_mbuf *pkt,		\
		uint64_t *pkts_mask,		\
		void *arg)					\
{									\
	f_pkt4_work(pkt, arg);			\
	f_pkt_work(pkt, arg);			\
	int i = *pkts_mask; i++;		\
	return 0;						\
}
/**
 * pipeline port out bulk action handler
 */
#define PIPELINE_PORT_OUT_BAH(f_ah, f_pkt_work, f_pkt4_work)	\
static int							\
f_ah(								\
		struct rte_mbuf **pkt,		\
		uint64_t *pkts_mask,		\
		void *arg)					\
{									\
	f_pkt4_work(*pkt, arg);			\
	f_pkt_work(*pkt, arg);			\
	int i = *pkts_mask; i++;		\
	return 0;						\
}

struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];

/**
 * VS: Routing Discovery
 */

#define NETMASK ntohl(4294967040)
#define TABLE_SIZE (8192 * 4)
#define ERR_RET(x) do { perror(x); return EXIT_FAILURE; } while (0);


/**
 * VS: Get Local arp table entry
 */
#define ARP_CACHE       "/proc/net/arp"
#define ARP_BUFFER_LEN  1024
#define ARP_DELIM       " "

#define BUFFER_SIZE 4096

/* VS: buffers */
char ipAddr[128];
char gwAddr[128];
char netMask[128];
int route_sock = -1;
int gatway_flag = 0;


/**
 * @brief  : Structure for sending the request
 */
typedef struct
{
    struct nlmsghdr nlMsgHdr;
    struct rtmsg rtMsg;
    char buf[4096];
}route_request;

/**
 * @brief  : Structure for storing routes
 */
struct RouteInfo
{
	uint32_t dstAddr;
	uint32_t mask;
	uint32_t gateWay;
	uint32_t flags;
	uint32_t srcAddr;
	char proto;
	char ifName[IF_NAMESIZE];
	/** mac address */
	struct ether_addr gateWay_Mac;
};

/**
 * @brief  : print arp table
 * @param  : No param
 * @return : Returns nothing
 */
static void print_arp_table(void);

/**
 * memory pool for arp pkts.
 */
static char *arp_xmpoolname[NUM_SPGW_PORTS] = {
	"arp_icmp_S1Uxmpool",
	"arp_icmp_SGixmpool"
};
struct rte_mempool *arp_xmpool[NUM_SPGW_PORTS];
/**
 * arp pkts buffer.
 */
struct rte_mbuf *arp_pkt[NUM_SPGW_PORTS];

/**
 * memory pool for queued data pkts.
 */
static char *arp_quxmpoolname[NUM_SPGW_PORTS] = {
	"arp_S1Uquxmpool",
	"arp_SGiquxmpool"
};

struct rte_mempool *arp_quxmpool[NUM_SPGW_PORTS];

/**
 * @brief  : hash params.
 */
static struct rte_hash_parameters
	arp_hash_params[NUM_SPGW_PORTS] = {
		{	.name = "ARP_S1U",
			.entries = 64*64,
			.reserved = 0,
			.key_len =
					sizeof(uint32_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0 },
		{
			.name = "ARP_SGI",
			.entries = 64*64,
			.reserved = 0,
			.key_len =
					sizeof(uint32_t),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0 }
};

/**
 * rte hash handler.
 */
/* 2 hash handles, one for S1U and another for SGI */
struct rte_hash *arp_hash_handle[NUM_SPGW_PORTS];

/**
 * arp pipeline
 */
struct rte_pipeline *myP;

/**
 * @brief  : arp port address
 */
struct arp_port_address {
	/** ipv4 address*/
	uint32_t ip;
	/** mac address */
	struct ether_addr *mac_addr;
};

/**
 * ports mac address.
 */
extern struct ether_addr ports_eth_addr[];
/**
 * arp port address
 */
static struct arp_port_address arp_port_addresses[RTE_MAX_ETHPORTS];

/**
 * @brief  : arp params structure.
 */
struct epc_arp_params {
	/** Count since last flush */
	int flush_count;
	/** Number of pipeline runs between flush */
	int flush_max;
	/** RTE pipeline params */
	struct rte_pipeline_params pipeline_params;
	/** Input port id */
	uint32_t port_in_id[NUM_SPGW_PORTS];
	/** Output port IDs */
	uint32_t port_out_id[NUM_SPGW_PORTS];
	/** table id */
	uint32_t table_id;
	/** RTE pipeline name*/
	char   name[PIPE_NAME_SIZE];
} __rte_cache_aligned;

/**
 * global arp param variable.
 */
static struct epc_arp_params arp_params;

uint32_t pkt_hit_count;
uint32_t pkt_miss_count;
uint32_t pkt_key_count;
uint32_t pkt_out_count;

/**
 * @brief  : arp icmp route table details
 */
struct arp_icmp_route_table_entry {
	uint32_t ip;
	uint32_t mask;
	uint32_t port;
	uint32_t nh;
};

struct ether_addr broadcast_ether_addr = {
	.addr_bytes[0] = 0xFF,
	.addr_bytes[1] = 0xFF,
	.addr_bytes[2] = 0xFF,
	.addr_bytes[3] = 0xFF,
	.addr_bytes[4] = 0xFF,
	.addr_bytes[5] = 0xFF,
};
static const struct ether_addr null_ether_addr = {
	.addr_bytes[0] = 0x00,
	.addr_bytes[1] = 0x00,
	.addr_bytes[2] = 0x00,
	.addr_bytes[3] = 0x00,
	.addr_bytes[4] = 0x00,
	.addr_bytes[5] = 0x00,
};

/**
 * @brief  : Print Ip address
 * @param  : ip , ip address
 * @return : Returns nothing
 */
static void print_ip(int ip)
{
	unsigned char bytes[4];
	bytes[0] = ip & 0xFF;
	bytes[1] = (ip >> 8) & 0xFF;
	bytes[2] = (ip >> 16) & 0xFF;
	bytes[3] = (ip >> 24) & 0xFF;
	clLog(clSystemLog, eCLSeverityDebug,"%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}

/**
 * @brief  : Add entry in ARP table.
 * @param  : arp_key, key.
 * @param  : ret_arp_data, arp data
 * @param  : portid, port
 * @return : Returns nothing
 */
static void add_arp_data(
			struct arp_ipv4_key *arp_key,
			struct arp_entry_data *ret_arp_data, uint8_t portid) {
	int ret;
	/* ARP Entry not present. Add ARP Entry */
	ret = rte_hash_add_key_data(arp_hash_handle[portid],
					&(arp_key->ip), ret_arp_data);
	if (ret) {
		/* Add arp_data panic because:
		 * ret == -EINVAL &&  wrong parameter ||
		 * ret == -ENOSPC && hash table size insufficient
		 * */
		rte_panic("ARP: Error at:%s::"
				"\n\tadd arp_data= %s"
				"\n\tError= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&arp_key->ip),
				rte_strerror(abs(ret)));
	}
}

/**
 * returns 0 if packet was queued
 * return 1 if arp was resolved prior to acquiring lock - not queued - to be forwarded
 * return -1 if packet could not be queued - no ring
 */
int arp_qunresolved_ulpkt(struct arp_entry_data *arp_data,
				struct rte_mbuf *m, uint8_t portid)
{
	int ret;
	struct rte_mbuf *buf_pkt =
			rte_pktmbuf_clone(m, arp_quxmpool[portid]);

	struct epc_meta_data *from_meta_data;
	struct epc_meta_data *to_meta_data;

	if (buf_pkt == NULL) {
		clLog(clSystemLog, eCLSeverityDebug, "ARP:%s::"
				"\n\tError rte_pktmbuf_clone... Dropping pkt"
				"\n\tarp_data->ip= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&arp_data->ip));
		clLog(clSystemLog, eCLSeverityCritical,"%s: Error rte_pktmbuf_clone... Dropping pkt.\n", __func__);
		print_arp_table();
		return -1;
	}

	from_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
		META_DATA_OFFSET);
	to_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(buf_pkt,
		META_DATA_OFFSET);
	*to_meta_data = *from_meta_data;
	ret = rte_ring_enqueue(arp_data->queue, buf_pkt);
	if (ret == -ENOBUFS) {
		rte_pktmbuf_free(buf_pkt);
		clLog(clSystemLog, eCLSeverityDebug, "%s::"
			"\n\tCan't queue pkt- ring full... Dropping pkt"
			"\n\tarp_data->ip= %s\n",
			__func__,
			inet_ntoa(*(struct in_addr *) &arp_data->ip));
	} else {
		if (ARPICMP_DEBUG) {
			clLog(clSystemLog, eCLSeverityMajor, "%s::"
					"\n\tQueued pkt"
					"\n\tarp_data->ip= %20s\n",
					__func__,
					inet_ntoa(*(struct in_addr *) &arp_data->ip));
		}
	}
	return ret;
}

int arp_qunresolved_dlpkt(struct arp_entry_data *arp_data,
				struct rte_mbuf *m, uint8_t portid)
{
	int ret;
	struct rte_mbuf *buf_pkt =
			rte_pktmbuf_clone(m, arp_quxmpool[portid]);

	struct epc_meta_data *from_meta_data;
	struct epc_meta_data *to_meta_data;

	if (buf_pkt == NULL) {
		clLog(clSystemLog, eCLSeverityDebug, "ARP:%s::"
				"\n\tError rte_pktmbuf_clone... Dropping pkt"
				"\n\tarp_data->ip= %s\n",
				__func__,
				inet_ntoa(*(struct in_addr *)&arp_data->ip));
		clLog(clSystemLog, eCLSeverityCritical,"%s: Error rte_pktmbuf_clone... Dropping pkt.\n", __func__);
		print_arp_table();
		return -1;
	}

	from_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(m,
		META_DATA_OFFSET);
	to_meta_data =
		(struct epc_meta_data *)RTE_MBUF_METADATA_UINT8_PTR(buf_pkt,
		META_DATA_OFFSET);
	*to_meta_data = *from_meta_data;

	ret = rte_ring_enqueue(arp_data->queue, buf_pkt);
	if (ret == -ENOBUFS) {
		rte_pktmbuf_free(buf_pkt);
		clLog(clSystemLog, eCLSeverityDebug, "%s::"
			"\n\tCan't queue pkt- ring full... Dropping pkt"
			"\n\tarp_data->ip= %s\n",
			__func__,
			inet_ntoa(*(struct in_addr *) &arp_data->ip));
	} else {
		if (ARPICMP_DEBUG) {
			clLog(clSystemLog, eCLSeverityMajor, "%s::"
					"\n\tQueued pkt"
					"\n\tarp_data->ip= %20s\n",
					__func__,
					inet_ntoa(*(struct in_addr *) &arp_data->ip));
		}
	}
	return ret;
}

/**
 * @brief  : Get arp opration name string
 * @param  : arp_op, opration type
 * @return : Returns arp opration name string
 */
static const char *
arp_op_name(uint16_t arp_op)
{
	switch (CHECK_ENDIAN_16(arp_op)) {
	case (ARP_OP_REQUEST):
		return "ARP Request";
	case (ARP_OP_REPLY):
		return "ARP Reply";
	case (ARP_OP_REVREQUEST):
		return "Reverse ARP Request";
	case (ARP_OP_REVREPLY):
		return "Reverse ARP Reply";
	case (ARP_OP_INVREQUEST):
		return "Peer Identify Request";
	case (ARP_OP_INVREPLY):
		return "Peer Identify Reply";
	default:
		break;
	}
	return "Unkwown ARP op";
}

/**
 * @brief  : Print icmp packet information
 * @param  : icmp_h, icmp header data
 * @return : Returns nothing
 */
static void
print_icmp_packet(struct icmp_hdr *icmp_h)
{
	clLog(clSystemLog, eCLSeverityDebug,"  ICMP: type=%d (%s) code=%d id=%d seqnum=%d\n",
			icmp_h->icmp_type,
			(icmp_h->icmp_type == IP_ICMP_ECHO_REPLY ? "Reply" :
			 (icmp_h->icmp_type == IP_ICMP_ECHO_REQUEST ? "Reqest" : "Undef")),
			icmp_h->icmp_code,
			CHECK_ENDIAN_16(icmp_h->icmp_ident),
			CHECK_ENDIAN_16(icmp_h->icmp_seq_nb));
}

/**
 * @brief  : Print ipv4 packet information
 * @param  : ip_h, ipv4 header data
 * @return : Returns nothing
 */
static void
print_ipv4_h(struct ipv4_hdr *ip_h)
{
	struct icmp_hdr *icmp_h =
				(struct icmp_hdr *)((char *)ip_h +
				sizeof(struct ipv4_hdr));
	clLog(clSystemLog, eCLSeverityDebug,
			"\tIPv4: Version=%d"
			"\n\tHLEN=%d Type=%d Protocol=%d Length=%d\n",
			(ip_h->version_ihl & 0xf0) >> 4,
			(ip_h->version_ihl & 0x0f),
			ip_h->type_of_service,
			ip_h->next_proto_id,
			rte_cpu_to_be_16(ip_h->total_length));
	clLog(clSystemLog, eCLSeverityDebug,"Dst IP:");
	print_ip(ntohl(ip_h->dst_addr));
	clLog(clSystemLog, eCLSeverityDebug,"Src IP:");
	print_ip(ntohl(ip_h->src_addr));

	if (ip_h->next_proto_id == IPPROTO_ICMP) {
		print_icmp_packet(icmp_h);
	}
}

/**
 * @brief  : Print arp packet information
 * @param  : arp_h, arp header data
 * @return : Returns nothing
 */
static void
print_arp_packet(struct arp_hdr *arp_h)
{
	clLog(clSystemLog, eCLSeverityDebug,"  ARP:  hrd=%d proto=0x%04x hln=%d "
			"pln=%d op=%u (%s)\n",
			CHECK_ENDIAN_16(arp_h->arp_hrd),
			CHECK_ENDIAN_16(arp_h->arp_pro), arp_h->arp_hln,
			arp_h->arp_pln, CHECK_ENDIAN_16(arp_h->arp_op),
			arp_op_name(arp_h->arp_op));

	if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
		clLog(clSystemLog, eCLSeverityDebug,"incorrect arp_hrd format for IPv4 ARP (%d)\n",
				(arp_h->arp_hrd));
	} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
		clLog(clSystemLog, eCLSeverityDebug,"incorrect arp_pro format for IPv4 ARP (%d)\n",
				(arp_h->arp_pro));
	} else if (arp_h->arp_hln != 6) {
		clLog(clSystemLog, eCLSeverityDebug,"incorrect arp_hln format for IPv4 ARP (%d)\n",
				arp_h->arp_hln);
	} else if (arp_h->arp_pln != 4) {
		clLog(clSystemLog, eCLSeverityDebug,"incorrect arp_pln format for IPv4 ARP (%d)\n",
				arp_h->arp_pln);
	} else {
		clLog(clSystemLog, eCLSeverityDebug,"  sha=%02X:%02X:%02X:%02X:%02X:%02X",
				arp_h->arp_data.arp_sha.addr_bytes[0],
				arp_h->arp_data.arp_sha.addr_bytes[1],
				arp_h->arp_data.arp_sha.addr_bytes[2],
				arp_h->arp_data.arp_sha.addr_bytes[3],
				arp_h->arp_data.arp_sha.addr_bytes[4],
				arp_h->arp_data.arp_sha.addr_bytes[5]);
		clLog(clSystemLog, eCLSeverityDebug," sip=%d.%d.%d.%d\n",
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 24) &
								0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 16) &
								0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >>  8) &
								0xFF,
				CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) &
								0xFF);
		clLog(clSystemLog, eCLSeverityDebug,"  tha=%02X:%02X:%02X:%02X:%02X:%02X",
				arp_h->arp_data.arp_tha.addr_bytes[0],
				arp_h->arp_data.arp_tha.addr_bytes[1],
				arp_h->arp_data.arp_tha.addr_bytes[2],
				arp_h->arp_data.arp_tha.addr_bytes[3],
				arp_h->arp_data.arp_tha.addr_bytes[4],
				arp_h->arp_data.arp_tha.addr_bytes[5]);
		clLog(clSystemLog, eCLSeverityDebug," tip=%d.%d.%d.%d\n",
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 24) &
								0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >> 16) &
								0xFF,
				(CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) >>  8) &
								0xFF,
				CHECK_ENDIAN_32(arp_h->arp_data.arp_tip) &
								0xFF);
	}
}

/**
 * @brief  : Print ethernet data
 * @param  : eth_h, ethernet header data
 * @return : Returns nothing
 */
static void
print_eth(struct ether_hdr *eth_h)
{
	clLog(clSystemLog, eCLSeverityDebug,"  ETH:  src=%02X:%02X:%02X:%02X:%02X:%02X",
			eth_h->s_addr.addr_bytes[0],
			eth_h->s_addr.addr_bytes[1],
			eth_h->s_addr.addr_bytes[2],
			eth_h->s_addr.addr_bytes[3],
			eth_h->s_addr.addr_bytes[4],
			eth_h->s_addr.addr_bytes[5]);
	clLog(clSystemLog, eCLSeverityDebug," dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
			eth_h->d_addr.addr_bytes[0],
			eth_h->d_addr.addr_bytes[1],
			eth_h->d_addr.addr_bytes[2],
			eth_h->d_addr.addr_bytes[3],
			eth_h->d_addr.addr_bytes[4],
			eth_h->d_addr.addr_bytes[5]);

}

void
print_mbuf(const char *rx_tx, unsigned portid,
			struct rte_mbuf *mbuf, unsigned line)
{
	struct ether_hdr *eth_h =
			rte_pktmbuf_mtod(mbuf, struct ether_hdr *);
	struct arp_hdr *arp_h =
				(struct arp_hdr *)((char *)eth_h +
				sizeof(struct ether_hdr));
	struct ipv4_hdr *ipv4_h =
				(struct ipv4_hdr *)((char *)eth_h +
				sizeof(struct ether_hdr));

	clLog(clSystemLog, eCLSeverityDebug,"%s(%u): on port %u pkt-len=%u nb-segs=%u\n",
			rx_tx, line, portid, mbuf->pkt_len, mbuf->nb_segs);
	print_eth(eth_h);
	switch (rte_cpu_to_be_16(eth_h->ether_type)) {
	case ETHER_TYPE_IPv4:
		print_ipv4_h(ipv4_h);
		break;
	case ETHER_TYPE_ARP:
		print_arp_packet(arp_h);
		break;
	default:
		clLog(clSystemLog, eCLSeverityDebug,"  unknown packet type\n");
		break;
	}
	fflush(stdout);
}

struct arp_entry_data *
retrieve_arp_entry(struct arp_ipv4_key arp_key,
		uint8_t portid)
{
	int ret;
	struct arp_entry_data *ret_arp_data = NULL;
	struct RouteInfo *route_entry = NULL;
	if (ARPICMP_DEBUG)
		clLog(clSystemLog, eCLSeverityDebug,"%s::"
				"\n\tretrieve_arp_entry for ip 0x%x\n",
				__func__, arp_key.ip);

	ret = rte_hash_lookup_data(arp_hash_handle[portid],
					&arp_key.ip, (void **)&ret_arp_data);
	if (ret < 0) {
		/* Compute the key(subnet) based on netmask is 24 */
		struct RouteInfo key;
		key.dstAddr = (arp_key.ip & NETMASK);

		ret = rte_hash_lookup_data(route_hash_handle,
						&key.dstAddr, (void **)&route_entry);


		if (ret == 0) {
			if ((route_entry->gateWay != 0) && (route_entry->gateWay_Mac.addr_bytes != 0)) {
					/* Fill the gateway entry */
					ret_arp_data =
							rte_malloc_socket(NULL,
									sizeof(struct arp_entry_data),
									RTE_CACHE_LINE_SIZE, rte_socket_id());
					ret_arp_data->last_update = time(NULL);
					ret_arp_data->status = COMPLETE;
					ret_arp_data->ip = route_entry->gateWay;
					ret_arp_data->eth_addr = route_entry->gateWay_Mac;
					return ret_arp_data;

			} else if ((route_entry->gateWay != 0) && (route_entry->gateWay_Mac.addr_bytes == 0)) {
						struct arp_ipv4_key gw_arp_key;
						gw_arp_key.ip = route_entry->gateWay;
						clLog(clSystemLog, eCLSeverityInfo, "GateWay ARP entry not found for %s!!!\n",
								inet_ntoa(*((struct in_addr *)&gw_arp_key.ip)));
						/* No arp entry for arp_key.ip
						 * Add arp_data for arp_key.ip at
						 * arp_hash_handle[portid]
						 * */
						ret_arp_data =
								rte_malloc_socket(NULL,
										sizeof(struct arp_entry_data),
										RTE_CACHE_LINE_SIZE, rte_socket_id());
						ret_arp_data->last_update = time(NULL);
						ret_arp_data->status = INCOMPLETE;
						add_arp_data(&gw_arp_key, ret_arp_data, portid);

						/* Added arp_data for gw_arp_key.ip at
						 * arp_hash_handle[portid]
						 * Queue arp_data in arp_pkt mbuf
						 * send_arp_req(portid, gw_arp_key.ip)
						 * */
						ret_arp_data->ip = gw_arp_key.ip;
						ret_arp_data->queue = rte_ring_create(
								inet_ntoa(*((struct in_addr *)&gw_arp_key.ip)),
								ARP_BUFFER_RING_SIZE,
								rte_socket_id(), 0);

						if (ret_arp_data->queue == NULL) {
							clLog(clSystemLog, eCLSeverityDebug,"%s::"
									"\n\tARP ring create error"
									"\n\tarp_key.ip= %s; portid= %d"
									"\n\tError=%s::errno(%d)\n",
									__func__,
									inet_ntoa(*(struct in_addr *)&gw_arp_key.ip),
									portid,
									rte_strerror(abs(rte_errno)), rte_errno);
							print_arp_table();
							if (rte_errno == EEXIST) {
								rte_free(ret_arp_data);
								ret_arp_data = NULL;
							}
						}
					return ret_arp_data;
				}
			}

		clLog(clSystemLog, eCLSeverityInfo, "ARP entry not found for %s!!!\n",
				inet_ntoa(*((struct in_addr *)&arp_key.ip)));
		/* No arp entry for arp_key.ip
		 * Add arp_data for arp_key.ip at
		 * arp_hash_handle[portid]
		 * */
		ret_arp_data =
				rte_malloc_socket(NULL,
						sizeof(struct arp_entry_data),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
		ret_arp_data->last_update = time(NULL);
		ret_arp_data->status = INCOMPLETE;
		add_arp_data(&arp_key, ret_arp_data, portid);

		/* Added arp_data for arp_key.ip at
		 * arp_hash_handle[portid]
		 * Queue arp_data in arp_pkt mbuf
		 * send_arp_req(portid, arp_key.ip)
		 * */
		ret_arp_data->ip = arp_key.ip;
		ret_arp_data->queue = rte_ring_create(
				inet_ntoa(*((struct in_addr *)&arp_key.ip)),
				ARP_BUFFER_RING_SIZE,
				rte_socket_id(), 0);

		if (ret_arp_data->queue == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,"%s::"
					"\n\tARP ring create error"
					"\n\tarp_key.ip= %s; portid= %d"
					"\n\tError=%s::errno(%d)\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&arp_key.ip),
					portid,
					rte_strerror(abs(rte_errno)), rte_errno);
			print_arp_table();
			if (rte_errno == EEXIST) {
				rte_free(ret_arp_data);
				ret_arp_data = NULL;
			}
		}
	}
	return ret_arp_data;
}

void
print_arp_table(void)
{
	const void *next_key;
	void *next_data;
	uint32_t iter = 0;

	uint8_t port_cnt = 0;
	for (; port_cnt < NUM_SPGW_PORTS; ++port_cnt) {
		while (
				rte_hash_iterate(
							arp_hash_handle[port_cnt],
							&next_key, &next_data, &iter
							) >= 0) {

			struct arp_entry_data *tmp_arp_data =
					(struct arp_entry_data *)next_data;
			struct arp_ipv4_key tmp_arp_key;

			memcpy(&tmp_arp_key, next_key,
					sizeof(struct arp_ipv4_key));
			clLog(clSystemLog, eCLSeverityDebug,"\t%02X:%02X:%02X:%02X:%02X:%02X  %10s  %s\n",
					tmp_arp_data->eth_addr.addr_bytes[0],
					tmp_arp_data->eth_addr.addr_bytes[1],
					tmp_arp_data->eth_addr.addr_bytes[2],
					tmp_arp_data->eth_addr.addr_bytes[3],
					tmp_arp_data->eth_addr.addr_bytes[4],
					tmp_arp_data->eth_addr.addr_bytes[5],
					tmp_arp_data->status == COMPLETE ? "COMPLETE" : "INCOMPLETE",
					inet_ntoa(
						*((struct in_addr *)(&tmp_arp_data->ip))));
		}
	}
}

/**
 * @brief  : Forward buffered arp packets
 * @param  : queue, packet queue pointer
 * @param  : hw_addr, ethernet address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static void
arp_send_buffered_pkts(struct rte_ring *queue,
			const struct ether_addr *hw_addr, uint8_t portid)
{
	unsigned ring_count = rte_ring_count(queue);
	unsigned count = 0;

	while (!rte_ring_empty(queue)) {
		struct rte_mbuf *pkt;
		int ret = rte_ring_dequeue(queue, (void **) &pkt);
		if (ret == 0) {
			struct ether_hdr *e_hdr =
				rte_pktmbuf_mtod(pkt, struct ether_hdr *);
			ether_addr_copy(hw_addr, &e_hdr->d_addr);
			ether_addr_copy(&ports_eth_addr[portid],
					&e_hdr->s_addr);
			if (rte_ring_enqueue(shared_ring[portid], pkt) == -ENOBUFS) {
				rte_pktmbuf_free(pkt);
				clLog(clSystemLog, eCLSeverityCritical, "%s::Can't queue pkt- ring full..."
						" Dropping pkt\n", __func__);
				continue;
			}
			++count;
		}
	}
#ifdef NGCORE_SHRINK
#ifdef STATS
	if (portid == SGI_PORT_ID) {
		epc_app.ul_params[S1U_PORT_ID].pkts_out +=  count;
	} else if (portid == S1U_PORT_ID) {
		epc_app.dl_params[SGI_PORT_ID].pkts_out += count;
	}
#endif /* STATS */
#endif /* NGCORE_SHRINK */

	if (ARPICMP_DEBUG) {
		clLog(clSystemLog, eCLSeverityDebug,"%s::"
				"\n\tForwarded count pkts=  %u"
				"\n\tOut of pkts in ring= %u\n",
				__func__, count, ring_count);
	}

	rte_ring_free(queue);
	//queue = NULL;
}

#ifdef USE_REST
/**
 * @brief  : Function to process GTP-U echo response
 * @param  : echo_pkt, rte_mbuf pointer
 * @return : Returns nothing
 */
static void
process_echo_response(struct rte_mbuf *echo_pkt)
{

	int ret = 0;
	peerData *conn_data = NULL;

	//uint8_t rest_cnt = 0;
	//struct ether_hdr *eth_h = rte_pktmbuf_mtod(echo_pkt, struct ether_hdr *);
	//struct ether_addr tmp_mac;
	//ether_addr_copy(&eth_h->s_addr, &tmp_mac);

	/* Retrive src IP addresses */
	struct ipv4_hdr *ip_hdr = get_mtoip(echo_pkt);

	//struct gtpu_hdr *gtpu_hdr = get_mtogtpu(echo_pkt);
	//gtpu_recovery_ie *recovery_ie = (gtpu_recovery_ie*)(rte_pktmbuf_mtod(echo_pkt, unsigned char *) +
	//		ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + GTPU_HDR_SIZE);
	//recovery_ie = (gtpu_recovery_ie*)((char*)gtpu_hdr+
	//		GTPU_HDR_SIZE + ntohs(gtpu_hdr->msglen));
	//rest_cnt = recovery_ie->restart_cntr;
	//

	/* VS: TODO */
	ret = rte_hash_lookup_data(conn_hash_handle,
				&ip_hdr->src_addr, (void **)&conn_data);

	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityDebug, " Entry not found for NODE :%s\n",
							inet_ntoa(*(struct in_addr *)&ip_hdr->src_addr));
		return;

	} else {
		conn_data->itr_cnt = 0;

		update_peer_timeouts(ip_hdr->src_addr,0);

		/* Reset Activity flag */
		conn_data->activityFlag = 0;
		/* Stop transmit timer for specific Node */
		stopTimer( &conn_data->tt );
		/* Stop periodic timer for specific Node */
		stopTimer( &conn_data->pt );
		/* Reset Periodic Timer */
		if ( startTimer( &conn_data->pt ) < 0)
			clLog(clSystemLog, eCLSeverityCritical, "Periodic Timer failed to start...\n");
	}

	//if (rest_cnt < conn_data->rstCnt) {
	//	flush_eNB_session(&data[inx]);
	//	conn_data->rstCnt = 0;
	//	return;
	//}
	//
	//conn_data->rstCnt = rest_cnt;

}
#endif /* USE_REST */

/**
 * @brief  : Function to process arp message
 * @param  : hw_addr, ethernet address
 * @param  : ipaddr, ip address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static
void process_arp_msg(const struct ether_addr *hw_addr,
		uint32_t ipaddr, uint8_t portid)
{
	struct arp_ipv4_key arp_key;
	arp_key.ip = ipaddr;

	if (ARPICMP_DEBUG)
		clLog(clSystemLog, eCLSeverityDebug,"%s::"
				"\n\tarp_key.ip= 0x%x; portid= %d\n",
				__func__, arp_key.ip, portid);

	/* On ARP_REQ || ARP_RSP retrieve_arp_entry */
	struct arp_entry_data *arp_data =
				retrieve_arp_entry(arp_key, portid);

	if (arp_data) {
		arp_data->last_update = time(NULL);
		if (!(is_same_ether_addr(&arp_data->eth_addr, hw_addr))) {
			/* ARP_RSP || ARP_REQ:
			 * Copy hw_addr -> arp_data->eth_addr
			 * */
			ether_addr_copy(hw_addr, &arp_data->eth_addr);
			if (arp_data->status == INCOMPLETE) {
				if (arp_data->queue) {
					arp_send_buffered_pkts(
							arp_data->queue, hw_addr, portid);
					}
				arp_data->status = COMPLETE;
			}
		}
	}
}

void print_pkt1(struct rte_mbuf *pkt)
{
	if (ARPICMP_DEBUG < 2)
		return;
	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);
	int i = 0, j = 0;
	clLog(clSystemLog, eCLSeverityDebug,
			"ARPICMP Packet Stats"
			"- hit = %u, miss = %u, key %u, out %u\n"
			, pkt_hit_count, pkt_miss_count,
			pkt_key_count, pkt_out_count);
	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			clLog(clSystemLog, eCLSeverityDebug,"%02x ", rd[(20*i)+j]);
		clLog(clSystemLog, eCLSeverityDebug,"\n");
	}
}

/**
 * @brief  : Function to retrive mac address and ip address
 * @param  : addr, arp port address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static void
get_mac_ip_addr(struct arp_port_address *addr, uint8_t port_id)
{
	switch (app.spgw_cfg) {
		case SGWU:
			if (app.s1u_port == port_id) {
				addr[port_id].ip = app.s1u_ip;
				addr[port_id].mac_addr = &app.s1u_ether_addr;
			} else if (app.s5s8_sgwu_port == port_id) {
				addr[port_id].ip = app.s5s8_sgwu_ip;
				addr[port_id].mac_addr = &app.s5s8_sgwu_ether_addr;
			} else {
				clLog(clSystemLog, eCLSeverityDebug,"Unknown input port\n");
			}
			break;

		case PGWU:
			if (app.s5s8_pgwu_port == port_id) {
				addr[port_id].ip = app.s5s8_pgwu_ip;
				addr[port_id].mac_addr = &app.s5s8_pgwu_ether_addr;
			} else if (app.sgi_port == port_id) {
				addr[port_id].ip = app.sgi_ip;
				addr[port_id].mac_addr = &app.sgi_ether_addr;
			} else {
				clLog(clSystemLog, eCLSeverityDebug,"Unknown input port\n");
			}
			break;

		case SAEGWU:
			if (app.s1u_port == port_id) {
				addr[port_id].ip = app.s1u_ip;
				addr[port_id].mac_addr = &app.s1u_ether_addr;
			} else if (app.sgi_port == port_id) {
				addr[port_id].ip = app.sgi_ip;
				addr[port_id].mac_addr = &app.sgi_ether_addr;
			} else {
				clLog(clSystemLog, eCLSeverityDebug,"Unknown input port\n");
			}
			break;

		default:
			break;
	}
}

/**
 * @brief  : Function to process arp request
 * @param  : pkt, rte_mbuf pointer
 * @param  : arg, port id
 * @return : Returns nothing
 */
static inline void
pkt_work_arp_key(
		struct rte_mbuf *pkt,
		void *arg)
{
	uint8_t in_port_id = (uint8_t)(uintptr_t)arg;

	pkt_key_count++;
	print_pkt1(pkt);


	CLIinterface it;

	if (in_port_id == S1U_PORT_ID)
	{
		if (app.spgw_cfg == SGWU || app.spgw_cfg == SAEGWU){
			it = S1U;
		} else if (app.spgw_cfg == PGWU)
		{
			it = S5S8;
		}

	} else { //if (in_port_id == SGI_PORT_ID){
		if (app.spgw_cfg == SGWU )
		{
		  it = S5S8;
		} else //if (app.spgw_cfg == PGWU || app.spgw_cfg == SAEGWU)
		{
			it = SGI;
		}

	}

	struct ether_hdr *eth_h = rte_pktmbuf_mtod(pkt, struct ether_hdr *);

	if ((eth_h->d_addr.addr_bytes[0] == 0x01)
			&& (eth_h->d_addr.addr_bytes[1] == 0x80)
			&& (eth_h->d_addr.addr_bytes[2] == 0xc2))
		return ;

	if ((eth_h->d_addr.addr_bytes[0] == 0x01)
			&& (eth_h->d_addr.addr_bytes[1] == 0x00)
			&& (eth_h->d_addr.addr_bytes[2] == 0x0c))
		return ;

	if (ARPICMP_DEBUG)
		print_eth(eth_h);

	if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		struct arp_hdr *arp_h = (struct arp_hdr *)((char *)eth_h +
								sizeof(struct ether_hdr));
		if (ARPICMP_DEBUG)
			print_arp_packet(arp_h);

		if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
			clLog(clSystemLog, eCLSeverityDebug,"Invalid hardware address format-"
					"\nnot processing ARP_REQ\n");
		} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
			clLog(clSystemLog, eCLSeverityDebug,"Invalid protocol format-"
					"\nnot processing ARP_REQ\n");
		} else if (arp_h->arp_hln != 6) {
			clLog(clSystemLog, eCLSeverityDebug,"Invalid hardware address length-"
					"\nnot processing ARP_REQ\n");
		} else if (arp_h->arp_pln != 4) {
			clLog(clSystemLog, eCLSeverityDebug,"Invalid protocol address length-"
					"\nnot processing ARP_REQ\n");
		} else {
			get_mac_ip_addr(arp_port_addresses, in_port_id);
			if (arp_h->arp_data.arp_tip !=
				arp_port_addresses[in_port_id].ip) {
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,"%s::"
						"ARP-REQ IP != Port IP::discarding"
						"\n\tARP_REQ IP= %s;"
						"\n\tPort ID= %X; IF IP= %s\n",
						__func__,
						inet_ntoa(
							*(struct in_addr *)&arp_h->
								arp_data.arp_tip),
						in_port_id,
						inet_ntoa(
							*(struct in_addr *)
								&arp_port_addresses[in_port_id].ip)
							);
				}
			} else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
				/* ARP_REQ IP matches. Process ARP_REQ */
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
							"%s::"
							"\n\tarp_op= %d; ARP_OP_REQUEST= %d"
							"\n\tprint_mbuf=\n",
							__func__,
							arp_h->arp_op,
							rte_cpu_to_be_16(ARP_OP_REQUEST));
					print_mbuf("RX", in_port_id, pkt, __LINE__);
				}
				process_arp_msg(&arp_h->arp_data.arp_sha,
						arp_h->arp_data.arp_sip, in_port_id);

#ifdef STATIC_ARP
				/* Build ARP_RSP */
				uint32_t req_tip = arp_h->arp_data.arp_tip;
				ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
				ether_addr_copy(
						arp_port_addresses[in_port_id].mac_addr,
						&eth_h->s_addr);
				arp_h->arp_op = rte_cpu_to_be_16(ARP_OP_REPLY);
				ether_addr_copy(&eth_h->s_addr,
						&arp_h->arp_data.arp_sha);
				arp_h->arp_data.arp_tip = arp_h->arp_data.arp_sip;
				arp_h->arp_data.arp_sip = req_tip;
				ether_addr_copy(&eth_h->d_addr,
						&arp_h->arp_data.arp_tha);
				if (ARPICMP_DEBUG) {
					print_mbuf("TX", in_port_id, pkt, __LINE__);
					print_pkt1(pkt);
				}

				/* Send ARP_RSP */
				int pkt_size =
					RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
				/* arp_pkt @arp_xmpool[port_id] */
				struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
				if (pkt1) {
					memcpy(pkt1, pkt, pkt_size);
					rte_pipeline_port_out_packet_insert(
								myP,
								in_port_id, pkt1);
				}
#endif	/* STATIC_ARP */

			} else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REPLY)) {
				/* Process ARP_RSP */
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
						"ARP_RSP::IP= %s; "FORMAT_MAC"\n",
						inet_ntoa(
							*(struct in_addr *)&arp_h->
									arp_data.arp_sip),
						FORMAT_MAC_ARGS(arp_h->arp_data.arp_sha)
						);
				}
				process_arp_msg(&arp_h->arp_data.arp_sha,
						arp_h->arp_data.arp_sip, in_port_id);
			} else {
				if (ARPICMP_DEBUG)
					clLog(clSystemLog, eCLSeverityDebug,"Invalid ARP_OPCODE= %X"
							"\nnot processing ARP_REQ||ARP_RSP\n",
							arp_h->arp_op);
			}
		}
	} else {
		/* If UDP dest port is 2152, then pkt is GTPU-Echo request */
		struct gtpu_hdr *gtpuhdr = get_mtogtpu(pkt);
		if (gtpuhdr && gtpuhdr->msgtype == GTPU_ECHO_REQUEST) {

			struct ipv4_hdr *ip_hdr = get_mtoip(pkt);
			update_cli_stats(ip_hdr->src_addr,GTPU_ECHO_REQUEST,RCVD,it);

			process_echo_request(pkt, in_port_id);
			/* Send ECHO_RSP */
			int pkt_size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
			/* gtpu_echo_pkt @arp_xmpool[port_id] */
			struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
			if (pkt1) {
				memcpy(pkt1, pkt, pkt_size);
				if (rte_ring_enqueue(shared_ring[in_port_id], pkt1) == -ENOBUFS) {
					rte_pktmbuf_free(pkt1);
					clLog(clSystemLog, eCLSeverityCritical, "%s::Can't queue pkt- ring full..."
							" Dropping pkt\n", __func__);
					return;
				}
			update_cli_stats(ip_hdr->dst_addr,GTPU_ECHO_RESPONSE,SENT,it);

			}
		} else if (gtpuhdr && gtpuhdr->msgtype == GTPU_ECHO_RESPONSE) {
#ifdef USE_REST
			/*VS: TODO Add check for Restart counter */
			/* If peer Restart counter value of peer node is less than privious value than start flusing session*/
			struct ipv4_hdr *ip_hdr = get_mtoip(pkt);
			update_cli_stats(ip_hdr->src_addr,GTPU_ECHO_RESPONSE,RCVD,it);
			clLog(clSystemLog, eCLSeverityDebug, "VS: GTP-U Echo Response Received\n");
			process_echo_response(pkt);
#endif /* USE_REST */
		}
	}
}

/**
 * @brief  : Function to be implemented
 * @param  : pkt, unused param
 * @param  : arg, unused param
 * @return : Returns nothing
 */
static inline void
pkt4_work_arp_key(
		struct rte_mbuf **pkt,
		void *arg)
{
	(void)pkt;
	(void)arg;
	/* TO BE IMPLEMENTED IF REQUIRED */
}

/**
 * @brief  : Function to process incoming arp packets
 * @param  : p. rte pipeline pointer
 * @param  : pkt, rte_mbuf pointer
 * @param  : n, number of packets
 * @param  : arg, port id
 * @return : Returns 0 in case of success
 */
static int port_in_ah_arp_key(
		struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,
		void *arg)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (pkts[i])
			pkt_work_arp_key(pkts[i], arg);
	}

	return 0;
}

/**
 * @brief  : Function to parse ethernet address
 * @param  : hw_addr, structure to fill ethernet address
 * @param  : str , string to be parsed
 * @return : Returns number of parsed characters
 */
static int
parse_ether_addr(struct ether_addr *hw_addr, const char *str)
{
	int ret = sscanf(str, "%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8":"
			"%"SCNx8,
			&hw_addr->addr_bytes[0],
			&hw_addr->addr_bytes[1],
			&hw_addr->addr_bytes[2],
			&hw_addr->addr_bytes[3],
			&hw_addr->addr_bytes[4],
			&hw_addr->addr_bytes[5]);
	return  ret - RTE_DIM(hw_addr->addr_bytes);
}

#ifdef STATIC_ARP
/**
 * @brief  : Add static arp entry
 * @param  : entry, entry to be added
 * @param  : port_id, port number
 * @return : Returns nothing
 */
static void
add_static_arp_entry(struct rte_cfgfile_entry *entry,
			uint8_t port_id)
{
	struct arp_ipv4_key key;
	struct arp_entry_data *data;
	char *low_ptr;
	char *high_ptr;
	char *saveptr;
	struct in_addr low_addr;
	struct in_addr high_addr;
	uint32_t low_ip;
	uint32_t high_ip;
	uint32_t cur_ip;
	struct ether_addr hw_addr;
	int ret;

	low_ptr = strtok_r(entry->name, " \t", &saveptr);
	high_ptr = strtok_r(NULL, " \t", &saveptr);

	if (low_ptr == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,"Error parsing static arp entry: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	ret = inet_aton(low_ptr, &low_addr);
	if (ret == 0) {
		clLog(clSystemLog, eCLSeverityCritical,"Error parsing static arp entry: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	if (high_ptr) {
		ret = inet_aton(high_ptr, &high_addr);
		if (ret == 0) {
			clLog(clSystemLog, eCLSeverityCritical,"Error parsing static arp entry: %s = %s\n",
					entry->name, entry->value);
			return;
		}
	} else {
		high_addr = low_addr;
	}

	low_ip = ntohl(low_addr.s_addr);
	high_ip = ntohl(high_addr.s_addr);

	if (high_ip < low_ip) {
		clLog(clSystemLog, eCLSeverityCritical,"Error parsing static arp entry"
				" - range must be low to high: %s = %s\n",
				entry->name, entry->value);
		return;
	}

	if (parse_ether_addr(&hw_addr, entry->value)) {
		clLog(clSystemLog, eCLSeverityCritical,"Error parsing static arp entry mac addr"
				"%s = %s\n",
				entry->name, entry->value);
		return;
	}

	for (cur_ip = low_ip; cur_ip <= high_ip; ++cur_ip) {

		key.ip = ntohl(cur_ip);

		data = rte_malloc_socket(NULL,
				sizeof(struct arp_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (data == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,"Error allocating arp entry - "
					"%s = %s\n",
					entry->name, entry->value);
			return;
		}

		data->eth_addr = hw_addr;
		data->port = port_id;
		data->status = COMPLETE;
		data->ip = key.ip;
		data->last_update = time(NULL);
		data->queue = NULL;

		add_arp_data(&key, data, port_id);
	}
}

/**
 * @brief  : Configure static arp
 * @param  : No param
 * @return : Returns nothing
 */
static void
config_static_arp(void)
{
	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_ARP_FILE, 0);
	struct rte_cfgfile_entry *sgi_entries = NULL;
	struct rte_cfgfile_entry *s1u_entries = NULL;
	int num_sgi_entries;
	int num_s1u_entries;
	int i;

	if (file == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,"Cannot load configuration file %s\n",
				STATIC_ARP_FILE);
		return;
	}

	clLog(clSystemLog, eCLSeverityCritical,"Parsing %s\n", STATIC_ARP_FILE);

	num_sgi_entries = rte_cfgfile_section_num_entries(file, "sgi");
	if (num_sgi_entries > 0) {
		sgi_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_sgi_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (sgi_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Error configuring sgi entry of %s\n",
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "sgi", sgi_entries,
				num_sgi_entries);

		for (i = 0; i < num_sgi_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[SGI]: %s = %s\n", sgi_entries[i].name,
					sgi_entries[i].value);
			add_static_arp_entry(&sgi_entries[i], SGI_PORT_ID);
		}
		rte_free(sgi_entries);
	}

	num_s1u_entries = rte_cfgfile_section_num_entries(file, "s1u");
	if (num_s1u_entries > 0) {
		s1u_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_s1u_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (s1u_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, "Error configuring s1u entry of %s\n",
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "s1u", s1u_entries,
				num_s1u_entries);
		for (i = 0; i < num_sgi_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[S1u]: %s = %s\n", s1u_entries[i].name,
					s1u_entries[i].value);
			add_static_arp_entry(&s1u_entries[i], S1U_PORT_ID);
		}
		rte_free(s1u_entries);
	}

	if (ARPICMP_DEBUG)
		print_arp_table();
}
#endif	/* STATIC_ARP */

/**
 * VS: Routing Discovery
 */

/**
 * @brief  : Print route entry information
 * @param  : entry, route information entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int print_route_entry(
		struct RouteInfo *entry)
{
		/* VS:  Print the route records on cosole */
		printf("-----------\t------- \t--------\t------\t------ \n");
		printf("Destination\tGateway \tNetmask \tflags \tIfname \n");
		printf("-----------\t------- \t--------\t------\t------ \n");

		struct in_addr IP_Addr, GW_Addr, Net_Mask;
		IP_Addr.s_addr = entry->dstAddr;
		GW_Addr.s_addr = entry->gateWay;
		Net_Mask.s_addr = ntohl(entry->mask);

		strncpy(ipAddr, inet_ntoa(IP_Addr), sizeof(ipAddr));
		strncpy(gwAddr, inet_ntoa(GW_Addr), sizeof(gwAddr));
		strncpy(netMask, inet_ntoa(Net_Mask), sizeof(netMask));

		printf("%s  \t%8s\t%8s \t%u \t%s\n",
		        ipAddr, gwAddr, netMask,
		        entry->flags,
		        entry->ifName);

		printf("-----------\t------- \t--------\t------\t------ \n");
		return 0;
}

/**
 * @brief  : Delete entry in route table.
 * @param  : info, route information entry
 * @return : Returns nothing
 */
static int
del_route_entry(
			struct RouteInfo *info)
{
	int ret;
	struct RouteInfo *ret_route_data = NULL;

	/* Check Route Entry is present or Not */
	ret = rte_hash_lookup_data(route_hash_handle,
					&info->dstAddr, (void **)&ret_route_data);
	if (ret) {
		/* Route Entry is present. Delete Route Entry */
		ret = rte_hash_del_key(route_hash_handle, &info->dstAddr);
		if (ret < 0) {
			rte_panic("ROUTE: Error at:%s::"
					"\n\tDelete route_data= %s"
					"\n\tError= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&info->dstAddr),
					rte_strerror(abs(ret)));


			return -1;
		}

		printf("Route entry DELETED from hash table :: \n");
		print_route_entry(info);
	}
	return 0;

}

/**
 * @brief  : Add entry in route table.
 * @param  : info, route information entry
 * @return : Returns nothing
 */
static void add_route_data(
			struct RouteInfo *info) {
	int ret;
	struct RouteInfo *ret_route_data = NULL;

	/* Check Route Entry is present or Not */
	ret = rte_hash_lookup_data(route_hash_handle,
					&info->dstAddr, (void **)&ret_route_data);
	if (ret < 0) {

		/* Route Entry not present. Add Route Entry */
		if (gatway_flag != 1) {
			info->gateWay = 0;
			memset(&info->gateWay_Mac, 0, sizeof(struct ether_addr));
		}

		ret = rte_hash_add_key_data(route_hash_handle,
						&info->dstAddr, info);
		if (ret) {
			/* Add route_data panic because:
			 * ret == -EINVAL &&  wrong parameter ||
			 * ret == -ENOSPC && hash table size insufficient
			 * */
			rte_panic("ROUTE: Error at:%s::"
					"\n\tadd route_data= %s"
					"\n\tError= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&info->dstAddr),
					rte_strerror(abs(ret)));
		}

		gatway_flag = 0;

		printf("Route entry ADDED in hash table :: \n");
		print_route_entry(info);
		return;
	} else if (ret == 0) {
		if (ret_route_data->dstAddr == info->dstAddr){

			/* Route Entry not present. Add Route Entry */
			if (gatway_flag != 1) {
				info->gateWay = 0;
				memset(&info->gateWay_Mac, 0, sizeof(struct ether_addr));
			}

			ret = rte_hash_add_key_data(route_hash_handle,
							&info->dstAddr, info);
			if (ret) {
				/* Add route_data panic because:
				 * ret == -EINVAL &&  wrong parameter ||
				 * ret == -ENOSPC && hash table size insufficient
				 * */
				rte_panic("ROUTE: Error at:%s::"
						"\n\tadd route_data= %s"
						"\n\tError= %s\n",
						__func__,
						inet_ntoa(*(struct in_addr *)&info->dstAddr),
						rte_strerror(abs(ret)));
			}

			gatway_flag = 0;

			clLog(clSystemLog, eCLSeverityDebug,"Route entry ADDED in hash table :: \n");
			print_route_entry(info);
			return;
		}

	}
	print_route_entry(ret_route_data);

}

/**
 * @brief  : Get the interface name based on interface index.
 * @param  : iface_index, interface index
 * @param  : iface_Name, parameter to store interface name
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
get_iface_name(int iface_index, char *iface_Name)
{
	int fd;
	struct ifreq ifr;


	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1)
	{
	    perror("socket");
	    exit(1);
	}

	ifr.ifr_ifindex = iface_index;

	if(ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr)))
	{
		perror("ioctl");
		return -1;
	}

	strcpy(iface_Name, ifr.ifr_name);
	return 0;
}

/*
 * @brief  : Read cache data
 * @param  : Fd, file descriptor of input data
 * @param  : Buffer, buffer to store read result
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int readCache(int Fd, char *Buffer)
{
	if (Fd < 0)
	{
	    return -1;
	}

	char ch;
	size_t Read = 0;

	while (read(Fd, (Buffer + Read), 1))
	{
	    ch = Buffer[Read];
	    if (ch == '\n')
	    {
	        break;
	    }
	    Read++;
	}

	if (Read)
	{
		Buffer[Read] = 0;
		return 0;
	}

	return -1;

}

/**
 * @brief  : Get field value
 * @param  : Line_Arg, input data
 * @param  : Field, param to store output
 * @return : Returns result string in case of success, NULL otherwise
 */
static char *getField(char *Line_Arg, int Field)
{
	char *ret;
	char *s;

	char *Line = malloc(strlen(Line_Arg)), *ptr;
	memcpy(Line, Line_Arg, strlen(Line_Arg));
	ptr = Line;

	s = strtok(Line, ARP_DELIM);
	while (Field && s)
	{
	    s = strtok(NULL, ARP_DELIM);
	    Field--;
	};

	if (s)
	{
	    ret = (char*)malloc(strlen(s) + 1);
	    memset(ret, 0, strlen(s) + 1);
	    memcpy(ret, s, strlen(s));
	}
	free(ptr);

	return s ? ret : NULL;
}

/**
 * @brief  : Get the Gateway MAC Address from ARP TABLE.
 * @param  : IP_gateWay, gateway address
 * @param  : iface_Mac, mac address
 * @return : Returns 0 in case of success , 1 otherwise
 */
static int
get_gateWay_mac(uint32_t IP_gateWay, char *iface_Mac)
{
	int Fd = open(ARP_CACHE, O_RDONLY);

	if (Fd < 0)
	{
	    fprintf(stdout, "Arp Cache: Failed to open file \"%s\"\n", ARP_CACHE);
	    return 1;
	}

	char Buffer[ARP_BUFFER_LEN];

	/* Ignore first line */
	int Ret = readCache(Fd, &Buffer[0]);

	Ret = readCache(Fd, &Buffer[0]);
	//int count = 0;

	while (Ret == 0)
	{
	    char *Line;
	    Line = &Buffer[0];

	    /* Get Ip, Mac, Interface */
	    char *Ip		= getField(Line, 0);
	    char *Mac		= getField(Line, 3);
	    char *IfaceStr	= getField(Line, 5);

		char *tmp = inet_ntoa(*(struct in_addr *)&IP_gateWay);
		if (strcmp(Ip, tmp) == 0) {
			//fprintf(stdout, "%03d: here, Mac Address of [%s] on [%s] is \"%s\"\n",
			//        ++count, Ip, IfaceStr, Mac);

			strcpy(iface_Mac, Mac);
			return 0;
		}

	    free(Ip);
	    free(Mac);
	    free(IfaceStr);

	    Ret = readCache(Fd, &Buffer[0]);
	}
	close(Fd);
	return 0;
}


/**
 * @brief  : Create pthread to read or receive data/events from netlink socket.
 * @param  : arg, input
 * @return : Returns nothing
 */
static void
*netlink_recv_thread(void *arg)
{

	int		recv_bytes = 0;
	int		count = 0, i;
	struct	nlmsghdr *nlp;
	struct	rtmsg *rtp;
	struct	RouteInfo route[24];
	struct	rtattr *rtap;
	int		rtl = 0;
	char	buffer[BUFFER_SIZE];

	bzero(buffer, sizeof(buffer));

	struct sockaddr_nl *addr = (struct sockaddr_nl *)arg;
	while(1)
	{

		/* VS: Receive data pkts from netlink socket*/
		while (1)
		{
			bzero(buffer, sizeof(buffer));

			recv_bytes = recv(route_sock, buffer, sizeof(buffer), 0);

			if (recv_bytes < 0)
			    clLog(clSystemLog, eCLSeverityDebug,"Error in recv\n");

		    nlp = (struct nlmsghdr *) buffer;

			if ((nlp->nlmsg_type == NLMSG_DONE)	||
					(nlp->nlmsg_type == RTM_NEWROUTE) ||
					(nlp->nlmsg_type == RTM_DELROUTE) ||
					(addr->nl_groups == RTMGRP_IPV4_ROUTE))

				break;

		}

		for (i = -1 ; NLMSG_OK(nlp, recv_bytes); \
		                nlp = NLMSG_NEXT(nlp, recv_bytes))
		{
		    rtp = (struct rtmsg *) NLMSG_DATA(nlp);

		    /* Get main routing table */
		    if ((rtp->rtm_family != AF_INET) ||
					(rtp->rtm_table != RT_TABLE_MAIN))
		        continue;

			i++;
		    /* Get attributes of rtp */
		    rtap = (struct rtattr *) RTM_RTA(rtp);

		    /* Get the route atttibutes len */
		    rtl = RTM_PAYLOAD(nlp);

		    /* Loop through all attributes */
			for( ; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl))
			{

					switch(rtap->rta_type)
					{
						/* Get the destination IPv4 address */
						case RTA_DST:
						    count = 32 - rtp->rtm_dst_len;

						    route[i].dstAddr = *(uint32_t *) RTA_DATA(rtap);

						    route[i].mask = 0xffffffff;
						    for (; count!=0 ;count--)
						        route[i].mask = route[i].mask << 1;
						    break;

						case RTA_GATEWAY:
							{
								gatway_flag = 1;
								char mac[64];

								route[i].gateWay = *(uint32_t *) RTA_DATA(rtap);
								get_gateWay_mac(route[i].gateWay, mac);

								if (parse_ether_addr(&(route[i].gateWay_Mac), mac)) {
									clLog(clSystemLog, eCLSeverityDebug,"Error parsing gatway arp entry mac addr"
											"= %s\n",
											mac);

								}

								fprintf(stdout, "Gateway, Mac Address of [%s] is \"%02X:%02X:%02X:%02X:%02X:%02X\"\n",
										inet_ntoa(*(struct in_addr *)&route[i].gateWay),
								        route[i].gateWay_Mac.addr_bytes[0],
								        route[i].gateWay_Mac.addr_bytes[1],
								        route[i].gateWay_Mac.addr_bytes[2],
								        route[i].gateWay_Mac.addr_bytes[3],
								        route[i].gateWay_Mac.addr_bytes[4],
								        route[i].gateWay_Mac.addr_bytes[5]);
								break;
							}

						case RTA_PREFSRC:
						    route[i].srcAddr = *(uint32_t *) RTA_DATA(rtap);
						    break;

						case RTA_OIF:
						    get_iface_name(*((int *) RTA_DATA(rtap)),
									route[i].ifName);
						    break;

						default:
						    break;
					}

				route[i].flags|=RTF_UP;

				if (route[i].gateWay != 0)
					route[i].flags|=RTF_GATEWAY;

				if (route[i].mask == 0xFFFFFFFF)
					route[i].flags|=RTF_HOST;
			}

			/* Now we can dump the routing attributes */
			if (nlp->nlmsg_type == RTM_DELROUTE) {
				del_route_entry(&route[i]);
			}

			if (nlp->nlmsg_type == RTM_NEWROUTE) {
				add_route_data(&route[i]);
			}

			//clLog(clSystemLog, eCLSeverityDebug,"%s  \t%8s\t%8s \t%u \t%s\n",
			//        dest_addr, gw_addr, net_mask,
			//        route[i].flags,
			//        route[i].ifName);

		}
	}
	return NULL; //GCC_Security flag
}

/**
 * @brief  : Initialize netlink socket
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
init_netlink_socket(void)
{
	int retValue = -1;
	struct sockaddr_nl addr_t;

	route_request *request =
		(route_request *)malloc(sizeof(route_request));

	route_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	bzero(request,sizeof(route_request));

	/* Fill the NETLINK header */
	request->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nlMsgHdr.nlmsg_type = RTM_GETROUTE;
	//request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	/* set the routing message header */
	request->rtMsg.rtm_family = AF_INET;
	request->rtMsg.rtm_table = RT_TABLE_MAIN;

	addr_t.nl_family = PF_NETLINK;
	addr_t.nl_pad = 0;
	addr_t.nl_pid = getpid();
	addr_t.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE;

	if (bind(route_sock,(struct sockaddr *)&addr_t,sizeof(addr_t)) < 0)
		ERR_RET("bind socket");

	/* Send routing request */
	if ((retValue = send(route_sock, request, sizeof(route_request), 0)) < 0)
	{
	    perror("send");
	    return -1;
	}

	/*
	 * Create pthread to read or receive data/events from netlink socket.
	 */
	pthread_t net;
	int err_val;

	err_val = pthread_create(&net, NULL, &netlink_recv_thread, &addr_t);
	if (err_val != 0) {
	    printf("\nAPI: Can't create Netlink socket event reader thread :[%s]\n",
				strerror(err_val));
		return -1;
	} else {
	    printf("\nAPI: Netlink socket event reader thread "
				"created successfully...!!!\n");
	}

	return 0;
}

void
epc_arp_init(void)
{
	struct rte_pipeline *p;
	uint32_t i, in_ports_arg_size;
	struct epc_arp_params *params = &arp_params;

	/* Pipeline */
	{
		struct rte_pipeline_params pipeline_params = {
			.name = "arp icmp",
			.socket_id = rte_socket_id(),
			.offset_port_id = 0,
		};

		p = rte_pipeline_create(&pipeline_params);
		if (p == NULL) {
			return;
		}

		myP = p;
	}

	/* Memory allocation for in_port_h_arg */
	in_ports_arg_size =
		RTE_CACHE_LINE_ROUNDUP(
				(sizeof(struct pipeline_arp_icmp_in_port_h_arg)) *
				(NUM_SPGW_PORTS)); /* Fixme */
	struct pipeline_arp_icmp_in_port_h_arg *ap =
		rte_zmalloc_socket(NULL, in_ports_arg_size,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (ap == NULL)
		return;

	/* Input port configuration */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_port_ring_reader_params port_ring_params = {
			.ring = epc_app.epc_mct_rx[i]
		};

		struct rte_pipeline_port_in_params port_params = {
			.ops = &rte_port_ring_reader_ops,
			.arg_create = &port_ring_params,
			.f_action = port_in_ah_arp_key,
			.arg_ah = (void *)(uintptr_t)i,
			.burst_size = epc_app.burst_size_tx_write
		};

		int status = rte_pipeline_port_in_create(p,
				&port_params,
				&params->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p);
		}
		get_mac_ip_addr(arp_port_addresses, i);
	}

	/* Output port configuration */
	for (i = 0; i < epc_app.n_ports; i++) {
#ifdef NGCORE_SHRINK
		struct rte_port_ethdev_writer_nodrop_params
					port_ethdev_params =
			{
				.port_id = epc_app.ports[i],
				.queue_id = 0,
				.tx_burst_sz = epc_app.burst_size_tx_write,
				.n_retries = 0,
			};
		struct rte_pipeline_port_out_params port_params =
		{
			.ops = &rte_port_ethdev_writer_nodrop_ops,
			.arg_create = (void *)&port_ethdev_params,
			.f_action = NULL,
			.arg_ah = NULL,
		};
#else
		struct rte_port_ring_writer_params port_ring_params = {
			.ring = epc_app.ring_tx[epc_app.core_mct][i],
			.tx_burst_sz = epc_app.burst_size_tx_write,
		};

		struct rte_pipeline_port_out_params port_params = {
			.ops = &rte_port_ring_writer_ops,
			.arg_create = (void *) &port_ring_params,
		};
#endif /*NGCORE_SHRINK*/

		if (
			rte_pipeline_port_out_create(p,
					&port_params, &params->port_out_id[i])
			) {
			rte_panic("%s::"
					"\n\tError!!! On config o/p ring RX %i\n",
					__func__, i);
		}
	}

	/* Table configuration */
	struct rte_pipeline_table_params table_params = {
		.ops = &rte_table_stub_ops,
	};

	int status;

	status = rte_pipeline_table_create(p,
			&table_params,
			&params->table_id);

	if (status) {
		rte_pipeline_free(p);
		return;
	}

	/* Add entries to tables */
	for (i = 0; i < epc_app.n_ports; i++) {
		struct rte_pipeline_table_entry entry = {
			.action = RTE_PIPELINE_ACTION_DROP,
		};
		struct rte_pipeline_table_entry *default_entry_ptr;

		if (
			rte_pipeline_table_default_entry_add(p,
					params->table_id, &entry,
					&default_entry_ptr)
			)
			rte_panic("Error!!! on default entry @table id= %u\n",
					params->table_id);
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_connect_to_table(p,
				params->port_in_id[i],
				params->table_id);

		if (status) {
			rte_pipeline_free(p);
		}
	}

	for (i = 0; i < epc_app.n_ports; i++) {
		int status = rte_pipeline_port_in_enable(p,
				params->port_in_id[i]);

		if (status) {
			rte_pipeline_free(p);
		}
	}

	if (rte_pipeline_check(p) < 0) {
		rte_pipeline_free(p);
		rte_panic("%s::"
				"\n\tPipeline consistency check failed\n",
				__func__);
	}

	uint8_t port_cnt;
	for (port_cnt = 0; port_cnt < NUM_SPGW_PORTS; ++port_cnt) {
		/* Create arp_pkt TX mempool for each port */
		arp_xmpool[port_cnt] =
				rte_pktmbuf_pool_create(
						arp_xmpoolname[port_cnt],
						NB_ARP_MBUF, 32,
						0, RTE_MBUF_DEFAULT_BUF_SIZE,
						rte_socket_id());
		if (arp_xmpool[port_cnt] == NULL) {
			rte_panic("rte_pktmbuf_pool_create failed::"
					"\n\tarp_icmp_xmpoolname[%u]= %s;"
					"\n\trte_strerror= %s\n",
					port_cnt, arp_xmpoolname[port_cnt],
					rte_strerror(abs(errno)));
			return;
		}
		/* Allocate arp_pkt mbuf at port mempool */
		arp_pkt[port_cnt] =
					rte_pktmbuf_alloc(arp_xmpool[port_cnt]);
		if (arp_pkt[port_cnt] == NULL) {
			return;
		}

		/* Create arp_queued_pkt TX mmempool for each port */
		arp_quxmpool[port_cnt] = rte_pktmbuf_pool_create(
				arp_quxmpoolname[port_cnt],
				NB_ARP_MBUF, 32,
				0, RTE_MBUF_DEFAULT_BUF_SIZE,
				rte_socket_id());
		if (arp_quxmpool[port_cnt] == NULL) {
			rte_panic("rte_pktmbuf_pool_create failed::"
					"\n\tarp_quxmpoolname[%u]= %s;"
					"\n\trte_strerror= %s\n",
					port_cnt, arp_quxmpoolname[port_cnt],
					rte_strerror(abs(errno)));
			return;
		}

		/* Create arp_hash for each port */
		arp_hash_params[port_cnt].socket_id = rte_socket_id();
		arp_hash_handle[port_cnt] =
				rte_hash_create(&arp_hash_params[port_cnt]);
		if (!arp_hash_handle[port_cnt]) {
			rte_panic("%s::"
					"\n\thash create failed::"
					"\n\trte_strerror= %s; rte_errno= %u\n",
					arp_hash_params[port_cnt].name,
					rte_strerror(rte_errno),
					rte_errno);
		}
	}

	/**
	 * VS: Routing Discovery
	 */

	if (init_netlink_socket() != 0)
		rte_exit(EXIT_FAILURE, "Cannot init netlink socket...!!!\n");

#ifdef STATIC_ARP
	config_static_arp();
#endif	/* STATIC_ARP */
}

/**
 * @brief  : Burst rx from kni interface and enqueue rx pkts in ring
 * @param  : No param
 * @return : Returns 0 in case of success , -1 otherwise
 */
static void *handle_kni_process(__rte_unused void *arg)
{
	for (uint32_t port = 0; port < nb_ports; port++) {
		kni_egress(kni_port_params_array[port]);
	}
	return NULL; //GCC_Security flag
}

void epc_arp(__rte_unused void *arg)
{
	struct epc_arp_params *param = &arp_params;
		rte_pipeline_run(myP);
		if (++param->flush_count >= param->flush_max) {
			rte_pipeline_flush(myP);
			param->flush_count = 0;
		}
		handle_kni_process(NULL);
#ifdef NGCORE_SHRINK
#ifdef STATS
	epc_stats_core();
#endif
#endif
}
