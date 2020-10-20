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
#include "ipv6.h"
#include "stats.h"
#include "up_main.h"
#include "epc_arp.h"
#include "pfcp_util.h"
#include "epc_packet_framework.h"

#ifdef use_rest
#include "../rest_timer/gstimer.h"
#endif /* use_rest */

#include "li_interface.h"

#ifdef DP_BUILD
#include "gw_adapter.h"
#endif
#include "pfcp_enum.h"

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
int route_sock_v4 = -1;
int route_sock_v6 = -1;
int gatway_flag = 0;
extern int clSystemLog;
extern struct rte_hash *conn_hash_handle;

struct addr_info {
	struct sockaddr_nl addr_ipv4;
	struct sockaddr_nl addr_ipv6;
};

/**
 * @brief  : Structure for sending the request
 */
struct route_request_t {
	struct nlmsghdr nlMsgHdr;
	struct rtmsg rtMsg;
	char buf[4096];
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

typedef struct route_request_t route_request;
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
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

struct RouteInfo_v6
{
	uint8_t prefix;
	uint32_t flags;
	struct in6_addr dstAddr;
	struct in6_addr gateWay;
	struct in6_addr srcAddr;
	char proto;
	char ifName[IF_NAMESIZE];
	/** mac address */
	struct ether_addr gateWay_Mac;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

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
	"arp_icmp_ULxmpool",
	"arp_icmp_DLxmpool"
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
	"arp_ULquxmpool",
	"arp_DLquxmpool"
};

struct rte_mempool *arp_quxmpool[NUM_SPGW_PORTS];

/**
 * @brief  : hash params.
 */
static struct rte_hash_parameters
	arp_hash_params[NUM_SPGW_PORTS] = {
		{	.name = "ARP_UL",
			.entries = 64*64,
			.reserved = 0,
			.key_len = sizeof(struct arp_ip_key),
			.hash_func = rte_jhash,
			.hash_func_init_val = 0 },
		{
			.name = "ARP_DL",
			.entries = 64*64,
			.reserved = 0,
			.key_len = sizeof(struct arp_ip_key),
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
	/** IP type */
	ip_type_t ip_type;
	/** ipv4 address*/
	uint32_t ipv4;
	/** ipv6 address*/
	struct in6_addr ipv6;
	/** mac address */
	struct ether_addr *mac_addr;
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

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
}__attribute__((packed, aligned(RTE_CACHE_LINE_SIZE)));

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
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"IP Address: %d.%d.%d.%d\n",
		LOG_VALUE, bytes[3], bytes[2], bytes[1], bytes[0]);
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

/**
 * @brief  : Add entry in ARP table.
 * @param  : arp_key, key.
 * @param  : ret_arp_data, arp data
 * @param  : portid, port
 * @return : Returns nothing
 */
static void add_arp_data(
			struct arp_ip_key *arp_key,
			struct arp_entry_data *ret_arp_data, uint8_t portid)
{
	int ret;
	/* ARP Entry not present. Add ARP Entry */
	ret = rte_hash_add_key_data(arp_hash_handle[portid],
					arp_key, ret_arp_data);
	if (ret) {
		if (arp_key->ip_type.ipv4) {
			/* Add arp_data failed because :
			 * ret == -EINVAL &&  wrong parameter ||
			 * ret == -ENOSPC && hash table size insufficient
			 * */
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ARP: Error at:%s::"
					"\n\tadd arp_data= %s"
					"\n\tError= %s\n",
					__func__,
					inet_ntoa(*(struct in_addr *)&arp_key->ip_addr.ipv4),
					rte_strerror(abs(ret)));
			return;
		} else if (arp_key->ip_type.ipv6) {
			/* Add arp_data failed because :
			 * ret == -EINVAL &&  wrong parameter ||
			 * ret == -ENOSPC && hash table size insufficient
			 * */
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ARP: Error at:%s::"
					"\n\tadd arp_data= "IPv6_FMT""
					"\n\tError= %s\n",
					__func__,
					IPv6_PRINT(arp_key->ip_addr.ipv6),
					rte_strerror(abs(ret)));
			return;
		}
	}

	if (arp_key->ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityInfo,
				LOG_FORMAT"ARP: Entry added for IPv4: "IPV4_ADDR", portid:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key->ip_addr.ipv4)), portid);
	} else if (arp_key->ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityInfo,
				LOG_FORMAT"ARP: Entry added for IPv6: "IPv6_FMT", portid:%u\n",
				LOG_VALUE, IPv6_PRINT(arp_key->ip_addr.ipv6), portid);
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
		if (arp_data->ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"ARP:"
				" Error rte pkt memory buf clone Dropping pkt"
				"arp data IPv4: "IPV4_ADDR"\n", LOG_VALUE,
				IPV4_ADDR_HOST_FORMAT(ntohl(arp_data->ipv4)));
		} else if (arp_data->ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"ARP:"
				" Error rte pkt memory buf clone Dropping pkt"
				"arp data IPv6: "IPv6_FMT"\n", LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
		}

		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error rte PKT memory buf clone Dropping pkt\n", LOG_VALUE);
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
		if (arp_data->ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Can't queue PKT ring full, so dropping PKT"
				"arp data IP: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(arp_data->ipv4));
		} else if (arp_data->ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Can't queue PKT ring full, so dropping PKT"
				"arp data IPv6: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
		}
	} else {
		if (ARPICMP_DEBUG) {
			if (arp_data->ip_type.ipv4) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Queued PKT arp data IPv4: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_data->ipv4)));
			} else if (arp_data->ip_type.ipv6) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Queued PKT arp data IPv6: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
			}
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
		if (arp_data->ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"ARP"
					": Error rte PKT memory buf clone so dropping PKT"
					"and arp data IPv4: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(arp_data->ipv4));
		} else if (arp_data->ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"ARP"
					": Error rte PKT memory buf clone so dropping PKT"
					"and arp data IPv6: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
		}
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"ARP :Error rte PKT memory buf clone so dropping PKT\n", LOG_VALUE);
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
		if (arp_data->ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Can't queue PKT  ring full so dropping PKT"
				" arp data IPv4: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(arp_data->ipv4));
		} else if (arp_data->ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Can't queue PKT  ring full so dropping PKT"
				" arp data IPv6: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
		}
	} else {
		if (ARPICMP_DEBUG) {
			if (arp_data->ip_type.ipv4) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Queued pkt"
					" and arp data IPv4: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(arp_data->ipv4));
			} else if (arp_data->ip_type.ipv6) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Queued pkt"
					" and arp data IPv6: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(arp_data->ipv6));
			}
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
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ICMP: type=%d (%s) code=%d id=%d seqnum=%d\n", LOG_VALUE,
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
		LOG_FORMAT"\tIPv4: Version=%d"
		" Header LEN=%d Type=%d Protocol=%d Length=%d\n", LOG_VALUE,
		(ip_h->version_ihl & 0xf0) >> 4,
		(ip_h->version_ihl & 0x0f),
		ip_h->type_of_service,
		ip_h->next_proto_id,
		rte_cpu_to_be_16(ip_h->total_length));
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Dst IP:", LOG_VALUE);
	print_ip(ntohl(ip_h->dst_addr));
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Src IP:", LOG_VALUE);
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
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ARP:  hrd=%d proto=0x%04x hln=%d "
		"pln=%d op=%u (%s)\n", LOG_VALUE,
		CHECK_ENDIAN_16(arp_h->arp_hrd),
		CHECK_ENDIAN_16(arp_h->arp_pro), arp_h->arp_hln,
		arp_h->arp_pln, CHECK_ENDIAN_16(arp_h->arp_op),
		arp_op_name(arp_h->arp_op));

	if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Incorrect arp header format for IPv4 ARP (%d)\n", LOG_VALUE,
			(arp_h->arp_hrd));
	} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Incorrect arp protocol format for IPv4 ARP (%d)\n",
			LOG_VALUE, (arp_h->arp_pro));
	} else if (arp_h->arp_hln != 6) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Incorrect arp_hln format for IPv4 ARP (%d)\n",
			LOG_VALUE, arp_h->arp_hln);
	} else if (arp_h->arp_pln != 4) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Incorrect arp_pln format for IPv4 ARP (%d)\n",
			LOG_VALUE, arp_h->arp_pln);
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Sha: %02X:%02X:%02X:%02X:%02X:%02X", LOG_VALUE,
			arp_h->arp_data.arp_sha.addr_bytes[0],
			arp_h->arp_data.arp_sha.addr_bytes[1],
			arp_h->arp_data.arp_sha.addr_bytes[2],
			arp_h->arp_data.arp_sha.addr_bytes[3],
			arp_h->arp_data.arp_sha.addr_bytes[4],
			arp_h->arp_data.arp_sha.addr_bytes[5]);
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"SIP: %d.%d.%d.%d\n", LOG_VALUE,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 24) &
							0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >> 16) &
							0xFF,
			(CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) >>  8) &
							0xFF,
			CHECK_ENDIAN_32(arp_h->arp_data.arp_sip) &
							0xFF);
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Tha: %02X:%02X:%02X:%02X:%02X:%02X", LOG_VALUE,
			arp_h->arp_data.arp_tha.addr_bytes[0],
			arp_h->arp_data.arp_tha.addr_bytes[1],
			arp_h->arp_data.arp_tha.addr_bytes[2],
			arp_h->arp_data.arp_tha.addr_bytes[3],
			arp_h->arp_data.arp_tha.addr_bytes[4],
			arp_h->arp_data.arp_tha.addr_bytes[5]);
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT" Tip: %d.%d.%d.%d\n", LOG_VALUE,
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
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"  ETH: src: %02X:%02X:%02X:%02X:%02X:%02X", LOG_VALUE,
		eth_h->s_addr.addr_bytes[0],
		eth_h->s_addr.addr_bytes[1],
		eth_h->s_addr.addr_bytes[2],
		eth_h->s_addr.addr_bytes[3],
		eth_h->s_addr.addr_bytes[4],
		eth_h->s_addr.addr_bytes[5]);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT" dst: %02X:%02X:%02X:%02X:%02X:%02X\n", LOG_VALUE,
		eth_h->d_addr.addr_bytes[0],
		eth_h->d_addr.addr_bytes[1],
		eth_h->d_addr.addr_bytes[2],
		eth_h->d_addr.addr_bytes[3],
		eth_h->d_addr.addr_bytes[4],
		eth_h->d_addr.addr_bytes[5]);

}

/**
 * @brief  : Print ethernet data
 * @param  : eth_h, ethernet header data
 * @return : Returns nothing
 */
static void
print_ipv6_eth(struct ether_addr *eth_h)
{
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"IPv6 Pkt: ETH: src: %02X:%02X:%02X:%02X:%02X:%02X", LOG_VALUE,
		eth_h->addr_bytes[0],
		eth_h->addr_bytes[1],
		eth_h->addr_bytes[2],
		eth_h->addr_bytes[3],
		eth_h->addr_bytes[4],
		eth_h->addr_bytes[5]);
}

void
print_mbuf(const char *rx_tx, unsigned portid,
			struct rte_mbuf *mbuf, unsigned line)
{
	struct ether_hdr *eth_h =
			rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"%s(%u): on port %u pkt-len=%u nb-segs=%u\n", LOG_VALUE,
		rx_tx, line, portid, mbuf->pkt_len, mbuf->nb_segs);
	/* Print the ether header information*/
	print_eth(eth_h);

	switch (rte_cpu_to_be_16(eth_h->ether_type)) {
	case ETHER_TYPE_IPv4: {
			struct ipv4_hdr *ipv4_h =
						(struct ipv4_hdr *)((char *)eth_h +
						sizeof(struct ether_hdr));
			print_ipv4_h(ipv4_h);
			break;
		}
	case ETHER_TYPE_IPv6: {
							  /* TODO: print the IPv6 header */
			break;
		}
	case ETHER_TYPE_ARP: {
			struct arp_hdr *arp_h =
						(struct arp_hdr *)((char *)eth_h +
						sizeof(struct ether_hdr));
			print_arp_packet(arp_h);
			break;
		}
	default:
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"  Unknown packet type\n", LOG_VALUE);
		break;
	}
	fflush(stdout);
}

struct arp_entry_data *
retrieve_arp_entry(struct arp_ip_key arp_key,
		uint8_t portid)
{
	int ret;
	struct arp_entry_data *ret_arp_data = NULL;
	struct RouteInfo *route_entry = NULL;
	if (ARPICMP_DEBUG) {
		if (arp_key.ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Retrieve arp entry for ipv4: "IPV4_ADDR", portid:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
		} else if (arp_key.ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Retrieve arp entry for ipv6: "IPv6_FMT", portid:%u\n",
				LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
		}
	}

	ret = rte_hash_lookup_data(arp_hash_handle[portid],
					(const void *)&arp_key, (void **)&ret_arp_data);
	if (ret < 0) {
		if (arp_key.ip_type.ipv4) {
			/* Compute the key(subnet) based on netmask is 24 */
			struct RouteInfo key;
			key.dstAddr = (arp_key.ip_addr.ipv4 & NETMASK);

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
						ret_arp_data->ip_type.ipv4 = PRESENT;
						ret_arp_data->ipv4 = route_entry->gateWay;
						ret_arp_data->eth_addr = route_entry->gateWay_Mac;
						return ret_arp_data;

				} else if ((route_entry->gateWay != 0) && (route_entry->gateWay_Mac.addr_bytes == 0)) {
							struct arp_ip_key gw_arp_key;
							gw_arp_key.ip_type.ipv4 = PRESENT;
							gw_arp_key.ip_addr.ipv4 = route_entry->gateWay;
							clLog(clSystemLog, eCLSeverityInfo,
								LOG_FORMAT"GateWay ARP entry not found for %s\n",
								LOG_VALUE, inet_ntoa(*((struct in_addr *)&gw_arp_key.ip_addr.ipv4)));
							/* No arp entry for arp_key.ip_addr.ipv4
							 * Add arp_data for arp_key.ip_addr.ipv4 at
							 * arp_hash_handle[portid]
							 * */
							ret_arp_data =
									rte_malloc_socket(NULL,
											sizeof(struct arp_entry_data),
											RTE_CACHE_LINE_SIZE, rte_socket_id());
							ret_arp_data->last_update = time(NULL);
							ret_arp_data->status = INCOMPLETE;
							ret_arp_data->ip_type.ipv4 = PRESENT;
							add_arp_data(&gw_arp_key, ret_arp_data, portid);

							/* Added arp_data for gw_arp_key.ip_addr.ipv4 at
							 * arp_hash_handle[portid]
							 * Queue arp_data in arp_pkt mbuf
							 * send_arp_req(portid, gw_arp_key.ip_addr.ipv4)
							 * */
							ret_arp_data->ipv4 = gw_arp_key.ip_addr.ipv4;
							ret_arp_data->queue = rte_ring_create(
									inet_ntoa(*((struct in_addr *)&gw_arp_key.ip_addr.ipv4)),
									ARP_BUFFER_RING_SIZE,
									rte_socket_id(), 0);

							if (ret_arp_data->queue == NULL) {
								clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"ARP ring create error"
										" arp key IPv4: %s, portid: %d"
										"\n\tError: %s, errno(%d)\n", LOG_VALUE,
										inet_ntoa(*(struct in_addr *)&gw_arp_key.ip_addr.ipv4),
										portid, rte_strerror(abs(rte_errno)), rte_errno);
								print_arp_table();
								if (rte_errno == EEXIST) {
									rte_free(ret_arp_data);
									ret_arp_data = NULL;
									clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"ARP Ring Create Failed due to a "
										" memzone with the same name already exists 'EEXIST'\n");
								}
							} else {
								if (ARPICMP_DEBUG) {
									clLog(clSystemLog, eCLSeverityDebug,
										LOG_FORMAT"ARP Ring Create for key ipv4: "IPV4_ADDR", portid:%u\n",
										LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
								}
							}
						return ret_arp_data;
					}
				}

			clLog(clSystemLog, eCLSeverityInfo,
				LOG_FORMAT"ARP entry not found for IPv4: "IPV4_ADDR", portid:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
			/* No arp entry for arp_key.ip_addr.ip
			 * Add arp_data for arp_key.ip_addr.ip at
			 * arp_hash_handle[portid]
			 * */
			ret_arp_data =
					rte_malloc_socket(NULL,
							sizeof(struct arp_entry_data),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
			ret_arp_data->last_update = time(NULL);
			ret_arp_data->status = INCOMPLETE;
			ret_arp_data->ip_type.ipv4 = PRESENT;
			add_arp_data(&arp_key, ret_arp_data, portid);

			/* Added arp_data for arp_key.ip_addr.ipv4 at
			 * arp_hash_handle[portid]
			 * Queue arp_data in arp_pkt mbuf
			 * send_arp_req(portid, arp_key.ip_addr.ipv4)
			 * */
			ret_arp_data->ipv4 = arp_key.ip_addr.ipv4;
			ret_arp_data->queue = rte_ring_create(
					inet_ntoa(*((struct in_addr *)&arp_key.ip_addr.ipv4)),
					ARP_BUFFER_RING_SIZE,
					rte_socket_id(), 0);

			if (ret_arp_data->queue == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ARP ring create error"
						" arp key IPv4: "IPV4_ADDR", portid: %d"
						",Error: %s , errno(%d)\n",
						LOG_VALUE,
						IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)),
						portid,
						rte_strerror(abs(rte_errno)), rte_errno);
				print_arp_table();
				if (rte_errno == EEXIST) {
					rte_free(ret_arp_data);
					ret_arp_data = NULL;
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ARP Ring Create Failed due to a "
						" memzone with the same name already exists 'EEXIST'\n");
				}
			} else {
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ARP Ring Create for key ipv4: "IPV4_ADDR", portid:%u\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
				}
			}
		} else if (arp_key.ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityInfo,
				LOG_FORMAT"ARP entry not found for IPv6: "IPv6_FMT", portid:%u\n",
				LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);

			/* No arp entry for arp_key.ip_addr.ipv6
			 * Add arp_data for arp_key.ip_addr.ipv6 at
			 * arp_hash_handle[portid]
			 * */
			ret_arp_data =
					rte_malloc_socket(NULL,
							sizeof(struct arp_entry_data),
							RTE_CACHE_LINE_SIZE, rte_socket_id());
			ret_arp_data->last_update = time(NULL);
			ret_arp_data->status = INCOMPLETE;
			ret_arp_data->ip_type.ipv6 = PRESENT;
			add_arp_data(&arp_key, ret_arp_data, portid);

			/* Added arp_data for arp_key.ip_addr.ipv6 at
			 * arp_hash_handle[portid]
			 * Queue arp_data in arp_pkt mbuf
			 * send_arp_req(portid, arp_key.ip_addr.ipv6)
			 * */
			ret_arp_data->ipv6 = arp_key.ip_addr.ipv6;

			/* If received address is multicast address */
			char *all_node_addr = "ff02::1";
			char *all_router_addr = "ff02::2";
			struct in6_addr all_node_addr_t = {0};
			struct in6_addr all_router_addr_t = {0};

			/* All Node IPV6 Address */
			if (!inet_pton(AF_INET6, all_node_addr, &all_node_addr_t)) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Multicast:Invalid all Node IPv6 Address\n", LOG_VALUE);
			}

			/* All Router IPV6 Address */
			if (!inet_pton(AF_INET6, all_router_addr, &all_router_addr_t)) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Multicast:Invalid all Router IPv6 Address\n", LOG_VALUE);
			}

			if (!memcmp(&ret_arp_data->ipv6, &all_node_addr_t, IPV6_ADDR_LEN)) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Multicast:all Node IPv6 Address:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(ret_arp_data->ipv6));
				const char *mac_addr = "33:33:00:00:00:01";

				if (parse_ether_addr(&ret_arp_data->eth_addr, mac_addr)) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Muticast:Error parsing static arp entry for all node mac addr"
						"%s\n", LOG_VALUE, mac_addr);
				}
				ret_arp_data->status = COMPLETE;

			} else if (!memcmp(&ret_arp_data->ipv6, &all_router_addr_t, IPV6_ADDR_LEN)) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Multicast:all Router IPv6 Address:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(ret_arp_data->ipv6));
				const char *mac_addr = "33:33:00:00:00:02";

				if (parse_ether_addr(&ret_arp_data->eth_addr, mac_addr)) {
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Muticast:Error parsing static arp entry for all route mac addr"
						"%s\n", LOG_VALUE, mac_addr);
				}
				ret_arp_data->status = COMPLETE;
			}


			ret_arp_data->queue = rte_ring_create((char *)&arp_key.ip_addr.ipv6,
					ARP_BUFFER_RING_SIZE,
					rte_socket_id(), 0);

			if (ret_arp_data->queue == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ARP ring create error"
						" arp key IPv6: "IPv6_FMT", portid: %d"
						",Error: %s , errno(%d)\n",
						LOG_VALUE,
						IPv6_PRINT(arp_key.ip_addr.ipv6),
						portid,
						rte_strerror(abs(rte_errno)), rte_errno);
				print_arp_table();
				if (rte_errno == EEXIST) {
					rte_free(ret_arp_data);
					ret_arp_data = NULL;
					clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"ARP Ring Create Failed due to a "
						" memzone with the same name already exists 'EEXIST'\n");
				}
			} else {
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ARP Ring Create for key ipv6: "IPv6_FMT", portid:%u\n",
						LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
				}
			}
		}
		return ret_arp_data;
	}

	if (ARPICMP_DEBUG) {
		if (arp_key.ip_type.ipv4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Found arp entry for ipv4: "IPV4_ADDR", portid:%u\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
		} else if (arp_key.ip_type.ipv6) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Found arp entry for ipv6: "IPv6_FMT", portid:%u\n",
				LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
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

	for (uint8_t port_cnt = 0; port_cnt < NUM_SPGW_PORTS; port_cnt++) {
		while (
				rte_hash_iterate(
							arp_hash_handle[port_cnt],
							&next_key, &next_data, &iter
							) >= 0) {

			struct arp_entry_data *tmp_arp_data =
					(struct arp_entry_data *)next_data;
			struct arp_ip_key tmp_arp_key;

			memcpy(&tmp_arp_key, next_key,
					sizeof(struct arp_ip_key));
			if (tmp_arp_data->ip_type.ipv4) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv4:\t%02X:%02X:%02X:%02X:%02X:%02X  %10s  %s Portid:%u\n", LOG_VALUE,
					tmp_arp_data->eth_addr.addr_bytes[0],
					tmp_arp_data->eth_addr.addr_bytes[1],
					tmp_arp_data->eth_addr.addr_bytes[2],
					tmp_arp_data->eth_addr.addr_bytes[3],
					tmp_arp_data->eth_addr.addr_bytes[4],
					tmp_arp_data->eth_addr.addr_bytes[5],
					tmp_arp_data->status == COMPLETE ? "COMPLETE" : "INCOMPLETE",
					inet_ntoa(
						*((struct in_addr *)(&tmp_arp_data->ipv4))), port_cnt);
			} else if (tmp_arp_data->ip_type.ipv6) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6:\t%02X:%02X:%02X:%02X:%02X:%02X  %10s  "IPv6_FMT" Portid:%u\n", LOG_VALUE,
					tmp_arp_data->eth_addr.addr_bytes[0],
					tmp_arp_data->eth_addr.addr_bytes[1],
					tmp_arp_data->eth_addr.addr_bytes[2],
					tmp_arp_data->eth_addr.addr_bytes[3],
					tmp_arp_data->eth_addr.addr_bytes[4],
					tmp_arp_data->eth_addr.addr_bytes[5],
					tmp_arp_data->status == COMPLETE ? "COMPLETE" : "INCOMPLETE",
					IPv6_PRINT(tmp_arp_data->ipv6), port_cnt);
			}
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
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Can't queue PKT ring full"
					" so dropping PKT\n", LOG_VALUE);
				continue;
			}
			++count;
		}
	}

#ifdef STATS
	if (portid == SGI_PORT_ID) {
		epc_app.ul_params[S1U_PORT_ID].pkts_out += count;
	} else if (portid == S1U_PORT_ID) {
		epc_app.dl_params[SGI_PORT_ID].pkts_out += count;
	}
#endif /* STATS */

	if (ARPICMP_DEBUG) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Forwarded count PKTS:  %u"
			" Out of PKTS in ring: %u\n",
			LOG_VALUE, count, ring_count);
	}

	rte_ring_free(queue);
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
	node_address_t peer_addr = {0};
	struct ether_hdr *ether = NULL;

	/* Get the ether header info */
	ether = (struct ether_hdr *)rte_pktmbuf_mtod(echo_pkt, uint8_t *);

	if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		/* Retrieve src IP addresses */
		struct ipv4_hdr *ipv4_hdr = get_mtoip(echo_pkt);
		peer_addr.ip_type = IPV4_TYPE;
		peer_addr.ipv4_addr = ipv4_hdr->src_addr;
	} else if (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		/* Retrieve src IP addresses */
		struct ipv6_hdr *ipv6_hdr = get_mtoip_v6(echo_pkt);
		peer_addr.ip_type = IPV6_TYPE;
		memcpy(peer_addr.ipv6_addr,
				ipv6_hdr->src_addr, IPV6_ADDR_LEN);
	}

	/* VS: */
	ret = rte_hash_lookup_data(conn_hash_handle,
				&peer_addr, (void **)&conn_data);
	if ( ret < 0) {
		(peer_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ECHO_RSP: Entry not found for NODE IPv6 Addr: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ECHO_RSP: Entry not found for NODE IPv4 Addr: %s\n",
					LOG_VALUE, inet_ntoa(*(struct in_addr *)&peer_addr.ipv4_addr));
		return;

	} else {
		conn_data->itr_cnt = 0;
		peer_address_t addr = {0};
		addr.type = peer_addr.ip_type;

		if (peer_addr.ip_type == IPV6_TYPE) {
			memcpy(addr.ipv6.sin6_addr.s6_addr,
					peer_addr.ipv6_addr, IPV6_ADDR_LEN);
		} else if (peer_addr.ip_type == IPV4_TYPE) {
			addr.ipv4.sin_addr.s_addr = peer_addr.ipv4_addr;
		}
		update_peer_timeouts(&addr, 0);

		/* Reset Activity flag */
		conn_data->activityFlag = 0;
		/* Stop transmit timer for specific Node */
		stopTimer( &conn_data->tt );
		/* Stop periodic timer for specific Node */
		stopTimer( &conn_data->pt );
		/* Reset Periodic Timer */
		if ( startTimer( &conn_data->pt ) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Periodic Timer failed to start\n", LOG_VALUE);
			return;
		}
		(peer_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ECHO_RSP: Periodic Timer restarted for NODE IPv6 Addr: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ECHO_RSP: Periodic Timer restarted for NODE IPv4 Addr: %s\n",
					LOG_VALUE, inet_ntoa(*(struct in_addr *)&peer_addr.ipv4_addr));
	}
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
	struct arp_ip_key arp_key = {0};
	arp_key.ip_type.ipv4 = PRESENT;
	arp_key.ip_addr.ipv4 = ipaddr;

	if (ARPICMP_DEBUG) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ARP_RSP: Arp key IPv4 "IPV4_ADDR", portid= %d\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
	}

	/* On ARP_REQ || ARP_RSP retrieve_arp_entry */
	struct arp_entry_data *arp_data = NULL;
	arp_data = retrieve_arp_entry(arp_key, portid);
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
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ARP_RSP: Resoved the queued pkts and RING status = COMPLETE "
					"for IPv4:"IPV4_ADDR", portid: %d\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
			}
		}
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ARP_RSP: Arp data not found for key IPv4 "IPV4_ADDR", portid= %d\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(arp_key.ip_addr.ipv4)), portid);
	}
}

/**
 * @brief  : Function to process neighbor advertisement message
 * @param  : hw_addr, ethernet address
 * @param  : ip6_addr, ip6 address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static
void process_neighbor_advert_msg(const struct ether_addr *hw_addr,
		struct in6_addr *ip6_addr, uint8_t portid)
{
	struct arp_ip_key arp_key = {0};
	arp_key.ip_type.ipv6 = PRESENT;

	/* Fill the IPv6 Address and resolved buffered packets */
	memcpy(&arp_key.ip_addr.ipv6, ip6_addr, IPV6_ADDRESS_LEN);

	if (ARPICMP_DEBUG) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"NEIGHBOR: key IPv6 "IPv6_FMT", portid= %d\n",
			LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
	}

	/* On NEIGHBOR_SLOLITATION_REQ || NEIGHBOR_ADVERTISEMENT_RSP retrieve_arp_entry */
	struct arp_entry_data *arp_data = NULL;
	arp_data = retrieve_arp_entry(arp_key, portid);
	if (arp_data) {
		arp_data->last_update = time(NULL);
		if (!(is_same_ether_addr(&arp_data->eth_addr, hw_addr))) {
			/* NEIGHBOR_SLOLITATION_REQ || NEIGHBOR_ADVERTISEMENT_RSP:
			 * Copy hw_addr -> arp_data->eth_addr
			 * */
			ether_addr_copy(hw_addr, &arp_data->eth_addr);
			if (ARPICMP_DEBUG)
				print_ipv6_eth(&arp_data->eth_addr);

			if (arp_data->status == INCOMPLETE) {
				if (arp_data->queue) {
					arp_send_buffered_pkts(
							arp_data->queue, hw_addr, portid);
					}
				arp_data->status = COMPLETE;
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ARP_RSP: Resoved the queued pkts and RING status = COMPLETE "
					"for IPv6:"IPv6_FMT", portid: %d\n",
					LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
			}
		}
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"NEIGHBOR_ADVERT: Ether data not found for key IPv6 "IPv6_FMT", portid= %d\n",
			LOG_VALUE, IPv6_PRINT(arp_key.ip_addr.ipv6), portid);
	}
}

void print_pkt1(struct rte_mbuf *pkt)
{
	if (ARPICMP_DEBUG < 2)
		return;

	uint8_t *rd = RTE_MBUF_METADATA_UINT8_PTR(pkt, 0);
	int i = 0, j = 0;
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ARPICMP Packet Stats"
			"- hit = %u, miss = %u, key %u, out %u\n",
			LOG_VALUE, pkt_hit_count, pkt_miss_count,
			pkt_key_count, pkt_out_count);
	for (i = 0; i < 20; i++) {
		for (j = 0; j < 20; j++)
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"%02x \n", LOG_VALUE, rd[(20*i)+j]);
	}
}

/**
 * @brief  : Function to retrive mac address and ipv4 address
 * @param  : addr, arp port address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static void
get_mac_ip_addr(struct arp_port_address *addr, uint32_t ip_addr,
		uint8_t port_id)
{
	if (app.wb_port == port_id) {
		/* Validate the Destination IP Address subnet */
		if (validate_Subnet(ntohl(ip_addr), app.wb_net, app.wb_bcast_addr)) {
			addr[port_id].ipv4 = htonl(app.wb_ip);
		} else if (validate_Subnet(ntohl(ip_addr), app.wb_li_net, app.wb_li_bcast_addr)) {
			addr[port_id].ipv4 = htonl(app.wb_li_ip);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"WB:ARP Destination IPv4 Addr "IPV4_ADDR" "
					"is NOT in local intf subnet\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(ip_addr)));
		}
		addr[port_id].ip_type.ipv4 = PRESENT;
		addr[port_id].mac_addr = &app.wb_ether_addr;

	} else if (app.eb_port == port_id) {
		/* Validate the Destination IP Address subnet */
		if (validate_Subnet(ntohl(ip_addr), app.eb_net, app.eb_bcast_addr)) {
			addr[port_id].ipv4 = htonl(app.eb_ip);
		} else if (validate_Subnet(ntohl(ip_addr), app.eb_li_net, app.eb_li_bcast_addr)) {
			addr[port_id].ipv4 = htonl(app.eb_li_ip);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"EB:ARP Destination IPv4 Addr "IPV4_ADDR" "
					"is NOT in local intf subnet\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ntohl(ip_addr)));
		}
		addr[port_id].ip_type.ipv4 = PRESENT;
		addr[port_id].mac_addr = &app.eb_ether_addr;
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Unknown input port\n", LOG_VALUE);
	}
}

/**
 * @brief  : Function to retrive mac address and ipv6 address
 * @param  : addr, ns port address
 * @param  : portid, port number
 * @return : Returns nothing
 */
static void
get_mac_ipv6_addr(struct arp_port_address *addr, struct in6_addr ip_addr,
		uint8_t port_id)
{
	if (app.wb_port == port_id) {
		/* Validate the Destination IPv6 Address subnet */
		if (validate_ipv6_network(ip_addr, app.wb_ipv6, app.wb_ipv6_prefix_len)) {
			memcpy(&addr[port_id].ipv6, &app.wb_ipv6, IPV6_ADDRESS_LEN);
		} else if (validate_ipv6_network(ip_addr, app.wb_li_ipv6, app.wb_li_ipv6_prefix_len)){
			memcpy(&addr[port_id].ipv6, &app.wb_li_ipv6, IPV6_ADDRESS_LEN);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"WB:Neighbor Destination IPv6 Addr "IPv6_FMT" "
					"is NOT in local intf subnet\n",
					LOG_VALUE, IPv6_PRINT(ip_addr));
		}
		addr[port_id].ip_type.ipv6 = PRESENT;
		addr[port_id].mac_addr = &app.eb_ether_addr;

	} else if (app.eb_port == port_id) {
		/* Validate the Destination IPv6 Address subnet */
		if (validate_ipv6_network(ip_addr, app.eb_ipv6, app.eb_ipv6_prefix_len)) {
			memcpy(&addr[port_id].ipv6, &app.eb_ipv6, IPV6_ADDRESS_LEN);
		} else if (validate_ipv6_network(ip_addr, app.eb_li_ipv6, app.eb_li_ipv6_prefix_len)){
			memcpy(&addr[port_id].ipv6, &app.eb_li_ipv6, IPV6_ADDRESS_LEN);
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"EB:Neighbor Destination IPv6 Addr "IPv6_FMT" "
					"is NOT in local intf subnet\n",
					LOG_VALUE, IPv6_PRINT(ip_addr));
		}
		addr[port_id].ip_type.ipv6 = PRESENT;
		addr[port_id].mac_addr = &app.eb_ether_addr;
	} else {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Unknown input port\n", LOG_VALUE);
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
		it = S1U;
	} else {
		it = SGI;
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

	/* Print ethernet header information */
	if (ARPICMP_DEBUG)
		print_eth(eth_h);

	if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_ARP)) {
		struct arp_hdr *arp_h = (struct arp_hdr *)((char *)eth_h +
								sizeof(struct ether_hdr));
		/* Print ARP header information */
		if (ARPICMP_DEBUG)
			print_arp_packet(arp_h);

		if (CHECK_ENDIAN_16(arp_h->arp_hrd) != ARP_HRD_ETHER) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Invalid hardware address format-"
				"not processing ARP REQ\n", LOG_VALUE);
		} else if (CHECK_ENDIAN_16(arp_h->arp_pro) != ETHER_TYPE_IPv4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Invalid protocol format-"
					"not processing ARP REQ\n", LOG_VALUE);
		} else if (arp_h->arp_hln != 6) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Invalid hardware address length-"
				"not processing ARP REQ\n", LOG_VALUE);
		} else if (arp_h->arp_pln != 4) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Invalid protocol address length-"
				"not processing ARP REQ\n", LOG_VALUE);
		} else {
			get_mac_ip_addr(arp_port_addresses, arp_h->arp_data.arp_tip, in_port_id);
			if (arp_h->arp_data.arp_tip !=
				arp_port_addresses[in_port_id].ipv4) {
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ARP REQ IPv4 != Port IP::discarding"
						"ARP REQ IP: %s;"
						"Port ID: %X; Interface IPv4: %s\n",LOG_VALUE,
						inet_ntoa(*(struct in_addr *)&arp_h->arp_data.arp_tip), in_port_id,
						inet_ntoa(*(struct in_addr *)&arp_port_addresses[in_port_id].ipv4));
				}
			} else if (arp_h->arp_op == rte_cpu_to_be_16(ARP_OP_REQUEST)) {
				/* ARP_REQ IP matches. Process ARP_REQ */
				if (ARPICMP_DEBUG) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"\nArp op: %d; ARP OP REQUEST: %d"
						" print memory bufffer:\n",
						LOG_VALUE, arp_h->arp_op,
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
						LOG_FORMAT"ARP RSP::IPv4= %s; "FORMAT_MAC"\n", LOG_VALUE,
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
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Invalid ARP OPCODE= %X"
						"\nnot processing ARP REQ||ARP RSP\n", LOG_VALUE,
						arp_h->arp_op);
			}
		}
	} else if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4)) {
		/* If UDP dest port is 2152, then pkt is GTPU-Echo request */
		struct gtpu_hdr *gtpuhdr = get_mtogtpu(pkt);
		if (gtpuhdr && (gtpuhdr->msgtype == GTPU_ECHO_REQUEST)) {

			struct ipv4_hdr *ip_hdr = get_mtoip(pkt);
			/* Check Request recvd form Valid IP address */
			if ((app.wb_ip != ntohl(ip_hdr->dst_addr)) && (app.eb_ip != ntohl(ip_hdr->dst_addr))) {
				/* Check for logical interface */
				if ((app.wb_li_ip != ntohl(ip_hdr->dst_addr))
						&& (app.eb_li_ip != ntohl(ip_hdr->dst_addr))) {
					return;
				}
			}
			peer_address_t address;
			address.ipv4.sin_addr.s_addr = ip_hdr->src_addr;
			address.type = IPV4_TYPE;
			update_cli_stats((peer_address_t *) &address, GTPU_ECHO_REQUEST, RCVD, it);

			process_echo_request(pkt, in_port_id, IPV4_TYPE);
			/* Send ECHO_RSP */
			int pkt_size =
				RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
			/* gtpu_echo_pkt @arp_xmpool[port_id] */
			struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
			if (pkt1) {
				memcpy(pkt1, pkt, pkt_size);
				if (rte_ring_enqueue(shared_ring[in_port_id], pkt1) == -ENOBUFS) {
					rte_pktmbuf_free(pkt1);
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Can't queue pkt- ring full"
							" Dropping pkt\n", LOG_VALUE);
					return;
				}

				peer_address_t address;
				address.ipv4.sin_addr.s_addr = ip_hdr->dst_addr;
				address.type = IPV4_TYPE;
				update_cli_stats((peer_address_t *) &address, GTPU_ECHO_RESPONSE, SENT,it);

			}
		} else if (gtpuhdr && gtpuhdr->msgtype == GTPU_ECHO_RESPONSE) {
#ifdef USE_REST
			/*VS: Add check for Restart counter */
			/* If peer Restart counter value of peer node is less than privious value than start flusing session*/
			struct ipv4_hdr *ip_hdr = get_mtoip(pkt);
			peer_address_t address;
			address.ipv4.sin_addr.s_addr = ip_hdr->src_addr;
			address.type = IPV4_TYPE;
			update_cli_stats((peer_address_t *) &address, GTPU_ECHO_RESPONSE, RCVD, it);

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"GTPU Echo Response Received\n", LOG_VALUE);
			process_echo_response(pkt);
#endif /* USE_REST */
		} else if (gtpuhdr && gtpuhdr->msgtype == GTP_GPDU) {
			/* Process the Router Solicitation Message */
			struct ipv6_hdr *ipv6_hdr = NULL;
			ipv6_hdr = (struct ipv6_hdr*)((char*)gtpuhdr + GTPU_HDR_SIZE);

			if (ipv6_hdr->proto == IPPROTO_ICMPV6) {
				/* Target IPv6 Address */
				struct in6_addr target_addr = {0};
				memcpy(&target_addr.s6_addr, &ipv6_hdr->src_addr, IPV6_ADDR_LEN);

				/* Get the ICMPv6 Header */
				struct icmp_hdr *icmp = NULL;
				icmp = (struct icmp_hdr *)((char*)gtpuhdr + GTPU_HDR_SIZE + IPv6_HDR_SIZE);

				if (icmp->icmp_type == ICMPv6_ROUTER_SOLICITATION) {
					/* Check the TEID value */
					if (!gtpuhdr->teid) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"IPv6: Failed to Process ICMPv6_ROUTER_SOLICITATION Message,"
								" due to teid value is not set\n",
								LOG_VALUE);
						return;
					}

					/* Retrieve Session info based on the teid */
					pfcp_session_datat_t *ul_sess_data = NULL;
					pfcp_session_datat_t *dl_sess_data = NULL;
					struct ul_bm_key key = {0};
					struct dl_bm_key dl_key = {0};
					key.teid = ntohl(gtpuhdr->teid);

					/* Get the session info */
					if (iface_lookup_uplink_data(&key, (void **)&ul_sess_data) < 0) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! ULKEY "
								"TEID: %u\n", LOG_VALUE, key.teid);
						return;
					}

					/* Check session data is not NULL */
					if (ul_sess_data == NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! ULKEY "
								"TEID: %u\n", LOG_VALUE, key.teid);
						return;
					}
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"RS:SESSION INFO:"
							"TEID:%u, Session State:%u\n",
							LOG_VALUE, key.teid, ul_sess_data->sess_state);

					if (ul_sess_data->pdrs != NULL) {
						/* Get the Downlink PDR and FAR info */
						memcpy(&dl_key.ue_ip.ue_ipv6, &(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_address,
								IPV6_ADDR_LEN);

						/* Get the Downlink Session information */
						if (iface_lookup_downlink_data(&dl_key, (void **)&dl_sess_data) < 0) {
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! DLKEY "
									"UE IPv6: "IPv6_FMT"\n", LOG_VALUE,
									IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
							return;
						}

						/* Check session data is not NULL */
						if (dl_sess_data == NULL) {
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! DLKEY "
									"UE IPv6: "IPv6_FMT"\n", LOG_VALUE,
									IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
							return;
						}
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"RS:SESSION INFO:"
								"UE IPv6:"IPv6_FMT", Session State:%u\n",
								LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6),
								dl_sess_data->sess_state);
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT":RS:PDR is NULL in UL session for "
								"TEID: %u\n", LOG_VALUE, key.teid);
						return;
					}

					/* Validate PDR and FAR is not NULL */
					if ((dl_sess_data->pdrs != NULL) && ((dl_sess_data->pdrs)->far != NULL))
					{
						/* Processing received Router Solicitation Request and responsed with Advertisement Resp */
						uint32_t tmp_teid = ntohl((dl_sess_data->pdrs)->far->frwdng_parms.outer_hdr_creation.teid);
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"IPv6: Process RCVD ICMPv6_ROUTER_SOLICITATION Message..!!\n",
								LOG_VALUE);

						/* Update the GTPU TEID */
						process_router_solicitation_request(pkt, tmp_teid);

						/* Update the Inner IPv6 HDR Src Address */
						struct ipv6_hdr *ipv6_hdr = NULL;
						ipv6_hdr = (struct ipv6_hdr*)((char*)gtpuhdr + GTPU_HDR_SIZE);

						/* Update the Source Link Locak Layer Address */
						memcpy(&ipv6_hdr->src_addr, &app.wb_l3_ipv6, IPV6_ADDR_LEN);

						/* Update the Router Advertisement pkt */
						struct icmp6_hdr_ra *ra = (struct icmp6_hdr_ra *)((char*)gtpuhdr + GTPU_HDR_SIZE + IPv6_HDR_SIZE);

						/* Get the Network Prefix */
						struct in6_addr prefix_addr_t = {0};
						prefix_addr_t = retrieve_ipv6_prefix(*(struct in6_addr*)(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_address,
								(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits);

						/* Fill the Network Prefix and Prefix Length */
						ra->icmp.icmp6_data.icmp6_data8[0] = (ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits;
						ra->opt.prefix_length = (ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits;
						memcpy(ra->opt.prefix_addr, &prefix_addr_t.s6_addr, IPV6_ADDR_LEN);
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"RA: Fill the Network Prefix:"IPv6_FMT" and Prefix len:%u, TEID:%u\n",
								LOG_VALUE, IPv6_PRINT(*(struct in6_addr*)ra->opt.prefix_addr), ra->opt.prefix_length, tmp_teid);

						/* Set the ICMPv6 Header Checksum */
						ra->icmp.icmp6_cksum = 0;
						ra->icmp.icmp6_cksum = ipv6_icmp_cksum(ipv6_hdr, &ra->icmp);

						/* Update the IP and UDP header checksum */
						ra_set_checksum(pkt);

						/* Send ICMPv6 Router Advertisement resp */
						int pkt_size =
							RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));

						/* arp_pkt @arp_xmpool[port_id] */
						struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
						if (pkt1) {
							memcpy(pkt1, pkt, pkt_size);
							if (rte_ring_enqueue(shared_ring[in_port_id], pkt1) == -ENOBUFS) {
								rte_pktmbuf_free(pkt1);
								clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"RA:Can't queue pkt- ring full"
										" Dropping pkt\n", LOG_VALUE);
								return;
							}
							clLog(clSystemLog, eCLSeverityDebug,
									LOG_FORMAT"IPv6: Send ICMPv6_ROUTER_ADVERTISEMENT Message "
									"to IPv6 Addr:"IPv6_FMT"\n",
									LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr));
#ifdef STATS
							++epc_app.ul_params[in_port_id].pkts_rs_out;
#endif /* STATS */
						}
					} else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"RS:SESSION INFO: PDR/FAR not found(NULL) for UE IPv6:"IPv6_FMT"\n",
								LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
					}
				}
			}
		} else if (gtpuhdr && gtpuhdr->msgtype == GTPU_ERROR_INDICATION) {
			struct ipv4_hdr *ip_hdr = get_mtoip(pkt);

			/* Handle the Error indication pkts received from the peer nodes */
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"ERROR_INDICATION: Received Error Indication pkts from the peer node:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ip_hdr->src_addr));
#ifdef STATS
			if(in_port_id == SGI_PORT_ID) {
				++epc_app.dl_params[in_port_id].pkts_err_in;
			} else {
				++epc_app.ul_params[in_port_id].pkts_err_in;
			}
#endif /* STATS */
		}
	} else if (eth_h->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6)) {
		/* Get the IPv6 Header from pkt */
		struct ipv6_hdr *ipv6_hdr = NULL;
		ipv6_hdr = get_mtoip_v6(pkt);

		/* L4: If next header is ICMPv6 and Neighbor Solicitation/Advertisement */
		if ((ipv6_hdr->proto == IPPROTO_ICMPV6) &&
				(ipv6_hdr->proto != IPPROTO_UDP)) {
			/* Get the ICMP IPv6 Header from pkt */
			struct icmp_hdr *icmp = NULL;
			icmp = get_mtoicmpv6(pkt);

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"IPv6: RCVD ICMPv6 Message Type:%u\n",
				LOG_VALUE, icmp->icmp_type);

			/* Process Neighbor Solicitation/Advertisement Messages */
			if (icmp->icmp_type == ICMPv6_NEIGHBOR_SOLICITATION) {
				struct icmp6_hdr_ns *ns = get_mtoicmpv6_ns(pkt);

				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: Process RCVD ICMPv6_NEIGHBOR_SOLICITATION Message..!!\n",
					LOG_VALUE);


				/* Validate the Target IPv6 Address */
				if (in_port_id == S1U_PORT_ID) {
					/* Validate the Source IPv6 address is in same network */
					if (memcmp(&(app.wb_ipv6), &ns->icmp6_target_addr, IPV6_ADDRESS_LEN) &&
							memcmp(&(app.wb_li_ipv6), &ns->icmp6_target_addr, IPV6_ADDRESS_LEN)) {
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"NEIGHBOR_SOLICITATION: Target dest addr mismatch "
							"Expected:app.wb_ipv6("IPv6_FMT" or "IPv6_FMT") != RCVD:ns->icmp6_target_addr("IPv6_FMT")\n",
							LOG_VALUE, IPv6_PRINT(app.wb_ipv6), IPv6_PRINT(app.wb_li_ipv6), IPv6_PRINT(ns->icmp6_target_addr));
						return;
					}
				} else if (in_port_id == SGI_PORT_ID) {
					/* Validate the Source IPv6 address is in same network */
					if (memcmp(&(app.eb_ipv6), &ns->icmp6_target_addr, IPV6_ADDRESS_LEN) &&
							memcmp(&(app.eb_li_ipv6), &ns->icmp6_target_addr, IPV6_ADDRESS_LEN)) {
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"NEIGHBOR_SOLICITATION: Target dest addr mismatch "
							"Expected:app.eb_ipv6("IPv6_FMT" or "IPv6_FMT") != RCVD:ns->icmp6_target_addr("IPv6_FMT")\n",
							LOG_VALUE, IPv6_PRINT(app.eb_ipv6), IPv6_PRINT(app.eb_li_ipv6), IPv6_PRINT(ns->icmp6_target_addr));
						return;
					}
				}

				/* Source hardware address */
				if (ns->opt.type == SRC_LINK_LAYER_ADDR) {
					struct ether_addr mac_addr = {0};

					/* Source IPv6 Address */
					struct in6_addr src_addr = {0};
					memcpy(&src_addr, (struct in6_addr *)ipv6_hdr->src_addr, IPV6_ADDRESS_LEN);

					/* Fill the Source Link Layer Address */
					memcpy(&mac_addr, &ns->opt.link_layer_addr, ETHER_ADDR_LEN);

					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6_ARP_NS: Check ARP entry for IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->src_addr));
					if (ARPICMP_DEBUG) {
						print_ipv6_eth(&mac_addr);
					}

					/* Add the ARP entry into arp table and resolved buffer packets */
					process_neighbor_advert_msg(&mac_addr, &src_addr, in_port_id);
#ifdef STATIC_ARP
					/* Build ICMPv6_NEIGHBOR_ADVERTISEMENT Resp */
					get_mac_ipv6_addr(arp_port_addresses, ns->icmp6_target_addr, in_port_id);

					/* Fill the ether header info */
					ether_addr_copy(&eth_h->s_addr, &eth_h->d_addr);
					ether_addr_copy(
							arp_port_addresses[in_port_id].mac_addr,
							&eth_h->s_addr);
					/* Fill the IPv6 header */
					memcpy(&ipv6_hdr->dst_addr, &ipv6_hdr->src_addr,
							IPV6_ADDRESS_LEN);
					memcpy(&ipv6_hdr->src_addr, &arp_port_addresses[in_port_id].ipv6.s6_addr,
							IPV6_ADDRESS_LEN);

					struct in6_addr target_addr = {0};
					memcpy(&target_addr, &ns->icmp6_target_addr, IPV6_ADDRESS_LEN);

					/* Reset the neighbor solicitaion header */
					memset(ns, 0, sizeof(struct icmp6_hdr_ns));

					struct icmp6_hdr_na *na = get_mtoicmpv6_na(pkt);
					memset(na, 0, sizeof(struct icmp6_hdr_na));

					/* Fill neighbor advertisement pkt */
					na->icmp6_type = ICMPv6_NEIGHBOR_ADVERTISEMENT;
					na->icmp6_code = 0;
					/*TODO: Calculate the checksum */
					//na->icmp6_cksum = 0;
					na->icmp6_flags = 0x60;
					//na->icmp6_reserved = 0;
					memcpy(&na->icmp6_target_addr, &arp_port_addresses[in_port_id].ipv6,
							IPV6_ADDRESS_LEN);

					na->opt.type = TRT_LINK_LAYER_ADDR;
					na->opt.length = (ETHER_ADDR_LEN + sizeof(na->opt.length))/8;
					memcpy(&na->opt.link_layer_addr, &arp_port_addresses[in_port_id].mac_addr,
							ETHER_ADDR_LEN);

					/* Send ICMPv6 Neighbor Advertisement resp */
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
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: Send ICMPv6_NEIGHBOR_ADVERTISEMENT Message "
						"to IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr));
#endif	/* STATIC_ARP */
				} else {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: RCVD ICMPv6_NEIGHBOR_SOLICITATION Message "
						"not include SRC_LINK_LAYER_ADDR\n", LOG_VALUE);
				}
			} else if (icmp->icmp_type == ICMPv6_NEIGHBOR_ADVERTISEMENT) {
				struct icmp6_hdr_na *na = get_mtoicmpv6_na(pkt);
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: Process RCVD ICMPv6_NEIGHBOR_ADVERTISEMENT Message..!!\n",
					LOG_VALUE);

				/* Validate the Target IPv6 Address */
				if (in_port_id == S1U_PORT_ID) {
					/* Validate the Source IPv6 address is in same network */
					if (memcmp(&(app.wb_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN) &&
							memcmp(&(app.wb_li_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN)) {
						if (memcmp(&(app.wb_l3_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN)) {
							clLog(clSystemLog, eCLSeverityDebug,
									LOG_FORMAT"NEIGHBOR_ADVERT: Dest Addr mismatch "
									"Expected:app.wb_ipv6("IPv6_FMT" or "IPv6_FMT") != RCVD:ns->ipv6_dst_addr("IPv6_FMT")\n",
									LOG_VALUE, IPv6_PRINT(app.wb_ipv6), IPv6_PRINT(app.wb_li_ipv6), IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr));
							return;
						}
					}
				} else if (in_port_id == SGI_PORT_ID) {
					/* Validate the Source IPv6 address is in same network */
					if (memcmp(&(app.eb_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN) &&
							memcmp(&(app.eb_li_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN)) {
						if (memcmp(&(app.eb_l3_ipv6), (struct in6_addr *)ipv6_hdr->dst_addr, IPV6_ADDRESS_LEN)) {
							clLog(clSystemLog, eCLSeverityDebug,
									LOG_FORMAT"NEIGHBOR_ADVERT: Dest Addr mismatch "
									"Expected:app.eb_ipv6("IPv6_FMT" or "IPv6_FMT") != RCVD:ns->ipv6_dst_addr("IPv6_FMT")\n",
									LOG_VALUE, IPv6_PRINT(app.eb_ipv6), IPv6_PRINT(app.eb_li_ipv6), IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr));
							return;
						}
					}
				}

				/* Target hardware address */
				if (na->opt.type == TRT_LINK_LAYER_ADDR) {
					struct ether_addr mac_addr = {0};

					/* Target IPv6 Address */
					struct in6_addr target_addr = {0};
					memcpy(&target_addr, &na->icmp6_target_addr, IPV6_ADDRESS_LEN);

					/* Fill the Source Link Layer Address */
					memcpy(&mac_addr, &na->opt.link_layer_addr, ETHER_ADDR_LEN);

					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6_ARP_NA: Check ARP entry for IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(na->icmp6_target_addr));
					if (ARPICMP_DEBUG) {
						print_ipv6_eth(&mac_addr);
					}

					/* Add the ARP entry into arp table and resolved buffer packets */
					process_neighbor_advert_msg(&mac_addr, &target_addr, in_port_id);
				} else {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: RCVD ICMPv6_NEIGHBOR_ADVERTISEMENT Message "
						"not include TRT_LINK_LAYER_ADDR\n", LOG_VALUE);
				}
			}
		} else if ((ipv6_hdr->proto == IPPROTO_UDP) &&
				(ipv6_hdr->proto != IPPROTO_ICMPV6)) {

			/* If UDP dest port is 2152, then pkt is GTPU-Echo request */
			struct gtpu_hdr *gtpuhdr = get_mtogtpu_v6(pkt);
			if (gtpuhdr && (gtpuhdr->msgtype == GTPU_ECHO_REQUEST)) {
				peer_address_t addr = {0};
				addr.type = IPV6_TYPE;
				memcpy(addr.ipv6.sin6_addr.s6_addr,
						ipv6_hdr->dst_addr, IPV6_ADDR_LEN);
				update_cli_stats(&addr, GTPU_ECHO_REQUEST, RCVD, it);

				/* Host IPv6 Address */
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: RCVD Echo Request Received From IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(addr.ipv6.sin6_addr.s6_addr)));

				process_echo_request(pkt, in_port_id, IPV6_TYPE);
				/* Send ECHO_RSP */
				int pkt_size =
					RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
				/* gtpu_echo_pkt @arp_xmpool[port_id] */
				struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
				if (pkt1) {
					memcpy(pkt1, pkt, pkt_size);
					if (rte_ring_enqueue(shared_ring[in_port_id], pkt1) == -ENOBUFS) {
						rte_pktmbuf_free(pkt1);
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Can't queue pkt- ring full"
								" Dropping pkt\n", LOG_VALUE);
						return;
					}

					update_cli_stats(&addr, GTPU_ECHO_RESPONSE, SENT,it);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"IPv6: Send Echo Response to IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(IPv6_CAST(addr.ipv6.sin6_addr.s6_addr)));

				}
			} else if (gtpuhdr && gtpuhdr->msgtype == GTPU_ECHO_RESPONSE) {

				/* TODO: Add the Handling for GTPU ECHO Resp Process for IPv6 */
				/* Host IPv6 Address */
				struct in6_addr ho_addr = {0};
				memcpy(&ho_addr.s6_addr, &ipv6_hdr->dst_addr, IPV6_ADDR_LEN);

				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"IPv6: RCVD Echo Response Received From IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(ho_addr));

#ifdef USE_REST
				/* If peer Restart counter value of peer node is less than privious value than start flusing session*/
				peer_address_t addr = {0};
				memcpy(addr.ipv6.sin6_addr.s6_addr,
						ipv6_hdr->dst_addr, IPV6_ADDR_LEN);
				addr.type = IPV6_TYPE;
				update_cli_stats(&addr, GTPU_ECHO_RESPONSE, RCVD, it);

				process_echo_response(pkt);
#endif /* USE_REST */
			} else if (gtpuhdr && gtpuhdr->msgtype == GTP_GPDU) {
				/* Process the Router Solicitation Message */
				struct ipv6_hdr *ipv6_hdr = NULL;
				ipv6_hdr = get_inner_mtoipv6(pkt);

				if (ipv6_hdr->proto == IPPROTO_ICMPV6) {
					/* Target IPv6 Address */
					struct in6_addr target_addr = {0};
					memcpy(&target_addr.s6_addr, &ipv6_hdr->src_addr, IPV6_ADDR_LEN);

					/* Get the ICMPv6 Header */
					struct icmp_hdr *icmp = NULL;
					icmp = get_inner_mtoicmpv6(pkt);

					if (icmp->icmp_type == ICMPv6_ROUTER_SOLICITATION) {
						/* Check the TEID value */
						if (!gtpuhdr->teid) {
							clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"IPv6: Failed to Process ICMPv6_ROUTER_SOLICITATION Message,"
								" due to teid value is not set\n",
								LOG_VALUE);
							return;
						}

						/* Retrieve Session info based on the teid */
						pfcp_session_datat_t *ul_sess_data = NULL;
						pfcp_session_datat_t *dl_sess_data = NULL;
						struct ul_bm_key key = {0};
						struct dl_bm_key dl_key = {0};
						key.teid = ntohl(gtpuhdr->teid);

						/* Get the session info */
						if (iface_lookup_uplink_data(&key, (void **)&ul_sess_data) < 0) {
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! ULKEY "
								"TEID: %u\n", LOG_VALUE, key.teid);
							return;
						}

						/* Check session data is not NULL */
						if (ul_sess_data == NULL) {
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! ULKEY "
								"TEID: %u\n", LOG_VALUE, key.teid);
							return;
						}
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"RS:SESSION INFO:"
							"TEID:%u, Session State:%u\n",
							LOG_VALUE, key.teid, ul_sess_data->sess_state);

						if (ul_sess_data->pdrs != NULL) {
							/* Get the Downlink PDR and FAR info */
							memcpy(&dl_key.ue_ip.ue_ipv6, &(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_address,
									IPV6_ADDR_LEN);

							/* Get the Downlink Session information */
							if (iface_lookup_downlink_data(&dl_key, (void **)&dl_sess_data) < 0) {
								clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! DLKEY "
									"UE IPv6: "IPv6_FMT"\n", LOG_VALUE,
									IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
								return;
							}

							/* Check session data is not NULL */
							if (dl_sess_data == NULL) {
								clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":RS:Session Data LKUP:FAIL!! DLKEY "
									"UE IPv6: "IPv6_FMT"\n", LOG_VALUE,
									IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
								return;
							}
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"RS:SESSION INFO:"
								"UE IPv6:"IPv6_FMT", Session State:%u\n",
								LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6),
								dl_sess_data->sess_state);
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT":RS:PDR is NULL in UL session for "
									"TEID: %u\n", LOG_VALUE, key.teid);
							return;
						}

						/* Validate PDR and FAR is not NULL */
						if ((dl_sess_data->pdrs != NULL) && ((dl_sess_data->pdrs)->far != NULL))
						{
							/* Processing received Router Solicitation Request and responsed with Advertisement Resp */
							uint32_t tmp_teid = ntohl((dl_sess_data->pdrs)->far->frwdng_parms.outer_hdr_creation.teid);
							clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"IPv6: Process RCVD ICMPv6_ROUTER_SOLICITATION Message..!!\n",
								LOG_VALUE);

							/* Update the GTPU TEID */
							process_router_solicitation_request(pkt, tmp_teid);

							/* Update the Inner IPv6 HDR Src Address */
							struct ipv6_hdr *ipv6_hdr = NULL;
							ipv6_hdr = (struct ipv6_hdr*)((char*)gtpuhdr + GTPU_HDR_SIZE);

							/* Update the Source Link Locak Layer Address */
							memcpy(&ipv6_hdr->src_addr, &app.wb_l3_ipv6, IPV6_ADDR_LEN);

							/* Update the Router Advertisement pkt */
							struct icmp6_hdr_ra *ra = get_mtoicmpv6_ra(pkt);

							/* Get the Network Prefix */
							struct in6_addr prefix_addr_t = {0};
							prefix_addr_t = retrieve_ipv6_prefix(*(struct in6_addr*)(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_address,
									(ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits);

							/* Fill the Network Prefix and Prefix Length */
							ra->icmp.icmp6_data.icmp6_data8[0] = (ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits;
							ra->opt.prefix_length = (ul_sess_data->pdrs)->pdi.ue_addr.ipv6_pfx_dlgtn_bits;
							memcpy(ra->opt.prefix_addr, &prefix_addr_t.s6_addr, IPV6_ADDR_LEN);
							clLog(clSystemLog, eCLSeverityDebug,
									LOG_FORMAT"RA: Fill the Network Prefix:"IPv6_FMT" and Prefix len:%u, TEID:%u\n",
									LOG_VALUE, IPv6_PRINT(*(struct in6_addr*)ra->opt.prefix_addr), ra->opt.prefix_length, tmp_teid);

							/* Set the ICMPv6 Header Checksum */
							ra->icmp.icmp6_cksum = 0;
							ra->icmp.icmp6_cksum = ipv6_icmp_cksum(ipv6_hdr, &ra->icmp);

							/* Update the IP and UDP header checksum */
							ra_set_checksum(pkt);


							/* Send ICMPv6 Router Advertisement resp */
							int pkt_size =
								RTE_CACHE_LINE_ROUNDUP(sizeof(struct rte_mbuf));
							/* arp_pkt @arp_xmpool[port_id] */
							struct rte_mbuf *pkt1 = arp_pkt[in_port_id];
							if (pkt1) {
								memcpy(pkt1, pkt, pkt_size);
								if (rte_ring_enqueue(shared_ring[in_port_id], pkt1) == -ENOBUFS) {
									rte_pktmbuf_free(pkt1);
									clLog(clSystemLog, eCLSeverityCritical,
										LOG_FORMAT"RA:Can't queue pkt- ring full"
										" Dropping pkt\n", LOG_VALUE);
									return;
								}
								clLog(clSystemLog, eCLSeverityDebug,
									LOG_FORMAT"IPv6: Send ICMPv6_ROUTER_ADVERTISEMENT Message "
									"to IPv6 Addr:"IPv6_FMT"\n",
									LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)ipv6_hdr->dst_addr));
#ifdef STATS
								++epc_app.ul_params[in_port_id].pkts_rs_out;
#endif /* STATS */
							}
						} else {
							clLog(clSystemLog, eCLSeverityCritical,
									LOG_FORMAT"RS:SESSION INFO: PDR/FAR not found(NULL) for UE IPv6:"IPv6_FMT"\n",
									LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)dl_key.ue_ip.ue_ipv6));
						}

					}
				}
			} else if (gtpuhdr && gtpuhdr->msgtype == GTPU_ERROR_INDICATION) {
				struct ipv6_hdr *ipv6_hdr = NULL;
				ipv6_hdr = get_mtoip_v6(pkt);

				/* Handle the Error indication pkts received from the peer nodes */
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"ERROR_INDICATION: Received Error Indication pkts from the peer node:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(ipv6_hdr->src_addr)));
#ifdef STATS
				if(in_port_id == SGI_PORT_ID) {
					++epc_app.dl_params[in_port_id].pkts_err_in;
				} else {
					++epc_app.ul_params[in_port_id].pkts_err_in;
				}
#endif /* STATS */
			}
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

#ifdef STATIC_ARP
/**
 * @brief  : Add static arp entry for IPv4 Address
 * @param  : entry, entry to be added
 * @param  : port_id, port number
 * @return : Returns nothing
 */
static void
add_static_arp_ipv4_entry(struct rte_cfgfile_entry *entry,
			uint8_t port_id)
{
	struct arp_ip_key key;
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
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv4:Error parsing static arp entry: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	ret = inet_aton(low_ptr, &low_addr);
	if (ret == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv4:Error parsing static arp entry: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	if (high_ptr) {
		ret = inet_aton(high_ptr, &high_addr);
		if (ret == 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"IPv4:Error parsing static arp entry: %s = %s\n",
				LOG_VALUE, entry->name, entry->value);
			return;
		}
	} else {
		high_addr = low_addr;
	}

	low_ip = ntohl(low_addr.s_addr);
	high_ip = ntohl(high_addr.s_addr);

	if (high_ip < low_ip) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv4:Error parsing static arp entry"
			" - range must be low to high: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	if (parse_ether_addr(&hw_addr, entry->value)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv4:Error parsing static arp entry mac addr"
			"%s = %s\n", LOG_VALUE, entry->name, entry->value);
		return;
	}

	for (cur_ip = low_ip; cur_ip <= high_ip; ++cur_ip) {

		key.ip_type.ipv4 = PRESENT;
		key.ip_addr.ipv4 = ntohl(cur_ip);

		data = rte_malloc_socket(NULL,
				sizeof(struct arp_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (data == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"IPv4:Error allocating arp entry - "
				"%s = %s\n", LOG_VALUE, entry->name, entry->value);
			return;
		}

		data->eth_addr = hw_addr;
		data->port = port_id;
		data->status = COMPLETE;
		data->ip_type.ipv4 = PRESENT;
		data->ipv4 = key.ip_addr.ipv4;
		data->last_update = time(NULL);
		data->queue = NULL;

		add_arp_data(&key, data, port_id);
	}
}

/**
 * @brief  : Add static arp entry for IPv6 Address
 * @param  : entry, entry to be added
 * @param  : port_id, port number
 * @return : Returns nothing
 */
static void
add_static_arp_ipv6_entry(struct rte_cfgfile_entry *entry,
			uint8_t port_id)
{
	struct arp_ip_key key;
	struct arp_entry_data *data;
	char *low_ptr;
	char *high_ptr;
	char *saveptr;
	struct in6_addr low_addr;
	struct in6_addr high_addr;
	struct ether_addr hw_addr;
	int ret;

	low_ptr = strtok_r(entry->name, " \t", &saveptr);
	high_ptr = strtok_r(NULL, " \t", &saveptr);

	if (low_ptr == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv6:Error parsing static arp entry: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	ret = inet_pton(AF_INET6, low_ptr, &low_addr);
	if (ret == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv6:Error parsing static arp entry: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	if (high_ptr) {
		ret = inet_pton(AF_INET6, high_ptr, &high_addr);
		if (ret == 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"IPv6:Error parsing static arp entry: %s = %s\n",
				LOG_VALUE, entry->name, entry->value);
			return;
		}
	} else {
		high_addr = low_addr;
	}

	if (memcmp(&low_addr, &high_addr, IPV6_ADDRESS_LEN) > 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv6:Error parsing static arp entry"
			" - range must be low to high: %s = %s\n",
			LOG_VALUE, entry->name, entry->value);
		return;
	}

	if (parse_ether_addr(&hw_addr, entry->value)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"IPv6:Error parsing static arp entry mac addr"
			"%s = %s\n", LOG_VALUE, entry->name, entry->value);
		return;
	}

	if (!memcmp(&low_addr, &high_addr, IPV6_ADDRESS_LEN)) {
		key.ip_type.ipv6 = PRESENT;
		memcpy(&key.ip_addr.ipv6, &low_addr, IPV6_ADDRESS_LEN);

		data = rte_malloc_socket(NULL,
				sizeof(struct arp_entry_data),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (data == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error allocating arp entry - "
				"%s = %s\n", LOG_VALUE, entry->name, entry->value);
			return;
		}

		data->eth_addr = hw_addr;
		data->port = port_id;
		data->status = COMPLETE;
		data->last_update = time(NULL);
		data->queue = NULL;
		data->ip_type.ipv6 = PRESENT;
		memcpy(&data->ipv6, &key.ip_addr.ipv6, IPV6_ADDRESS_LEN);

		add_arp_data(&key, data, port_id);
	} else {
		int bit = 0;
		for (;;) {
			/* Break the Loop if low addr reached to high range */
			if (memcmp(&low_addr, &high_addr, IPV6_ADDRESS_LEN) > 0) {
				break;
			}

			key.ip_type.ipv6 = PRESENT;
			memcpy(&key.ip_addr.ipv6, &low_addr, IPV6_ADDRESS_LEN);

			data = rte_malloc_socket(NULL,
					sizeof(struct arp_entry_data),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (data == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error allocating arp entry - "
					"%s = %s\n", LOG_VALUE, entry->name, entry->value);
				return;
			}

			data->eth_addr = hw_addr;
			data->port = port_id;
			data->status = COMPLETE;
			data->last_update = time(NULL);
			data->queue = NULL;
			data->ip_type.ipv6 = PRESENT;
			memcpy(&data->ipv6, &key.ip_addr.ipv6, IPV6_ADDRESS_LEN);

			add_arp_data(&key, data, port_id);

			/* Increment the Low addr pointer towards high pointer*/
			for (bit = 15; bit >=0; --bit) {
				if (low_addr.s6_addr[bit] < 255) {
					low_addr.s6_addr[bit]++;
					break;
				} else {
					low_addr.s6_addr[bit] = 0;
				}
			}

			/* Break the loop if reached to last bit*/
			if (bit < 0) {
				break;
			}
		}
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
	int i;
	int num_eb_entries;
	int num_wb_entries;
	struct rte_cfgfile_entry *eb_entries = NULL;
	struct rte_cfgfile_entry *wb_entries = NULL;
	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_ARP_FILE, 0);

	if (file == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Cannot load configuration file %s\n",
			LOG_VALUE, STATIC_ARP_FILE);
		return;
	}

	clLog(clSystemLog, eCLSeverityCritical,
		LOG_FORMAT"Parsing %s\n", LOG_VALUE, STATIC_ARP_FILE);

	/* VS: EB IPv4 entries */
	num_eb_entries = rte_cfgfile_section_num_entries(file, "EASTBOUND_IPv4");
	if (num_eb_entries > 0) {
		eb_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_eb_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (eb_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error configuring EB IPv4 entry of %s\n", LOG_VALUE,
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "EASTBOUND_IPv4", eb_entries,
				num_eb_entries);

		for (i = 0; i < num_eb_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[EASTBOUND_IPv4]: %s = %s\n", eb_entries[i].name,
					eb_entries[i].value);
			add_static_arp_ipv4_entry(&eb_entries[i], SGI_PORT_ID);
		}
		rte_free(eb_entries);
		eb_entries = NULL;
	}

	/* VS: EB IPv6 entries */
	num_eb_entries = rte_cfgfile_section_num_entries(file, "EASTBOUND_IPv6");
	if (num_eb_entries > 0) {
		eb_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_eb_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (eb_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error configuring EB IPv6 entry of %s\n", LOG_VALUE,
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "EASTBOUND_IPv6", eb_entries,
				num_eb_entries);

		for (i = 0; i < num_eb_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[EASTBOUND_IPv6]: %s = %s\n", eb_entries[i].name,
					eb_entries[i].value);
			add_static_arp_ipv6_entry(&eb_entries[i], SGI_PORT_ID);
		}
		rte_free(eb_entries);
		eb_entries = NULL;
	}

	/* VS: WB IPv4 entries */
	num_wb_entries = rte_cfgfile_section_num_entries(file, "WESTBOUND_IPv4");
	if (num_wb_entries > 0) {
		wb_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_wb_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (wb_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error configuring WB IPv4 entry of %s\n", LOG_VALUE,
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "WESTBOUND_IPv4", wb_entries,
				num_wb_entries);
		for (i = 0; i < num_wb_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[WESTBOUND_IPv4]: %s = %s\n", wb_entries[i].name,
					wb_entries[i].value);
			add_static_arp_ipv4_entry(&wb_entries[i], S1U_PORT_ID);
		}
		rte_free(wb_entries);
		wb_entries = NULL;
	}

	/* VS: WB IPv6 entries */
	num_wb_entries = rte_cfgfile_section_num_entries(file, "WESTBOUND_IPv6");
	if (num_wb_entries > 0) {
		wb_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_wb_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}
	if (wb_entries == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error configuring WB IPv6 entry of %s\n", LOG_VALUE,
				STATIC_ARP_FILE);
	} else {
		rte_cfgfile_section_entries(file, "WESTBOUND_IPv6", wb_entries,
				num_wb_entries);
		for (i = 0; i < num_wb_entries; ++i) {
			clLog(clSystemLog, eCLSeverityDebug,"[WESTBOUND_IPv6]: %s = %s\n", wb_entries[i].name,
					wb_entries[i].value);
			add_static_arp_ipv6_entry(&wb_entries[i], S1U_PORT_ID);
		}
		rte_free(wb_entries);
		wb_entries = NULL;
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
 * @brief  : Print IPv6 Link Local Layer entry information
 * @param  : entry, route information entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int print_ipv6_link_entry(
		struct RouteInfo_v6 *entry)
{
		/* VS:  Print the route records on cosole */
		printf("--------------------- \t\t\t-------\n");
		printf("Local Link Layer Addr \t\t\tIfname \n");
		printf("--------------------- \t\t\t-------\n");

		printf(""IPv6_FMT"\t%s\n",
		        IPv6_PRINT(entry->dstAddr),
		        entry->ifName);

		printf("--------------------- \t\t\t--------\n");
		return 0;
}

/**
 * @brief  : Print IPv6 route entry information
 * @param  : entry, route information entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int print_ipv6_route_entry(
		struct RouteInfo_v6 *entry)
{
		/* VS:  Print the route records on cosole */
		printf("-----------\t------- \t------ \n");
		printf("Destination\tNext Hop\tIfname \n");
		printf("-----------\t------- \t------ \n");

		printf(""IPv6_FMT"\t"IPv6_FMT"\t%s\n",
		        IPv6_PRINT(entry->dstAddr),
				IPv6_PRINT(entry->gateWay),
		        entry->ifName);

		printf("-----------\t------- \t------- \n");
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
 * @brief  : Delete entry in route table for IPv6.
 * @param  : info, route information entry
 * @return : Returns nothing
 */
static void del_ipv6_route_entry(
			struct RouteInfo_v6 *info)
{
	printf("Route entry DELETED in hash table :: \n");
	print_ipv6_route_entry(info);
	return;
}
/**
 * @brief  : Add entry in route table for IPv6.
 * @param  : info, route information entry
 * @return : Returns nothing
 */
static void add_ipv6_route_entry(
			struct RouteInfo_v6 *info)
{
	printf("Route entry ADDED in hash table :: \n");
	print_ipv6_route_entry(info);
	return;
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

			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Route entry ADDED in hash table\n", LOG_VALUE);
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

	strncpy(iface_Name, ifr.ifr_name, IF_NAMESIZE);
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
		perror("Error");
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
	clLog(clSystemLog, eCLSeverityCritical,
		LOG_FORMAT"Failed to readCache\n", LOG_VALUE);
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
	char *ret = NULL;
	char *s = NULL;

	char *Line = malloc(strnlen(Line_Arg, ARP_BUFFER_LEN)), *ptr;
	if(Line != NULL){
		memcpy(Line, Line_Arg, strnlen(Line_Arg, ARP_BUFFER_LEN));
		ptr = Line;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to allocate memory\n",
			LOG_VALUE);
	}

	s = strtok(Line, ARP_DELIM);
	while (Field && s)
	{
	    s = strtok(NULL, ARP_DELIM);
	    Field--;
	};

	if (s)
	{
	    int len = strnlen(s,ARP_BUFFER_LEN);
		ret = (char*)malloc(len + 1);
	    memset(ret, 0, len + 1);
	    memcpy(ret, s, len);
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

			strncpy(iface_Mac, Mac, MAC_ADDR_LEN);
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
*netlink_recv_thread_ipv6(void *arg)
{
	int i = 0;
	int		recv_bytes = 0;
	struct	nlmsghdr *nlp;
	struct	rtmsg *rtp;
	struct	RouteInfo_v6 route[24];
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

			recv_bytes = recv(route_sock_v6, buffer, sizeof(buffer), 0);

			if (recv_bytes < 0)
			    clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"IPv6: Error in recv\n", LOG_VALUE);

		    nlp = (struct nlmsghdr *) buffer;

			if ((nlp->nlmsg_type == NLMSG_DONE) ||
					(nlp->nlmsg_type == RTM_NEWROUTE) ||
					(nlp->nlmsg_type == RTM_DELROUTE) ||
					(nlp->nlmsg_type == RTM_NEWADDR) ||
					(addr->nl_groups == RTMGRP_IPV6_ROUTE))
				break;
		}

		if (nlp->nlmsg_type == RTM_NEWADDR) {

			/* Set the Reference Link Local Layer Address*/
			struct in6_addr tmp_addr = {0};
			char *tmp = "fe80::";
			/* All Node IPV6 Address */
			if (!inet_pton(AF_INET6, tmp, &tmp_addr)) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"LL2:Invalid Local Link layer IPv6 Address\n", LOG_VALUE);
			}

			for (i = -1 ; NLMSG_OK(nlp, recv_bytes); \
					nlp = NLMSG_NEXT(nlp, recv_bytes))
			{
				uint8_t ignore = 0;
				struct ifaddrmsg *ifa = NULL;

				i++;
				/* Get the interface details */
				ifa = (struct ifaddrmsg *)NLMSG_DATA(nlp);
				/* Get the interface attribute info */
				rtap = (struct rtattr *)IFA_RTA(ifa);

				/* Get the interface info and check valid interface needed */
				get_iface_name(ifa->ifa_index, route[i].ifName);

				rtl = IFA_PAYLOAD(nlp);

				/* Loop through all attributes */
				for( ; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl))
				{
					switch(rtap->rta_type) {
						case IFA_ADDRESS:
							memcpy(&route[i].dstAddr.s6_addr, RTA_DATA(rtap), IPV6_ADDR_LEN);
							break;
						default:
							break;
					}
				}
				/* Filter the WBdev and EBdev Interfaces */
				if (!memcmp(&route[i].ifName, &app.wb_iface_name, MAX_LEN)) {
					/* Validate the Link Layer hexstat: 2 byte, 'fe80' */
					for (uint8_t inx = 0; inx < 2; inx++) {
						if (memcmp(&route[i].dstAddr.s6_addr[inx], &tmp_addr.s6_addr[inx],
									sizeof(route[i].dstAddr.s6_addr[inx]))) {
							ignore = 1;
							break;
						}
					}
					if (!ignore) {
						fprintf(stderr, "IPv6: %s interface Local Link Layer Addr..\n", route[i].ifName);
						app.wb_l3_ipv6 = route[i].dstAddr;
						print_ipv6_link_entry(&route[i]);
					}
				}

				if (!memcmp(&route[i].ifName, &app.eb_iface_name, MAX_LEN)) {
					/* Validate the Link Layer hexstat: 2 byte, 'fe80' */
					for (uint8_t inx = 0; inx < 2; inx++) {
						if (memcmp(&route[i].dstAddr.s6_addr[inx], &tmp_addr.s6_addr[inx],
									sizeof(route[i].dstAddr.s6_addr[inx]))) {
							ignore = 1;
							break;
						}
					}
					if (!ignore) {
						fprintf(stderr, "IPv6: %s interface Local Link Layer Addr..\n", route[i].ifName);
						app.eb_l3_ipv6 = route[i].dstAddr;
						print_ipv6_link_entry(&route[i]);
					}
				}
			}
		} else {
			for (i = -1 ; NLMSG_OK(nlp, recv_bytes); \
					nlp = NLMSG_NEXT(nlp, recv_bytes))
			{
				rtp = (struct rtmsg *) NLMSG_DATA(nlp);

				/* Get main routing table */
				if ((rtp->rtm_family != AF_INET6) ||
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

					switch(rtap->rta_type) {
						case RTA_DST:
							route[i].dstAddr = *(struct in6_addr *)RTA_DATA(rtap);
							break;
						case RTA_GATEWAY:
							route[i].gateWay = *(struct in6_addr *)RTA_DATA(rtap);
							break;
						case RTA_SRC:
							route[i].srcAddr = *(struct in6_addr *)RTA_DATA(rtap);
							break;
						case RTA_PREFSRC:
							route[i].srcAddr = *(struct in6_addr *)RTA_DATA(rtap);
							break;
						case RTA_OIF:
							get_iface_name(*((int *) RTA_DATA(rtap)),
									route[i].ifName);
							break;
						case RTA_IIF:
							break;
						default:
							break;
					}
				}

				/* Now we can dump the routing attributes */
				if (nlp->nlmsg_type == RTM_DELROUTE) {
					del_ipv6_route_entry(&route[i]);
				}

				if (nlp->nlmsg_type == RTM_NEWROUTE) {
					add_ipv6_route_entry(&route[i]);
				}
			}
		}
	}

	fprintf(stderr, "IPv6: Netlink Listner thread terminated.\n");
	return NULL; //GCC_Security flag
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

			recv_bytes = recv(route_sock_v4, buffer, sizeof(buffer), 0);

			if (recv_bytes < 0)
			    clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Error in recv\n", LOG_VALUE);

		    nlp = (struct nlmsghdr *) buffer;

			if ((nlp->nlmsg_type == NLMSG_DONE) ||
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
								char mac[MAC_ADDR_LEN];

								route[i].gateWay = *(uint32_t *) RTA_DATA(rtap);
								get_gateWay_mac(route[i].gateWay, mac);

								if (parse_ether_addr(&(route[i].gateWay_Mac), mac)) {
									clLog(clSystemLog, eCLSeverityDebug,
										LOG_FORMAT"Error parsing gatway arp entry mac addr"
										"= %s\n", LOG_VALUE, mac);
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

		}
	}
	fprintf(stderr, "IPv4: Netlink Listner thread terminated.\n");
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
	struct sockaddr_nl addr_v6;
	struct addr_info addr = {0};

	route_request *request =
		(route_request *)malloc(sizeof(route_request));
	route_request *request_v6 =
		(route_request *)malloc(sizeof(route_request));

	route_sock_v4 = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	route_sock_v6 = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"NetLink Sockets Created, IPv4:%u, IPv6:%u\n",
			LOG_VALUE, route_sock_v4, route_sock_v6);

	bzero(request, sizeof(route_request));
	bzero(request_v6, sizeof(route_request));

	/* Fill the NETLINK header for IPv4 */
	request->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request->nlMsgHdr.nlmsg_type = RTM_GETROUTE;
	//request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	/* set the routing message header IPv4*/
	request->rtMsg.rtm_family = AF_INET;
	request->rtMsg.rtm_table = RT_TABLE_MAIN;

	/* Set Sockets info for IPv4 */
	addr_t.nl_family = PF_NETLINK;
	addr_t.nl_pad = 0;
	addr_t.nl_pid = getpid();
	addr_t.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_ROUTE;

	/* Fill the NETLINK header for IPv6 */
	request_v6->nlMsgHdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
	request_v6->nlMsgHdr.nlmsg_type = RTM_GETROUTE | RTM_GETADDR;
	request_v6->nlMsgHdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;

	/* set the routing message header IPv6*/
	request_v6->rtMsg.rtm_family = AF_INET6;
	request_v6->rtMsg.rtm_table = RT_TABLE_MAIN;

	/* Set Sockets info for IPv6 */
	addr_v6.nl_family = PF_NETLINK;
	addr_v6.nl_pad = 0;
	//addr_v6.nl_pid = getpid();
	addr_v6.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR;

	if (bind(route_sock_v4, (struct sockaddr *)&addr_t, sizeof(addr_t)) < 0) {
		fprintf(stderr, "IPv4 bind socket ID:%u\n", route_sock_v4);
		ERR_RET("IPv4 bind socket");
	}

	if (bind(route_sock_v6, (struct sockaddr *)&addr_v6, sizeof(addr_v6)) < 0) {
		fprintf(stderr, "IPv6 bind socket ID:%u\n", route_sock_v6);
		ERR_RET("IPv6 bind socket");
	}

	/* Send routing request IPv4 */
	if ((retValue = send(route_sock_v4, request, sizeof(route_request), 0)) < 0)
	{
	    perror("IPv4: Send");
	    return -1;
	}

	/* Send routing request IPv6 */
	if ((retValue = send(route_sock_v6, request_v6, sizeof(route_request), 0)) < 0)
	{
	    perror("IPv6: Send");
	    return -1;
	}

	/* Fill the IPv4 and IPv6 Addr Structure */
	addr.addr_ipv4 = addr_t;
	addr.addr_ipv6 = addr_v6;

	/*
	 * Create pthread to read or receive data/events from netlink socket.
	 */
	pthread_t net, net1;
	int err_val;

	err_val = pthread_create(&net, NULL, &netlink_recv_thread, &addr.addr_ipv4);
	if (err_val != 0) {
	    printf("\nAPI_IPv4: Can't create Netlink socket event reader thread :[%s]\n",
				strerror(err_val));
		return -1;
	}

	err_val = pthread_create(&net1, NULL, &netlink_recv_thread_ipv6, &addr.addr_ipv6);
	if (err_val != 0) {
	    printf("\nAPI_IPv6: Can't create Netlink socket event reader thread :[%s]\n",
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
	uint32_t i;
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
	}

	/* Output port configuration */
	for (i = 0; i < epc_app.n_ports; i++) {
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

void process_li_data(){

	int ret = 0;
	struct ip_addr dummy = {0};
	uint32_t li_ul_cnt = rte_ring_count(li_ul_ring);
	if(li_ul_cnt){
		li_data_t *li_data[li_ul_cnt];
		uint32_t ul_cnt = rte_ring_dequeue_bulk(li_ul_ring,
				(void**)li_data, li_ul_cnt, NULL);

		for(uint32_t i = 0; i < ul_cnt; i++){

			if (NULL == li_data[i]) {
				continue;
			}

			int size = li_data[i]->size;
			uint64_t id = li_data[i]->id;
			uint64_t imsi = li_data[i]->imsi;

			if (NULL == li_data[i]->pkts) {
				continue;
			}

			create_li_header(li_data[i]->pkts, &size, CC_BASED, id, imsi, dummy, dummy,
					0, 0, li_data[i]->forward);

			ret = send_li_data_pkt(ddf3_fd, li_data[i]->pkts, size);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to send UPLINK"
					" data on TCP sock with error %d\n", LOG_VALUE, ret);
			}
			rte_free(li_data[i]->pkts);
			rte_free(li_data[i]);
		}
	}
	uint32_t li_dl_cnt = rte_ring_count(li_dl_ring);
	if(li_dl_cnt){
		li_data_t *li_data[li_dl_cnt];
		uint32_t dl_cnt = rte_ring_dequeue_bulk(li_dl_ring,
				(void**)li_data, li_dl_cnt, NULL);

		for(uint32_t i = 0; i < dl_cnt; i++){
			if (li_data[i] == NULL) {
				continue;
			}

			int size = li_data[i]->size;
			uint64_t id = li_data[i]->id;
			uint64_t imsi = li_data[i]->imsi;

			if (li_data[i]->pkts == NULL) {
				continue;
			}

			create_li_header(li_data[i]->pkts, &size, CC_BASED, id, imsi, dummy, dummy,
					0, 0, li_data[i]->forward);

			ret = send_li_data_pkt(ddf3_fd, li_data[i]->pkts, size);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to send DOWNLINK"
					" data on TCP sock with error %d\n", LOG_VALUE, ret);
			}

			rte_free(li_data[i]->pkts);
			rte_free(li_data[i]);
		}
	}

	return;
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
	process_li_data();
}
