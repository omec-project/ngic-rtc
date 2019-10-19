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

#include <signal.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_hash_crc.h>

#include "ue.h"
#include "pfcp.h"
#include "gtpv2c.h"
#include "cp_stats.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"

#ifdef C3PO_OSS
#include"cp_config.h"
#endif /* C3PO_OSS */

#ifdef USE_DNS_QUERY
#include "cdnshelper.h"
#endif /* USE_DNS_QUERY */

#define PCAP_TTL           (64)
#define PCAP_VIHL          (0x0045)

int s11_fd = -1;
int s5s8_fd = -1;
int pfcp_fd = -1;
int s11_pcap_fd = -1;

pcap_t *pcap_reader;
pcap_dumper_t *pcap_dumper;

enum cp_config spgw_cfg;
struct cp_stats_t cp_stats;
extern pfcp_config_t pfcp_config;

/* MME */
struct sockaddr_in s11_mme_sockaddr;

/* S5S8 */
struct sockaddr_in s5s8_recv_sockaddr;

/* PFCP */
in_port_t pfcp_port;
struct sockaddr_in pfcp_sockaddr;

/* UPF PFCP */
in_port_t upf_pfcp_port;
struct sockaddr_in upf_pfcp_sockaddr;
socklen_t s5s8_sockaddr_len = sizeof(s5s8_sockaddr);
socklen_t s11_mme_sockaddr_len = sizeof(s11_mme_sockaddr);

in_port_t s11_port;
in_port_t s5s8_port;
struct sockaddr_in s11_sockaddr;
struct sockaddr_in s5s8_sockaddr;

uint8_t s11_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s11_tx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t pfcp_tx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t msg_buf_t[MAX_GTPV2C_UDP_LEN];
uint8_t tx_buf[MAX_GTPV2C_UDP_LEN];

#ifdef USE_REST
/* ECHO PKTS HANDLING */
uint8_t echo_tx_buf[MAX_GTPV2C_UDP_LEN];
#endif /* USE_REST */


uint8_t s5s8_rx_buf[MAX_GTPV2C_UDP_LEN];
uint8_t s5s8_tx_buf[MAX_GTPV2C_UDP_LEN];

#ifdef SYNC_STATS
/**
 * @brief Initializes the hash table used to account for statstics of req and resp time.
 */
void
init_stats_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "stats_hash",
	    .entries = STATS_HASH_SIZE,
	    .key_len = sizeof(uint64_t),
	    .hash_func = rte_hash_crc,
	    .hash_func_init_val = 0,
	    .socket_id = rte_socket_id(),
	};

	stats_hash = rte_hash_create(&rte_hash_params);
	if (!stats_hash) {
		rte_panic("%s hash create failed: %s (%u)\n",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

#endif /* SYNC_STATS */

void
stats_update(uint8_t msg_type)
{
	switch (pfcp_config.cp_type) {
		case SGWC:
		case SAEGWC:
			switch (msg_type) {
				case GTP_CREATE_SESSION_REQ:
					cp_stats.create_session++;
					break;
				case GTP_DELETE_SESSION_REQ:
					cp_stats.delete_session++;
					break;
				case GTP_MODIFY_BEARER_REQ:
					cp_stats.modify_bearer++;
					break;
				case GTP_RELEASE_ACCESS_BEARERS_REQ:
					cp_stats.rel_access_bearer++;
					break;
				case GTP_BEARER_RESOURCE_CMD:
					cp_stats.bearer_resource++;
					break;

				case GTP_DELETE_BEARER_RSP:
					cp_stats.delete_bearer++;
					return;
				case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
					cp_stats.ddn_ack++;
					break;
				case GTP_ECHO_REQ:
					cp_stats.echo++;
					break;
			}
			break;

		case PGWC:
			 switch (msg_type) {
			 case GTP_CREATE_SESSION_REQ:
				 cp_stats.create_session++;
				 break;

			 case GTP_DELETE_SESSION_REQ:
			     cp_stats.delete_session++;
			     break;
			 }
			break;
	default:
			rte_panic("main.c::control_plane::cp_stats-"
					"Unknown spgw_cfg= %d.", pfcp_config.cp_type);
			break;
		}
}

void
dump_pcap(uint16_t payload_length, uint8_t *tx_buf)
{
	static struct pcap_pkthdr pcap_tx_header;
	gettimeofday(&pcap_tx_header.ts, NULL);
	pcap_tx_header.caplen = payload_length
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr);
	pcap_tx_header.len = payload_length
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr);
	uint8_t dump_buf[MAX_GTPV2C_UDP_LEN
			+ sizeof(struct ether_hdr)
			+ sizeof(struct ipv4_hdr)
			+ sizeof(struct udp_hdr)];
	struct ether_hdr *eh = (struct ether_hdr *) dump_buf;

	memset(&eh->d_addr, '\0', sizeof(struct ether_addr));
	memset(&eh->s_addr, '\0', sizeof(struct ether_addr));
	eh->ether_type = htons(ETHER_TYPE_IPv4);

	struct ipv4_hdr *ih = (struct ipv4_hdr *) &eh[1];

	ih->dst_addr = pfcp_config.s11_mme_ip.s_addr;
	ih->src_addr = pfcp_config.s11_ip.s_addr;
	ih->next_proto_id = IPPROTO_UDP;
	ih->version_ihl = PCAP_VIHL;
	ih->total_length =
			ntohs(payload_length
				+ sizeof(struct udp_hdr)
				+ sizeof(struct ipv4_hdr));
	ih->time_to_live = PCAP_TTL;

	struct udp_hdr *uh = (struct udp_hdr *) &ih[1];

	uh->dgram_len = htons(
	    ntohs(ih->total_length) - sizeof(struct ipv4_hdr));
	uh->dst_port = htons(GTPC_UDP_PORT);
	uh->src_port = htons(GTPC_UDP_PORT);

	void *payload = &uh[1];
	memcpy(payload, tx_buf, payload_length);
	pcap_dump((u_char *) pcap_dumper, &pcap_tx_header,
			dump_buf);
	fflush(pcap_dump_file(pcap_dumper));
}

/**
 * @brief
 * Util to send or dump gtpv2c messages
 */
void
gtpv2c_send(int gtpv2c_if_fd, uint8_t *gtpv2c_tx_buf,
		uint16_t gtpv2c_pyld_len, struct sockaddr *dest_addr,
		socklen_t dest_addr_len)
{
	int bytes_tx;
	if (pcap_dumper) {
		dump_pcap(gtpv2c_pyld_len, gtpv2c_tx_buf);
	} else {
		bytes_tx = sendto(gtpv2c_if_fd, gtpv2c_tx_buf, gtpv2c_pyld_len, 0,
			(struct sockaddr *) dest_addr, dest_addr_len);

		clLog(clSystemLog, eCLSeverityDebug, "NGIC- main.c::gtpv2c_send()""\n\tgtpv2c_if_fd= %d\n", gtpv2c_if_fd);

	if (bytes_tx != (int) gtpv2c_pyld_len) {
			fprintf(stderr, "Transmitted Incomplete GTPv2c Message:"
					"%u of %d tx bytes\n",
					gtpv2c_pyld_len, bytes_tx);
		}
	}
}

#ifdef USE_DNS_QUERY
static void
set_dns_config(void)
{
	set_dnscache_refresh_params(pfcp_config.dns_cache.concurrent,
			pfcp_config.dns_cache.percent, pfcp_config.dns_cache.sec);

	set_dns_retry_params(pfcp_config.dns_cache.timeoutms,
			pfcp_config.dns_cache.tries);

	/* set OPS dns config */
	for (uint32_t i = 0; i < pfcp_config.ops_dns.nameserver_cnt; i++)
	{
		set_nameserver_config(pfcp_config.ops_dns.nameserver_ip[i],
				DNS_PORT, DNS_PORT, NS_OPS);
	}

	apply_nameserver_config(NS_OPS);
	init_save_dns_queries(NS_OPS, pfcp_config.ops_dns.filename,
			pfcp_config.ops_dns.freq_sec);
	load_dns_queries(NS_OPS, pfcp_config.ops_dns.filename);

	/* set APP dns config */
	for (uint32_t i = 0; i < pfcp_config.app_dns.nameserver_cnt; i++)
		set_nameserver_config(pfcp_config.app_dns.nameserver_ip[i],
				DNS_PORT, DNS_PORT, NS_APP);

	apply_nameserver_config(NS_APP);
	init_save_dns_queries(NS_APP, pfcp_config.app_dns.filename,
			pfcp_config.app_dns.freq_sec);
	load_dns_queries(NS_APP, pfcp_config.app_dns.filename);
}
#endif /* USE_DNS_QUERY */

void
init_pfcp(void)
{
	int ret;
	upf_pfcp_sockaddr.sin_port = htons(pfcp_config.upf_pfcp_port);
	pfcp_port = htons(pfcp_config.pfcp_port);

	pfcp_fd = socket(AF_INET, SOCK_DGRAM, 0);
	my_sock.sock_fd = pfcp_fd;

	if (pfcp_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(pfcp_sockaddr.sin_zero,
			sizeof(pfcp_sockaddr.sin_zero));
	pfcp_sockaddr.sin_family = AF_INET;
	pfcp_sockaddr.sin_port = pfcp_port;
	pfcp_sockaddr.sin_addr = pfcp_config.pfcp_ip;

	ret = bind(pfcp_fd, (struct sockaddr *) &pfcp_sockaddr,
			sizeof(struct sockaddr_in));

	clLog(sxlogger, eCLSeverityInfo,  "NGIC- main.c::init_pfcp()" "\n\tpfcp_fd = %d :: "
			"\n\tpfcp_ip = %s : pfcp_port = %d\n",
			pfcp_fd, inet_ntoa(pfcp_config.pfcp_ip),
			ntohs(pfcp_port));
	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
				inet_ntoa(pfcp_sockaddr.sin_addr),
				ntohs(pfcp_sockaddr.sin_port),
				strerror(errno));
	}

#ifndef USE_DNS_QUERY
	/* Initialize peer UPF inteface for sendto(.., dest_addr), If DNS is Disable */
	upf_pfcp_port =  htons(pfcp_config.upf_pfcp_port);
	bzero(upf_pfcp_sockaddr.sin_zero,
			sizeof(upf_pfcp_sockaddr.sin_zero));
	upf_pfcp_sockaddr.sin_family = AF_INET;
	upf_pfcp_sockaddr.sin_port = upf_pfcp_port;
	upf_pfcp_sockaddr.sin_addr = pfcp_config.upf_pfcp_ip;
#endif  /* USE_DNS_QUERY */
}


/**
 * @brief Initalizes S11 interface if in use
 */
static void
init_s11(void)
{
	int ret;
	/* TODO: Need to think*/
	s11_mme_sockaddr.sin_port = htons(pfcp_config.s11_port);
	s11_port = htons(pfcp_config.s11_port);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s11_fd = socket(AF_INET, SOCK_DGRAM, 0);
	my_sock.sock_fd_s11 = s11_fd;

	if (s11_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(s11_sockaddr.sin_zero,
			sizeof(s11_sockaddr.sin_zero));
	s11_sockaddr.sin_family = AF_INET;
	s11_sockaddr.sin_port = s11_port;
	s11_sockaddr.sin_addr = pfcp_config.s11_ip;

	ret = bind(s11_fd, (struct sockaddr *) &s11_sockaddr,
			    sizeof(struct sockaddr_in));

	clLog(s11logger, eCLSeverityInfo, "NGIC- main.c::init_s11()"
			"\n\ts11_fd= %d :: "
			"\n\ts11_ip= %s : s11_port= %d\n",
			s11_fd, inet_ntoa(pfcp_config.s11_ip), ntohs(s11_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s11_sockaddr.sin_addr),
			ntohs(s11_sockaddr.sin_port),
			strerror(errno));
	}
}

/**
 * @brief Initalizes s5s8_sgwc interface if in use
 */
static void
init_s5s8(void)
{
	int ret;
	/* TODO: Need to think*/
	s5s8_recv_sockaddr.sin_port = htons(pfcp_config.s5s8_port);
	s5s8_port = htons(pfcp_config.s5s8_port);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s5s8_fd = socket(AF_INET, SOCK_DGRAM, 0);
	my_sock.sock_fd_s5s8 = s5s8_fd;

	if (s5s8_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(s5s8_sockaddr.sin_zero,
			sizeof(s5s8_sockaddr.sin_zero));
	s5s8_sockaddr.sin_family = AF_INET;
	s5s8_sockaddr.sin_port = s5s8_port;
	s5s8_sockaddr.sin_addr = pfcp_config.s5s8_ip;

	ret = bind(s5s8_fd, (struct sockaddr *) &s5s8_sockaddr,
			    sizeof(struct sockaddr_in));

	clLog(s5s8logger, eCLSeverityInfo, "NGIC- main.c::init_s5s8_sgwc()"
			"\n\ts5s8_fd= %d :: "
			"\n\ts5s8_ip= %s : s5s8_port= %d\n",
			s5s8_fd, inet_ntoa(pfcp_config.s5s8_ip),
			ntohs(s5s8_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s5s8_sockaddr.sin_addr),
			ntohs(s5s8_sockaddr.sin_port),
			strerror(errno));
	}
}

void
initialize_tables_on_dp(void)
{
#ifdef CP_DP_TABLE_CONFIG
	struct dp_id dp_id = { .id = DPN_ID };

	sprintf(dp_id.name, SDF_FILTER_TABLE);
	if (sdf_filter_table_create(dp_id, SDF_FILTER_TABLE_SIZE))
		rte_panic("sdf_filter_table creation failed\n");

	sprintf(dp_id.name, ADC_TABLE);
	if (adc_table_create(dp_id, ADC_TABLE_SIZE))
		rte_panic("adc_table creation failed\n");

	sprintf(dp_id.name, PCC_TABLE);
	if (pcc_table_create(dp_id, PCC_TABLE_SIZE))
		rte_panic("pcc_table creation failed\n");

	sprintf(dp_id.name, METER_PROFILE_SDF_TABLE);
	if (meter_profile_table_create(dp_id, METER_PROFILE_SDF_TABLE_SIZE))
		rte_panic("meter_profile_sdf_table creation failed\n");

	sprintf(dp_id.name, SESSION_TABLE);

	if (session_table_create(dp_id, LDB_ENTRIES_DEFAULT))
		rte_panic("session_table creation failed\n");
#endif

}

void
init_dp_rule_tables(void)
{

#ifdef CP_DP_TABLE_CONFIG
	initialize_tables_on_dp();
#endif

	init_packet_filters();
	parse_adc_rules();

}
/**
 * @brief
 * Initializes Control Plane data structures, packet filters, and calls for the
 * Data Plane to create required tables
 */
void
init_cp(void)
{

	init_pfcp();

	switch (spgw_cfg) {
	case SGWC:
		init_s11();
	case PGWC:
		init_s5s8();
		break;
	case SAEGWC:
		init_s11();
		break;
	default:
		rte_panic("main.c::init_cp()-"
				"Unknown spgw_cfg= %u\n", spgw_cfg);
		break;
	}

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");

	create_ue_hash();

	create_upf_context_hash();

	create_gx_context_hash();

	create_upf_by_ue_hash();

#ifdef USE_DNS_QUERY
	set_dns_config();
#endif /* USE_DNS_QUERY */
}
