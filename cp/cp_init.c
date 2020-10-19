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
#include <errno.h>
#include <sys/time.h>

#include "ue.h"
#include "pfcp.h"
#include "gtpv2c.h"
#include "cp_stats.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "restoration_timer.h"
#include "sm_struct.h"
#include "cp_timer.h"
#include "cp_config.h"
#include "redis_client.h"
#include "clogger.h"
#include "pfcp_util.h"
#include "cdnshelper.h"
#include "interface.h"
#include "predef_rule_init.h"

int s11_fd = -1;
int ddf2_fd = -1;
int s5s8_fd = -1;
int pfcp_fd = -1;
int s11_pcap_fd = -1;

pcap_t *pcap_reader;
pcap_dumper_t *pcap_dumper;

struct cp_stats_t cp_stats;
extern pfcp_config_t pfcp_config;
extern udp_sock_t my_sock;
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
uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = {0};

#ifdef USE_REST
/* ECHO PKTS HANDLING */
uint8_t echo_tx_buf[MAX_GTPV2C_UDP_LEN];
#endif /* USE_REST */


uint8_t s5s8_rx_buf[MAX_GTPV2C_UDP_LEN] = {0};
uint8_t s5s8_tx_buf[MAX_GTPV2C_UDP_LEN] = {0};

#ifdef SYNC_STATS
/**
 * @brief  : Initializes the hash table used to account for statstics of req and resp time.
 * @param  : void
 * @return : void
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
					"Unknown gw_cfg= %d.", pfcp_config.cp_type);
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
 * @brief  : Util to send or dump gtpv2c messages
 * @param  : fd, interface indentifier
 * @param  : t_tx, buffer to store data for peer node
 * @param  : context, UE context for lawful interception
 * @return : void
 */
void
timer_retry_send(int fd, peerData *t_tx, ue_context *context)
{
	int bytes_tx;
	struct sockaddr_in tx_sockaddr;

	if(fd == pfcp_fd)
		tx_sockaddr.sin_addr.s_addr = ntohl(t_tx->dstIP);
	else
		tx_sockaddr.sin_addr.s_addr = t_tx->dstIP;

	tx_sockaddr.sin_port = t_tx->dstPort;
	tx_sockaddr.sin_family = AF_INET;
	if (pcap_dumper) {
		dump_pcap(t_tx->buf_len, t_tx->buf);
	} else {

		bytes_tx = gtpv2c_send(fd,t_tx->buf,t_tx->buf_len,(struct sockaddr *)&tx_sockaddr,sizeof(struct sockaddr_in),SENT);

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::gtpv2c_send()""\n\tgtpv2c_if_fd= %d\n", LOG_VALUE, fd);

		if (NULL != context) {
			uint8_t tx_buf[MAX_GTPV2C_UDP_LEN];
			uint16_t payload_length;

			payload_length = t_tx->buf_len;
			memset(tx_buf, 0, MAX_GTPV2C_UDP_LEN);
			memcpy(tx_buf, t_tx->buf, payload_length);

			switch(t_tx->portId) {
				case GX_IFACE:
					break;
				case S11_IFACE:
					/* copy packet for user level packet copying or li */
					if (context->dupl) {
						process_pkt_for_li(
								context, S11_INTFC_OUT, tx_buf, payload_length,
								ntohl(pfcp_config.s11_ip.s_addr), tx_sockaddr.sin_addr.s_addr,
								pfcp_config.s11_port, tx_sockaddr.sin_port);
					}
					break;
				case S5S8_IFACE:
					/* copy packet for user level packet copying or li */
					if (context->dupl) {
						process_pkt_for_li(
								context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
								ntohl(pfcp_config.s5s8_ip.s_addr), tx_sockaddr.sin_addr.s_addr,
								pfcp_config.s5s8_port, tx_sockaddr.sin_port);
					}
					break;
				case PFCP_IFACE:
					/* copy packet for user level packet copying or li */
					if (context->dupl) {
						process_pkt_for_li(
								context, SX_INTFC_OUT, tx_buf, payload_length,
								pfcp_config.pfcp_ip.s_addr, tx_sockaddr.sin_addr.s_addr,
								pfcp_config.pfcp_port, tx_sockaddr.sin_port);
					}
					break;
				default:
					break;
			}
		}

	if (bytes_tx != (int) t_tx->buf_len) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Transmitted Incomplete Timer Retry Message:"
					"%u of %d tx bytes : %s\n", LOG_VALUE,
					t_tx->buf_len, bytes_tx, strerror(errno));
		}
	}
}

/**
 * @brief  : Util to send or dump gtpv2c messages
 * @param  : gtpv2c_if_fd, interface indentifier
 * @param  : gtpv2c_tx_buf, buffer to store data for peer node
 * @param  : gtpv2c_pyld_len, data length
 * @param  : dest_addr, destination address
 * @param  : dest_addr_len, destination address length
 * @return : returns the transmitted bytes
 */
int
gtpv2c_send(int gtpv2c_if_fd, uint8_t *gtpv2c_tx_buf,
		uint16_t gtpv2c_pyld_len, struct sockaddr *dest_addr,
		socklen_t dest_addr_len,Dir dir)
{
	CLIinterface it;
	gtpv2c_header_t *gtpv2c_s11_tx = (gtpv2c_header_t *) gtpv2c_tx_buf;
	int bytes_tx;
	struct sockaddr_in *sin = (struct sockaddr_in *) dest_addr;
	sin->sin_addr.s_addr = htonl(sin->sin_addr.s_addr);


	if (pcap_dumper) {
		dump_pcap(gtpv2c_pyld_len, gtpv2c_tx_buf);
	} else {
		bytes_tx = sendto(gtpv2c_if_fd, gtpv2c_tx_buf, gtpv2c_pyld_len, 0,
			(struct sockaddr *) dest_addr, dest_addr_len);

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::gtpv2c_send()"
			"\n\tgtpv2c_if_fd= %d, payload_length= %d ,Direction= %d, tx bytes= %d\n",
			LOG_VALUE, gtpv2c_if_fd, gtpv2c_pyld_len, dir, bytes_tx);

	if (bytes_tx != (int) gtpv2c_pyld_len) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Transmitted Incomplete GTPv2c Message:"
					"%u of %d tx bytes\n", LOG_VALUE,
					gtpv2c_pyld_len, bytes_tx);
	}
	}

	if(gtpv2c_if_fd == s11_fd) {
		it = S11;
	}
	else if(gtpv2c_if_fd == s5s8_fd) {
		if(cli_node.s5s8_selection == NOT_PRESENT) {
			cli_node.s5s8_selection = OSS_S5S8_SENDER;
		}
		it = S5S8;
	}
	else if (gtpv2c_if_fd == pfcp_fd) {
		it = SX;
	}
	else
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"\nunknown file discriptor, "
			"file discriptor = %d\n", LOG_VALUE, gtpv2c_if_fd);
	update_cli_stats(sin->sin_addr.s_addr, gtpv2c_s11_tx->gtpc.message_type, dir,it);

	sin->sin_addr.s_addr = ntohl(sin->sin_addr.s_addr);

	return bytes_tx;
}

/**
 * @brief  : Set dns configurations parameters
 * @param  : void
 * @return : void
 */
static void
set_dns_config(void)
{
	if (pfcp_config.use_dns){
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
}

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

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_pfcp()" "\n\tpfcp_fd = %d :: "
			"\n\tpfcp_ip = %s : pfcp_port = %d\n", LOG_VALUE,
			pfcp_fd, inet_ntoa(pfcp_config.pfcp_ip),
			ntohs(pfcp_port));
	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
				inet_ntoa(pfcp_sockaddr.sin_addr),
				ntohs(pfcp_sockaddr.sin_port),
				strerror(errno));
	}
	if (pfcp_config.use_dns == 0){
		/* Initialize peer UPF inteface for sendto(.., dest_addr), If DNS is Disable */
		upf_pfcp_port =  htons(pfcp_config.upf_pfcp_port);
		bzero(upf_pfcp_sockaddr.sin_zero,
				sizeof(upf_pfcp_sockaddr.sin_zero));
		upf_pfcp_sockaddr.sin_family = AF_INET;
		upf_pfcp_sockaddr.sin_port = upf_pfcp_port;
		upf_pfcp_sockaddr.sin_addr = pfcp_config.upf_pfcp_ip;
	}
}

/**
 * @brief  : Initalizes S11 interface if in use
 * @param  : void
 * @return : void
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

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_s11()"
			"\n\ts11_fd= %d :: "
			"\n\ts11_ip= %s : s11_port= %d\n", LOG_VALUE,
			s11_fd, inet_ntoa(pfcp_config.s11_ip), ntohs(s11_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s11_sockaddr.sin_addr),
			ntohs(s11_sockaddr.sin_port),
			strerror(errno));
	}
}

/**
 * @brief  : Initalizes s5s8_sgwc interface if in use
 * @param  : void
 * @return : void
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

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_s5s8_sgwc()"
			"\n\ts5s8_fd= %d :: "
			"\n\ts5s8_ip= %s : s5s8_port= %d\n", LOG_VALUE,
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

	snprintf(dp_id.name, MAX_LEN, SDF_FILTER_TABLE);
	if (sdf_filter_table_create(dp_id, SDF_FILTER_TABLE_SIZE))
		rte_panic("sdf_filter_table creation failed\n");

	snprintf(dp_id.name, MAX_LEN, ADC_TABLE);
	if (adc_table_create(dp_id, ADC_TABLE_SIZE))
		rte_panic("adc_table creation failed\n");

	snprintf(dp_id.name, MAX_LEN, PCC_TABLE);
	if (pcc_table_create(dp_id, PCC_TABLE_SIZE))
		rte_panic("pcc_table creation failed\n");

	snprintf(dp_id.name, MAX_LEN, METER_PROFILE_SDF_TABLE);
	if (meter_profile_table_create(dp_id, METER_PROFILE_SDF_TABLE_SIZE))
		rte_panic("meter_profile_sdf_table creation failed\n");

	snprintf(dp_id.name,MAX_LEN, SESSION_TABLE);

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

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined rules from files.\n", LOG_VALUE);
	init_packet_filters();

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined adc rules\n", LOG_VALUE);
	parse_adc_rules();
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Reading predefined adc rules completed\n", LOG_VALUE);

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Read predefined rules and successfully stored in internal tables.\n",
			LOG_VALUE);
}
/**
 * @brief  : Initializes Control Plane data structures, packet filters, and calls for the
 *           Data Plane to create required tables
 */
void
init_cp(void)
{

	init_pfcp();

	switch (pfcp_config.cp_type) {
	case SGWC:
		init_s11();
	case PGWC:
		init_s5s8();
		break;
	case SAEGWC:
		init_s11();
		init_s5s8();
		break;
	default:
		rte_panic("main.c::init_cp()-"
				"Unknown CP_TYPE= %u\n", pfcp_config.cp_type);
		break;
	}

	if (signal(SIGINT, cp_sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");

	create_ue_hash();

	create_upf_context_hash();

	create_gx_context_hash();

	create_upf_by_ue_hash();

	create_li_info_hash();

	if(pfcp_config.use_dns)
		set_dns_config();
}

int
init_redis(void)
{
	redis_config_t cfg = {0};
	char redis_cert_path[PATH_MAX] = {0};
	char redis_key_path[PATH_MAX] = {0};
	char redis_ca_cert_path[PATH_MAX] = {0};
	cfg.type = REDIS_TLS;

	if(pfcp_config.redis_ip.s_addr == 0
			|| pfcp_config.cp_redis_ip.s_addr == 0) {
		clLog(clSystemLog, eCLSeverityCritical,"Redis"
				"ip/cp redis ip missing,"
				"Connection to redis failed\n");
		return -1;
	}

	strncpy(redis_cert_path, pfcp_config.redis_cert_path, PATH_MAX);
	strncat(redis_cert_path,"/redis.crt", PATH_MAX);
	strncpy(redis_key_path, pfcp_config.redis_cert_path, PATH_MAX);
	strncat(redis_key_path,"/redis.key", PATH_MAX);
	strncpy(redis_ca_cert_path, pfcp_config.redis_cert_path, PATH_MAX);
	strncat(redis_ca_cert_path,"/ca.crt", PATH_MAX);

	strncpy(cfg.conf.tls.cert_path, redis_cert_path, PATH_MAX);
	strncpy(cfg.conf.tls.key_path, redis_key_path, PATH_MAX);
	strncpy(cfg.conf.tls.ca_cert_path, redis_ca_cert_path, PATH_MAX);

	/*Store redis ip and cp redis ip*/
	snprintf(cfg.conf.tls.host, IP_BUFF_SIZE, "%s",
			inet_ntoa(*((struct in_addr *)&pfcp_config.redis_ip.s_addr)));
	cfg.conf.tls.port = (int)pfcp_config.redis_port;
	snprintf(cfg.cp_ip, IP_BUFF_SIZE, "%s",
			inet_ntoa(*((struct in_addr *)&pfcp_config.cp_redis_ip.s_addr)));

	struct timeval tm = {REDIS_CONN_TIMEOUT, 0};
	cfg.conf.tls.timeout = tm;

	ctx = redis_connect(&cfg);

	if(ctx == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Connection to redis server failed,"
					"Unable to send CDR to redis server\n", LOG_VALUE);
		return -1;
	} else {
		clLog(clSystemLog, eCLSeverityInfo,LOG_FORMAT"Redis Server"
				"Connected Succesfully\n", LOG_VALUE);
	}

	return 0;

}
