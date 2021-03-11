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
#include "ngic_timer.h"
#include "sm_struct.h"
#include "cp_timer.h"
#include "cp_config.h"
#include "redis_client.h"
#include "pfcp_util.h"
#include "cdnshelper.h"
#include "interface.h"
#include "predef_rule_init.h"

int s11_fd = -1;
int s11_fd_v6 = -1;
void *ddf2_fd = NULL;
int s5s8_fd = -1;
int s5s8_fd_v6 = -1;
int pfcp_fd = -1;
int pfcp_fd_v6 = -1;
int s11_pcap_fd = -1;

pcap_t *pcap_reader;
pcap_dumper_t *pcap_dumper;

struct cp_stats_t cp_stats;
extern pfcp_config_t config;
extern udp_sock_t my_sock;

// struct sockaddr_in s11_sockaddr;
// struct sockaddr_in6 s11_sockaddr_ipv6;
peer_addr_t s11_sockaddr;

// struct sockaddr_in6 s5s8_sockaddr_ipv6;
// struct sockaddr_in s5s8_sockaddr;
peer_addr_t s5s8_sockaddr;

extern int clSystemLog;
/* MME */
peer_addr_t s11_mme_sockaddr;

/* S5S8 */
peer_addr_t s5s8_recv_sockaddr;

/* PFCP */
in_port_t pfcp_port;
peer_addr_t pfcp_sockaddr;

/* UPF PFCP */
in_port_t upf_pfcp_port;
peer_addr_t upf_pfcp_sockaddr;

socklen_t s5s8_sockaddr_len = sizeof(s5s8_sockaddr.ipv4);
socklen_t s5s8_sockaddr_ipv6_len = sizeof(s5s8_sockaddr.ipv6);

socklen_t s11_mme_sockaddr_len = sizeof(s11_mme_sockaddr.ipv4);
socklen_t s11_mme_sockaddr_ipv6_len = sizeof(s11_mme_sockaddr.ipv6);

in_port_t s11_port;
in_port_t s5s8_port;

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
	switch (config.cp_type) {
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
					"Unknown gw_cfg= %d.", config.cp_type);
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
	/* s11 mme ip not exist in cp config */
	//ih->dst_addr = config.s11_mme_ip.s_addr;
	ih->src_addr = config.s11_ip.s_addr;
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
timer_retry_send(int fd_v4, int fd_v6, peerData *t_tx, ue_context *context)
{
	int bytes_tx;
	peer_addr_t tx_sockaddr;

	tx_sockaddr.type = t_tx->dstIP.ip_type;

	if (t_tx->dstIP.ip_type == PDN_TYPE_IPV4) {

		tx_sockaddr.ipv4.sin_family = AF_INET;
		tx_sockaddr.ipv4.sin_port = t_tx->dstPort;
		tx_sockaddr.ipv4.sin_addr.s_addr = t_tx->dstIP.ipv4_addr;
	} else {

		tx_sockaddr.ipv6.sin6_family = AF_INET6;
		tx_sockaddr.ipv6.sin6_port = t_tx->dstPort;
		memcpy(&tx_sockaddr.ipv6.sin6_addr.s6_addr, t_tx->dstIP.ipv6_addr, IPV6_ADDRESS_LEN);
	}

	if (pcap_dumper) {
		dump_pcap(t_tx->buf_len, t_tx->buf);
	} else {

		bytes_tx = gtpv2c_send(fd_v4, fd_v6, t_tx->buf, t_tx->buf_len, tx_sockaddr, SENT);

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::"
			"gtpv2c_send()""\n\tgtpv2c_if_fd_v4= %d::gtpv2c_if_fd_v6= %d\n",
			LOG_VALUE, fd_v4, fd_v6);

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
								fill_ip_info(tx_sockaddr.type,
										config.s11_ip.s_addr,
										config.s11_ip_v6.s6_addr),
								fill_ip_info(tx_sockaddr.type,
										tx_sockaddr.ipv4.sin_addr.s_addr,
										tx_sockaddr.ipv6.sin6_addr.s6_addr),
								config.s11_port,
								((tx_sockaddr.type == IPTYPE_IPV4_LI) ?
									tx_sockaddr.ipv4.sin_port : tx_sockaddr.ipv6.sin6_port));
					}
					break;
				case S5S8_IFACE:
					/* copy packet for user level packet copying or li */
					if (context->dupl) {
						process_pkt_for_li(
								context, S5S8_C_INTFC_OUT, tx_buf, payload_length,
								fill_ip_info(tx_sockaddr.type,
										config.s5s8_ip.s_addr,
										config.s5s8_ip_v6.s6_addr),
								fill_ip_info(tx_sockaddr.type,
										tx_sockaddr.ipv4.sin_addr.s_addr,
										tx_sockaddr.ipv6.sin6_addr.s6_addr),
								config.s5s8_port,
								((tx_sockaddr.type == IPTYPE_IPV4_LI) ?
									tx_sockaddr.ipv4.sin_port : tx_sockaddr.ipv6.sin6_port));
					}
					break;
				case PFCP_IFACE:
					/* copy packet for user level packet copying or li */
					if (context->dupl) {
						process_pkt_for_li(
								context, SX_INTFC_OUT, tx_buf, payload_length,
								fill_ip_info(tx_sockaddr.type,
										config.pfcp_ip.s_addr,
										config.pfcp_ip_v6.s6_addr),
								fill_ip_info(tx_sockaddr.type,
										tx_sockaddr.ipv4.sin_addr.s_addr,
										tx_sockaddr.ipv6.sin6_addr.s6_addr),
								config.pfcp_port,
								((tx_sockaddr.type == IPTYPE_IPV4_LI) ?
									tx_sockaddr.ipv4.sin_port : tx_sockaddr.ipv6.sin6_port));
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

int create_udp_socket_v4(uint32_t ipv4_addr, uint16_t port,
					peer_addr_t *addr) {

	int mode = 1;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	socklen_t v4_addr_len = sizeof(addr->ipv4);

	if (fd < 0) {
		rte_panic("Socket call error : %s", strerror(errno));
		return -1;
	}

	/*Below Option allows to bind to same port for multiple IPv6 addresses*/
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &mode, sizeof(mode));

	bzero(addr->ipv4.sin_zero, sizeof(addr->ipv4.sin_zero));

	addr->ipv4.sin_family = AF_INET;
	addr->ipv4.sin_port = port;
	addr->ipv4.sin_addr.s_addr = ipv4_addr;

	int ret = bind(fd, (struct sockaddr *) &addr->ipv4, v4_addr_len);
	if (ret < 0) {
		rte_panic("Bind error for V4 UDP Socket %s:%u - %s\n",
			inet_ntoa(addr->ipv4.sin_addr),
			ntohs(addr->ipv4.sin_port),
			strerror(errno));
		return -1;
	}

	addr->type = PDN_TYPE_IPV4;
	return fd;

}

int create_udp_socket_v6(uint8_t ipv6_addr[], uint16_t port,
					peer_addr_t *addr) {

	int mode = 1, ret = 0;
	socklen_t v6_addr_len = sizeof(addr->ipv6);

	int fd = socket(AF_INET6, SOCK_DGRAM, 0);

	if (fd < 0) {
		rte_panic("Socket call error : %s", strerror(errno));
		return -1;
	}

	/*Below Option allows to bind to same port for multiple IPv6 addresses*/
	setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &mode, sizeof(mode));

	/*Below Option allows to bind to same port for IPv4 and IPv6 addresses*/
	setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&mode, sizeof(mode));

	addr->ipv6.sin6_family = AF_INET6;
	memcpy(addr->ipv6.sin6_addr.s6_addr, ipv6_addr, IPV6_ADDRESS_LEN);
	addr->ipv6.sin6_port = port;

	ret = bind(fd, (struct sockaddr *) &addr->ipv6, v6_addr_len);
	if (ret < 0) {
		rte_panic("Bind error for V6 UDP Socket "IPv6_FMT":%u - %s\n",
			IPv6_PRINT(addr->ipv6.sin6_addr),
			ntohs(addr->ipv4.sin_port),
			strerror(errno));
		return -1;
	}

	addr->type = PDN_TYPE_IPV6;
	return fd;

}


int
gtpv2c_send(int gtpv2c_if_fd_v4, int gtpv2c_if_fd_v6, uint8_t *gtpv2c_tx_buf,
			uint16_t gtpv2c_pyld_len, peer_addr_t dest_addr,Dir dir)
{
	CLIinterface it;
	gtpv2c_header_t *gtpv2c_tx = (gtpv2c_header_t *) gtpv2c_tx_buf;
	gtpv2c_header_t *piggy_backed;
	int bytes_tx = 0;
	if (pcap_dumper) {
		dump_pcap(gtpv2c_pyld_len, gtpv2c_tx_buf);
	} else {

		if(dest_addr.type == PDN_TYPE_IPV4) {

			if(gtpv2c_if_fd_v4 <= 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"GTPV2C send not possible due to incompatiable "
				"IP Type at Source and Destination \n", LOG_VALUE);
				return 0;
			}

			bytes_tx = sendto(gtpv2c_if_fd_v4, gtpv2c_tx_buf, gtpv2c_pyld_len, MSG_DONTWAIT,
			(struct sockaddr *) &dest_addr.ipv4, sizeof(dest_addr.ipv4));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::gtpv2c_send()"
				"on IPv4 socket "
				"\n\tgtpv2c_if_fd_v4 = %d, payload_length= %d ,Direction= %d,"
				"tx bytes= %d\n", LOG_VALUE, gtpv2c_if_fd_v4, gtpv2c_pyld_len,
				dir, bytes_tx);

		} else if(dest_addr.type == PDN_TYPE_IPV6) {

			if(gtpv2c_if_fd_v6 <= 0) {

				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"GTPV2C send not possible due to incompatiable "
					"IP Type at Source and Destination \n", LOG_VALUE);
				return 0;
			}

			bytes_tx = sendto(gtpv2c_if_fd_v6, gtpv2c_tx_buf, gtpv2c_pyld_len, MSG_DONTWAIT,
			(struct sockaddr *) &dest_addr.ipv6, sizeof(dest_addr.ipv6));

			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"NGIC- main.c::gtpv2c_send()"
				"on IPv6 socket "
				"\n\tgtpv2c_if_fd_v6 = %d, payload_length= %d ,Direction= %d,"
				"tx bytes= %d\n", LOG_VALUE, gtpv2c_if_fd_v6, gtpv2c_pyld_len,
				dir, bytes_tx);

		} else {

			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Niether IPV4 nor IPV6 type is set "
			"of %d TYPE \n", LOG_VALUE, dest_addr.type);
		}

	}
	if (bytes_tx != (int) gtpv2c_pyld_len) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Transmitted Incomplete GTPv2c Message:"
		"%u of %d tx bytes\n", LOG_VALUE,
		gtpv2c_pyld_len, bytes_tx);
	}

	if(((gtpv2c_if_fd_v4 == s11_fd) && (gtpv2c_if_fd_v4 != -1)) ||
		((gtpv2c_if_fd_v6 == s11_fd_v6) &&  (gtpv2c_if_fd_v6 != -1))) {
		it = S11;
	} else if(((gtpv2c_if_fd_v4 == s5s8_fd) && (gtpv2c_if_fd_v4 != -1)) ||
		((gtpv2c_if_fd_v6 == s5s8_fd_v6) &&  (gtpv2c_if_fd_v6 != -1))) {
		if(cli_node.s5s8_selection == NOT_PRESENT) {
			cli_node.s5s8_selection = OSS_S5S8_SENDER;
		}
		it = S5S8;
	} else if (((gtpv2c_if_fd_v4 == pfcp_fd) && (gtpv2c_if_fd_v4 != -1))
			|| ((gtpv2c_if_fd_v6 == pfcp_fd_v6) &&  (gtpv2c_if_fd_v6  != -1))) {
		it = SX;
	} else {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"\nunknown file discriptor, "
				"IPV4 file discriptor = %d::IPV6 file discriptor = %d\n",
				LOG_VALUE, gtpv2c_if_fd_v4, gtpv2c_if_fd_v6);
	}

	update_cli_stats((peer_address_t *) &dest_addr,
		gtpv2c_tx->gtpc.message_type, dir, it);

	if(gtpv2c_tx->gtpc.piggyback) {
		piggy_backed = (gtpv2c_header_t*) ((uint8_t *)gtpv2c_tx +
				sizeof(gtpv2c_tx->gtpc) + ntohs(gtpv2c_tx->gtpc.message_len));
		update_cli_stats((peer_address_t *) &dest_addr,
				piggy_backed->gtpc.message_type, dir, it);
	}


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
	if (config.use_dns){
		set_dnscache_refresh_params(config.dns_cache.concurrent,
				config.dns_cache.percent, config.dns_cache.sec);

		set_dns_retry_params(config.dns_cache.timeoutms,
				config.dns_cache.tries);

		/* set OPS dns config */
		for (uint32_t i = 0; i < config.ops_dns.nameserver_cnt; i++)
		{
			set_nameserver_config(config.ops_dns.nameserver_ip[i],
					DNS_PORT, DNS_PORT, NS_OPS);
		}

		set_dns_local_ip(NS_OPS, config.cp_dns_ip_buff);
		apply_nameserver_config(NS_OPS);
		init_save_dns_queries(NS_OPS, config.ops_dns.filename,
				config.ops_dns.freq_sec);
		load_dns_queries(NS_OPS, config.ops_dns.filename);

		/* set APP dns config */
		for (uint32_t i = 0; i < config.app_dns.nameserver_cnt; i++)
			set_nameserver_config(config.app_dns.nameserver_ip[i],
					DNS_PORT, DNS_PORT, NS_APP);
		set_dns_local_ip(NS_APP, config.cp_dns_ip_buff);
		apply_nameserver_config(NS_APP);
		init_save_dns_queries(NS_APP, config.app_dns.filename,
				config.app_dns.freq_sec);
		load_dns_queries(NS_APP, config.app_dns.filename);
	}
}

void
init_pfcp(void)
{
	int fd = 0;
	upf_pfcp_sockaddr.ipv4.sin_port = htons(config.upf_pfcp_port);
	upf_pfcp_sockaddr.ipv6.sin6_port = htons(config.upf_pfcp_port);
	pfcp_port = htons(config.pfcp_port);

	if (config.pfcp_ip_type == PDN_TYPE_IPV6 || config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v6(config.pfcp_ip_v6.s6_addr,
							pfcp_port, &pfcp_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd_v6 = fd;
			pfcp_fd_v6 = fd;
		}
	}

	if (config.pfcp_ip_type == PDN_TYPE_IPV4 || config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v4(config.pfcp_ip.s_addr,
							pfcp_port, &pfcp_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd = fd;
			pfcp_fd = fd;
		}
	}

	if (config.use_dns == 0) {
		/* Initialize peer UPF inteface for sendto(.., dest_addr), If DNS is Disable */
		upf_pfcp_port =  htons(config.upf_pfcp_port);
		bzero(upf_pfcp_sockaddr.ipv4.sin_zero,
				sizeof(upf_pfcp_sockaddr.ipv4.sin_zero));

		if ((config.pfcp_ip_type == PDN_TYPE_IPV6
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV6
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {

			upf_pfcp_sockaddr.ipv6.sin6_family = AF_INET6;
			upf_pfcp_sockaddr.ipv6.sin6_port = upf_pfcp_port;
			memcpy(upf_pfcp_sockaddr.ipv6.sin6_addr.s6_addr, config.upf_pfcp_ip_v6.s6_addr,
				IPV6_ADDRESS_LEN);

			upf_pfcp_sockaddr.type = PDN_TYPE_IPV6;

		} else if ((config.pfcp_ip_type == PDN_TYPE_IPV4
					|| config.pfcp_ip_type == PDN_TYPE_IPV4_IPV6)
				&& (config.upf_pfcp_ip_type == PDN_TYPE_IPV4
					|| config.upf_pfcp_ip_type == PDN_TYPE_IPV4_IPV6)) {
			upf_pfcp_sockaddr.ipv4.sin_family = AF_INET;
			upf_pfcp_sockaddr.ipv4.sin_port = upf_pfcp_port;
			upf_pfcp_sockaddr.ipv4.sin_addr.s_addr = config.upf_pfcp_ip.s_addr;

			upf_pfcp_sockaddr.type = PDN_TYPE_IPV4;
		}

	}

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_pfcp()"
		"\n\tpfcp_fd_v4 = %d :: \n\tpfcp_fd_v6 = %d :: "
		"\n\tpfcp_ip_v4 = %s :: \n\tpfcp_ip_v6 = "IPv6_FMT" ::"
		"\n\tpfcp_port = %d\n", LOG_VALUE,
		pfcp_fd, pfcp_fd_v6, inet_ntoa(config.pfcp_ip),
		IPv6_PRINT(config.pfcp_ip_v6), ntohs(pfcp_port));

}

/**
 * @brief  : Initalizes S11 interface if in use
 * @param  : void
 * @return : void
 */
static void
init_s11(void)
{
	int fd = 0;
	/* TODO: Need to think*/
	s11_mme_sockaddr.ipv4.sin_port = htons(config.s11_port);
	s11_mme_sockaddr.ipv6.sin6_port = htons(config.s11_port);
	s11_port = htons(config.s11_port);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	if (config.s11_ip_type == PDN_TYPE_IPV6 || config.s11_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v6(config.s11_ip_v6.s6_addr,
							s11_port, &s11_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd_s11_v6 = fd;
			s11_fd_v6 = fd;
		}
	}

	if (config.s11_ip_type == PDN_TYPE_IPV4 || config.s11_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v4(config.s11_ip.s_addr, s11_port,
									&s11_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd_s11 = fd;
			s11_fd = fd;
		}
	}

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_s11()"
			"\n\ts11_fd_v4 = %d :: \n\ts11_fd_v6= %d :: "
			"\n\ts11_ip_v4 = %s :: \n\ts11_ip_v6 = "IPv6_FMT" ::"
			"\n\ts11_port = %d\n", LOG_VALUE,
			s11_fd, s11_fd_v6, inet_ntoa(config.s11_ip),
			IPv6_PRINT(config.s11_ip_v6), ntohs(s11_port));
}

/**
 * @brief  : Initalizes s5s8_sgwc interface if in use
 * @param  : void
 * @return : void
 */
static void
init_s5s8(void)
{
	int fd = 0;
	/* TODO: Need to think*/
	s5s8_recv_sockaddr.ipv4.sin_port = htons(config.s5s8_port);
	s5s8_recv_sockaddr.ipv6.sin6_port = htons(config.s5s8_port);
	s5s8_port = htons(config.s5s8_port);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	if (config.s5s8_ip_type == PDN_TYPE_IPV6 || config.s5s8_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v6(config.s5s8_ip_v6.s6_addr,
							s5s8_port, &s5s8_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd_s5s8_v6 = fd;
			s5s8_fd_v6 = fd;
		}
	}

	if (config.s5s8_ip_type == PDN_TYPE_IPV4 || config.s5s8_ip_type == PDN_TYPE_IPV4_IPV6) {

		fd = create_udp_socket_v4(config.s5s8_ip.s_addr,
								s5s8_port, &s5s8_sockaddr);

		if (fd > 0) {
			my_sock.sock_fd_s5s8 = fd;
			s5s8_fd = fd;
		}
	}

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"NGIC- main.c::init_s5s8_sgwc()"
			"\n\ts5s8_fd_v4 = %d :: \n\ts5s8_fd_v6 = %d :: "
			"\n\ts5s8_ip_v4 = %s :: \n\ts5s8_ip_v6 = "IPv6_FMT" ::"
			"\n\ts5s8_port = %d\n", LOG_VALUE,
			s5s8_fd, s5s8_fd_v6, inet_ntoa(config.s5s8_ip),
			IPv6_PRINT(config.s5s8_ip_v6), ntohs(s5s8_port));
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

	switch (config.cp_type) {
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
				"Unknown CP_TYPE= %u\n", config.cp_type);
		break;
	}

	create_ue_hash();

	create_upf_context_hash();

	create_gx_context_hash();

	create_upf_by_ue_hash();

	create_li_info_hash();

	if(config.use_dns)
		set_dns_config();
}

int
init_redis(void)
{
	redis_config_t cfg = {0};

	cfg.type = REDIS_TLS;

	if (config.redis_server_ip_type !=
			config.cp_redis_ip_type) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Invalid Redis configuration "
					"Use only ipv4 or only ipv6 for "
					"connection\n", LOG_VALUE);
		return -1;

	}

	strncpy(cfg.conf.tls.cert_path, config.redis_cert_path, PATH_MAX);
	strncat(cfg.conf.tls.cert_path,"/redis.crt", PATH_MAX);
	strncpy(cfg.conf.tls.key_path, config.redis_cert_path, PATH_MAX);
	strncat(cfg.conf.tls.key_path,"/redis.key", PATH_MAX);
	strncpy(cfg.conf.tls.ca_cert_path, config.redis_cert_path, PATH_MAX);
	strncat(cfg.conf.tls.ca_cert_path,"/ca.crt", PATH_MAX);

	/*Store redis ip and cp redis ip*/
	cfg.conf.tls.port = (int)config.redis_port;
	snprintf(cfg.conf.tls.host, IP_BUFF_SIZE, "%s",
			config.redis_ip_buff);
	snprintf(cfg.cp_ip, IP_BUFF_SIZE, "%s",
			config.cp_redis_ip_buff);

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
