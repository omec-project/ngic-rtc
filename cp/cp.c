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
#include <stdio.h>
#include <getopt.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_cfgfile.h>

#include "cp.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "debug_str.h"
#include "dp_ipc_api.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_association.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_messages_encoder.h"

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#ifdef USE_DNS_QUERY
#include "cdnshelper.h"
#endif /* USE_DNS_QUERY */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

extern int s11_fd;
extern int s5s8_fd;
extern pfcp_config_t pfcp_config;

uint32_t start_time;

enum cp_config spgw_cfg;

/* Global static , so that this cnt can be incremented for buffered msg in SGWC/PGWC*/
static uint8_t s5s8_sgwc_msgcnt = 0;
static uint8_t s5s8_pgwc_msgcnt = 0;

/* S5S8 */
struct sockaddr_in s5s8_recv_sockaddr;

struct cp_params cp_params;
extern struct cp_stats_t cp_stats;

extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_sockaddr_len;

void
control_plane(void)
{
	bzero(&s11_rx_buf, sizeof(s11_rx_buf));
	bzero(&s11_tx_buf, sizeof(s11_tx_buf));
	bzero(&s5s8_rx_buf, sizeof(s5s8_rx_buf));
	bzero(&s5s8_tx_buf, sizeof(s5s8_tx_buf));
	gtpv2c_header *gtpv2c_s11_rx = (gtpv2c_header *) s11_rx_buf;
	gtpv2c_header *gtpv2c_s11_tx = (gtpv2c_header *) s11_tx_buf;
	gtpv2c_header *gtpv2c_s5s8_rx = (gtpv2c_header *) s5s8_rx_buf;
	gtpv2c_header *gtpv2c_s5s8_tx = (gtpv2c_header *) s5s8_tx_buf;

	uint16_t payload_length;

	uint8_t delay = 0; /*TODO move this when more implemented?*/
	int bytes_pcap_rx = 0;
	int bytes_s11_rx = 0;
	int bytes_s5s8_rx = 0;
	static uint8_t s11_msgcnt = 0;
	/*static uint8_t s5s8_sgwc_msgcnt = 0;
	static uint8_t s5s8_pgwc_msgcnt = 0;*/
	int ret = 0;

	if (pcap_reader) {
		static struct pcap_pkthdr *pcap_rx_header;
		const u_char *t;
		const u_char **tmp = &t;
		ret = pcap_next_ex(pcap_reader, &pcap_rx_header, tmp);
		if (ret < 0) {
			printf("Finished reading from pcap file"
					" - exiting\n");
			exit(0);
		}
		bytes_pcap_rx = pcap_rx_header->caplen
				- (sizeof(struct ether_hdr)
				+ sizeof(struct ipv4_hdr)
				+ sizeof(struct udp_hdr));
		memcpy(gtpv2c_s11_rx, *tmp
				+ (sizeof(struct ether_hdr)
				+ sizeof(struct ipv4_hdr)
				+ sizeof(struct udp_hdr)), bytes_pcap_rx);
	}

	if (spgw_cfg == SGWC) {
		bytes_s5s8_rx = recvfrom(s5s8_fd, s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				&s5s8_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "SGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_recv_sockaddr.sin_addr),
					s5s8_recv_sockaddr.sin_port,
					strerror(errno));
		}
	}

	if (spgw_cfg == PGWC) {
		bytes_s5s8_rx = recvfrom(s5s8_fd, s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_recv_sockaddr,
				&s5s8_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "PGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_recv_sockaddr.sin_addr),
					s5s8_recv_sockaddr.sin_port,
					strerror(errno));
		}

	}

	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
		bytes_s11_rx = recvfrom(s11_fd,
				s11_rx_buf, MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s11_mme_sockaddr,
				&s11_mme_sockaddr_len);
		if (bytes_s11_rx == 0) {
			fprintf(stderr, "SGWC|SAEGWC_s11 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s11_mme_sockaddr.sin_addr),
					s11_mme_sockaddr.sin_port,
					strerror(errno));
			return;
		}
	}

	if (
		(bytes_s5s8_rx < 0) && (bytes_s11_rx < 0) &&
		(errno == EAGAIN  || errno == EWOULDBLOCK)
		)
		return;

	if ((spgw_cfg == SGWC) || (spgw_cfg == PGWC)) {
		if ((bytes_s5s8_rx > 0) &&
			 (unsigned)bytes_s5s8_rx != (
			 ntohs(gtpv2c_s5s8_rx->gtpc.length)
			 + sizeof(gtpv2c_s5s8_rx->gtpc))
			) {
			ret = GTPV2C_CAUSE_INVALID_LENGTH;
			/* According to 29.274 7.7.7, if message is request,
			 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
			 *  should be sent - ignoring packet for now
			 */
			fprintf(stderr, "SGWC|PGWC_s5s8 Received UDP Payload:"
					"\n\t(%d bytes) with gtpv2c + "
					"header (%u + %lu) = %lu bytes\n",
					bytes_s5s8_rx, ntohs(gtpv2c_s5s8_rx->gtpc.length),
					sizeof(gtpv2c_s5s8_rx->gtpc),
					ntohs(gtpv2c_s5s8_rx->gtpc.length)
					+ sizeof(gtpv2c_s5s8_rx->gtpc));
		}
	}
	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC )) {
		if (
			 (bytes_s11_rx > 0) &&
			 (unsigned)bytes_s11_rx !=
			 (ntohs(gtpv2c_s11_rx->gtpc.length)
			 + sizeof(gtpv2c_s11_rx->gtpc))
			) {
			ret = GTPV2C_CAUSE_INVALID_LENGTH;
			/* According to 29.274 7.7.7, if message is request,
			 * reply with cause = GTPV2C_CAUSE_INVALID_LENGTH
			 *  should be sent - ignoring packet for now
			 */
			fprintf(stderr, "SGWC|SAEGWC_s11 Received UDP Payload:"
					"\n\t(%d bytes) with gtpv2c + "
					"header (%u + %lu) = %lu bytes\n",
					bytes_s11_rx, ntohs(gtpv2c_s11_rx->gtpc.length),
					sizeof(gtpv2c_s11_rx->gtpc),
					ntohs(gtpv2c_s11_rx->gtpc.length)
					+ sizeof(gtpv2c_s11_rx->gtpc));
			return;
		}
	}

	if ((bytes_s5s8_rx > 0) || (bytes_s11_rx > 0))
		++cp_stats.rx;

	if (!pcap_reader) {
		if ( ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) &&
			 (bytes_s11_rx > 0) &&
			 (
			  (s11_mme_sockaddr.sin_addr.s_addr != pfcp_config.s11_mme_ip.s_addr) ||
			  (gtpv2c_s11_rx->gtpc.version != GTP_VERSION_GTPV2C)
			 )
			) {
			fprintf(stderr, "Discarding packet from %s:%u - "
					"Expected S11_MME_IP = %s\n",
					inet_ntoa(s11_mme_sockaddr.sin_addr),
					ntohs(s11_mme_sockaddr.sin_port),
					inet_ntoa(pfcp_config.s11_mme_ip)
					);
			return;
		} else if (((spgw_cfg == PGWC) && (bytes_s5s8_rx > 0)) &&
			  (gtpv2c_s5s8_rx->gtpc.version != GTP_VERSION_GTPV2C)
			) {
			fprintf(stderr, "PFCP Discarding packet from %s:%u - "
					"Expected S5S8_IP = %s\n",
					inet_ntoa(s5s8_recv_sockaddr.sin_addr),
					ntohs(s5s8_recv_sockaddr.sin_port),
					inet_ntoa(pfcp_config.s5s8_ip));
			return;
			}

	}

	if (bytes_s5s8_rx > 0) {
		if (spgw_cfg == SGWC) {
			switch (gtpv2c_s5s8_rx->gtpc.type) {
			case GTP_CREATE_SESSION_RSP:
				/* Check s5s8 GTP_CREATE_SESSION_RSP */
				ret = process_sgwc_s5s8_create_session_response(
						gtpv2c_s5s8_rx, gtpv2c_s11_tx);
				if (ret) {
					cp_stats.create_session_resp_rej_rcvd++;
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC:"
							"\n\tprocess_sgwc_s5s8_create_session_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.pgwc_status = 1;
				cp_stats.nbr_of_pgwc_to_sgwc_timeouts = 0;
				cp_stats.create_session_resp_acc_rcvd++;

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);

				RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
						"\n\tcase GTP_CREATE_SESSION_RSP"
						"\n\ts11_msgcnt= %u;"
						"\n\tgtpv2c_send :: s11_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s11_msgcnt, s11_fd,
						inet_ntoa(s11_mme_sockaddr.sin_addr),
						s11_mme_sockaddr_len,
						ntohs(s11_mme_sockaddr.sin_port));
				/* Note: s11_tx_buf should be prepared by call to:
				 * process_sgwc_s5s8_create_session_response
				 */
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);

				s11_msgcnt++;
				break;
			case GTP_DELETE_SESSION_RSP:
				/* Check s5s8 GTP_DELETE_SESSION_RSP */
				ret = process_sgwc_s5s8_delete_session_response(
						gtpv2c_s5s8_rx, gtpv2c_s11_tx);
				if (ret) {
					cp_stats.sm_delete_session_resp_rej_rcvd++;
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC:"
							"\n\tprocess_sgwc_s5s8_delete_session_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.session_deletion_req_sent++;
				cp_stats.sm_delete_session_resp_acc_rcvd++;
				cp_stats.session_deletion_resp_acc_rcvd++;

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);

				RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
						"\n\tcase GTP_DELETE_SESSION_RSP"
						"\n\ts11_msgcnt= %u;"
						"\n\tgtpv2c_send :: s11_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s11_msgcnt, s11_fd,
						inet_ntoa(s11_mme_sockaddr.sin_addr),
						s11_mme_sockaddr_len,
						ntohs(s11_mme_sockaddr.sin_port));
				/* Note: s11_tx_buf should be prepared by call to:
				 * process_sgwc_s5s8_delete_session_response
				 */
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);

				s11_msgcnt++;
				break;
#ifdef USE_REST
			case GTP_ECHO_REQ:
				ret = process_echo_request(gtpv2c_s5s8_rx, gtpv2c_s5s8_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC :"
							"\n\tprocess_echo_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.pgwc_status = 1;
				cp_stats.nbr_of_pgwc_to_sgwc_echo_req_rcvd++;

				/* Reset ECHO Timers */
				ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
				if (ret) {
					/*TODO: Error handling not implemented */
				}

				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);

				gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
				  (struct sockaddr *) &s5s8_recv_sockaddr,
				  s5s8_sockaddr_len);

				cp_stats.nbr_of_sgwc_to_pgwc_echo_resp_sent++;

				break;

			case GTP_ECHO_RSP:
				ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC:"
							"\n\tprocess_echo_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.pgwc_status = 1;
				cp_stats.nbr_of_pgwc_to_sgwc_echo_resp_rcvd++;

				break;
#endif /* USE_REST */

			default:
				fprintf(stderr, "main.c::control_plane::process_msgs-"
						"\n\tcase: SGWC::spgw_cfg= %d;"
						"\n\tReceived unprocessed s5s8 GTPv2c Message Type: "
						"%s (%u 0x%x)... Discarding\n",
						spgw_cfg, gtp_type_str(gtpv2c_s5s8_rx->gtpc.type),
						gtpv2c_s5s8_rx->gtpc.type,
						gtpv2c_s5s8_rx->gtpc.type);
				return;
				break;
			}
		}

		if (spgw_cfg == PGWC) {
			switch (gtpv2c_s5s8_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ: {
				create_session_request_t csr = {0};
				char sgwu_fqdn[MAX_HOSTNAME_LENGTH] = {0};
				struct in_addr upf_ipv4 = {0};
#ifdef USE_REST
				/* Add a entry for SGW-C */
				if (s5s8_recv_sockaddr.sin_addr.s_addr != 0) {
					if ((add_node_conn_entry((uint32_t)s5s8_recv_sockaddr.sin_addr.s_addr,
									S5S8_PGWC_PORT_ID)) != 0) {
						RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGW-C\n");
					}
				}
#endif /* USE_REST */

				if (decode_check_csr(gtpv2c_s5s8_rx, &csr) != 0)
					return;

#ifdef USE_DNS_QUERY
				if (get_upf_list(&csr) == 0)
					return;
#else
				upf_ipv4 = pfcp_config.upf_pfcp_ip;
#endif /* USE_DNS_QUERY */

				cp_stats.sgwc_status = 1;

				if (ASSOC_ESTABLISHED ==
						process_pfcp_assoication_request(&csr,
								sgwu_fqdn, &upf_ipv4)) {
					ret = process_pgwc_s5s8_create_session_request(gtpv2c_s5s8_rx,
							gtpv2c_s5s8_tx, &upf_ipv4);
				} else {
					return;
				}

				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase PGWC:"
							"\n\tprocess_pgwc_s5s8_create_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);
				RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
						"\n\tcase GTP_CREATE_SESSION_REQ"
						"\n\ts5s8_pgwc_msgcnt= %u;"
						"\n\tgtpv2c_send :: s5s8_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s5s8_pgwc_msgcnt, s5s8_fd,
						inet_ntoa(s5s8_recv_sockaddr.sin_addr),
						s5s8_sockaddr_len,
						ntohs(s5s8_recv_sockaddr.sin_port));

				gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len);

				s5s8_pgwc_msgcnt++;
				break;
			}
			case GTP_DELETE_SESSION_REQ:
				ret = process_pgwc_s5s8_delete_session_request(
					gtpv2c_s5s8_rx, gtpv2c_s5s8_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase PGWC:"
							"\n\tprocess_pgwc_s5s8_delete_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);
				RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
						"\n\tcase GTP_DELETE_SESSION_REQ"
						"\n\ts5s8_pgwc_msgcnt= %u;"
						"\n\tgtpv2c_send :: s5s8_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s5s8_pgwc_msgcnt, s5s8_fd,
						inet_ntoa(s5s8_recv_sockaddr.sin_addr),
						s5s8_sockaddr_len,
						ntohs(s5s8_recv_sockaddr.sin_port));

				gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len);

				s5s8_pgwc_msgcnt++;
				break;
#ifdef USE_REST
			case GTP_ECHO_REQ:
				ret = process_echo_request(gtpv2c_s5s8_rx, gtpv2c_s5s8_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase PGWC:"
							"\n\tprocess_echo_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.nbr_of_sgwc_to_pgwc_echo_req_rcvd++;

				/* Reset ECHO Timers */
				ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
				if (ret) {
					/* TODO: Error handling not implemented */
				}

				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);

				gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_recv_sockaddr,
						s5s8_sockaddr_len);

				cp_stats.nbr_of_pgwc_to_sgwc_echo_resp_sent++;

				break;

			case GTP_ECHO_RSP:
				RTE_LOG_DP(DEBUG, CP, "VS: Echo Response Received From SGWC\n");
				ret = process_response(s5s8_recv_sockaddr.sin_addr.s_addr);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC | SAEGWC:"
							"\n\tprocess_echo_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.nbr_of_sgwc_to_pgwc_echo_resp_rcvd++;

				break;
#endif /* USE_REST */

			default:
				fprintf(stderr, "main.c::control_plane::process_msgs-"
						"\n\tcase: PGWC::spgw_cfg= %d;"
						"\n\tReceived unprocessed s5s8 GTPv2c Message Type: "
						"%s (%u 0x%x)... Discarding\n",
						spgw_cfg, gtp_type_str(gtpv2c_s5s8_rx->gtpc.type),
						gtpv2c_s5s8_rx->gtpc.type,
						gtpv2c_s5s8_rx->gtpc.type);
				return;
				break;
			}
		}
	}

	if (bytes_s11_rx > 0) {
		if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
			switch (gtpv2c_s11_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ: {
				create_session_request_t csr = {0};
				char sgwu_fqdn[MAX_HOSTNAME_LENGTH] = {0};
				struct in_addr upf_ipv4 = {0};
#ifdef USE_REST
				/* Add a entry for MME */
				if (s11_mme_sockaddr.sin_addr.s_addr != 0) {
					if ((add_node_conn_entry((uint32_t)s11_mme_sockaddr.sin_addr.s_addr,
											S11_SGW_PORT_ID)) != 0) {
						RTE_LOG_DP(ERR, DP, "Failed to add connection entry for MME\n");
					}
				}
#endif /* USE_REST */

				if (decode_check_csr(gtpv2c_s11_rx, &csr) != 0)
					return;

#ifdef USE_DNS_QUERY
				if (get_upf_list(&csr) == 0)
					return;
#else
				upf_ipv4 = pfcp_config.upf_pfcp_ip;
#endif /* USE_DNS_QUERY */

				cp_stats.mme_status = 1;

				if (ASSOC_ESTABLISHED ==
						process_pfcp_assoication_request(&csr, sgwu_fqdn,
								&upf_ipv4)) {
					ret = process_pfcp_sess_est_request(gtpv2c_s11_rx,
							&csr, gtpv2c_s11_tx,gtpv2c_s5s8_tx, sgwu_fqdn,
							&upf_ipv4);
				} else {
					return;
				}

				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC | SAEGWC:"
							"\n\tprocess_create_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.number_of_ues++;

				if (spgw_cfg == SGWC) {
					/* Forward s11 create_session_request on s5s8 */
					payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
							+ sizeof(gtpv2c_s5s8_tx->gtpc);

					RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
							"\n\tcase GTP_CREATE_SESSION_REQ"
							"\n\ts5s8_sgwc_msgcnt= %u;"
							"\n\tgtpv2c_send :: s5s8_fd= %d;"
							"\n\tdest_addr= %s : dest_addrln= %u;"
							"\n\tdest_port= %u\n",
							s5s8_sgwc_msgcnt, s5s8_fd,
							inet_ntoa(s5s8_recv_sockaddr.sin_addr),
							s5s8_sockaddr_len,
							ntohs(s5s8_recv_sockaddr.sin_port));

					gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
							(struct sockaddr *) &s5s8_recv_sockaddr,
							s5s8_sockaddr_len);
							cp_stats.sm_create_session_req_sent++;

					s5s8_sgwc_msgcnt++;
				}

				if (spgw_cfg == SAEGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);

					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
				}

				break;
			}

			case GTP_DELETE_SESSION_REQ:
				ret = process_pfcp_sess_del_request(gtpv2c_s11_rx,
							gtpv2c_s11_tx, gtpv2c_s5s8_tx);

				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_delete_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.number_of_ues--;

				if (spgw_cfg == SGWC)  {
					/* Forward s11 delete_session_request on s5s8 */
					payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);

					RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
							"\n\tcase GTP_DELETE_SESSION_REQ"
							"\n\ts5s8_sgwc_msgcnt= %u;"
							"\n\tgtpv2c_send :: s5s8_fd= %d;"
							"\n\tdest_addr= %s : dest_addrln= %u;"
							"\n\tdest_port= %u\n",
							s5s8_sgwc_msgcnt, s5s8_fd,
							inet_ntoa(s5s8_recv_sockaddr.sin_addr),
							s5s8_sockaddr_len,
							ntohs(s5s8_recv_sockaddr.sin_port));

					gtpv2c_send(s5s8_fd, s5s8_tx_buf, payload_length,
							(struct sockaddr *) &s5s8_recv_sockaddr,
							s5s8_sockaddr_len);
							//cp_stats.sm_delete_session_req_sent++;

					cp_stats.sm_delete_session_req_sent++;
					s5s8_sgwc_msgcnt++;
				}

				if (spgw_cfg == SAEGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);

					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
				}
				break;

			case GTP_MODIFY_BEARER_REQ:
				ret = process_pfcp_sess_mod_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx);

				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_modify_bearer_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);

				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			case GTP_RELEASE_ACCESS_BEARERS_REQ:
				ret = process_release_access_bearer_request(
						gtpv2c_s11_rx, gtpv2c_s11_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_release_access_bearer_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			case GTP_BEARER_RESOURCE_CMD:
				ret = process_bearer_resource_command(
						gtpv2c_s11_rx, gtpv2c_s11_tx);

				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_bearer_resource_command "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr, s11_mme_sockaddr_len);
				break;

			case GTP_CREATE_BEARER_RSP:
				ret = process_create_bearer_response(gtpv2c_s11_rx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_create_bearer_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			case GTP_DELETE_BEARER_RSP:
				ret = process_delete_bearer_response(gtpv2c_s11_rx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_delete_bearer_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
				break;

			case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
				ret = process_ddn_ack(gtpv2c_s11_rx, &delay);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SAEGWC:"
							"\n\tprocess_ddn_ack "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				/* TODO something with delay if set */
				break;

			case GTP_ECHO_REQ:
				ret = process_echo_request(gtpv2c_s11_rx, gtpv2c_s11_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC | SAEGWC:"
							"\n\tprocess_echo_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.nbr_of_mme_to_sgwc_echo_req_rcvd++;

#ifdef USE_REST
				/* Reset ECHO Timers */
				ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
				if (ret) {
					/* TODO: Error handling not implemented */
				}
#endif /* USE_REST */

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);

				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);

				cp_stats.nbr_of_sgwc_to_mme_echo_resp_sent++;
				break;
#ifdef USE_REST
			case GTP_ECHO_RSP:
				ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC | SAEGWC:"
							"\n\tprocess_echo_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

				cp_stats.nbr_of_mme_to_sgwc_echo_resp_rcvd++;

				break;
#endif /* USE_REST */
			default:
				fprintf(stderr, "main.c::control_plane::process_msgs-"
						"\n\tcase: SAEGWC::spgw_cfg= %d;"
						"\n\tReceived unprocessed s11 GTPv2c Message Type: "
						"%s (%u 0x%x)... Discarding\n",
						spgw_cfg, gtp_type_str(gtpv2c_s11_rx->gtpc.type),
						gtpv2c_s11_rx->gtpc.type,
						gtpv2c_s11_rx->gtpc.type);
				return;
				break;
			}
		}
	}

	if ((bytes_s5s8_rx > 0) || (bytes_s11_rx > 0))
		++cp_stats.tx;

	switch (spgw_cfg) {
	case SGWC:
	case SAEGWC:
		if (bytes_s11_rx > 0) {
			switch (gtpv2c_s11_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ:
				cp_stats.create_session++;
				cp_stats.number_of_connected_ues++;
				break;
			case GTP_DELETE_SESSION_REQ:
				/* Need Clarification on it */
				/*if (spgw_cfg != SGWC) { */
					cp_stats.delete_session++;

				if (cp_stats.number_of_connected_ues > 0) {
					cp_stats.number_of_connected_ues--;
				}
				break;
			case GTP_MODIFY_BEARER_REQ:
				cp_stats.modify_bearer++;
				break;
			case GTP_RELEASE_ACCESS_BEARERS_REQ:
				cp_stats.rel_access_bearer++;
				cp_stats.number_of_connected_ues--;
				break;
			case GTP_BEARER_RESOURCE_CMD:
				cp_stats.bearer_resource++;
				break;
			case GTP_CREATE_BEARER_RSP:
				cp_stats.create_bearer++;
				return;
			case GTP_DELETE_BEARER_RSP:
				cp_stats.delete_bearer++;
				return;
			case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
				cp_stats.ddn_ack++;
				cp_stats.number_of_connected_ues++;
				/*cp_stats.rel_access_bearer--;*/
			case GTP_ECHO_REQ:
				cp_stats.echo++;
				break;
			}
		}
		break;
	case PGWC:
		if (bytes_s5s8_rx > 0) {
			switch (gtpv2c_s5s8_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ:
				cp_stats.create_session++;
				cp_stats.sm_create_session_req_rcvd++;
				break;
			case GTP_DELETE_SESSION_REQ:
				cp_stats.delete_session++;
				cp_stats.sm_delete_session_req_rcvd++;
				break;
			}
		}
		break;
	default:
		rte_panic("main.c::control_plane::cp_stats-"
				"Unknown spgw_cfg= %u.", spgw_cfg);
		break;
	}
}

