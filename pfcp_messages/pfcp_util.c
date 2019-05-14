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

#include <errno.h>
#include <stdbool.h>

#include <rte_debug.h>

#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#include "pfcp_set_ie.h"
#include "pfcp_messages.h"
#include "pfcp_util.h"

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "cdnshelper.h"
#endif

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

#define DNSCACHE_CONCURRENT 2
#define DNSCACHE_PERCENTAGE 70
#define DNSCACHE_INTERVAL 4000
#define DNS_PORT 53

struct rte_hash *node_id_hash;
struct rte_hash *heartbeat_recovery_hash;
extern pfcp_context_t pfcp_ctxt;
struct rte_hash *associated_upf_hash;
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];
extern pfcp_config_t pfcp_config;

extern struct pfcp_config_t pfcp_config;


#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
int
get_upf_list(create_session_request_t *csr,
		struct in_addr *p_upf_list, char *sgwu_fqdn)
{
	int upf_count =0;

	set_dnscache_refresh_params(DNSCACHE_CONCURRENT,
			DNSCACHE_PERCENTAGE, DNSCACHE_INTERVAL);

	for (uint32_t i = 0; i < pfcp_config.num_nameserver; i++)
		set_named_server(pfcp_config.nameserver_ip[i], DNS_PORT, DNS_PORT);

	/* Get enodeb id, mnc, mcc from Create Session Request */
	uint32_t enbid = csr->uli.ecgi.eci >> 8;
	char enodeb[11] = {0};
	sprintf(enodeb, "%u", enbid);

	char mnc[4] = {0};
	char mcc[4] = {0};

	if (csr->uli.ecgi.mcc_mnc.mnc_digit_3 == 15)
		sprintf(mnc, "%u%u", csr->uli.ecgi.mcc_mnc.mnc_digit_1,
			csr->uli.ecgi.mcc_mnc.mnc_digit_2);
	else
		sprintf(mnc, "%u%u%u", csr->uli.ecgi.mcc_mnc.mnc_digit_1,
			csr->uli.ecgi.mcc_mnc.mnc_digit_2,
			csr->uli.ecgi.mcc_mnc.mnc_digit_3);

	sprintf(mcc, "%u%u%u", csr->uli.ecgi.mcc_mnc.mcc_digit_1,
				csr->uli.ecgi.mcc_mnc.mcc_digit_2,
				csr->uli.ecgi.mcc_mnc.mcc_digit_3);

	/* Get network capabilities from apn configuration file */
	apn *apn_requested = get_apn((char *)csr->apn.apn, csr->apn.header.len);

	if (!apn_requested) {
		fprintf(stderr, "Could not get SGW-U list using DNS"
				"query. APN missing in CSR.\n");
		return 0;
	}

	char apn_name[64] = {0};
	memcpy(apn_name, csr->apn.apn + 1, apn_requested->apn_name_length -1);

	if (pfcp_config.cp_type == SAEGWC || pfcp_config.cp_type == SGWC) {

		void *enbupf_node_sel = init_enbupf_node_selector(enodeb, mnc, mcc);

		set_desired_proto(enbupf_node_sel, ENBUPFNODESELECTOR, UPF_X_SXA);
		set_nwcapability(enbupf_node_sel, apn_requested->apn_net_cap);
		if (csr->ue_usage_type.header.len)
			set_ueusage_type(enbupf_node_sel,
					csr->ue_usage_type.mapped_ue_usage_type);
		else
			set_ueusage_type(enbupf_node_sel,
					apn_requested->apn_usage_type);

		dns_query_result_t sgwu_list[16] = {0};
		uint16_t sgwu_count = 0;
		process_dnsreq(enbupf_node_sel, sgwu_list, &sgwu_count);

		if (!sgwu_count) {
			fprintf(stderr, "Could not get SGW-U list using DNS"
					"query \n");
			deinit_node_selector(enbupf_node_sel);
			return 0;
		}

		/* SAEGW-C */
		if (csr->s5s8pgw_pmip.ip.ipv4v6.ipv4.s_addr == 0) {

			dns_query_result_t pgwu_list[16] = {0};
			uint16_t pgwu_count = 0;

			void *pwupf_node_sel = init_pgwupf_node_selector(apn_name,
					mnc, mcc);

			set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);
			set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);
			if (csr->ue_usage_type.header.len)
				set_ueusage_type(pwupf_node_sel,
						csr->ue_usage_type.mapped_ue_usage_type);
			else
				set_ueusage_type(pwupf_node_sel,
						apn_requested->apn_usage_type);

			process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

			/* Get colocated candidate list */
			canonical_result_t result[16] = {0};
			int res_count = get_colocated_candlist(enbupf_node_sel,
						pwupf_node_sel, result);

			for (int i = 0; i < res_count; i++) {
				inet_aton(result[i].host2_info.ipv4_hosts[0],
						&p_upf_list[upf_count++]);
			}

			deinit_node_selector(pwupf_node_sel);

		} else { /* SGW-C */
			for (int i = 0; i < sgwu_count; i++) {
				inet_aton(sgwu_list[i].ipv4_hosts[0],
						&p_upf_list[upf_count++]);
			}
			strncpy(sgwu_fqdn, sgwu_list[0].hostname,
					strnlen(sgwu_list[0].hostname,
							MAX_HOSTNAME_LENGTH - 1) + 1);
			return sgwu_count;
		}

		deinit_node_selector(enbupf_node_sel);

	} else if (pfcp_config.cp_type == PGWC) {

		dns_query_result_t pgwu_list[16] = {0};
		uint16_t pgwu_count = 0;

		void *pwupf_node_sel = init_pgwupf_node_selector(apn_name, mnc, mcc);

		set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);
		set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);

		if (csr->ue_usage_type.header.len)
			set_ueusage_type(pwupf_node_sel,
					csr->ue_usage_type.mapped_ue_usage_type);
		else
			set_ueusage_type(pwupf_node_sel,
					apn_requested->apn_usage_type);

		process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

		/* Get collocated candidate list */
		if (!csr->sgwu_nodename.header.len) {
			fprintf(stderr, "SGW-U node name missing in CSR. \n");
			deinit_node_selector(pwupf_node_sel);
			return 0;
		}

		canonical_result_t result[16] = {0};
		int res_count = get_colocated_candlist_fqdn(
				(char *)csr->sgwu_nodename.fqdn, pwupf_node_sel, result);

		for (int i = 0; i < res_count; i++) {
			inet_aton(result[i].host2_info.ipv4_hosts[0],
					&p_upf_list[upf_count++]);
		}

		deinit_node_selector(pwupf_node_sel);
	}



	return upf_count;
}
#endif

int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes;
	if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC)
		bytes = recvfrom(pfcp_sgwc_fd_arr[0], msg_payload, size, 0,
				(struct sockaddr *)peer_addr, &addr_len);
	else
		bytes = recvfrom(pfcp_pgwc_fd_arr[0], msg_payload, size, 0,
				(struct sockaddr *)peer_addr, &addr_len);
	return bytes;
}

int
pfcp_send(int fd,void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes = sendto(fd,
			(uint8_t *) msg_payload,
			size,
			MSG_DONTWAIT,
			(struct sockaddr *)peer_addr,
			addr_len);
	return bytes;
}

long
uptime(void)
{
	struct sysinfo s_info;
	int error = sysinfo(&s_info);
	if(error != 0) {
		RTE_LOG_DP(DEBUG, CP, "Error in uptime\n");
	}
	return s_info.uptime;
}

void
create_node_id_hash(void)
{

	struct rte_hash_parameters rte_hash_params = {
		.name = "node_id_hash",
		.entries = LDB_ENTRIES_DEFAULT,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	node_id_hash = rte_hash_create(&rte_hash_params);
	if (!node_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void
create_associated_upf_hash(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "associated_upf_hash",
		.entries = 50,
		.key_len = UINT32_SIZE,
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id(),
	};

	associated_upf_hash = rte_hash_create(&rte_hash_params);
	if (!associated_upf_hash) {
		rte_panic("%s Associated UPF hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

uint32_t
current_ntp_timestamp(void) {

	struct timeval tim;
	uint8_t ntp_time[8] = {0};
	uint32_t timestamp = 0;

	gettimeofday(&tim, NULL);
	time_to_ntp(&tim, ntp_time);

	timestamp |= ntp_time[0] << 24 | ntp_time[1] << 16
								| ntp_time[2] << 8 | ntp_time[3];

	return timestamp;
}

void
time_to_ntp(struct timeval *tv, uint8_t *ntp)
{
	uint64_t ntp_tim = 0;
	uint8_t len = (uint8_t)sizeof(ntp)/sizeof(ntp[0]);
	uint8_t *p = ntp + len;

	int i = 0;

	ntp_tim = tv->tv_usec;
	ntp_tim <<= 32;
	ntp_tim /= 1000000;

	/* Setting the ntp in network byte order */

	for (i = 0; i < len/2; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

	ntp_tim = tv->tv_sec;
	ntp_tim += OFFSET;

	/* Settting  the fraction of second */

	for (; i < len; i++) {
		*--p = ntp_tim & 0xff;
		ntp_tim >>= 8;
	}

}
