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

#include <sys/time.h>
#include <rte_hash.h>
#include <rte_errno.h>
#include <rte_debug.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_hash_crc.h>

#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages.h"

#ifdef CP_BUILD
#include "cp_config.h"
#include "sm_pcnd.h"
#ifdef C3PO_OSS
#include "cp_stats.h"
#endif /* C3PO_OSS */
#else
#define LDB_ENTRIES_DEFAULT (1024 * 1024 * 4)
#endif /* CP_BUILD */

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
#include "cdnshelper.h"

#define FAILED_ENB_FILE "logs/failed_enb_queries.log"
#endif

#define QUERY_RESULT_COUNT 16

extern int pfcp_fd;

struct rte_hash *node_id_hash;
struct rte_hash *heartbeat_recovery_hash;
struct rte_hash *associated_upf_hash;

#if defined(CP_BUILD) && defined(USE_DNS_QUERY)
extern pfcp_config_t pfcp_config;

static int
add_canonical_result_upflist_entry(canonical_result_t *res,
		uint8_t res_count, uint64_t *imsi_val, uint16_t imsi_len)
{
	upfs_dnsres_t *upf_list = rte_zmalloc_socket(NULL,
				sizeof(upfs_dnsres_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (NULL == upf_list) {
		fprintf(stderr, "Failure to allocate memeory for upf list "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	uint8_t upf_count = 0;

	for (int i = 0; i < res_count; i++) {
		for (int j = 0; j < res[i].host2_info.ipv4host_count; j++) {
			inet_aton(res[i].host2_info.ipv4_hosts[j],
					&upf_list->upf_ip[upf_count]);
			memcpy(upf_list->upf_fqdn[upf_count], res[i].cano_name2,
					strlen((char *)res[i].cano_name2));
			upf_count++;
		}
	}

	if (upf_count == 0) {
		fprintf(stderr, "Could not get collocated candidate list. \n");
		return 0;
	}

	upf_list->upf_count = upf_count;

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	return upf_count;
}

static int
add_dns_result_upflist_entry(dns_query_result_t *res,
		uint8_t res_count, uint64_t *imsi_val, uint16_t imsi_len)
{
	upfs_dnsres_t *upf_list = rte_zmalloc_socket(NULL,
				sizeof(upfs_dnsres_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (NULL == upf_list) {
		fprintf(stderr, "Failure to allocate memeory for upf list "
				"structure: %s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__,
				__LINE__);
		return -1;
	}

	uint8_t upf_count = 0;

	for (int i = 0; i < res_count; i++) {
		for (int j = 0; j < res[i].ipv4host_count; j++) {
			inet_aton(res[i].ipv4_hosts[j],
					&upf_list->upf_ip[upf_count]);
			memcpy(upf_list->upf_fqdn[upf_count], res[i].hostname,
					strlen(res[i].hostname));
			upf_count++;
		}
	}

	if (upf_count == 0) {
		fprintf(stderr, "Could not get SGW-U list using DNS query \n");
		return 0;
	}

	upf_list->upf_count = upf_count;

	upflist_by_ue_hash_entry_add(imsi_val, imsi_len, upf_list);

	return upf_count;
}

static int
record_failed_enbid(char *enbid)
{
	FILE *fp = fopen(FAILED_ENB_FILE, "a");

	if (fp == NULL) {
		fprintf(stderr, "Could not open %s for writing failed "
				"eNodeB query entry.\n", FAILED_ENB_FILE);
		return 1;
	}

	fwrite(enbid, sizeof(char), strlen(enbid), fp);
	fwrite("\n", sizeof(char), 1, fp);
	fclose(fp);

	return 0;
}

int
get_upf_list(pdn_connection *pdn)
{
	int upf_count = 0;
	ue_context *ctxt = NULL;
	char apn_name[MAX_APN_LEN] = {0};

	/* VS: Retrive the UE context */
	ctxt = pdn->context;

	/* Get enodeb id, mnc, mcc from Create Session Request */
	uint32_t enbid = ctxt->uli.ecgi2.eci >> 8;
	char enodeb[11] = {0};
	char mnc[4] = {0};
	char mcc[4] = {0};

	sprintf(enodeb, "%u", enbid);

	if (ctxt->uli.ecgi2.ecgi_mnc_digit_3 == 15)
		sprintf(mnc, "%u%u", ctxt->uli.ecgi2.ecgi_mnc_digit_1,
			ctxt->uli.ecgi2.ecgi_mnc_digit_2);
	else
		sprintf(mnc, "%u%u%u", ctxt->uli.ecgi2.ecgi_mnc_digit_1,
			ctxt->uli.ecgi2.ecgi_mnc_digit_2,
			ctxt->uli.ecgi2.ecgi_mnc_digit_3);

	sprintf(mcc, "%u%u%u", ctxt->uli.ecgi2.ecgi_mcc_digit_1,
				ctxt->uli.ecgi2.ecgi_mcc_digit_2,
				ctxt->uli.ecgi2.ecgi_mcc_digit_3);

	if (!pdn->apn_in_use) {
		return 0;
	}

	/* Get network capabilities from apn configuration file */
	apn *apn_requested = pdn->apn_in_use;

	//memcpy(apn_name,(char *)ctxt->apn.apn + 1, apn_requested->apn_name_length -1);
	/* VS: Need to revist this */
	memcpy(apn_name, (pdn->apn_in_use)->apn_name_label + 1, (pdn->apn_in_use)->apn_name_length -1);

	if (pfcp_config.cp_type == SAEGWC || pfcp_config.cp_type == SGWC) {

		void *sgwupf_node_sel = init_enbupf_node_selector(enodeb, mnc, mcc);

		set_desired_proto(sgwupf_node_sel, ENBUPFNODESELECTOR, UPF_X_SXA);
		if(strlen(apn_requested->apn_net_cap) > 0) {
			set_nwcapability(sgwupf_node_sel, apn_requested->apn_net_cap);
		}

		if (apn_requested->apn_usage_type != -1) {
			set_ueusage_type(sgwupf_node_sel,
				apn_requested->apn_usage_type);
		}

		uint16_t sgwu_count = 0;
		dns_query_result_t sgwu_list[QUERY_RESULT_COUNT] = {0};
		process_dnsreq(sgwupf_node_sel, sgwu_list, &sgwu_count);

		if (!sgwu_count) {

			record_failed_enbid(enodeb);
			deinit_node_selector(sgwupf_node_sel);

			/* Query DNS based on lb and hb of tac */
			char lb[8] = {0};
			char hb[8] = {0};

			if (ctxt->uli.tai != 1) {
				fprintf(stderr, "Could not get SGW-U list using DNS"
								"query. TAC missing in CSR.\n");
				return 0;
			}

			sprintf(lb, "%u", ctxt->uli.tai2.tai_tac & 0xFF);
			sprintf(hb, "%u", (ctxt->uli.tai2.tai_tac >> 8) & 0xFF);

			sgwupf_node_sel = init_sgwupf_node_selector(lb, hb, mnc, mcc);

			set_desired_proto(sgwupf_node_sel, SGWUPFNODESELECTOR, UPF_X_SXA);

			if(strlen(apn_requested->apn_net_cap) > 0) {
				set_nwcapability(sgwupf_node_sel, apn_requested->apn_net_cap);
			}

			if (apn_requested->apn_usage_type != -1) {
				set_ueusage_type(sgwupf_node_sel,
					apn_requested->apn_usage_type);
			}

			process_dnsreq(sgwupf_node_sel, sgwu_list, &sgwu_count);

			if (!sgwu_count) {
				fprintf(stderr, "Could not get SGW-U list using DNS"
					"query \n");
				return 0;
			}
		}

		/* SAEGW-C */
		if (pdn->s5s8_pgw_gtpc_ipv4.s_addr == 0) {

			uint16_t pgwu_count = 0;
			dns_query_result_t pgwu_list[QUERY_RESULT_COUNT] = {0};

			void *pwupf_node_sel = init_pgwupf_node_selector(apn_name,
					mnc, mcc);

			set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);

			if(strlen(apn_requested->apn_net_cap) > 0) {
				set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);
			}

			if (apn_requested->apn_usage_type != -1) {
				set_ueusage_type(pwupf_node_sel,
					apn_requested->apn_usage_type);
			}

			process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

			/* Get colocated candidate list */
			canonical_result_t result[QUERY_RESULT_COUNT] = {0};
			int res_count = get_colocated_candlist(sgwupf_node_sel,
						pwupf_node_sel, result);

			if (!res_count) {
				deinit_node_selector(pwupf_node_sel);
				return 0;
			}

			/* VS: Need to check this */
			upf_count = add_canonical_result_upflist_entry(result, res_count,
							&ctxt->imsi, sizeof(ctxt->imsi));

			deinit_node_selector(pwupf_node_sel);

		} else { /* SGW-C */

			upf_count = add_dns_result_upflist_entry(sgwu_list, sgwu_count,
							&ctxt->imsi, sizeof(ctxt->imsi));
		}

		deinit_node_selector(sgwupf_node_sel);

	} else if (pfcp_config.cp_type == PGWC) {

		uint16_t pgwu_count = 0;
		dns_query_result_t pgwu_list[QUERY_RESULT_COUNT] = {0};

		void *pwupf_node_sel = init_pgwupf_node_selector(apn_name, mnc, mcc);

		set_desired_proto(pwupf_node_sel, PGWUPFNODESELECTOR, UPF_X_SXB);
		if(strlen(apn_requested->apn_net_cap) > 0) {
			set_nwcapability(pwupf_node_sel, apn_requested->apn_net_cap);
		}

		if (apn_requested->apn_usage_type != -1) {
			set_ueusage_type(pwupf_node_sel,
				apn_requested->apn_usage_type);
		}

		process_dnsreq(pwupf_node_sel, pgwu_list, &pgwu_count);

		/* VS: Need to check this */
		/* Get collocated candidate list */
		if (!strlen((char *)pdn->fqdn)) {
			fprintf(stderr, "SGW-U node name missing in CSR. \n");
			deinit_node_selector(pwupf_node_sel);
			return 0;
		}

		canonical_result_t result[QUERY_RESULT_COUNT] = {0};
		int res_count = get_colocated_candlist_fqdn(
				(char *)pdn->fqdn, pwupf_node_sel, result);

		if (!res_count) {
			fprintf(stderr, "Could not get collocated candidate list. \n");
			deinit_node_selector(pwupf_node_sel);
			return 0;
		}

		upf_count = add_canonical_result_upflist_entry(result, res_count,
							&ctxt->imsi, sizeof(ctxt->imsi));

		deinit_node_selector(pwupf_node_sel);
	}

	return upf_count;
}

int
dns_query_lookup(ue_context *context, uint8_t eps_index, uint32_t **upf_ip)
{
	upfs_dnsres_t *entry = NULL;

	if (get_upf_list(context->pdns[eps_index]) == 0){
		 clLog(sxlogger, eCLSeverityCritical, "%s:%d Error:\n",
			    __func__, __LINE__);
		return GTPV2C_CAUSE_REQUEST_REJECTED;
	}

	/* Fill msg->upf_ipv4 address */
	if ((get_upf_ip(context, &entry, upf_ip)) != 0) {
		fprintf(stderr, "Failed to get upf ip address\n");
		return GTPV2C_CAUSE_REQUEST_REJECTED;
	}
	memcpy((context->pdns[eps_index])->fqdn, entry->upf_fqdn[entry->current_upf],
					strlen(entry->upf_fqdn[entry->current_upf]));
	return 0;
}

#endif /* CP_BUILD && USE_DNS_QUERY */

#ifdef CP_BUILD
int
pfcp_recv(void *msg_payload, uint32_t size,
		struct sockaddr_in *peer_addr)
{
	socklen_t addr_len = sizeof(*peer_addr);
	uint32_t bytes;
	bytes = recvfrom(pfcp_fd, msg_payload, size, 0,
			(struct sockaddr *)peer_addr, &addr_len);
	//if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC)
	//	bytes = recvfrom(pfcp_sgwc_fd_arr[0], msg_payload, size, 0,
	//			(struct sockaddr *)peer_addr, &addr_len);
	//else
	//	bytes = recvfrom(pfcp_pgwc_fd_arr[0], msg_payload, size, 0,
	//			(struct sockaddr *)peer_addr, &addr_len);
	return bytes;
}
#endif /* CP_BUILD */

int
pfcp_send(int fd, void *msg_payload, uint32_t size,
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
#ifdef CP_BUILD
		clLog(clSystemLog, eCLSeverityDebug, "Error in uptime\n");
#endif /* CP_BUILD */
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
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id()
	};

	node_id_hash = rte_hash_create(&rte_hash_params);
	if (!node_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

void
create_heartbeat_hash_table(void)
{
	struct rte_hash_parameters rte_hash_params = {
		.name = "RECOVERY_TIME_HASH",
		.entries = HEARTBEAT_ASSOCIATION_ENTRIES_DEFAULT,
		.key_len = sizeof(uint32_t),
		.hash_func = rte_hash_crc,
		.hash_func_init_val = 0,
		.socket_id = rte_socket_id()
	};

	heartbeat_recovery_hash = rte_hash_create(&rte_hash_params);
	if (!heartbeat_recovery_hash) {
		rte_panic("%s hash create failed: %s (%u)\n.",
				rte_hash_params.name,
				rte_strerror(rte_errno), rte_errno);
	}

}

/* TODO: HP: Remove following */
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
