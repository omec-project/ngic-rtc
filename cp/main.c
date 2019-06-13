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
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <getopt.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <signal.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_ether.h>

#include <rte_common.h>
#include <rte_acl.h>
#include <rte_ip.h>
#include <sys/timeb.h>

#include <rte_cfgfile.h>

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "debug_str.h"
#include "interface.h"
#include "packet_filters.h"
#include "dp_ipc_api.h"
#include "cp.h"
#include "cp_stats.h"
#include "cp_config.h"
#include "req_resp.h"
#include "pfcp_set_ie.h"
#include "pfcp.h"
#include "pfcp_ies.h"

#ifdef C3PO_OSS
#include "cp_adapter.h"
#include "clogger.h"
#include "cstats.h"
#include "crest.h"
#endif

#include "../pfcp_messages/pfcp_util.h"
#include "../pfcp_messages/pfcp_set_ie.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_association.h"
#include "pfcp_session.h"

#ifdef USE_REST
#include "../restoration/restoration_timer.h"
#endif /* USE_REST */

#ifdef ZMQ_COMM
#include "gtpv2c_set_ie.h"
#endif  /* ZMQ_COMM */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#define PCAP_TTL                     (64)
#define PCAP_VIHL                    (0x0045)

#define LOG_LEVEL_SET           (0x0001)

#define REQ_ARGS                (LOG_LEVEL_SET)

#define RTE_LOGTYPE_CP RTE_LOGTYPE_USER4

#ifdef ZMQ_COMM
#define OP_ID_HASH_SIZE     (1 << 18)

struct rte_hash *resp_op_id_hash;

#endif  /* ZMQ_COMM */

enum cp_config spgw_cfg;
int s11_fd = -1;
int s11_pcap_fd = -1;
int s5s8_sgwc_fd = -1;
int s5s8_pgwc_fd = -1;

extern int s11_sgwc_fd_arr[MAX_NUM_SGWC];
extern int s5s8_sgwc_fd_arr[MAX_NUM_SGWC];
extern int s5s8_pgwc_fd_arr[MAX_NUM_PGWC];
extern int pfcp_sgwc_fd_arr[MAX_NUM_SGWC];
extern int pfcp_pgwc_fd_arr[MAX_NUM_PGWC];

extern struct rte_hash *associated_upf_hash;

int pfcp_sgwc_fd =-1 ;

uint32_t start_time;

/* pfcp_changes starts */
int num_dp = 0;

struct pfcp_config_t pfcp_config;

pcap_dumper_t *pcap_dumper;
pcap_t *pcap_reader;

//time_t curtime;

struct cp_params cp_params;
struct cp_stats_t cp_stats;

socklen_t s11_mme_sockaddr_len = sizeof(s11_mme_sockaddr);
socklen_t s5s8_sgwc_sockaddr_len = sizeof(s5s8_sgwc_sockaddr);
socklen_t s5s8_pgwc_sockaddr_len = sizeof(s5s8_pgwc_sockaddr);

/*Global static , so that this cnt can be incremented for buffered msg in SGWC/PGWC*/
static uint8_t s5s8_sgwc_msgcnt = 0;
static uint8_t s5s8_pgwc_msgcnt = 0;

#ifdef USE_REST
uint32_t up_time = 0;
uint8_t rstCnt = 0;
#endif /* USE_REST*/

int apnidx = 0;
clock_t cp_stats_execution_time;

/**
 * Setting/enable CP RTE LOG_LEVEL.
 */
static void
set_log_level(uint8_t log_level)
{

/** Note :In dpdk set max log level is INFO, here override the
 *  max value of RTE_LOG_INFO for enable DEBUG logs (dpdk-16.11.4
 *  and dpdk-18.02).
 */
	if (log_level == DEBUG)
		rte_log_set_level(RTE_LOGTYPE_CP, RTE_LOG_DEBUG);
	else if (log_level == NOTICE)
		rte_log_set_global_level(RTE_LOG_NOTICE);
	else rte_log_set_global_level(RTE_LOG_INFO);

}

/**
 * Parses c-string containing dotted decimal ipv4 and stores the
 *   value within the in_addr type
 *
 * @param optarg
 *   c-string containing dotted decimal ipv4 address
 * @param addr
 *   destination of parsed IP string
 */
/*
static void
parse_arg_ip(const char *optarg, struct in_addr *addr)
{
	if (!inet_aton(optarg, addr))
		rte_panic("Invalid argument - %s - Exiting.\n", optarg);
}
*/

/**
 *
 * Parses non-dpdk command line program arguments for control plane
 *
 * @param argc
 *   number of arguments
 * @param argv
 *   array of c-string arguments
 */
static void
parse_arg(int argc, char **argv)
{
	char errbuff[PCAP_ERRBUF_SIZE];
	int args_set = 0;
	int c = 0;
	pcap_t *pcap;

	const struct option long_options[] = {
	  {"pcap_file_in", required_argument, NULL, 'x'},
	  {"pcap_file_out", required_argument, NULL, 'y'},
	  {"log_level",   required_argument, NULL, 'z'},
	  {0, 0, 0, 0}
	};

	do {
		int option_index = 0;

		c = getopt_long(argc, argv, "x:y:z:", long_options,
		    &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'x':
			pcap_reader = pcap_open_offline(optarg, errbuff);
			break;
		case 'y':
			pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
			pcap_dumper = pcap_dump_open(pcap, optarg);
			s11_pcap_fd = pcap_fileno(pcap);
			break;
		case 'z':
			set_log_level((uint8_t)atoi(optarg));
			args_set |= LOG_LEVEL_SET;
			break;
		default:
			rte_panic("Unknown argument - %s.", argv[optind]);
			break;
		}
	} while (c != -1);
	if ((args_set & REQ_ARGS) != REQ_ARGS) {
		fprintf(stderr, "Usage: %s\n", argv[0]);
		for (c = 0; long_options[c].name; ++c) {
			fprintf(stderr, "\t[ -%s | -%c ] %s\n",
					long_options[c].name,
					long_options[c].val,
					long_options[c].name);
		}
		rte_panic("\n");
	}
}

//#ifdef PFCP_COMM
/**
 * @brief
 * Initializes Control Plane data structures, packet filters, and calls for the
 * Data Plane to create required tables
 */
void
pfcp_init_cp(void)
{
	init_pfcp();

	switch (pfcp_config.cp_type) {
		case SAEGWC:
			pfcp_init_s11();
			break;
		case SGWC:
			pfcp_init_s11();
			pfcp_init_s5s8_sgwc();
			break;
		case PGWC:
			pfcp_init_s5s8_pgwc();
			break;
		default:
			rte_panic("main.c::pfcp_init_cp()-"
					"Unknown spgw_cfg= %u.", pfcp_config.cp_type);
			break;
	}
}

/**
 * @brief Initalizes S11 interface if in use
 */
void
pfcp_init_s11(void)
{
	int ret;
	int option =1;
	for(uint32_t i =0 ; i < pfcp_config.num_sgwc; i++) {
		s11_sgwc_fd_arr[i] = socket(AF_INET, SOCK_DGRAM, 0);
		setsockopt(s11_sgwc_fd_arr[i], SOL_SOCKET, SO_REUSEADDR,
							&option, sizeof(option));

		if (s11_sgwc_fd_arr[i] < 0)
			rte_panic("Socket call error : %s", strerror(errno));

		s11_sgwc_port_arr[i] = htons(pfcp_config.sgwc_s11_port[i]);
		bzero(s11_sgwc_sockaddr_arr[i].sin_zero,
				sizeof(s11_sgwc_sockaddr_arr[i].sin_zero));
		s11_sgwc_sockaddr_arr[i].sin_family = AF_INET;
		s11_sgwc_sockaddr_arr[i].sin_port = s11_sgwc_port_arr[i];
		s11_sgwc_sockaddr_arr[i].sin_addr = pfcp_config.sgwc_s11_ip[i];

		ret = bind(s11_sgwc_fd_arr[i], (struct sockaddr *) &s11_sgwc_sockaddr_arr[i],
				sizeof(struct sockaddr_in));

		RTE_LOG_DP(INFO, CP, "NGIC- main.c::pfcp_init_s11()"
				"\n\ts11_sgwc_fd_arr[%d]= %d :: "
				"\n\ts11_sgw_ip[%d]= %s : s11_port[%d]= %d\n",i,
				s11_sgwc_fd_arr[i], i, inet_ntoa(pfcp_config.sgwc_s11_ip[i]),
						 i, ntohs(s11_sgwc_port_arr[i]));

		if (ret < 0) {
			rte_panic("Bind error for %s:%u - %s\n",
					inet_ntoa(s11_sgwc_sockaddr_arr[i].sin_addr),
					ntohs(s11_sgwc_sockaddr_arr[i].sin_port),
					strerror(errno));
		}
	}
}

/**
 * @brief Initalizes s5s8_pgwc interface if in use
 */
void
pfcp_init_s5s8_pgwc(void)
{
	int ret;
	for(uint32_t i =0; i< pfcp_config.num_pgwc; i++){
		s5s8_pgwc_fd_arr[i] = socket(AF_INET, SOCK_DGRAM, 0);

		if (s5s8_pgwc_fd_arr[i] < 0)
			rte_panic("Socket call error : %s", strerror(errno));

		s5s8_pgwc_port_arr[i] = htons(pfcp_config.pgwc_s5s8_port[i]);
		bzero(s5s8_pgwc_sockaddr_arr[i].sin_zero,
				sizeof(s5s8_pgwc_sockaddr_arr[i].sin_zero));
		s5s8_pgwc_sockaddr_arr[i].sin_family = AF_INET;
		s5s8_pgwc_sockaddr_arr[i].sin_port = s5s8_pgwc_port_arr[i];
		s5s8_pgwc_sockaddr_arr[i].sin_addr = pfcp_config.pgwc_s5s8_ip[i];

		ret = bind(s5s8_pgwc_fd_arr[i], (struct sockaddr *) &s5s8_pgwc_sockaddr_arr[i],
				sizeof(struct sockaddr_in));
		RTE_LOG_DP(INFO, CP, "NGIC- main.c::pfcp_init_s5s8_pgwc()"
				"\n\ts5s8_pgwc_fd_arr[%d]= %d :: "
				"\n\ts5s8_pgwc_ip_arr[%d]= %s : s5s8_pgwc_port_arr[%d]= %d\n",
				i, s5s8_pgwc_fd_arr[i],i, inet_ntoa(pfcp_config.pgwc_s5s8_ip[i]),
				i, ntohs(s5s8_pgwc_port_arr[i]));

		if (ret < 0) {
			rte_panic("Bind error for %s:%u - %s\n",
					inet_ntoa(s5s8_pgwc_sockaddr_arr[i].sin_addr),
					ntohs(s5s8_pgwc_sockaddr_arr[i].sin_port),
					strerror(errno));
		}
	}
	/* Initialize peer sgwc inteface for sendto(.., dest_addr) */
	for(uint32_t i =0; i< pfcp_config.num_sgwc;i++){
		bzero(s5s8_sgwc_sockaddr_arr[i].sin_zero,
				sizeof(s5s8_sgwc_sockaddr_arr[i].sin_zero));
		s5s8_sgwc_sockaddr_arr[i].sin_family = AF_INET;
		s5s8_sgwc_sockaddr_arr[i].sin_port = htons(pfcp_config.sgwc_s5s8_port[i]);
		s5s8_sgwc_sockaddr_arr[i].sin_addr = pfcp_config.sgwc_s5s8_ip[i];
	}
}

/**
 * @brief Initalizes s5s8_pgwc interface if in use
 */

void
pfcp_init_s5s8_sgwc(void)
{
	int ret;
	for(uint32_t i =0; i< pfcp_config.num_sgwc; i++){
		s5s8_sgwc_port_arr[i] = htons(pfcp_config.sgwc_s5s8_port[i]);

		s5s8_sgwc_fd_arr[i] = socket(AF_INET, SOCK_DGRAM, 0);

		if (s5s8_sgwc_fd_arr[i] < 0)
			rte_panic("Socket call error : %s", strerror(errno));

		bzero(s5s8_sgwc_sockaddr_arr[i].sin_zero,
				sizeof(s5s8_sgwc_sockaddr_arr[i].sin_zero));
		s5s8_sgwc_sockaddr_arr[i].sin_family = AF_INET;
		s5s8_sgwc_sockaddr_arr[i].sin_port = s5s8_sgwc_port_arr[i];
		s5s8_sgwc_sockaddr_arr[i].sin_addr = pfcp_config.sgwc_s5s8_ip[i];

		ret = bind(s5s8_sgwc_fd_arr[i], (struct sockaddr *) &s5s8_sgwc_sockaddr_arr[i],
				sizeof(struct sockaddr_in));
		RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_s5s8_sgwc()"
				"\n\ts5s8_sgwc_fd_arr[%d]= %d :: "
				"\n\ts5s8_sgwc_ip_arr[%d]= %s : s5s8_sgwc_port_arr[%d]= %d\n", i,
				s5s8_sgwc_fd_arr[i], i, inet_ntoa(pfcp_config.sgwc_s5s8_ip[i]),
				i, ntohs(s5s8_sgwc_port_arr[i]));

		if (ret < 0) {
			rte_panic("Bind error for %s:%u - %s\n",
					inet_ntoa(s5s8_sgwc_sockaddr_arr[i].sin_addr),
					ntohs(s5s8_sgwc_sockaddr_arr[i].sin_port),
					strerror(errno));
		}
	}
	/* Initialize peer pgwc inteface for sendto(.., dest_addr) */
	for(uint32_t i =0; i< pfcp_config.num_pgwc; i++){
		bzero(s5s8_pgwc_sockaddr_arr[i].sin_zero,
				sizeof(s5s8_pgwc_sockaddr_arr[i].sin_zero));
		s5s8_pgwc_sockaddr_arr[i].sin_family = AF_INET;
		s5s8_pgwc_sockaddr_arr[i].sin_port = htons(pfcp_config.pgwc_s5s8_port[i]);
		s5s8_pgwc_sockaddr_arr[i].sin_addr = pfcp_config.pgwc_s5s8_ip[i];
	}
}


void
init_pfcp(void)
{
	int ret;
	if(pfcp_config.cp_type == SGWC || pfcp_config.cp_type == SAEGWC)
	{
		for(uint32_t i =0; i < pfcp_config.num_sgwc; i++){
			pfcp_sgwc_port_arr[i] = htons(pfcp_config.sgwc_pfcp_port[i]);

			pfcp_sgwc_fd_arr[i] = socket(AF_INET, SOCK_DGRAM, 0);

			if (pfcp_sgwc_fd_arr[i] < 0)
				rte_panic("Socket call error : %s", strerror(errno));
			bzero(pfcp_sgwc_sockaddr_arr[i].sin_zero,
					sizeof(pfcp_sgwc_sockaddr_arr[i].sin_zero));
			pfcp_sgwc_sockaddr_arr[i].sin_family = AF_INET;
			pfcp_sgwc_sockaddr_arr[i].sin_port = pfcp_sgwc_port_arr[i];
			pfcp_sgwc_sockaddr_arr[i].sin_addr = pfcp_config.sgwc_pfcp_ip[i];

			ret = bind(pfcp_sgwc_fd_arr[i], (struct sockaddr *) &pfcp_sgwc_sockaddr_arr[i],
					sizeof(struct sockaddr_in));
			RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_pfcp()"
					"\n\tpfcp_sgwc_fd_arr[%d]= %d :: "
					"\n\tpfcp_sgwc_ip_arr[%d]= %s : pfcp_sgwc_port_arr[%d]= %d\n",i,
					pfcp_sgwc_fd_arr[i],i, inet_ntoa(pfcp_config.sgwc_pfcp_ip[i]),i,
					ntohs(pfcp_sgwc_port_arr[i]));
			if (ret < 0) {
				rte_panic("Bind error for %s:%u - %s\n",
						inet_ntoa(pfcp_sgwc_sockaddr_arr[i].sin_addr),
						ntohs(pfcp_sgwc_sockaddr_arr[i].sin_port),
						strerror(errno));
			}
		}
	} else {

		for(uint32_t i =0; i < pfcp_config.num_pgwc; i++){
			pfcp_pgwc_port_arr[i] = htons(pfcp_config.pgwc_pfcp_port[i]);

			pfcp_pgwc_fd_arr[i] = socket(AF_INET, SOCK_DGRAM, 0);

			if (pfcp_pgwc_fd_arr[i] < 0)
				rte_panic("Socket call error : %s", strerror(errno));
			bzero(pfcp_pgwc_sockaddr_arr[i].sin_zero,
					sizeof(pfcp_pgwc_sockaddr_arr[i].sin_zero));
			pfcp_pgwc_sockaddr_arr[i].sin_family = AF_INET;
			pfcp_pgwc_sockaddr_arr[i].sin_port = pfcp_pgwc_port_arr[i];
			pfcp_pgwc_sockaddr_arr[i].sin_addr = pfcp_config.pgwc_pfcp_ip[i];

			ret = bind(pfcp_pgwc_fd_arr[i], (struct sockaddr *) &pfcp_pgwc_sockaddr_arr[i],
					sizeof(struct sockaddr_in));
			RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_pfcp()"
					"\n\tpfcp_pgwc_fd_arr[%d]= %d :: "
					"\n\tpfcp_pgwc_ip_arr[%d]= %s : pfcp_pgwc_port_arr[%d]= %d\n",i,
					pfcp_pgwc_fd_arr[i],i, inet_ntoa(pfcp_config.pgwc_pfcp_ip[i]),i,
					ntohs(pfcp_pgwc_port_arr[i]));
			if (ret < 0) {
				rte_panic("Bind error for %s:%u - %s\n",
						inet_ntoa(pfcp_pgwc_sockaddr_arr[i].sin_addr),
						ntohs(pfcp_pgwc_sockaddr_arr[i].sin_port),
						strerror(errno));
			}
		}
	}
	/* Initialize peer sgwu/pgwu/spgwu inteface for sendto(.., dest_addr) */
	switch ( pfcp_config.cp_type) {
		case SGWC:
			//Initializing SGWU only
			for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){
				pfcp_sgwu_port_arr[i] = htons(pfcp_config.sgwu_pfcp_port[i]);
				bzero(pfcp_sgwu_sockaddr_arr[i].sin_zero,
						sizeof(pfcp_sgwu_sockaddr_arr[i].sin_zero));
				pfcp_sgwu_sockaddr_arr[i].sin_family = AF_INET;
				pfcp_sgwu_sockaddr_arr[i].sin_port = pfcp_sgwu_port_arr[i];
				pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_config.sgwu_pfcp_ip[i];
			}
			break;

		case PGWC:
			//Initializing PGWU only
			for(uint32_t i=0;i < pfcp_config.num_pgwu; i++ ){
				pfcp_pgwu_port_arr[i] = htons(pfcp_config.pgwu_pfcp_port[i]);
				bzero(pfcp_pgwu_sockaddr_arr[i].sin_zero,
						sizeof(pfcp_pgwu_sockaddr_arr[i].sin_zero));
				pfcp_pgwu_sockaddr_arr[i].sin_family = AF_INET;
				pfcp_pgwu_sockaddr_arr[i].sin_port = pfcp_pgwu_port_arr[i];
				pfcp_pgwu_sockaddr_arr[i].sin_addr = pfcp_config.pgwu_pfcp_ip[i];
			}
			break;

	// case SPGWC:
	// //Initializing SAEGWU only
	// for(uint32_t i=0;i < pfcp_config.num_spgwu; i++ ){
	// pfcp_spgwu_port_arr[i] = htons(pfcp_config.spgwu_pfcp_port[i]);
	// bzero(pfcp_spgwu_sockaddr_arr[i].sin_zero,
	// sizeof(pfcp_spgwu_sockaddr_arr[i].sin_zero));
	// pfcp_spgwu_sockaddr_arr[i].sin_family = AF_INET;
	// pfcp_spgwu_sockaddr_arr[i].sin_port = pfcp_spgwu_port_arr[i];
	// pfcp_spgwu_sockaddr_arr[i].sin_addr = pfcp_config.spgwu_pfcp_ip[i];
	// }
	// break;

		case SAEGWC:
			//Initializing SAEGWU and SGWU both
			//for(uint32_t i=0;i < pfcp_config.num_spgwu; i++ ){
			// pfcp_spgwu_port_arr[i] =  htons(pfcp_config.spgwu_pfcp_port[i]);
			// bzero(pfcp_spgwu_sockaddr_arr[i].sin_zero,
			//   sizeof(pfcp_spgwu_sockaddr_arr[i].sin_zero));
			// pfcp_spgwu_sockaddr_arr[i].sin_family = AF_INET;
			// pfcp_spgwu_sockaddr_arr[i].sin_port = pfcp_spgwu_port_arr[i];
			// pfcp_spgwu_sockaddr_arr[i].sin_addr = pfcp_config.spgwu_pfcp_ip[i];
			//}
			for(uint32_t i=0;i < pfcp_config.num_sgwu; i++ ){
				pfcp_sgwu_port_arr[i] =  htons(pfcp_config.sgwu_pfcp_port[i]);
				bzero(pfcp_sgwu_sockaddr_arr[i].sin_zero,
						sizeof(pfcp_sgwu_sockaddr_arr[i].sin_zero));
				pfcp_sgwu_sockaddr_arr[i].sin_family = AF_INET;
				pfcp_sgwu_sockaddr_arr[i].sin_port = pfcp_sgwu_port_arr[i];
				pfcp_sgwu_sockaddr_arr[i].sin_addr = pfcp_config.sgwu_pfcp_ip[i];
			}
			break;
		default:
			rte_panic("main.c::init_pfcp()-"
					"Unknown spgw_cfg= %u.", pfcp_config.cp_type);
			break;
	}
}

struct in_addr upf_list[10];
//#endif /* PFCP_COMM */

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

/**
 * @brief Initalizes S11 interface if in use
 */
static void
init_s11(void)
{
	//VG1
#if 0
	int ret;
	s11_mme_sockaddr.sin_port = htons(GTPC_UDP_PORT);
	s11_port = htons(GTPC_UDP_PORT);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s11_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (s11_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(s11_sgw_sockaddr.sin_zero,
			sizeof(s11_sgw_sockaddr.sin_zero));
	s11_sgw_sockaddr.sin_family = AF_INET;
	s11_sgw_sockaddr.sin_port = s11_port;
	s11_sgw_sockaddr.sin_addr = s11_sgw_ip;

	ret = bind(s11_fd, (struct sockaddr *) &s11_sgw_sockaddr,
			    sizeof(struct sockaddr_in));
	RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_s11()"
			"\n\ts11_fd= %d :: "
			"\n\ts11_sgw_ip= %s : s11_port= %d\n",
			s11_fd, inet_ntoa(s11_sgw_ip), ntohs(s11_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s11_sgw_sockaddr.sin_addr),
			ntohs(s11_sgw_sockaddr.sin_port),
			strerror(errno));
	}
#endif
}

/**
 * @brief Initalizes s5s8_sgwc interface if in use
 */
static void
init_s5s8_sgwc(void)
{
	//VG1
#if 0
	int ret;
	s5s8_sgwc_port = htons(GTPC_UDP_PORT);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s5s8_sgwc_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (s5s8_sgwc_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(s5s8_sgwc_sockaddr.sin_zero,
			sizeof(s5s8_sgwc_sockaddr.sin_zero));
	s5s8_sgwc_sockaddr.sin_family = AF_INET;
	s5s8_sgwc_sockaddr.sin_port = s5s8_sgwc_port;
	s5s8_sgwc_sockaddr.sin_addr = s5s8_sgwc_ip;

	ret = bind(s5s8_sgwc_fd, (struct sockaddr *) &s5s8_sgwc_sockaddr,
			    sizeof(struct sockaddr_in));
	RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_s5s8_sgwc()"
			"\n\ts5s8_sgwc_fd= %d :: "
			"\n\ts5s8_sgwc_ip= %s : s5s8_sgwc_port= %d\n",
			s5s8_sgwc_fd, inet_ntoa(s5s8_sgwc_ip),
			ntohs(s5s8_sgwc_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
			ntohs(s5s8_sgwc_sockaddr.sin_port),
			strerror(errno));
	}
	/* Initialize peer pgwc inteface for sendto(.., dest_addr) */
	s5s8_pgwc_port = htons(GTPC_UDP_PORT);
	bzero(s5s8_pgwc_sockaddr.sin_zero,
			sizeof(s5s8_pgwc_sockaddr.sin_zero));
	s5s8_pgwc_sockaddr.sin_family = AF_INET;
	s5s8_pgwc_sockaddr.sin_port = s5s8_pgwc_port;
	s5s8_pgwc_sockaddr.sin_addr = s5s8_pgwc_ip;
#endif
}

/**
 * @brief Initalizes s5s8_pgwc interface if in use
 */
static void
init_s5s8_pgwc(void)
{
#if 0
	int ret;
	s5s8_pgwc_port = htons(GTPC_UDP_PORT);

	if (pcap_reader != NULL && pcap_dumper != NULL)
		return;

	s5s8_pgwc_fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (s5s8_pgwc_fd < 0)
		rte_panic("Socket call error : %s", strerror(errno));

	bzero(s5s8_pgwc_sockaddr.sin_zero,
			sizeof(s5s8_pgwc_sockaddr.sin_zero));
	s5s8_pgwc_sockaddr.sin_family = AF_INET;
	s5s8_pgwc_sockaddr.sin_port = s5s8_pgwc_port;
	s5s8_pgwc_sockaddr.sin_addr = s5s8_pgwc_ip;

	ret = bind(s5s8_pgwc_fd, (struct sockaddr *) &s5s8_pgwc_sockaddr,
			    sizeof(struct sockaddr_in));
	RTE_LOG_DP(INFO, CP, "NGIC- main.c::init_s5s8_sgwc()"
			"\n\ts5s8_pgwc_fd= %d :: "
			"\n\ts5s8_pgwc_ip= %s : s5s8_pgwc_port= %d\n",
			s5s8_pgwc_fd, inet_ntoa(s5s8_pgwc_ip),
			ntohs(s5s8_pgwc_port));

	if (ret < 0) {
		rte_panic("Bind error for %s:%u - %s\n",
			inet_ntoa(s5s8_pgwc_sockaddr.sin_addr),
			ntohs(s5s8_pgwc_sockaddr.sin_port),
			strerror(errno));
	}
	/* Initialize peer sgwc inteface for sendto(.., dest_addr) */
	s5s8_sgwc_port = htons(GTPC_UDP_PORT);
	bzero(s5s8_sgwc_sockaddr.sin_zero,
			sizeof(s5s8_sgwc_sockaddr.sin_zero));
	s5s8_sgwc_sockaddr.sin_family = AF_INET;
	s5s8_sgwc_sockaddr.sin_port = s5s8_sgwc_port;
	s5s8_sgwc_sockaddr.sin_addr = s5s8_sgwc_ip;

#endif
}

/**
 * @brief
 * Initializes Control Plane data structures, packet filters, and calls for the
 * Data Plane to create required tables
 */
static void
init_cp(void)
{
	switch (spgw_cfg) {
	case SGWC:
		init_s11();
		init_s5s8_sgwc();
		break;
	case PGWC:
		init_s5s8_pgwc();
		break;
	case SAEGWC:
		init_s11();
		break;
	default:
		rte_panic("main.c::init_cp()-"
				"Unknown spgw_cfg= %u.", spgw_cfg);
		break;
	}

	iface_module_constructor();

	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");

#ifdef PFCP_COMM
#ifndef SDN_ODL_BUILD
#ifdef CP_DP_TABLE_CONFIG
	initialize_tables_on_dp();
#endif
	init_packet_filters();
	parse_adc_rules();
#endif
#endif

	create_ue_hash();
}

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
pfcp_gtpv2c_send(uint16_t gtpv2c_pyld_len, uint8_t *tx_buf,gtpv2c_header *gtpv2c_s11_rx)
{
	struct sockaddr_in dest_addr  =  {0};
	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
	dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr;
	printf("SENDING MSG [%d] FROM CP TO MME %d\n",gtpv2c_s11_rx->gtpc.type ,gtpv2c_pyld_len);

	gtpv2c_send(s11_sgwc_fd_arr[0],tx_buf,gtpv2c_pyld_len,
			(struct sockaddr *) &dest_addr,
			s11_mme_sockaddr_len);
	stats_update(gtpv2c_s11_rx->gtpc.type);
}


void
pfcp_s5s8_send(uint16_t gtpv2c_pyld_len, uint8_t *tx_buf, uint8_t msg_type)
{
	struct sockaddr_in dest_addr  =  {0};
	dest_addr.sin_family = AF_INET;

	stats_update(msg_type);

	if(pfcp_config.cp_type == SGWC) {

		dest_addr.sin_port = htons(pfcp_config.pgwc_s5s8_port[0]);
		dest_addr.sin_addr.s_addr = pfcp_config.pgwc_s5s8_ip[0].s_addr;

		printf("SENDING MSG FROM SGWC TO PGWC \n" );
		gtpv2c_send(s5s8_sgwc_fd_arr[0],tx_buf,gtpv2c_pyld_len,
				(struct sockaddr *) &dest_addr,
				s5s8_pgwc_sockaddr_len);
		s5s8_sgwc_msgcnt++;
		//cp_stats.sm_create_session_req_sent++;

	} else if (pfcp_config.cp_type == PGWC) {
		dest_addr.sin_port = htons(pfcp_config.sgwc_s5s8_port[0]);
		dest_addr.sin_addr.s_addr = pfcp_config.sgwc_s5s8_ip[0].s_addr;
		printf("SENDING MSG FROM PGWC TO SGWC \n" );

		gtpv2c_send(s5s8_pgwc_fd_arr[0],tx_buf,gtpv2c_pyld_len,
				(struct sockaddr *) &dest_addr,
				s5s8_sgwc_sockaddr_len);
		s5s8_pgwc_msgcnt++;
	}
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
		RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::gtpv2c_send()"
			"\n\tgtpv2c_if_fd= %d\n", gtpv2c_if_fd);

	if (bytes_tx != (int) gtpv2c_pyld_len) {
			fprintf(stderr, "Transmitted Incomplete GTPv2c Message:"
					"%u of %d tx bytes\n",
					gtpv2c_pyld_len, bytes_tx);
		}
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

	ih->dst_addr = s11_mme_ip.s_addr;
	ih->src_addr = s11_sgw_ip.s_addr;
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
#ifdef PFCP_COMM
		bytes_s5s8_rx = recvfrom(s5s8_sgwc_fd_arr[0], s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_sgwc_sockaddr_arr[0]  ,
				&s5s8_sgwc_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "SGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_sgwc_sockaddr_arr[0].sin_addr),
					s5s8_sgwc_sockaddr_arr[0].sin_port,
					strerror(errno));
		}
#else
		bytes_s5s8_rx = recvfrom(s5s8_sgwc_fd, s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_sgwc_sockaddr,
				&s5s8_sgwc_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "SGWC_s5s8 recvfrom error:"
					s5s8_sgwc_sockaddr.sin_port,
					strerror(errno));
		}
#endif
	}

	if (spgw_cfg == PGWC) {

#ifdef PFCP_COMM
		bytes_s5s8_rx = recvfrom(s5s8_pgwc_fd_arr[0], s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_sgwc_sockaddr,
				&s5s8_sgwc_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "PGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
					s5s8_sgwc_sockaddr.sin_port,
					strerror(errno));
		}
#else

		bytes_s5s8_rx = recvfrom(s5s8_pgwc_fd, s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_pgwc_sockaddr,
				&s5s8_pgwc_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "PGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
					s5s8_sgwc_sockaddr.sin_port,
					strerror(errno));
		}
#endif

	}

	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
		bytes_s11_rx = recvfrom(
#ifdef PFCP_COMM
				s11_sgwc_fd_arr[0],
#else
				s11_fd,
#endif
				s11_rx_buf,MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
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
			if (
				 ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) &&
				 (bytes_s11_rx > 0) &&
				 (
#ifdef PFCP_COMM
				  (s11_mme_sockaddr.sin_addr.s_addr != pfcp_config.mme_s11_ip[0].s_addr) ||
#else
				 (s11_mme_sockaddr.sin_addr.s_addr != s11_mme_ip.s_addr)||
#endif
				  (gtpv2c_s11_rx->gtpc.version != GTP_VERSION_GTPV2C)
				 )
				) {
				fprintf(stderr, "Discarding packet from %s:%u - "
						"Expected S11_MME_IP = %s\n",
						inet_ntoa(s11_mme_sockaddr.sin_addr),
						ntohs(s11_mme_sockaddr.sin_port),
#ifdef PFCP_COMM
						inet_ntoa(pfcp_config.mme_s11_ip[0])
#else
						inet_ntoa(s11_mme_ip)
#endif
						);
				return;
			} else if (

#ifdef PFCP_COMM
					((spgw_cfg == PGWC) && (bytes_s5s8_rx > 0)) &&
					(
					 (s5s8_sgwc_sockaddr_arr[0].sin_addr.s_addr !=
					  pfcp_config.sgwc_s5s8_ip[0].s_addr) ||
					 (gtpv2c_s5s8_rx->gtpc.version != GTP_VERSION_GTPV2C)
					)
				  ) {
				fprintf(stderr, "PFCP Discarding packet from %s:%u - "
						"Expected S5S8_SGWC_IP = %s\n",
						inet_ntoa(s5s8_sgwc_sockaddr_arr[0].sin_addr),
						ntohs(s5s8_sgwc_sockaddr_arr[0].sin_port),
						inet_ntoa(pfcp_config.sgwc_s5s8_ip[0]));
				return;
			}

#else

			((spgw_cfg == PGWC) && (bytes_s5s8_rx > 0)) &&
				(
				 (s5s8_sgwc_sockaddr.sin_addr.s_addr !=
				  s5s8_sgwc_ip.s_addr) ||
				 (gtpv2c_s5s8_rx->gtpc.version != GTP_VERSION_GTPV2C)
				)
				{

					fprintf(stderr, "Discarding packet from %s:%u - "
							"Expected S5S8_SGWC_IP = %s\n",
							inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
							ntohs(s5s8_sgwc_sockaddr.sin_port),
							inet_ntoa(s5s8_sgwc_ip)

				return;
	        }
#endif

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

				cp_stats.create_session_resp_acc_rcvd++;

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);

#ifdef PFCP_COMM
					struct sockaddr_in dest_addr  =  {0};
					dest_addr.sin_family = AF_INET;
					dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
					dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
					gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
							(struct sockaddr *) &dest_addr,
							s11_mme_sockaddr_len);
#else
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
#endif
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
				cp_stats.sm_delete_session_resp_acc_rcvd++;

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
#ifdef PFCP_COMM
					//struct sockaddr_in dest_addr  =  {0};
					dest_addr.sin_family = AF_INET;
					dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
					dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
					gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
							(struct sockaddr *) &dest_addr,
							s11_mme_sockaddr_len);
#else
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
#endif
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

				/* VS: Reset ECHO Timers */
				ret = process_response(s5s8_sgwc_sockaddr_arr[0].sin_addr.s_addr);
				if (ret) {
					/* VS:  TODO: Error handling not implemented */
				}

				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);
#ifdef PFCP_COMM
				pfcp_s5s8_send(payload_length, s5s8_tx_buf, GTP_ECHO_REQ);
				/*gtpv2c_send(s5s8_sgwc_fd_arr[0], s5s8_tx_buf, payload_length,
				*		(struct sockaddr *) &s5s8_pgwc_sockaddr_arr[0],
				*		s5s8_pgwc_sockaddr_len);
				*/

#endif /* PFCP_COMM */
				break;
			case GTP_ECHO_RSP:
				ret = process_response(s5s8_sgwc_sockaddr_arr[0].sin_addr.s_addr);
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
#ifdef PFCP_COMM
				create_session_request_t csr = {0};
				char sgwu_fqdn[MAX_HOSTNAME_LENGTH] = {0};

#ifdef USE_REST
				/* VS: Add a entry for SGW-C */
				if (s5s8_sgwc_sockaddr.sin_addr.s_addr != 0) {
					if ((add_node_conn_entry((uint32_t)s5s8_sgwc_sockaddr.sin_addr.s_addr,
									S5S8_PGWC_PORT_ID)) != 0) {
						RTE_LOG_DP(ERR, DP, "Failed to add connection entry for SGW-C\n");
					}
				}
#endif /* USE_REST */

				if (PFCP_ASSOC_ALREADY_ESTABLISHED ==
						process_pfcp_assoication_request(gtpv2c_s5s8_rx, &csr,
								sgwu_fqdn)) {
					ret = process_pgwc_s5s8_create_session_request(gtpv2c_s5s8_rx,
							gtpv2c_s5s8_tx);
				} else {
					return;
				}
#else
				ret = process_pgwc_s5s8_create_session_request(
					gtpv2c_s5s8_rx, gtpv2c_s5s8_tx);
#endif
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
						"\n\tgtpv2c_send :: s5s8_pgwc_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s5s8_pgwc_msgcnt, s5s8_pgwc_fd,
						inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
						s5s8_sgwc_sockaddr_len,
						ntohs(s5s8_sgwc_sockaddr.sin_port));
#ifndef ZMQ_COMM
#ifdef PFCP_COMM
				pfcp_s5s8_send(payload_length, s5s8_tx_buf, GTP_CREATE_SESSION_REQ);
#else
				gtpv2c_send(s5s8_pgwc_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_sgwc_sockaddr,
						s5s8_sgwc_sockaddr_len);
#endif /* PFCP_COMM */
#endif /* ZMQ_COMM */
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
						"\n\tgtpv2c_send :: s5s8_pgwc_fd= %d;"
						"\n\tdest_addr= %s : dest_addrln= %u;"
						"\n\tdest_port= %u\n",
						s5s8_pgwc_msgcnt, s5s8_pgwc_fd,
						inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
						s5s8_sgwc_sockaddr_len,
						ntohs(s5s8_sgwc_sockaddr.sin_port));
#ifndef ZMQ_COMM

#ifdef PFCP_COMM
				pfcp_s5s8_send(payload_length, s5s8_tx_buf, GTP_DELETE_SESSION_REQ);
#else
				gtpv2c_send(s5s8_pgwc_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_sgwc_sockaddr,
						s5s8_sgwc_sockaddr_len);
#endif /*PFCP_COMM*/

#endif /* ZMQ_COMM */
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

				/* VS: Reset ECHO Timers */
				ret = process_response(s5s8_sgwc_sockaddr.sin_addr.s_addr);
				if (ret) {
					/* VS:  TODO: Error handling not implemented */
				}

				payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
						+ sizeof(gtpv2c_s5s8_tx->gtpc);
#ifdef PFCP_COMM
				pfcp_s5s8_send(payload_length, s5s8_tx_buf, GTP_ECHO_REQ);
				/*gtpv2c_send(s5s8_pgwc_fd_arr[0], s5s8_tx_buf, payload_length,
				*		(struct sockaddr *) &s5s8_sgwc_sockaddr_arr[0],
				*		s5s8_sgwc_sockaddr_len);
				*/
#endif /* PFCP_COMM */
				break;
			case GTP_ECHO_RSP:
				RTE_LOG_DP(DEBUG, CP, "VS: Echo Response Received From SGWC\n");
				ret = process_response(s5s8_sgwc_sockaddr.sin_addr.s_addr);
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
		int ret = 0;
		if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
			switch (gtpv2c_s11_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ: {
#ifdef PFCP_COMM
				create_session_request_t csr = {0};
				char sgwu_fqdn[MAX_HOSTNAME_LENGTH] = {0};

#ifdef USE_REST
				/* VS: Add a entry for PGW-C */
				if (s5s8_pgwc_sockaddr_arr[0].sin_addr.s_addr != 0) {
					if ((add_node_conn_entry((uint32_t)s5s8_pgwc_sockaddr_arr[0].sin_addr.s_addr,
											S5S8_SGWC_PORT_ID)) != 0) {
						RTE_LOG_DP(ERR, DP, "Failed to add connection entry for PGW-C\n");
					}
				}
#endif /* USE_REST */

				if (PFCP_ASSOC_ALREADY_ESTABLISHED ==
						process_pfcp_assoication_request(gtpv2c_s11_rx, &csr,
								sgwu_fqdn)) {
					ret = process_pfcp_sess_est_request(gtpv2c_s11_rx,
							gtpv2c_s11_tx,gtpv2c_s5s8_tx, sgwu_fqdn);
				} else {
					return;
				}
#else
				ret = process_create_session_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx, gtpv2c_s5s8_tx);
#endif
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
#ifdef PFCP_COMM
					RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
							"\n\tcase GTP_CREATE_SESSION_REQ"
							"\n\ts5s8_sgwc_msgcnt= %ui;"
							"\n\tgtpv2c_send :: s5s8_sgwc_fd= %d;"
							"\n\tdest_addr= %s : dest_addrln= %u;"
							"\n\tdest_port= %u\n",
							s5s8_sgwc_msgcnt, s5s8_sgwc_fd_arr[0],
							inet_ntoa(s5s8_pgwc_sockaddr_arr[0].sin_addr),
							s5s8_pgwc_sockaddr_len,
							ntohs(s5s8_pgwc_sockaddr_arr[0].sin_port));

					gtpv2c_send(s5s8_sgwc_fd_arr[0], s5s8_tx_buf, payload_length,
							(struct sockaddr *) &s5s8_pgwc_sockaddr_arr[0],
							s5s8_pgwc_sockaddr_len);
							cp_stats.sm_create_session_req_sent++;
#else
					RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
							"\n\tcase GTP_CREATE_SESSION_REQ"
							"\n\ts5s8_sgwc_msgcnt= %ui;"
							"\n\tgtpv2c_send :: s5s8_sgwc_fd= %d;"
							"\n\tdest_addr= %s : dest_addrln= %u;"
							"\n\tdest_port= %u\n",
							s5s8_sgwc_msgcnt, s5s8_sgwc_fd,
							inet_ntoa(s5s8_pgwc_sockaddr.sin_addr),
							s5s8_pgwc_sockaddr_len,
							ntohs(s5s8_pgwc_sockaddr.sin_port));
					gtpv2c_send(s5s8_sgwc_fd, s5s8_tx_buf, payload_length,
							(struct sockaddr *) &s5s8_pgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
							cp_stats.sm_create_session_req_sent++;

#endif
					s5s8_sgwc_msgcnt++;
				}

#ifndef ZMQ_COMM
				if (spgw_cfg == SAEGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);
#ifdef PFCP_COMM
					struct sockaddr_in dest_addr  =  {0};
					dest_addr.sin_family = AF_INET;
					dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
					dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
					gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
							(struct sockaddr *) &dest_addr,
							s11_mme_sockaddr_len);
#else
					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
#endif
				}
#endif /* ZMQ_COMM */
				break;
			}

			case GTP_DELETE_SESSION_REQ:
#ifdef PFCP_COMM
				ret = process_pfcp_sess_del_request(gtpv2c_s11_rx,gtpv2c_s11_tx,gtpv2c_s5s8_tx);

#else
				ret = process_delete_session_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx, gtpv2c_s5s8_tx);
#endif
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
#ifdef PFCP_COMM
					pfcp_s5s8_send(payload_length, s5s8_tx_buf, GTP_DELETE_SESSION_REQ);
					cp_stats.sm_delete_session_req_sent++;
#else
					RTE_LOG_DP(DEBUG, CP, "NGIC- main.c::control_plane()::"
							"\n\tcase GTP_DELETE_SESSION_REQ"
							"\n\ts5s8_sgwc_msgcnt= %u;"
							"\n\tgtpv2c_send :: s5s8_sgwc_fd= %d;"
							"\n\tdest_addr= %s : dest_addrln= %u;"
							"\n\tdest_port= %u\n",
							s5s8_sgwc_msgcnt, s5s8_sgwc_fd,
							inet_ntoa(s5s8_pgwc_sockaddr.sin_addr),
							s5s8_pgwc_sockaddr_len,
							ntohs(s5s8_pgwc_sockaddr.sin_port));
					gtpv2c_send(s5s8_sgwc_fd, s5s8_tx_buf, payload_length,
							(struct sockaddr *) &s5s8_pgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
							cp_stats.sm_delete_session_req_sent++;
#endif
					s5s8_sgwc_msgcnt++;
				}

#ifndef ZMQ_COMM
				if (spgw_cfg == SAEGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);
#ifdef PFCP_COMM
					struct sockaddr_in dest_addr  =  {0};
					dest_addr.sin_family = AF_INET;
					dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
					dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
					gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
							(struct sockaddr *) &dest_addr,
							s11_mme_sockaddr_len);
#else
					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
#endif
				}
#endif /* ZMQ_COMM */
				break;

			case GTP_MODIFY_BEARER_REQ:
#ifdef PFCP_COMM
				ret = process_pfcp_sess_mod_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx);
#else
				ret = process_modify_bearer_request(
						gtpv2c_s11_rx, gtpv2c_s11_tx);
#endif
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
#ifndef ZMQ_COMM
				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
#ifdef PFCP_COMM
					struct sockaddr_in dest_addr  =  {0};
					dest_addr.sin_family = AF_INET;
					dest_addr.sin_port = htons(pfcp_config.mme_s11_port[0]);
					dest_addr.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
					gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
							(struct sockaddr *) &dest_addr,
							s11_mme_sockaddr_len);
#else
					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
#endif
#endif /* ZMQ_COMM */
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

				cp_stats.number_of_mme_health_req++;

#ifdef USE_REST
				/* VS: Reset ECHO Timers */
				//ret = process_echo_resp((uint32_t)pfcp_config.mme_s11_ip[0].s_addr);
				ret = process_response(s11_mme_sockaddr.sin_addr.s_addr);
				if (ret) {
					/* VS:  TODO: Error handling not implemented */
				}
#endif /* USE_REST */

				payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
						+ sizeof(gtpv2c_s11_tx->gtpc);
#ifdef PFCP_COMM
				/* VS: TODO: Need to remove this PART */
				struct sockaddr_in dest_addr_t  =  {0};
				dest_addr_t.sin_family = AF_INET;
				dest_addr_t.sin_port = htons(pfcp_config.mme_s11_port[0]);
				dest_addr_t.sin_addr.s_addr = pfcp_config.mme_s11_ip[0].s_addr ;
				gtpv2c_send(s11_sgwc_fd_arr[0], s11_tx_buf, payload_length,
						(struct sockaddr *) &dest_addr_t,
						s11_mme_sockaddr_len);
#else
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
#endif /* PFCP_COMM */
				cp_stats.number_of_sgwc_resp_to_mme_health_req++;
				break;
#ifdef USE_REST
			case GTP_ECHO_RSP:
				//printf("VS: Echo Response From MME\n");
				//ret = process_echo_resp((uint32_t)pfcp_config.mme_s11_ip[0].s_addr);
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
				if (spgw_cfg != SGWC) {
					cp_stats.delete_session++;
				}
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
				cp_stats.rel_access_bearer--;
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
				//cp_stats.create_session++;
				cp_stats.sm_create_session_req_rcvd++;
				break;
			case GTP_DELETE_SESSION_REQ:
				//cp_stats.delete_session++;
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

int
ddn_by_session_id(uint64_t session_id) {
	uint8_t tx_buf[MAX_GTPV2C_UDP_LEN] = { 0 };
	gtpv2c_header *gtpv2c_tx = (gtpv2c_header *) tx_buf;
	uint32_t sgw_s11_gtpc_teid = UE_SESS_ID(session_id);
	ue_context *context = NULL;
	static uint32_t ddn_sequence = 1;

	int ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
			(const void *) &sgw_s11_gtpc_teid,
			(void **) &context);

	if (ret < 0 || !context)
		return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;

	ret = create_downlink_data_notification(context,
			UE_BEAR_ID(session_id),
			ddn_sequence,
			gtpv2c_tx);

	if (ret)
		return ret;

	struct sockaddr_in mme_s11_sockaddr_in = {
		.sin_family = AF_INET,
		.sin_port = htons(GTPC_UDP_PORT),
		.sin_addr = context->s11_mme_gtpc_ipv4,
		.sin_zero = {0},
	};

	uint16_t payload_length = ntohs(gtpv2c_tx->gtpc.length)
			+ sizeof(gtpv2c_tx->gtpc);

	if (pcap_dumper) {
		dump_pcap(payload_length, tx_buf);
	} else {
		uint32_t bytes_tx = sendto(s11_fd, tx_buf, payload_length, 0,
		    (struct sockaddr *) &mme_s11_sockaddr_in,
		    sizeof(mme_s11_sockaddr_in));

		if (bytes_tx != (int) payload_length) {
			fprintf(stderr, "Transmitted Incomplete GTPv2c Message:"
					"%u of %u tx bytes\n",
					payload_length, bytes_tx);
		}
	}
	ddn_sequence += 2;
	++cp_stats.ddn;

	return 0;
}

#ifndef SDN_ODL_BUILD
/**
 * @brief callback to handle downlink data notification messages from the
 * data plane
 * @param msg_payload
 * message payload received by control plane from the data plane
 * @return
 * 0 inicates success, error otherwise
 */
#ifndef ZMQ_COMM
static int
cb_ddn(struct msgbuf *msg_payload)
#else
int
cb_ddn(uint64_t sess_id)
#endif  /* ZMQ_COMM */
{
#ifndef ZMQ_COMM
	int ret = ddn_by_session_id(msg_payload->msg_union.sess_entry.sess_id);
#else
	int ret = ddn_by_session_id(sess_id);
#endif  /* ZMQ_COMM */

	if (ret) {
		fprintf(stderr, "Error on DDN Handling %s: (%d) %s\n",
				gtp_type_str(ret), ret,
				(ret < 0 ? strerror(-ret) : cause_str(ret)));
	}
	return ret;
}

/**
 * @brief callback initated by nb listener thread
 * @param arg
 * unused
 * @return
 * never returns
 */
static int
listener(__rte_unused void *arg)
{
	iface_init_ipc_node();

#ifndef ZMQ_COMM
	iface_ipc_register_msg_cb(MSG_DDN, cb_ddn);
#endif  /* ZMQ_COMM*/

	while (1) {
#ifdef ZMQ_COMM
		iface_remove_que(COMM_ZMQ);
#else
		iface_process_ipc_msgs();
#endif /*ZMQ_COMM */
	}

	return 0;
}
#endif /* SDN_ODL_BUILD */

/**
 * @brief initializes the core assignments for various control plane threads
 */
static void
init_cp_params(void) {
	unsigned last_lcore = rte_get_master_lcore();

#ifndef SDN_ODL_BUILD
	cp_params.nb_core_id = rte_get_next_lcore(last_lcore, 1, 0);

	if (cp_params.nb_core_id == RTE_MAX_LCORE)
		rte_panic("Insufficient cores in coremask to "
				"spawn nb thread\n");
	last_lcore = cp_params.nb_core_id;
#endif

	cp_params.stats_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.stats_core_id == RTE_MAX_LCORE)
		fprintf(stderr, "Insufficient cores in coremask to "
				"spawn stats thread\n");
	last_lcore = cp_params.stats_core_id;

#ifdef SIMU_CP
	cp_params.simu_core_id = rte_get_next_lcore(last_lcore, 1, 0);
	if (cp_params.simu_core_id == RTE_MAX_LCORE)
		fprintf(stderr, "Insufficient cores in coremask to "
				"spawn stats thread\n");
	last_lcore = cp_params.simu_core_id;
#endif
}

#ifdef SYNC_STATS
/**
 * @brief Initializes the hash table used to account for statstics of req and resp time.
 */
static void
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

#ifdef ZMQ_COMM
/**
 * @brief Initializes the hash table used to account for NB messages by op_id
 */
static void
init_resp_op_id(void)
{
	struct rte_hash_parameters rte_hash_params = {
			.name = "resp_op_id_hash",
			.entries = OP_ID_HASH_SIZE,
			.key_len = sizeof(uint64_t),
			.hash_func = rte_hash_crc,
			.hash_func_init_val = 0,
			.socket_id = rte_socket_id(),
	};

	resp_op_id_hash = rte_hash_create(&rte_hash_params);
	if (!resp_op_id_hash) {
		rte_panic("%s hash create failed: %s (%u)\n",
				rte_hash_params.name,
		    rte_strerror(rte_errno), rte_errno);
	}
}

#endif

/**
 * Main function - initializes dpdk environment, parses command line arguments,
 * calls initialization function, and spawns stats and control plane function
 * @param argc
 *   number of arguments
 * @param argv
 *   array of c-string arguments
 * @return
 *   returns 0
 */
int
main(int argc, char **argv)
{
	int ret;

	start_time = current_ntp_timestamp();

#ifdef USE_REST
	/* VS: Set current component start/up time */
	up_time = current_ntp_timestamp();

	/* VS: Increment the restart counter value after starting control plane */
	rstCnt = update_rstCnt();

	cp_stats_execution_time = clock();

	printf("Control Plane rstCnt: %u\n", rstCnt);
	recovery_time_into_file(start_time);
#endif /* USE_REST */

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	parse_arg(argc - ret, argv + ret);

	/* pfcp changes start*/
	config_cp_ip_port(&pfcp_config);
	spgw_cfg = pfcp_config.cp_type;

	init_cp();
	init_cp_params();

#ifdef C3PO_OSS

	clSetOption(eCLOptLogFileName, "logs/cp.log");
	clSetOption(eCLOptStatFileName, "logs/cp_stat.log");
	clSetOption(eCLOptAuditFileName, "logs/cp_sys.log");

	clInit("sgwc");

	int s11logger = clAddLogger("s11");
	int s5s8logger = clAddLogger("s5s8");

	clAddRecentLogger("sgwc-001","cp",5);

	clStart();


	clLog(clSystemLog, eCLSeverityMinor, "sample [system] [Minor] log msg" );
	clLog(s11logger, eCLSeverityMajor, "sample [s11] [Major] log msg");
	clLog(s5s8logger, eCLSeverityCritical, "sample [s5s8] [critical] log msg");

	if (spgw_cfg == SGWC) {
		csSetName("SGWC");
		csInit(clGetStatsLogger(), get_stat_spgwc, 2, 5000);
	} else if(spgw_cfg == PGWC) {
	        csSetName("PGWC");
	csInit(clGetStatsLogger(), get_stat_pgwc, 2, 5000);
	} else {
	       csSetName("SPGWC");
		csInit(clGetStatsLogger(), get_stat_spgwc, 2, 5000);
	}


	//csInit(clGetStatsLogger(), get_stat, get_time_stat, 2, 5000);
	//csInit(clGetStatsLogger(), get_stat, 2, 5000);
	//csInit(clGetStatsLogger(), get_stat_spgwc, 2, 5000);

	if (spgw_cfg == SGWC || spgw_cfg == SAEGWC) {

	int Interface1 = csAddInterface("S11", "gtpv2");   //<----make it interface
	int peer1     = csAddPeer(Interface1, "true", inet_ntoa(pfcp_config.mme_s11_ip[0]));

	csAddLastactivity(Interface1, peer1, "2019-01-01T01:03:05");
	csAddHealth(Interface1, peer1, 5, 3, 0);
	csAddMessage(Interface1, peer1, "Create Session Request", "IN");
	csAddMessage(Interface1, peer1, "Modify Bearer Request", "IN");
	csAddMessage(Interface1, peer1, "Delete Session Request", "IN");

	csAddMessage(Interface1, peer1, "sgw-nbr-of-ues", "IN");
	//csAddMessage(Interface1, peer1, "sgw-nbr-of-connected-ues", "IN");
	//csAddMessage(Interface1, peer1, "nbr-of-suspended-ues", "IN");
	csAddMessage(Interface1, peer1, "sgw-nbr-of-pdn-connections", "IN");
	csAddMessage(Interface1, peer1, "sgw-nbr-of-bearers", "IN");
	//csAddMessage(Interface1, peer1, "sgw-nbr-of-active-bearers", "IN");
	//csAddMessage(Interface1, peer1, "sgw-nbr-of-idle-bearers", "IN");

	}

	int Interface2,peer2;

	if (spgw_cfg == SAEGWC) {
		Interface2 = csAddInterface("Sx", "PFCP");
		peer2 = csAddPeer(Interface2, "true", inet_ntoa(pfcp_config.sgwu_pfcp_ip[0]));
	} else if (spgw_cfg == SGWC) {
		 Interface2 = csAddInterface("Sxa", "PFCP");
		peer2 = csAddPeer(Interface2, "true", inet_ntoa(pfcp_config.sgwu_pfcp_ip[0]));
	} else {
		 Interface2 = csAddInterface("Sxb", "PFCP");
		peer2 = csAddPeer(Interface2, "true", inet_ntoa(pfcp_config.pgwu_pfcp_ip[0]));
	}

	//peer2 = csAddPeer(Interface2, "true", inet_ntoa(s1u_sgw_ip));

	csAddLastactivity(Interface2, peer2, "2019-01-01T01:03:05");
	csAddHealth(Interface2, peer2, 5, 3, 0);
	csAddMessage(Interface2, peer2, "session-establishment-req-sent", "OUT");
	csAddMessage(Interface2, peer2, "session-establishment-resp-acc-rcvd", "IN");
	csAddMessage(Interface2, peer2, "session-establishment-resp-rej-rcvd", "IN");


	csAddMessage(Interface2, peer2, "session-deletion-req-sent", "OUT");
	csAddMessage(Interface2, peer2, "session-deletion-resp-acc-rcvd", "IN");
	csAddMessage(Interface2, peer2, "session-deletion-resp-rej-rcvd", "IN");
	csAddMessage(Interface2, peer2, "association-setup-req-sent", "OUT");
	csAddMessage(Interface2, peer2, "association-setup-resp-acc-rcvd", "IN");
	csAddMessage(Interface2, peer2, "association-setup-resp-rej-rcvd", "IN");


	if (spgw_cfg != PGWC)
	{
		csAddMessage(Interface2, peer2, "session-modification-req-sent", "OUT");
		csAddMessage(Interface2, peer2, "session-modification-resp-acc-rcvd", "IN");
		csAddMessage(Interface2, peer2, "session-modification-resp-rej-rcvd", "IN");
	}



	if (spgw_cfg == SGWC){
		int Interface3 = csAddInterface("S5-S8", "gtpv2");
		int peer3 = csAddPeer(Interface3, "true", inet_ntoa(s5s8_pgwc_ip));

		csAddLastactivity(Interface3, peer3, "2019-01-01T01:03:05");
		csAddHealth(Interface3, peer3, 5, 3, 0);
		csAddMessage(Interface3, peer3, "sm-create-session-req-sent", "OUT"); //To be implemented.
		csAddMessage(Interface3, peer3, "sm-create-session-resp-acc-rcvd", "IN");
		csAddMessage(Interface3, peer3, "sm-create-session-resp-rej-rcvd", "IN");
		csAddMessage(Interface3, peer3, "sm-delete-session-req-sent", "OUT");
		csAddMessage(Interface3, peer3, "sm-delete-session-resp-acc-rcvd", "IN");
		csAddMessage(Interface3, peer3, "sm-delete-session-resp-rej-rcvd", "IN");
	} else if (spgw_cfg == PGWC ){
		int Interface3 = csAddInterface("S5-S8", "gtpv2");
		int peer3 = csAddPeer(Interface3, "true", inet_ntoa(s5s8_sgwc_ip));

		csAddLastactivity(Interface3, peer3, "2019-01-01T01:03:05");
		csAddHealth(Interface3, peer3, 5, 3, 0);
		csAddMessage(Interface3, peer3, "sm-create-session-req-rcvd", "OUT"); //To check req-rcvd
		csAddMessage(Interface3, peer3, "sm-delete-session-req-rcvd", "OUT"); //To check req-rcvd
		csAddMessage(Interface3, peer3, "sgw-nbr-of-ues", "IN");
		//csAddMessage(Interface2, peer2, "sm-create-session-resp-acc-rcvd", "IN");
		//csAddMessage(Interface2, peer2, "sm-create-session-resp-rej-rcvd", "IN");
	}

	/*int peer31 = csAddPeer(Interface3, "true", inet_ntoa(s5s8_pgwc_ip));
	csAddLastactivity(Interface3, peer31, "2019-01-01T01:03:05");
	csAddHealth(Interface3, peer31, 5, 3, 0);
	csAddMessage(Interface3, peer31, "p2first", "OUT");
	csAddMessage(Interface3, peer31, "p2second", "IN");

	int peer32 = csAddPeer(Interface3, "true", inet_ntoa(s5s8_pgwc_ip));
	csAddLastactivity(Interface3, peer32, "2019-01-01T01:03:05");
	csAddHealth(Interface3, peer32, 5, 3, 0);
	csAddMessage(Interface3, peer32, "p3first", "OUT");
	csAddMessage(Interface3, peer32, "p3second", "IN");*/

	csStart();

	init_rest_methods(12997, 1);

#endif   /*C3PO_OSS */


	pfcp_init_cp();
	create_heartbeat_hash_table();
	create_associated_upf_hash();

#ifdef SYNC_STATS
	stats_init();
	init_stats_hash();
#endif /* SYNC_STATS */

	if (cp_params.stats_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(do_stats, NULL, cp_params.stats_core_id);

#ifdef SIMU_CP
	if (cp_params.simu_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(simu_cp, NULL, cp_params.simu_core_id);
#endif
#ifdef SDN_ODL_BUILD
	init_nb();
	server();
#else
#ifdef ZMQ_COMM
	init_resp_op_id();
#endif  /* ZMQ_COMM */

	if (cp_params.nb_core_id != RTE_MAX_LCORE)
		rte_eal_remote_launch(listener, NULL, cp_params.nb_core_id);

#ifdef USE_REST

	/* VS: Create thread for handling for sending echo req to its peer node */
	rest_thread_init();

	if ((spgw_cfg == SGWC) || (spgw_cfg == SAEGWC)) {
		/* VS: Added default entry for MME */
		if ((add_node_conn_entry((uint32_t)pfcp_config.mme_s11_ip[0].s_addr, S11_SGW_PORT_ID)) != 0) {
			RTE_LOG_DP(ERR, DP, "Failed to add connection entry for MME");
		}
	}

#endif  /* USE_REST */

	while (1)
		control_plane();
#endif

	//TODO:VS:Move this call in appropriate place
	//clear_heartbeat_hash_table();
	return 0;
}

