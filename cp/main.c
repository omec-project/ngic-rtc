/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2019 Intel Corporation
 */

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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

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

#include "gtpv2c.h"
#include "gtpv2c_ie.h"
#include "debug_str.h"
#include "interface.h"
#include "packet_filters.h"
#include "dp_ipc_api.h"
#include "cp.h"
#include "cp_stats.h"
#include "cp_config.h"

#ifdef ZMQ_COMM
#include "gtpv2c_set_ie.h"
#ifdef MULTI_UPFS
#include "interface.h"
#include "zmq_push_pull.h"
#endif /* MULTI_UPFS */
#endif  /* ZMQ_COMM */

#ifdef SDN_ODL_BUILD
#include "nb.h"
#endif

#define PCAP_TTL                     (64)
#define PCAP_VIHL                    (0x0045)

#define SGW_CONFIG_SET			(0x0001)
#define S11_SGW_IP_SET			(0x0002)
#define S5S8_SGWC_IP_SET		(0x0004)
#define S5S8_PGWC_IP_SET		(0x0008)
#define S1U_SGW_IP_SET			(0x0010)
#define S5S8_SGWU_IP_SET		(0x0020)
#define S5S8_PGWU_IP_SET		(0x0040)
#define IP_POOL_IP_SET			(0x0080)
#define IP_POOL_MASK_SET		(0x0100)
#define APN_NAME_SET			(0x0200)
#define LOG_LEVEL_SET			(0x0300)

#define REQ_ARGS				(SGW_CONFIG_SET | \
								S11_SGW_IP_SET | \
								S1U_SGW_IP_SET | IP_POOL_IP_SET | \
								IP_POOL_MASK_SET | APN_NAME_SET | \
								LOG_LEVEL_SET)

#ifdef ZMQ_COMM
#define OP_ID_HASH_SIZE     (1 << 18)

struct rte_hash *resp_op_id_hash;

#endif  /* ZMQ_COMM */

enum cp_config spgw_cfg;
int s11_fd = -1;
int s11_pcap_fd = -1;
int s5s8_sgwc_fd = -1;
int s5s8_pgwc_fd = -1;
char *config_update_base_folder = NULL;
bool native_config_folder = false;

/* We should move all the config inside this structure eventually 
 * config is scattered all across the place as of now 
 */
struct app_config *appl_config = NULL;

pcap_dumper_t *pcap_dumper;
pcap_t *pcap_reader;

struct cp_params cp_params;
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

#define SLEEP_SEC 5
#define NUM_RETRIES 10

/**
 * Parses c-string containing dotted decimal ipv4 or hostname and stores the
 *   value within the in_addr type
 *
 * @param optarg
 *   c-string containing dotted decimal ipv4 address or hostname
 * @param addr
 *   destination of parsed IP string
 */
void
parse_arg_host(const char *optarg, struct in_addr *addr)
{
	int ret = -1, retries = NUM_RETRIES;
	struct addrinfo hints, *servinfo;
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET;

	/*NUM_RETRIES with SLEEP_SEC in between to resolve the name*/
  while(retries-- > 0 && (ret = getaddrinfo(optarg, NULL, &hints, &servinfo) !=0)){
			RTE_LOG(ERR, CP, "Unable to resolve %s. Retrying in %d sec\n",
						optarg, SLEEP_SEC);
			sleep(SLEEP_SEC);
  }

	if(ret)
			rte_exit(EXIT_FAILURE, "Unable to resolve %s. Exiting\n", optarg);

  struct sockaddr_in *h = (struct sockaddr_in *) servinfo->ai_addr;
  memcpy(addr, &h->sin_addr, sizeof(struct in_addr));
  freeaddrinfo(servinfo);
}

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
	int apnidx = 0;

	const struct option long_options[] = {
	  {"spgw_cfg",  required_argument, NULL, 'd'},
	  {"s11_sgw_ip",  required_argument, NULL, 's'},
	  {"s5s8_sgwc_ip", optional_argument, NULL, 'r'},
	  {"s5s8_pgwc_ip",  optional_argument, NULL, 'g'},
	  {"s1u_sgw_ip",  required_argument, NULL, 'w'},
	  {"s5s8_sgwu_ip",  optional_argument, NULL, 'v'},
	  {"s5s8_pgwu_ip",  optional_argument, NULL, 'u'},
	  {"ip_pool_ip",  required_argument, NULL, 'i'},
	  {"ip_pool_mask", required_argument, NULL, 'p'},
	  {"apn_name",   required_argument, NULL, 'a'},
	  {"log_level",   required_argument, NULL, 'l'},
	  {"pcap_file_in", required_argument, NULL, 'x'},
	  {"pcap_file_out", required_argument, NULL, 'y'},
	  {"static_pool", optional_argument, NULL, 'h'},
	  {"config_update_base_folder",optional_argument, NULL, 'f'},
	  {0, 0, 0, 0}
	};

	do {
		int option_index = 0;

		c = getopt_long(argc, argv, "d:m:s:r:g:w:v:u:i:p:a:l:x:y:h:f:", long_options,
		    &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'd':
			spgw_cfg = (uint8_t)atoi(optarg);
			args_set |= SGW_CONFIG_SET;
			break;
		case 's':
			parse_arg_host(optarg, &s11_sgw_ip);
			args_set |= S11_SGW_IP_SET;
			break;
		case 'r':
			parse_arg_host(optarg, &s5s8_sgwc_ip);
			args_set |= S5S8_SGWC_IP_SET;
			break;
		case 'g':
			parse_arg_host(optarg, &s5s8_pgwc_ip);
			args_set |= S5S8_PGWC_IP_SET;
			break;
		case 'w':
			parse_arg_host(optarg, &s1u_sgw_ip);
			args_set |= IP_POOL_MASK_SET;
			break;
		case 'v':
			parse_arg_host(optarg, &s5s8_sgwu_ip);
			args_set |= S5S8_SGWU_IP_SET;
			break;
		case 'u':
			parse_arg_host(optarg, &s5s8_pgwu_ip);
			args_set |= S5S8_PGWU_IP_SET;
			break;
		case 'i':
			set_ip_pool_ip(optarg);
			args_set |= S1U_SGW_IP_SET;
			break;
		case 'p':
			set_ip_pool_mask(optarg);
			args_set |= IP_POOL_IP_SET;
			break;
		case 'a':
			if (apnidx < MAX_NB_DPN) {
				set_apn_name(&apn_list[apnidx++], optarg);
				args_set |= APN_NAME_SET;
			}
			break;
		case 'l':
			set_log_level((uint8_t)atoi(optarg));
			args_set |= LOG_LEVEL_SET;
			break;
		case 'x':
			pcap_reader = pcap_open_offline(optarg, errbuff);
			break;
		case 'y':
			pcap = pcap_open_dead(DLT_EN10MB, UINT16_MAX);
			pcap_dumper = pcap_dump_open(pcap, optarg);
			s11_pcap_fd = pcap_fileno(pcap);
			break;
		case 'h':
			{
#ifndef MULTI_UPFS
				char *pool = parse_create_static_ip_pool(&static_addr_pool, optarg);
				if (pool != NULL)
					RTE_LOG_DP(ERR, CP, "STATIC_IP_POOL configured %s \n", pool);
#else
				RTE_LOG_DP(ERR, CP, "STATIC_IP_POOL is for multi upf case should be provided in app_config.cfg \n");
#endif
			}
			break;
		case 'f':
			config_update_base_folder = calloc(1, 128);
			if (config_update_base_folder == NULL)
				rte_panic("Unable to allocate memory for config_update_base_folder var!\n");
			strcpy(config_update_base_folder, optarg);
			break;
		default:
			rte_panic("Unknown argument - %s.", argv[optind]);
			break;
		}
	} while (c != -1);

	/* Lets put default values if some configuration is missing */
	if (config_update_base_folder == NULL) {
		config_update_base_folder = (char *) calloc(1, 128);
		if (config_update_base_folder == NULL)
			rte_panic("Unable to allocate memory for config_update_base_folder!\n");
		strcpy(config_update_base_folder, CONFIG_FOLDER);
		native_config_folder = true;
	}

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

/* TODO : we should get dp_id as argument. CP_DP_TABLE_CONFIG is never enabled */
/* XXX: need to figure out whether this can be deleted */
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
}

/**
 * @brief Initalizes s5s8_sgwc interface if in use
 */
static void
init_s5s8_sgwc(void)
{
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
}

/**
 * @brief Initalizes s5s8_pgwc interface if in use
 */
static void
init_s5s8_pgwc(void)
{
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
	case SPGWC:
		init_s11();
		break;
	default:
		rte_panic("main.c::init_cp()-"
				"Unknown spgw_cfg= %u.", spgw_cfg);
		break;
	}

	iface_module_constructor();

#if defined (ZMQ_COMM) && defined (MULTI_UPFS)
	init_dp_sock();
#endif
	if (signal(SIGINT, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGINT\n");
	if (signal(SIGSEGV, sig_handler) == SIG_ERR)
		rte_exit(EXIT_FAILURE, "Error:can't catch SIGSEGV\n");

#ifndef SDN_ODL_BUILD
#ifdef CP_DP_TABLE_CONFIG
	initialize_tables_on_dp();
#endif
	init_packet_filters();
	parse_adc_rules();
#endif

	appl_config = (struct app_config *) calloc(1, sizeof(struct app_config));
	if (appl_config == NULL) {
		rte_exit(EXIT_FAILURE, "Can't allocate memory for appl_config!\n");
	}

	/* Parse initial configuration file */
	init_spgwc_dynamic_config(appl_config);

	/* Lets register config change hook */
	char file[128] = {'\0'};
	strcat(file, config_update_base_folder);
	strcat(file, "app_config.cfg");
	RTE_LOG_DP(DEBUG, CP, "Config file to monitor %s ", file);
	register_config_updates(file);

	create_ue_hash();
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
		dump_pcap(gtpv2c_pyld_len, gtpv2c_tx_buf, dest_addr);
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
dump_pcap(uint16_t payload_length, uint8_t *tx_buf, struct sockaddr *dest_addr)
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

	struct sockaddr_in *mme_addr = (struct sockaddr_in *)dest_addr;
	ih->dst_addr = mme_addr->sin_addr.s_addr;
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

	socklen_t s11_mme_sockaddr_len = sizeof(s11_mme_sockaddr);
	socklen_t s5s8_sgwc_sockaddr_len = sizeof(s5s8_sgwc_sockaddr);
	socklen_t s5s8_pgwc_sockaddr_len = sizeof(s5s8_pgwc_sockaddr);
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
	static uint8_t s5s8_sgwc_msgcnt = 0;
	static uint8_t s5s8_pgwc_msgcnt = 0;
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
		bytes_s5s8_rx = recvfrom(s5s8_sgwc_fd, s5s8_rx_buf,
				MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
				(struct sockaddr *) &s5s8_sgwc_sockaddr,
				&s5s8_sgwc_sockaddr_len);
		if (bytes_s5s8_rx == 0) {
			fprintf(stderr, "SGWC_s5s8 recvfrom error:"
					"\n\ton %s:%u - %s\n",
					inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
					s5s8_sgwc_sockaddr.sin_port,
					strerror(errno));
		}
	}
	if (spgw_cfg == PGWC) {
		bytes_s5s8_rx = recvfrom(s5s8_pgwc_fd, s5s8_rx_buf,
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
	}
	if ((spgw_cfg == SGWC) || (spgw_cfg == SPGWC)) {
			bytes_s11_rx = recvfrom(s11_fd, s11_rx_buf,
					MAX_GTPV2C_UDP_LEN, MSG_DONTWAIT,
					(struct sockaddr *) &s11_mme_sockaddr,
					&s11_mme_sockaddr_len);
		if (bytes_s11_rx == 0) {
			fprintf(stderr, "SGWC|SPGWC_s11 recvfrom error:"
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
	if ((spgw_cfg == SGWC) || (spgw_cfg == SPGWC)) {
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
			fprintf(stderr, "SGWC|SPGWC_s11 Received UDP Payload:"
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
				 ((spgw_cfg == SGWC) || (spgw_cfg == SPGWC)) &&
				 (bytes_s11_rx > 0) &&
				 (
				  (gtpv2c_s11_rx->gtpc.version != GTP_VERSION_GTPV2C)
				 )
				) {
				fprintf(stderr, "Discarding packet from %s:%u - "
						"Expected GTPv2 packet but received gtp version  = %d\n",
						inet_ntoa(s11_mme_sockaddr.sin_addr),
						ntohs(s11_mme_sockaddr.sin_port),
						gtpv2c_s11_rx->gtpc.version);
				return;
			} else if (
						 ((spgw_cfg == PGWC) && (bytes_s5s8_rx > 0)) &&
						 (
						  (s5s8_sgwc_sockaddr.sin_addr.s_addr !=
							 s5s8_sgwc_ip.s_addr) ||
						  (gtpv2c_s5s8_rx->gtpc.version != GTP_VERSION_GTPV2C)
						 )
					) {
				fprintf(stderr, "Discarding packet from %s:%u - "
						"Expected S5S8_SGWC_IP = %s\n",
						inet_ntoa(s5s8_sgwc_sockaddr.sin_addr),
						ntohs(s5s8_sgwc_sockaddr.sin_port),
						inet_ntoa(s5s8_sgwc_ip));
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
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC:"
							"\n\tprocess_sgwc_s5s8_create_session_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

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
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC:"
							"\n\tprocess_sgwc_s5s8_delete_session_response "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s5s8_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}

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
			case GTP_CREATE_SESSION_REQ:
				ret = process_pgwc_s5s8_create_session_request(
					gtpv2c_s5s8_rx, gtpv2c_s5s8_tx);
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
				gtpv2c_send(s5s8_pgwc_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_sgwc_sockaddr,
						s5s8_sgwc_sockaddr_len);
#endif	/* ZMQ_COMM */
				s5s8_pgwc_msgcnt++;
				break;
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
				gtpv2c_send(s5s8_pgwc_fd, s5s8_tx_buf, payload_length,
						(struct sockaddr *) &s5s8_sgwc_sockaddr,
						s5s8_sgwc_sockaddr_len);
#endif	/* ZMQ_COMM */
				s5s8_pgwc_msgcnt++;
				break;
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
		if ((spgw_cfg == SGWC) || (spgw_cfg == SPGWC)) {
			switch (gtpv2c_s11_rx->gtpc.type) {
			case GTP_CREATE_SESSION_REQ:
				ret = process_create_session_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx, gtpv2c_s5s8_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SGWC | SPGWC:"
							"\n\tprocess_create_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				if (spgw_cfg == SGWC) {
					/* Forward s11 create_session_request on s5s8 */
					payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
							+ sizeof(gtpv2c_s5s8_tx->gtpc);
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
					s5s8_sgwc_msgcnt++;
				}

#ifndef ZMQ_COMM
				if (spgw_cfg == SPGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);
					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
				}
#endif	/* ZMQ_COMM */
				break;

			case GTP_DELETE_SESSION_REQ:
				ret = process_delete_session_request(
					gtpv2c_s11_rx, gtpv2c_s11_tx, gtpv2c_s5s8_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SPGWC:"
							"\n\tprocess_delete_session_request "
							"%s: (%d) %s\n",
							gtp_type_str(gtpv2c_s11_rx->gtpc.type), ret,
							(ret < 0 ? strerror(-ret) : cause_str(ret)));
					/* Error handling not implemented */
					return;
				}
				if (spgw_cfg == SGWC) {
					/* Forward s11 delete_session_request on s5s8 */
					payload_length = ntohs(gtpv2c_s5s8_tx->gtpc.length)
							+ sizeof(gtpv2c_s5s8_tx->gtpc);
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
					s5s8_sgwc_msgcnt++;
				}

#ifndef ZMQ_COMM
				if (spgw_cfg == SPGWC) {
					payload_length = ntohs(gtpv2c_s11_tx->gtpc.length)
							+ sizeof(gtpv2c_s11_tx->gtpc);
					gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
				}
#endif	/* ZMQ_COMM */
				break;

			case GTP_MODIFY_BEARER_REQ:
				ret = process_modify_bearer_request(
						gtpv2c_s11_rx, gtpv2c_s11_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SPGWC:"
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
				gtpv2c_send(s11_fd, s11_tx_buf, payload_length,
						(struct sockaddr *) &s11_mme_sockaddr,
						s11_mme_sockaddr_len);
#endif	/* ZMQ_COMM */
				break;

			case GTP_RELEASE_ACCESS_BEARERS_REQ:
				ret = process_release_access_bearer_request(
						gtpv2c_s11_rx, gtpv2c_s11_tx);
				if (ret) {
					fprintf(stderr, "main.c::control_plane()::Error"
							"\n\tcase SPGWC:"
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
							"\n\tcase SPGWC:"
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
							"\n\tcase SPGWC:"
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
							"\n\tcase SPGWC:"
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
							"\n\tcase SPGWC:"
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
							"\n\tcase SGWC | SPGWC:"
							"\n\tprocess_echo_request "
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

			default:
				fprintf(stderr, "main.c::control_plane::process_msgs-"
						"\n\tcase: SPGWC::spgw_cfg= %d;"
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
	case SPGWC:
		if (bytes_s11_rx > 0) {
			switch (gtpv2c_s11_rx->gtpc.type) {
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
			case GTP_CREATE_BEARER_RSP:
				cp_stats.create_bearer++;
				return;
			case GTP_DELETE_BEARER_RSP:
				cp_stats.delete_bearer++;
				return;
			case GTP_DOWNLINK_DATA_NOTIFICATION_ACK:
				cp_stats.ddn_ack++;
				return;
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
				break;
			case GTP_DELETE_SESSION_REQ:
				cp_stats.delete_session++;
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
		dump_pcap(payload_length, tx_buf, (struct sockaddr *)&mme_s11_sockaddr_in);
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
#endif	/*ZMQ_COMM */
	}

	return 0;
}
#endif 	/* SDN_ODL_BUILD */

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
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");

	parse_arg(argc - ret, argv + ret);
	printf("spgw_cfg:  %d\n", spgw_cfg);
	printf("s11_sgw_ip:  %s\n", inet_ntoa(s11_sgw_ip));
	printf("s5s8_sgwc_ip:  %s\n", inet_ntoa(s5s8_sgwc_ip));
	printf("s5s8_pgwc_ip:  %s\n", inet_ntoa(s5s8_pgwc_ip));
	printf("s1u_sgw_ip:  %s\n", inet_ntoa(s1u_sgw_ip));
	printf("s5s8_sgwu_ip:  %s\n", inet_ntoa(s5s8_sgwu_ip));
	printf("s5s8_pgwu_ip:  %s\n", inet_ntoa(s5s8_pgwu_ip));

	init_cp_params();
	init_cp();

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

	while (1)
		control_plane();
#endif

	return 0;
}
