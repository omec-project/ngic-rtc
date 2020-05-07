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

/*
 * NOTE: clLogger initalization happens after parsing of configuration file,
 *       thus clLog cannot be used here, instead printf is used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>

#include <rte_ethdev.h>
#include <rte_kni.h>

#include "gtpu.h"
#include "up_main.h"
#include "pipeline/epc_packet_framework.h"

/**
 * @brief  : prints the usage statement and quits with an error message
 * @param  : No param
 * @return : Returns nothing
 */
static inline void dp_print_usage(void)
{
	printf("\nDataplane supported command line arguments are:\n\n");

	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
#define ARGUMENT_WIDTH 17
#define PRESENCE_WIDTH 11
#define DESCRIPTION_WIDTH 42
	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "ARGUMENT",
			PRESENCE_WIDTH,    "PRESENCE",
			DESCRIPTION_WIDTH, "DESCRIPTION");
	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U GW IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U GW network mask of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s1u_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S1U port mac address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_sgwu_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_SGWU IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_sgwu_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_SGWU port mac address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgw_s5s8gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGW_S5S8GW IP address of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgw_s5s8gw_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGW_S5S8GW network mask of the SGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--pgw_s5s8gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "PGW_S5S8GW IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--pgw_s5s8gw_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "PGW_S5S8GW network mask of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_pgwu_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_PGWU IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--s5s8_pgwu_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "S5S8_PGWU port mac address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_gw_ip",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI GW IP address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_mask",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI GW network mask of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--sgi_mac",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH, "SGI port mac address of the PGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--num_workers",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH, "no. of worker instances.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--log",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"log level, 1- Notification, 2- Debug.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--cdr_path",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"CDR file path location.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--master_cdr",
			PRESENCE_WIDTH,    "OPTIONAL",
			DESCRIPTION_WIDTH,
			"CDR Master file.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--numa",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"numa 1- enable, 0- disable.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--spgw_cfg",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"spgw_cfg 01 - SGW, 02- PGW, 03- SPGW.");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--kni_portmask",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"Configured dpdk port mask");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--ul_iface",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"Configured UL interface name(i.e. S1U interface)");

	printf("| %-*s | %-*s | %-*s |\n",
			ARGUMENT_WIDTH,    "--dl_iface",
			PRESENCE_WIDTH,    "MANDATORY",
			DESCRIPTION_WIDTH,
			"Configured DL interface name(i.e SGI interface)");

	printf("+-------------------+-------------+"
			"--------------------------------------------+\n");
	printf("\n\nExample Usage:\n"
			"$ ./build/ngic_dataplane -c 0xfff -n 4 --\n"
			"--spgw_cfg 01\n"
			"--s1u_ip 11.1.1.100 --s1u_mac 90:e2:ba:58:c8:64\n"
			"--s5s8_sgwu_ip 12.3.1.93\n"
			"--s5s8_pgwu_ip 14.3.1.93\n"
			"--sgi_ip 13.1.1.93 --sgi_mac 90:e2:ba:58:c8:65\n"
			"--s1uc 0 --sgic 1\n"
			"--bal 2 --mct 3 --iface 4 --stats 3\n"
			"--num_workers 2 --numa 0 --log 1\n"
			"--spgw_cfg 3 --ul_iface S1Udev\n"
			"--dl_iface SGIdev --kni_portmask 3\n");
	exit(0);
}

/**
 * @brief  : parse ethernet address
 * @param  : hwaddr, structure to parsed ethernet address
 * @param  : str, input string
 * @return : Returns 0 in case of success , 1 otherwise
 */
static inline int parse_ether_addr(struct ether_addr *hwaddr, const char *str)
{
	/* 01 34 67 90 23 56 */
	/* XX:XX:XX:XX:XX:XX */
	if (strlen(str) != 17 ||
			!isxdigit(str[0]) ||
			!isxdigit(str[1]) ||
			str[2] != ':' ||
			!isxdigit(str[3]) ||
			!isxdigit(str[4]) ||
			str[5] != ':' ||
			!isxdigit(str[6]) ||
			!isxdigit(str[7]) ||
			str[8] != ':' ||
			!isxdigit(str[9]) ||
			!isxdigit(str[10]) ||
			str[11] != ':' ||
			!isxdigit(str[12]) ||
			!isxdigit(str[13]) ||
			str[14] != ':' ||
			!isxdigit(str[15]) ||
			!isxdigit(str[16])) {
		printf("invalid mac hardware address format->%s<-\n", str);
		return 0;
	}
	sscanf(str, "%02zx:%02zx:%02zx:%02zx:%02zx:%02zx",
			(size_t *) &hwaddr->addr_bytes[0],
			(size_t *) &hwaddr->addr_bytes[1],
			(size_t *) &hwaddr->addr_bytes[2],
			(size_t *) &hwaddr->addr_bytes[3],
			(size_t *) &hwaddr->addr_bytes[4],
			(size_t *) &hwaddr->addr_bytes[5]);
	return 1;
}

/**
 * @brief  : Set unused core
 * @param  : core
 * @param  : used_coremask
 * @return : Returns nothing
 */
static inline void set_unused_lcore(int *core, uint64_t *used_coremask)
{
	if (*core != -1) {
		if (!rte_lcore_is_enabled(*core))
			rte_panic("Invalid Core Assignment - "
					"core %u not in coremask", *core);
		return;
	}
	unsigned lcore;
	RTE_LCORE_FOREACH(lcore) {
		if ((1ULL << lcore) & *used_coremask)
			continue;
		*used_coremask |= (1ULL << lcore);
		*core = lcore;
		return;
	}
	rte_exit(EXIT_FAILURE, "No free core available - check coremask\n");
}

/**
 * @brief  : Function to parse command line config.
 * @param  : app, global app config structure.
 * @param  : argc, number of arguments.
 * @param  : argv, list of arguments.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static inline int
parse_config_args(struct app_params *app, int argc, char **argv)
{
	int opt;
	int option_index;
	int i;
	struct ether_addr mac_addr;
	uint64_t used_coremask = 0;
#ifndef SGX_CDR
	//const char *master_cdr_file = NULL;
#endif

	static struct option spgw_opts[] = {
		{"spgw_cfg",  required_argument, 0, 'h'},
		{"s1u_ip", required_argument, 0, 'i'},
		{"s1u_mac", required_argument, 0, 'm'},
		{"sgi_ip", required_argument, 0, 's'},
		{"sgi_mac", required_argument, 0, 'n'},
		{"s1u_gw_ip", required_argument, 0, 'o'},
		{"s1u_mask", required_argument, 0, 'q'},
		{"sgw_s5s8gw_ip", required_argument, 0, '1'},
		{"sgw_s5s8gw_mask", required_argument, 0, '2'},
		{"s5s8_sgwu_ip", required_argument, 0, 'v'},
		{"s5s8_sgwu_mac", required_argument, 0, 'j'},
		{"s5s8_pgwu_ip", required_argument, 0, 'r'},
		{"pgw_s5s8gw_ip", required_argument, 0, '3'},
		{"pgw_s5s8gw_mask", required_argument, 0, '4'},
		{"s5s8_pgwu_mac", required_argument, 0, 'k'},
		{"sgi_gw_ip", required_argument, 0, 'x'},
		{"sgi_mask", required_argument, 0, 'z'},
		{"log", required_argument, 0, 'l'},
		{"num_workers", required_argument, 0, 'w'},
		{"cdr_path", required_argument, 0, 'a'},
		{"master_cdr", required_argument, 0, 'e'},
		{"numa", required_argument, 0, 'f'},
		{"gtpu_seqnb_in",  required_argument, 0, 'I'},
		{"gtpu_seqnb_out",  required_argument, 0, 'O'},
		{"kni_portmask", required_argument, 0, 'p'},
		{"ul_iface", required_argument, 0, 'b'},
		{"dl_iface", required_argument, 0, 'c'},
		{"transmit_timer", required_argument, 0, 'T'},
		{"periodic_timer", required_argument, 0, 'P'},
		{"transmit_count", required_argument, 0, 'Q'},
		{"teidri", required_argument, 0, 'R'},
		{"dp_logger", required_argument, 0, 'L'},
		{NULL, 0, 0, 0}
	};

	optind = 0;/* reset getopt lib */

	while ((opt = getopt_long(argc, argv, "i:m:s:n:w:l:f:h:a:e:I:O:T:P:Q:R:L:",
					spgw_opts, &option_index)) != EOF) {
		switch (opt) {
		case 'h':
			app->spgw_cfg = atoi(optarg);
			break;

		/* s1u_ip address */
		case 'i':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_ip)) {
				printf("Invalid s1u interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_ip = 0;
				return -1;
			}
			printf("Parsed s1u ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s1u_ip)));
			break;

			/* s1u_mac address */
		case 'm':
			if (!parse_ether_addr(&app->s1u_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s1u_ether_addr, &mac_addr)) {
					printf("s1u port %d\n", i);
					app->s1u_port = i;
					break;
				}
			}
			break;

			/* sgi_ip address */
		case 's':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_ip)) {
				printf("invalid sgi interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_ip = 0;
				return -1;
			}
			printf("Parsed sgi ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->sgi_ip)));

			break;

			/* sgi_mac address */
		case 'n':
			if (!parse_ether_addr(&app->sgi_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->sgi_ether_addr, &mac_addr)) {
					printf("sgi port %d\n", i);
					app->sgi_port = i;
					break;
				}
			}
			break;

			/* s1u_gw_ip address */
		case 'o':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_gw_ip)) {
				printf("Invalid s1u gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_gw_ip = 0;
				return -1;
			}
			printf("Parsed s1u gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->s1u_gw_ip)));
			break;

			/* s1u_net address */
		case 'q':
			if (!inet_aton(optarg, (struct in_addr *)&app->s1u_mask)) {
				printf("Invalid s1u network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s1u_mask = 0;
				return -1;
			}
			printf("Parsed s1u network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->s1u_mask)));
			break;

			/* sgw_s5s8gw_ip address */
		case '1':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgw_s5s8gw_ip)) {
				printf("Invalid sgw s5s8 gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgw_s5s8gw_ip = 0;
				return -1;
			}
			printf("Parsed sgw s5s8gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgw_s5s8gw_ip)));
			break;

			/* sgw_s5s8gw_mask address */
		case '2':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgw_s5s8gw_mask)) {
				printf("Invalid sgw s5s8gw network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgw_s5s8gw_mask = 0;
				return -1;
			}
			printf("Parsed sgw s5s8 network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgw_s5s8gw_mask)));
			break;
		/* s5s8_sgwu_ip address */
		case 'v':
			if (!inet_aton(optarg, (struct in_addr *)&app->s5s8_sgwu_ip)) {
				printf("Invalid s5s8_sgwu interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s5s8_sgwu_ip = 0;
				return -1;
			}
			printf("Parsed s5s8_sgwu ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s5s8_sgwu_ip)));
			break;

			/* s5s8_sgwu_mac address */
		case 'j':
			if (!parse_ether_addr(&app->s5s8_sgwu_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s5s8_sgwu_ether_addr, &mac_addr)) {
					printf("s5s8_sgwu port %d\n", i);
					app->s5s8_sgwu_port = i;
					break;
				}
			}
			break;

		/* s5s8_pgwu_ip address */
		case 'r':
			if (!inet_aton(optarg, (struct in_addr *)&app->s5s8_pgwu_ip)) {
				printf("Invalid s5s8_pgwu interface ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->s5s8_pgwu_ip = 0;
				return -1;
			}
			printf("Parsed s5s8_pgwu ip: %s\n",
				inet_ntoa(*((struct in_addr *)&app->s5s8_pgwu_ip)));
			break;

			/* sgi_gw_ip address */
		case 'x':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_gw_ip)) {
				printf("Invalid sgi gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_gw_ip = 0;
				return -1;
			}
			printf("Parsed sgi gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgi_gw_ip)));
			break;

			/* sgi_net address */
		case 'z':
			if (!inet_aton(optarg, (struct in_addr *)&app->sgi_mask)) {
				printf("Invalid sgi network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->sgi_mask = 0;
				return -1;
			}
			printf("Parsed sgi network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->sgi_mask)));
			break;

			/* pgw_s5s8gw_ip address */
		case '3':
			if (!inet_aton(optarg, (struct in_addr *)&app->pgw_s5s8gw_ip)) {
				printf("Invalid pgw s5s8 gateway ip ->%s<-\n",
						optarg);
				dp_print_usage();
				app->pgw_s5s8gw_ip = 0;
				return -1;
			}
			printf("Parsed pgw s5s8gw ip: %s\n",
					inet_ntoa(*((struct in_addr *)&app->pgw_s5s8gw_ip)));
			break;

			/* pgw_s5s8gw_mask address */
		case '4':
			if (!inet_aton(optarg, (struct in_addr *)&app->pgw_s5s8gw_mask)) {
				printf("Invalid sgw s5s8gw network mask ->%s<-\n",
						optarg);
				dp_print_usage();
				app->pgw_s5s8gw_mask = 0;
				return -1;
			}
			printf("Parsed pgw s5s8 network mask: %s\n",
					inet_ntoa(*((struct in_addr *)&app->pgw_s5s8gw_mask)));
			break;
			/* s5s8_pgwu_mac address */
		case 'k':
			if (!parse_ether_addr(&app->s5s8_pgwu_ether_addr, optarg)) {
				dp_print_usage();
				return -1;
			}

			for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->s5s8_pgwu_ether_addr, &mac_addr)) {
					printf("s5s8_pgwu port %d\n", i);
					app->s5s8_pgwu_port = i;
					break;
				}
			}
			break;

		case 'l':
			app->log_level = atoi(optarg);
			break;

		case 'w':
			epc_app.num_workers = atoi(optarg);
			printf("Parsed num_workers:\t%u\n",
						epc_app.num_workers);
			break;

		case 'a':
			//set_cdr_path(optarg);
			break;

		case 'e':
#ifndef SGX_CDR
			//master_cdr_file = optarg;
#endif
			break;

		case 'f':
			app->numa_on = atoi(optarg);
			break;

		case 'I':
			app->gtpu_seqnb_in = atoi(optarg);
			break;

		case 'O':
			app->gtpu_seqnb_out = atoi(optarg);
			break;

			/* Dpdk ports mask */
		case 'p':
			app->ports_mask = atoi(optarg);
			break;

			/* Configure S1U interface name*/
		case 'b':
			memcpy(app->ul_iface_name, optarg, RTE_KNI_NAMESIZE);
			break;

			/* Configure SGI interface name*/
		case 'c':
			memcpy(app->dl_iface_name, optarg, RTE_KNI_NAMESIZE);
			break;

			/* Configure Transmit timer */
		case 'T':
			app->transmit_timer = atoi(optarg);
			break;

			/* Configure Periodic timer */
		case 'P':
			app->periodic_timer = atoi(optarg);
			break;

			/* Configure Transmit count */
		case 'Q':
			app->transmit_cnt = atoi(optarg);
			break;

			/* Configure TEIDRI val */
		case 'R':
			app->teidri_val = atoi(optarg);
			if( app->teidri_val < 0 || app->teidri_val > 7 ){
				printf("Invalid TEIDRI value %d. Please configure TEIDRI value between 0 to 7\n",
						app->teidri_val);
				dp_print_usage();
				app->teidri_val = 0;
				return -1;
			}
			break;
		case 'L':
			app->dp_logger = atoi(optarg);
			break;
		default:
			dp_print_usage();
			return -1;
		}		/* end switch (opt) */
	}			/* end while() */

#ifndef SGX_CDR
	//set_master_cdr_file(master_cdr_file);
#endif /* SGX_CDR */

	set_unused_lcore(&epc_app.core_mct, &used_coremask);
	set_unused_lcore(&epc_app.core_iface, &used_coremask);
#ifdef NGCORE_SHRINK
	set_unused_lcore(&epc_app.core_ul[S1U_PORT_ID], &used_coremask);
	set_unused_lcore(&epc_app.core_dl[SGI_PORT_ID], &used_coremask);
#else
#ifdef STATS
	set_unused_lcore(&epc_app.core_stats, &used_coremask);
#endif
	set_unused_lcore(&epc_app.core_spns_dns, &used_coremask);
	set_unused_lcore(&epc_app.core_rx[S1U_PORT_ID], &used_coremask);
	epc_app.core_tx[S1U_PORT_ID] = epc_app.core_rx[S1U_PORT_ID];
	set_unused_lcore(&epc_app.core_rx[SGI_PORT_ID], &used_coremask);
	epc_app.core_tx[SGI_PORT_ID] = epc_app.core_rx[SGI_PORT_ID];
	set_unused_lcore(&epc_app.core_load_balance, &used_coremask);

	for (i = 0; i < epc_app.num_workers; ++i) {
		epc_app.worker_cores[i] = -1;
		set_unused_lcore(&epc_app.worker_cores[i], &used_coremask);
	}
#endif	/* NGCORE_SHRINK */

	app->s1u_net = app->s1u_ip & app->s1u_mask;
	app->s1u_bcast_addr = app->s1u_ip | ~(app->s1u_mask);
	RTE_LOG(NOTICE, DP, "DP Config:%s::"
			"\n\tDP: S1U IP:\t\t%s;\n\t",
			__func__,
			inet_ntoa(*(struct in_addr *)&app->s1u_ip));
	RTE_LOG(NOTICE, DP, "S1U NET:\t\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->s1u_net));
	RTE_LOG(NOTICE, DP, "S1U MASK:\t\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->s1u_mask));
	RTE_LOG(NOTICE, DP, "S1U BCAST ADDR:\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->s1u_bcast_addr));
	RTE_LOG(NOTICE, DP, "S1U GW IP:\t\t%s\n",
			inet_ntoa(*(struct in_addr *)&app->s1u_gw_ip));

	app->sgw_s5s8gw_net = app->sgw_s5s8gw_ip & app->sgw_s5s8gw_mask;
	app->pgw_s5s8gw_net = app->pgw_s5s8gw_ip & app->pgw_s5s8gw_mask;

	app->sgi_net = app->sgi_ip & app->sgi_mask;
	app->sgi_bcast_addr = app->sgi_ip | ~(app->sgi_mask);
	RTE_LOG(NOTICE, DP, "DP Config:%s::"
			"\n\tDP: SGI IP:\t\t%s;\n\t",
			__func__,
			inet_ntoa(*(struct in_addr *)&app->sgi_ip));
	RTE_LOG(NOTICE, DP, "SGI NET:\t\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->sgi_net));
	RTE_LOG(NOTICE, DP, "SGI MASK:\t\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->sgi_mask));
	RTE_LOG(NOTICE, DP, "SGI BCAST ADDR:\t%s;\n\t",
			inet_ntoa(*(struct in_addr *)&app->sgi_bcast_addr));
	RTE_LOG(NOTICE, DP, "SGI GW IP:\t\t%s\n",
			inet_ntoa(*(struct in_addr *)&app->sgi_gw_ip));


	RTE_LOG(NOTICE, DP, "TEIDRI :  %d\n",app->teidri_val);
	RTE_LOG(NOTICE, DP, "DP_LOGGER :  %d\n",app->dp_logger);
	return 0;
}

void dp_init(int argc, char **argv)
{
	if (parse_config_args(&app, argc, argv) < 0)
		rte_exit(EXIT_FAILURE, "Error: Config parse fail !!!\n");
	switch (app.gtpu_seqnb_in)
	{
		case 1: /* include sequence number */
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_with_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_with_seqnb;
			fp_decap_gtpu_hdr = decap_gtpu_hdr_with_seqnb;
			break;
		}
		case 2: /* sequence number not included */
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_without_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_without_seqnb;
			fp_decap_gtpu_hdr = decap_gtpu_hdr_without_seqnb;
			break;
		}
		case 0: /* dynamic */
		default:
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_dynamic_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_dynamic_seqnb;
			fp_decap_gtpu_hdr = decap_gtpu_hdr_dynamic_seqnb;
			break;
		}
	}

	switch (app.gtpu_seqnb_out)
	{
		case 1: /* include sequence number */
		{
			fp_encap_gtpu_hdr = encap_gtpu_hdr_with_seqnb;
			break;
		}
		case 0: /* don't include sequence number */
		default:
		{
			fp_encap_gtpu_hdr = encap_gtpu_hdr_without_seqnb;
			break;
		}
	}
}
