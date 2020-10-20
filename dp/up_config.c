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

/*
 * NOTE: clLogger initalization happens after parsing of configuration file,
 *       thus clLog cannot be used here, instead printf is used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_cfgfile.h>

#include "gtpu.h"
#include "up_main.h"
#include "teid_upf.h"
#include "pfcp_util.h"
#include "pipeline/epc_packet_framework.h"
#include "pfcp_up_sess.h"
#include "gw_adapter.h"

#define DECIMAL_BASE 10
#define IPv4_ADDRESS_LEN  16
#define TEIDRI_TIMEOUT_DEFAULT 600000
#define TEIDRI_VALUE_DEFAULT 3
#define STATIC_DP_FILE "../config/dp.cfg"
#define ENTRY_NAME_SIZE 64

#define IPv6_ADDRESS_LEN  16
#define IPv6_PREFIX_LEN   1

extern uint16_t dp_comm_port;
extern struct in_addr dp_comm_ip;
extern struct in6_addr dp_comm_ipv6;
extern uint8_t dp_comm_ip_type;
extern struct in_addr cp_comm_ip;
extern struct in6_addr cp_comm_ip_v6;
extern uint8_t cp_comm_ip_type;
extern uint16_t cp_comm_port;

static int
get_ipv6_address(char *str, char **addr, uint8_t *net)
{
	char *addr_t = NULL;
	char *net_t = NULL;

	/* Check the pointer to string is not NULL */
	if (str != NULL) {
		/* Point to IPv6 Address */
		addr_t = strtok(str, "/");
		/* Point to Prefix Length */
		net_t = strtok(NULL, "/");
		if (net_t == NULL) {
				fprintf(stderr, "ERROR: IPv6 Prefix Length is not Configured\n");
				return -1;
		}
	} else {
		return -1;
	}

	*addr = addr_t;
	*net = atoi(net_t);
	return 0;
}

int
isIPv6Present(struct in6_addr *ipv6_addr)
{
	int ret = 0;
	struct in6_addr tmp_addr = {0};
	ret = memcmp(ipv6_addr, &tmp_addr, sizeof(struct in6_addr));
	return ret;
}

int isMacPresent(struct ether_addr *hwaddr)
{
	int ret = 0;
	struct ether_addr tmp_hwaddr = {0};
	ret = memcmp(hwaddr, &tmp_hwaddr, sizeof(struct ether_addr));
	return ret;
}

/**
 * @brief  : parse ethernet address
 * @param  : hwaddr, structure to parsed ethernet address
 * @param  : str, input string
 * @return : Returns 0 in case of success , 1 otherwise
 */
static inline int
parse_ether_addr(struct ether_addr *hwaddr, const char *str, uint8_t intf_type)
{
	/* 01 34 67 90 23 56 */
	/* XX:XX:XX:XX:XX:XX */
	/*TODO : change strlen with strnlen with proper size (n)*/
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

	if (intf_type)
		fprintf(stderr, "DP: EB_MAC_ADDR: %s\n", str);
	else
		fprintf(stderr, "DP: WB_MAC_ADDR: %s\n", str);

	return 1;
}

/**
 * @brief  : Validate the Mandatory Parameters are Configured or Not
 * @param  : app, structure that holds dp parameter configurations
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
validate_mandatory_params(struct app_params *app)
{
	/* Check WB_IP Address or Mask is configured or not */
	if (!(((app->wb_ip) && (app->wb_mask))
				|| (isIPv6Present(&app->wb_ipv6)))) {
		fprintf(stderr, "ERROR: West Bound(WB_IP or WB_MASK) intf IPv4 and IPv6 Address"
				" or intf Mask not configured.\n");
		return -1;
	}

	/* Check WB_LI_IP Address or intf MASK or intf Name is configured or not */
	if (app->wb_li_ip) {
		if (!((app->wb_li_mask)
					&& (strncmp("", (const char *)app->wb_li_iface_name, ENTRY_NAME_SIZE)))) {
			fprintf(stderr, "ERROR: West Bound(WB_LI_MASK or WB_LI_IFACE)"
					" intf MASK or intf Name not configured.\n");
			return -1;
		}
	}

	/* Check EB_IP Address is configured or not */
	if (!(((app->eb_ip) && (app->eb_mask))
				|| (isIPv6Present(&app->eb_ipv6)))) {
		fprintf(stderr, "ERROR: East Bound(EB_IP or EB_MASK) intf IPv4 and IPv6 Address"
				" or intf Mask not configured.\n");
		return -1;
	}

	/* Check EB_LI_IPv4 Address or intf MASK or intf Name is configured or not */
	if (app->eb_li_ip) {
		if (!((app->eb_li_mask)
					&& (strncmp("", (const char *)app->eb_li_iface_name, ENTRY_NAME_SIZE)))) {
			fprintf(stderr, "ERROR: East Bound(EB_LI_IPv4_MASK or EB_LI_IFACE)"
					" intf MASK or intf Name not configured.\n");
			return -1;
		}
	}

	/* Check WB_MAC Address is configured or not */
	if (!isMacPresent(&app->wb_ether_addr)) {
		fprintf(stderr, "ERROR: West Bound(WB_MAC) intf MAC Address not configured.\n");
		return -1;
	}

	/* Check WB_IFACE Name is configured or not */
	if (!strncmp("", (const char *)app->wb_iface_name, ENTRY_NAME_SIZE)) {
		fprintf(stderr, "ERROR: West Bound(WB_IFACE) intf name not configured.\n");
		return -1;
	}

	/* Check EB_MAC Address is configured or not */
	if (!isMacPresent(&app->eb_ether_addr)) {
		fprintf(stderr, "ERROR: East Bound(EB_MAC) intf MAC Address not configured.\n");
		return -1;
	}

	/* Check EB_IFACE Address is configured or not */
	if (!strncmp("", (const char *)app->eb_iface_name, ENTRY_NAME_SIZE)) {
		fprintf(stderr, "ERROR: East Bound(EB_IFACE) intf name not configured.\n");
		return -1;
	}

	/* Check TEIDRI value is configured or not */
	if(app->teidri_val == -1){
		app->teidri_val = TEIDRI_VALUE_DEFAULT;
		fprintf(stderr, "TEIDRI value not configured, assigning default value TEIDRI : %d\n",
				TEIDRI_VALUE_DEFAULT);
		/* TODO: VISHAL: Need to pull changes from r_1.8 */
	}

	return 0;
}

static int8_t
parse_up_config_param(struct app_params *app)
{
	uint8_t inx = 0;
	struct ether_addr mac_addr = {0};
	int32_t num_global_entries = 0;
	char *endptr = NULL;
	long temp_val = 0;

	struct rte_cfgfile_entry *global_entries = NULL;

	struct rte_cfgfile *file = rte_cfgfile_load(STATIC_DP_FILE, 0);
	if (file == NULL) {
		rte_exit(EXIT_FAILURE, "Cannot load configuration file %s\n",
				STATIC_DP_FILE);
	}

	fprintf(stderr,
			"\n\n###############[Data-Plane Config Reading]################\n");
	fprintf(stderr,
			"DP: User-Plane Configuration Parsing from %s\n", STATIC_DP_FILE);

	/* Read GLOBAL seaction values and configure respective params. */
	num_global_entries = rte_cfgfile_section_num_entries(file, "GLOBAL");

	if (num_global_entries > 0) {
		global_entries = rte_malloc_socket(NULL,
				sizeof(struct rte_cfgfile_entry) *
				num_global_entries,
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	}

	if (global_entries == NULL) {
		rte_panic("Error configuring global entry of %s\n",
				STATIC_DP_FILE);
	}

	rte_cfgfile_section_entries(file, "GLOBAL", global_entries,
			num_global_entries);

	/* Initialize teidri value to -1, it will be used to verify if teidri
	 * is configured or not
	 */
	app->teidri_val = -1;

	/* Validate the Mandatory Parameters are Configured or Not */
	for (inx = 0; inx < num_global_entries; ++inx) {

		/* Select static user-plane mode from config file */
		if(strncmp("DP_CFG", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {

		} else if(strncmp("WB_IPv4", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S1U/S5S8 IP Address */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) IPv4 Address\n");
				app->wb_ip = 0;
				return -1;
			}
			app->wb_ip = ntohl(tmp.s_addr);
			app->wb_ip_type.ipv4 = PRESENT;

			/* Set the IP Type to dual connectivity */
			if (app->wb_ip_type.ipv4 && app->wb_ip_type.ipv6) {
				app->wb_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: WB_IPv4(S1U/S5S8) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_ip));

		} else if(strncmp("WB_IPv6", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			uint8_t net_t[IPv6_PREFIX_LEN] = {0};
			char *addr_t[IPV6_STR_LEN] = {NULL};

			/* Parse the IPv6 String and separate out address and prefix */
			if (get_ipv6_address(global_entries[inx].value, addr_t, net_t) < 0) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) IPv6 Address and Prefix Configuration.\n");
				return -1;
			}

			/* S1U/S5S8 IPV6 Address */
			if (!inet_pton(AF_INET6, *addr_t, &(app->wb_ipv6))) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) IPv6 Address\n");
				return -1;
			}

			/* Fill the prefix length */
			memcpy(&app->wb_ipv6_prefix_len, net_t, IPv6_PREFIX_LEN);

			app->wb_ip_type.ipv6 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->wb_ip_type.ipv4 && app->wb_ip_type.ipv6) {
				app->wb_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: WB_IPv6(S1U/S5S8) Addr/Prefix: %s/%u\n",
				global_entries[inx].value, app->wb_ipv6_prefix_len);

		} else if(strncmp("WB_LI_IPv4", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8-P West_Bound Logical interface Address */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid West_Bound(S5S8) Logical iface IPv4 Address\n");
				app->wb_li_ip = 0;
				return -1;
			}
			app->wb_li_ip = ntohl(tmp.s_addr);

			app->wb_li_ip_type.ipv4 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->wb_li_ip_type.ipv4 && app->wb_li_ip_type.ipv6) {
				app->wb_li_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: WB_LI_IPv4(West_Bound) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_li_ip));

		} else if(strncmp("WB_LI_IPv6", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			uint8_t net_t[IPv6_PREFIX_LEN] = {0};
			char *addr_t[IPV6_STR_LEN] = {NULL};

			/* Parse the IPv6 String and separate out address and prefix */
			if (get_ipv6_address(global_entries[inx].value, addr_t, net_t) < 0) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) Logical intf IPv6 Address and Prefix Configuration.\n");
				return -1;
			}

			/* S1U/S5S8 Logical IPV6 Address */
			if (!inet_pton(AF_INET6, *addr_t, &(app->wb_li_ipv6))) {
				fprintf(stderr, "Invalid West_LI_Bound(S1U/S5S8) Logical IPv6 Address\n");
				return -1;
			}

			/* Fill the prefix length */
			memcpy(&app->wb_li_ipv6_prefix_len, net_t, IPv6_PREFIX_LEN);

			app->wb_li_ip_type.ipv6 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->wb_li_ip_type.ipv4 && app->wb_li_ip_type.ipv6) {
				app->wb_li_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: WB_LI_IPv6(S1U/S5S8) Addr/Prefix: %s/%u\n",
				global_entries[inx].value, app->wb_li_ipv6_prefix_len);

		} else if(strncmp("EB_LI_IPv6", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			uint8_t net_t[IPv6_PREFIX_LEN] = {0};
			char *addr_t[IPV6_STR_LEN] = {NULL};

			/* Parse the IPv6 String and separate out address and prefix */
			if (get_ipv6_address(global_entries[inx].value, addr_t, net_t) < 0) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) Logical intf IPv6 Address and Prefix Configuration.\n");
				return -1;
			}

			/* S1U/S5S8 Logical IPV6 Address */
			if (!inet_pton(AF_INET6, *addr_t, &(app->eb_li_ipv6))) {
				fprintf(stderr, "Invalid East_LI_Bound(S5S8/SGI) Logical IPv6 Address\n");
				return -1;
			}

			/* Fill the prefix length */
			memcpy(&app->eb_li_ipv6_prefix_len, net_t, IPv6_PREFIX_LEN);

			app->eb_li_ip_type.ipv6 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->eb_li_ip_type.ipv4 && app->eb_li_ip_type.ipv6) {
				app->eb_li_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: EB_LI_IPv6(S5S8/SGI) Addr/Prefix: %s/%u\n",
				global_entries[inx].value, app->eb_li_ipv6_prefix_len);

		} else if(strncmp("EB_IPv4", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8/SGI IP Address */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) IPv4 Address\n");
				app->eb_ip = 0;
				return -1;
			}
			app->eb_ip = ntohl(tmp.s_addr);
			app->eb_ip_type.ipv4 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->eb_ip_type.ipv4 && app->eb_ip_type.ipv6) {
				app->eb_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: EB_IPv4(S5S8/SGI) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_ip));

		} else if(strncmp("EB_IPv6", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			uint8_t net_t[IPv6_PREFIX_LEN] = {0};
			char *addr_t[IPV6_STR_LEN] = {NULL};

			/* Parse the IPv6 String and separate out address and prefix */
			if (get_ipv6_address(global_entries[inx].value, addr_t, net_t) < 0) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) IPv6 Address and Prefix Configuration.\n");
				return -1;
			}

			/* S5S8/SGI IPV6 Address */
			if (!inet_pton(AF_INET6, *addr_t, &(app->eb_ipv6))) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) IPv6 Address\n");
				return -1;
			}

			/* Fill the prefix length */
			memcpy(&app->eb_ipv6_prefix_len, net_t, IPv6_PREFIX_LEN);

			app->eb_ip_type.ipv6 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->eb_ip_type.ipv4 && app->eb_ip_type.ipv6) {
				app->eb_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: EB_IPv6(S5S8/SGI) Addr/Prefix: %s/%u\n",
				global_entries[inx].value, app->eb_ipv6_prefix_len);

		} else if(strncmp("EB_LI_IPv4", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8-S IP Address */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid East_Bound(S5S8) Logical iface IP Address\n");
				app->eb_li_ip = 0;
				return -1;
			}
			app->eb_li_ip = ntohl(tmp.s_addr);

			app->eb_li_ip_type.ipv4 = PRESENT;
			/* Set the IP Type to dual connectivity */
			if (app->eb_li_ip_type.ipv4 && app->eb_li_ip_type.ipv6) {
				app->eb_li_ip_type.ipv4_ipv6 = PRESENT;
			}

			fprintf(stderr, "DP: EB_LI_IPv4(S5S8) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_li_ip));

		} else if(strncmp("WB_GW_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* Configured GW IP for Routing */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) Gateway IP Address\n");
				app->wb_gw_ip = 0;
				return -1;
			}
			app->wb_gw_ip = ntohl(tmp.s_addr);

			fprintf(stderr, "DP: WB_GW_IP(S1U/S5S8) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_gw_ip));
		} else if(strncmp("EB_GW_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* Configured GW IP for Routing */
			struct in_addr tmp = {0};
			if (!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) Gateway IP Address\n");
				app->eb_gw_ip = 0;
				return -1;
			}
			app->eb_gw_ip = tmp.s_addr;

			fprintf(stderr, "DP: EB_GW_IP(S5S8/SGI) Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_gw_ip));
		} else if(strncmp("PFCP_IPv4", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* Configured PFCP IP Address  */
			if (!inet_aton(global_entries[inx].value, &(dp_comm_ip))) {
				fprintf(stderr, "Invalid DP PFCP IPv4 Address\n");
				dp_comm_ip.s_addr = 0;
				return -1;
			}

			strncpy(CDR_FILE_PATH, "logs/", CDR_BUFF_SIZE);
			strncat(CDR_FILE_PATH, inet_ntoa(dp_comm_ip), CDR_BUFF_SIZE);
			strncat(CDR_FILE_PATH, "_cdr.csv", strlen("_cdr.csv"));
			fprintf(stderr, "DP: CDR_FILE_PATH: ngic_rtc/dp/%s\n", CDR_FILE_PATH);
			dp_comm_ip.s_addr = dp_comm_ip.s_addr;
			dp_comm_ip_type |= 1;

			fprintf(stderr, "DP: PFCP_IPv4 Addr: "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(ntohl(dp_comm_ip.s_addr)));
		} else if(strncmp("PFCP_IPv6", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			uint8_t net_t[IPv6_PREFIX_LEN] = {0};
			char *addr_t[IPV6_STR_LEN] = {NULL};
			char temp[CDR_BUFF_SIZE] = {0};

			/* Parse the IPv6 String and separate out address and prefix */
			if (get_ipv6_address(global_entries[inx].value, addr_t, net_t) < 0) {
				fprintf(stderr, "Invalid DP PFCP_IPv6 Address and Prefix Configuration.\n");
				return -1;
			}
			/* Configured PFCP IP Address  */
			if (!inet_pton(AF_INET6, *addr_t, &(dp_comm_ipv6))) {
				fprintf(stderr, "Invalid DP PFCP IPv6 Address\n");
				return -1;
			}

			inet_ntop(AF_INET6, dp_comm_ipv6.s6_addr, temp, CDR_BUFF_SIZE);
			strncat(temp, "_cdr.csv", strlen("_cdr.csv"));
			strncpy(CDR_FILE_PATH, "logs/", CDR_BUFF_SIZE);
			strncat(CDR_FILE_PATH, temp, CDR_BUFF_SIZE);
			fprintf(stderr, "DP: CDR_FILE_PATH: ngic_rtc/dp/%s\n", CDR_FILE_PATH);
			memcpy(&app->pfcp_ipv6_prefix_len, net_t, IPv6_PREFIX_LEN);
			dp_comm_ip_type |= 2;

			fprintf(stderr, "DP: PFCP_IPv6 Addr: %s/%u\n",
				global_entries[inx].value, *net_t);
		} else if(strncmp("PFCP_PORT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			dp_comm_port = (uint16_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: PFCP PORT: %u\n", dp_comm_port);
		} else if(strncmp("WB_IPv4_MASK", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S1U/S5S8 Subnet mask */
			struct in_addr tmp = {0};
			if(!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid West_Bound(S1U/S5S8) IPv4 Subnet Masks\n");
				app->wb_mask = 0;
				return -1;
			}
			app->wb_mask = ntohl(tmp.s_addr);

			fprintf(stderr, "DP: WB_IPv4_MASK(S1U/S5S8): "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_mask));
		} else if(strncmp("WB_LI_IPv4_MASK", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8-P Subnet mask */
			struct in_addr tmp = {0};
			if(!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid West_Bound(S5S8) logical iface Masks\n");
				app->wb_li_mask = 0;
				return -1;
			}
			app->wb_li_mask = ntohl(tmp.s_addr);

			fprintf(stderr, "DP: WB_LI_IPv4_MASK(S5S8): "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_li_mask));
		} else if(strncmp("EB_IPv4_MASK", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8/SGI Subnet mask */
			struct in_addr tmp = {0};
			if(!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid East_Bound(S5S8/SGI) IPv4 Subnet Masks\n");
				app->eb_mask = 0;
				return -1;
			}
			app->eb_mask = ntohl(tmp.s_addr);

			fprintf(stderr, "DP: EB_IPv4_MASK(S5S8/SGI): "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_mask));
		} else if(strncmp("EB_LI_IPv4_MASK", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* S5S8-S Subnet mask */
			struct in_addr tmp = {0};
			if(!inet_aton(global_entries[inx].value, &(tmp))) {
				fprintf(stderr, "Invalid East_Bound(S5S8) logical iface Masks\n");
				app->eb_li_mask = 0;
				return -1;
			}
			app->eb_li_mask = ntohl(tmp.s_addr);

			fprintf(stderr, "DP: EB_LI_IPv4_MASK(S5S8): "IPV4_ADDR"\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_li_mask));
		} else if(strncmp("WB_MAC", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			if (!parse_ether_addr(&app->wb_ether_addr, global_entries[inx].value, 0)) {
				return -1;
			}

			for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->wb_ether_addr, &mac_addr)) {
					fprintf(stderr, "DP: West_Bound(WB/S1U/S5S8) Port_ID: %d\n", i);
					app->wb_port = i;
					break;
				}
			}
			if (app->wb_port != 0) {
				fprintf(stderr, "ERROR: Iface assignment or West Bound(WB_MAC) intf"
						" MAC Address is wrong configured.\n");
				return -1;
			}
		} else if(strncmp("EB_MAC", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			if (!parse_ether_addr(&app->eb_ether_addr, global_entries[inx].value, 1)) {
				return -1;
			}

			for (int i = 0; i < RTE_MAX_ETHPORTS; i++) {
				rte_eth_macaddr_get(i, &mac_addr);
				if (is_same_ether_addr
					(&app->eb_ether_addr, &mac_addr)) {
					fprintf(stderr, "DP: East_Bound(EB/S5S8/SGI) Port_ID: %d\n", i);
					app->eb_port = i;
					break;
				}
			}
			if (app->eb_port != 1) {
				fprintf(stderr, "ERROR: Iface assignment or East Bound(EB_MAC) intf"
						" MAC Address is wrong configured.\n");
				return -1;
			}
		} else if(strncmp("WB_IFACE", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->wb_iface_name, global_entries[inx].value, MAX_LEN);

			fprintf(stderr, "DP: KNI West_Bound iface: %s\n", app->wb_iface_name);
		} else if(strncmp("WB_LI_IFACE", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->wb_li_iface_name, global_entries[inx].value, MAX_LEN);

			fprintf(stderr, "DP: KNI West_Bound(S5S8) Logical iface: %s\n", app->wb_li_iface_name);
		} else if(strncmp("EB_IFACE", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->eb_iface_name, global_entries[inx].value, MAX_LEN);

			fprintf(stderr, "DP: KNI East_Bound iface: %s\n", app->eb_iface_name);
		} else if(strncmp("EB_LI_IFACE", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->eb_li_iface_name, global_entries[inx].value, MAX_LEN);

			fprintf(stderr, "DP: KNI East_Bound(S5S8) Logical iface: %s\n", app->eb_li_iface_name);
		} else if(strncmp("NUMA", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->numa_on = (uint8_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: NUMA Mode:%u\n", app->numa_on);
		} else if(strncmp("GTPU_SEQNB_IN", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->gtpu_seqnb_in = (uint8_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: GTPU_SEQNB_IN: %u\n", app->gtpu_seqnb_in);
		} else if(strncmp("GTPU_SEQNB_OUT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->gtpu_seqnb_out = (uint8_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: GTPU_SEQNB_OUT: %u\n", app->gtpu_seqnb_out);
		} else if(strncmp("TRANSMIT_TIMER", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->transmit_timer = (int)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: TRANSMIT_TIMER: %d\n", app->transmit_timer);
		} else if(strncmp("PERIODIC_TIMER", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->periodic_timer = (int)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: PERIODIC_TIMER: %d\n", app->periodic_timer);
		} else if(strncmp("TRANSMIT_COUNT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->transmit_cnt = (uint8_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: TRANSMIT_COUNT: %u\n", app->transmit_cnt);
		} else if(strncmp("TEIDRI", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* Configure TEIDRI val */
			errno = 0;
			endptr = NULL;
			temp_val = 0;
			int temp_val = strtol(global_entries[inx].value, &endptr, DECIMAL_BASE);
			if ((errno == ERANGE && (temp_val == LONG_MAX || temp_val == LONG_MIN))
					|| (errno != 0 && temp_val == 0)
					|| (*endptr != '\0')  /* Checks if input contains any non digit value*/
					|| (temp_val < 0 || temp_val > 7)) { /* checks if input is positive and is within given range */
				printf("Invalid TEIDRI value %s\n", global_entries[inx].value);
				printf("     - Input should be valid positive integer value \n");
				printf("     - Input should not contain any non digit character \n");
				printf("     - Input should contain value between 0 to 7\n");
				app->teidri_val = 0;
				return -1;
			}
			app->teidri_val = temp_val;

			fprintf(stderr, "DP: TEIDRI: %d\n", app->teidri_val);
		} else if(strncmp("TEIDRI_TIMEOUT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* Configure TEIDRI timeout val */
			errno = 0;
			endptr = NULL;
			temp_val = 0;
			temp_val = strtol(global_entries[inx].value, &endptr, DECIMAL_BASE);
			if ((errno == ERANGE && (temp_val == LONG_MAX || temp_val == LONG_MIN))
					|| (errno != 0 && temp_val == 0)
					|| (*endptr != '\0')  /* Checks if input contains any non digit value*/
					|| (temp_val < 0 || temp_val > INT_MAX)) { /* checks if input is positive and is inside integer range */
				printf("Invalid TEIDRI TIMEOUT value %s\n", global_entries[inx].value);
				printf("     - Input should be valid positive integer value \n");
				printf("     - Input should not contain any non digit character \n");
				printf("Falling back to default value %d for TEIDRI TIMEOUT \n", TEIDRI_TIMEOUT_DEFAULT);
				app->teidri_timeout = TEIDRI_TIMEOUT_DEFAULT;
			}else{
				app->teidri_timeout = temp_val;
				fprintf(stderr, "DP: TEIDRI_TIMEOUT: %d\n", app->teidri_timeout);
			}
		} else if(strncmp("DDF2_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* DDF2 IP Address */
			strncpy(app->ddf2_ip, global_entries[inx].value, IPV6_STR_LEN);
			fprintf(stderr, "DP: DDF2_IP: %s\n", app->ddf2_ip);
		} else if(strncmp("DDF2_PORT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->ddf2_port = (uint16_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: DDF2_PORT: %u\n", app->ddf2_port);
		} else if(strncmp("DDF2_LOCAL_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->ddf2_local_ip, global_entries[inx].value, IPV6_STR_LEN);

			fprintf(stderr, "DP: DDF2_LOCAL_IP: %s\n", app->ddf2_local_ip);
		} else if(strncmp("DDF3_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			/* DDF3 IP Address */
			strncpy(app->ddf3_ip, global_entries[inx].value, IPV6_STR_LEN);

			fprintf(stderr, "DP: DDF3_IP: %s\n", app->ddf3_ip);
		} else if(strncmp("DDF3_PORT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->ddf3_port = (uint16_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: DDF3_PORT: %u\n", app->ddf3_port);
		} else if(strncmp("DDF3_LOCAL_IP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			strncpy(app->ddf3_local_ip, global_entries[inx].value, IPV6_STR_LEN);

			fprintf(stderr, "DP: DDF3_LOCAL_IP: %s\n", app->ddf3_local_ip);
		} else if(strncmp("GENERATE_PCAP", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->generate_pcap = (uint8_t)atoi(global_entries[inx].value);

			fprintf(stderr, "DP: GENERATE_PCAP: %u\n", app->generate_pcap);
		} else if (strncmp("CLI_REST_IP" , global_entries[inx].name,
					ENTRY_NAME_SIZE) == 0) {

			/* Check for IP type (ipv4/ipv6) */
			struct addrinfo *ip_type = NULL;
			if (getaddrinfo(global_entries[inx].value, NULL, NULL, &ip_type)) {
				fprintf(stderr, "CP: CP_REST_IP : %s is in incorrect format\n",
					global_entries[inx].value);
				rte_panic();
			}

			if(ip_type->ai_family == AF_INET6) {
				strncpy(app->cli_rest_ip_buff,
					global_entries[inx].value, IPV6_STR_LEN);
			} else {
				strncpy(app->cli_rest_ip_buff,
					global_entries[inx].value, IPv4_ADDRESS_LEN);
			}
			fprintf(stdout, "CP: CP_REST_IP : %s\n",
					app->cli_rest_ip_buff);
		} else if(strncmp("CLI_REST_PORT", global_entries[inx].name, ENTRY_NAME_SIZE) == 0) {
			app->cli_rest_port = (uint16_t)atoi(global_entries[inx].value);
			fprintf(stdout, "CP: CLI_REST_PORT : %d\n",
					app->cli_rest_port);
		}
	}

	rte_free(global_entries);

	/* Validate the Mandatory Parameters are Configured or Not */
	if (validate_mandatory_params(app)) {
		return -1;
	}

	app->wb_net = app->wb_ip & app->wb_mask;
	app->wb_bcast_addr = app->wb_ip | ~(app->wb_mask);
	fprintf(stderr, "DP: Config:%s::"
			"\n\tDP: West_Bound(S1U/S5S8) IP:\t\t"IPV4_ADDR";\n\t",
			__func__, IPV4_ADDR_HOST_FORMAT(app->wb_ip));
	fprintf(stderr, "West_Bound(S1U/S5S8) NET:\t\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->wb_net));
	fprintf(stderr, "West_Bound(S1U/S5S8) MASK:\t\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->wb_mask));
	fprintf(stderr, "West_Bound(S1U/S5S8) BCAST ADDR:\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->wb_bcast_addr));
	fprintf(stderr, "West_Bound(S1U/S5S8) GW IP:\t\t"IPV4_ADDR"\n\n",
			IPV4_ADDR_HOST_FORMAT(app->wb_gw_ip));

	if(app->wb_li_ip) {
		app->wb_li_net = app->wb_li_ip & app->wb_li_mask;
		app->wb_li_bcast_addr = app->wb_li_ip | ~(app->wb_li_mask);
		fprintf(stderr, "DP: Config:%s::"
				"\n\tDP: West_Bound(S5S8) Logical Intf IP:\t\t"IPV4_ADDR";\n\t",
				__func__, IPV4_ADDR_HOST_FORMAT(app->wb_li_ip));
		fprintf(stderr, "West_Bound(S5S8) Logical Intf NET:\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(app->wb_li_net));
		fprintf(stderr, "West_Bound(S5S8) Logical Intf MASK:\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(app->wb_li_mask));
		fprintf(stderr, "West_Bound(S5S8) Logical Intf BCAST ADDR:\t"IPV4_ADDR";\n\n",
				IPV4_ADDR_HOST_FORMAT(app->wb_li_bcast_addr));
		//fprintf(stderr, "West_Bound(S5S8) Logical Intf GW IP:\t\t"IPV4_ADDR"\n",
		//		IPV4_ADDR_HOST_FORMAT(app->wb_li_gw_ip));
	}

	app->eb_net = app->eb_ip & app->eb_mask;
	app->eb_bcast_addr = app->eb_ip | ~(app->eb_mask);
	fprintf(stderr, "DP: Config:%s::"
			"\n\tDP: East_Bound(S5S8/SGI) IP:\t\t"IPV4_ADDR";\n\t",
			__func__, IPV4_ADDR_HOST_FORMAT(app->eb_ip));
	fprintf(stderr, "East_Bound(S5S8/SGI) NET:\t\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->eb_net));
	fprintf(stderr, "East_Bound(S5S8/SGI) MASK:\t\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->eb_mask));
	fprintf(stderr, "East_Bound(S5S8/SGI) BCAST ADDR:\t"IPV4_ADDR";\n\t",
			IPV4_ADDR_HOST_FORMAT(app->eb_bcast_addr));
	fprintf(stderr, "East_Bound(S5S8/SGI) GW IP:\t\t"IPV4_ADDR"\n\n",
			IPV4_ADDR_HOST_FORMAT(app->eb_gw_ip));

	if(app->eb_li_ip) {
		app->eb_li_net = app->eb_li_ip & app->eb_li_mask;
		app->eb_li_bcast_addr = app->eb_li_ip | ~(app->eb_li_mask);
		fprintf(stderr, "DP: Config:%s::"
				"\n\tDP: East_Bound(S5S8) Logical Intf IP:\t\t"IPV4_ADDR";\n\t",
				__func__, IPV4_ADDR_HOST_FORMAT(app->eb_li_ip));
		fprintf(stderr, "East_Bound(S5S8) Logical Intf NET:\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(app->eb_li_net));
		fprintf(stderr, "East_Bound(S5S8) Logical Intf MASK:\t\t"IPV4_ADDR";\n\t",
				IPV4_ADDR_HOST_FORMAT(app->eb_li_mask));
		fprintf(stderr, "East_Bound(S5S8) Logical Intf BCAST ADDR:\t"IPV4_ADDR";\n\n",
				IPV4_ADDR_HOST_FORMAT(app->eb_li_bcast_addr));
		//fprintf(stderr, "East_Bound(S5S8) Logical Intf GW IP:\t\t"IPV4_ADDR"\n",
		//		IPV4_ADDR_HOST_FORMAT(app->wb_li_gw_ip));
	}

	fprintf(stderr,
			"###############[Completed Data-Plane Config Reading]################\n\n\n");
	return 0;
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
	uint64_t used_coremask = 0;

	/* Parse Data-Plane Configuration File */
	if (parse_up_config_param(app) < 0) {
		return -1;
	}

	static struct option spgw_opts[] = {
		{"LOG",required_argument, 0, 'l'},
		{"KNI_PORTMASK", required_argument, 0, 'p'},
		{NULL, 0, 0, 0}
	};

	optind = 0;/* reset getopt lib */

	while ((opt = getopt_long(argc, argv, "l:p:",
					spgw_opts, &option_index)) != EOF) {
		switch (opt) {

		case 'l':
			app->log_level = atoi(optarg);
			break;
		case 'p':
			app->ports_mask = atoi(optarg);
			break;
		default:
			fprintf(stderr, "Parsing Configuration Error \n");
			return -1;
		}		/* end switch (opt) */
	}			/* end while() */

	set_unused_lcore(&epc_app.core_mct, &used_coremask);
	set_unused_lcore(&epc_app.core_iface, &used_coremask);
	set_unused_lcore(&epc_app.core_ul[S1U_PORT_ID], &used_coremask);
	set_unused_lcore(&epc_app.core_dl[SGI_PORT_ID], &used_coremask);

	return 0;
}

void dp_init(int argc, char **argv)
{
	if (parse_config_args(&app, argc, argv) < 0)
		rte_exit(EXIT_FAILURE,
				LOG_FORMAT"Error: Failed parsing of the data-plane configuration\n", LOG_VALUE);

	if (read_teidri_data(TEIDRI_FILENAME,
				&upf_teidri_blocked_list, &upf_teidri_free_list, app.teidri_val) != 0) {
		/* Need to think about error handling */
	}
	switch (app.gtpu_seqnb_in)
	{
		case 1: /* include sequence number */
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_with_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_with_seqnb;
			fp_gtpu_inner_src_ipv6 = gtpu_inner_src_ipv6_with_seqnb;
			fp_decap_gtpu_hdr = decap_gtpu_hdr_with_seqnb;
			break;
		}
		case 2: /* sequence number not included */
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_without_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_without_seqnb;
			fp_gtpu_inner_src_ipv6 = gtpu_inner_src_ipv6_without_seqnb;
			fp_decap_gtpu_hdr = decap_gtpu_hdr_without_seqnb;
			break;
		}
		case 0: /* dynamic */
		default:
		{
			fp_gtpu_get_inner_src_dst_ip = gtpu_get_inner_src_dst_ip_dynamic_seqnb;
			fp_gtpu_inner_src_ip = gtpu_inner_src_ip_dynamic_seqnb;
			fp_gtpu_inner_src_ipv6 = gtpu_inner_src_ipv6_dynamic_seqnb;
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
