/*
 * Copyright (c) 2020 Sprint
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

#include<stdio.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_string_fns.h>
#include <netdb.h>

#include "config_validater.h"

cfg_data cfg_parms_list[] = {
	{   "CP_TYPE", NULL, &is_valid_integer                },
	{   "S11_IP", NULL, &is_valid_ipv4                    },
	{   "S11_IP_V6", NULL, &is_valid_ipv6                 },
	{   "S11_PORT", NULL, &is_valid_integer               },
	{   "S5S8_IP", NULL, &is_valid_ipv4                   },
	{   "S5S8_IP_V6", NULL, &is_valid_ipv6                },
	{   "S5S8_PORT", NULL, &is_valid_integer              },
	{   "PFCP_IP", NULL, &is_valid_ipv4                   },
	{   "PFCP_IP_V6", NULL, &is_valid_ipv6                },
	{   "PFCP_PORT", NULL, &is_valid_integer              },
	{   "UPF_PFCP_IP", NULL, &is_valid_ipv4               },
	{   "UPF_PFCP_IP_V6", NULL, &is_valid_ipv6            },
	{   "UPF_PFCP_PORT", NULL, &is_valid_integer          },
	{   "REDIS_IP", NULL, &is_valid_ipv4v6                },
	{   "REDIS_PORT", NULL, &is_valid_integer             },
	{   "CP_REDIS_IP", NULL, &is_valid_ipv4v6             },
	{   "REDIS_CERT_PATH", NULL, &is_valid_string         },
	{   "DDF2_IP", NULL, &is_valid_ipv4_ipv6              },
	{   "DDF2_PORT", NULL, &is_valid_integer              },
	{   "DDF2_LOCAL_IP", NULL, &is_valid_ipv4_ipv6        },
	{   "DADMF_IP", NULL, &is_valid_ipv4_ipv6             },
	{   "DADMF_PORT", NULL, &is_valid_integer             },
	{   "DADMF_LOCAL_IP", NULL, &is_valid_ipv4_ipv6       },
	{   "SUGGESTED_PKT_COUNT", NULL, &is_valid_integer    },
	{   "LOW_LEVEL_ARP_PRIORITY", NULL, &is_valid_integer },
	{   "TRANSMIT_TIMER", NULL, &is_valid_integer         },
	{   "PERIODIC_TIMER", NULL, &is_valid_integer         },
	{   "TRANSMIT_COUNT", NULL, &is_valid_integer         },
	{   "REQUEST_TIMEOUT", NULL, &is_valid_integer        },
	{   "REQUEST_TRIES", NULL, &is_valid_integer          },
	{   "USE_DNS", NULL, &is_valid_integer                },
	{   "CP_DNS_IP", NULL, &is_valid_ipv4v6               },
	{   "CLI_REST_PORT", NULL, &is_valid_integer          },
	{   "CLI_REST_IP", NULL, &is_valid_ipv4v6             },
	{   "GENERATE_CDR", NULL, &is_valid_integer           },
	{   "GENERATE_SGW_CDR", NULL, &is_valid_integer       },
	{   "SGW_CC", NULL, &is_valid_integer                 },
	{   "ADD_DEFAULT_RULE", NULL, &is_valid_integer       },
	{   "IP_ALLOCATION_MODE", NULL, &is_valid_integer     },
	{   "IP_TYPE_SUPPORTED", NULL, &is_valid_integer      },
	{   "IP_TYPE_PRIORITY", NULL, &is_valid_integer       },
	{   "USE_GX", NULL, &is_valid_integer                 },
	{   "name", NULL, &is_valid_string                    },
	{   "usage_type", NULL, &is_valid_integer             },
	{   "network_capability", NULL, &is_valid_string      },
	{   "trigger_type", NULL, &is_valid_integer           },
	{   "uplink_volume_th", NULL, &is_valid_integer       },
	{   "downlink_volume_th", NULL, &is_valid_integer     },
	{   "time_th", NULL, &is_valid_integer                },
	{   "concurrent", NULL, &is_valid_integer             },
	{   "percentage", NULL, &is_valid_integer             },
	{   "interval_seconds", NULL, &is_valid_integer       },
	{   "query_timeout_ms", NULL, &is_valid_integer       },
	{   "query_tries", NULL, &is_valid_integer            },
	{   "frequency_seconds", NULL, &is_valid_integer      },
	{   "filename", NULL, &is_valid_string                },
	{   "nameserver", NULL, &is_valid_ipv4v6              },
	{   "IP_POOL_IP", NULL, &is_valid_ipv4                },
	{   "IP_POOL_MASK", NULL, &is_valid_ipv4              },
	{   "IPV6_NETWORK_ID", NULL, &is_valid_ipv6           },
	{   "IPV6_PREFIX_LEN", NULL, &is_valid_string         },
	{   "PFCP_IPv4", NULL, &is_valid_ipv4                 },
	{   "PFCP_IPv6", NULL, &is_valid_ipv6                 },
	{   "WB_IFACE", NULL, &is_valid_string                },
	{   "EB_IFACE", NULL, &is_valid_string                },
	{   "WB_IPv4", NULL, &is_valid_ipv4                   },
	{   "WB_IPv6", NULL, &is_valid_ipv6                   },
	{   "WB_IPv4_MASK", NULL, &is_valid_ipv4              },
	{   "WB_MAC", NULL, &is_valid_mac                     },
	{   "EB_IPv4", NULL, &is_valid_ipv4                   },
	{   "EB_IPv6", NULL, &is_valid_ipv6                   },
	{   "EB_IPv4_MASK", NULL, &is_valid_ipv4              },
	{   "EB_MAC", NULL, &is_valid_mac                     },
	{   "WB_LI_IPv4", NULL, &is_valid_ipv4                },
	{   "WB_LI_IPv6", NULL, &is_valid_ipv6                },
	{   "WB_LI_IPv4_MASK", NULL, &is_valid_ipv4           },
	{   "WB_LI_IFACE", NULL, &is_valid_string             },
	{   "EB_LI_IPv4", NULL, &is_valid_ipv4                },
	{   "EB_LI_IPv6", NULL, &is_valid_ipv6                },
	{   "EB_LI_IPv4_MASK", NULL, &is_valid_ipv4           },
	{   "EB_LI_IFACE", NULL, &is_valid_string             },
	{   "NUMA", NULL, &is_valid_integer                   },
	{   "TEIDRI", NULL, &is_valid_integer                 },
	{   "TEIDRI_TIMEOUT", NULL, &is_valid_integer         },
	{   "GENERATE_PCAP", NULL, &is_valid_integer          },
	{   "DDF3_IP", NULL, &is_valid_ipv4_ipv6              },
	{   "DDF3_PORT", NULL, &is_valid_integer              },
	{   "DDF3_LOCAL_IP", NULL, &is_valid_ipv4_ipv6        },
	{   "WB_GW_IP", NULL, &is_valid_ipv4                  },
	{   "EB_GW_IP", NULL, &is_valid_ipv4                  },
	{   "GTPU_SEQNB_IN", NULL, &is_valid_integer          },
	{   "GTPU_SEQNB_OUT", NULL, &is_valid_integer         }
};

section section_list[] = {
	{   "[GLOBAL]"            },
	{   "[APN]"               },
	{   "[URR_DEFAULT]"       },
	{   "[NAMESERVER_CONFIG]" },
	{   "[CACHE]"             },
	{   "[APP]"               },
	{   "[OPS]"               },
	{   "[IP_POOL_CONFIG]"    }
};

int is_valid_integer(char *key, char *value) {
	unsigned int idx = 0;
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	for(idx = 0; idx < strnlen(value,CFG_VALUE_LENGTH); idx++) {
		if(isdigit(value[idx])  == 0) {
			return VALUE_FORMAT_NOT_CORRECT;
		}
	}
	RTE_SET_USED(key);
	return 0;
}

int is_valid_ipv4(char *key, char *value) {
	char buf[IPV4_LEN];
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;
	if (!(inet_pton(AF_INET, value, buf)))
		return VALUE_FORMAT_NOT_CORRECT;
	RTE_SET_USED(key);
	return 0;
}

int is_valid_ipv4v6(char *key, char *value) {
	struct addrinfo *ip_type = NULL;

	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	if(getaddrinfo(value, NULL, NULL, &ip_type)) {
		return VALUE_FORMAT_NOT_CORRECT;
	}

	RTE_SET_USED(key);
	return 0;
}

int is_valid_ipv6(char *key, char *value) {
	char buf[IPV6_LEN];
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	if( strstr(value, "/") != NULL){
		int ip_token = 0;
		char *ip_fld[2];
		ip_token = rte_strsplit(value, strnlen(value, CFG_VALUE_LENGTH), ip_fld, 2, '/');
		if(ip_token > 2)
			return VALUE_FORMAT_NOT_CORRECT;
		if (!(inet_pton(AF_INET6, ip_fld[0], buf)))
			return VALUE_FORMAT_NOT_CORRECT;
		RTE_SET_USED(key);
	}else {
		if (!(inet_pton(AF_INET6, value, buf)))
			return VALUE_FORMAT_NOT_CORRECT;
		RTE_SET_USED(key);
	}
	return 0;
}

int is_valid_ipv4_ipv6(char *key, char *value) {
	char buf[IPV4_LEN];
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;
	if (!(inet_pton(AF_INET, value, buf))) {

		if (!(inet_pton(AF_INET6, value, buf))) {
			return VALUE_FORMAT_NOT_CORRECT;
		}
	}

	RTE_SET_USED(key);
	return 0;
}

int is_valid_mac(char *key, char *value) {
	int hex_itr = 0;
	int separater = 0;
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;
	while(*value) {
		if (isxdigit(*value)) {
			hex_itr++;
		} else if (*value == ':') {

			if (hex_itr == 0 || hex_itr / 2 - 1 != separater)
				break;

			++separater;
		} else {
			separater = -1;
		}
		++value;
	}

	if ((hex_itr == MAC_ADDRESS_LEN) && (separater == MAC_ADDRESS_SEPARTER)) {
		return 0;
	} else {
		return VALUE_FORMAT_NOT_CORRECT;
	}
	RTE_SET_USED(key);
}

int is_valid_apn(char *value) {
	unsigned int idx = 0;
	if(value == NULL) {
		return VALUE_FORMAT_NOT_CORRECT;
	} else if(!(isalnum(value[STARTING_INDEX]) &
		isalnum(value[strnlen(value,CFG_VALUE_LENGTH) - 1]))) {
		return VALUE_FORMAT_NOT_CORRECT;
	} else {
		for(idx = 1; idx < strnlen(value,CFG_VALUE_LENGTH) - 1; idx++) {
			if(value[idx]  == '.' && isalnum(value[idx + 1]) == 0) {
				return VALUE_FORMAT_NOT_CORRECT;
			} else if(isalnum(value[idx]) == 0 && value[idx] != '.') {
				return VALUE_FORMAT_NOT_CORRECT;
			}
		}
	}
	return 0;
}

int is_valid_alphanumeric_value(char *value) {
	unsigned int idx = 0;
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	for(idx = 0; idx < strnlen(value,CFG_VALUE_LENGTH); idx++) {
		if(isalnum(value[idx])  == 0) {
			return VALUE_FORMAT_NOT_CORRECT;
		}
	}
	return 0;
}

int is_valid_alpha_value(char *value) {
	unsigned int idx = 0;
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	for(idx = 0; idx < strnlen(value,CFG_VALUE_LENGTH); idx++) {
		if(isalpha(value[idx])  == 0) {
			return VALUE_FORMAT_NOT_CORRECT;
		}
	}
	return 0;
}

int is_valid_interface(char *value) {
	unsigned int idx = 0;
	if(value == NULL) {
		return VALUE_FORMAT_NOT_CORRECT;
	} else if(!(isalnum(value[STARTING_INDEX]) &
		isalnum(value[strnlen(value,CFG_VALUE_LENGTH) - 1]))) {
		return VALUE_FORMAT_NOT_CORRECT;
	} else {
		for(idx = 1; idx < strnlen(value,CFG_VALUE_LENGTH) - 1; idx++) {
			if(value[idx]  == ':' && isalnum(value[idx + 1]) == 0) {
				return VALUE_FORMAT_NOT_CORRECT;
			} else if(isalnum(value[idx]) == 0 && value[idx] != ':') {
				return VALUE_FORMAT_NOT_CORRECT;
			}
		}
	}
	return 0;
}

int is_valid_string(char *key, char *value) {
	if(value == NULL)
		return VALUE_FORMAT_NOT_CORRECT;

	if(!strncmp(key, "WB_IFACE", KEY_LEN)) {
		if(is_valid_interface(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "WB_LI_IFACE", KEY_LEN)) {
		if(is_valid_interface(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "EB_IFACE", KEY_LEN)) {
		if(is_valid_interface(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "EB_LI_IFACE", KEY_LEN)) {
		if(is_valid_interface(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "REDIS_CERT_PATH", KEY_LEN)) {
		if(strncmp(value, "../config/redis_cert", CFG_VALUE_LENGTH) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "network_capability", KEY_LEN)) {
		if(is_valid_alpha_value(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "filename", KEY_LEN)) {
		if((strnlen(value, CFG_VALUE_LENGTH) == 0)
				|| (strnlen(value, CFG_VALUE_LENGTH) == 0))
			return VALUE_FORMAT_NOT_CORRECT;
	} else if(!strncmp(key, "name", KEY_LEN)) {
		if(is_valid_apn(value) != 0)
			return VALUE_FORMAT_NOT_CORRECT;
	}

	return 0;
}

void read_cfg_file(const char *path) {
	char buffer[BUFFER_SIZE] = {0};
	int itr_buff = 0;
	int index = 0;
	bool key_value_filled = false;
	int no_of_cfg_params = sizeof(cfg_parms_list) / sizeof(cfg_parms_list[STARTING_INDEX]);
	int no_of_sections = sizeof(section_list) / sizeof(section_list[STARTING_INDEX]);
	FILE *fp = fopen(path, "r");

	if(fp == NULL) {
		fprintf(stderr, "\nFailed to open %s file\n", path);
		exit(0);
	}
	while(fgets(buffer, sizeof(buffer), fp) != NULL) {
		char cfg_key[KEY_LEN] = {0};
		char cfg_parameter_value[CFG_VALUE_LENGTH] = {0};
		char cfg_section_value[KEY_LEN] = {0};
		int itr_cfg_params = 0;
		int itr_cfg_section = 0;
		index = 0;
		key_value_filled = false;
		if(buffer[STARTING_INDEX] != ';'
				&& buffer[STARTING_INDEX] != '#' && buffer[STARTING_INDEX] != '\n') {
			for (itr_buff = 0;
					buffer[itr_buff] != '\n' &&  buffer[itr_buff] != '\0'; itr_buff++) {
				if(buffer[STARTING_INDEX] == '[') {
					cfg_section_value [index++] = buffer[itr_buff];
				} else if(buffer[itr_buff] == '=') {
					cfg_key[index] = '\0';
					index = 0;
					key_value_filled = true;
				} else if(!key_value_filled &&  buffer[itr_buff] != ' ') {
					cfg_key[index++] = buffer[itr_buff];
				} else {
					if(buffer[itr_buff] != ' ')
						cfg_parameter_value[index++] = buffer[itr_buff];
				}
			}

			if(buffer[STARTING_INDEX] != '[') {
				cfg_parameter_value[index] = '\0';
				for(itr_cfg_params = 0; itr_cfg_params < no_of_cfg_params; itr_cfg_params++) {
					if(!strncmp(cfg_parms_list[itr_cfg_params].key, cfg_key, KEY_LEN)) {
						if((*cfg_parms_list[itr_cfg_params].fun_ptr)(cfg_key, cfg_parameter_value) != 0) {
							fprintf(stderr, "\nNeed to enter the valid value for %s key\n", cfg_key);
							exit(0);
						}
						break;
					}
				}
			} else {
				cfg_section_value [index++] = '\0';
				for(itr_cfg_section = 0; itr_cfg_section < no_of_sections; itr_cfg_section++) {
					if(!strncmp(section_list[itr_cfg_section].section_name,
								cfg_section_value, KEY_LEN))
						break;
				}
			}
		}

		if(itr_cfg_params == no_of_cfg_params && buffer[STARTING_INDEX] != '[') {
			fprintf(stderr, "\nInvalid Key : %s\n", cfg_key);
			exit(0);
		} else if(itr_cfg_section == no_of_sections) {
			fprintf(stderr, "\nInvalid Section : %s\n", cfg_section_value);
			exit(0);
		}
	}
}
