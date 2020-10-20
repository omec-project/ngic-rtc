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

#include "cp.h"
#include "gw_adapter.h"
#include "cstats.h"
#include "cdadmfapi.h"

#define MAX_STRING_LEN          32
#define CFG_VALUE_LEN           256

#define GLOBAL_ENTRIES          "GLOBAL"
#define APN_ENTRIES             "APN"
#define NAMESERVER_ENTRIES      "NAMESERVER_CONFIG"
#define IP_POOL_ENTRIES         "IP_POOL_CONFIG"
#define CACHE_ENTRIES           "CACHE"
#define APP_ENTRIES             "APP"
#define OPS_ENTRIES             "OPS"

#define CP_TYPE                 "CP_TYPE"
#define S11_IPS                 "S11_IP"
#define S11_IPS_V6              "S11_IP_V6"
#define S11_PORTS               "S11_PORT"
#define S5S8_IPS                "S5S8_IP"
#define S5S8_IPS_V6             "S5S8_IP_V6"
#define S5S8_PORTS              "S5S8_PORT"
#define PFCP_IPS                "PFCP_IP"
#define PFCP_IPS_V6             "PFCP_IP_V6"
#define PFCP_PORTS          	"PFCP_PORT"
#define DDF2_IP					"DDF2_IP"
#define DDF2_PORT				"DDF2_PORT"
#define DDF2_LOCAL_IPS			"DDF2_LOCAL_IP"
#define DADMF_IPS               "DADMF_IP"
#define DADMF_PORTS             "DADMF_PORT"
#define DADMF_LOCAL_IPS         "DADMF_LOCAL_IP"
#define UPF_PFCP_IPS            "UPF_PFCP_IP"
#define UPF_PFCP_IPS_V6         "UPF_PFCP_IP_V6"
#define UPF_PFCP_PORTS          "UPF_PFCP_PORT"
#define REDIS_IPS               "REDIS_IP"
#define CP_REDIS_IP             "CP_REDIS_IP"
#define REDIS_PORTS             "REDIS_PORT"
#define REDIS_CERT_PATH         "REDIS_CERT_PATH"
#define USE_DNS                 "USE_DNS"
#define CP_DNS_IP               "CP_DNS_IP"
#define CLI_REST_IP             "CLI_REST_IP"
#define CLI_REST_PORT           "CLI_REST_PORT"
#define IP_ALLOCATION_MODE		"IP_ALLOCATION_MODE"
#define IP_TYPE_SUPPORTED       "IP_TYPE_SUPPORTED"
#define IP_TYPE_PRIORITY        "IP_TYPE_PRIORITY"
#define USE_GX                  "USE_GX"
#define SUGGESTED_PKT_COUNT		"SUGGESTED_PKT_COUNT"
#define LOW_LVL_ARP_PRIORITY	"LOW_LEVEL_ARP_PRIORITY"

#define APN_SEC_NAME_LEN        8
#define NAME                    "name"
#define USAGE_TYPE              "usage_type"
#define NETWORK_CAPABILITY      "network_capability"
#define TRIGGER_TYPE            "trigger_type"
#define UPLINK_VOLTH            "uplink_volume_th"
#define DOWNLINK_VOLTH          "downlink_volume_th"
#define TIMETH                  "time_th"
#define URR_DEFAULT             "URR_DEFAULT"

#define NAMESERVER              "nameserver"
#define IP_POOL_IP              "IP_POOL_IP"
#define IPV6_NETWORK_ID    		"IPV6_NETWORK_ID"
#define IPV6_PREFIX_LEN 		"IPV6_PREFIX_LEN"
#define IP_POOL_MASK            "IP_POOL_MASK"
#define CONCURRENT              "concurrent"
#define PERCENTAGE              "percentage"
#define INT_SEC                 "interval_seconds"
#define FREQ_SEC                "frequency_seconds"
#define FILENAME                "filename"
#define QUERY_TIMEOUT           "query_timeout_ms"
#define QUERY_TRIES             "query_tries"

/* Restoration Parameters */
#define TRANSMIT_TIMER          "TRANSMIT_TIMER"
#define PERIODIC_TIMER          "PERIODIC_TIMER"
#define TRANSMIT_COUNT          "TRANSMIT_COUNT"

/* CP Timer Parameter */
#define REQUEST_TIMEOUT         "REQUEST_TIMEOUT"
#define REQUEST_TRIES           "REQUEST_TRIES"

/* CP CDR Parameter */
#define GENERATE_CDR            "GENERATE_CDR"
#define GENERATE_SGW_CDR        "GENERATE_SGW_CDR"
#define SGW_CC       			"SGW_CC"

#define ADD_DEFAULT_RULE       "ADD_DEFAULT_RULE"
/* LI-DF Parameter */
#define NUMBER_OF_LINES          100
#define MAX_LINE_LENGTH          1024
#define LI_DF_CONFIG_FILE_NAME   "../config/LI_DF.csv"
#define READ_ONLY_MODE           "r"
#define APPEND_MODE              "a"
#define LI_DF_CSV_HEADER_INFO    1
#define SGW_CC_CHECK			 2

#define PCAP_TTL                 (64)
#define PCAP_VIHL                (0x0045)
#define IP_BUFF_SIZE             16
#define REQUEST_TIMEOUT_DEFAULT_VALUE 3000
#define REQUEST_TRIES_DEFAULT_VALUE   2
#define GX_FILE_PATH "gx_app/gx.conf"
#define CONNECT_TO "ConnectTo"
uint8_t recovery_flag;

/**
 * @brief  : parse the SGWU/PGWU/SAEGWU IP from config file
 * @param  : config, config file path
 * @return : Returns nothing
 */
void
config_cp_ip_port(pfcp_config_t *config);

/**
 * @brief  : Validate cp requst timeout configured value
 * @param  : value, configured value
 * @return : Returns 0 in case of success, -1 otherwise
 */
int
check_cp_req_timeout_config(char *value);

/**
 * @brief  : Validate cp requst tries configured value
 * @param  : value, configured value
 * @return : Returns 0 in case of success, -1 otherwise
 */
int
check_cp_req_tries_config(char *value);

/**
 * @brief  : Convert apn name to readable format
 * @param  : apn_name_label, apn name which is to be convert
 * @param  : apn_name, array to store apn name
 * @return : Returns 0 in case of success, -1 otherwise
 */
int
get_apn_name(char *apn_name_label, char *apn_name);

/**
 * @brief  : Identify ip address family ipv4/ipv6
 * @param  : ip_addr, ip address
 * @return : Returns ip address family type in
 *           case of success, -1 otherwise
 */
int
get_ip_address_type(const char *ip_addr);

/**
 * @brief  : extract pcrf ip from gx config file
 * @param  : filename, filename with path
 * @param  : peer_addr, pointer of peer_addr
 * @return : Returns case of success, -1 otherwise
 */
int fill_pcrf_ip(const char *filename, char *peer_addr);

/**
 * @brief  : fill gx interface ip into config struture
 * @param  : void
 * @return : Returns case of success, -1 otherwise
 */
int8_t fill_gx_iface_ip(void);
