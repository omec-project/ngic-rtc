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


#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifndef GW_STRUCT_H
#define GW_STRUCT_H

#define IP_ADDR_V4_LEN              16
#define IPV6_STR_LEN		        40
#define REST_SUCESSS                200
#define REST_FAIL                   400
#define LAST_TIMER_SIZE             128
#define JSON_RESP_SIZE              512
#define SX_STATS_SIZE                23
#define S11_STATS_SIZE               51
#define S5S8_STATS_SIZE              37
#define GX_STATS_SIZE                23
#define ENTRY_VALUE_SIZE             64
#define ENTRY_NAME_SIZE              64
#define LINE_SIZE                   256
#define CMD_LIST_SIZE                10
#define MAC_ADDR_LEN                 64
#define MAX_LEN                     128
#define ENODE_LEN                    16
#define MCC_MNC_LEN                   4
#define LB_HB_LEN                     8
#define MAX_SYS_STATS                 5
#define MAX_NUM_NAMESERVER            8
#define NETCAP_LEN                   64
#define MAC_BYTES_LEN                32
#define MAX_NUM_APN                  16
#define INET_ADDRSTRLEN              16
#define PATH_LEN                     64
#define APN_NAME_LEN                 64
#define DNS_IP_INDEX                  1
#define MAC_ADDR_BYTES_IN_INT_ARRAY   6
#define FOUR_BIT_MAX_VALUE           15
#define REDIS_CERT_PATH_LEN         256
#define SGW_CHARGING_CHARACTERISTICS  2
#define CLI_GX_IP            "127.0.0.1"

#define MAX_PEER                     10
#define S11_MSG_TYPE_LEN             49
#define S5S8_MSG_TYPE_LEN            35
#define SX_MSG_TYPE_LEN              23
#define GX_MSG_TYPE_LEN               8
#define SYSTEM_MSG_TYPE_LEN           4
#define HEALTH_STATS_SIZE             2

#define MAX_NUM_GW_MESSAGES         256
#define MAX_INTERFACE_NAME_LEN       10
#define MAX_GATEWAY_NAME_LEN         16
#define CP_PATH      "../config/cp.cfg"
#define DP_PATH      "../config/dp.cfg"


#define GTP_ECHO_REQ                                         (1)
#define GTP_ECHO_RSP                                         (2)

#define GTP_CREATE_SESSION_REQ                               (32)
#define GTP_CREATE_SESSION_RSP                               (33)
#define GTP_MODIFY_BEARER_REQ                                (34)
#define GTP_MODIFY_BEARER_RSP                                (35)
#define GTP_DELETE_SESSION_REQ                               (36)
#define GTP_DELETE_SESSION_RSP                               (37)
#define GTP_CREATE_BEARER_REQ                                (95)
#define GTP_CREATE_BEARER_RSP                                (96)
#define GTP_UPDATE_BEARER_REQ                                (97)
#define GTP_UPDATE_BEARER_RSP                                (98)
#define GTP_DELETE_BEARER_REQ                                (99)
#define GTP_DELETE_BEARER_RSP                                (100)
#define GTP_DELETE_PDN_CONNECTION_SET_REQ                    (101)
#define GTP_DELETE_PDN_CONNECTION_SET_RSP                    (102)
#define GTP_CHANGE_NOTIFICATION_REQ                          (38)
#define GTP_CHANGE_NOTIFICATION_RSP                          (39)
#define GTP_DELETE_BEARER_CMD                                (66)
#define GTP_DELETE_BEARER_FAILURE_IND                        (67)
#define GTP_MODIFY_BEARER_CMD                                (64)
#define GTP_MODIFY_BEARER_FAILURE_IND                        (65)
#define GTP_BEARER_RESOURCE_CMD                              (68)
#define GTP_BEARER_RESOURCE_FAILURE_IND                      (69)
#define GTP_PGW_RESTART_NOTIFICATION                         (179)
#define GTP_PGW_RESTART_NOTIFICATION_ACK                     (180)
#define GTP_UPDATE_PDN_CONNECTION_SET_REQ                    (200)
#define GTP_UPDATE_PDN_CONNECTION_SET_RSP                    (201)
#define IPV4_TYPE                                            (1)
#define IPV6_TYPE		                                     (2)
#define IP_ADDR_V6_LEN		                                 (16)
enum GxMessageType {
	OSS_CCR_INITIAL = 120,
	OSS_CCA_INITIAL,
	OSS_CCR_UPDATE,
	OSS_CCA_UPDATE,
	OSS_CCR_TERMINATE,
	OSS_CCA_TERMINATE,
	OSS_RAR,
	OSS_RAA
};

enum oss_gw_config {
	OSS_CONTROL_PLANE = 01,
	OSS_USER_PLANE = 02
};

enum oss_s5s8_selection {
	OSS_S5S8_RECEIVER = 01,
	OSS_S5S8_SENDER = 02
};

typedef enum {
	PERIODIC_TIMER_INDEX,
	TRANSMIT_TIMER_INDEX,
	TRANSMIT_COUNT_INDEX,
	REQUEST_TIMEOUT_INDEX,
	REQUEST_TRIES_INDEX,
	PCAP_GENERATION_INDEX,
} SystemCmds;


/**
 * @brief  : Maintains restoration parameters information
 */
typedef struct restoration_params_t {
	uint8_t transmit_cnt;
	int transmit_timer;
	int periodic_timer;
} restoration_params_t;

/**
 * @brief  : Maintains apn related information
 */
typedef struct apn_info_t {
	char apn_name_label[APN_NAME_LEN];
	int apn_usage_type;
	char apn_net_cap[NETCAP_LEN];
	int trigger_type;
	int uplink_volume_th;
	int downlink_volume_th;
	int time_th;
	size_t apn_name_length;
	uint8_t apn_idx;
	struct in_addr ip_pool_ip;
	struct in_addr ip_pool_mask;
	struct in6_addr ipv6_network_id;
	uint8_t ipv6_prefix_len;
} apn_info_t;


/**
 * @brief  : Maintains dns cache information
 */
typedef struct dns_cache_parameters_t {
	uint32_t concurrent;
	uint32_t sec;
	uint8_t percent;
	unsigned long timeoutms;
	uint32_t tries;
} dns_cache_parameters_t;

typedef enum {
	ACC = 0,
	REJ = 1,
	SENT = 0,
	RCVD = 1,
	BOTH = 0
} Dir;

typedef enum {
	S11,
	S5S8,
	SX,
	GX,
	S1U,
	SGI
}CLIinterface;

typedef enum {
	itS11,
	itS5S8,
	itSx,
	itGx,
	itS1U,
	itSGI,
} EInterfaceType;

typedef enum {
	dIn,
	dOut,
	dRespSend,
	dRespRcvd,
	dBoth,
	dNone
} EDirection;

typedef enum {
	DECREMENT,
	INCREMENT,
} Operation;

typedef enum {
	number_of_active_session,
	number_of_users,
	number_of_bearers,
	number_of_pdn_connections,
} SystemStats;

typedef enum {
	PCAP_GEN_OFF,
	PCAP_GEN_ON,
	PCAP_GEN_RESTART,

} PcapGenCmd;

/**
 * @brief  : Maintains dns configuration
 */
typedef struct dns_configuration_t {
	uint8_t freq_sec;
	char filename[PATH_LEN];
	uint8_t nameserver_cnt;
	char nameserver_ip[MAX_NUM_NAMESERVER][IPV6_STR_LEN];
} dns_configuration_t;


typedef struct {
	int msgtype;
	const char *msgname;
	EDirection dir;
	EDirection pgwc_dir;
} MessageType;

typedef struct {
	int cnt[2];
	char ts[LAST_TIMER_SIZE];
} Statistic;

/**
 * @brief  : Maintains peer address details
 */
typedef struct peer_address_t {

	uint8_t type;

	struct sockaddr_in ipv4;
	struct sockaddr_in6 ipv6;

} peer_address_t;

/**
 * @brief  : Maintains health request , response and interface stats for peers
 */
#pragma pack(1)
typedef struct {
	peer_address_t cli_peer_addr;
	EInterfaceType intfctype;

	bool status;
	int *response_timeout;
	int *maxtimeout;
	uint8_t timeouts;

	char lastactivity[LAST_TIMER_SIZE];

	int hcrequest[HEALTH_STATS_SIZE];
	int hcresponse[HEALTH_STATS_SIZE];
	union {
		Statistic s11[S11_STATS_SIZE];
		Statistic s5s8[S5S8_STATS_SIZE];
		Statistic sx[SX_STATS_SIZE];
		Statistic gx[GX_STATS_SIZE];
	} stats;
} SPeer;

/**
 * @brief  : Maintains CP-Configuration
 */
typedef struct {
	uint8_t cp_type;
	uint16_t s11_port;
	uint16_t s5s8_port;
	uint16_t pfcp_port;
	uint16_t dadmf_port;
	uint16_t ddf2_port;
	struct in_addr s11_ip;
	struct in_addr s5s8_ip;
	struct in_addr pfcp_ip;
	char dadmf_ip[IPV6_STR_LEN];
	char ddf2_ip[IPV6_STR_LEN];
	char ddf2_local_ip[IPV6_STR_LEN];
	uint16_t upf_pfcp_port;
	struct in_addr upf_pfcp_ip;
	uint16_t redis_port;
	char redis_ip_buff[IPV6_STR_LEN];
	char cp_redis_ip_buff[IPV6_STR_LEN];
	char redis_cert_path[REDIS_CERT_PATH_LEN];
	uint8_t request_tries;
	int request_timeout;
	uint8_t add_default_rule;
	uint8_t use_dns;
	uint32_t num_apn;
	struct apn_info_t apn_list[MAX_NUM_APN];
	int trigger_type;
	int uplink_volume_th;
	int downlink_volume_th;
	int time_th;
	struct dns_cache_parameters_t dns_cache;
	struct dns_configuration_t ops_dns;
	struct dns_configuration_t app_dns;
	struct restoration_params_t restoration_params;
	struct in_addr ip_pool_ip;
	struct in_addr ip_pool_mask;
	uint8_t generate_cdr;
	uint8_t generate_sgw_cdr;
	uint16_t sgw_cc;
	uint8_t ip_byte_order_changed;
	uint8_t use_gx;
	uint8_t perf_flag;
	uint8_t is_gx_interface;
	char dadmf_local_addr[IPV6_STR_LEN];
	uint16_t dl_buf_suggested_pkt_cnt;
	uint16_t low_lvl_arp_priority;
	struct in6_addr ipv6_network_id;
	uint8_t ipv6_prefix_len;
	uint8_t ip_allocation_mode;
	uint8_t ip_type_supported;
	uint8_t ip_type_priority;
	char cp_dns_ip_buff[IPV6_STR_LEN];
	struct in6_addr s11_ip_v6;
	struct in6_addr s5s8_ip_v6;
	struct in6_addr pfcp_ip_v6;
	struct in6_addr upf_pfcp_ip_v6;
	uint16_t cli_rest_port;
	char cli_rest_ip_buff[IPV6_STR_LEN];
} cp_configuration_t;

/**
 * @brief  : Maintains DP-Configuration
 */
typedef struct {
	uint8_t dp_type;
	uint32_t wb_ip;
	struct in6_addr wb_ipv6;
	uint8_t wb_ipv6_prefix_len;
	uint32_t wb_mask;
	uint32_t wb_port;
	uint32_t eb_ip;
	uint32_t eb_mask;
	uint32_t eb_port;
	uint8_t eb_ipv6_prefix_len;
	struct in6_addr eb_ipv6;
	uint32_t numa_on;
	int teidri_val;
	int teidri_timeout;
	uint8_t generate_pcap;
	uint8_t perf_flag;
	struct in_addr dp_comm_ip;
	struct in6_addr dp_comm_ipv6;
	uint8_t pfcp_ipv6_prefix_len;
	uint16_t dp_comm_port;
	struct restoration_params_t restoration_params;
	char ddf2_ip[IPV6_STR_LEN];
	char ddf3_ip[IPV6_STR_LEN];
	uint16_t ddf2_port;
	uint16_t ddf3_port;
	char ddf2_local_ip[IPV6_STR_LEN];
	char ddf3_local_ip[IPV6_STR_LEN];
	char wb_iface_name[MAX_LEN];
	char eb_iface_name[MAX_LEN];
	char wb_mac[MAC_BYTES_LEN];
	char eb_mac[MAC_BYTES_LEN];
	uint32_t wb_li_ip;
	struct in6_addr wb_li_ipv6;
	uint8_t wb_li_ipv6_prefix_len;
	char wb_li_iface_name[MAX_LEN];
	uint32_t wb_li_mask;
	char eb_li_iface_name[MAX_LEN];
	uint32_t eb_li_mask;
	uint32_t eb_li_ip;
	struct in6_addr eb_li_ipv6;
	uint8_t eb_li_ipv6_prefix_len;
	struct in6_addr eb_l3_ipv6;
	struct in6_addr wb_l3_ipv6;
	uint32_t wb_gw_ip;
	uint32_t eb_gw_ip;
	uint8_t gtpu_seqnb_out;
	uint8_t gtpu_seqnb_in;
	uint16_t cli_rest_port;
	char cli_rest_ip_buff[IPV6_STR_LEN];

} dp_configuration_t;

typedef struct li_df_config_t {

	/* Identifier */
	uint64_t uiId;

	/* Unique Ue Identity */
	uint64_t uiImsi;

	/* Signalling Interfaces */
	uint16_t uiS11;
	uint16_t uiSgwS5s8C;
	uint16_t uiPgwS5s8C;

	/* Sx Signalling Interfaces */
	uint16_t uiSxa;
	uint16_t uiSxb;
	uint16_t uiSxaSxb;

	/* Header OR Header + Data OR Data*/
	uint16_t uiS1uContent;
	uint16_t uiSgwS5s8UContent;
	uint16_t uiPgwS5s8UContent;
	uint16_t uiSgiContent;

	/* Data Interfaces */
	uint16_t uiS1u;
	uint16_t uiSgwS5s8U;
	uint16_t uiPgwS5s8U;
	uint16_t uiSgi;

	/* Forward to DFx */
	uint16_t uiForward;
} li_df_config_t;

/**
 * @brief  : Maintains GW-Callbacks
 */
typedef struct gw_adapter_callback_register {
	int8_t (*update_request_tries)(const int);
	int8_t (*update_request_timeout)(const int);
	int8_t (*update_periodic_timer)(const int);
	int8_t (*update_transmit_timer)(const int);
	int8_t (*update_transmit_count)(const int);
	int8_t (*update_pcap_status)(const int);
	int8_t (*update_perf_flag)(const int);
	int (*get_request_tries)(void);
	int (*get_request_timeout)(void);
	int (*get_periodic_timer)(void);
	int (*get_transmit_timer)(void);
	int (*get_transmit_count)(void);
	uint8_t (*get_perf_flag)(void);
	int8_t (*get_cp_config)(cp_configuration_t*);
	int8_t (*get_dp_config)(dp_configuration_t*);
	int8_t (*get_generate_pcap)(void);
	int8_t (*add_ue_entry)(li_df_config_t*, uint16_t);
	int8_t (*update_ue_entry)(li_df_config_t*, uint16_t);
	uint8_t (*delete_ue_entry)(uint64_t*, uint16_t);
} gw_adapter_callback_register;


/**
 * @brief  : Maintains CLI-config data
 */
typedef struct cli_config_t {
	int number_of_transmit_count;
	int number_of_request_tries;
	int transmit_timer_value;
	int periodic_timer_value;
	int request_timeout_value;
	uint8_t generate_pcap_status;
	int cnt_peer;
	int nbr_of_peer;
	uint64_t oss_reset_time;
	uint8_t perf_flag;
	cp_configuration_t cp_configuration;
	dp_configuration_t dp_configuration;
	gw_adapter_callback_register gw_adapter_callback_list;
} cli_config_t;

/**
 * @brief  : Maintains CLI-node data
 */
typedef struct {
	uint8_t gw_type;
	uint64_t *upsecs;
	uint64_t *resetsecs;
	uint8_t s5s8_selection;
	uint64_t stats[MAX_SYS_STATS];
	cli_config_t cli_config;
	SPeer *peer[MAX_PEER];
}cli_node_t;


#pragma pack()

/*Following variables also used in ngic-rtc*/

extern int s11MessageTypes[MAX_NUM_GW_MESSAGES];
extern int s5s8MessageTypes[MAX_NUM_GW_MESSAGES];
extern int sxMessageTypes[MAX_NUM_GW_MESSAGES];
extern int gxMessageTypes[MAX_NUM_GW_MESSAGES];
extern int supported_commands[CMD_LIST_SIZE][CMD_LIST_SIZE];

extern MessageType ossS5s8MessageDefs[];
extern MessageType ossS11MessageDefs[];
extern MessageType ossSxMessageDefs[];
extern MessageType ossGxMessageDefs[];
extern MessageType ossSystemMessageDefs[];
extern char ossInterfaceStr[][MAX_INTERFACE_NAME_LEN];
extern char ossInterfaceProtocolStr[][MAX_INTERFACE_NAME_LEN];
extern char ossGatewayStr[][MAX_GATEWAY_NAME_LEN];

extern uint64_t reset_time;

#endif
