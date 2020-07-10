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
#ifndef GW_ADAPTER_H
#define GW_ADAPTER_H

#ifdef CP_BUILD
#include "cp.h"
#endif /* CP_BUILD */

#define REST_SUCESSS  200
#define REST_FAIL     400
#define LAST_TIMER_SIZE 128
#define JSON_RESP_SIZE 512
#define SX_STATS_SIZE 23
#define S11_STATS_SIZE 51
#define S5S8_STATS_SIZE 37
#define GX_STATS_SIZE 23
#define ENTRY_VALUE_SIZE 64
#define ENTRY_NAME_SIZE 64
#define LINE_SIZE 256
#define CMD_LIST_SIZE 10
#define MAC_ADDR_LEN 64
#define MAX_LEN  128
#define ENODE_LEN 16
#define MCC_MNC_LEN 4
#define LB_HB_LEN 8
#define MAX_SYS_STATS 5
#define DDF_INTFC_LEN 64
#define MAX_NUM_NAMESERVER 8
#define NETCAP_LEN 64
#define MAC_BYTES_LEN 32
#define MAX_NUM_APN 16
#define INET_ADDRSTRLEN 16
#define PATH_LEN 64
#define APN_NAME_LEN 64
#define DNS_IP_INDEX 1
#define MAC_ADDR_BYTES_IN_INT_ARRAY 6
#define FOUR_BIT_MAX_VALUE 15
#define REDIS_CERT_PATH_LEN 256
#define SGW_CHARGING_CHARACTERISTICS 2
#define CLI_GX_IP "127.0.0.1"
/**
 * @brief initiates the rest service
 * @param port_no  - Rest service port number
 * @param thread_count - number of threads
 * @return void
 */
void init_rest_methods(int port_no, size_t thread_count);
int change_config_file(const char *path, const char *param, const char *value);

typedef long long int _timer_t;

#define TIMER_GET_CURRENT_TP(now)                                             \
({                                                                            \
 struct timespec ts;                                                          \
 now = clock_gettime(CLOCK_REALTIME,&ts) ?                                    \
 	-1 : (((_timer_t)ts.tv_sec) * 1000000000) + ((_timer_t)ts.tv_nsec);   \
 now;                                                                         \
 })

#define TIMER_GET_ELAPSED_NS(start)                                           \
({                                                                            \
 _timer_t ns;                                                                 \
 TIMER_GET_CURRENT_TP(ns);                                                    \
 if (ns != -1){                                                               \
 	ns -= start;                                                          \
 }									      \
 ns;                                                                          \
 })

extern _timer_t st_time;


/////////////////////////////////////////////////////////////////////////////////////////

#define MAX_PEER               10
#define S11_MSG_TYPE_LEN       49
#define S5S8_MSG_TYPE_LEN      35
#define SX_MSG_TYPE_LEN    23
#define GX_MSG_TYPE_LEN        8
#define SYSTEM_MSG_TYPE_LEN    4
#define HEALTH_STATS_SIZE      2

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

#define MAX_UINT16_T										65535

/* Single curl command has maximum UE entry limit */
#define MAX_LI_ENTRIES										255

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
	// REQ = 0,
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
	PERIODIC_TIMER_INDEX,
	TRANSMIT_TIMER_INDEX,
	TRANSMIT_COUNT_INDEX,
	REQUEST_TIMEOUT_INDEX,
	REQUEST_TRIES_INDEX,
} SystemCmds;

typedef enum {
	STOP_PCAP_GEN,
	START_PCAP_GEN,
	RESTART_PCAP_GEN

} PcapGenCmd;

typedef struct {
	int msgtype;
	const char *msgname;
	EDirection dir;
} MessageType;

typedef struct {
	int cnt[2];
	//time_t ts;
	char ts[LAST_TIMER_SIZE];
} Statistic;

#define FALSE 0
#define TRUE 1


/**
 * @brief  : Maintains health request , response and interface stats for peers
 */
#pragma pack(1)
typedef struct {
	struct in_addr ipaddr;
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

/*
 * 0 --> active sessions
 * 1 --> Nbr-of-ues
 * 2 --> Nbr-of-pdn-conn
 * & so on.
 */

/**
 * @brief  : Maintains CLI-node data
 */
typedef struct {
	uint8_t gw_type;
	uint64_t *upsecs;
	uint64_t *resetsecs;
	uint8_t s5s8_selection;
	//uint64_t upsecs;
	uint64_t stats[MAX_SYS_STATS];
	SPeer *peer[MAX_PEER];
}cli_node_t;

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

/**
 * @brief  : Maintains dns configuration
 */
typedef struct dns_configuration_t {
	uint8_t freq_sec;
	char filename[PATH_LEN];
	uint8_t nameserver_cnt;
	char nameserver_ip[MAX_NUM_NAMESERVER][INET_ADDRSTRLEN];
} dns_configuration_t;

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
} apn_info_t;

/**
* @brief  : Maintains restoration parameters information
*/
typedef struct restoration_params_t {
	uint8_t transmit_cnt;
	int transmit_timer;
	int periodic_timer;
} restoration_params_t;

/**
 * @brief  : Maintains CP-Configuration
 */
typedef struct {
	uint8_t cp_type;
	uint16_t s11_mme_port;
	struct in_addr s11_mme_ip;
	char ddf2_intfc[DDF_INTFC_LEN];
	uint16_t s11_port;
	uint16_t s5s8_port;
	uint16_t pfcp_port;
	uint16_t dadmf_port;
	uint16_t ddf2_port;
	struct in_addr s11_ip;
	struct in_addr s5s8_ip;
	struct in_addr pfcp_ip;
	struct in_addr dadmf_ip;
	struct in_addr ddf2_ip;
	uint16_t upf_pfcp_port;
	struct in_addr upf_pfcp_ip;
	uint16_t redis_port;
	struct in_addr redis_ip;
	struct in_addr cp_redis_ip;
	char redis_cert_path[REDIS_CERT_PATH_LEN];
	uint8_t request_tries;
	int request_timeout;
	uint8_t add_default_rule;
	uint8_t cp_logger;
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
	uint32_t upf_s5s8_ip;
	uint32_t upf_s5s8_mask;
	uint8_t is_gx_interface;
	struct in_addr dadmf_local_addr;
}cp_configuration_t;

/**
 * @brief  : Maintains DP-Configuration
 */
typedef struct {
	uint8_t dp_type;
	uint32_t wb_ip;
	uint32_t wb_mask;
	uint32_t wb_port;
	uint32_t eb_ip;
	uint32_t eb_mask;
	uint32_t eb_port;
	uint32_t numa_on;
	int teidri_val;
	int teidri_timeout;
	uint8_t dp_logger;
	uint8_t generate_pcap;
	struct in_addr dp_comm_ip;
	struct in_addr cp_comm_ip;
	uint16_t dp_comm_port;
	uint16_t cp_comm_port;
	struct restoration_params_t restoration_params;
	uint32_t ddf2_ip;
	uint32_t ddf3_ip;
	uint16_t ddf2_port;
	uint16_t ddf3_port;
	char ddf2_intfc[DDF_INTFC_LEN];
	char ddf3_intfc[DDF_INTFC_LEN];
	char ddf_intfc[DDF_INTFC_LEN];
	char wb_iface_name[MAX_LEN];
	char eb_iface_name[MAX_LEN];
	char wb_mac[MAC_BYTES_LEN];
	char eb_mac[MAC_BYTES_LEN];
	uint32_t wb_li_ip;
	uint32_t wb_li_mask;
	uint8_t gtpu_seqnb_out;
	uint8_t gtpu_seqnb_in;
	char wb_li_iface_name[MAX_LEN];
}dp_configuration_t;

/**
 * @brief  : Maintains LI-DF configuration value
 */
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

}li_df_config_t;

#pragma pack()

extern cli_node_t cli_node;
extern uint64_t reset_time;
extern cp_configuration_t cp_configuration;
extern dp_configuration_t dp_configuration;

extern struct in_addr dp_comm_ip;
extern struct in_addr cp_comm_ip;
extern uint16_t dp_comm_port;
extern uint16_t cp_comm_port;

/* last index of array */
extern int cnt_peer;
/* total nbr of peer count */
extern int nbr_of_peer;

extern int number_of_transmit_count;
extern int number_of_request_tries;
extern int transmit_timer_value;
extern int periodic_timer_value;
extern int request_timeout_value;
extern cli_node_t *cli_node_ptr;
extern struct rte_hash *conn_hash_handle;

extern MessageType ossS5s8MessageDefs[];
extern MessageType ossS11MessageDefs[];
extern MessageType ossSxMessageDefs[];
extern MessageType ossGxMessageDefs[];
extern MessageType ossSystemMessageDefs[];
extern char ossInterfaceStr[][10];
extern char ossInterfaceProtocolStr[][10];
extern char ossGatewayStr[][16];
extern uint64_t oss_reset_time;

#ifdef CP_BUILD
extern pfcp_config_t pfcp_config;
#else /* DP_BUILD */
extern struct app_params app;
#endif /* CP_BUILD */


/* Function */
/**
 * @brief  : Initializes the cli module
 * @param  : gw_logger, type of gateway
 * @return : Returns nothing
 */
void init_cli_module(uint8_t gw_logger);

/* Function */
/**
 * @brief  : Updates the cli stats as per the interface and direction
 * @param  : ip_addr,
 * @param  : msg_type, Type of message
 * @param  : dir, Direction of message on interface
 * @param  : it, interface of the message
 * @return : Returns 0 on success , otherwise -1
 */
int update_cli_stats(uint32_t ip_addr, uint8_t mgs_type, int dir, CLIinterface it);

/* Function */
/**
 * @brief  : Adds information about peer gateway
 * @param  : ip_addr, ip address of peer gateway
 * @param  : it, interface of the message
 * @return : Returns nothing
 */
void add_cli_peer(uint32_t ip_addr,CLIinterface it);

/* Function */
/**
 * @brief  : gives index of the peer gateway ip
 * @param  : ip_addr, ip address of peer gateway
 * @return : Returns index on success, otherwise -1
 */
int get_peer_index(uint32_t ip_addr);

/* Function */
/**
 * @brief  : updates alive status of peer
 * @param  : ip_addr, ip address of peer gateway
 * @param  : val, boolean value of status
 * @return : Returns 0 on success, otherwise -1
 */
int update_peer_status(uint32_t ip_addr,bool val);

/* Function */
/**
 * @brief  : updates timeout counter
 * @param  : ip_addr, ip address of peer gateway
 * @param  : val, timeout counter
 * @return : Returns 0 on success, otherwise -1
 */
int update_peer_timeouts(uint32_t ip_addr,uint8_t val);

/* Function */
/**
 * @brief  : deletes peer gateway
 * @param  : ip_addr, ip address of peer gateway
 * @return : Returns 0 on success, otherwise -1
 */
int delete_cli_peer(uint32_t ip_addr);

/* Function */
/**
 * @brief  : finds first position of peer gateway
 * @param  : void
 * @return : Returns index of peer in an array on success, otherwise 0
 */
int get_first_index(void);

/* Function */
/**
 * @brief  : updates timestamp of the peer gateway
 * @param  : ip_addr, ip address of peer gateway
 * @param  : timestamp, timestamp of the moment
 * @return : Returns 0 on success, otherwise -1
 */
int update_last_activity(uint32_t ip_addr, char *time_stamp);

/* Function */
/**
 * @brief  : updates count of system or users
 * @param  : index, type of system
 * @param  : operation, operation value
 * @return : Returns 0
 */
int update_sys_stat(int index, int operation);

/* Function */
/**
 * @brief  : retrieves current time
 * @param  : last_time_stamp, last timestamp
 * @return : Returns nothing
 */
void get_current_time_oss(char *last_time_stamp);

/* Function */
/**
 * @brief  : checks if activity has updated or not
 * @param  : msg_type, message type
 * @param  : it, interface type
 * @return : Returns true on success otherwise false
 */
bool is_last_activity_update(uint8_t msg_type, CLIinterface it);

/* Function */
/**
 * @brief  : update value of periodic timer
 * @param  : periodic_timer_value, value of periodic timer
 * @return : Returns 0
 */
int update_periodic_timer_value(int periodic_timer_value);

/* Function */
/**
 * @brief  : update value of transmit timer
 * @param  : transmit_timer_value, value of transmit timer
 * @return : Returns 0
 */
int update_transmit_timer_value(int transmit_timer_value);

/* Function */
/**
 * @brief  : resets stats value of peer nodes
 * @param  : void
 * @return : Returns 0
 */
int reset_stats(void);

/* Function */
/**
 * @brief  : checks if command is suppported for respective gateway
 * @param  : cmd_number, command number
 * @return : Returns true if supported, otherwise false
 */
bool is_cmd_supported(int cmd_number);

/* Function */
/**
 * @brief  : recieves type of gateway
 * @param  : void
 * @return : Returns type of gateway
 */
uint8_t get_gw_type(void);

/* Function */
/**
 * @brief  : reset the dp system stats
 * @param  : void
 * @return : Returns nothing
 */
void reset_sys_stat(void);

/* Function */
/**
 * @brief  : fill cp configuration
 * @param  : void
 * @return : Returns nothing
 */
void fill_cp_configuration(void);

/* Function */
/**
 * @brief  : fill dp configuration
 * @param  : void
 * @return : Returns nothing
 */
void fill_dp_configuration(void);

/* Function */
/**
 * @brief  : set mac value
 * @param  : mac char ptr
 * @param  : mac int ptr
 * @return : Returns nothing
 */
void set_mac_value(char *mac_addr_char_ptr, uint8_t *mac_addr_int_ptr);
#endif
