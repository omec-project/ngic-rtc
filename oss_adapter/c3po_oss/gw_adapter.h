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

/* TODO: Verify */
#ifdef CP_BUILD
#include "cp.h"
#endif /* CP_BUILD */

#define REST_SUCESSS  200
#define REST_FAIL     400
#define LAST_TIMER_SIZE 128
#define JSON_RESP_SIZE 512
#define SXA_STATS_SIZE 21
#define SXB_STATS_SIZE 23
#define SXASXB_STATS_SIZE 23
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
#define NWINST_LEN 32
#define MAX_SYS_STATS 5

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
#define SXA_MSG_TYPE_LEN       21
#define SXB_MSG_TYPE_LEN       23
#define SXASXB_MSG_TYPE_LEN    23
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
#define GTP_PGW_RESTART_NOTIFICATION                         (179)
#define GTP_PGW_RESTART_NOTIFICATION_ACK                     (180)

#define MAX_UINT16_T										65535

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
	OSS_SGWC = 01,
	OSS_PGWC = 02,
	OSS_SAEGWC = 03,
	OSS_SGWU = 04,
	OSS_PGWU = 05,
	OSS_SAEGWU = 06
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
	itSxa,
	itSxb,
	itSxaSxb,
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
typedef struct {
	struct in_addr ipaddr;
	EInterfaceType intfctype;

	bool status;
	int *response_timeout;  //TRANSMIT TIMER
	int *maxtimeout;    //TRANSMIT COUNT in cp.cfg
	uint8_t timeouts;

	char lastactivity[LAST_TIMER_SIZE];

	int hcrequest[HEALTH_STATS_SIZE];
	int hcresponse[HEALTH_STATS_SIZE];
	union {
		Statistic s11[S11_STATS_SIZE];
		Statistic s5s8[S5S8_STATS_SIZE];
		Statistic sxa[SXA_STATS_SIZE];
		Statistic sxb[SXB_STATS_SIZE];
		Statistic sxasxb[SXASXB_STATS_SIZE];
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
	//uint64_t upsecs;
	uint64_t stats[MAX_SYS_STATS];
	SPeer *peer[MAX_PEER];
}cli_node_t;

/**
 * @brief  : Maintains LI-DF configuration value
 */
typedef struct li_df_config_t {
	uint64_t uiImsi;
	uint16_t uiOperation;
	uint16_t uiAction;
	struct in_addr ddf2_ip;
	uint16_t uiDDf2Port;
	struct in_addr ddf3_ip;
	uint16_t uiDDf3Port;
	uint64_t uiTimerValue;

}li_df_config_t;

extern cli_node_t cli_node;
extern uint64_t reset_time;

//extern SPeer *peer[MAX_PEER];
extern int cnt_peer;  /*last index of array*/
extern int nbr_of_peer; /*total nbr of peer count*/

extern int number_of_transmit_count;
extern int number_of_request_tries;
extern int transmit_timer_value;
extern int periodic_timer_value;
extern int request_timeout_value;
extern cli_node_t *cli_node_ptr; // OSS cli node ptr
extern struct rte_hash *conn_hash_handle;

extern MessageType ossS5s8MessageDefs[];
extern MessageType ossS11MessageDefs[];
extern MessageType ossSxaMessageDefs[];
extern MessageType ossSxbMessageDefs[];
extern MessageType ossSxaSxbMessageDefs[];
extern MessageType ossGxMessageDefs[];
extern MessageType ossSystemMessageDefs[];
extern char ossInterfaceStr[][10];
extern char ossInterfaceProtocolStr[][10];
extern char ossGatewayStr[][10];
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
#endif
