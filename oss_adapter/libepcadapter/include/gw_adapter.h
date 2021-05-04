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

#ifndef __NGIC_GW_ADAPTER_H__
#define __NGIC_GW_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include "gw_structs.h"

#define STANDARD_LOGID               (1)
#define STATS_LOGID                  (2)
#define CLI_STATS_TIMER_INTERVAL     (5000)
#define MAX_UINT16_T				 (65535)
/* Single curl command has maximum UE entry limit */
#define MAX_LI_ENTRIES				 (255)
#define FALSE                        (0)
#define TRUE                         (1)
#define PERF_ON						 (1)
#define PERF_OFF					 (0)
#define __file__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#define LOG_FORMAT "%s:%s:%d:"
#define LOG_VALUE __file__, __func__, __LINE__
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
 }                                                                           \
 ns;                                                                          \
 })

extern _timer_t st_time;
extern cli_node_t cli_node;
extern cli_node_t *cli_node_ptr;

enum CLogType {
	eCLTypeBasicFile,
	eCLTypeSysLog,
	eCLTypeRotatingFile,
	eCLTypeStdOut,
	eCLTypeStdErr
};

enum CLoggerSeverity {
	eCLSeverityDebug,
	eCLSeverityInfo,
	eCLSeverityStartup,
	eCLSeverityMinor,
	eCLSeverityMajor,
	eCLSeverityCritical
};

enum CLoggerLogLevel
{
	eCLogLevelDebug = 0,
	eCLogLevelInfo,
	eCLogLevelStartup,
	eCLogLevelMinor,
	eCLogLevelMajor,
	eCLogLevelCritical,
	eCLogLevelOff,
};

/* Function */
/**
 * @brief  : init log module
 * @param  : name, name of file
 * @return : Returns 0 on success else -1
 */
int8_t init_log_module(const char *name);

/* Function */
/**
 * @brief  : clLog for logging
 * @param  : logid, logid
 * @param  : sev, Severity of logging
 * @param  : fmt, logger string params for printing
 * @return : Returns nothing
 */
void clLog(const int logid, enum CLoggerSeverity sev, const char *fmt, ...);

/* Function */
/**
 * @brief  : init rest framework
 * @param  : cli_rest_ip, ip for rest http request
 * @param  : cli_rest_port, port for rest http request
 * @return : Returns 0 on success else -1
 */
int8_t init_rest_framework(char *cli_rest_ip, uint16_t cli_rest_port);

/* Function */
/**
 * @brief  : Updates the cli stats as per the interface and direction
 * @param  : ip_addr,
 * @param  : msg_type, Type of message
 * @param  : dir, Direction of message on interface
 * @param  : it, interface of the message
 * @return : Returns 0 on success , otherwise -1
 */
int update_cli_stats(peer_address_t *cli_peer_addr, uint8_t mgs_type, int dir, CLIinterface it);

/* Function */
/**
 * @brief  : Adds information about peer gateway
 * @param  : ip_addr, ip address of peer gateway
 * @param  : it, interface of the message
 * @return : Returns nothing
 */
void add_cli_peer(peer_address_t *cli_peer_addr, CLIinterface it);

/* Function */
/**
 * @brief  : gives index of the peer gateway ip
 * @param  : ip_addr, ip address of peer gateway
 * @return : Returns index on success, otherwise -1
 */
int get_peer_index(peer_address_t *cli_peer_addr);

/* Function */
/**
 * @brief  : updates alive status of peer
 * @param  : ip_addr, ip address of peer gateway
 * @param  : val, boolean value of status
 * @return : Returns 0 on success, otherwise -1
 */
int update_peer_status(peer_address_t *cli_peer_addr, bool val);

/* Function */
/**
 * @brief  : updates timeout counter
 * @param  : ip_addr, ip address of peer gateway
 * @param  : val, timeout counter
 * @return : Returns 0 on success, otherwise -1
 */
int update_peer_timeouts(peer_address_t *cli_peer_addr, uint8_t val);

/* Function */
/**
 * @brief  : deletes peer gateway
 * @param  : ip_addr, ip address of peer gateway
 * @return : Returns 0 on success, otherwise -1
 */
int delete_cli_peer(peer_address_t *cli_peer_addr);

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
int update_last_activity(peer_address_t *cli_peer_addr, char *time_stamp);

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
 * @brief  : checks if command is suppported for respective gateway
 * @param  : cmd_number, command number
 * @return : Returns true if supported, otherwise false
 */
bool is_cmd_supported(int cmd_number);

/* Function */
/**
 * @brief  : get type of gateway
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
 * @brief  : set mac value
 * @param  : mac char ptr
 * @param  : mac int ptr
 * @return : Returns nothing
 */
void set_mac_value(char *mac_addr_char_ptr, uint8_t *mac_addr_int_ptr);

/* Function */
/**
 * @brief  : init stats timer
 * @param  : void
 * @return : Returns nothing
 */
void init_stats_timer(void);

/* Function */
/**
 * @brief  : set gateway type
 * @param  : gateway_type, type of gateway
 * @return : Returns nothing
 */
void set_gw_type(uint8_t gateway_type);

/* Function */
/**
 * @brief  : get stat live
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_stat_live(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get periodic timer
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_pt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get transmit timer
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_tt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get transmit count
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_tc(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get request tries
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_rt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get request timeout
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_rto(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get perf flag
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_pf(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get generate pcap status
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_generate_pcap_status(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get stat logging
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_stat_logging(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get configuration
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_configuration(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get stat live all
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_stat_live_all(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : get stat frequency
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int get_stat_frequency(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post periodic timer
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_pt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post transmit timer
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_tt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post transmit count
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_tc(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post request tries
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_rt(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post request timeout
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_rto(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post generate pcap cmd
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_generate_pcap_cmd(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post stat logging
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_stat_logging(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : post reset stats cmd
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int reset_cli_stats(const char *request_body, char **response_body);

/* Function */
/**gateway
 * @brief  : post stat frequency
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_stat_frequency(const char *request_body, char **response_body);

/* Function */
/**gateway
 * @brief  : post perf flag value
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int post_pf(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : add ue entry details
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int add_ue_entry_details(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : update ue entry details
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int update_ue_entry_details(const char *request_body, char **response_body);

/* Function */
/**
 * @brief  : delete ue entry details
 * @param  : request_body, http request body
 * @param  : response_body, http response body
 * @return : Returns status code
 */
int delete_ue_entry_details(const char *request_body, char **response_body);

#ifdef __cplusplus
}
#endif

#endif  /* __NGIC_GW_ADAPTER_H__ */
