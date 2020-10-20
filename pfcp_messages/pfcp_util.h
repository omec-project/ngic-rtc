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

#ifndef PFCP_UTIL_H
#define PFCP_UTIL_H

#include <sys/sysinfo.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "gw_adapter.h"
#include "interface.h"

#ifdef CP_BUILD
#include "ue.h"
#include "gtp_messages.h"
#include "sm_struct.h"
#else
#define LDB_ENTRIES_DEFAULT (1024 * 512)
#endif /* CP_BUILD */

#ifdef CP_BUILD
#define S11_INTFC_IN						1
#define S11_INTFC_OUT						2
#define S5S8_C_INTFC_IN						3
#define S5S8_C_INTFC_OUT					4
#define SX_INTFC_IN						5
#define SX_INTFC_OUT						6
#endif /* CP_BUILD */

#define COPY_SIG_MSG_ON						2
#define SX_COPY_CP_MSG						1
#define SX_COPY_DP_MSG						2
#define SX_COPY_CP_DP_MSG					3

#define FRWDING_PLCY_SX						0
#define FRWDING_PLCY_WEST_DIRECTION			1
#define FRWDING_PLCY_WEST_CONTENT			2
#define FRWDING_PLCY_EAST_DIRECTION			3
#define FRWDING_PLCY_EAST_CONTENT			4
#define FRWDING_PLCY_FORWARD				5
#define FRWDING_PLCY_ID						6

extern uint32_t start_time;
extern struct rte_hash *node_id_hash;
extern struct rte_hash *heartbeat_recovery_hash;

#define QUERY_RESULT_COUNT 16
#define MAX_ENODEB_LEN     16
#define PFCP_MSG_LEN       4096

/*VS: Define the IPv6 Format Specifier to print IPv6 Address */
#define IPv6_CAST *(struct in6_addr *)
#define IPv6_FMT "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_PRINT(addr)\
		(unsigned)((addr).s6_addr[0]),\
		(unsigned)((addr).s6_addr[1]),\
		(unsigned)((addr).s6_addr[2]),\
		(unsigned)((addr).s6_addr[3]),\
		(unsigned)((addr).s6_addr[4]),\
		(unsigned)((addr).s6_addr[5]),\
		(unsigned)((addr).s6_addr[6]),\
		(unsigned)((addr).s6_addr[7]),\
		(unsigned)((addr).s6_addr[8]),\
		(unsigned)((addr).s6_addr[9]),\
		(unsigned)((addr).s6_addr[10]),\
		(unsigned)((addr).s6_addr[11]),\
		(unsigned)((addr).s6_addr[12]),\
		(unsigned)((addr).s6_addr[13]),\
		(unsigned)((addr).s6_addr[14]),\
		(unsigned)((addr).s6_addr[15])

/*This macro is used to print IPv6 address in string if IPv6 address is stored in uint8_t array*/
#define PRINT_IPV6_ADDR(addr)\
		(unsigned)(addr[0]),\
		(unsigned)(addr[1]),\
		(unsigned)(addr[2]),\
		(unsigned)(addr[3]),\
		(unsigned)(addr[4]),\
		(unsigned)(addr[5]),\
		(unsigned)(addr[6]),\
		(unsigned)(addr[7]),\
		(unsigned)(addr[8]),\
		(unsigned)(addr[9]),\
		(unsigned)(addr[10]),\
		(unsigned)(addr[11]),\
		(unsigned)(addr[12]),\
		(unsigned)(addr[13]),\
		(unsigned)(addr[14]),\
		(unsigned)(addr[15])


#ifdef CP_BUILD

#define FAILED_ENB_FILE "logs/failed_enb_queries.log"

typedef enum {
	NO_DNS_QUERY,
	ENODEB_BASE_QUERY,
	APN_BASE_QUERY,
	TAC_BASE_QUERY = 4
}dns_domain;
/**
 * @brief  : send DNS query
 * @param  : pdn, pdn connection context information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
push_dns_query(pdn_connection *pdn);

/**
 * @brief  : DNS callback.
 * @param  : node_sel, node selectore information
 * @param  : data, contain callback information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int dns_callback(void *node_sel, void *data, void *user_data);

#endif /* CP_BUILD */

/**
 * @brief  : Read data from peer node
 * @param  : msg_payload, buffer to store received data
 * @param  : size, max size to read data
 * @param  : peer_addr, peer node address
 * @return : Returns received number of bytes
 */
int
pfcp_recv(void *msg_payload, uint32_t size, peer_addr_t *peer_addr, bool is_ipv6);

/**
 * @brief  : Send data to peer node
 * @param  : fd_v4, IPv4 socket or file descriptor to use to send data
 * @param  : fd_v6, IPv6 socket or file descriptor to use to send data
 * @param  : msg_payload, buffer to store data to be send
 * @param  : size, max size to send data
 * @param  : peer_addr, peer node address
 * @return : Returns sent number of bytes
 */
int
pfcp_send(int fd_v4 , int fd_v6, void *msg_payload, uint32_t size,
		peer_addr_t peer_addr, Dir dir);

/**
 * @brief  : Returns system seconds since boot
 * @param  : No param
 * @return : Returns number of system seconds since boot
 */
long
uptime(void);

/**
 * @brief  : Creates node id hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_node_id_hash(void );

/**
 * @brief  : creates associated upf hash
 * @param  : No param
 * @return : Returns nothing
 */
void
create_associated_upf_hash(void );

/**
 * @brief  : Checks current ntp timestamp
 * @param  : No param
 * @return : Returns timestamp value
 */
uint32_t
current_ntp_timestamp(void);

/**
 * @brief  : Converts timeval to ntp format
 * @param  : tv, input timeval
 * @param  : ntp, converted ntp time
 * @return : Returns nothing
 */
void
time_to_ntp(struct timeval *tv, uint8_t *ntp);


/**
 * @brief  : Converts ntp time to unix/epoch(UTC) format
 * @param  : ntp, input ntp timeval
 * @param  : unix_tm, converted unix time
 * @return : Returns nothing
 */
void
ntp_to_unix_time(uint32_t *ntp, struct timeval *unix_tm);

/* VS: */
/**
 * @brief  : Validate the IP Address is in the subnet or not
 * @param  : addr, IP address for search
 * @param  : net_init, Starting value of the subnet
 * @param  : net_end, End value of the subnet
 * @return : Returns 1 if addr within the range, 0 not in the range
 * */
int
validate_Subnet(uint32_t addr, uint32_t net_init, uint32_t net_end);

/* VS: Validate the IPv6 Address is in the subnet or not */
/**
 * @brief  : Validate the IPv6 Address is in the network or not
 * @param  : addr, IP address for search
 * @param  : local_addr, Compare Network ID
 * @param  : local_prefix, Network bits
 * @return : Returns 1 if addr within the range, 0 not in the range
 * */
int
validate_ipv6_network(struct in6_addr addr,
		struct in6_addr local_addr, uint8_t local_prefix);

/**
 * @brief  : Retrieve the IPv6 Network Prefix Address
 * @param  : local_addr, Compare Network ID
 * @param  : local_prefix, Network bits
 * @return : Returns Prefix
 * */
struct in6_addr
retrieve_ipv6_prefix(struct in6_addr addr, uint8_t local_prefix);

/**
 * @brief  : Retrive UE Database From SEID and If require copy the message to LI server
 * @param  : sess_id, key for search
 * @param  : buf_tx, message to copy to LI server
 * @param  : buf_tx_size, message size
 * @return : Returns 0 in case of success , -1 otherwise
 */
#ifdef CP_BUILD
/**
 * @brief  : Check LI is enabled or not
 * @param  : li_data, li_data information from context
 * @param  : intfc_name, interface name
 * @return : Returns 1 if yes, 0 otherwise
 */
uint8_t
is_li_enabled(li_data_t *li_data, uint8_t intfc_name, uint8_t cp_type);

/**
 * @brief  : Check LI is enabled or not using imsi
 * @param  : uiImsi, IMSI of UE
 * @param  : intfc_name, interface name
 * @return : Returns 1 if yes, 0 otherwise
 */
uint8_t
is_li_enabled_using_imsi(uint64_t uiImsi, uint8_t intfc_name, uint8_t cp_type);

/**
 * @brief  : Process li message
 * @param  : sess_id, session id
 * @param  : intfc_name, interface name
 * @param  : buf_tx
 * @param  : buf_tx_size, size of buf_tx
 * @param  : srcIp, source ip address
 * @param  : dstIp, destination ip address
 * @param  : uiSrcPort, source port number
 * @param  : uiDstPort, destination port number
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_cp_li_msg(uint64_t sess_id, uint8_t intfc_name, uint8_t *buf_tx,
		int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort,
		uint16_t uiDstPort);

/**
 * @brief  : Process messages for li
 * @param  : context, ue context details
 * @param  : intfc_name, interface name
 * @param  : msg, msg_info structure
 * @param  : srcIp, source ip address
 * @param  : dstIp, destination ip address
 * @param  : uiSrcPort, source port number
 * @param  : uiDstPort, destination port number
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_msg_for_li(ue_context *context, uint8_t intfc_name, msg_info *msg,
		struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort, uint16_t uiDstPort);

/**
 * @brief  : Process li message. Sender must check li is enabled or not
 * @param  : li_data, configurations for li
 * @param  : uiLiDataCntr, Number of li entries for single ue
 * @param  : intfc_name, interface name
 * @param  : buf_tx
 * @param  : buf_tx_size, size of buf_tx
 * @param  : srcIp, source ip address
 * @param  : dstIp, destination ip address
 * @param  : uiSrcPort, source port number
 * @param  : uiDstPort, destination port number
 * @param  : uiCpMode, control plane mode
 * @param  : uiImsi, imsi of ue
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_cp_li_msg_for_cleanup(li_data_t *li_data, uint8_t li_data_cntr, uint8_t intfc_name,
		uint8_t *buf_tx, int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp,
		uint16_t uiSrcPort, uint16_t uiDstPort, uint8_t uiCpMode, uint64_t uiImsi);

/**
 * @brief  : Process packet for li.
 * @param  : context, context of ue
 * @param  : intfc_name, interface name
 * @param  : buf_tx, packet
 * @param  : buf_tx_size, size of buf_tx
 * @param  : srcIp, source ip address
 * @param  : dstIp, destination ip address
 * @param  : uiSrcPort, source port number
 * @param  : uiDstPort, destination port number
 * @param  : uiForward, forward to df2 or not
 * @return : Returns 0 on success, -1 otherwise
 */
int
process_pkt_for_li(ue_context *context, uint8_t intfc_name, uint8_t *buf_tx,
		int buf_tx_size, struct ip_addr srcIp, struct ip_addr dstIp, uint16_t uiSrcPort,
		uint16_t uiDstPort);

#endif /* CP_BUILD */

#endif /* PFCP_UTIL_H */
