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

#ifndef __GSTIMER_H
#define __GSTIMER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef DP_BUILD
#include <rte_ethdev.h>
#endif

#define S11_SGW_PORT_ID   0
#define S5S8_SGWC_PORT_ID 1
#define SX_PORT_ID        2
#define S5S8_PGWC_PORT_ID 3

#define OFFSET      2208988800ULL

/**
 * @brief  : Numeric value for true and false
 */
typedef enum { False = 0, True } boolean;

/**
 * @brief  : Maintains timer related information
 */
typedef struct _gstimerinfo_t gstimerinfo_t;

/**
 * @brief  : function pointer to timer callback
 */
typedef void (*gstimercallback)(gstimerinfo_t *ti, const void *data);

/**
 * @brief  : Maintains timer type
 */
typedef enum {
	ttSingleShot,
	ttInterval
} gstimertype_t;

/**
 * @brief  : Maintains timer related information
 */
struct _gstimerinfo_t {
	timer_t           ti_id;
	gstimertype_t     ti_type;
	gstimercallback   ti_cb;
	int               ti_ms;
	const void       *ti_data;
};

#ifdef CP_BUILD

/**
 * @brief  : Maintains peer node related information for control plane
 */
typedef struct {
	/** S11 || S5/S8 || Sx port id */
	uint8_t portId;
	/** In-activity Flag */
	uint8_t activityFlag;
	/** Number of Iteration */
	uint8_t itr;
	/** Iteration Counter */
	uint8_t itr_cnt;
	/** Dst Addr */
	uint32_t dstIP;
	/* Dst port */
	uint16_t dstPort;
	/** Recovery Time */
	uint32_t rcv_time;
	/** Periodic Timer */
	gstimerinfo_t  pt;
	/** Transmit Timer */
	gstimerinfo_t  tt;
	const char    *name;
	/* Teid */
	uint32_t teid;
	/*ebi ID */
	uint8_t ebi_index;
	uint16_t buf_len;
	uint8_t buf[1024];
} peerData;

#else

/**
 * @brief  : Maintains peer node related information for data plane
 */
typedef struct {
	/** UL || DL || Sx port id */
	uint8_t portId;
	/** In-activity Flag */
	uint8_t activityFlag;
	/** Number of Iteration */
	uint8_t itr;
	/** Iteration Counter */
	uint8_t itr_cnt;
	/** GTP-U response Counter */
	uint32_t rstCnt;
	/** Session Counter */
	uint32_t sess_cnt;
	/** Set of Session IDs */
	uint64_t sess_id[3200];
	/** src ipv4 address */
	uint32_t srcIP;
	/** dst ipv4 address */
	uint32_t dstIP;
	/** Recovery Time */
	uint32_t rcv_time;
	/** src ether address */
	struct ether_addr src_eth_addr;
	/** dst ether address */
	struct ether_addr dst_eth_addr;
	/** Periodic Timer */
	gstimerinfo_t  pt;
	/** Transmit Timer */
	gstimerinfo_t  tt;
	/** Name String */
	const char    *name;
	//struct rte_mbuf *buf;

} peerData;

#endif

/* Configured start/up time of component */
/*	extern uint32_t up_time;
	uint32_t current_ntp_timestamp(void);
*/

/**
 * @brief  : start the timer thread and wait for _timer_tid to be populated
 * @param  : No param
 * @return : Returns true in case of success , false otherwise
 */
bool gst_init(void);

/**
 * @brief  : Stop the timer handler thread
 * @param  : No param
 * @return : Returns nothing
 */
void gst_deinit(void);

/**
 * @brief  : Initialize timer with provided information
 * @param  : ti, timer structure to be initialized
 * @param  : cb, timer callback function
 * @param  : milliseconds, timeout in milliseconds
 * @param  : data, timer data
 * @return : Returns true in case of success , false otherwise
 */
bool gst_timer_init( gstimerinfo_t *ti, gstimertype_t tt,
			gstimercallback cb, int milliseconds, const void *data );

/**
 * @brief  : Delete timer
 * @param  : ti, holds information about timer to be deleted
 * @return : Returns nothing
 */
void gst_timer_deinit( gstimerinfo_t *ti );

/**
 * @brief  : Set timeout in timer
 * @param  : ti, holds information about timer
 * @param  : milliseconds, timeout in milliseconds
 * @return : Returns true in case of success , false otherwise
 */
bool gst_timer_setduration( gstimerinfo_t *ti, int milliseconds );

/**
 * @brief  : Start timer
 * @param  : ti, holds information about timer
 * @return : Returns true in case of success , false otherwise
 */
bool gst_timer_start( gstimerinfo_t *ti );

/**
 * @brief  : Stop timer
 * @param  : ti, holds information about timer
 * @return : Returns nothing
 */
void gst_timer_stop( gstimerinfo_t *ti );

/**
 * @brief  : Intialize peer node information
 * @param  : md, Peer node information
 * @param  : name, Peer node name
 * @param  : t1ms, periodic timer interval
 * @param  : t2ms, transmit timer interval
 * @return : Returns true in case of success , false otherwise
 */
bool initpeerData( peerData *md, const char *name, int t1ms, int t2ms );

/**
 * @brief  : Start timer
 * @param  : ti, holds information about timer
 * @return : Returns true in case of success , false otherwise
 */
bool startTimer( gstimerinfo_t *ti );

/**
 * @brief  : Stop timer
 * @param  : ti, holds information about timer
 * @return : Returns nothing
 */
void stopTimer( gstimerinfo_t *ti );

/**
 * @brief  : Delete timer
 * @param  : ti, holds information about timer
 * @return : Returns nothing
 */
void deinitTimer( gstimerinfo_t *ti );

/**
 * @brief  : Delay calling process for a given amount of time
 * @param  : seconds, timer interval
 * @return : Returns nothing
 */
void _sleep( int seconds );

/**
 * @brief  : Timer callback
 * @param  : ti, holds information about timer
 * @param  : data_t, Peer node related information
 * @return : Returns nothing
 */
void timerCallback( gstimerinfo_t *ti, const void *data_t );

/**
 * @brief  : Delete entry from connection table
 * @param  : ipAddr, key to search entry to be deleted
 * @return : Returns nothing
 */
void del_entry_from_hash(uint32_t ipAddr);

/**
 * @brief  : Convert time into printable format
 * @param  : No param
 * @return : Returns nothing
 */
const char *getPrintableTime(void);

/**
 * @brief  : Reset the periodic timers
 * @param  : dstIp, Peer node ip address
 * @return : Returns nothing
 */
uint8_t process_response(uint32_t dstIp);

/**
 * @brief  : Add entry for recovery time into heartbeat recovery file
 * @param  : recov_time, recovery time
 * @return : Returns nothing
 */
void recovery_time_into_file(uint32_t recov_time);

/**
 * @brief  : Initialize timer
 * @param  : md, Peer node information
 * @param  : t1ms, periodic timer interval
 * @param  : cb, timer callback function
 * @return : Returns true in case of success , false otherwise
 */
bool init_timer(peerData *md, int ptms, gstimercallback cb);

/**
 * @brief  : Start timer
 * @param  : ti, holds information about timer
 * @return : Returns true in case of success , false otherwise
 */
bool starttimer( gstimerinfo_t *ti );

/**
 * @brief  : Stop timer
 * @param  : tid, timer id
 * @return : Returns nothing
 */
void stoptimer(timer_t *tid);

/**
 * @brief  : Delete timer
 * @param  : tid, timer id
 * @return : Returns nothing
 */
void deinittimer(timer_t *tid);

#endif
