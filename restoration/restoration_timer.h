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

#include <rte_ethdev.h>

#define S11_SGW_PORT_ID   0
#define S5S8_SGWC_PORT_ID 1
#define SX_PORT_ID        2
#define S5S8_PGWC_PORT_ID 3

#define OFFSET      2208988800ULL

typedef enum { False = 0, True } boolean;

typedef struct _gstimerinfo_t gstimerinfo_t;
typedef void (*gstimercallback)(gstimerinfo_t *ti, const void *data);

typedef enum {
	ttSingleShot,
	ttInterval
} gstimertype_t;

struct _gstimerinfo_t {
	timer_t           ti_id;
	gstimertype_t     ti_type;
	gstimercallback   ti_cb;
	int               ti_ms;
	const void       *ti_data;
};

#ifdef CP_BUILD

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
	/** Recovery Time */
	uint32_t rcv_time;
	/** Periodic Timer */
	gstimerinfo_t  pt;
	/** Transmit Timer */
	gstimerinfo_t  tt;
	const char    *name;
	//gtpv2c_header *buf;
} peerData;

#else

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

bool gst_init(void);

void gst_deinit(void);

bool gst_timer_init( gstimerinfo_t *ti, gstimertype_t tt,
			gstimercallback cb, int milliseconds, const void *data );

void gst_timer_deinit( gstimerinfo_t *ti );

bool gst_timer_setduration( gstimerinfo_t *ti, int milliseconds );

bool gst_timer_start( gstimerinfo_t *ti );

void gst_timer_stop( gstimerinfo_t *ti );

bool initpeerData( peerData *md, const char *name, int t1ms, int t2ms );

bool startTimer( gstimerinfo_t *ti );

void stopTimer( gstimerinfo_t *ti );

void deinitTimer( gstimerinfo_t *ti );

void _sleep( int seconds );

void timerCallback( gstimerinfo_t *ti, const void *data_t );

void del_entry_from_hash(uint32_t ipAddr);

const char *getPrintableTime(void);

uint8_t process_response(uint32_t dstIp);

void recovery_time_into_file(uint32_t recov_time);

#endif
