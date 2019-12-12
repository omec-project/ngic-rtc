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

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <semaphore.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#include "restoration_timer.h"

#ifdef CP_BUILD
#include "main.h"
#ifdef C3PO_OSS
#include "cp_stats.h"
#include "cp_adapter.h"
#endif
#else
#include "up_main.h"
#endif

char hbt_filename[256] = "../config/hrtbeat_recov_time.txt";

static pthread_t _gstimer_thread;
static pid_t _gstimer_tid;

extern struct rte_hash *conn_hash_handle;

const char *getPrintableTime(void)
{
	static char buf[128];
	struct timeval tv;
	struct timezone tz;
	struct tm *ptm;

	gettimeofday(&tv, &tz);
	ptm = localtime( &tv.tv_sec );

	sprintf( buf, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
			ptm->tm_year + 1900,
			ptm->tm_mon + 1,
			ptm->tm_mday,
			ptm->tm_hour,
			ptm->tm_min,
			ptm->tm_sec,
			tv.tv_usec / 1000 );

	return buf;
}


static void *_gstimer_thread_func(void *arg)
{
	int keepgoing = 1;
	sem_t *psem = (sem_t*)arg;
	sigset_t set;
	siginfo_t si;

	_gstimer_tid = syscall(SYS_gettid);
	sem_post( psem );

	sigemptyset( &set );
	sigaddset( &set, SIGRTMIN );
	sigaddset( &set, SIGUSR1 );

	while (keepgoing)
	{
		int sig = sigwaitinfo( &set, &si );

		if ( sig == SIGRTMIN )
		{
			gstimerinfo_t *ti = (gstimerinfo_t*)si.si_value.sival_ptr;

			if ( ti->ti_cb )
				(*ti->ti_cb)( ti, ti->ti_data );
		}
		else if ( sig == SIGUSR1 )
		{
			keepgoing = 0;
		}
	}

	return NULL;
}

static bool _create_timer(timer_t *timer_id, const void *data)
{
	int status;
	struct sigevent se;

	/*
	 * Set the sigevent structure to cause the signal to be
	 * delivered by creating a new thread.
	 */
	memset(&se, 0, sizeof(se));
	se.sigev_notify = SIGEV_THREAD_ID;
	se._sigev_un._tid = _gstimer_tid;
	se.sigev_signo = SIGRTMIN;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	se.sigev_value.sival_ptr = (void*)data;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	/*
	 * create the timer
	 */
	status = timer_create(CLOCK_REALTIME, &se, timer_id);

	return status == -1 ? false : true;
}

bool gst_init(void)
{
	int status;
	sem_t sem;

	/*
	 * start the timer thread and wait for _timer_tid to be populated
	 */
	sem_init( &sem, 0, 0 );
	status = pthread_create( &_gstimer_thread, NULL, &_gstimer_thread_func, &sem );
	if (status != 0)
		return False;

	sem_wait( &sem );
	sem_destroy( &sem );

	return true;
}

void gst_deinit(void)
{
	/*
	 * stop the timer handler thread
	 */
	pthread_kill( _gstimer_thread, SIGUSR1 );
	pthread_join( _gstimer_thread, NULL );
}

bool gst_timer_init( gstimerinfo_t *ti, gstimertype_t tt,
				gstimercallback cb, int milliseconds, const void *data )
{
	ti->ti_type = tt;
	ti->ti_cb = cb;
	ti->ti_ms = milliseconds;
	ti->ti_data = data;

	return _create_timer( &ti->ti_id, ti );
}

void gst_timer_deinit(gstimerinfo_t *ti)
{
	timer_delete( ti->ti_id );
}

bool gst_timer_setduration(gstimerinfo_t *ti, int milliseconds)
{
	ti->ti_ms = milliseconds;
	return gst_timer_start( ti );
}

bool gst_timer_start(gstimerinfo_t *ti)
{
	int status;
	struct itimerspec ts;

	/*
	 * set the timer expiration
	 */
	ts.it_value.tv_sec = ti->ti_ms / 1000;
	ts.it_value.tv_nsec = (ti->ti_ms % 1000) * 1000000;
	if ( ti->ti_type == ttInterval )
	{
		ts.it_interval.tv_sec = ts.it_value.tv_sec;
		ts.it_interval.tv_nsec = ts.it_value.tv_nsec;
	}
	else
	{
		ts.it_interval.tv_sec = 0;
		ts.it_interval.tv_nsec = 0;
	}

	status = timer_settime( ti->ti_id, 0, &ts, NULL );
	return status == -1 ? false : true;
}

void gst_timer_stop(gstimerinfo_t *ti)
{
	struct itimerspec ts;

	/*
	 * set the timer expiration, setting it_value and it_interval to 0 disables the timer
	 */
	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	timer_settime( ti->ti_id, 0, &ts, NULL );

}


bool initpeerData( peerData *md, const char *name, int ptms, int ttms )
{
	md->name = name;

	if ( !gst_timer_init( &md->pt, ttInterval, timerCallback, ptms, md ) )
		return False;

	return gst_timer_init( &md->tt, ttInterval, timerCallback, ttms, md );
}

bool startTimer( gstimerinfo_t *ti )
{
	return gst_timer_start( ti );
}

void stopTimer( gstimerinfo_t *ti )
{
	gst_timer_stop( ti );
}

void deinitTimer( gstimerinfo_t *ti )
{
	gst_timer_deinit( ti );
}

void _sleep( int seconds )
{
	sleep( seconds );
}

void del_entry_from_hash(uint32_t ipAddr)
{

	int ret = 0;

	RTE_LOG_DP(DEBUG, DP, " Delete entry from connection table of ip:%s\n",
			inet_ntoa(*(struct in_addr *)&ipAddr));

	/* Delete entry from connection hash table */
	ret = rte_hash_del_key(conn_hash_handle,
			&ipAddr);

	if (ret == -ENOENT)
		RTE_LOG_DP(DEBUG, DP, "key is not found\n");
	if (ret == -EINVAL)
		RTE_LOG_DP(DEBUG, DP, "Invalid Params: Failed to del from hash table\n");
	if (ret < 0)
		RTE_LOG_DP(DEBUG, DP, "VS: Failed to del entry from hash table\n");

	conn_cnt--;

}


uint8_t process_response(uint32_t dstIp)
{
	int ret = 0;
	peerData *conn_data = NULL;

	ret = rte_hash_lookup_data(conn_hash_handle,
			&dstIp, (void **)&conn_data);

	if ( ret < 0) {
		RTE_LOG_DP(DEBUG, DP, " Entry not found for NODE :%s\n",
				inet_ntoa(*(struct in_addr *)&dstIp));
	} else {
		conn_data->itr_cnt = 0;
#ifdef CP_BUILD
			update_peer_timeouts(conn_data->dstIP,0); //cli

#endif /*CP_BUILD*/

		/* Stop transmit timer for specific peer node */
		stopTimer( &conn_data->tt );
		/* Stop periodic timer for specific peer node */
		stopTimer( &conn_data->pt );
		/* Reset Periodic Timer */
		if ( startTimer( &conn_data->pt ) < 0)
			RTE_LOG_DP(ERR, DP, "Periodic Timer failed to start...\n");

	}
	return 0;
}

void recovery_time_into_file(uint32_t recov_time)
{
	FILE *fp = NULL;

	if ((fp = fopen(hbt_filename, "w+")) == NULL) {
				RTE_LOG_DP(ERR, DP, "Unable to open heartbeat recovery file..\n");

	} else {
		fseek(fp, 0, SEEK_SET);
		fprintf(fp, "%u\n", recov_time);
		fclose(fp);
	}
}
