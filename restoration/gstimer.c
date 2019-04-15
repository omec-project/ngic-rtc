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

#include "gstimer.h"

static pthread_t _gstimer_thread;
static pid_t _gstimer_tid;

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

//static void time_to_ntp(struct timeval *tv, uint8_t *ntp)
//{
//	uint64_t ntp_tim = 0;
//	uint8_t len = (uint8_t)sizeof(ntp)/sizeof(ntp[0]);
//	uint8_t *p = ntp + len;
//
//	int i = 0;
//	printf("len is %d\n",len);
//
//	ntp_tim = tv->tv_usec;
//	ntp_tim <<= 32;
//	ntp_tim /= 1000000;
//
//	// we set the ntp in network byte order
//	for (i = 0; i < len/2; i++) {
//		*--p = ntp_tim & 0xff;
//		ntp_tim >>= 8;
//	}
//
//	ntp_tim = tv->tv_sec;
//	ntp_tim += OFFSET;
//
//	// let's go with the fraction of second /
//	for (; i < len; i++) {
//		*--p = ntp_tim & 0xff;
//		ntp_tim >>= 8;
//	}
//
//}
//
//uint32_t current_ntp_timestamp(void) {
//
//	struct timeval tim;
//	uint8_t ntp_time[8] = {0};
//
//	gettimeofday(&tim, NULL);
//
//	time_to_ntp(&tim, ntp_time);
//
//	uint32_t timestamp = 0;
//
//	timestamp |= ntp_time[0] << 24 | ntp_time[1] << 16 | ntp_time[2] << 8 | ntp_time[3];
//
//	return timestamp;
//}

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
	//return false;
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

bool gst_timer_init( gstimerinfo_t *ti, gstimertype_t tt, gstimercallback cb, int milliseconds, const void *data )
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
	//int status;
	struct itimerspec ts;

	/*
	 * set the timer expiration, setting it_value and it_interval to 0 disables the timer
	 */
	ts.it_value.tv_sec = 0;
	ts.it_value.tv_nsec = 0;
	ts.it_interval.tv_sec = 0;
	ts.it_interval.tv_nsec = 0;

	//status = timer_settime( ti->ti_id, 0, &ts, NULL );
	timer_settime( ti->ti_id, 0, &ts, NULL );

}


bool initpeerData( peerData *md, const char *name, int ptms, int ttms )
{
	md->name = name;

	if ( !gst_timer_init( &md->pt, ttInterval, timerCallback, ptms, md ) )
		return False;

	return gst_timer_init( &md->tt, ttSingleShot, timerCallback, ttms, md );
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

int32_t 
inx_bsearch(peerData conn_arr[], int32_t lw, int32_t hw, uint32_t srcIP) 
{
   if (hw < lw) 
       return -1; 

   int32_t md = (lw + hw)/2;  /* VS:TODO: low + (high - low)/2;*/

   if (srcIP == conn_arr[md].dstIP) 
       return md; 

   if (srcIP > conn_arr[md].dstIP) 
       return inx_bsearch(conn_arr, (md + 1), hw, srcIP); 

   return inx_bsearch(conn_arr, lw, (md -1), srcIP); 
}

 
