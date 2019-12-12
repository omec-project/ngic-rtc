#ifndef __TIMER_H_
#define __TIMER_H_

#include <time.h>

/**
 * During performance measurements, ignore initial few burts in the beginning
 * in order to avoid capturing erroneous numbers
   Note: If (PPS*duration) > 5,000, set LEADING_BURST_IGNORE to 10
	 Else, set LEADING_BURST_IGNORE to 2
**/
#define LEADING_BURST_IGNORE 10
extern uint8_t print_ul_perf_stats;
extern uint8_t print_dl_perf_stats;
#ifdef AUTO_ANALYSIS
extern int dl_ignore_cnt;
extern int ul_ignore_cnt;
#define SET_PERF_MAX_MIN_TIME(param, start_time, n, is_dl) {          \
	if ((is_dl && dl_ignore_cnt > LEADING_BURST_IGNORE) ||            \
	    (!is_dl && ul_ignore_cnt > LEADING_BURST_IGNORE)) {           \
	  _timer_t fin_time = TIMER_GET_ELAPSED_NS(start_time);           \
	  param.duration += fin_time;                                     \
	  if (!param.max_time) {                                          \
	  	/* fin_time == min == max */                                  \
	  	param.max_time = param.min_time = fin_time;                   \
	  	param.max_burst_sz =param.min_burst_sz = n;                   \
	  } else if (fin_time > param.max_time) {                         \
	  	/* If lookup time is greater than previous max lookup time,   \
	  	 * then set new time as max time and set max burst cnt to n   \
	  	 */                                                           \
	  	param.max_time = fin_time;                                    \
	  	param.max_burst_sz = n;                                       \
	  } else if (fin_time < param.min_time) {                         \
	  	/* If lookup time is less than previous min lookup time,      \
	  	 * then set new time as min time and set min burst cnt to n   \
	  	 */                                                           \
	  	param.min_time = fin_time;                                    \
	  	param.min_burst_sz = n;                                       \
	  }                                                               \
	}                                                                 \
}

/**
 * @brief  : Maintains statistic
 */
struct per_op_statistics {
	uint64_t duration;
	uint32_t max_time;
	uint32_t max_burst_sz;
	uint32_t min_time;
	uint32_t min_burst_sz;
};

/**
 * @brief  : structure to hold stats of all the DL operations
 */
struct dl_performance_stats {
	uint64_t no_of_bursts;
	uint64_t cumm_pkt_cnt;
	/* op_time[0] = sdf_acl, [1] = sdf_pcc_hash, [2] = adc_acl
	 * [3] = adc_hash, [4] = adc_pcc_hash, [5] = dl_sess_hash
	 * [6] = arp_hash, [7] = update_dns [8] = update_adc_rid,
	 * [9] = pcc_gate, [10] = clone_dns [11] = gtp_encap,
	 * [12] = sgi_time, [13] = port_in_out_time
	 * */
	struct per_op_statistics op_time[14];
};
extern struct dl_performance_stats dl_perf_stats;

/**
 * @brief  : structure to hold stats of all the UL operations
 */
struct ul_performance_stats {
	uint64_t no_of_bursts;
	uint64_t cumm_pkt_cnt;
	/* op_time[0] = sdf_lookup, [1] = sdf_pcc_hash, [2] = adc_acl
	 * [3] = adc_hash_lookup, [4] = update_adc_rid, [5] = ue_info_lookup
	 * [6] = adc_pcc_hash, [7] = pcc_gating [8] = ul_sess_hash,
	 * [9] = gtpu_decap, [10] = arp_hash, [11] = s1u_time,
	 * [12] = port_in_out_time
	 * */
	struct per_op_statistics op_time[13];
};
extern struct ul_performance_stats ul_perf_stats;
#endif /* AUTO_ANALYSIS */

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

/*
 * @brief  : Prints and converts number in coma seperated fashion
 * @param  : num, input
 * @return : Returns converted string
 */
char* format(uint64_t num);
#endif

