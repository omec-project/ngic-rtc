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

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

#include <rte_ether.h>
#include <rte_debug.h>
#include <stdbool.h>
#include "cdr.h"
#include "util.h"
#define STATS_PATH "./logs/"

#ifdef TIMER_STATS
FILE *ul_timer_stats_file;
FILE *dl_timer_stats_file;
uint64_t ul_pkts_count = 1;
uint64_t dl_pkts_count = 1;
uint8_t print_ul_perf_stats = 0;
uint8_t print_dl_perf_stats = 0;
#ifdef AUTO_ANALYSIS
struct dl_performance_stats dl_perf_stats;
struct ul_performance_stats ul_perf_stats;
int dl_ignore_cnt = 0;
int ul_ignore_cnt = 0;
#endif /* AUTO_ANALYSIS */

/**
 * @brief  : Initialize timer stats log files
 * @param  : op, type, uplink or downlink
 * @return : Returns nothing
 */
static void stats_init(char *op)
{
	char timestamp[NAME_MAX];
	char filename[PATH_MAX];

	ul_pkts_count = 0;
	dl_pkts_count = 0;

	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	strftime(timestamp, NAME_MAX, "%Y%m%d%H%M%S", tmp);
	snprintf(filename, PATH_MAX, "%stimer_stats_%s_%s.log",
			STATS_PATH, op, timestamp);

	clLog(clSystemLog, eCLSeverityDebug,"Logging timer stats into %s\n", filename);
	if (!strcmp(op, "UL")) {
		ul_timer_stats_file = fopen(filename, "w");
		if (!ul_timer_stats_file)
			rte_panic("Timer Stats file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);
	} else {
		dl_timer_stats_file = fopen(filename, "w");
		if (!dl_timer_stats_file)
			rte_panic("Timer Stats file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);
	}
}

void
ul_timer_stats(uint32_t n, struct ul_timer_stats *stat_info)
{
	static uint8_t first_logging = 1;
	if (first_logging) {
		stats_init("UL");
		if (fprintf(ul_timer_stats_file, "%s, %s, %s, %s, %s, %s, %s, %s, %s, "
					"%s, %s, %s, %s, %s, %s, \n",
					"No.of burst", "pkt_burst cnt",	"sdf_acl_delta",
					"sdf_pcc_hash_delta", "adc_acl_delta", "adc_hash_delta",
					"update_adc_delta", "ue_info_lkup_delta", "adc_pcc_hash_delta",
					"pcc_gating_delta", "ul_sess_hash_delta",
					"gtp_decap_delta", "retrive_hash_delta",
					"s1u_handler_delta", "port_in_out_delta") < 0)
			rte_panic("%s [%d] fprintf(ul_timer_stats_file header failed - %s "
					"(%d)\n",
					__FILE__, __LINE__, strerror(errno), errno);
		if (fflush(ul_timer_stats_file))
			rte_panic("%s [%d] fflush(ul_timer_stats_file failed - %s (%d)\n",
					__FILE__, __LINE__, strerror(errno), errno);
		first_logging = 0;
	}
	fprintf(ul_timer_stats_file, "%"PRIu64", %"PRIu32", "
		"%llu, %llu, %llu, %llu, %llu, %llu, "
		"%llu, %llu, %llu, %llu, %llu, %llu, %llu\n",
		ul_pkts_count,
		n,
		stat_info->sdf_acl_delta,
		stat_info->sdf_pcc_hash_delta,
		stat_info->adc_acl_delta,
		stat_info->adc_hash_delta,
		stat_info->update_adc_delta,
		stat_info->ue_info_lkup_delta,
		stat_info->adc_pcc_hash_delta,
		stat_info->pcc_gating_delta,
		stat_info->ul_sess_hash_delta,
		stat_info->gtp_decap_delta,
		stat_info->retrive_hash_delta,
		stat_info->s1u_handler_delta,
		stat_info->port_in_out_delta);

	fflush(ul_timer_stats_file);

	++ul_pkts_count;
}

void
dl_timer_stats(uint32_t n, struct dl_timer_stats *stat_info)
{
	static uint8_t first_logging = 1;
	if (first_logging) {
		stats_init("DL");
		if (fprintf(dl_timer_stats_file, "#%s, %s, %s, %s, %s, %s, %s, %s, %s, "
					"%s, %s, %s, %s, %s, %s, %s\n",
					"No.of burst", "pkt_burst cnt",	"sdf_acl_delta",
					"sdf_pcc_hash_delta", "adc_acl_delta", "adc_hash_delta",
					"adc_pcc_hash_delta", "dl_sess_hash_delta",
					"retrive_hash_delta", "update_dns_delta", "update_adc_delta",
					"pcc_gating_delta", "clone_dns_delta", "gtp_encap_delta",
					"sgi_handler_delta", "port_in_out_delta") < 0)
			rte_panic("%s [%d] fprintf(dl_timer_stats_file header failed - %s "
					"(%d)\n",
					__FILE__, __LINE__, strerror(errno), errno);
		if (fflush(dl_timer_stats_file))
			rte_panic("%s [%d] fflush(dl_timer_stats_file failed - %s (%d)\n",
					__FILE__, __LINE__, strerror(errno), errno);
		first_logging = 0;
	}
	fprintf(dl_timer_stats_file, "%"PRIu64", %"PRIu32", "
		"%llu, %llu, %llu, %llu, %llu, %llu, "
		"%llu, %llu, %llu, %llu, %llu, %llu, %llu, %llu\n",
		dl_pkts_count,
		n,
		stat_info->sdf_acl_delta,
		stat_info->sdf_pcc_hash_delta,
		stat_info->adc_acl_delta,
		stat_info->adc_hash_delta,
		stat_info->adc_pcc_hash_delta,
		stat_info->dl_sess_hash_delta,
		stat_info->retrive_hash_delta,
		stat_info->update_dns_delta,
		stat_info->update_adc_delta,
		stat_info->pcc_gating_delta,
		stat_info->clone_dns_delta,
		stat_info->gtp_encap_delta,
		stat_info->sgi_handler_delta,
		stat_info->port_in_out_delta);

	fflush(dl_timer_stats_file);

	++dl_pkts_count;
}

#ifdef AUTO_ANALYSIS
/**
 * @brief  : Convert number to format string
 * @param  : str, output string
 * @param  : num, input number
 * @return : Returns nothing
 */
static char* SET_FORMAT(char *str, uint64_t num)  {
	memset(str, '\0', 100);
	int cnt = 0, coma_cntr = 0;
	uint64_t tmp_num = num;
	while (tmp_num) {
		int rem = tmp_num%10;
		str[cnt++] = rem + '0';
		tmp_num /= 10;
		if (tmp_num && coma_cntr++ == 2) {
			str[cnt++] = ',';
			coma_cntr = 0;
		}
	}
	str[cnt] = '\0';
	int len = strlen(str);
	for (cnt = 0; cnt < (len/2); ++cnt) {
		char tmp = str[cnt];
		str[cnt] = str[len-cnt-1];
		str[len-cnt-1] = tmp;
	}
	return str;
}
#if 0
#define SET_FORMAT(str, num) ( {        \
	memset(str, 100, '\0');             \
	int cnt = 0, coma_cntr = 0;           \
	uint64_t tmp_num = num;             \
	while (tmp_num) {                       \
		int rem = tmp_num%10;               \
		str[cnt++] = rem + '0';           \
		tmp_num /= 10;                      \
		if (tmp_num && coma_cntr++ == 2) {  \
			str[cnt++] = ',';             \
			coma_cntr = 0;              \
		}                               \
	}                                   \
	str[cnt] = '\0';                      \
	int len = strlen(str);              \
	for (cnt = 0; cnt < (len/2); ++cnt) {   \
		char tmp = str[cnt];              \
		str[cnt] = str[len-cnt-1];          \
		str[len-cnt-1] = tmp;             \
	}                                   \
	str;                                \
})
char* format(uint64_t num) {
	clLog(clSystemLog, eCLSeverityDebug,"NUm is %lu\n", num);
	memset(str, 100, '\0');
	int i = 0, coma_cntr = 0;
	while (num) {
		int rem = num%10;
		str[i++] = rem + '0';
		num /= 10;
		if (num && coma_cntr++ == 2) {
			str[i++] = ',';
			coma_cntr = 0;
		}
	}
	str[i] = '\0';
	int len = strlen(str);
	for (i = 0; i < (len/2)+1; ++i) {
		char tmp = str[i];
		str[i] = str[len-i-1];
		str[len-i-1] = tmp;
	}
	clLog(clSystemLog, eCLSeverityDebug,"str is %s\n", str);
	return str;
}
#endif

/**
 * @brief  : Print uplink performance statistics
 * @param  : No param
 * @return : Returns nothing
 */
static void print_ul_perf_statistics(void) {
	stats_init("UL");
	printf ("%70s", "\n\n********* Final UL performance statistics *********** \n");
	fprintf (ul_timer_stats_file, "%s", "\n\nFinal UL performance statistics\n");
	int i = 0;
	uint64_t tot_duration = 0;
	for (i = 0; i < sizeof(ul_perf_stats.op_time)/sizeof(struct per_op_statistics);
			++i) {
		switch (i) {
		case 0:
			printf ("\n==== SDF ACL stats =====\n");
			fprintf (ul_timer_stats_file, "\nSDF ACL stats\n");
			break;
		case 1:
			printf ("\n==== SDF PCC HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nSDF PCC HASH stats\n");
			break;
		case 2:
			printf ("\n==== ADC ACL stats =====\n");
			fprintf (ul_timer_stats_file, "\nADC ACL stats\n");
			break;
		case 3:
			printf ("\n==== ADC HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nADC HASH stats\n");
			break;
		case 4:
			printf ("\n==== UPDATE ADC RID stats =====\n");
			fprintf (ul_timer_stats_file, "\nUPDATE ADC RID stats\n");
			break;
		case 5:
			printf ("\n==== UE INFO LOOKUP HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nADC PCC HASH stats\n");
			break;
		case 6:
			printf ("\n==== SDF PCC HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nSDF PCC HASH stats\n");
			break;
		case 7:
			printf ("\n==== PCC GATING stats =====\n");
			fprintf (ul_timer_stats_file, "\nPCC GATING stats\n");
			break;
		case 8:
			printf ("\n==== UL SessionInfo HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nUL SessionInfo HASH stats\n");
			break;
		case 9:
			printf ("\n==== GTP DECAP stats =====\n");
			fprintf (ul_timer_stats_file, "\nGTP DECAP stats\n");
			break;
		case 10:
			printf ("\n==== ARP HASH stats =====\n");
			fprintf (ul_timer_stats_file, "\nARP HASH stats\n");
			break;
		case 11:
			printf ("\n==== S1U PKT HANDLER operation =====\n");
			fprintf (ul_timer_stats_file, "\nS1U PKT HANDLER operation\n");
			break;
		case 12:
			printf ("\n==== PORT IN-PORT OUT operation =====\n");
			fprintf (ul_timer_stats_file, "\nPORT IN-PORT OUT opertion\n");
			break;
		}
    	clLog(clSystemLog, eCLSeverityDebug,"%10s%11s%15s%15s%21s%15s%21s\n","Bursts|", "Cum Pkt Cnt|",
			"Total Duration|", "max_pktsvctime|", "max_svctime_burst_sz|",
			"min_pktsvctime|", "min_svctime_burst_sz");
    	fprintf(ul_timer_stats_file, "%s|%s|%s|%s|%s|%s|%s\n","Bursts", "Cum Pkt Cnt",
			"Total Duration", "max_pktsvctime", "max_svctime_burst_sz",
			"min_pktsvctime", "min_svctime_burst_sz");
		printf ("%9lu %11lu %11lu %14u %20u %14u %20u\n",
			ul_perf_stats.no_of_bursts, ul_perf_stats.cumm_pkt_cnt,
			ul_perf_stats.op_time[i].duration, ul_perf_stats.op_time[i].max_time,
			ul_perf_stats.op_time[i].max_burst_sz, ul_perf_stats.op_time[i].min_time,
			ul_perf_stats.op_time[i].min_burst_sz);
		char str[7][100] = {0};
		fprintf (ul_timer_stats_file, "%s|%s|%s|%s|%s|%s|%s\n",
			SET_FORMAT(str[0], ul_perf_stats.no_of_bursts),
			SET_FORMAT(str[1], ul_perf_stats.cumm_pkt_cnt),
			SET_FORMAT(str[2], ul_perf_stats.op_time[i].duration),
			SET_FORMAT(str[3], ul_perf_stats.op_time[i].max_time),
			SET_FORMAT(str[4], ul_perf_stats.op_time[i].max_burst_sz),
			SET_FORMAT(str[5], ul_perf_stats.op_time[i].min_time),
			SET_FORMAT(str[6], ul_perf_stats.op_time[i].min_burst_sz));
		if (fflush(ul_timer_stats_file))
			rte_panic("%s [%d] fflush(ul_timer_stats_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
	}
	/* while computing total duration of test cases,
	 * skip sgi_time and port-in port -out time*/
	for (i = 0;
		i < (sizeof(ul_perf_stats.op_time)/sizeof(struct per_op_statistics))-2;
		++i) {
		tot_duration += ul_perf_stats.op_time[i].duration;
	}
	printf ("Cum. time for all S1U operations: %lu\n", tot_duration);
	char str[100] = {'\0'};
	fprintf (ul_timer_stats_file, "Cum. time for all S1U operations|-|%s\n",
			SET_FORMAT(str, tot_duration));
	if (fflush(ul_timer_stats_file))
		rte_panic("%s [%d] fflush(ul_timer_stats_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}

/**
 * @brief  : Print downlink performance statistics
 * @param  : No param
 * @return : Returns nothing
 */
static void print_dl_perf_statistics(void) {
	stats_init("DL");
	printf ("%70s", "\n\n********* Final DL performance statistics *********** \n");
	fprintf (dl_timer_stats_file, "%s", "\nFinal DL performance statistics\n");
	int i = 0;
	uint64_t tot_duration = 0;
	for (i = 0; i < sizeof(dl_perf_stats.op_time)/sizeof(struct per_op_statistics);
			++i) {
		switch (i) {
		case 0:
			printf ("\n==== SDF ACL stats =====\n");
			fprintf (dl_timer_stats_file, "\nSDF ACL stats\n");
			break;
		case 1:
			printf ("\n==== SDF PCC HASH stats =====\n");
			fprintf (dl_timer_stats_file, "\nSDF PCC HASH stats\n");
			break;
		case 2:
			printf ("\n==== ADC ACL stats =====\n");
			fprintf (dl_timer_stats_file, "\nADC ACL stats\n");
			break;
		case 3:
			printf ("\n==== ADC HASH stats =====\n");
			fprintf (dl_timer_stats_file, "\nADC HASH stats\n");
			break;
		case 4:
			printf ("\n==== ADC PCC HASH stats =====\n");
			fprintf (dl_timer_stats_file, "\nADC PCC HASH stats\n");
			break;
		case 5:
			printf ("\n==== DL SessionInfo HASH stats =====\n");
			fprintf (dl_timer_stats_file, "\nDL SessionInfo HASH stats\n");
			break;
		case 6:
			printf ("\n==== ARP HASH stats =====\n");
			fprintf (dl_timer_stats_file, "\nARP HASH stats\n");
			break;
		case 7:
			printf ("\n==== UPDATE DNS META DATA stats =====\n");
			fprintf (dl_timer_stats_file, "\nUPDATE DNS META DATA stats\n");
			break;
		case 8:
			printf ("\n==== UPDATE ADC RID stats =====\n");
			fprintf (dl_timer_stats_file, "\nUPDATE ADC RID stats\n");
			break;
		case 9:
			printf ("\n==== PCC GATING stats =====\n");
			fprintf (dl_timer_stats_file, "\nPCC GATING stats\n");
			break;
		case 10:
			printf ("\n==== CLONE DNS stats =====\n");
			fprintf (dl_timer_stats_file, "\nCLONE DNS stats\n");
			break;
		case 11:
			printf ("\n==== GTP ENCAP stats =====\n");
			fprintf (dl_timer_stats_file, "\nGTP ENCAP stats\n");
			break;
		case 12:
			printf ("\n==== SGI PKT HANDLER operation =====\n");
			fprintf (dl_timer_stats_file, "\nSGI PKT HANDLER operation\n");
			break;
		case 13:
			printf ("\n==== PORT IN-PORT OUT operation =====\n");
			fprintf (dl_timer_stats_file, "\nPORT IN-PORT OUT operation\n");
			break;
		}
    	clLog(clSystemLog, eCLSeverityDebug,"%10s%11s%15s%15s%21s%15s%21s\n","Bursts|", "Cum Pkt Cnt|",
			"Total Duration|", "max_pktsvctime|", "max_svctime_burst_sz|",
			"min_pktsvctime|", "min_svctime_burst_sz");
    	fprintf(dl_timer_stats_file, "%s|%s|%s|%s|%s|%s|%s\n","Bursts", "Cum Pkt Cnt",
			"Total Duration", "max_pktsvctime", "max_svctime_burst_sz",
			"min_pktsvctime", "min_svctime_burst_sz");
		printf ("%9lu %11lu %11lu %14u %20u %14u %20u\n",
			dl_perf_stats.no_of_bursts, dl_perf_stats.cumm_pkt_cnt,
			dl_perf_stats.op_time[i].duration, dl_perf_stats.op_time[i].max_time,
			dl_perf_stats.op_time[i].max_burst_sz, dl_perf_stats.op_time[i].min_time,
			dl_perf_stats.op_time[i].min_burst_sz);
		char str[7][100] = {0};
		fprintf (dl_timer_stats_file, "%s|%s|%s|%s|%s|%s|%s\n",
			SET_FORMAT(str[0], dl_perf_stats.no_of_bursts),
			SET_FORMAT(str[1], dl_perf_stats.cumm_pkt_cnt),
			SET_FORMAT(str[2], dl_perf_stats.op_time[i].duration),
			SET_FORMAT(str[3], dl_perf_stats.op_time[i].max_time),
			SET_FORMAT(str[4], dl_perf_stats.op_time[i].max_burst_sz),
			SET_FORMAT(str[5], dl_perf_stats.op_time[i].min_time),
			SET_FORMAT(str[6], dl_perf_stats.op_time[i].min_burst_sz));
		if (fflush(dl_timer_stats_file))
			rte_panic("%s [%d] fflush(dl_timer_stats_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
	}
	for (i = 0;
		i < (sizeof(dl_perf_stats.op_time)/sizeof(struct per_op_statistics))-2;
		++i) {
		tot_duration += dl_perf_stats.op_time[i].duration;
	}
	printf ("Cum. time for all SGI operations: %lu\n", tot_duration);
	char str[100] = {0};
	fprintf (dl_timer_stats_file, "Cum. time for all SGI operations|-|%s\n",
			SET_FORMAT(str, tot_duration));
	if (fflush(dl_timer_stats_file))
		rte_panic("%s [%d] fflush(dl_timer_stats_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}

void print_perf_statistics(void) {
	if (print_dl_perf_stats) {
		print_dl_perf_statistics();
	}
	if (print_ul_perf_stats) {
		print_ul_perf_statistics();
	}
}
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS*/
