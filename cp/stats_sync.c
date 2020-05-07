/*
 * Copyright (c) 2017 Intel Corporation
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

#include "cp.h"

#define CSV_EXTENSION ".csv"
#define CUR_EXTENSION ".cur"

#define DEBUG_STATS 0

FILE *stats_file;
uint64_t stats_cnt;

void
retrive_stats_entry(void)
{
	int ret;
	uint64_t key = 0;

	for(key = 1; key < op_id; key++)
	{
		struct sync_stats *stats;

		ret = rte_hash_lookup_data(stats_hash, (void *)&key,
				(void **)&stats);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:rte_hash_lookup_data failed for"
					"key %lu: %s (%d)\n", __func__,
					key, rte_strerror(abs(ret)), ret);
			continue;
		}

		export_stats_report(*stats);
	}

	clLog(clSystemLog, eCLSeverityCritical, "\nStatstics export in file completed.\n");
	rte_hash_free(stats_hash);

}

void
export_stats_report(struct sync_stats stats_info)
{

#if DEBUG_STATS
#ifdef SDN_ODL_BUILD
	fprintf(stats_file, "%"PRIu64", %"PRIu16", %"PRIu64
						", %"PRIu64", %"PRIu64", %"PRIu64
						", %"PRIu64", %"PRIu64"\n",
						stats_cnt, stats_info.type,
						stats_info.op_id, stats_info.session_id,
						stats_info.req_init_time, stats_info.ack_rcv_time,
						stats_info.resp_recv_time,
						((stats_info.resp_recv_time) - (stats_info.req_init_time)));
#else

	fprintf(stats_file, "%"PRIu64", %"PRIu16", %"PRIu64
						", %"PRIu64", %"PRIu64
						", %"PRIu64", %"PRIu64"\n",
						stats_cnt, stats_info.type,
						stats_info.op_id, stats_info.session_id,
						stats_info.req_init_time,
						stats_info.resp_recv_time,
						((stats_info.resp_recv_time) - (stats_info.req_init_time)));

#endif  /* SDN_ODL_BUILD */
#else

	fprintf(stats_file, "%"PRIu64", %"PRIu64"\n",
						stats_cnt,
						((stats_info.resp_recv_time) - (stats_info.req_init_time)));
#endif  /* DEBUG_STATS */

	fflush(stats_file);

	++stats_cnt;
}

void
close_stats(void)
{
	if (stats_file) {
		FILE *old_file = stats_file;
		stats_file = stderr;

		fclose(old_file);
	}
}

void
stats_init(void)
{
	char timestamp[NAME_MAX];
	char filename[PATH_MAX];
	stats_cnt = 1;

	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	strftime(timestamp, NAME_MAX, "%Y_%m_%d_%H_%M_%S", tmp);
	snprintf(filename, PATH_MAX, "%sCP_Sync_Stats_%s"
			CSV_EXTENSION, DEFAULT_STATS_PATH, timestamp);

	clLog(clSystemLog, eCLSeverityCritical, "\nLogging Sync Statistics Records to %s\n", filename);

	stats_file = fopen(filename, "w");
	if (!stats_file)
		rte_panic("Statistics file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);
#if DEBUG_STATS
	fprintf(stats_file, "#Session Type:\n#\t1:CREATE\n#\t2:UPDATE\n#\t3:DELETE\n");

#ifdef SDN_ODL_BUILD
	if (fprintf(stats_file, "#%s, %s, %s, %s, %s, %s, %s, %s\n",
				"record",
				"Session type",
				"op_id",
				"session_id",
				"req_init_time(n/sec)",
				"ack_rcv_time(n/sec)",
				"resp_recv_time(n/sec)",
				"req_resp_diff(m/sec)") < 0)
		rte_panic("%s [%d] fprintf(stats_file header failed - %s "
				"(%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
#else
	if (fprintf(stats_file, "#%s, %s, %s, %s, %s, %s, %s\n",
				"record",
				"Session type",
				"op_id",
				"session_id",
				"req_init_time(n/sec)",
				"resp_recv_time(n/sec)",
				"req_resp_diff(m/sec)") < 0)
		rte_panic("%s [%d] fprintf(stats_file header failed - %s "
				"(%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);

#endif  /* SDN_ODL_BUILD */
#else

	if (fprintf(stats_file, "#%s, %s\n",
				"record",
				"req_resp_diff(n/sec)") < 0)
		rte_panic("%s [%d] fprintf(stats_file header failed - %s "
				"(%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);

#endif  /* DEBUG_STATS */

	if (fflush(stats_file))
		rte_panic("%s [%d] fflush(stats_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);

}

/**
 * @brief  : maintain request statstics in hash table.
 */
void
add_stats_entry(struct sync_stats *stats)
{
	int ret;
	_timer_t _init_time = 0;


	struct sync_stats *tmp = rte_zmalloc("test",
			sizeof(struct sync_stats),
			RTE_CACHE_LINE_SIZE);

	if (NULL == tmp)
		rte_panic("%s:Failure to allocate create session buffer: "
				"%s (%s:%d)\n", __func__, rte_strerror(rte_errno),
				__FILE__,
				__LINE__);

	memcpy(tmp, stats, sizeof(struct sync_stats));

	GET_CURRENT_TS(_init_time);
	tmp->req_init_time = _init_time;

	ret = rte_hash_add_key_data(stats_hash, (void *)&tmp->op_id,
			(void *)tmp);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:rte_hash_add_key_data failed for"
				" op_id %"PRIu64": %s (%u)\n", __func__,
				tmp->op_id, rte_strerror(abs(ret)), ret);
	}
}

void
update_stats_entry(uint64_t key, uint8_t type)
{
	int ret;
	_timer_t _init_time = 0;
	struct sync_stats *stats = NULL;

	ret = rte_hash_lookup_data(stats_hash, (void *)&key,
			(void **)&stats);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:rte_hash_lookup_data failed for"
				"key %"PRIu64": %s (%u)\n", __func__,
				key, rte_strerror(abs(ret)), ret);
		return;
	}

	GET_CURRENT_TS(_init_time);

	if (type == ACK) {
		stats->ack_rcv_time = _init_time;
	} else {
		stats->resp_recv_time = _init_time;
	}
}

