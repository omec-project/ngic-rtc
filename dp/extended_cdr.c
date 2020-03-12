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

#include "cdr.h"
#include "util.h"

FILE *extended_cdr_file;
uint64_t extcdr_count;

void
extended_cdr_init(void)
{
	char timestamp[NAME_MAX];
	char filename[PATH_MAX];

	extcdr_count = 0;

	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);

	strftime(timestamp, NAME_MAX, "%Y%m%d%H%M%S", tmp);
	snprintf(filename, PATH_MAX, "%sextended_cdr_%s"
			CDR_CSV_EXTENSION, cdr_path, timestamp);

	clLog(clSystemLog, eCLSeverityDebug,"Logging Extended CDR Records to %s\n", filename);

	extended_cdr_file = fopen(filename, "w");
	if (!extended_cdr_file)
		rte_panic("Extended CDR file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);

	if (fprintf(extended_cdr_file, "#%s,%s,%s,%s,%s,%s,%s,%s,"
				"%s,%s,%s,%s,%s\n",
				"record",
				"time",
				"ue_ip",
				"app_ip",
				"direction",
				"pcc_rule_id",
				"pcc_rule_name",
				"filter_type",
				"action",
				"sponsor_id",
				"service_id",
				"rate_group",
				"report_level") < 0)
		rte_panic("%s [%d] fprintf(extended_cdr_file header failed - %s "
				"(%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(extended_cdr_file))
		rte_panic("%s [%d] fflush(extended_cdr_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}


void
export_extended_cdr(char *ue_ip,
			char *app_ip, uint8_t pkt_mask, struct pcc_rules *pcc_info,
			int direction)
{
	if(UL_FLOW == direction){
		fprintf(extended_cdr_file, "%"PRIu64",%"PRIu32",%s,%s,%s,%"PRIu32
			",%s,%s,%s,%s,%"PRIu32",%"PRIu32",%"PRIu32"\n",
			extcdr_count, 1, ue_ip, app_ip, "UL", pcc_info->rule_id,
			pcc_info->rule_name,
			pcc_info->sdf_idx_cnt > 0 ? "SDF":"ADC",
			pkt_mask == 1 ? "CHARGED":"DROPPED",
			pcc_info->sponsor_id, pcc_info->service_id,
			pcc_info->rating_group, pcc_info->report_level);
	} else {
		fprintf(extended_cdr_file, "%"PRIu64",%"PRIu32",%s,%s,%s,%"PRIu32
			",%s,%s,%s,%s,%"PRIu32",%"PRIu32",%"PRIu32"\n",
			extcdr_count, 1, app_ip, ue_ip, "DL", pcc_info->rule_id,
			pcc_info->rule_name,
			pcc_info->sdf_idx_cnt > 0 ? "SDF":"ADC",
			pkt_mask == 1 ? "CHARGED":"DROPPED",
			pcc_info->sponsor_id, pcc_info->service_id,
			pcc_info->rating_group, pcc_info->report_level);
	}

	fflush(extended_cdr_file);

	++extcdr_count;
}

