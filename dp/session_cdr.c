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
#include "session_cdr.h"
#include "util.h"

#define SESS_CDR_FILE "/var/log/dpn/sess_cdr.csv"
FILE *sess_cdr_file;

void
sess_cdr_init(void)
{
	char filename[MAX_LEN] = SESS_CDR_FILE;
	DIR *cdr_dir = opendir("/var/log/dpn/");
	if (cdr_dir)
		closedir(cdr_dir);
	else if (errno == ENOENT) {
		errno = 0;
		mkdir("/var/log/dpn/", S_IRWXU);
	}

	clLog(clSystemLog, eCLSeverityDebug,"Logging Session ID based CDR Records to %s\n", filename);

	sess_cdr_file = fopen(filename, "w");
	if (!sess_cdr_file)
		rte_panic("CDR file %s failed to open for writing\n - %s (%d)",
					filename, strerror(errno), errno);

	if (fprintf(sess_cdr_file, "#%s,%s,%s,%s,%s,%s,%s,"
				"%s,%s,%s,%s,%s,%s,%s\n",
				"time",
				"sess_id",
				"cdr_type",
				"id",
				"ue_ip",
				"dl_pkt_cnt",
				"dl_bytes",
				"ul_pkt_cnt",
				"ul_bytes",
				"dl_drop_cnt",
				"dl_drop_bytes",
				"ul_drop_cnt",
				"ul_drop_bytes",
				"rate_group") < 0)
		rte_panic("%s [%d] fprintf(sess_cdr_file header failed - %s "
				"(%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
	if (fflush(sess_cdr_file))
		rte_panic("%s [%d] fflush(sess_cdr_file failed - %s (%d)\n",
				__FILE__, __LINE__, strerror(errno), errno);
}

void
sess_cdr_reset(void)
{
	fclose(sess_cdr_file);
	sess_cdr_init();
}

/**
 * @brief  : Function to update timestamp of records to file.
 * @param  : cfile, filename
 * @return : Returns nothing
 */
static void
update_timestamp(FILE *cfile)
{
	/* create time string */
	char time_str[30];
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (tmp == NULL)
		return;
	strftime(time_str, sizeof(time_str), "%y%m%d_%H%M%S", tmp);
	fprintf(cfile, "%s", time_str);
}

/**
 * @brief  : Function to update Uplink and downlink records to file.
 * @param  : cfile, filename
 * @param  : charge_record, cdr information
 * @return : Returns nothing
 */
static void
update_pkt_counts(FILE *cfile,
				struct ipcan_dp_bearer_cdr *charge_record)
{
	if (!charge_record)
		return;

	fprintf(cfile, ",%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64
				",%"PRIu64",%"PRIu64,
				charge_record->data_vol.dl_cdr.pkt_count,
				charge_record->data_vol.dl_cdr.bytes,
				charge_record->data_vol.ul_cdr.pkt_count,
				charge_record->data_vol.ul_cdr.bytes,
				charge_record->data_vol.dl_drop.pkt_count,
				charge_record->data_vol.dl_drop.bytes,
				charge_record->data_vol.ul_drop.pkt_count,
				charge_record->data_vol.ul_drop.bytes);
}

void
export_cdr_record(struct dp_session_info *session, char *name,
			uint32_t id, struct ipcan_dp_bearer_cdr *charge_record)
{
	update_timestamp(sess_cdr_file);
	fprintf(sess_cdr_file, ",%"PRIu64"", session->sess_id);
	fprintf(sess_cdr_file, ",%s,%u,%s", name, id,
						iptoa(session->ue_addr));
	update_pkt_counts(sess_cdr_file, charge_record);
	fprintf(sess_cdr_file, ",%"PRIu32"\n", charge_record->rating_group);
	fflush(sess_cdr_file);
}
