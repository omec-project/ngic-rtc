/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#define _GNU_SOURCE     /* Expose declaration of strptime() */
#include <time.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "master_cdr.h"
#include "cdr.h"

#define MASTER_FILE_HEADER_PREFIX   "#"
#define MASTER_FILE_ENTRY_SEPARATOR ","
#define MASTER_FILE_ENTRY_POSTFIX   "\n"
#define DEFAULT_MASTER_FILENAME DEFAULT_CDR_PATH"master.csv"

struct master_file_entry_t {
	unsigned char md5_digest[MD5_DIGEST_LENGTH];
	char *absolute_filename;
	struct tm start_tm;
	struct tm end_tm;
	uint32_t num_entries;
};

struct master_field_t {
	const char *header;
	void (*print_value)(FILE *file, struct master_file_entry_t *entry);
};

static char *master_cdr_filename;

static void
filename_master_cb(FILE *file, struct master_file_entry_t *entry)
{
	fprintf(file, "%s", entry->absolute_filename);
}

static void
time_master_helper(FILE *file, struct tm *t) {
	char time_str[RECORD_TIME_LENGTH];
	strftime(time_str, RECORD_TIME_LENGTH, RECORD_TIME_FORMAT, t);
	fprintf(file, "%s", time_str);
}

static void start_time_cb(FILE *file, struct master_file_entry_t *entry)
{
	if (entry->num_entries == 0)
		fprintf(file, "(null)");
	else
		time_master_helper(file, &entry->start_tm);
}

static void end_time_cb(FILE *file, struct master_file_entry_t *entry)
{
	if (entry->num_entries == 0)
		fprintf(file, "(null)");
	else
		time_master_helper(file, &entry->end_tm);
}

static void num_entries_cb(FILE *file, struct master_file_entry_t *entry)
{
	fprintf(file, "%"PRIu32, entry->num_entries);
}

static void md5_cb(FILE *file, struct master_file_entry_t *entry)
{
	unsigned i;
	for (i = 0; i < MD5_DIGEST_LENGTH; ++i)
		fprintf(file, "%02x", entry->md5_digest[i]);
}


struct master_field_t master_fields[] = {
		{"filename", filename_master_cb},
		{"start_time", start_time_cb},
		{"end_time", end_time_cb},
		{"num_entries", num_entries_cb},
		{"MD5", md5_cb}
};

static int
calc_md5(FILE *file, off_t filesize, struct master_file_entry_t *master_entry)
{
	unsigned char buffer[BUFFER_SIZE];
	MD5_CTX md5_context;
	off_t read = 0;
	size_t r;
	int ret;
	ret = MD5_Init(&md5_context);
	if (ret != 1) {
		printf("MD5 Init failed for file - ");
		return EXIT_FAILURE;
	}
	rewind(file);
	do {
		r = fread(buffer, sizeof(unsigned char),
				sizeof(buffer), file);
		read += r;
		if (r < sizeof(buffer) && read != filesize) {
			fprintf(stderr, "Read error on %s - %s - ", __func__,
					strerror(errno));
			return EXIT_FAILURE;
		}

		ret = MD5_Update(&md5_context, buffer, r);
		if (ret != 1) {
			fprintf(stderr, "MD5 Update failed for file - ");
			return EXIT_FAILURE;
		}
	} while (read < filesize);
	ret = MD5_Final(master_entry->md5_digest, &md5_context);
	if (ret != 1) {
		fprintf(stderr, "MD5 Final failed for file - ");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

static int
parse_records(FILE *file,
		struct master_file_entry_t *master_entry)
{
	char buffer[BUFFER_SIZE];
	char *entry_values[NUM_CDR_FIELDS];
	char *ret;
	char *tok;

	int res;
	unsigned i;

	time_t end = 0;
	time_t start = time(NULL);

	/* get header */
	ret = fgets(buffer, BUFFER_SIZE, file);
	if (ret == NULL) {
		fprintf(stderr, "Unable to read header - ");
		return EXIT_FAILURE;
	}


	for (i = 0; i < NUM_CDR_FIELDS; ++i) {
		entry_values[i] = strtok_r(
				(i == 0) ? buffer : NULL,
				MASTER_FILE_HEADER_PREFIX
				MASTER_FILE_ENTRY_POSTFIX
				MASTER_FILE_ENTRY_SEPARATOR, &tok);
		if (entry_values[i] == NULL) {
			fprintf(stderr, "Failed to tokenize record - ");
			return EXIT_FAILURE;
		}

		res = strcmp(entry_values[i], cdr_fields[i].header);
		if (res) {
			fprintf(stderr, "Header mismatch - ");
			return EXIT_FAILURE;
		}
	}

	do {
		struct tm entry_tm = {0};
		time_t entry_time;

		ret = fgets(buffer, BUFFER_SIZE, file);
		if (ret == NULL)
			break;

		char *stringp = buffer;
		for (i = 0; i < NUM_CDR_FIELDS; ++i) {
			entry_values[i] = strsep(&stringp,
					MASTER_FILE_ENTRY_POSTFIX
					MASTER_FILE_ENTRY_SEPARATOR);
			if (entry_values[i] == NULL) {
				fprintf(stderr, "Failed to tokenize record - ");
				return EXIT_FAILURE;
			}
		}

		ret = strptime(entry_values[CDR_TIME_FIELD_INDEX],
				RECORD_TIME_FORMAT, &entry_tm);
		if (ret == NULL) {
			fprintf(stderr, "Failed to parse time format - ");
			return EXIT_FAILURE;
		}

		entry_time = mktime(&entry_tm);

		if (entry_time < start)
			start = entry_time;
		else if (end < entry_time)
			end = entry_time;

		master_entry->num_entries++;
	} while (1);

	gmtime_r(&start, &master_entry->start_tm);
	gmtime_r(&end, &master_entry->end_tm);

	return EXIT_SUCCESS;
}

static void
create_master_entry(FILE *master_file,
		const char *old_filename,
		const char *new_filename)
{
	struct stat statbuf;
	static struct master_file_entry_t master_entry;
	int ret;
	unsigned i;
	memset(&master_entry, 0, sizeof(struct master_file_entry_t));
	ret = stat(old_filename, &statbuf);
	FILE *file = fopen(old_filename, "r");
	if (file == NULL) {
		printf("Unable to open %s to finalize record\n", old_filename);
		return;
	}
	ret = parse_records(file, &master_entry);
	if (ret != EXIT_SUCCESS) {
		fprintf(stderr, "Failed to parse records of %s "
				"(%s:%d)\n",
				old_filename, __FILE__, __LINE__);
		return;
	}
	ret = calc_md5(file, statbuf.st_size, &master_entry);
	if (ret != EXIT_SUCCESS) {
		fprintf(stderr, "Failed to calculate MD5 of %s "
				"(%s:%d)\n",
				old_filename, __FILE__, __LINE__);
		return;
	}



	ret = rename(old_filename, new_filename);
	if (ret)
		fprintf(stderr, "Failed to rename %s (%s:%d)\n",
				old_filename, __FILE__, __LINE__);
	master_entry.absolute_filename = realpath(new_filename, NULL);
	if (ret)
		fprintf(stderr, "Failed to retrieve realpath of %s "
				"(%s:%d)\n",
				new_filename, __FILE__, __LINE__);

	for (i = 0; i < RTE_DIM(master_fields); ++i) {
		master_fields[i].print_value(master_file, &master_entry);
		fprintf(master_file, MASTER_FILE_ENTRY_SEPARATOR);
	}
	fprintf(master_file, MASTER_FILE_ENTRY_POSTFIX);
}

static void
create_master_dir(void)
{
	char *p = strrchr(master_cdr_filename, '/');
	if (p == NULL)
		return;
	*p = '\0';
	create_sys_path(master_cdr_filename);
	*p = '/';
}

void
finalize_cur_cdrs(const char *cdr_path)
{
	char old_filename[PATH_MAX];
	char new_filename[PATH_MAX];
	int ret;
	unsigned i;
	int new_file_access = access(master_cdr_filename, F_OK);
	FILE *master_file;
	DIR *dir;

	create_master_dir();
	master_file = fopen(master_cdr_filename, "a");
	if (master_file == NULL)
		rte_panic("Failed to open master_file %s: %s\n",
				master_cdr_filename, strerror(errno));
	dir = opendir(cdr_path);
	if (dir == NULL)
		rte_panic("Failed to open cdr_path to finalize old records: "
				"%s\n", strerror(errno));

	if (new_file_access == -1) {
		fprintf(master_file, MASTER_FILE_HEADER_PREFIX);

		for (i = 0; i < RTE_DIM(master_fields); ++i) {
			fprintf(master_file, "%s", master_fields[i].header);
			fprintf(master_file, MASTER_FILE_ENTRY_SEPARATOR);
		}
		fprintf(master_file, MASTER_FILE_ENTRY_POSTFIX);
	}

	struct dirent *dir_entry;
	errno = 0;
	while ((dir_entry = readdir(dir)) != NULL) {
		char *dot = strrchr(dir_entry->d_name, '.');
		if (dot == NULL)
			continue;
		if (strcmp(dot, CDR_CUR_EXTENSION) != 0)
			continue;
		ret = snprintf(old_filename, PATH_MAX, "%s%s",
				cdr_path, dir_entry->d_name);
		if (ret > PATH_MAX || ret < 0)
			fprintf(stderr, "Failed to finalize %s (%s:%d)\n",
					dir_entry->d_name, __FILE__, __LINE__);
		memcpy(dot, CDR_CSV_EXTENSION, sizeof(CDR_CSV_EXTENSION));
		ret = snprintf(new_filename, PATH_MAX, "%s%s",
				cdr_path, dir_entry->d_name);
		if (ret > PATH_MAX || ret < 0)
			fprintf(stderr, "Failed to finalize %s (%s:%d)\n",
					dir_entry->d_name, __FILE__, __LINE__);
		create_master_entry(master_file, old_filename, new_filename);
	}
	if (errno)
		rte_panic("Failed to scan cdr_path to finalize old records:"
				" %s.\n", strerror(errno));
	closedir(dir);
	fclose(master_file);
}


void
set_master_cdr_file(const char *filename)
{
	if (filename == NULL)
		filename = DEFAULT_MASTER_FILENAME;
	master_cdr_filename = strdup(filename);
}

void
free_master_cdr(void)
{
	if (master_cdr_filename)
		free(master_cdr_filename);
	master_cdr_filename = NULL;

}
