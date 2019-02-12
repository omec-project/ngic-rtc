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

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <hs.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include "sponsdn.h"

/* TODO: is there an existing #define
 * max len per rfc is 255 octets, ignoring the length encoding
 * of the first and last labels, the max len can be 253 chars.
 */
#define MAX_DNS_NAME_LEN 256

struct ctx {
	unsigned matching_id;
	unsigned long long off;
};

struct dns_header {
	uint16_t id;
	uint16_t flags;
	uint16_t qns;
	uint16_t ans;
	uint16_t auth_rr;
	uint16_t addl_rr;
} __attribute__ ((packed));

/* Fixed size members of DNS query */
struct dns_query {
	uint16_t type;
	uint16_t class;
} __attribute__ ((packed));

/* Fixed size members of DNS address response */
struct dns_response {
	uint16_t name;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t data_len;
	struct in_addr addr[0];
} __attribute__ ((packed));

static struct ctx ctx;
static unsigned *host_ids;
static unsigned *rule_ids;
static unsigned *flags;

static hs_database_t *database;
static hs_scratch_t *scratch;
static hs_compile_error_t *compile_err;

static char (*host_names)[MAX_DNS_NAME_LEN];
static char **host_name_tbl;
static unsigned free_idx;
static uint32_t max_host_names;

static inline bool is_compressed_name(uint16_t name)
{
	return !!(rte_be_to_cpu_16(name) & 0xe000);
}

static int compile_tbl(void)
{
	hs_error_t err;

	if (!free_idx)
		return 0;

	err = hs_compile_multi
		((const char *const *)host_name_tbl, flags, host_ids, free_idx,
		HS_MODE_BLOCK, NULL, &database, &compile_err);

	if (err != HS_SUCCESS) {
		fprintf(stderr, "ERROR: Unable to compile pattern : %s\n",
			compile_err->message);
		hs_free_compile_error(compile_err);
		return -1;
	}

	err = hs_alloc_scratch(database, &scratch);

	if (err != HS_SUCCESS) {
		fprintf(stderr,
			"ERROR: %d Unable to allocate scratch space. Exiting.\n",
			err);
		hs_free_database(database);
		return -1;
	}

	return 0;
}

int epc_sponsdn_create(uint32_t max_dn)
{
	unsigned i;

	max_host_names = max_dn;
	host_names = rte_zmalloc("dns", sizeof(host_names[0])*max_dn, 0);
	if (!host_names)
		goto err;

	host_name_tbl = rte_zmalloc("dns name table", sizeof(char *)*max_dn, 0);
	if (!host_name_tbl)
		goto err;

	host_ids = rte_zmalloc("host_ids", sizeof(host_ids[0])*max_dn, 0);
	if (!host_ids)
		goto err;

	rule_ids = rte_zmalloc("rule_ids", sizeof(rule_ids[0])*max_dn, 0);
	if (!rule_ids)
		goto err;

	flags = rte_zmalloc("flags", sizeof(flags[0])*max_dn, 0);
	if (!flags)
		goto err;

	for (i = 0; i < max_dn; i++) {
		host_name_tbl[i] = host_names[i];
		host_ids[i] = i;
		flags[i] = HS_FLAG_SINGLEMATCH;
	}

	return 0;

err:
	if (host_names)
		rte_free(host_names);
	if (host_name_tbl)
		rte_free(host_name_tbl);
	if (host_ids)
		rte_free(host_ids);
	if (flags)
		rte_free(flags);

	host_names = NULL;
	host_name_tbl = NULL;
	host_ids = NULL;
	flags = NULL;
	return -ENOMEM;
}

void epc_sponsdn_free(void)
{
	if (host_names) {
		rte_free(host_names);
		rte_free(host_ids);
		rte_free(rule_ids);
		rte_free(host_name_tbl);
		host_name_tbl = NULL;
		host_names = NULL;
		host_ids = NULL;
		rule_ids = NULL;
	}
}

int epc_sponsdn_dn_add_single(char *dn, const unsigned int rule)
{
	if (free_idx + 1 > max_host_names || free_idx + 1 < free_idx)
		return -EINVAL;

	strncpy(host_names[free_idx], dn, MAX_DNS_NAME_LEN);
	rule_ids[free_idx] = rule;

	free_idx += 1;

	return free_idx ? compile_tbl() : 0;
}


/*
 * TODO: handle frees, RCU etc.
 */
int epc_sponsdn_dn_add_multi(char **dn, const unsigned int *rules, uint32_t num)
{
	unsigned i;

	if (free_idx + num > max_host_names || free_idx + num < free_idx) {
		return -EINVAL;
	}

	for (i = 0; i < num; i++) {
		strncpy(host_names[i + free_idx], dn[i], MAX_DNS_NAME_LEN);
		if (rules)
			rule_ids[i + free_idx] = rules[i];
	}

	free_idx += num;
	return free_idx ? compile_tbl() : 0;
}

int epc_sponsdn_dn_del(char **dn, unsigned int num)
{
	unsigned i;
	unsigned j;
	unsigned num_del = 0;

	/* Reset entries that match */
	for (i = 0; i < free_idx; i++)
		for (j = 0; j < num; j++) {
			if (!strcmp(dn[j], host_names[i])) {
				memset(host_names[i], 0, MAX_DNS_NAME_LEN);
				num_del++;
			}
		}

	/* Replace contents of matching entries from the
	 * end of the array
	 */
	j = free_idx - 1;
	for (i = 0; i < free_idx; i++) {
		if (!host_names[i][0]) {
			for (; j  > i; j--)
				if (host_names[j][0]) {
					strcpy(host_names[i], host_names[j]);
					rule_ids[i] = rule_ids[j];
					break;
				}
		}
	}

	free_idx -= num_del;
	if (free_idx)
		return compile_tbl();

	hs_free_scratch(scratch);
	hs_free_database(database);
	database = NULL;
	return 0;
}

static int event_handler(unsigned int id, __rte_unused unsigned long long from,
			unsigned long long to, __rte_unused unsigned int flags,
			void *ctx)
{
	struct ctx *match_ctx = ctx;

	match_ctx->matching_id = id;
	match_ctx->off = to;
	return 0;
}

static const struct dns_response *next_response(const struct dns_response *resp)
{
	uint16_t len = rte_be_to_cpu_16(resp->data_len);
	char *buf = (char *)&resp->addr;

	return (const struct dns_response *)(buf + len);
}

int epc_sponsdn_scan(const char *resp, unsigned len, char *hname,
		     unsigned *rule_id, struct in_addr *addr4, int *addr4_cnt,
		     __rte_unused char **hname_6,
		     __rte_unused struct in6_addr *addr6,
		     __rte_unused int *addr6_cnt)
{
	const struct dns_query *query;
	const struct dns_response *response;
	const struct dns_header *header = (const struct dns_header *)resp;
	unsigned i;
	unsigned num_ans;
	int cnt4;

	if (!header->ans)
		return -1;

	num_ans = rte_be_to_cpu_16(header->ans);
	if (!num_ans)
		return -1;


	ctx.matching_id = (unsigned)~0;
	if (hs_scan(database, resp, len, 0, scratch, event_handler,
		    &ctx) != HS_SUCCESS) {
		fprintf(stderr,
			"ERROR: Unable to scan input buffer. Exiting.\n");

		return -1;
	}

	if (ctx.matching_id == (unsigned)~0) {
		*addr4_cnt = 0;
		return 0;
	}

	query = (const struct dns_query *)(resp + ctx.off + 1);
	if (!(rte_be_to_cpu_16(query->type) == 1 &&	/* Type = A */
		rte_be_to_cpu_16(query->class) == 1)) { /* Class = IN */
		return -1;
	}

	response = (const struct dns_response *)(query + 1);

	cnt4 = 0;
	for (i = 0; i < num_ans; i++, response = next_response(response)) {
		if (rte_be_to_cpu_16(response->type) != 1)
			continue;

		if (is_compressed_name(response->name)) {
			cnt4++;
			if (addr4)
				*addr4++ = *response->addr;
		} else {
			const char *b = (const char *)resp;

			while (*b) {
				uint8_t skip = *b;

				b += skip + 1;
			}
			response = (const struct dns_response *)(b - 1);
			cnt4++;
			if (addr4)
				*addr4++ = *response->addr;
		}
	}

	*addr4_cnt = cnt4;
	if (hname)
		strncpy(hname, host_names[ctx.matching_id], MAX_DNS_NAME_LEN);

	if (rule_id)
		*rule_id = rule_ids[ctx.matching_id];

	return 0;
}
