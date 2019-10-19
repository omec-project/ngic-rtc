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

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include <search.h>

#include "up_acl.h"
#include "up_main.h"

#define ACL_DENY_SIGNATURE	0x00000000

/* Currently restrict acl context to use single category*/
#define DEFAULT_MAX_CATEGORIES	1

#define uint32_t_to_char(ip, a, b, c, d) do {\
	*a = (unsigned char)((ip) >> 24 & 0xff);\
	*b = (unsigned char)((ip) >> 16 & 0xff);\
	*c = (unsigned char)((ip) >> 8 & 0xff);\
	*d = (unsigned char)((ip) & 0xff);\
} while (0)

#define OFF_ETHHEAD	(sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define MBUF_IPV4_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)

#define GET_CB_FIELD(in, fd, base, lim, dlm)	do {        \
	unsigned long val;                                      \
	char *end;                                              \
	errno = 0;                                              \
	val = strtoul((in), &end, (base));                      \
	if (errno != 0 || end[0] != (dlm) || val > (lim))       \
	return -EINVAL;                                         \
	(fd) = (typeof(fd))val;                                 \
	(in) = end + 1;                                         \
} while (0)

/*
 * ACL rules should have higher priorities than route ones to ensure ACL rule
 * always be found when input packets have multi-matches in the database.
 * An exception case is performance measure, which can define route rules with
 * higher priority and route rules will always be returned in each lookup.
 * Reserve range from ACL_RULE_PRIORITY_MAX + 1 to
 * RTE_ACL_MAX_PRIORITY for route entries in performance measure
 */
#define ACL_RULE_PRIORITY_MAX 0x10000000
#define PREFETCH_OFFSET    8

/*
 * Forward port info save in ACL lib starts from 1
 * since ACL assume 0 is invalid.
 * So, need add 1 when saving and minus 1 when forwarding packets.
 */
#define FWD_PORT_SHIFT 1

static uint32_t acl_table_indx_offset = 1;
static uint32_t acl_table_indx;
/* Max number of sdf rules */
static uint8_t sdf_rule_id;

enum {
	PROTO_FIELD_IPV4,
	SRC_FIELD_IPV4,
	DST_FIELD_IPV4,
	SRCP_FIELD_IPV4,
	DSTP_FIELD_IPV4,
	NUM_FIELDS_IPV4
};

enum {
	RTE_ACL_IPV4VLAN_PROTO,
	RTE_ACL_IPV4VLAN_VLAN,
	RTE_ACL_IPV4VLAN_SRC,
	RTE_ACL_IPV4VLAN_DST,
	RTE_ACL_IPV4VLAN_PORTS,
	RTE_ACL_IPV4VLAN_NUM
};

struct rte_acl_field_def ipv4_defs[NUM_FIELDS_IPV4] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PROTO,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_SRC,
		.offset = offsetof(struct ipv4_hdr, src_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_DST,
		.offset = offsetof(struct ipv4_hdr, dst_addr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV4,
		.input_index = RTE_ACL_IPV4VLAN_PORTS,
		.offset = sizeof(struct ipv4_hdr) -
			offsetof(struct ipv4_hdr, next_proto_id) +
			sizeof(uint16_t),
	},
};

enum {
	CB_FLD_SRC_ADDR,
	CB_FLD_DST_ADDR,
	CB_FLD_SRC_PORT_LOW,
	CB_FLD_SRC_PORT_DLM,
	CB_FLD_SRC_PORT_HIGH,
	CB_FLD_DST_PORT_LOW,
	CB_FLD_DST_PORT_DLM,
	CB_FLD_DST_PORT_HIGH,
	CB_FLD_PROTO,
	CB_FLD_USERDATA,
	CB_FLD_NUM,
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));

struct acl_config {
	//char mapped[NB_SOCKETS];
	struct rte_acl_ctx *acx_ipv4;
	//struct rte_acl_ctx *acx_ipv4[NB_SOCKETS];
	uint8_t acx_ipv4_built;
	//uint8_t acx_ipv4_built[NB_SOCKETS];
};

struct acl_search {
	const uint8_t *data_ipv4[MAX_BURST_SZ];
	struct rte_mbuf *m_ipv4[MAX_BURST_SZ];
	uint32_t res_ipv4[MAX_BURST_SZ];
	int num_ipv4;
};

static struct{
	const char *rule_ipv4_name;
	int scalar;
} parm_config;

const char cb_port_delim[] = ":";

struct acl_rules_table {
	char name[MAX_LEN];
	void *root;
	uint16_t num_entries;
	uint16_t max_entries;
	int (*compare)(const void *r1p, const void *r2p);
	int (*compare_rule)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
	void (*add_entry)(const void *nodep, const VISIT which, const int depth);
};

struct acl_config acl_config[MAX_ACL_TABLES];
struct acl_rules_table acl_rules_table[MAX_ACL_TABLES];
struct acl_search acl_search;


/*******************************************************[START]**********************************************************/
static inline void print_one_ipv4_rule(struct acl4_rule *rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
			rule->field[SRC_FIELD_IPV4].mask_range.u32);
	uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	printf("%hhu.%hhu.%hhu.%hhu/%u ", a, b, c, d,
			rule->field[DST_FIELD_IPV4].mask_range.u32);
	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
			rule->field[SRCP_FIELD_IPV4].value.u16,
			rule->field[SRCP_FIELD_IPV4].mask_range.u16,
			rule->field[DSTP_FIELD_IPV4].value.u16,
			rule->field[DSTP_FIELD_IPV4].mask_range.u16,
			rule->field[PROTO_FIELD_IPV4].value.u8,
			rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x \n",
				rule->data.category_mask,
				rule->data.priority,
				rule->data.userdata & ~ACL_DENY_SIGNATURE);
}

static inline void dump_ipv4_rules(struct acl4_rule *rule, int num, int extra)
{
	int i;
	int j;

	for (i = 0, j = 0; i < MAX_SDF_RULE_NUM; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv4_rule(rule, extra);
		printf("\n");
		j++;
		if (j == num)
			break;
	}
}

static inline void
prepare_one_packet_ipv4(struct rte_mbuf **pkts_in, struct acl_search *acl,
		int index)
{
	struct rte_mbuf *pkt = pkts_in[index];

	/* Fill acl structure */
	acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
	acl->m_ipv4[(acl->num_ipv4)++] = pkt;
}

static inline void
prepare_acl_parameter(struct rte_mbuf **pkts_in, struct acl_search *acl,
		int nb_rx)
{
	int i;

	acl->num_ipv4 = 0;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void *));


	for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod
				(pkts_in[i + PREFETCH_OFFSET], void *));
		prepare_one_packet_ipv4(pkts_in, acl, i);
	}

	/* Process left packets */
	for (; i < nb_rx; i++)
		prepare_one_packet_ipv4(pkts_in, acl, i);
}

static inline void send_one_packet(struct rte_mbuf *m, uint32_t res)
{

	if (likely((res & ACL_DENY_SIGNATURE) == 0 && res != 0)) {
		/* forward packets */
		;
	} else {
		/* in the ACL list, drop it */
		rte_pktmbuf_free(m);
	}
}

/**
*static inline void update_stats(uint32_t *res, int num)
*{
*	int i;
*
*	for (i = 0; i < num; i++) {
*		res[i] &= ~ACL_DENY_SIGNATURE;
*		acl_rule_stats[res[i]]++;
*		RTE_LOG_DP(DEBUG, DP, "ACL_LKUP: rid[%d]:%u\n", i, res[i]);
*	}
*}
*/

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
static int parse_ipv4_net(const char *in, uint32_t *addr, uint32_t *mask_len)
{
	uint8_t a, b, c, d, m;

	GET_CB_FIELD(in, a, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, b, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, c, 0, UINT8_MAX, '.');
	GET_CB_FIELD(in, d, 0, UINT8_MAX, '/');
	GET_CB_FIELD(in, m, 0, sizeof(uint32_t) * CHAR_BIT, 0);

	addr[0] = IPv4(a, b, c, d);
	mask_len[0] = m;

	return 0;
}


void
swap_src_dst_ip(char *str)
{
	char *s, *sp, *in[CB_FLD_NUM], tmp[MAX_LEN] = {0};
	static const char *dlm = " \t\n";
	strncpy(tmp, str, strlen(str));
	s = tmp;
	in[0] = strtok_r(s, dlm, &sp);
	in[1] = strtok_r(NULL, dlm, &sp);
	sprintf(str, "%s %s %s\n", in[1], in[0], sp);
	RTE_LOG_DP(DEBUG, DP, "SDF: UL LINK: %s\n", str);
}


/* Function to the parse the SDF filter rule */
static int
parse_cb_ipv4vlan_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s = NULL, *sp = NULL, *in[CB_FLD_NUM]={0}, tmp[MAX_LEN] = {0};
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;

	strncpy(tmp, str, strlen(str));
	s = tmp;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL) {
			RTE_LOG_DP(DEBUG, DP, "ERROR: String is NULL..\n");
			return -EINVAL;
		}
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		RTE_LOG_DP(ERR, DP, "INVALID Source Address/Mask: %s\n",
				in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		RTE_LOG_DP(ERR, DP, "INVALID Destination Address/Mask: %s\n",
				in[CB_FLD_DST_ADDR]);
		return rc;
	}

	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
			v->field[SRCP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
			v->field[SRCP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0) {
		RTE_LOG_DP(ERR, DP, "INVALID Source Port/Mask: %s\n",
				in[CB_FLD_SRC_PORT_DLM]);
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
			v->field[DSTP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
			v->field[DSTP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0) {
		RTE_LOG_DP(ERR, DP, "INVALID Destination Port/Mask: %s\n",
				in[CB_FLD_DST_PORT_DLM]);
		return -EINVAL;
	}

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
			< v->field[SRCP_FIELD_IPV4].value.u16
			|| v->field[DSTP_FIELD_IPV4].mask_range.u16
			< v->field[DSTP_FIELD_IPV4].value.u16) {
		RTE_LOG_DP(ERR, DP, "INVALID Src and Dst Mask Ranges\n");
		return -EINVAL;
	}

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
			0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
			0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0,
				UINT32_MAX, 0);

	return 0;
}

/**
 * Print the Rule entry.
 */
static void acl_rule_print(const void *nodep, const VISIT which, const int depth)
{
	struct acl4_rule *r = NULL;
	uint32_t precedence = 0;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct acl4_rule **) nodep;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	precedence = r->data.userdata - ACL_DENY_SIGNATURE;
	switch (which) {
	case leaf:
	case postorder:
		printf("Depth: %d, Precedence: %u,",
				depth, precedence);
		printf("Prio: %x, Category mask: %x\n",
				r->data.priority, r->data.category_mask);
		print_one_ipv4_rule(r, 1);
		break;
	default:
		break;
	}
}

/**
 * Dump the table entries.
 * @param table
 *	table - table pointer whose entries to dump.
 *
 * @return
 *	void
 */
void acl_table_dump(struct acl_rules_table *t)
{
	twalk(t->root, t->print_entry);
}

/**
 * Add the Rule entry in rte acl table.
 */
static void add_single_rule(const void *nodep, const VISIT which, const int depth)
{
	struct acl4_rule *r = NULL;

	struct acl_config *pacl_config = &acl_config[acl_table_indx];
	struct rte_acl_ctx *context = pacl_config->acx_ipv4;

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct acl4_rule **) nodep;
#pragma GCC diagnostic pop   /* require GCC 4.6 */

	switch (which) {
	case leaf:
	case postorder:
		if (rte_acl_add_rules(context, (struct rte_acl_rule *)r, 1)) {
			RTE_LOG_DP(ERR, DP, FORMAT":Failed to add sdf rule\n", ERR_MSG);
		}
		RTE_LOG_DP(DEBUG, DP, "SDF Rule Added in ACL table\n");
		break;
	default:
		break;
	}
}

/**
 * Compare entries.
 */
static int acl_rule_prcdnc_compare(const void *r1p, const void *r2p)
{
	struct acl4_rule *r1, *r2;

	r1 = (struct acl4_rule *) r1p;
	r2 = (struct acl4_rule *) r2p;

	/* compare precedence */
	if (r1->data.userdata < r2->data.userdata)
		return -1;
	else if (r1->data.userdata == r2->data.userdata)
		return 0;
	else
		return 1;

}

/**
 * Compare rule entry.
 */
static int acl_rule_compare(const void *r1p, const void *r2p)
{
	struct acl4_rule *rule1, *rule2;

	rule1 = (struct acl4_rule *) r1p;
	rule2 = (struct acl4_rule *) r2p;

	/* compare rule */
	if (rule1->data.userdata == rule2->data.userdata) {
		if (rule1->field[SRC_FIELD_IPV4].value.u16 ==
				rule2->field[SRC_FIELD_IPV4].value.u16) {
			if (rule1->field[SRCP_FIELD_IPV4].mask_range.u16 ==
					rule2->field[SRCP_FIELD_IPV4].mask_range.u16) {
				if (rule1->field[DST_FIELD_IPV4].value.u16 ==
						rule2->field[DST_FIELD_IPV4].value.u16) {
					if (rule1->field[DSTP_FIELD_IPV4].mask_range.u16 ==
							rule2->field[DSTP_FIELD_IPV4].mask_range.u16) {
						if (rule1->field[PROTO_FIELD_IPV4].value.u8 ==
								rule2->field[PROTO_FIELD_IPV4].value.u8) {
							if (rule1->field[PROTO_FIELD_IPV4].mask_range.u8 ==
								rule2->field[PROTO_FIELD_IPV4].mask_range.u8) {
								RTE_LOG_DP(DEBUG, DP, "SDF Rule matched...\n");
								return 0;
							}
						}
					}
				}
			}
		}
	}
	return -1;
}

/**
 * Create ACL table.
 * @param ACL Table index
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
up_acl_rules_table_create(uint32_t indx, uint32_t max_elements)
{
	struct acl_rules_table *t = &acl_rules_table[indx];
	if (t->root != NULL) {
		RTE_LOG_DP(DEBUG, DP, FORMAT"ACL table: \"%s\" exist\n", ERR_MSG, t->name);
		return -1;
	}

	t->num_entries = 0;
	t->max_entries = max_elements;
	sprintf(t->name, "ACL_RULES_TABLE-%u", indx);
	t->compare = acl_rule_prcdnc_compare;
	t->compare_rule = acl_rule_compare;
	t->print_entry = acl_rule_print;
	t->add_entry = add_single_rule;
	RTE_LOG_DP(DEBUG, DP, "ACL rules table: \"%s\" created\n", t->name);
	return 0;
}

/**
 *	Init acl table context.
 *	If cflag ACL_READ_CFG is enabled, this function reads rules
 *	from config file and build acl tables. Else it will add
 *	default rule "0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0"
 *	with id = max_elements.
 *
 * @param name
 *	name string for table name.
 * @param acl_num
 *	max elements that can be added in this table.
 * @param rs
 *	each rule size
 * @param ipv6
 *	set this if rules are ipv6
 * @param socketid
 *	socket id
 *
 * @return
 *	rte_acl_ctx on Success.
 *	NULL on Failure.
 */
static struct rte_acl_ctx *acl_context_init(char *name,
		unsigned int max_elements, int rs, int ipv6,
		int socketid)
{
	struct rte_acl_ctx *context = NULL;
	struct rte_acl_param acl_param = {0};
	int dim = RTE_DIM(ipv4_defs);

	/* Create ACL contexts */
	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = max_elements;

	/*Create the ACL Table */
	context = rte_acl_create(&acl_param);
	if (context == NULL)
		rte_exit(EXIT_FAILURE, FORMAT"Failed to create ACL context\n", ERR_MSG);

	if (parm_config.scalar
			&& rte_acl_set_ctx_classify(context,
				RTE_ACL_CLASSIFY_SCALAR)
			!= 0)
		rte_exit(EXIT_FAILURE, FORMAT"Failed to setup classify method for ACL context\n",
			ERR_MSG);

	return context;
}

/**
 * Init config of acl tables.
 *
 * @param acl_config
 *	config base address of this table.
 * @param name
 *	name string for table name.
 * @param max_elements
 *	max elements that can be added in this table.
 * @param rs
 *	rule size of each elements.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
acl_config_init(struct acl_config *acl_config,
		char *name, uint32_t max_elements, int rs)
{

	memset(acl_config, 0, sizeof(struct acl_config));

	acl_config->acx_ipv4 =
	acl_context_init(name, max_elements, rs, 0, 0);
	return 0;
}

/**
 *  Create SDF rules table
 *
 * @param max_elements
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
up_sdf_filter_table_create(uint32_t max_elements)
{
	char name[32];
	char *buf = "ACLTable-";
	acl_table_indx = acl_table_indx_offset;

	/* Increment the New Created ACL tables */
	sprintf(name, "%s%u", buf, acl_table_indx);

	/* Configure the ACL table */
	if (acl_config_init(&acl_config[acl_table_indx], name,
			max_elements, sizeof(struct acl4_rule)) < 0) {
		/* TODO: Error Handling */
		return -1;
	}

	/* Create the local acl rules table copy */
	if (up_acl_rules_table_create(acl_table_indx, max_elements)) {
		/* TODO: Error Handling */
		return -1;
	}

	/* Increment the ACL Table index */
	acl_table_indx_offset++;
	/* Return New created ACL table index */
	return acl_table_indx;
}

/**
 * Add rules from local table to rte acl rules table.
 * @param ACL Table Index
 *
 * @return
 *	void
 */
static void
add_rules_to_rte_acl(uint8_t indx)
{
	struct acl_rules_table *t = &acl_rules_table[indx];
	acl_table_indx = indx;
	twalk(t->root, t->add_entry);
}

/**
 * To reset and build ACL table.
 *	This funciton reset the acl context rules,
 *	and add the new rules and build table.
 *	This should be called only for standby tables.
 *
 * @param ACL Table Index
 *	table index to reset and build.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
reset_and_build_rules(uint32_t indx)
{
	int ret = 0;
	int dim = RTE_DIM(ipv4_defs);
	struct rte_acl_config acl_build_param = {0};
	struct acl_config *pacl_config = &acl_config[indx];
	struct rte_acl_ctx *context = pacl_config->acx_ipv4;

	/* Delete all rules from the ACL context. */
	rte_acl_reset_rules(context);

	/* Add the rules from local table to ACL table */
	add_rules_to_rte_acl(indx);

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	memcpy(&acl_build_param.defs, ipv4_defs,
			sizeof(ipv4_defs));

	/* Build the ACL run time structure */
	if ((ret = rte_acl_build(context, &acl_build_param)) != 0) {
		rte_exit(EXIT_FAILURE, FORMAT"Failed to build ACL trie,"
				"ACL_RULES_TABLE-%u, ret:%d, error:%s\n",
				ERR_MSG, indx, ret, rte_strerror(rte_errno));
	}

	pacl_config->acx_ipv4_built = 1;

#ifdef DEBUG_ACL
	rte_acl_dump(context);
#endif
	return 0;
}

/**
 * Add rules entry.
 * @param t
 *	rules table pointer
 * @param rule
 *	element to be added in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
up_rules_entry_add(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	if (t->num_entries == t->max_entries)
		RTE_LOG_DP(DEBUG, DP, FORMAT":%s reached max rules entries\n", ERR_MSG, t->name);

	struct acl4_rule *new = rte_malloc("acl_rule", sizeof(struct acl4_rule),
			RTE_CACHE_LINE_SIZE);
	if (new == NULL) {
		RTE_LOG_DP(DEBUG, DP, FORMAT"ADC: Failed to allocate memory\n", ERR_MSG);
		return -1;
	}
	*new = *rule;
	/* put node into the tree */
	if (tsearch(new, &t->root, t->compare) == 0) {
		RTE_LOG_DP(DEBUG, DP, FORMAT":Fail to add acl precedance %d\n", ERR_MSG,
				rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}

	t->num_entries++;
	return 0;
}

/* Currently NOT USING */
/**
 *	To add sdf or adc filter in acl table.
 *	The entries are first stored in local memory and then updated on
 *	standby table.
 *
 * @param ACL table Index
 * @param sdf_pkt_filter
 *	packet filter which include ruleid, priority and
 *		acl rule string to be added.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
up_filter_entry_add(uint32_t indx, struct sdf_pkt_filter *pkt_filter)
{
	struct acl4_rule r = {0};
	struct rte_acl_rule *next = NULL;

	char *buf = NULL;
	uint8_t prio = 0;

	/* check sdf filter exist or not */
	if (pkt_filter == NULL) {
		fprintf(stderr, "%s:%d read msg_payload failed\n", __func__, __LINE__);
		return -1;
	}

	/* TODO: Ensure rule_id does not exceed max num rules*/
	if (sdf_rule_id == SDF_DEFAULT_DROP_RULE_ID)
		prio = 0;

	prio = (255 - pkt_filter->precedence);
	buf = (char *)&pkt_filter->u.rule_str[0];
	next = (struct rte_acl_rule *)&r;

	/* Parse the sdf filter into acl ipv4 rule format */
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
		fprintf(stderr, "%s:%d\n"
				"parse rules error\n", __func__, __LINE__);
		return -1;
	}

	next->data.userdata = pkt_filter->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;

	/* Find similar rule is present or not */
	struct acl_rules_table *ctx = &acl_rules_table[indx];
	struct acl_rules_table *t = NULL;
	if (ctx != NULL) {

		RTE_LOG_DP(DEBUG, DP, "Search SDF Rule in ACL_Table_Index-%u\n", indx);
		t = tfind(next, &ctx->root, ctx->compare_rule);
		if (t != NULL) {
			RTE_LOG_DP(DEBUG, DP, "SDF Rule match in ACL_Table_Index-%u\nDP: SDF Rule:%s\n",
				indx, pkt_filter->u.rule_str);
			return 0;
		}
	}

	if (up_rules_entry_add(&acl_rules_table[indx],
				(struct acl4_rule *)next) < 0) {
		return -1;
	}

	if (reset_and_build_rules(indx) < 0)
		return -1;

	RTE_LOG_DP(DEBUG, DP, "ACL ADD: %s, ACL_Indx:%u, precedence:%u, rule:%s\n",
			"SDF RULE", indx, pkt_filter->precedence, pkt_filter->u.rule_str);
	return 0;
}

/**
 *  Add SDF rules
 *
 * @param  pkt_filter
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_entry_add(uint32_t indx, struct sdf_pkt_filter *pkt_filter)
{
	static int is_first = 1;
	/* TODO: Need to think on CDR records */
	if (is_first == 1) {
		//cdr_init();
		is_first = 0;
	}

	if (up_filter_entry_add(indx, pkt_filter)) {
		/* TODO: ERROR Handling */
		return -1;
	}

	return 0;
}

/* Function to retrive the acl table index */
int
get_acl_table_indx(struct sdf_pkt_filter *pkt_filter)
{
	uint8_t prio = 0;
	uint32_t it = 0;
	char *buf = NULL;
	struct acl4_rule r = {0};
	struct rte_acl_rule *next = NULL;

	/* check sdf filter exist or not */
	if (pkt_filter == NULL) {
		fprintf(stderr, FORMAT":read msg_payload failed\n", ERR_MSG);
		return -1;
	}

	/* TODO: Need to check this */
	prio = (255 - pkt_filter->precedence);
	buf = (char *)&pkt_filter->u.rule_str[0];
	next = (struct rte_acl_rule *)&r;

	/* Parse the sdf filter into acl ipv4 rule format */
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
		fprintf(stderr, FORMAT": parse rules error\n", ERR_MSG);
		return -1;
	}

	/* Fill the received rule information */
	next->data.userdata = pkt_filter->precedence + ACL_DENY_SIGNATURE;
	/* TODO: Need to check */
	next->data.priority = prio;
	next->data.category_mask = -1;

	/* Find similar rule is present or not */
	for (uint32_t itr = 1; itr < acl_table_indx_offset; itr++) {
		struct acl_rules_table *ctx = &acl_rules_table[itr];
		struct acl_rules_table *t = NULL;
		if (ctx == NULL)
			continue;

		RTE_LOG_DP(DEBUG, DP, "Search SDF Rule in ACL_Table_Index-%u\n", itr);
		t = tfind(next, &ctx->root, ctx->compare_rule);
		if (t != NULL) {
			RTE_LOG_DP(DEBUG, DP, "SDF Rule match in ACL_Table_Index-%u\nDP: SDF Rule:%s\n",
				itr, pkt_filter->u.rule_str);
			return itr;
		}
	}

	/* If ACL table is not present than create the new ACL table */
	if ((it = up_sdf_filter_table_create(MAX_SDF_RULE_NUM)) < 0) {
		return -1;
	}

	/* Add the sdf filter rule in ACL table */
	if (up_rules_entry_add(&acl_rules_table[it],
				(struct acl4_rule *)next) < 0) {
		return -1;
	}

	RTE_LOG_DP(DEBUG, DP, "ACL ADD:%s, precedence:%u, rule:%s\n",
			"SDF", pkt_filter->precedence, pkt_filter->u.rule_str);

	/* Rebuild the ACl table */
	if (reset_and_build_rules(it) < 0)
		return -1;
	return it;
}

/**
 * Free the memory allocated for node.
 * @param p
 *	void pointer to be free.
 *
 * @return
 *	None
 */
static void
free_node(void *p)
{
	rte_free(p);
}

/**
 * Delete Rules table.
 * @param t
 *	rules table pointer.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
up_acl_rules_table_delete(struct acl_rules_table *t)
{
	tdestroy(&t->root, free_node);
	RTE_LOG_DP(DEBUG, DP, FORMAT"ACL Rules table: \"%s\" destroyed\n",
				ERR_MSG, t->name);
	memset(t, 0, sizeof(struct acl_rules_table));
	return 0;
}

/**
 *  Delete SDF rules table
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_table_delete(uint32_t indx)
{
	struct rte_acl_ctx *ctx = acl_config[indx].acx_ipv4;
	struct acl_rules_table *t = &acl_rules_table[indx];

	/* Delete all rules from the ACL context and destroy all internal run-time structures */
	rte_acl_reset(ctx);

	/* Delete entry from local table */
	if(up_acl_rules_table_delete(t)) {
		/* TODO: ERROR Handling */
		return -1;
	}

	/* Deleted ACL Table */
	--acl_table_indx_offset;
	acl_table_indx = 0;
	RTE_LOG_DP(DEBUG, DP, "ACL table %s deleted", ctx->name);

	rte_free(ctx);
	return 0;
}

/**
 * Delete rules entry.
 * @param t
 *	rules table pointer
 * @param rule
 *	element to be deleted from this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_rules_entry_delete(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	void **p;
	/* delete node from the tree */
	p = tdelete(rule, &t->root, t->compare);
	if (p == NULL) {
		RTE_LOG_DP(DEBUG, DP, FORMAT"Fail to delete acl rule id %d\n", ERR_MSG,
						rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}
	rte_free(*p);
	t->num_entries--;

	return 0;
}

/**
 * Delete SDF rules.
 * To delete sdf filter in acl table.
 * The entries are first removed in local memory and then updated on
 * ACL table.
 *
 * @param  pkt_filter
 *	sdf packet filter entry structure
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
up_sdf_filter_entry_delete(uint32_t indx,
			struct sdf_pkt_filter *pkt_filter_entry)
{
	uint32_t precedence = 0;
	struct acl4_rule rule = {0};
	struct rte_acl_ctx *ctx = acl_config[indx].acx_ipv4;

	if (pkt_filter_entry == NULL) {
		fprintf(stderr, FORMAT":read msg_payload failed\n", ERR_MSG);
		return -1;
	}

	precedence = pkt_filter_entry->precedence;
	RTE_LOG_DP(DEBUG, DP, "ACL DEL:%s precedence:%u\n",
			ctx->name, precedence);

	rule.data.userdata = precedence + ACL_DENY_SIGNATURE;
	up_rules_entry_delete(&acl_rules_table[indx], &rule);

	return reset_and_build_rules(indx);
}

static uint32_t *acl_lookup(struct rte_mbuf **m, uint32_t indx,
		struct acl_config *acl_config,
		struct acl_search *acl_search)
{
	if (acl_config != NULL) {

		if (((acl_config->acx_ipv4)->trans_table != NULL)) {

			prepare_acl_parameter(m, acl_search, 1);

			if (acl_search->num_ipv4) {
				rte_acl_classify(acl_config->acx_ipv4,
						acl_search->data_ipv4,
						acl_search->res_ipv4,
						acl_search->num_ipv4,
						DEFAULT_MAX_CATEGORIES);

				//update_stats((acl_search+lcore_id)->res_ipv4,
				//		(acl_search+lcore_id)->num_ipv4);
			}
		}
		return (uint32_t *)&(acl_search->res_ipv4);
	}
	RTE_LOG_DP(DEBUG, DP, "ERROR: ACL Context is NULL \n");
	return 0;
}

uint32_t *sdf_lookup(struct rte_mbuf **m, int nb_rx, uint32_t indx)
{
	RTE_SET_USED(nb_rx);
	return acl_lookup(m, indx, &acl_config[indx], &acl_search);
}

/**
 *  Create the ACL table and add SDF rules
 * @param precedence
 *    PDR precedence
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
int
default_up_filter_entry_add(uint32_t precedence, uint8_t direction)
{
	uint32_t indx = 0;
	struct sdf_pkt_filter pktf = {
			.precedence = precedence,
		};

	if (direction == UPLINK ) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			"0.0.0.0", 0, /*local_ip & mask */
			"0.0.0.0", 0, /*remote_ip, mask,*/
			0, /*local_port_low),*/
			65535, /*local_port_high),*/
			0,/*remote_port_low),*/
			65535, /*remote_port_high),*/
			0, 0/*proto, proto_mask)*/
			);
	} else {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			"0.0.0.0", 0, /*local_ip & mask */
			"0.0.0.0", 0, /*remote_ip, mask,*/
			0, /*local_port_low),*/
			65535, /*local_port_high),*/
			0,/*remote_port_low),*/
			65535, /*remote_port_high),*/
			0, 0/*proto, proto_mask)*/
			);
	}

	/* If ACL table is not present than create the new ACL table */
	if ((indx = up_sdf_filter_table_create(MAX_SDF_RULE_NUM)) < 0) {
		return -1;
	}

	if (up_filter_entry_add(indx, &pktf)) {
		/* TODO: ERROR Handling */
		return -1;
	}

	RTE_LOG_DP(DEBUG, DP, "ACL ADD:%s, precedence:%u, rule:%s\n",
			"SDF", pktf.precedence, pktf.u.rule_str);
	return indx;
}

/* Function to add the default entry into the acl table */
int up_sdf_default_entry_add(uint32_t indx, uint32_t precedence, uint8_t direction)
{
	struct sdf_pkt_filter pktf = {
			.precedence = precedence,
		};

	if (direction == UPLINK ) {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			"16.0.0.0", 0, /*local_ip & mask */
			"0.0.0.0", 0, /*remote_ip, mask,*/
			0, /*local_port_low),*/
			65535, /*local_port_high),*/
			0,/*remote_port_low),*/
			65535, /*remote_port_high),*/
			0, 0/*proto, proto_mask)*/
			);
	} else {
		snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
			PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
			PRIx8"/0x%"PRIx8"\n",
			"13.0.0.0", 0, /*local_ip & mask */
			"0.0.0.0", 0, /*remote_ip, mask,*/
			0, /*local_port_low),*/
			65535, /*local_port_high),*/
			0,/*remote_port_low),*/
			65535, /*remote_port_high),*/
			0, 0/*proto, proto_mask)*/
			);
	}

	if (up_filter_entry_add(indx, &pktf))
		return -1;

	RTE_LOG_DP(DEBUG, DP, "ACL ADD:%s, precedence:%u, rule:%s\n",
			"SDF", pktf.precedence, pktf.u.rule_str);
	return 0;
}
/*******************************************************[END]**********************************************************/
/**
static uint8_t
retrive_acl_table_indx(char *str)
{
	uint8_t idx = 0, index = 0, indx = 0;
	char buf[MAX_LEN] = {0};

	if(str == NULL)
	{
		fprintf(stderr, "%s:%d String is NULL\n",
				__func__, __LINE__);
		return -1;
	}

	idx = 9;
	for(;str[idx] != '\0'; ++idx)
	{
		buf[index] = str[idx];
		++index;
	}

	indx = atoi(buf);
	if (indx < 0) {
		fprintf(stderr, "%s:%d ACL Table index not found\n",
				__func__, __LINE__);
		return -1;
	}

	return indx;
}
*/

////VS
//int up_sdf_default_entry_action_modify(uint32_t itr, uint32_t precedence)
//{
//	struct acl4_rule rule = {0};
//	struct rte_acl_ctx *ctx = &acl_config[itr];
//
//	RTE_LOG_DP(DEBUG, DP, "ACL DEL:%s precedence:%d\n",
//			"SDF", precedence);
//
//	rule.data.userdata = precedence + ACL_DENY_SIGNATURE;
//	if (up_rules_entry_delete(&acl_rules_table[itr], &rule))
//		return -1;
//
//	struct sdf_pkt_filter pktf = {
//			.precedence = 0,
//			//.precedence = SDF_DEFAULT_RULE_ID,
//		};
//
//	snprintf(pktf.u.rule_str, MAX_LEN, "%s/%"PRIu8" %s/%"PRIu8" %"
//		PRIu16" : %"PRIu16" %"PRIu16" : %"PRIu16" 0x%"
//		PRIx8"/0x%"PRIx8"\n",
//		"0.0.0.0", 0, /*local_ip & mask */
//		"0.0.0.0", 0, /*remote_ip, mask,*/
//		0, /*local_port_low),*/
//		65535, /*local_port_high),*/
//		0,/*remote_port_low),*/
//		65535, /*remote_port_high),*/
//		0, 0/*proto, proto_mask)*/
//		);
//
//	if (up_filter_entry_add(ctx, &pktf) < 0)
//		return -1;
//
//	return 0;
//}
