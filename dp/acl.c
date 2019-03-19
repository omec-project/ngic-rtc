/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#define _GNU_SOURCE     /* Expose declaration of tdestroy() */
#include <search.h>

#include "cdr.h"
#include "acl_dp.h"
#include "acl.h"
#include "main.h"
#include "interface.h"

#define acl_log(format, ...)    RTE_LOG_DP(ERR, DP, format, ##__VA_ARGS__)

#define COMMENT_LEAD_CHAR	('#')
#define OPTION_RULE_IPV4	"rule_ipv4"
#define OPTION_RULE_IPV6	"rule_ipv6"
#define OPTION_SCALAR		"scalar"
#define ACL_DENY_SIGNATURE	0x00000000

/* Currently restrict acl context to use single category*/
#define DEFAULT_MAX_CATEGORIES	1
#define NB_SOCKETS 8

#define uint32_t_to_char(ip, a, b, c, d) do {\
	*a = (unsigned char)((ip) >> 24 & 0xff);\
	*b = (unsigned char)((ip) >> 16 & 0xff);\
	*c = (unsigned char)((ip) >> 8 & 0xff);\
	*d = (unsigned char)((ip) & 0xff);\
} while (0)
#define OFF_ETHHEAD	(sizeof(struct ether_hdr))
#define OFF_IPV42PROTO (offsetof(struct ipv4_hdr, next_proto_id))
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV62PROTO)

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

#define	IPV6_ADDR_LEN	16
#define	IPV6_ADDR_U16	(IPV6_ADDR_LEN / sizeof(uint16_t))
#define	IPV6_ADDR_U32	(IPV6_ADDR_LEN / sizeof(uint32_t))



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
	PROTO_FIELD_IPV6,
	SRC1_FIELD_IPV6,
	SRC2_FIELD_IPV6,
	SRC3_FIELD_IPV6,
	SRC4_FIELD_IPV6,
	DST1_FIELD_IPV6,
	DST2_FIELD_IPV6,
	DST3_FIELD_IPV6,
	DST4_FIELD_IPV6,
	SRCP_FIELD_IPV6,
	DSTP_FIELD_IPV6,
	NUM_FIELDS_IPV6
};

struct rte_acl_field_def ipv6_defs[NUM_FIELDS_IPV6] = {
	{
		.type = RTE_ACL_FIELD_TYPE_BITMASK,
		.size = sizeof(uint8_t),
		.field_index = PROTO_FIELD_IPV6,
		.input_index = PROTO_FIELD_IPV6,
		.offset = 0,
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC1_FIELD_IPV6,
		.input_index = SRC1_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, src_addr) -
			offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC2_FIELD_IPV6,
		.input_index = SRC2_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, src_addr) -
			offsetof(struct ipv6_hdr, proto) + sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC3_FIELD_IPV6,
		.input_index = SRC3_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, src_addr) -
			offsetof(struct ipv6_hdr, proto) + 2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = SRC4_FIELD_IPV6,
		.input_index = SRC4_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, src_addr) -
			offsetof(struct ipv6_hdr, proto) + 3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST1_FIELD_IPV6,
		.input_index = DST1_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr)
			- offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST2_FIELD_IPV6,
		.input_index = DST2_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr) -
			offsetof(struct ipv6_hdr, proto) + sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST3_FIELD_IPV6,
		.input_index = DST3_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr) -
			offsetof(struct ipv6_hdr, proto) + 2 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_MASK,
		.size = sizeof(uint32_t),
		.field_index = DST4_FIELD_IPV6,
		.input_index = DST4_FIELD_IPV6,
		.offset = offsetof(struct ipv6_hdr, dst_addr) -
			offsetof(struct ipv6_hdr, proto) + 3 * sizeof(uint32_t),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = SRCP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = sizeof(struct ipv6_hdr) -
			offsetof(struct ipv6_hdr, proto),
	},
	{
		.type = RTE_ACL_FIELD_TYPE_RANGE,
		.size = sizeof(uint16_t),
		.field_index = DSTP_FIELD_IPV6,
		.input_index = SRCP_FIELD_IPV6,
		.offset = sizeof(struct ipv6_hdr) -
			offsetof(struct ipv6_hdr, proto) + sizeof(uint16_t),
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
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

struct acl_config {
	char mapped[NB_SOCKETS];
	struct rte_acl_ctx *acx_ipv4[NB_SOCKETS];
	struct rte_acl_ctx *acx_ipv6[NB_SOCKETS];
	uint8_t acx_ipv4_built[NB_SOCKETS];
	uint8_t acx_ipv6_built[NB_SOCKETS];
};

struct acl_search {
	const uint8_t *data_ipv4[MAX_BURST_SZ];
	struct rte_mbuf *m_ipv4[MAX_BURST_SZ];
	uint32_t res_ipv4[MAX_BURST_SZ];
	int num_ipv4;

	const uint8_t *data_ipv6[MAX_BURST_SZ];
	struct rte_mbuf *m_ipv6[MAX_BURST_SZ];
	uint32_t res_ipv6[MAX_BURST_SZ];
	int num_ipv6;
};

static struct{
	const char *rule_ipv4_name;
	const char *rule_ipv6_name;
	int scalar;
} parm_config;

const char cb_port_delim[] = ":";
extern struct app_params app;

enum acl_cfg_tbl{
	SDF_ACTIVE,
	SDF_STANDBY,
	ADC_UL_ACTIVE,
	ADC_UL_STANDBY,
	ADC_DL_ACTIVE,
	ADC_DL_STANDBY,
	MAX_TBLS,
};
enum acl_rules_params{
	SDF_PARAM,
	ADC_UL_PARAM,
	ADC_DL_PARAM,
	MAX_PARAM,
};
struct acl_rules_table {
	char name[MAX_LEN];
	void *root;
	uint16_t num_entries;
	uint16_t max_entries;
	int (*compare)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
	void (*add_entry)(const void *nodep, const VISIT which, const int depth);
};

struct acl_config acl_config[MAX_TBLS];
struct acl_search acl_search[MAX_PARAM][DP_MAX_LCORE];
enum acl_cfg_tbl sdf_active_tbl = SDF_ACTIVE;
enum acl_cfg_tbl adc_ul_active_tbl = ADC_UL_ACTIVE, adc_dl_active_tbl = ADC_DL_ACTIVE;
enum acl_cfg_tbl config_tbl;
struct acl_rules_table acl_rules_table[MAX_PARAM];

extern struct rte_hash *rte_sdf_pcc_hash;
extern struct rte_hash *rte_adc_pcc_hash;

#ifdef ACL_READ_CFG
/* to read cfg file. */
struct rte_acl_rule *acl_base_ipv4, *acl_base_ipv6;
unsigned int acl_num_ipv4, acl_num_ipv6;
#endif /* ACL_READ_CFG */

/**
 * Compare entries.
 */
static int acl_rule_id_compare(const void *r1p, const void *r2p)
{
	struct acl4_rule *r1, *r2;

	r1 = (struct acl4_rule *) r1p;
	r2 = (struct acl4_rule *) r2p;

	/* compare rule_ids */
	if (r1->data.userdata < r2->data.userdata)
		return -1;
	else if (r1->data.userdata == r2->data.userdata)
		return 0;
	else
		return 1;

}

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
/**
 * Print the Rule entry.
 */
static void acl_rule_print(const void *nodep, const VISIT which, const int depth)
{
	struct acl4_rule *r;
	uint32_t rule_id;
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct acl4_rule **) nodep;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	rule_id = r->data.userdata - ACL_DENY_SIGNATURE;
	switch (which) {
	case leaf:
	case postorder:
		printf("Depth: %d, Rule ID: %u,",
				depth, rule_id);
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
 * Print the Rule entry in rte acl table.
 */
static void add_single_rule(const void *nodep, const VISIT which, const int depth)
{
	struct acl4_rule *r;
	/*
	 * Check numa socket enable or disable based on
	 * get or set socketid.
	 */
	int socketid = app.numa_on?rte_socket_id():0;

	struct acl_config *pacl_config = &acl_config[config_tbl];
	struct rte_acl_ctx *context = pacl_config->acx_ipv4[socketid];
#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct acl4_rule **) nodep;
#pragma GCC diagnostic pop   /* require GCC 4.6 */
	//uint32_t rule_id; //GCC_Security flag
	//rule_id = r->data.userdata - ACL_DENY_SIGNATURE;
	switch (which) {
	case leaf:
	case postorder:
		rte_acl_add_rules(context, (struct rte_acl_rule *)r, 1);
		break;
	default:
		break;
	}
}
/**
 * Add rules from local table to rte acl rules table.
 * @param type
 *	table type.
 *
 * @return
 *	void
 */
static void add_rules_to_rte_acl(enum acl_cfg_tbl type)
{
	struct acl_rules_table *t = &acl_rules_table[type/2];
	config_tbl = type;
	twalk(t->root, t->add_entry);
}
/**
 * Create ACL table.
 * @param type
 *	rules table type.
 * @param max_element
 *	max number of elements in this table.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
dp_acl_rules_table_create(enum acl_rules_params type, uint32_t max_elements)
{
	struct acl_rules_table *t = &acl_rules_table[type];
	if (t->root != NULL) {
		RTE_LOG_DP(INFO, DP, "ACL table: \"%s\" exist\n", t->name);
		return -1;
	}
	t->num_entries = 0;
	t->max_entries = max_elements;
	sprintf(t->name, "ACL_RULES_TABLE-%d", type);
	t->compare = acl_rule_id_compare;
	t->print_entry = acl_rule_print;
	t->add_entry = add_single_rule;
	RTE_LOG_DP(INFO, DP, "ACL rules table: \"%s\" created\n", t->name);
	return 0;
}

/**
 * Free the memory allocated for node.
 * @param p
 *	void pointer to be free.
 *
 * @return
 *	None
 */
static void free_node(void *p)
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
int
dp_acl_rules_table_delete(struct acl_rules_table *t)
{
	tdestroy(&t->root, free_node);
	RTE_LOG_DP(INFO, DP, "ACL Rules table: \"%s\" destroyed\n", t->name);
	memset(t, 0, sizeof(struct acl_rules_table));
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
int
dp_rules_entry_add(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	if (t->num_entries == t->max_entries)
		RTE_LOG_DP(INFO, DP, "%s reached max rules entries\n", t->name);

	struct acl4_rule *new = rte_malloc("acl_rule", sizeof(struct acl4_rule),
			RTE_CACHE_LINE_SIZE);
	if (new == NULL) {
		RTE_LOG_DP(INFO, DP, "ADC: Failed to allocate memory\n");
		return -1;
	}
	*new = *rule;
	/* put node into the tree */
	if (tsearch(new, &t->root, t->compare) == 0) {
		RTE_LOG_DP(INFO, DP, "Fail to add acl rule id %d\n",
				rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}

	t->num_entries++;
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
dp_rules_entry_delete(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	void **p;
	/* delete node from the tree */
	p = tdelete(rule, &t->root, t->compare);
	if (p == NULL) {
		RTE_LOG_DP(INFO, DP, "Fail to delete acl rule id %d\n",
						rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}
	rte_free(*p);
	t->num_entries--;

	return 0;
}

static inline void print_one_ipv6_rule(struct acl6_rule *rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC1_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC2_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC3_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[SRC4_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
			rule->field[SRC1_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC2_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC3_FIELD_IPV6].mask_range.u32
			+ rule->field[SRC4_FIELD_IPV6].mask_range.u32);

	uint32_t_to_char(rule->field[DST1_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf("%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST2_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST3_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x", a, b, c, d);
	uint32_t_to_char(rule->field[DST4_FIELD_IPV6].value.u32,
			&a, &b, &c, &d);
	printf(":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
			rule->field[DST1_FIELD_IPV6].mask_range.u32
			+ rule->field[DST2_FIELD_IPV6].mask_range.u32
			+ rule->field[DST3_FIELD_IPV6].mask_range.u32
			+ rule->field[DST4_FIELD_IPV6].mask_range.u32);

	printf("%hu : %hu %hu : %hu 0x%hhx/0x%hhx ",
			rule->field[SRCP_FIELD_IPV6].value.u16,
			rule->field[SRCP_FIELD_IPV6].mask_range.u16,
			rule->field[DSTP_FIELD_IPV6].value.u16,
			rule->field[DSTP_FIELD_IPV6].mask_range.u16,
			rule->field[PROTO_FIELD_IPV6].value.u8,
			rule->field[PROTO_FIELD_IPV6].mask_range.u8);
	if (extra)
		printf("0x%x-0x%x-0x%x ",
				rule->data.category_mask,
				rule->data.priority, rule->data.userdata);
}

/* Bypass comment and empty lines */
static inline int is_bypass_line(char *buff)
{
	int i = 0;

	/* comment line */
	if (buff[0] == COMMENT_LEAD_CHAR)
		return 1;
	/* empty line */
	while (buff[i] != '\0') {
		if (!isspace(buff[i]))
			return 0;
		i++;
	}
	return 1;
}

static inline void dump_ipv4_rules(struct acl4_rule *rule, int num, int extra)
{
	int i;
	int j;

	for (i = 0, j = 0; i < MAX_ACL_RULE_NUM; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv4_rule(rule, extra);
		printf("\n");
		j++;
		if (j == num)
			break;
	}
}

static inline void dump_ipv6_rules(struct acl6_rule *rule, int num, int extra)
{
	int i;

	for (i = 0; i < num; i++, rule++) {
		printf("\t%d:", i + 1);
		print_one_ipv6_rule(rule, extra);
		printf("\n");
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
	acl->num_ipv6 = 0;

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

static inline void update_stats(uint32_t *res, int num)
{
	int i;

	for (i = 0; i < num; i++) {
		res[i] &= ~ACL_DENY_SIGNATURE;
		acl_rule_stats[res[i]]++;
		RTE_LOG_DP(DEBUG, DP, "ACL_LKUP: rid[%d]:%u\n", i, res[i]);
	}
}

/*
 * Parses IPV6 address, exepcts the following format:
 * XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX (where X - is a hexedecimal digit).
 */
	static int
parse_ipv6_addr(const char *in, const char **end, uint32_t v[IPV6_ADDR_U32],
		char dlm)
{
	uint32_t addr[IPV6_ADDR_U16];

	GET_CB_FIELD(in, addr[0], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[1], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[2], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[3], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[4], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[5], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[6], 16, UINT16_MAX, ':');
	GET_CB_FIELD(in, addr[7], 16, UINT16_MAX, dlm);

	*end = in;

	v[0] = (addr[0] << 16) + addr[1];
	v[1] = (addr[2] << 16) + addr[3];
	v[2] = (addr[4] << 16) + addr[5];
	v[3] = (addr[6] << 16) + addr[7];

	return 0;
}

static int parse_ipv6_net(const char *in, struct rte_acl_field field[4])
{
	int32_t rc;
	const char *mp;
	uint32_t i, m, v[4];
	const uint32_t nbu32 = sizeof(uint32_t) * CHAR_BIT;

	/* get address. */
	rc = parse_ipv6_addr(in, &mp, v, '/');
	if (rc != 0)
		return rc;

	/* get mask. */
	GET_CB_FIELD(mp, m, 0, CHAR_BIT * sizeof(v), 0);

	/* put all together. */
	for (i = 0; i != RTE_DIM(v); i++) {
		if (m >= (i + 1) * nbu32)
			field[i].mask_range.u32 = nbu32;
		else
			field[i].mask_range.u32 = m > (i * nbu32) ?
				m - (i * 32) : 0;

		field[i].value.u32 = v[i];
	}

	return 0;
}

	static int __rte_unused
parse_cb_ipv6_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s, *sp, *in[CB_FLD_NUM];
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;

	s = str;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv6_net(in[CB_FLD_SRC_ADDR], v->field + SRC1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
				in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv6_net(in[CB_FLD_DST_ADDR], v->field + DST1_FIELD_IPV6);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
				in[CB_FLD_DST_ADDR]);
		return rc;
	}

	/* source port. */
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
			v->field[SRCP_FIELD_IPV6].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
			v->field[SRCP_FIELD_IPV6].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	/* destination port. */
	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
			v->field[DSTP_FIELD_IPV6].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
			v->field[DSTP_FIELD_IPV6].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (v->field[SRCP_FIELD_IPV6].mask_range.u16
			< v->field[SRCP_FIELD_IPV6].value.u16
			|| v->field[DSTP_FIELD_IPV6].mask_range.u16
			< v->field[DSTP_FIELD_IPV6].value.u16)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].value.u8,
			0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV6].mask_range.u8,
			0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata,
				0, UINT32_MAX, 0);

	return 0;
}

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
		if (in[i] == NULL)
			return -EINVAL;
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read source address/mask: %s\n",
				in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		acl_log("failed to read destination address/mask: %s\n",
				in[CB_FLD_DST_ADDR]);
		return rc;
	}

	GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
			v->field[SRCP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
			v->field[SRCP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
			v->field[DSTP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
	GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
			v->field[DSTP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0)
		return -EINVAL;

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
			< v->field[SRCP_FIELD_IPV4].value.u16
			|| v->field[DSTP_FIELD_IPV4].mask_range.u16
			< v->field[DSTP_FIELD_IPV4].value.u16)
		return -EINVAL;

	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].value.u8,
			0, UINT8_MAX, '/');
	GET_CB_FIELD(in[CB_FLD_PROTO], v->field[PROTO_FIELD_IPV4].mask_range.u8,
			0, UINT8_MAX, 0);

	if (has_userdata)
		GET_CB_FIELD(in[CB_FLD_USERDATA], v->data.userdata, 0,
				UINT32_MAX, 0);

	return 0;
}

static void
swap_src_dst_ip(char *str)
{
	char *s, *sp, *in[CB_FLD_NUM], tmp[MAX_LEN];
	static const char *dlm = " \t\n";
	strncpy(tmp, str, strlen(str));
	s = tmp;
	in[0] = strtok_r(s, dlm, &sp);
	in[1] = strtok_r(NULL, dlm, &sp);
	sprintf(str, "%s %s %s\n", in[1], in[0], sp);
}

#ifdef ACL_READ_CFG
static int
add_rules(const char *rule_path,
		struct rte_acl_rule **pacl_base,
		unsigned int *pacl_num, uint32_t rule_size,
		int (*parser)(char *, struct rte_acl_rule *, int))
{
	uint8_t *acl_rules;
	struct rte_acl_rule *next;
	unsigned int acl_num = 0, total_num = 0;
	unsigned int acl_cnt = 0;
	char buff[LINE_MAX];
	FILE *fh = fopen(rule_path, "rb");
	unsigned int i = 0;

	if (fh == NULL)
		rte_exit(EXIT_FAILURE, "%s: Open %s failed\n", __func__,
				rule_path);

	while ((fgets(buff, LINE_MAX, fh) != NULL))
		acl_num++;


	fseek(fh, 0, SEEK_SET);

	acl_rules = rte_zmalloc("acl_rules", acl_num * rule_size,
			RTE_CACHE_LINE_SIZE);
	if (acl_rules == NULL)
		rte_exit(EXIT_FAILURE, "%s: failed to malloc memory\n",
				__func__);

	i = 0;
	while (fgets(buff, LINE_MAX, fh) != NULL) {
		i++;

		if (is_bypass_line(buff))
			continue;

		/* ACL entry */
		next = (struct rte_acl_rule *)(acl_rules + acl_cnt * rule_size);

		if (parser(buff + 1, next, 0) != 0)
			rte_exit(EXIT_FAILURE,
					"%s Line %u: parse rules error\n",
					rule_path, i);

		next->data.userdata = ACL_DENY_SIGNATURE + acl_cnt;
		acl_cnt++;
		next->data.priority = RTE_ACL_MAX_PRIORITY - total_num;
		next->data.category_mask = -1;
		total_num++;
	}

	fclose(fh);

	*pacl_base = (struct rte_acl_rule *)acl_rules;
	*pacl_num = acl_num;

	return 0;
}

static void dump_acl_config(void)
{
	printf("ACL option are:\n");
	printf(OPTION_RULE_IPV4 ": %s\n", parm_config.rule_ipv4_name);
	printf(OPTION_RULE_IPV6 ": %s\n", parm_config.rule_ipv6_name);
	printf(OPTION_SCALAR ": %d\n", parm_config.scalar);
}

static int check_acl_config(void)
{
	if (parm_config.rule_ipv4_name == NULL) {
		acl_log("ACL IPv4 rule file not specified\n");
		return -1;
	} else if (parm_config.rule_ipv6_name == NULL) {
		acl_log("ACL IPv6 rule file not specified\n");
		return -1;
	}

	return 0;
}

#endif /*ACL_READ_CFG*/

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
	struct rte_acl_param acl_param;
	int dim = ipv6 ? RTE_DIM(ipv6_defs) : RTE_DIM(ipv4_defs);
	struct rte_acl_ctx *context;

	/* Create ACL contexts */
	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;
	context = rte_acl_create(&acl_param);
	if (context == NULL)
		rte_exit(EXIT_FAILURE, "Failed to create ACL context\n");

	if (parm_config.scalar
			&& rte_acl_set_ctx_classify(context,
				RTE_ACL_CLASSIFY_SCALAR)
			!= 0)
		rte_exit(EXIT_FAILURE,
				"Failed to setup classify method for  ACL context\n");
#ifdef ACL_READ_CFG
	if (rte_acl_add_rules(context, acl_base_ipv4, acl_num_ipv4) < 0)
		rte_exit(EXIT_FAILURE, "add rules failed\n");

	struct rte_acl_config acl_build_param;
	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;

	memcpy(&acl_build_param.defs, ipv4_defs,
			sizeof(ipv4_defs));
	if (rte_acl_build(context, &acl_build_param) != 0)
		rte_exit(EXIT_FAILURE, "Failed to build ACL trie\n");
#endif	/*ACL_READ_CFG*/

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
	unsigned lcore_id;
	int socketid;
	unsigned int i;

#ifdef ACL_READ_CFG
	parm_config.rule_ipv4_name = "../config/rules_ipv4.cfg";
	parm_config.rule_ipv6_name = "../config/rules_ipv6.cfg";

	if (check_acl_config() != 0)
		rte_exit(EXIT_FAILURE, "Failed to get valid ACL options\n");

	dump_acl_config();

	/* Load  rules from the input file */
	if (add_rules(parm_config.rule_ipv4_name,
				&acl_base_ipv4, &acl_num_ipv4,
				rs, &parse_cb_ipv4vlan_rule) < 0)
		rte_exit(EXIT_FAILURE, "Failed to add rules\n");

	acl_log("IPv4 ACL entries %u:\n", acl_num_ipv4);

	if (add_rules(parm_config.rule_ipv6_name,
				&acl_base_ipv6, &acl_num_ipv6,
				sizeof(struct acl6_rule),
				&parse_cb_ipv6_rule) < 0)
		rte_exit(EXIT_FAILURE, "Failed to add rules\n");

	acl_log("IPv6 ACL entries %u:\n", acl_num_ipv6);

	dump_ipv6_rules((struct acl6_rule *)acl_base_ipv6, acl_num_ipv6, 1);

#endif /* ACL_READ_CFG*/

	memset(acl_config, 0, sizeof(struct acl_config));

	/* Check sockets a context should be created on */
	if (!app.numa_on)
		acl_config->mapped[0] = 1;
	else {
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			socketid = rte_lcore_to_socket_id(lcore_id);
			if (socketid >= NB_SOCKETS) {
				acl_log("Socket %d of lcore %u is out\n"
						"of range %d\n",
						socketid, lcore_id, NB_SOCKETS);
				return -1;
			}
			acl_config->mapped[socketid] = 1;
		}
	}

	for (i = 0; i < NB_SOCKETS; i++) {
		if (acl_config->mapped[i]) {
			acl_config->acx_ipv4[i] =
			acl_context_init(name, max_elements, rs, 0, i);

#ifdef ACL_READ_CFG
			acl_config->acx_ipv6[i] =
			acl_context_init(name, max_elements, rs, 1, i);
#endif
		}
	}
	return 0;
}

/**
 * To reset and build ACL table.
 *	This funciton reset the acl context rules,
 *	and add the new rules and build table.
 *	This should be called only for standby tables.
 *
 * @param type
 *	table type to reset and build.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
reset_and_build_rules(enum acl_cfg_tbl type)
{
	int dim = RTE_DIM(ipv4_defs);
	struct rte_acl_config acl_build_param;
	/*
	 * Check numa socket enable or disable based on
	 * get or set socketid.
	 */
	int socketid = app.numa_on?rte_socket_id():0;
	/* struct rte_acl_param acl_param; */ //GCC_Security flag
	/* char name[MAX_LEN]; */ ////GCC_Security flag
	struct acl_config *pacl_config = &acl_config[type];
	struct rte_acl_ctx *context = pacl_config->acx_ipv4[socketid];

	if (socketid < 0) {
		RTE_LOG_DP(ERR, ACL, "Invalid RTE socket Id: %d. \nExit.\n",
			socketid);
		return -1;
	}

	/* --> GCC_Security flag */
#if 0
	sprintf(name, "ACLTable-%d", type);
	acl_param.name = name;
	acl_param.socket_id = socketid;
	acl_param.rule_size = RTE_ACL_RULE_SZ(dim);
	acl_param.max_rule_num = MAX_ACL_RULE_NUM;
#endif
	/* <-- GCC_Security flag */
	/* Delete all rules from the ACL context. */
	rte_acl_reset_rules(context);

	add_rules_to_rte_acl(type);

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;

	memcpy(&acl_build_param.defs, ipv4_defs,
			sizeof(ipv4_defs));
	if (rte_acl_build(context, &acl_build_param) != 0)
		rte_exit(EXIT_FAILURE, "Failed to build ACL trie\n");

	pacl_config->acx_ipv4_built[socketid] = 1;

#ifdef DEBUG_ACL
	rte_acl_dump(context);
#endif
	return 0;
}

/**
 *	To add sdf or adc filter in acl table.
 *	The entries are first stored in local memory and then updated on
 *	standby table.
 *
 * @param name
 *	ACL table name (SDF/ADC), only for debug logs.
 * @param type
 *	table to add entry.
 * @param pkt_filter
 *	packet filter which include ruleid, priority and
 *		acl rule string to be added.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
dp_filter_entry_add(char *name, enum acl_cfg_tbl type, struct pkt_filter *pkt_filter)
{
	struct rte_acl_rule *next = NULL;
	struct rte_hash *hash = NULL;
	struct filter_pcc_data *pinfo = NULL;
	uint32_t rule_id;

	/* TODO: As precedence is no longer part of ADC & SDF, we are adding priority.
	 * For default ADC & SDF rule, we have considered priority as 0.
	 * Also what should be the maximum value of priority?
	 * Currently only 255 is considered. Need to revisit.
	 */
	uint8_t prio = 0;
	char *buf;
	if (pkt_filter == NULL)
		rte_exit(EXIT_FAILURE, "%s:\n"
				"read msg_payload failed\n", __func__);

	/* TODO: Ensure rule_id does not exceed max num rules*/
	rule_id = pkt_filter->pcc_rule_id;
	if (rule_id == SDF_DEFAULT_DROP_RULE_ID)
		prio = 0;

	if (!strcmp("SDF", name))
		hash = rte_sdf_pcc_hash;
	else
		hash = rte_adc_pcc_hash;

	if(NULL != hash){
		int ret = rte_hash_lookup_data(hash, &rule_id, (void **)&pinfo);

		if (ret < 0 || NULL == pinfo) {
				/* If there is no matching pcc rule, what should be
				 * values of pcc? Currently hardcoding to 1 with
				 * gate-status 1 (pass traffic) : Default policy in pcc
				 */
				prio = 0;

			} else {

				prio = (255 - pinfo->pcc_info[0].precedence);
		}
	}

	buf = (char *)&pkt_filter->u.rule_str[0];

	struct acl4_rule r;
	next = (struct rte_acl_rule *)&r;
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0)
		rte_exit(EXIT_FAILURE,
				"%s  parse rules error\n",
				__func__);

	next->data.userdata = rule_id + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;
		if (dp_rules_entry_add(&acl_rules_table[type/2], (struct acl4_rule *)next) < 0)
			return -1;

	if (reset_and_build_rules(type) < 0)
		return -1;

	return 0;
}
/**
 *	to get standby table id from active table.
 *
 * @param type
 *	current active table id.
 *
 * @return
 *	standby table id
 */
static int
dp_acl_get_standby(enum acl_cfg_tbl type)
{
	return (type % 2)?(type - 1):(type + 1);
}

/**
 *	To delete sdf or adc filter in acl table.
 *	The entries are first removed in local memory and then updated on
 *	standby table.
 *
 * @param name
 *	ACL table name (SDF/ADC), only for debug logs.
 * @param type
 *	table to add entry.
 * @param pkt_filter
 *	packet filter which include ruleid, priority and
 *		acl rule string to be deleted.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
dp_filter_entry_delete(char *name, enum acl_cfg_tbl type,
			struct pkt_filter *pkt_filter_entry)
{
	uint32_t rule_id;

	if (pkt_filter_entry == NULL)
		rte_exit(EXIT_FAILURE, "%s:\n"
				"read msg_payload failed\n", __func__);

	rule_id = pkt_filter_entry->pcc_rule_id;
	RTE_LOG_DP(INFO, DP, "ACL DEL:%s rule_id:%d\n",
			name, rule_id);

	struct acl4_rule rule;
	rule.data.userdata = rule_id + ACL_DENY_SIGNATURE;
	dp_rules_entry_delete(&acl_rules_table[type/2], &rule);

	return reset_and_build_rules(type);
}
/**
 *	To add sdf or adc filter in acl table.
 *	The entries are first stored in local memory and then updated on
 *	standby table.
 *
 * @param name
 *	ACL table name (SDF/ADC), only for debug logs.
 * @param type
 *	table to add entry.
 * @param rule_id
 *	rule id to add default filter.
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
/* --> GCC_security flag */
#if 0
static int
default_entry_add(char *name, enum acl_cfg_tbl type, uint32_t rule_id)
{
	struct pkt_filter def_pkt_filter;
	/* default rule id = max_elements of table */
	def_pkt_filter.pcc_rule_id = rule_id;
	sprintf((char *)&def_pkt_filter.u.rule_str[0], "0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0\n");

	if (dp_filter_entry_add(name, type, &def_pkt_filter) < 0)
		return -1;
	return 0;
}
#endif
/* <-- GCC_Security flag */

/**
 *	Add DNS pkt filter in adc acl table.
 */
static int
dns_entry_add(struct dp_id dp_id)
{
	/* TODO : Query : Why DNS_RULE_ID is 17 (MAX_ADC_RULE +1).
	 *        Why MAX_ADC_RULE = 16 ?
	 *        What should be precedence of DNS rule?
	 */
	struct pkt_filter dns_pkt_filter;

	dns_pkt_filter.pcc_rule_id = DNS_RULE_ID;
	sprintf((char *)&dns_pkt_filter.u.rule_str[0], "0.0.0.0/0 0.0.0.0/0 53 : 53 0 : 65535 0x0/0x0\n");

	if (dp_adc_filter_entry_add(dp_id, &dns_pkt_filter) < 0)
		return -1;
	return 0;
}

int
dp_sdf_filter_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	RTE_SET_USED(dp_id);
	if (acl_config_init(&acl_config[SDF_ACTIVE], "ACLTable-0",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;
	if (acl_config_init(&acl_config[SDF_STANDBY], "ACLTable-1",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;

	/* create acl rules table */
	return dp_acl_rules_table_create(SDF_PARAM, max_elements);
}

int
dp_sdf_filter_table_delete(struct dp_id dp_id)
{
	int i;
	RTE_SET_USED(dp_id);
	struct acl_config *pacl_config = &acl_config[SDF_ACTIVE];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	pacl_config = &acl_config[SDF_STANDBY];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	dp_acl_rules_table_delete(&acl_rules_table[SDF_PARAM]);

	return 0;
}

int
dp_sdf_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter)
{
	static int is_first = 1;
	enum acl_cfg_tbl standby = dp_acl_get_standby(sdf_active_tbl);
	RTE_SET_USED(dp_id);

	if (is_first == 1) {
		cdr_init();
		is_first = 0;
	}

	if (dp_filter_entry_add("SDF", standby, pkt_filter) < 0)
		return -1;

	sdf_active_tbl = standby;

	RTE_LOG_DP(INFO, DP, "ACL ADD:%s, rule_id:%d, rule:%s\n",
			"SDF", pkt_filter->pcc_rule_id, pkt_filter->u.rule_str);
	return 0;
}

int
dp_sdf_filter_entry_delete(struct dp_id dp_id,
			struct pkt_filter *pkt_filter_entry)
{
	enum acl_cfg_tbl standby = dp_acl_get_standby(sdf_active_tbl);
	RTE_SET_USED(dp_id);
	if (dp_filter_entry_delete("SDF", standby, pkt_filter_entry) < 0)
		return -1;

	sdf_active_tbl = standby;
	return 0;
}

int
dp_adc_filter_table_create(struct dp_id dp_id, uint32_t max_elements)
{
	RTE_SET_USED(dp_id);
	if (acl_config_init(&acl_config[ADC_UL_ACTIVE], "ACLTable-2",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;
	if (acl_config_init(&acl_config[ADC_UL_STANDBY], "ACLTable-3",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;
	if (acl_config_init(&acl_config[ADC_DL_ACTIVE], "ACLTable-2",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;
	if (acl_config_init(&acl_config[ADC_DL_STANDBY], "ACLTable-3",
			max_elements, sizeof(struct acl4_rule)) < 0)
			return -1;
	/* create acl rules table */
	dp_acl_rules_table_create(ADC_UL_PARAM, max_elements);

	dp_acl_rules_table_create(ADC_DL_PARAM, max_elements);

	return 0;
}

int
dp_adc_filter_table_delete(struct dp_id dp_id)
{
	int i;
	RTE_SET_USED(dp_id);
	struct acl_config *pacl_config;

	pacl_config	= &acl_config[ADC_UL_PARAM];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	pacl_config = &acl_config[ADC_UL_STANDBY];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	pacl_config = &acl_config[ADC_DL_ACTIVE];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	pacl_config = &acl_config[ADC_DL_STANDBY];
	for (i = 0; i < NB_SOCKETS; i++)
		if (pacl_config->mapped[i])
			rte_acl_reset(pacl_config->acx_ipv4[i]);

	dp_acl_rules_table_delete(&acl_rules_table[ADC_UL_PARAM]);

	dp_acl_rules_table_delete(&acl_rules_table[ADC_DL_PARAM]);

	return 0;
}

int
dp_adc_filter_entry_add(struct dp_id dp_id, struct pkt_filter *pkt_filter)
{
	enum acl_cfg_tbl standby = dp_acl_get_standby(adc_ul_active_tbl);

	RTE_SET_USED(dp_id);

	if (dp_filter_entry_add("ADC", standby, pkt_filter) < 0)
		return -1;
	adc_ul_active_tbl = standby;

	/* swap the src and dst address for DL traffic.*/
	swap_src_dst_ip((char *)&pkt_filter->u.rule_str[0]);

	standby = dp_acl_get_standby(adc_dl_active_tbl);
	RTE_SET_USED(dp_id);
	if (dp_filter_entry_add("ADC", standby, pkt_filter) < 0)
		return -1;
	adc_dl_active_tbl = standby;
	return 0;
}

int
dp_adc_filter_entry_delete(struct dp_id dp_id,
				struct pkt_filter *pkt_filter_entry)
{
	enum acl_cfg_tbl standby = dp_acl_get_standby(adc_ul_active_tbl);
	RTE_SET_USED(dp_id);
	if (dp_filter_entry_delete("ADC", standby, pkt_filter_entry) < 0)
		return -1;

	adc_ul_active_tbl = standby;

	/* swap the src and dst address for DL traffic.*/
	swap_src_dst_ip((char *)&pkt_filter_entry->u.rule_str[0]);

	standby = dp_acl_get_standby(adc_dl_active_tbl);
	RTE_SET_USED(dp_id);
	if (dp_filter_entry_delete("ADC", standby, pkt_filter_entry) < 0)
		return -1;

	adc_dl_active_tbl = standby;
	return 0;
}

/******************** Callback functions **********************/
/**
 *  Callback function to parse msg payload and
 *	create sdf rules table
 *
 * @param msg_payload
 *	payload from CP
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
cb_sdf_filter_table_create(struct msgbuf *msg_payload)
{
	return sdf_filter_table_create(msg_payload->dp_id,
			msg_payload->msg_union.msg_table.max_elements);
}

/**
 *  Callback function to parse msg payload and
 *	delete sdf rules table
 *
 * @param msg_payload
 *	payload from CP
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
cb_sdf_filter_table_delete(struct msgbuf *msg_payload)
{
	return sdf_filter_table_delete(msg_payload->dp_id);
}

/**
 *  Callback function to parse msg payload and
 *	add sdf rules
 *
 * @param msg_payload
 *	payload from CP
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
cb_sdf_filter_entry_add(struct msgbuf *msg_payload)
{
	return sdf_filter_entry_add(msg_payload->dp_id,
				msg_payload->msg_union.pkt_filter_entry);
}

/**
 * *  Callback function to parse msg payload and delete sdf rules.
 *
 * @param msg_payload
 *	payload from CP
 *
 * @return
 *	- 0 on success
 *	- -1 on failure
 */
static int
cb_sdf_filter_entry_delete(struct msgbuf *msg_payload)
{
	return sdf_filter_entry_delete(msg_payload->dp_id,
				msg_payload->msg_union.pkt_filter_entry);
}

/**
 * Initialization of filter table callback functions.
 */
void app_filter_tbl_init(void)
{
	/* register msg type in DB*/
	iface_ipc_register_msg_cb(MSG_SDF_CRE, cb_sdf_filter_table_create);
	iface_ipc_register_msg_cb(MSG_SDF_DES, cb_sdf_filter_table_delete);
	iface_ipc_register_msg_cb(MSG_SDF_ADD, cb_sdf_filter_entry_add);
	iface_ipc_register_msg_cb(MSG_SDF_DEL, cb_sdf_filter_entry_delete);

	/* Create ADC Rule table*/
	struct dp_id dp_id;
	sprintf(dp_id.name, "ADC_Filter_Table");
	dp_adc_filter_table_create(dp_id, MAX_ADC_RULES + RESVD_IDS);

	/* install DNS pkt filter*/
	dns_entry_add(dp_id);
}

uint32_t *dp_acl_lookup(struct rte_mbuf **m, int nb_rx,
		struct acl_config *acl_config,
		struct acl_search *acl_search)
{
	int socketid;
	unsigned lcore_id;

	lcore_id = rte_lcore_id();
	socketid = rte_lcore_to_socket_id(lcore_id);

	if ((nb_rx > 0) && ((acl_config->acx_ipv4[socketid])->trans_table != NULL)) {

		prepare_acl_parameter(m, acl_search+lcore_id, nb_rx);

		if ((acl_search+lcore_id)->num_ipv4) {
			rte_acl_classify(acl_config->acx_ipv4[socketid],
					(acl_search+lcore_id)->data_ipv4,
					(acl_search+lcore_id)->res_ipv4,
					(acl_search+lcore_id)->num_ipv4,
					DEFAULT_MAX_CATEGORIES);

			update_stats((acl_search+lcore_id)->res_ipv4,
					(acl_search+lcore_id)->num_ipv4);
		}
	}
	return (uint32_t *)&(acl_search+lcore_id)->res_ipv4;
}

uint32_t *sdf_lookup(struct rte_mbuf **m, int nb_rx)
{
	return dp_acl_lookup(m, nb_rx, &acl_config[sdf_active_tbl], acl_search[SDF_PARAM]);
}

uint32_t *adc_ul_lookup(struct rte_mbuf **m, int nb_rx)
{
	return dp_acl_lookup(m, nb_rx, &acl_config[adc_ul_active_tbl], acl_search[ADC_UL_PARAM]);
}
uint32_t *adc_dl_lookup(struct rte_mbuf **m, int nb_rx)
{
	return dp_acl_lookup(m, nb_rx, &acl_config[adc_dl_active_tbl], acl_search[ADC_DL_PARAM]);
}

int dp_sdf_default_entry_add(struct dp_id dp_id, uint32_t rule_id)
{
	enum acl_cfg_tbl standby = dp_acl_get_standby(sdf_active_tbl);
	struct pkt_filter pktf = {
			.pcc_rule_id = rule_id,
		};

	RTE_SET_USED(dp_id);

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

	if (dp_filter_entry_add("SDF", standby, &pktf) < 0)
		return -1;

	sdf_active_tbl = standby;
	return 0;
}

int dp_sdf_default_entry_action_modify(struct dp_id dp_id, uint32_t rule_id)
{
	enum acl_cfg_tbl standby = dp_acl_get_standby(sdf_active_tbl);

	RTE_SET_USED(dp_id);

	RTE_LOG_DP(INFO, DP, "ACL DEL:%s rule_id:%d\n",
			"SDF", rule_id);

	struct acl4_rule rule;
	rule.data.userdata = rule_id + ACL_DENY_SIGNATURE;
	if (dp_rules_entry_delete(&acl_rules_table[standby/2], &rule))
		return -1;

	struct pkt_filter pktf = {
			.pcc_rule_id = SDF_DEFAULT_RULE_ID,
		};

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

	if (dp_filter_entry_add("SDF", standby, &pktf) < 0)
		return -1;

	sdf_active_tbl = standby;
	return 0;
}

int
dp_adc_filter_default_entry_add(struct dp_id dp_id)
{
	struct pkt_filter adc_filter;
	enum acl_cfg_tbl standby = dp_acl_get_standby(adc_ul_active_tbl);
	RTE_SET_USED(dp_id);

	adc_filter.pcc_rule_id = ADC_DEFAULT_RULE_ID;
	sprintf(adc_filter.u.rule_str, "0.0.0.0/0 0.0.0.0/0 "
		"0 : 65535 0 : 65535 0x0/0x0\n");

	if (dp_filter_entry_add("ADC", standby, &adc_filter) < 0)
		return -1;
	adc_ul_active_tbl = standby;

	return 0;
}
