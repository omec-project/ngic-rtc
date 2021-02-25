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
#include "clogger.h"

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

/**
 * @brief  : Maintains acl field type information
 */
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

/**
 * @brief  : Maintains acl configuration
 */
struct acl_config {
	struct rte_acl_ctx *acx_ipv4;
	uint8_t acx_ipv4_built;
};

/**
 * @brief  : Maintains acl parameters
 */
struct acl_search {
	const uint8_t *data_ipv4[MAX_BURST_SZ];
	struct rte_mbuf *m_ipv4[MAX_BURST_SZ];
	uint32_t res_ipv4[MAX_BURST_SZ];
	int num_ipv4;
};

/**
 * @brief  : Maintains parm config
 */
static struct{
	const char *rule_ipv4_name;
	int scalar;
} parm_config;

const char cb_port_delim[] = ":";

/**
 * @brief  : Maintains acl rule table information
 */
struct acl_rules_table {
	char name[MAX_LEN];
	void *root;
	uint16_t num_entries;
	uint16_t max_entries;
	int (*compare)(const void *r1p, const void *r2p);
	int (*compare_rule)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
	void (*add_entry)(const void *nodep, const VISIT which, const int depth);
	uint16_t num_of_ue;
};

struct acl_config acl_config[MAX_ACL_TABLES];
struct acl_rules_table acl_rules_table[MAX_ACL_TABLES];
struct acl_search acl_search;


/*******************************************************[START]**********************************************************/
/**
 * @brief  : Print one acl rule information
 * @param  : rule, acl rule
 * @param  : extra, data
 * @return : Returns nothing
 */
static inline void print_one_ipv4_rule(struct acl4_rule *rule, int extra)
{
	unsigned char a, b, c, d;

	uint32_t_to_char(rule->field[SRC_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL Rule Info : %hhu.%hhu.%hhu.%hhu/%u\n", LOG_VALUE, a, b, c, d,
		rule->field[SRC_FIELD_IPV4].mask_range.u32);
	uint32_t_to_char(rule->field[DST_FIELD_IPV4].value.u32, &a, &b, &c, &d);
	clLog(clSystemLog, eCLSeverityDebug,"ACL Rule Info : %hhu.%hhu.%hhu.%hhu/%u \n",
		LOG_VALUE, a, b, c, d, rule->field[DST_FIELD_IPV4].mask_range.u32);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL Rule Info : %hu : %hu %hu : %hu 0x%hhx/0x%hhx \n",LOG_VALUE,
		rule->field[SRCP_FIELD_IPV4].value.u16,
		rule->field[SRCP_FIELD_IPV4].mask_range.u16,
		rule->field[DSTP_FIELD_IPV4].value.u16,
		rule->field[DSTP_FIELD_IPV4].mask_range.u16,
		rule->field[PROTO_FIELD_IPV4].value.u8,
		rule->field[PROTO_FIELD_IPV4].mask_range.u8);
	if (extra)
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ACL Rule Info : 0x%x-0x%x-0x%x \n", LOG_VALUE,
			rule->data.category_mask,
			rule->data.priority,
			rule->data.userdata & ~ACL_DENY_SIGNATURE);
}

/**
 * @brief  : Print acl rule information
 * @param  : rule, acl rule
 * @param  : num, number of rules
 * @param  : extra, data
 * @return : Returns nothing
 */
static inline void dump_ipv4_rules(struct acl4_rule *rule, int num, int extra)
{
	int i;
	int j;

	for (i = 0, j = 0; i < MAX_SDF_RULE_NUM; i++, rule++) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ACL Rule Info : %d\n", LOG_VALUE, i + 1);
		print_one_ipv4_rule(rule, extra);
		j++;
		if (j == num)
			break;
	}
}

/**
 * @brief  : Fill acl rule information
 * @param  : pkts_in, input buffer
 * @param  : acl, acl structure to fill
 * @param  : index, index of packet in array
 * @return : Returns nothing
 */
static inline void
prepare_one_packet_ipv4(struct rte_mbuf **pkts_in, struct acl_search *acl,
		int index)
{
	struct rte_mbuf *pkt = pkts_in[index];

	/* Fill acl structure */
	acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
	acl->m_ipv4[(acl->num_ipv4)++] = pkt;
}

/**
 * @brief  : Process packets and fill acl rule information
 * @param  : pkts_in, input buffer
 * @param  : acl, acl structure to fill
 * @param  : nb_rx, number of packets
 * @return : Returns nothing
 */
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

/**
 * @brief  : Forward packets
 * @param  : pkts_in, input buffer
 * @param  : res
 * @return : Returns nothing
 */
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

/*
 * Parse ClassBench rules file.
 * Expected format:
 * '@'<src_ipv4_addr>'/'<masklen> <space> \
 * <dst_ipv4_addr>'/'<masklen> <space> \
 * <src_port_low> <space> ":" <src_port_high> <space> \
 * <dst_port_low> <space> ":" <dst_port_high> <space> \
 * <proto>'/'<mask>
 */
/**
 * @brief  : Parse ipv4 address
 * @param  : in, input ip string
 * @param  : addr, output
 * @param  : mask_len, mask length
 * @return : Returns 0
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
	strncpy(tmp, str, MAX_LEN);
	s = tmp;
	in[0] = strtok_r(s, dlm, &sp);
	in[1] = strtok_r(NULL, dlm, &sp);
	snprintf(str, MAX_LEN,"%s %s %s\n", in[1], in[0], sp);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"SDF UL LINK : %s\n", LOG_VALUE, str);
}


/**
 * @brief  : Function to the parse the SDF filter rule
 * @param  : str, input string
 * @param  : v, acl rule
 * @param  : has_userdata
 * @return : Returns 0 in case of success , negative error values otherwise
 */
static int
parse_cb_ipv4vlan_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
	int i, rc;
	char *s = NULL, *sp = NULL, *in[CB_FLD_NUM]={0}, tmp[MAX_LEN] = {0};
	static const char *dlm = " \t\n";
	int dim = has_userdata ? CB_FLD_NUM : CB_FLD_USERDATA;

	char *src_low_port = "0", *src_high_port = "65535";
	char *dst_low_port = "0", *dst_high_port = "65535";
	strncpy(tmp, str, MAX_LEN);
	s = tmp;

	for (i = 0; i != dim; i++, s = NULL) {
		in[i] = strtok_r(s, dlm, &sp);
		if (in[i] == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"ERROR: String is NULL\n", LOG_VALUE);
			return -EINVAL;
		}
	}

	rc = parse_ipv4_net(in[CB_FLD_SRC_ADDR],
			&v->field[SRC_FIELD_IPV4].value.u32,
			&v->field[SRC_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"INVALID Source Address/Mask: %s\n", LOG_VALUE,
			in[CB_FLD_SRC_ADDR]);
		return rc;
	}

	rc = parse_ipv4_net(in[CB_FLD_DST_ADDR],
			&v->field[DST_FIELD_IPV4].value.u32,
			&v->field[DST_FIELD_IPV4].mask_range.u32);
	if (rc != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"INVALID Destination Address/Mask: %s\n", LOG_VALUE,
			in[CB_FLD_DST_ADDR]);
		return rc;
	}

	if(atoi(in[CB_FLD_SRC_PORT_LOW]) == 0 && atoi(in[CB_FLD_SRC_PORT_HIGH]) == 0){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"SRC Port LOW and High both 0\n", LOG_VALUE);
		GET_CB_FIELD(src_low_port,
			v->field[SRCP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);

		GET_CB_FIELD(src_high_port,
			v->field[SRCP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);
	} else{
		GET_CB_FIELD(in[CB_FLD_SRC_PORT_LOW],
			v->field[SRCP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
		GET_CB_FIELD(in[CB_FLD_SRC_PORT_HIGH],
			v->field[SRCP_FIELD_IPV4].mask_range.u16,
			0, UINT16_MAX, 0);
	}

	if (strncmp(in[CB_FLD_SRC_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"INVALID Source Port/Mask: %s\n", LOG_VALUE,
			in[CB_FLD_SRC_PORT_DLM]);
		return -EINVAL;
	}

	if(atoi(in[CB_FLD_DST_PORT_LOW]) == 0 && atoi(in[CB_FLD_DST_PORT_HIGH]) == 0){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"DST Port LOW and High both 0\n", LOG_VALUE);
		GET_CB_FIELD(dst_low_port,
			v->field[DSTP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);

		GET_CB_FIELD(dst_high_port,
			v->field[DSTP_FIELD_IPV4].mask_range.u16, 0, UINT16_MAX, 0);
	} else {
		GET_CB_FIELD(in[CB_FLD_DST_PORT_LOW],
			v->field[DSTP_FIELD_IPV4].value.u16, 0, UINT16_MAX, 0);
		GET_CB_FIELD(in[CB_FLD_DST_PORT_HIGH],
			v->field[DSTP_FIELD_IPV4].mask_range.u16, 0, UINT16_MAX, 0);
	}

	if (strncmp(in[CB_FLD_DST_PORT_DLM], cb_port_delim,
				sizeof(cb_port_delim)) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"INVALID Destination Port/Mask: %s\n", LOG_VALUE,
			in[CB_FLD_DST_PORT_DLM]);
		return -EINVAL;
	}

	if (v->field[SRCP_FIELD_IPV4].mask_range.u16
			< v->field[SRCP_FIELD_IPV4].value.u16
			|| v->field[DSTP_FIELD_IPV4].mask_range.u16
			< v->field[DSTP_FIELD_IPV4].value.u16) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"INVALID Src and Dst Mask Ranges\n", LOG_VALUE);
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
 * @brief  : Print the Rule entry.
 * @param  : nodep, node to print
 * @param  : which, traversal order
 * @param  : depth, node depth
 * @return : Returns nothing
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
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Depth : %d, Precedence : %u", LOG_VALUE,
			depth, precedence);
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Prio : %x, Category Mask : %x\n", LOG_VALUE,
			r->data.priority, r->data.category_mask);
		print_one_ipv4_rule(r, 1);
		break;
	default:
		break;
	}
}

/**
 * @brief  : Dump the table entries.
 * @param  : table, table pointer whose entries to dump.
 * @return : Returns nothing
 */
void acl_table_dump(struct acl_rules_table *t)
{
	twalk(t->root, t->print_entry);
}

/**
 * @brief  : Add the Rule entry in rte acl table.
 * @param  : nodep, node to add
 * @param  : which, traversal order
 * @param  : depth, node depth
 * @return : Returns nothing
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
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to Add SDF rule\n", LOG_VALUE);
		}
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"SDF Rule Added in ACL table\n", LOG_VALUE);
		break;
	default:
		break;
	}
}

/**
 * @brief  : Compare acl rule precedence.
 * @param  : r1p, first acl rule
 * @param  : r2p, second acl rule
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int acl_rule_prcdnc_compare(const void *r1p, const void *r2p)
{
	struct acl4_rule *r1, *r2;

	r1 = (struct acl4_rule *) r1p;
	r2 = (struct acl4_rule *) r2p;

	/* compare precedence */
	if (r1->data.userdata < r2->data.userdata) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Compare precendence failed\n", LOG_VALUE);
		return -1;
	}
	else if (r1->data.userdata == r2->data.userdata)
		return 0;
	else
		return 1;

}

/**
 * @brief  : Compare rule entry.
 * @param  : r1p, first acl rule
 * @param  : r2p, second acl rule
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int acl_rule_compare(const void *r1p, const void *r2p)
{
	struct acl4_rule *rule1, *rule2;

	rule1 = (struct acl4_rule *) r1p;
	rule2 = (struct acl4_rule *) r2p;

	/* compare rule */
	if ((rule1->data.userdata == rule2->data.userdata) &&

		(rule1->field[SRC_FIELD_IPV4].value.u32 ==
			rule2->field[SRC_FIELD_IPV4].value.u32) &&

		(rule1->field[SRC_FIELD_IPV4].mask_range.u32 ==
			rule2->field[SRC_FIELD_IPV4].mask_range.u32) &&

		(rule1->field[SRCP_FIELD_IPV4].value.u16 ==
			rule2->field[SRCP_FIELD_IPV4].value.u16) &&

		(rule1->field[SRCP_FIELD_IPV4].mask_range.u16 ==
			rule2->field[SRCP_FIELD_IPV4].mask_range.u16) &&

		(rule1->field[DST_FIELD_IPV4].value.u32 ==
			rule2->field[DST_FIELD_IPV4].value.u32) &&

		(rule1->field[DST_FIELD_IPV4].mask_range.u32 ==
			rule2->field[DST_FIELD_IPV4].mask_range.u32) &&

		(rule1->field[DSTP_FIELD_IPV4].value.u16 ==
			rule2->field[DSTP_FIELD_IPV4].value.u16) &&

		(rule1->field[DSTP_FIELD_IPV4].mask_range.u16 ==
			rule2->field[DSTP_FIELD_IPV4].mask_range.u16) &&

		(rule1->field[PROTO_FIELD_IPV4].value.u8 ==
			rule2->field[PROTO_FIELD_IPV4].value.u8) &&

		(rule1->field[PROTO_FIELD_IPV4].mask_range.u8 ==
			rule2->field[PROTO_FIELD_IPV4].mask_range.u8)){

				clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"SDF Rule matched\n", LOG_VALUE);
				return 0;
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"SDF Rule mismatched\n", LOG_VALUE);
	return -1;
}

/**
 * @brief  : Create ACL table.
 * @param  : ACL Table index
 * @param  : max_element, max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
up_acl_rules_table_create(uint32_t indx, uint32_t max_elements)
{
	struct acl_rules_table *t = &acl_rules_table[indx];
	if (t->root != NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ACL table for index : \"%s\" Exist\n", LOG_VALUE, t->name);
		return -1;
	}

	t->num_entries = 0;
	t->max_entries = max_elements;
	snprintf(t->name, MAX_LEN, "ACL_RULES_TABLE-%u", indx);
	t->compare = acl_rule_prcdnc_compare;
	t->compare_rule = acl_rule_compare;
	t->print_entry = acl_rule_print;
	t->add_entry = add_single_rule;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL Rules table for \"%s\" Created\n", LOG_VALUE, t->name);
	return 0;
}

/**
 * @brief  : Init acl table context.
 *           If cflag ACL_READ_CFG is enabled, this function reads rules
 *           from config file and build acl tables. Else it will add
 *           default rule "0.0.0.0/0 0.0.0.0/0 0 : 65535 0 : 65535 0x0/0x0"
 *           with id = max_elements.
 * @param  : name, name string for table name.
 * @param  : acl_num, max elements that can be added in this table.
 * @param  : rs, each rule size
 * @param  : ipv6, set this if rules are ipv6
 * @param  : socketid, socket id
 * @return : Returns rte_acl_ctx on Success, NULL otherwise
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
		rte_exit(EXIT_FAILURE, LOG_FORMAT"Failed to create ACL context\n", LOG_VALUE);

	if (parm_config.scalar
			&& rte_acl_set_ctx_classify(context,
				RTE_ACL_CLASSIFY_SCALAR)
			!= 0)
		rte_exit(EXIT_FAILURE, LOG_FORMAT"Failed to setup classify method for ACL context\n",
			LOG_VALUE);

	return context;
}

/**
 * @brief  : Init config of acl tables.
 * @param  : acl_config
 *           config base address of this table.
 * @param  : name
 *           name string for table name.
 * @param  : max_elements
 *           max elements that can be added in this table.
 * @param  : rs
 *           rule size of each elements.
 * @return : Returns 0 in case of success , -1 otherwise
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
 * @brief  : Create SDF rules table
 * @param  : max_elements, max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
up_sdf_filter_table_create(uint32_t max_elements)
{
	char name[NAME_LEN];
	char *buf = "ACLTable-";
	acl_table_indx = acl_table_indx_offset;

	/* Increment the New Created ACL tables */
	snprintf(name, NAME_LEN, "%s%u", buf, acl_table_indx);

	/* Configure the ACL table */
	if (acl_config_init(&acl_config[acl_table_indx], name,
			max_elements, sizeof(struct acl4_rule)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Acl config init failed\n", LOG_VALUE);
		/* TODO: Error Handling */
		return -1;
	}

	/* Create the local acl rules table copy */
	if (up_acl_rules_table_create(acl_table_indx, max_elements)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Up acl rules table create failed\n", LOG_VALUE);
		/* TODO: Error Handling */
		return -1;
	}

	/* Increment the ACL Table index */
	acl_table_indx_offset++;
	/* Return New created ACL table index */
	return acl_table_indx;
}

/**
 * @brief  : Add rules from local table to rte acl rules table.
 * @param  : ACL Table Index
 * @return : Returns nothing
 */
static void
add_rules_to_rte_acl(uint8_t indx)
{
	struct acl_rules_table *t = &acl_rules_table[indx];
	acl_table_indx = indx;
	twalk(t->root, t->add_entry);
}

/**
 * @brief  : To reset and build ACL table.
 *           This funciton reset the acl context rules,
 *           and add the new rules and build table.
 *           This should be called only for standby tables.
 * @param  : ACL Table Index, table index to reset and build.
 * @return : Returns 0 in case of success , -1 otherwise
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
		rte_exit(EXIT_FAILURE, LOG_FORMAT"Failed to build ACL trie,"
				"ACL_RULES_TABLE-%u, ret:%d, error:%s\n",
				LOG_VALUE, indx, ret, rte_strerror(rte_errno));
	}

	pacl_config->acx_ipv4_built = 1;

#ifdef DEBUG_ACL
	rte_acl_dump(context);
#endif
	return 0;
}

/**
 * @brief  : Add rules entry.
 * @param  : t, rules table pointer
 * @param  : rule, element to be added in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
up_rules_entry_add(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	if (t->num_entries == t->max_entries)
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT":%s reached max rules entries\n", LOG_VALUE, t->name);

	struct acl4_rule *new = rte_malloc("acl_rule", sizeof(struct acl4_rule),
			RTE_CACHE_LINE_SIZE);
	if (new == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"ADC: Failed to allocate memory\n", LOG_VALUE);
		return -1;
	}
	memcpy(new, rule, sizeof(struct acl4_rule));
	/* put node into the tree */
	if (tsearch(new, &t->root, t->compare_rule) == 0) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT":Fail to add acl precedance %d\n", LOG_VALUE,
			rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}

	t->num_entries++;
	return 0;
}

/* Currently NOT USING */
/**
 * @brief  : To add sdf or adc filter in acl table.
 *           The entries are first stored in local memory and then updated on
 *           standby table.
 * @param  : ACL table Index
 * @param  : sdf_pkt_filter
 *           packet filter which include ruleid, priority and
 *           acl rule string to be added.
 * @return : Returns 0 in case of success , -1 otherwise
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
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Read msg payload failed\n", LOG_VALUE);
		return -1;
	}

	/* Ensure rule_id does not exceed max num rules*/
	if (sdf_rule_id == SDF_DEFAULT_DROP_RULE_ID)
		prio = 0;

	prio = (255 - pkt_filter->precedence);
	buf = (char *)&pkt_filter->u.rule_str[0];
	next = (struct rte_acl_rule *)&r;

	/* Parse the sdf filter into acl ipv4 rule format */
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Parse rules error\n", LOG_VALUE);
		return -1;
	}

	next->data.userdata = pkt_filter->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;

	/* Find similar rule is present or not */
	struct acl_rules_table *ctx = &acl_rules_table[indx];
	struct acl_rules_table *t = NULL;
	if (ctx != NULL) {

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Search SDF Rule in ACL_Table_Index-%u\n", LOG_VALUE, indx);
		t = tfind(next, &ctx->root, ctx->compare_rule);
		if (t != NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"SDF Rule match in ACL_Table_Index-%u\nDP: SDF Rule:%s\n",
				LOG_VALUE, indx, pkt_filter->u.rule_str);
			return 0;
		}
	}

	if (up_rules_entry_add(&acl_rules_table[indx],
				(struct acl4_rule *)next) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Up rules entry add failed\n", LOG_VALUE);
		return -1;
	}

	if (reset_and_build_rules(indx) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Reset and build rules Failed\n", LOG_VALUE);
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD: %s, ACL_Indx:%u, precedence:%u, rule:%s\n",
		"SDF RULE", LOG_VALUE, indx, pkt_filter->precedence, pkt_filter->u.rule_str);
	return 0;
}

int
up_sdf_filter_entry_add(uint32_t indx, struct sdf_pkt_filter *pkt_filter)
{
	static int is_first = 1;
	if (is_first == 1) {
		is_first = 0;
	}

	if (up_filter_entry_add(indx, pkt_filter)) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed in up filter entry addition\n", LOG_VALUE);
		/* TODO: ERROR Handling */
		return -1;
	}

	return 0;
}

/* Function to retrive the acl table index */
int
get_acl_table_indx(struct sdf_pkt_filter *pkt_filter, uint8_t is_create)
{
	uint8_t prio = 0;
	uint32_t it = 0;
	char *buf = NULL;
	struct acl4_rule r = {0};
	struct rte_acl_rule *next = NULL;

	/* check sdf filter exist or not */
	if (pkt_filter == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"read msg_payload failed\n", LOG_VALUE);
		return -1;
	}

	prio = (255 - pkt_filter->precedence);
	buf = (char *)&pkt_filter->u.rule_str[0];
	next = (struct rte_acl_rule *)&r;

	/* Parse the sdf filter into acl ipv4 rule format */
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Parse rules error\n", LOG_VALUE);
		return -1;
	}

	/* Fill the received rule information */
	next->data.userdata = pkt_filter->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;

	/* Find similar rule is present or not */
	for (uint32_t itr = 1; itr < acl_table_indx_offset; itr++) {
		struct acl_rules_table *ctx = &acl_rules_table[itr];
		struct acl_rules_table *t = NULL;
		if (ctx == NULL)
			continue;

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Search SDF Rule in ACL_Table_Index :%u\n",
			LOG_VALUE, itr);
		t = tfind(next, &ctx->root, ctx->compare_rule);
		if (t != NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"SDF Rule match in ACL_Table_Index-%u\nDP: SDF Rule:%s\n",
				LOG_VALUE, itr, pkt_filter->u.rule_str);
			if(SESS_CREATE == is_create)
				acl_rules_table[itr].num_of_ue++;
			return itr;
		}
	}

	if(SESS_CREATE != is_create)
		return -1;

	/* If ACL table is not present than create the new ACL table */
	if ((it = up_sdf_filter_table_create(MAX_SDF_RULE_NUM)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to create up sdf filter table\n", LOG_VALUE);
		return -1;
	}

	/* Add the sdf filter rule in ACL table */
	if (up_rules_entry_add(&acl_rules_table[it],
				(struct acl4_rule *)next) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Up rules entry addtion failed\n", LOG_VALUE);
		return -1;
	}
	acl_rules_table[it].num_of_ue++;

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD:%s, precedence:%u, rule:%s\n", LOG_VALUE,
		"SDF", pkt_filter->precedence, pkt_filter->u.rule_str);

	/* Rebuild the ACl table */
	if (reset_and_build_rules(it) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed in reset and build rules\n", LOG_VALUE);
		return -1;
	}
	return it;
}

/**
 * @brief  : Free the memory allocated for node.
 * @param  : p, void pointer to be free.
 * @return : Returns nothing
 */
static void
free_node(void *p)
{
	rte_free(p);
}

/**
 * @brief  : Delete Rules table.
 * @param  : t, rules table pointer.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
up_acl_rules_table_delete(struct acl_rules_table *t)
{
	tdestroy(&t->root, free_node);
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL Rules table : \"%s\" destroyed\n", LOG_VALUE, t->name);
	memset(t, 0, sizeof(struct acl_rules_table));
	return 0;
}

int
up_sdf_filter_table_delete(uint32_t indx)
{
	struct rte_acl_ctx *ctx = acl_config[indx].acx_ipv4;
	struct acl_rules_table *t = &acl_rules_table[indx];

	/* Delete all rules from the ACL context and destroy all internal run-time structures */
	rte_acl_reset(ctx);

	/* Delete entry from local table */
	if(up_acl_rules_table_delete(t)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed in up acl table delete\n", LOG_VALUE);
		/* TODO: ERROR Handling */
		return -1;
	}

	/* Deleted ACL Table */
	--acl_table_indx_offset;
	acl_table_indx = 0;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL table %s deleted", LOG_VALUE, ctx->name);

	rte_free(ctx);
	return 0;
}

/**
 * @brief  : Delete rules entry.
 * @param  : t, rules table pointer
 * @param  : rule, element to be deleted from this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
up_rules_entry_delete(struct acl_rules_table *t,
				struct acl4_rule *rule)
{
	void **p;
	/* delete node from the tree */
	p = tdelete(rule, &t->root, t->compare);
	if (p == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Fail to delete acl rule id %d\n", LOG_VALUE,
			rule->data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}
	t->num_entries--;
	rte_free(*p);
	return 0;
}

int
up_sdf_filter_entry_delete(uint32_t indx,
			struct sdf_pkt_filter *pkt_filter_entry)
{
	uint32_t precedence = 0;
	struct acl4_rule rule = {0};
	struct rte_acl_ctx *ctx = acl_config[indx].acx_ipv4;

	if (pkt_filter_entry == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Read msg Payload failed\n", LOG_VALUE);
		return -1;
	}

	precedence = pkt_filter_entry->precedence;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL DEL: %s, precedence: %u\n",
		LOG_VALUE, ctx->name, precedence);

	rule.data.userdata = precedence + ACL_DENY_SIGNATURE;
	up_rules_entry_delete(&acl_rules_table[indx], &rule);
	return 0;
}

/**
 * @brief  : Lookup into acl table
 * @param  : m, buffer
 * @param  : indx, ACL Table Index
 * @param  : acl_config, acl configuration
 * @param  : acl_search, acl search parameter
 * @return : Returns 0 in case of success
 */
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
			}
		}
		return (uint32_t *)&(acl_search->res_ipv4);
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ERROR: ACL Context is Not Found \n", LOG_VALUE);
	return 0;
}

uint32_t *sdf_lookup(struct rte_mbuf **m, int nb_rx, uint32_t indx)
{
	RTE_SET_USED(nb_rx);
	return acl_lookup(m, indx, &acl_config[indx], &acl_search);
}

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
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to create up sdf filter table\n", LOG_VALUE);
		return -1;
	}

	if (up_filter_entry_add(indx, &pktf)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add up filter entry\n", LOG_VALUE);
		/* TODO: ERROR Handling */
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD:%s, precedence:%u, rule:%s\n",
		"SDF", LOG_VALUE, pktf.precedence, pktf.u.rule_str);
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

	if (up_filter_entry_add(indx, &pktf)){
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to add up filter entry\n", LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD:%s, precedence:%u, rule:%s\n",
		"SDF", LOG_VALUE, pktf.precedence, pktf.u.rule_str);
	return 0;
}

int
sdf_table_delete(uint32_t indx,
					struct sdf_pkt_filter *pkt_filter_entry){
	uint32_t precedence = 0;
	struct rte_acl_ctx *ctx = acl_config[indx].acx_ipv4;
	struct acl_rules_table *t = &acl_rules_table[indx];

	/* Delete all rules from the ACL context and destroy all internal run-time structures */
	rte_acl_reset(ctx);

	struct acl4_rule rule = {0};
	precedence = pkt_filter_entry->precedence;
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL DEL:%s precedence: %u\n", LOG_VALUE, ctx->name, precedence);

	rule.data.userdata = precedence + ACL_DENY_SIGNATURE;
	up_rules_entry_delete(t, &rule);
	t = NULL;
	free(t);
	return 0;
}

int
remove_rule_entry_acl(uint32_t indx,
			struct sdf_pkt_filter *pkt_filter_entry){

	struct acl_rules_table *t = &acl_rules_table[indx];

	if(t->num_of_ue > 1){
		t->num_of_ue--;
		clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Rule is used for more then one Bearer/UE"
		" So not removing that table rule left for %u UE\n",
		LOG_VALUE, t->num_of_ue);
		return 0;
	}

	if(t->num_entries == 0){
		clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"No Acl Entery in Given Index table\n", LOG_VALUE);
		return 0;
	}
	if(t->num_entries == 1)
		return sdf_table_delete(indx, pkt_filter_entry);
	else{
		if(up_sdf_filter_entry_delete(indx, pkt_filter_entry)) {
			clLog(clSystemLog, eCLSeverityCritical,
				"Failed to delete up sdf filter entry\n", LOG_VALUE);
			return -1;
		}
		return reset_and_build_rules(indx);
	}
}
