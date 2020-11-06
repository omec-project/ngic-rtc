/*
 * Copyright (c) 2019 Sprint
 * Copyright (c) 2020 T-Mobile
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
#include "gw_adapter.h"
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
#define OFF_IPV62PROTO (offsetof(struct ipv6_hdr, proto))
#define MBUF_IPV4_2PROTO(m)	\
	rte_pktmbuf_mtod_offset((m), uint8_t *, OFF_ETHHEAD + OFF_IPV42PROTO)
#define MBUF_IPV6_2PROTO(m) \
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

static uint32_t acl_table_indx_offset = 1;
static uint32_t acl_table_indx;
/* Max number of sdf rules */
static uint8_t sdf_rule_id;
extern int clSystemLog;

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
            offsetof(struct ipv6_hdr, proto) +
            2 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = SRC4_FIELD_IPV6,
        .input_index = SRC4_FIELD_IPV6,
        .offset = offsetof(struct ipv6_hdr, src_addr) -
            offsetof(struct ipv6_hdr, proto) +
            3 * sizeof(uint32_t),
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
            offsetof(struct ipv6_hdr, proto) +
            2 * sizeof(uint32_t),
    },
    {
        .type = RTE_ACL_FIELD_TYPE_MASK,
        .size = sizeof(uint32_t),
        .field_index = DST4_FIELD_IPV6,
        .input_index = DST4_FIELD_IPV6,
        .offset = offsetof(struct ipv6_hdr, dst_addr) -
            offsetof(struct ipv6_hdr, proto) +
            3 * sizeof(uint32_t),
    },
};

RTE_ACL_RULE_DEF(acl4_rule, RTE_DIM(ipv4_defs));
RTE_ACL_RULE_DEF(acl6_rule, RTE_DIM(ipv6_defs));

/**
 * @brief  : Maintains acl configuration
 */
struct acl_config {
	struct rte_acl_ctx *acx_ipv4;
	struct rte_acl_ctx *acx_ipv6;
	uint8_t acx_ipv4_built;
	uint8_t acx_ipv6_built;
};

/**
 * @brief  : Maintains acl parameters
 */
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
	int (*compare_ipv6_rule)(const void *r1p, const void *r2p);
	void (*print_entry)(const void *nodep, const VISIT which, const int depth);
	void (*add_entry)(const void *nodep, const VISIT which, const int depth);
	void (*add_ipv6_entry)(const void *nodep, const VISIT which, const int depth);
	uint16_t num_of_ue;
};

struct acl_config acl_config[MAX_ACL_TABLES];
struct acl_rules_table acl_rules_table[MAX_ACL_TABLES];
struct acl_search acl_search = {0};


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

static inline void
print_one_ipv6_rule(struct acl6_rule *rule, int extra)
{
    unsigned char a, b, c, d;
    uint32_t_to_char(rule->field[SRC1_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
   clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"%.2x%.2x:%.2x%.2x", LOG_VALUE, a, b, c, d);
    uint32_t_to_char(rule->field[SRC2_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[SRC3_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[SRC4_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
            rule->field[SRC1_FIELD_IPV6].mask_range.u32
            + rule->field[SRC2_FIELD_IPV6].mask_range.u32
            + rule->field[SRC3_FIELD_IPV6].mask_range.u32
            + rule->field[SRC4_FIELD_IPV6].mask_range.u32);
    uint32_t_to_char(rule->field[DST1_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,"%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST2_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST3_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x", a, b, c, d);
    uint32_t_to_char(rule->field[DST4_FIELD_IPV6].value.u32,
        &a, &b, &c, &d);
    clLog(clSystemLog, eCLSeverityDebug,":%.2x%.2x:%.2x%.2x/%u ", a, b, c, d,
            rule->field[DST1_FIELD_IPV6].mask_range.u32
            + rule->field[DST2_FIELD_IPV6].mask_range.u32
            + rule->field[DST3_FIELD_IPV6].mask_range.u32
            + rule->field[DST4_FIELD_IPV6].mask_range.u32);
    clLog(clSystemLog, eCLSeverityDebug,"0x%hhx/0x%hhx \n",
        rule->field[PROTO_FIELD_IPV6].value.u8,
        rule->field[PROTO_FIELD_IPV6].mask_range.u8);
    if (extra)
        clLog(clSystemLog, eCLSeverityDebug,"0x%x-0x%x-0x%x ",
            rule->data.category_mask,
            rule->data.priority,
            rule->data.userdata);
}

/**
 * @brief  : Fill acl rule information
 * @param  : pkts_in, input buffer
 * @param  : acl, acl structure to fill
 * @param  : index, index of packet in array
 * @return : Returns nothing
 */
static inline void
prepare_one_packet(struct rte_mbuf **pkts_in, struct acl_search *acl,
		int index)
{
	struct rte_mbuf *pkt = pkts_in[index];

	/* Fill acl structure */
	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		/* IPv4 Information */
		acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
		/* IPv6 Information */
		acl->data_ipv6[acl->num_ipv6] = MBUF_IPV6_2PROTO(pkt);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	} else {
		/* Malformed packet, drop the packet */
		rte_pktmbuf_free(pkt);
	}
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
	acl->num_ipv6 = 0;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void *));


	for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod
				(pkts_in[i + PREFETCH_OFFSET], void *));
		prepare_one_packet(pkts_in, acl, i);
	}

	/* Process left packets */
	for (; i < nb_rx; i++)
		prepare_one_packet(pkts_in, acl, i);
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

static
void ipv6_expander(const struct in6_addr *addr, char *str){
    snprintf(str, IPV6_STR_LEN,"%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
    (int)addr->s6_addr[0], (int)addr->s6_addr[1],
    (int)addr->s6_addr[2], (int)addr->s6_addr[3],
    (int)addr->s6_addr[4], (int)addr->s6_addr[5],
    (int)addr->s6_addr[6], (int)addr->s6_addr[7],
    (int)addr->s6_addr[8], (int)addr->s6_addr[9],
    (int)addr->s6_addr[10], (int)addr->s6_addr[11],
    (int)addr->s6_addr[12], (int)addr->s6_addr[13],
    (int)addr->s6_addr[14], (int)addr->s6_addr[15]);
    return;

}

static int
parse_ipv6_addr(char *in, const char **end, uint32_t v[IPV6_ADDR_U32],
    char dlm)
{
	struct in6_addr ipv6 = {0};
	char tmp[IPV6_STR_LEN];
	char *saveptr, *ipv6_str, *final_ipv6 = NULL;
	final_ipv6 = (char *)malloc(MAX_LEN * sizeof(char));

	ipv6_str = strtok_r(in, "/", &saveptr);
	if(inet_pton(AF_INET6, ipv6_str, &ipv6)) {
	    ipv6_expander(&ipv6, tmp);
	}else{
		clLog(clSystemLog, eCLSeverityCritical,"IP conversion failes");
		return -1;
	}

    snprintf(final_ipv6, MAX_LEN, "%s/%s", tmp, saveptr);
    char *temp = final_ipv6;

    uint32_t addr[IPV6_ADDR_U16];
    GET_CB_FIELD(final_ipv6, addr[0], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[1], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[2], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[3], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[4], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[5], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[6], 16, UINT16_MAX, ':');
    GET_CB_FIELD(final_ipv6, addr[7], 16, UINT16_MAX, dlm);
    *end = final_ipv6;
    v[0] = (addr[0] << 16) + addr[1];
    v[1] = (addr[2] << 16) + addr[3];
    v[2] = (addr[4] << 16) + addr[5];
    v[3] = (addr[6] << 16) + addr[7];
    free(temp);
    return 0;
}

static int
parse_ipv6_net(char *in, struct rte_acl_field field[4])
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

static int
parse_cb_ipv6_rule(char *str, struct rte_acl_rule *v, int has_userdata)
{
    int i, rc;
    char *s, *sp, *in[CB_IPV6_FLD_NUM], tmp[MAX_LEN] = {0};
    static const char *dlm = " \t\n";
    int dim = has_userdata ? CB_IPV6_FLD_NUM : CB_IPV6_FLD_USERDATA;
    strncpy(tmp, str, MAX_LEN);
    s = tmp;
    for (i = 0; i != dim; i++, s = NULL) {
        in[i] = strtok_r(s, dlm, &sp);
        if (in[i] == NULL)
            return -EINVAL;
    }
    rc = parse_ipv6_net(in[CB_IPV6_FLD_SRC_ADDR], v->field + SRC1_FIELD_IPV6);
    if (rc != 0) {
        clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"failed to read source address/mask: %s\n",LOG_VALUE,
            in[CB_FLD_SRC_ADDR]);
        return rc;
    }
    rc = parse_ipv6_net(in[CB_IPV6_FLD_DST_ADDR], v->field + DST1_FIELD_IPV6);
    if (rc != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"failed to read destination address/mask: %s\n",LOG_VALUE,
            in[CB_FLD_SRC_ADDR]);
        return rc;
    }
    GET_CB_FIELD(in[CB_IPV6_FLD_PROTO], v->field[PROTO_FIELD_IPV6].value.u8,
        0, UINT8_MAX, '/');
    GET_CB_FIELD(in[CB_IPV6_FLD_PROTO], v->field[PROTO_FIELD_IPV6].mask_range.u8,
        0, UINT8_MAX, 0);
    if (has_userdata)
        GET_CB_FIELD(in[CB_IPV6_FLD_USERDATA], v->data.userdata,
            0, UINT32_MAX, 0);
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
 * @brief  : Add the IPv6 Rule entry in rte acl table.
 * @param  : nodep, node to add
 * @param  : which, traversal order
 * @param  : depth, node depth
 * @return : Returns nothing
 */
static void add_single_ipv6_rule(const void *nodep, const VISIT which, const int depth)
{
	struct acl6_rule *r = NULL;

	struct acl_config *pacl_config = &acl_config[acl_table_indx];
	struct rte_acl_ctx *context = pacl_config->acx_ipv6;

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	r = *(struct acl6_rule **) nodep;
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
 * @brief  : Compare rule entry.
 * @param  : r1p, first acl rule
 * @param  : r2p, second acl rule
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int acl_ipv6_rule_compare(const void *r1p, const void *r2p)
{
	struct acl6_rule *rule1, *rule2;

	rule1 = (struct acl6_rule *) r1p;
	rule2 = (struct acl6_rule *) r2p;

	/* compare rule */
	if ((rule1->data.userdata == rule2->data.userdata) &&

		(rule1->field[SRC1_FIELD_IPV6].value.u32 ==
			rule2->field[SRC1_FIELD_IPV6].value.u32) &&

		(rule1->field[SRC2_FIELD_IPV6].value.u32 ==
			rule2->field[SRC2_FIELD_IPV6].value.u32) &&

		(rule1->field[SRC3_FIELD_IPV6].value.u32 ==
			rule2->field[SRC3_FIELD_IPV6].value.u32) &&

		(rule1->field[SRC4_FIELD_IPV6].value.u32 ==
			rule2->field[SRC4_FIELD_IPV6].value.u32) &&

		(rule1->field[DST1_FIELD_IPV6].value.u32 ==
			rule2->field[DST1_FIELD_IPV6].value.u32) &&

		(rule1->field[DST2_FIELD_IPV6].value.u32 ==
			rule2->field[DST2_FIELD_IPV6].value.u32) &&

		(rule1->field[DST3_FIELD_IPV6].value.u32 ==
			rule2->field[DST3_FIELD_IPV6].value.u32) &&

		(rule1->field[DST4_FIELD_IPV6].value.u32 ==
			rule2->field[DST4_FIELD_IPV6].value.u32) &&

		(rule1->field[PROTO_FIELD_IPV6].value.u8 ==
			rule2->field[PROTO_FIELD_IPV6].value.u8) &&

		(rule1->field[PROTO_FIELD_IPV6].mask_range.u8 ==
			rule2->field[PROTO_FIELD_IPV6].mask_range.u8) &&

		((rule1->field[SRC1_FIELD_IPV6].mask_range.u32
            + rule1->field[SRC2_FIELD_IPV6].mask_range.u32
            + rule1->field[SRC3_FIELD_IPV6].mask_range.u32
            + rule1->field[SRC4_FIELD_IPV6].mask_range.u32) ==
			(rule2->field[SRC1_FIELD_IPV6].mask_range.u32
            + rule2->field[SRC2_FIELD_IPV6].mask_range.u32
            + rule2->field[SRC3_FIELD_IPV6].mask_range.u32
            + rule2->field[SRC4_FIELD_IPV6].mask_range.u32)) &&

		((rule1->field[DST1_FIELD_IPV6].mask_range.u32
            + rule1->field[DST2_FIELD_IPV6].mask_range.u32
            + rule1->field[DST3_FIELD_IPV6].mask_range.u32
            + rule1->field[DST4_FIELD_IPV6].mask_range.u32) ==
			(rule2->field[DST1_FIELD_IPV6].mask_range.u32
            + rule2->field[DST2_FIELD_IPV6].mask_range.u32
            + rule2->field[DST3_FIELD_IPV6].mask_range.u32
            + rule2->field[DST4_FIELD_IPV6].mask_range.u32))) {

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
up_acl_rules_table_create(uint32_t indx, uint32_t max_elements, uint8_t is_ipv6)
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
	t->compare_ipv6_rule = acl_ipv6_rule_compare;
	t->print_entry = acl_rule_print;
	t->add_entry = add_single_rule;
	t->add_ipv6_entry = add_single_ipv6_rule;
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
		unsigned int max_elements, int socketid, uint8_t is_ipv6)
{
	struct rte_acl_ctx *context = NULL;
	struct rte_acl_param acl_param = {0};
	int dim = (is_ipv6 ? RTE_DIM(ipv6_defs) : RTE_DIM(ipv4_defs));

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
		char *name, uint32_t max_elements, uint8_t is_ipv6)
{

	memset(acl_config, 0, sizeof(struct acl_config));

	if(!is_ipv6){
		acl_config->acx_ipv4 =
		acl_context_init(name, max_elements, 0, is_ipv6);
	} else{
		acl_config->acx_ipv6 =
		acl_context_init(name, max_elements, 0, is_ipv6);
	}
	return 0;
}

/**
 * @brief  : Create SDF rules table
 * @param  : max_elements, max number of elements in this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
up_sdf_filter_table_create(uint32_t max_elements, uint8_t is_ipv6)
{
	char name[NAME_LEN];
	char *buf = "ACLTable-";
	acl_table_indx = acl_table_indx_offset;

	/* Increment the New Created ACL tables */
	snprintf(name, NAME_LEN, "%s%u", buf, acl_table_indx);

	/* Configure the ACL table */
	if (acl_config_init(&acl_config[acl_table_indx], name,
			max_elements, is_ipv6) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Acl config init failed\n", LOG_VALUE);
		/* TODO: Error Handling */
		return -1;
	}

	/* Create the local acl rules table copy */
	if (up_acl_rules_table_create(acl_table_indx, max_elements, is_ipv6)) {
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
add_rules_to_rte_acl(uint8_t indx, uint8_t is_ipv6)
{
	struct acl_rules_table *t = &acl_rules_table[indx];
	acl_table_indx = indx;
	if(!is_ipv6)
		twalk(t->root, t->add_entry);
	else
		twalk(t->root, t->add_ipv6_entry);
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
reset_and_build_rules(uint32_t indx, uint8_t is_ipv6)
{
	int ret = 0;
	int dim = is_ipv6 ? RTE_DIM(ipv4_defs) : RTE_DIM(ipv4_defs);
	struct rte_acl_config acl_build_param = {0};
	struct acl_config *pacl_config = &acl_config[indx];
	struct rte_acl_ctx *context = NULL;
	if(!is_ipv6)
		context = pacl_config->acx_ipv4;
	else
		context = pacl_config->acx_ipv6;

	/* Delete all rules from the ACL context. */
	rte_acl_reset_rules(context);

	/* Add the rules from local table to ACL table */
	add_rules_to_rte_acl(indx, is_ipv6);

	/* Perform builds */
	memset(&acl_build_param, 0, sizeof(acl_build_param));

	acl_build_param.num_categories = DEFAULT_MAX_CATEGORIES;
	acl_build_param.num_fields = dim;
	if(!is_ipv6)
		memcpy(&acl_build_param.defs, ipv4_defs,
				sizeof(ipv4_defs));
	else
		memcpy(&acl_build_param.defs, ipv6_defs,
				sizeof(ipv6_defs));

	/* Build the ACL run time structure */
	if ((ret = rte_acl_build(context, &acl_build_param)) != 0) {
		rte_exit(EXIT_FAILURE, LOG_FORMAT"Failed to build ACL trie,"
				"ACL_RULES_TABLE-%u, ret:%d, error:%s\n",
				LOG_VALUE, indx, ret, rte_strerror(rte_errno));
	}

	if(!is_ipv6)
		pacl_config->acx_ipv4_built = 1;
	else
		pacl_config->acx_ipv6_built = 1;

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
				struct acl4_rule *rule, uint8_t is_ipv6)
{
	if (t->num_entries == t->max_entries)
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT":%s reached max rules entries\n", LOG_VALUE, t->name);
	if(!is_ipv6){
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
	} else {
		struct acl6_rule *new = rte_malloc("acl_rule", sizeof(struct acl6_rule),
				RTE_CACHE_LINE_SIZE);
		if (new == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"ADC: Failed to allocate memory\n", LOG_VALUE);
			return -1;
		}
		memcpy(new, rule, sizeof(struct acl6_rule));

		/* put node into the tree */
		if (tsearch(new, &t->root, t->compare_ipv6_rule) == 0) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT":Fail to add acl precedance %d\n", LOG_VALUE,
				rule->data.userdata - ACL_DENY_SIGNATURE);
			return -1;
		}
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
				(struct acl4_rule *)next, 0) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Up rules entry add failed\n", LOG_VALUE);
		return -1;
	}

	if (reset_and_build_rules(indx, 0) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Reset and build rules Failed\n", LOG_VALUE);
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD: %s, ACL_Indx:%u, precedence:%u, rule:%s\n",
		"SDF RULE", LOG_VALUE, indx, pkt_filter->precedence, pkt_filter->u.rule_str);
	return 0;
}


/* Function to retrive the acl table index */
int
get_acl_table_indx(struct sdf_pkt_filter *pkt_filter, uint8_t is_create)
{
	uint8_t prio = 0;
	uint32_t it = 0;
	char *buf = NULL;
	struct acl4_rule r4 = {0};
	struct acl6_rule r6 = {0};
	struct rte_acl_rule *next = NULL;
	uint8_t is_ipv6 = (pkt_filter->rule_ip_type == RULE_IPV6);
	/* check sdf filter exist or not */
	if (pkt_filter == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"read msg_payload failed\n", LOG_VALUE);
		return -1;
	}

	prio = (255 - pkt_filter->precedence);
	buf = (char *)&pkt_filter->u.rule_str[0];

	if(!is_ipv6){
		next = (struct rte_acl_rule *)&r4;
		/* Parse the sdf filter into acl ipv4 rule format */
		if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Parse IPv4 rules error\n", LOG_VALUE);
			return -1;
		}
	}else{
		next = (struct rte_acl_rule *)&r6;
		/* Parse the sdf filter into acl ipv6 rule format */
		if (parse_cb_ipv6_rule(buf, next, 0) != 0) {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Parse IPv6 rules error\n", LOG_VALUE);
			print_one_ipv6_rule((struct acl6_rule  *)next, 1);
			return -1;
		}

	}

	/* Fill the received rule information */
	next->data.userdata = pkt_filter->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;


	print_one_ipv6_rule((struct acl6_rule  *)next, 1);

	/* Find similar rule is present or not */
	for (uint32_t itr = 1; itr < acl_table_indx_offset; itr++) {
		struct acl_rules_table *ctx = &acl_rules_table[itr];
		struct acl_rules_table *t = NULL;
		if (ctx == NULL)
			continue;

		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Search SDF Rule in ACL_Table_Index :%u\n",
			LOG_VALUE, itr);
		if(!is_ipv6)
			t = tfind(next, &ctx->root, ctx->compare_rule);
		else
			t = tfind(next, &ctx->root, ctx->compare_ipv6_rule);
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
	if ((it = up_sdf_filter_table_create(MAX_SDF_RULE_NUM, is_ipv6)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to create up sdf filter table\n", LOG_VALUE);
		return -1;
	}

	/* Add the sdf filter rule in ACL table */
	if (up_rules_entry_add(&acl_rules_table[it],
				(struct acl4_rule *)next, is_ipv6) < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Up rules entry addtion failed\n", LOG_VALUE);
		return -1;
	}
	acl_rules_table[it].num_of_ue++;

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL ADD:%s, precedence:%u, rule:%s\n", LOG_VALUE,
		"SDF", pkt_filter->precedence, pkt_filter->u.rule_str);

	/* Rebuild the ACl table */
	if (reset_and_build_rules(it, is_ipv6) < 0) {
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
 * @brief  : Delete rules entry.
 * @param  : t, rules table pointer
 * @param  : rule, element to be deleted from this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
up_rules_entry_delete(struct acl_rules_table *t,
				struct sdf_pkt_filter *pkt_filter_entry)
{
	void **p;
	struct acl4_rule rule_v4 = {0};
	uint8_t prio = 0;
	char *buf = NULL;
	struct rte_acl_rule *next = NULL;

	prio = (255 - pkt_filter_entry->precedence);
	buf = (char *)&pkt_filter_entry->u.rule_str[0];

	next = (struct rte_acl_rule *)&rule_v4;
	if (parse_cb_ipv4vlan_rule(buf, next, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Parse IPv4 rules error\n", LOG_VALUE);
		return -1;
	}

	next->data.userdata = pkt_filter_entry->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;

	p = tdelete(next, &t->root, t->compare_rule);
	if (p == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Fail to delete acl rule id %d\n", LOG_VALUE,
			rule_v4.data.userdata - ACL_DENY_SIGNATURE);
		return -1;
	}
	t->num_entries--;
	rte_free(*p);
	return 0;
}

/**
 * @brief  : Delete IPV6 rules entry.
 * @param  : t, rules table pointer
 * @param  : rule, element to be deleted from this table.
 * @return : Returns 0 in case of success , -1 otherwise
 */
int
up_ipv6_rules_entry_delete(struct acl_rules_table *t,
				struct sdf_pkt_filter *pkt_filter_entry)
{
	void **p;
	struct acl6_rule rule_v6 = {0};
	uint8_t prio = 0;
	char *buf = NULL;
	struct rte_acl_rule *next = NULL;

	prio = (255 - pkt_filter_entry->precedence);
	buf = (char *)&pkt_filter_entry->u.rule_str[0];
	next = (struct rte_acl_rule *)&rule_v6;
	if (parse_cb_ipv6_rule(buf, next, 0) != 0) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Parse IPv6 rules error\n", LOG_VALUE);
		return -1;
	}
	next->data.userdata = pkt_filter_entry->precedence + ACL_DENY_SIGNATURE;
	next->data.priority = prio;
	next->data.category_mask = -1;

	p = tdelete(next, &t->root, t->compare_ipv6_rule);
	if (p == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Fail to delete acl rule id %d\n", LOG_VALUE,
			next->data.userdata - ACL_DENY_SIGNATURE);
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
	uint8_t is_ipv6 = (pkt_filter_entry->rule_ip_type == RULE_IPV6);

	if (pkt_filter_entry == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Read msg Payload failed\n", LOG_VALUE);
		return -1;
	}
	if(!is_ipv6)
		up_rules_entry_delete(&acl_rules_table[indx], pkt_filter_entry);
	else
		up_ipv6_rules_entry_delete(&acl_rules_table[indx], pkt_filter_entry);

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
	/* Reset the acl_search struct */
	memset(acl_search, 0, sizeof(struct acl_search));
	struct rte_acl_ctx *context = NULL;
	context = acl_config->acx_ipv4;
	if(context == NULL){
		context = acl_config->acx_ipv6;
		if(context == NULL){
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"No context available for Lookup",
														LOG_VALUE);
			return 0;
		}
	}

	if (acl_config != NULL) {

		if ((context->trans_table != NULL)) {

			prepare_acl_parameter(m, acl_search, 1);

			if (acl_search->num_ipv4) {
				rte_acl_classify(context,
						acl_search->data_ipv4,
						acl_search->res_ipv4,
						acl_search->num_ipv4,
						DEFAULT_MAX_CATEGORIES);

				return (uint32_t *)&(acl_search->res_ipv4);
			} else if(acl_search->num_ipv6) {
				rte_acl_classify(context,
						acl_search->data_ipv6,
						acl_search->res_ipv6,
						acl_search->num_ipv6,
						DEFAULT_MAX_CATEGORIES);

				return (uint32_t *)&(acl_search->res_ipv6);
			}
		}
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

	struct rte_acl_ctx *ctx = NULL;
	struct acl_rules_table *t = &acl_rules_table[indx];
	uint8_t is_ipv6 = (pkt_filter_entry->rule_ip_type == RULE_IPV6);
	if(!is_ipv6)
		ctx = acl_config[indx].acx_ipv4;
	else
		ctx = acl_config[indx].acx_ipv6;
	/* Delete all rules from the ACL context and destroy all internal run-time structures */
	rte_acl_reset(ctx);


	if(!is_ipv6){
		up_rules_entry_delete(t, pkt_filter_entry);
	} else {
		up_ipv6_rules_entry_delete(t, pkt_filter_entry);
	}
	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"ACL DEL:%s \n", LOG_VALUE, ctx->name);

	t = NULL;
	free(t);
	return 0;
}

int
remove_rule_entry_acl(uint32_t indx,
			struct sdf_pkt_filter *pkt_filter_entry){

	struct acl_rules_table *t = &acl_rules_table[indx];
	uint8_t is_ipv6 = (pkt_filter_entry->rule_ip_type == RULE_IPV6);
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
		return reset_and_build_rules(indx, is_ipv6);
	}
}
/****************************************[END]****************************************/
