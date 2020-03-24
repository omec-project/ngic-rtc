/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef UE_H
#define UE_H

/**
 * @file
 *
 * Contains all data structures required by 3GPP TS 23.401 Tables 5.7.3-1 and
 * 5.7.4-1 (that are nessecary for current implementaiton) to describe the
 * Connections, state, bearers, etc as well as functions to manage and/or
 * obtain value for their fields.
 *
 */

#include <stdint.h>
#include <arpa/inet.h>

#include <rte_malloc.h>
#include <rte_lcore.h>
#include <rte_jhash.h>
#include <rte_hash.h>

#include "gtpv2c_ie.h"
#include "packet_filters.h"
#include "interface.h"
#include "stdbool.h"
#include "cp_config.h"

#define SDF_FILTER_TABLE "sdf_filter_table"
#define ADC_TABLE "adc_rule_table"
#define PCC_TABLE "pcc_table"
#define SESSION_TABLE "session_table"
#define METER_PROFILE_SDF_TABLE "meter_profile_sdf_table"
#define METER_PROFILE_APN_TABLE "meter_profile_apn_table"

#define SDF_FILTER_TABLE_SIZE        (1024)
#define ADC_TABLE_SIZE               (1024)
#define PCC_TABLE_SIZE               (1025)
#define METER_PROFILE_SDF_TABLE_SIZE (2048)

#define DPN_ID                       (12345)

#define MAX_BEARERS                  (11)
#define MAX_FILTERS_PER_UE           (16)

#define GET_UE_IP(ue_index) \
		(((ip_pool_ip.s_addr | (~ip_pool_mask.s_addr)) \
				- htonl(ue_index)) - 0x01000000)

struct eps_bearer_t;
struct pdn_connection_t;

typedef struct apn_t {
	char *apn_name_label;
	size_t apn_name_length;
	uint8_t apn_idx;
} apn;

typedef struct ue_context_t {
	uint64_t imsi;
	uint8_t unathenticated_imsi;
	uint64_t mei;
	uint64_t msisdn;

	ambr_ie mn_ambr;

	uint32_t s11_sgw_gtpc_teid;
	struct in_addr s11_sgw_gtpc_ipv4;
	uint32_t s11_mme_gtpc_teid;
	struct in_addr s11_mme_gtpc_ipv4;

	uint16_t bearer_bitmap;
	uint16_t teid_bitmap;
	uint8_t num_pdns;

	struct pdn_connection_t *pdns[MAX_BEARERS];
	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 5 */

	/* temporary bearer to be used during resource bearer cmd -
	 * create/deletee bearer req - rsp */
	struct eps_bearer_t *ded_bearer;

	/* dpId tells which DP is holding the data bearers for this user context */ 
	uint64_t	dpId;

} ue_context;

typedef struct pdn_connection_t {
	apn *apn_in_use;
	ambr_ie apn_ambr;
	uint32_t apn_restriction;

	ambr_ie session_ambr;
	ambr_ie session_gbr;

	struct in_addr ipv4;
	struct in6_addr ipv6;

	uint32_t s5s8_sgw_gtpc_teid;
	struct in_addr s5s8_sgw_gtpc_ipv4;

	uint32_t s5s8_pgw_gtpc_teid;
	struct in_addr s5s8_pgw_gtpc_ipv4;

	pdn_type_ie pdn_type;
	/* See  3GPP TS 32.298 5.1.2.2.7 for Charging Characteristics fields*/
	charging_characteristics_ie charging_characteristics;

	uint8_t default_bearer_id;

	struct eps_bearer_t *eps_bearers[MAX_BEARERS]; /* index by ebi - 5 */

	struct eps_bearer_t *packet_filter_map[MAX_FILTERS_PER_UE];
} pdn_connection;

typedef struct eps_bearer_t {
	uint8_t eps_bearer_id;

	bearer_qos_ie qos;

	uint32_t charging_id;

	struct in_addr s1u_sgw_gtpu_ipv4;
	uint32_t s1u_sgw_gtpu_teid;
	struct in_addr s5s8_sgw_gtpu_ipv4;
	uint32_t s5s8_sgw_gtpu_teid;
	struct in_addr s5s8_pgw_gtpu_ipv4;
	uint32_t s5s8_pgw_gtpu_teid;
	struct in_addr s1u_enb_gtpu_ipv4;
	uint32_t s1u_enb_gtpu_teid;

	struct in_addr s11u_mme_gtpu_ipv4;
	uint32_t s11u_mme_gtpu_teid;

	struct pdn_connection_t *pdn;

	int packet_filter_map[MAX_FILTERS_PER_UE];
	uint8_t num_packet_filters;
} eps_bearer;

extern struct rte_hash *ue_context_by_imsi_hash;
extern struct rte_hash *ue_context_by_fteid_hash;

extern apn apn_list[MAX_NB_DPN];

/**
 * sets the s1u_sgw gtpu teid given the bearer
 * @param bearer
 *   bearer whose tied is to be set
 * @param context
 *   ue context of bearer, whose teid is to be set
 */
void
set_s1u_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);

/**
 * sets the s5s8_sgw gtpu teid given the bearer
 * @param bearer
 *   bearer whose tied is to be set
 * @param context
 *   ue context of bearer, whose teid is to be set
 */
void
set_s5s8_sgw_gtpu_teid(eps_bearer *bearer, ue_context *context);

/**
 * sets the s5s8_pgw gtpc teid given the pdn_connection
 * @param pdn
 *   pdn_connection whose s5s8 tied is to be set
 */
void
set_s5s8_pgw_gtpc_teid(pdn_connection *pdn);

/**
 * Initializes UE hash table
 */
void
create_ue_hash(void);

/** creates an UE Context (if needed), and pdn connection with a default bearer
 * given the UE IMSI, and EBI
 * @param imsi
 *   value of information element of the imsi
 * @param imsi_len
 *   length of information element of the imsi
 * @param ebi
 *   Eps Bearer Identifier of default bearer
 * @param context
 *   UE context to be created
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 *   \- < 0 for all other errors
 */
int
create_ue_context(uint8_t *imsi_val, uint16_t imsi_len,
		uint8_t ebi, ue_context **context);

/**
 * assigns the ip pool variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 */
void
set_ip_pool_ip(const char *ip_str);

/**
 * assigns the ip pool mask variable from parsed c-string
 * @param ip_str
 *   ip address c-string from command line
 *
 */
void
set_ip_pool_mask(const char *ip_str);

/**
 * This function takes the c-string argstr describing a apn by url, for example
 *  label1.label2.label3 and populates the apn structure according 3gpp 23.003
 *  clause 9.1
 * @param an_apn
 *   apn to be initialized
 * @param argstr
 *   c-string containing the apn label
 */
void
set_apn_name(apn *an_apn, char *argstr);

/**
 * returns the apn strucutre of the apn referenced by create session message
 * @param apn_label
 *   apn_label within a create session message
 * @param apn_length
 *   the length as recorded by the apn information element
 * @return
 *   the apn label configured for the CP
 */
apn *
get_apn(char *apn_label, uint16_t apn_length);

/**
 * Simple ip-pool
 * @param ipv4
 *   ip address to be used for a new UE connection
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to
 *          3gpp specified cause error value
 */
uint32_t
acquire_ip(struct in_addr *ipv4);

/* debug */

/** print (with a column header) either context by the context and/or
 * iterating over hash
 * @param h
 *   pointer to rte_hash containing ue hash table
 * @param context
 *   denotes if some context is to be indicated by '*' character
 */
void
print_ue_context_by(struct rte_hash *h, ue_context *context);

struct ip_table
{
  struct ip_table *octet[256];
  char *ue_address; // address 
  bool used ; 
};

void add_ipaddr_in_pool(struct ip_table *addr_tree , struct in_addr addr);
bool reserve_ip_node(struct ip_table *addr_tree , struct in_addr host);
bool release_ip_node(struct ip_table *addr_tree , struct in_addr host);
struct ip_table*create_ue_pool(struct in_addr network, uint32_t mask);

#endif /* UE_H */
