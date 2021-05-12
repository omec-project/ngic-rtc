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

#ifndef TEID_H
#define TEID_H

/**
 * @file
 *
 * Contains all data structures and functions to manage and/or
 * obtain value for teid assignement.
 *
 */

#include <stdint.h>
#include <pfcp_struct.h>

struct teid_info_t{
	/* DP ip address*/
	node_address_t dp_ip;

	/* Default teid range value */
	uint8_t teid_range;

	/* base value and offset for sgw teid generation */
	uint32_t up_gtpu_base_teid;
	uint32_t up_gtpu_teid_offset;
	uint32_t up_gtpu_teid;

	/* max teid value in range, after which teid value should loopback */
	uint32_t up_gtpu_max_teid_offset;

	struct teid_info_t *next;
};

typedef struct teid_info_t teid_info;

/*
 * Define type of Control Plane (CP)
 * SGWC - Serving GW Control Plane
 * PGWC - PDN GW Control Plane
 * SAEGWC - Combined SAEGW Control Plane
 */
enum cp_config_type {
	CP_TYPE_SGWC= 01,
	CP_TYPE_PGWC = 02,
	CP_TYPE_SAEGWC = 03,
};

/**
 * @brief  : sets base teid value given range by DP
 * @param  : ri_val
 *           teid range indicator assigned by DP
 * @param  : val
 *           teid range assigned by DP
 * @param  : upf_ip
 *           ip address of DP
 * @param  : upf_teid_info_head
 *           pointer to teid_info list
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t
set_base_teid(uint8_t ri_val, uint8_t val,  node_address_t upf_ip,
									teid_info **upf_teid_info_head);

/**
 * @brief  : sets the s1u_sgw gtpu teid
 * @param  : upf_ip
 *           ip address of DP
 * @param  : cp_type
 *           cp_type, SGWC, PGWC or SEAGWC
 * @param  : upf_teid_info_head
 *           pointer to teid_info list
 * @return : Returns s1u_sgw_gtpu_teid
 */
uint32_t
get_s1u_sgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **upf_teid_info_head);

/**
 * @brief  : sets the s5s8_sgw gtpu teid
 * @param  : upf_ip
 *           ip address of DP
 * @param  : cp_type
 *           cp_type, SGWC, PGWC or SEAGWC
 * @param  : upf_teid_info_head
 *           pointer to teid_info list
 * @return : Returns s5s8_sgw_gtpu_teid
 */
uint32_t
get_s5s8_sgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **upf_teid_info_head);

/**
 * @brief  : sets the s5s8_pgw gtpu teid
 * @param  : upf_ip
 *           ip address of DP
 * @param  : cp_type
 *           cp_type, SGWC, PGWC or SEAGWC
 * @param  : upf_teid_info_head
 *           pointer to teid_info list
 * @return : Returns s5s8_pgw_gtpu_teid
 */
uint32_t
get_s5s8_pgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **upf_teid_info_head);

/**
 * @brief  : sets the s5s8_sgw gtpc teid
 * @param  : No param
 * @return : Returns s5s8_sgw_gtpc_teid
 */
uint32_t
get_s5s8_sgw_gtpc_teid(void);

/**
 * @brief  : sets the s5s8_pgw gtpc teid
 * @param  : No param
 * @return : Returns s5s8_pgw_gtpc_teid
 */
uint32_t
get_s5s8_pgw_gtpc_teid(void);

/**
 * @brief  : sets s11 sgw gtpc teid
 * @param  : check_if_ue_hash_exist,
 *           ue hash flag
 * @param  : cp_type
 *           cp_type, SGWC, PGWC or SEAGWC
 * @param  : old_s11_sgw_gtpc_teid, s11_sgw_gtpc_teid already in context
 * @return : Returns s11_sgw_gtpc_teid
 */
uint32_t
get_s11_sgw_gtpc_teid(uint8_t *check_if_ue_hash_exist, int cp_type, uint32_t old_s11_sgw_gtpc_teid);

/**
 * @brief  : Retrives node from list for given ip
 * @param  : head
 *           teid_info linked list head
 * @param  : upf_ip
 *           ip address of DP
 * @return : Returns pointer to node in case of success, NULL otherwise
 */
teid_info *
get_teid_info(teid_info **head, node_address_t upf_ip);

/**
 * @brief  : Adds new node to the list
 * @param  : head
 *           teid_info linked list head
 * @param  : newNode
 *           new node to be addded in list
 * @return : Returns 0 in case of success, -1 otherwise
 */
int8_t
add_teid_info(teid_info **head, teid_info *newNode);

/**
 * @brief  : Deletes node from list for given ip
 * @param  : upf_ip
 *           ip address of DP
 * @param  : upf_teid_info_head
 *           pointer to teid_info list
 * @return : Returns nothing
 */
void
delete_entry_from_teid_list(node_address_t upf_ip, teid_info **upf_teid_info_head);

#endif /* TEID_H */
