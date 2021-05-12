/*
 * Copyright (c) 2017 Intel Corporation
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

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "teid.h"
#include "gw_adapter.h"
#include "gtpv2c_ie.h"
#include "pfcp_util.h"
#include "debug_str.h"

#define DEFAULT_SGW_BASE_TEID 0xC0FFEE
#define DEFAULT_SGW_S5S8_BASE_TEID 0xE0FFEE
#define DEFAULT_PGW_BASE_TEID 0xD0FFEE

/*Number of bits needed to be shifted in teid range so that tied range value
 * will be at proper place in TEID
 * e.g 0x00000010 ==> 0x10000000
 */
#define SHIFT_BITS 24

/* number of bits in teid range */
#define MAX_RI_BITS 8

/* base value for seid generation */
const uint32_t s11_sgw_gtpc_base_teid = DEFAULT_SGW_BASE_TEID;
const uint32_t s5s8_sgw_gtpc_base_teid = DEFAULT_SGW_S5S8_BASE_TEID;
const uint32_t s5s8_pgw_gtpc_base_teid = DEFAULT_PGW_BASE_TEID;

/* offset for seid generation */
static uint32_t s11_sgw_gtpc_teid_offset;
static uint32_t s5s8_sgw_gtpc_teid_offset;
static uint32_t s5s8_pgw_gtpc_teid_offset;

/* constant to clear first byte of teid */
static uint32_t CLEAR_BYTE = 0xffffffff;

extern int clSystemLog;

teid_info * get_teid_info(teid_info **head, node_address_t upf_ip){
	teid_info *temp = NULL;
	if(*head != NULL){
		temp = *head;
		while(temp != NULL) {
			if(upf_ip.ip_type == PDN_TYPE_IPV4 && (temp->dp_ip.ipv4_addr == upf_ip.ipv4_addr)) {

				return temp;

			} else if (upf_ip.ip_type == PDN_TYPE_IPV6
				&& (memcmp(temp->dp_ip.ipv6_addr, upf_ip.ipv6_addr, IPV6_ADDRESS_LEN) == 0)) {

				return temp;
			}

			temp = temp->next;
		}
	}
	return NULL;
}

/**
 * @brief  : Initializes teid_info structure
 * @param  : upf_info, pointer to structure
 * @return : Returns nothing
 */
static void
init_teid_info(teid_info *upf_info){

#define DEFAULT_TEID_RANGE 0x00
	upf_info->teid_range = DEFAULT_TEID_RANGE;

#define DEFAULT_INITIAL_TEID 0x00000001
	upf_info->up_gtpu_teid = DEFAULT_INITIAL_TEID;
	upf_info->up_gtpu_base_teid = DEFAULT_INITIAL_TEID;

	upf_info->dp_ip.ipv4_addr = 0;
	memset(upf_info->dp_ip.ipv6_addr, 0, IPV6_ADDRESS_LEN);
	upf_info->up_gtpu_teid_offset = 0;
#define MAX_TEID_OFFSET 0xFFFFFFFF
	upf_info->up_gtpu_max_teid_offset = MAX_TEID_OFFSET;
	upf_info->next = NULL;

}

int8_t
add_teid_info(teid_info **head, teid_info *newNode){
	if (*head == NULL) {
		*head = newNode;
	}else{
		teid_info *temp = *head;
		while(temp->next != NULL){
			temp = temp->next;
		}
		temp->next = newNode;
	}
	return 0;
}

void
delete_entry_from_teid_list(node_address_t upf_ip, teid_info **head){
	teid_info *temp = NULL;
	teid_info *prev = NULL;

	if(*head == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Failed to remove upf information, List is empty\n, "
			"IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT"",
			LOG_VALUE, ip_type_str(upf_ip.ip_type),
			upf_ip.ipv4_addr,
			PRINT_IPV6_ADDR(upf_ip.ipv6_addr));		
		return;
	}
	temp = *head;
	/* If node to be deleted is first node */
	if(upf_ip.ip_type == PDN_TYPE_IPV4 && (temp->dp_ip.ipv4_addr == upf_ip.ipv4_addr)) {
		*head = temp->next;
		free(temp);
		return;

	} else if (upf_ip.ip_type == PDN_TYPE_IPV6
		&& (memcmp(temp->dp_ip.ipv6_addr, upf_ip.ipv6_addr, IPV6_ADDRESS_LEN) == 0)) {
		*head = temp->next;
		free(temp);
		return;
	}

	/* If node to be deleted is not first node */
	prev = *head;
	while(temp != NULL){

		if(upf_ip.ip_type == PDN_TYPE_IPV4 && (temp->dp_ip.ipv4_addr == upf_ip.ipv4_addr)) {
			prev->next = temp->next;
			free(temp);
			return;

		} else if (upf_ip.ip_type == PDN_TYPE_IPV6
			&& (memcmp(temp->dp_ip.ipv6_addr, upf_ip.ipv6_addr, IPV6_ADDRESS_LEN) == 0)) {
			prev->next = temp->next;
			free(temp);
			return;
		}

		prev = temp;
		temp = temp->next;
	}
}

int8_t
set_base_teid(uint8_t ri_val, uint8_t val, node_address_t upf_ip,
		teid_info **upf_teid_info_head)
{

	teid_info *upf_info = NULL;
	uint8_t ret = 0;

	upf_info = get_teid_info(upf_teid_info_head, upf_ip);
	if(upf_info == NULL) {
		upf_info = malloc(sizeof(teid_info));
		if(upf_info == NULL){
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to add node for DP\n, IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT,
				LOG_VALUE, ip_type_str(upf_ip.ip_type),
				upf_ip.ipv4_addr,
				PRINT_IPV6_ADDR(upf_ip.ipv6_addr));
			return -1;
		}

		init_teid_info(upf_info);

		if (upf_ip.ip_type == PDN_TYPE_IPV4) {

			upf_info->dp_ip.ipv4_addr = upf_ip.ipv4_addr;
			upf_info->dp_ip.ip_type = PDN_TYPE_IPV4;

		} else if (upf_ip.ip_type == PDN_TYPE_IPV6) {

			memcpy(upf_info->dp_ip.ipv6_addr, upf_ip.ipv6_addr, IPV6_ADDRESS_LEN);
			upf_info->dp_ip.ip_type = PDN_TYPE_IPV6;
		}


		ret = add_teid_info(upf_teid_info_head, upf_info);
		if(ret != 0){
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to add node for DP\n, IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT,
				LOG_VALUE, ip_type_str(upf_ip.ip_type),
				upf_ip.ipv4_addr,
				PRINT_IPV6_ADDR(upf_ip.ipv6_addr));
			return -1;
		}
	}

	if (ri_val != 0) {
		/* set cp teid_range value */
		/* teid range will be (ri_val) MSBs of teid value, so need to shift teid range received from dp to MSB
		 * e.g: if teid_range received from DP = 0000 0001 , and teidri = 3, then teid range = 0010 0000
		 *      if teid_range received from DP = 0000 0101 , and teidri = 3, then teid range = 1010 0000
		 *      if teid_range received from DP = 0000 0011 , and teidri = 2, then teid range = 1100 0000
		 */
		upf_info->teid_range = (val << (MAX_RI_BITS - ri_val));

		/* e.g: if teidri = 3, then CLEAR_BYTE  = 0001 1111 1111 1111 1111 1111 1111 1111
		 *      if teidri = 8, then CLEAR_BYTE  = 0000 0000 1111 1111 1111 1111 1111 1111
		 */
		CLEAR_BYTE = (CLEAR_BYTE >> (ri_val));

		/* e.g: if teidri = 3, then max teid offset = 0001 1111 1111 1111 1111 1111 1111 1111
		 *      if teidri = 8, then max teid offset = 0000 0000 1111 1111 1111 1111 1111 1111
		 */
		upf_info->up_gtpu_max_teid_offset = CLEAR_BYTE;

		/* Set the TEID Base value based on the received TEID_Range*/
		upf_info->up_gtpu_base_teid = (upf_info->teid_range << SHIFT_BITS);

		/* teid will start from index 1 if teid range value is 0 and 0 otherwise
		 * e.g: if teid_range received from DP = 0000 0000 , and teidri = 3, then
		 *              base teid = 0000 0000 0000 0000 0000 0000 0000 0001
		 *      if teid_range received from DP = 0000 0101 , and teidri = 3, then
		 *              base teid = 1010 0000 0000 0000 0000 0000 0000 0000
		 *      if teid_range received from DP = 0000 0011 , and teidri = 2, then
		 *              base teid = 1100 0000 0000 0000 0000 0000 0000 0000
		 */
		if (upf_info->teid_range == 0) {
			upf_info->up_gtpu_base_teid++;
		}
	}
	return 0;
}

/* TODO: Make it generic common api across the all CP modes */
uint32_t
get_s1u_sgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **head){
	uint32_t s1u_sgw_gtpu_teid = 0;
	teid_info *upf_info = NULL;

	upf_info = get_teid_info(head, upf_ip);
	if(upf_info == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Failed to find upf information\n, IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT,
			LOG_VALUE, ip_type_str(upf_ip.ip_type),
			upf_ip.ipv4_addr,
			PRINT_IPV6_ADDR(upf_ip.ipv6_addr));		
		return 0;
	}

	if ((cp_type == CP_TYPE_SGWC) || (cp_type == CP_TYPE_SAEGWC)) {
		upf_info->up_gtpu_teid = upf_info->up_gtpu_base_teid + upf_info->up_gtpu_teid_offset;
		if (upf_info->up_gtpu_teid_offset >= upf_info->up_gtpu_max_teid_offset) {
			upf_info->up_gtpu_teid_offset = 0;
		} else {
			++upf_info->up_gtpu_teid_offset;
		}
	}

	s1u_sgw_gtpu_teid = (upf_info->up_gtpu_teid & CLEAR_BYTE)
		| ((upf_info->teid_range) << SHIFT_BITS);

	return s1u_sgw_gtpu_teid;
}

uint32_t
get_s5s8_sgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **head){
	/* Note: s5s8_sgw_gtpu_teid based s11_sgw_gtpc_teid
	 * Computation same as s1u_sgw_gtpu_teid
	 */
	uint32_t s5s8_sgw_gtpu_teid = 0;
	teid_info *upf_info = NULL;

	upf_info = get_teid_info(head, upf_ip);
	if(upf_info == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Failed to find upf information\n, IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT,
			LOG_VALUE, ip_type_str(upf_ip.ip_type),
			upf_ip.ipv4_addr,
			PRINT_IPV6_ADDR(upf_ip.ipv6_addr));	
		return 0;
	}


	if ((cp_type == CP_TYPE_SGWC) || (cp_type == CP_TYPE_SAEGWC)) {
		upf_info->up_gtpu_teid = upf_info->up_gtpu_base_teid + upf_info->up_gtpu_teid_offset;
		if (upf_info->up_gtpu_teid_offset >= upf_info->up_gtpu_max_teid_offset) {
			upf_info->up_gtpu_teid_offset = 0;
		} else {
			++upf_info->up_gtpu_teid_offset;
		}
	}

	s5s8_sgw_gtpu_teid = (upf_info->up_gtpu_teid & CLEAR_BYTE)
	    | ((upf_info->teid_range) << SHIFT_BITS);

	return s5s8_sgw_gtpu_teid;

}

uint32_t
get_s5s8_pgw_gtpu_teid(node_address_t upf_ip, int cp_type, teid_info **head){
	uint32_t s5s8_pgw_gtpu_teid = 0;
	teid_info *upf_info = NULL;

	upf_info = get_teid_info(head, upf_ip);
	if(upf_info == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Failed to find upf information\n, IP Type : %s | IPV4_ADDR : %u | IPV6_ADDR : "IPv6_FMT,
			LOG_VALUE, ip_type_str(upf_ip.ip_type),
			upf_ip.ipv4_addr,
			PRINT_IPV6_ADDR(upf_ip.ipv6_addr));	
		return 0;
	}

	if (cp_type == CP_TYPE_PGWC){
		upf_info->up_gtpu_teid = upf_info->up_gtpu_base_teid + upf_info->up_gtpu_teid_offset;
		if (upf_info->up_gtpu_teid_offset >= upf_info->up_gtpu_max_teid_offset) {
			upf_info->up_gtpu_teid_offset = 0;
		} else {
			++upf_info->up_gtpu_teid_offset;
		}
	}
	s5s8_pgw_gtpu_teid = (upf_info->up_gtpu_teid & CLEAR_BYTE)
		| ((upf_info->teid_range) << SHIFT_BITS);

	return s5s8_pgw_gtpu_teid;
}

uint32_t
get_s5s8_sgw_gtpc_teid(void){
	uint32_t s5s8_sgw_gtpc_teid = 0;

	s5s8_sgw_gtpc_teid = s5s8_sgw_gtpc_base_teid +
							s5s8_sgw_gtpc_teid_offset;
	++s5s8_sgw_gtpc_teid_offset;

	return s5s8_sgw_gtpc_teid;
}

uint32_t
get_s5s8_pgw_gtpc_teid(void){
	uint32_t s5s8_pgw_gtpc_teid = 0;

	s5s8_pgw_gtpc_teid = s5s8_pgw_gtpc_base_teid
		+ s5s8_pgw_gtpc_teid_offset;
	++s5s8_pgw_gtpc_teid_offset;

	return s5s8_pgw_gtpc_teid;
}

uint32_t
get_s11_sgw_gtpc_teid(uint8_t *check_if_ue_hash_exist, int cp_type,
									uint32_t old_s11_sgw_gtpc_teid) {
	uint32_t s11_sgw_gtpc_teid = old_s11_sgw_gtpc_teid;

	if (*check_if_ue_hash_exist == 0){
		if ((cp_type == CP_TYPE_SGWC) || (cp_type == CP_TYPE_SAEGWC)) {
			s11_sgw_gtpc_teid = s11_sgw_gtpc_base_teid
				+ s11_sgw_gtpc_teid_offset;
			++s11_sgw_gtpc_teid_offset;

		} else if (cp_type == CP_TYPE_PGWC){
			s11_sgw_gtpc_teid = get_s5s8_pgw_gtpc_teid();
		}
	}

	return s11_sgw_gtpc_teid;
}
