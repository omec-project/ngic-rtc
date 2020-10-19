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

#ifndef TEID_UPF_H
#define TEID_UPF_H

/**
 * @file
 *
 * Contains all data structures and functions to manage and/or
 * obtain value for teid assignement.
 *
 */

#include <stdint.h>

/* File name of TEIDRI and peer node address */
#define TEIDRI_FILENAME     "../config/upf_teid_range_data.csv"

/* dataplane rte logs */
#define RTE_LOGTYPE_DP  RTE_LOGTYPE_USER1

#define TEID_NAME  "TEIDRI"
#define TEID_LEN   10
/**
 * @brief : Collection of assinged TEID range and connected CP node address
 */
typedef struct teidri_info_t {
	/* IP address of conneted CP */
	uint32_t ip;
	/* TEID range assinged to CP */
	uint8_t teid_range;

	struct teidri_info_t  *next;

}teidri_info;

/**
 * @brief  : read assinged teid range and CP node address and adds thid data to
 *           teidri blocked list, initializes free teid range list.
 * @param  : filename
 *           filepath to store teid related information
 * @param  : blocked_list_head
 *           teidri_info linked list head of blocked teid ranges
 * @param  : free_list_head
 *           teidri_info linked list head free teid ranges
 * @param  : teidri_val
 *           configured teid range indicator value
 * @return : Returns 0 on success -1 otherwise
 */
int
read_teidri_data (char *filename, teidri_info **blocked_list_head, teidri_info **free_list_head, uint8_t teidri_va);

/**
 * @brief  : search and get node TEIDRI value if available in stored data.
 * @param  : teid_range, TEIDRI value.
 * @param  : node_addr, node address of CP .
 * @param  : head
 *           teidri_info linked list head
 * @return : Returns
 *           1 - on success , node address and teidri found.
 *           0 - node address not found.
 */
int
get_teidri_from_list(uint8_t *teid_range, uint32_t node_addr, teidri_info **head);

/**
 * @brief  : Write TEIDRI value and node address into file in csv format.
 * @param  : teid_range, TEIDRI value.
 * @param  : node_addr, node address of CP .
 * @param  : allocated_list_head
 *           teidri_info allocated linked list head
 * @param  : free_list_head
 *           teidri_info free linked list head
 * @return : Returns  0  on success , -1 otherwise
 */
int
add_teidri_node_entry(uint8_t teid_range, uint32_t node_addr, char *filename, teidri_info **allocated_list_head,
		teidri_info **free_list_head);

/**
 * @brief  : delete all containt from file.
 * @param  : filename, file name,
 * @param  : allocated_list_head
 *           teidri_info allocated linked list head
 * @param  : free_list_head
 *           teidri_info free linked list head
 * @param  : free_list_head
 *           teidri_info free linked list head
 * @param  : teidri_val
 *           configured teid range indicator value
 * @return : Returns  0  on success , -1 otherwise
 */
int
flush_inactive_teidri_data(char *filename, teidri_info **blocked_list_head, teidri_info **allocated_list_head,
		teidri_info **free_list_head, uint8_t teidri_val);

/**
 * @brief  : Delete  TEIDRI value and node address from file.
 * @param  : filename, file name.
 * @param  : node_addr, node address of CP .
 * @param  : head
 *           pointer to teidri_info list
 * @param  : free_list_head
 *           teidri_info free linked list head
 * @param  : teidri_val
 *           configured teid range indicator value
 * @return : Returns
 *           0 - on success.
 *           -1 - on fail.
 */
int
delete_teidri_node_entry(char *filename, uint32_t node_addr, teidri_info **head, teidri_info **free_list_head,
		uint8_t teidri_val);

/**
 * @brief  : Assign teid range from next available teid ranges
 * @param  : val , teidri value , must be between 0 to 7
 * @param  : free_list_head
 *           linked list head of free teid ranges
 * @return : Returns teid range in case of success, -1 otherwise
 */
int8_t
assign_teid_range(uint8_t val, teidri_info **free_list_head);

/**
 * @brief  : Retrives node from list for given ip
 * @param  : head
 *           teidri_info linked list head
 * @param  : ip
 *           ip address of CP
 * @return : Returns pointer to node in case of success, NULL otherwise
 */
teidri_info *
get_teidri_info(teidri_info **head, uint32_t ip);

/**
 * @brief  : Adds new node to the list
 * @param  : head
 *           teidri_info linked list head
 * @param  : newNode
 *           new node to be addded in list
 * @return : Returns 0 in case of success, -1 otherwise
 */
int8_t
add_teidri_info(teidri_info **head, teidri_info *newNode);

/**
 * @brief  : Deletes node from list for given ip
 * @param  : ip
 *           ip address of DP
 * @param  : head
 *           pointer to teidri_info list
 * @return : Returns nothing
 */
void
delete_entry_from_teidri_list_for_ip(uint32_t ip, teidri_info **head);

/**
 * @brief  : Deletes node from list for given ip
 * @param  : head
 *           pointer to teidri_info list
 * @param  : teid_range
 *           teid range for which entry to be deleted
 * @return : Returns nothing
 */
void
delete_entry_from_list_for_teid_range(teidri_info **head, uint8_t teid_range);

/**
 * @brief  : Searches for given teid range value in given list
 * @param  : head
 *           teidri_info linked list head
 * @param  : teidri_range
 *           teid range value to be searched
 * @return : Returns 0 on success -1 otherwise
 */
int
search_list_for_teid_range(teidri_info **head, uint8_t teid_range);

/**
 * @brief  : Create list of free teid ranges
 * @param  : blocked_list_head
 *           teidri_info linked list head of blocked teid ranges
 * @param  : free_list_head
 *           teidri_info linked list head free teid ranges
 * @param  : teidri_val
 *           configured teid range indicator value
 * @param  : num_cp
 *           number of cp's in blocked list
 * @return : Returns nothing
 */
void
create_teid_range_free_list(teidri_info **blocked_list_head, teidri_info **free_list_head, uint8_t teidri_val, uint8_t num_cp);

#endif /* TEID_UPF_H */
