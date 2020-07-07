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

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
 #include <arpa/inet.h>

#include "teid_upf.h"
#include "clogger.h"

#define RI_MAX 8
static int MAX_TEID[RI_MAX] = {0,2,4,8,16,32,64,128};

#define BUF_READ_SIZE 256
#define FIRST_LINE 1

/* variable will be used to check if dp already have active session with any cp
 * or not, if teidri is 0 and if any cp tried to setup association with dp
 */
bool assoc_available = true;

/**
 * ipv4 address format.
 */
#define IPV4_ADDR "%u.%u.%u.%u"
#define IPV4_ADDR_HOST_FORMAT(a)	(uint8_t)(((a) & 0xff000000) >> 24), \
				(uint8_t)(((a) & 0x00ff0000) >> 16), \
				(uint8_t)(((a) & 0x0000ff00) >> 8), \
				(uint8_t)((a) & 0x000000ff)

/* TEIDRI data info file fd */
FILE *teidri_fd = NULL;

int8_t
assign_teid_range(uint8_t val, teidri_info **free_list_head)
{
	uint8_t teid_range = 0;
	teidri_info *temp = NULL;
	if(val == 0){
		return 0;
	}else if (val > RI_MAX){
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Teid value is not between 0 to 7\n", LOG_VALUE);
		return -1;
	}

	temp = *free_list_head;
	/* Assigning first teid range from list */
	if(temp != NULL){
		teid_range = temp->teid_range;
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" Assigned teid range: %d\n", LOG_VALUE, teid_range);
		return teid_range;
	}else{
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT" TEID range is not available. \n", LOG_VALUE);
		return -1;
	}
}

int
search_list_for_teid_range(teidri_info **head, uint8_t teid_range)
{
	teidri_info *temp = NULL;
	if(*head != NULL){
		temp = *head;
		while(temp != NULL){
			if(temp->teid_range == teid_range){
				return 0;
			}
			temp = temp->next;
		}
	}
	return -1;
}

void
create_teid_range_free_list(teidri_info **blocked_list_head,
		teidri_info **free_list_head, uint8_t teidri_val, uint8_t num_cp)
{
	int ret = 0;
	uint8_t blocked_list_len = num_cp;
	uint8_t temp_teid_range;
	for(temp_teid_range = 0; temp_teid_range < MAX_TEID[teidri_val] ; temp_teid_range++){
		if((blocked_list_len != 0) && (*blocked_list_head != NULL)){
			/*Search in teid range is in blocked list*/
			ret = search_list_for_teid_range(blocked_list_head, temp_teid_range);
			if(ret == 0){
				/*If teid range is in blocked list dont add it to free list and continue*/
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Teid range %d found in blocked list\n",
						LOG_VALUE, temp_teid_range);
				blocked_list_len--;
				continue;
			}
		}
		/*teid range is not in blocked list, add it to free list*/
		teidri_info *upf_info = malloc(sizeof(teidri_info));
		if(upf_info == NULL){
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to add node for teid range %d in free list\n",
					LOG_VALUE, temp_teid_range);
			return;
		}
		upf_info->ip = 0;
		upf_info->teid_range = temp_teid_range;
		upf_info->next = NULL;

		ret = add_teidri_info(free_list_head, upf_info);
		if(ret != 0){
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to add for node teid range %d in free list\n",
					LOG_VALUE, temp_teid_range);
			return;
		}
	}
}

teidri_info *
get_teidri_info(teidri_info **head, uint32_t ip)
{
	teidri_info *temp = NULL;
	if(*head != NULL){
		temp = *head;
		while(temp != NULL){
			if(temp->ip == ip){
				return temp;
			}
			temp = temp->next;
		}
	}
	return NULL;
}

int8_t
add_teidri_info(teidri_info **head, teidri_info *newNode)
{
	if (*head == NULL) {
		*head = newNode;
	}else{
		teidri_info *temp = *head;
		while(temp->next != NULL){
			temp = temp->next;
		}
		temp->next = newNode;
	}
	return 0;
}

void
delete_entry_from_list_for_teid_range(teidri_info **head, uint8_t teid_range)
{
	teidri_info *temp = NULL;
	teidri_info *prev = NULL;

	if(*head == NULL){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"Failed to remove teidri information from free list for teid range : %d, List is empty\n",
				LOG_VALUE, teid_range);
		return;
	}
	temp = *head;
	/* If node to be deleted is first node */
	if(temp->teid_range == teid_range){
		*head = temp->next;
		free(temp);
		return;
	}

	/* If node to be deleted is not first node */
	prev = *head;
	while(temp != NULL){
		if(temp->teid_range == teid_range){
			prev->next = temp->next;
			free(temp);
			return;
		}
		prev = temp;
		temp = temp->next;
	}
}

void
delete_entry_from_teidri_list_for_ip(uint32_t ip, teidri_info **head)
{
	teidri_info *temp = NULL;
	teidri_info *prev = NULL;

	if(head == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to remove teidri information for cp : %u, List is empty\n",
				LOG_VALUE, ip);
		return;
	}
	temp = *head;
	/* If node to be deleted is first node */
	if(temp->ip == ip){
		*head = temp->next;
		free(temp);
		return;
	}

	/* If node to be deleted is not first node */
	prev = *head;
	while(temp != NULL){
		if(temp->ip == ip){
			prev->next = temp->next;
			free(temp);
			return;
		}
		prev = temp;
		temp = temp->next;
	}
}

/* read assinged teid range indication and CP node address */
int
read_teidri_data (char *filename, teidri_info **blocked_list_head,
		teidri_info **free_list_head, uint8_t teidri_val)
{
	char str_buf[BUF_READ_SIZE] = {0};
	char *token = NULL;
	int ret = 0;
	uint8_t num_cp = 0;

	/* Open file for read data if Created , if file not create then create file for store data */
	if ((teidri_fd = fopen(filename, "r")) == NULL) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Creating New file  %s : "
			"ERROR : %s\n",LOG_VALUE, filename, strerror(errno));
		/* Assume file is not created */
		if ((teidri_fd = fopen(filename, "w")) == NULL) {
			RTE_LOG(NOTICE, DP,  LOG_FORMAT"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
		/* Write into file TEIDRI value\n */
		if (fprintf(teidri_fd, "TEIDRI , %u ,\n", teidri_val) < 0) {
			RTE_LOG(NOTICE, DP,  LOG_FORMAT"Failed to write into "
					"file, Error : %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
		fclose(teidri_fd);

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Adding nodes in free list\n", LOG_VALUE);
		create_teid_range_free_list(blocked_list_head, free_list_head,
				teidri_val, num_cp);
		return 0;
	}

	RTE_LOG(NOTICE, DP, LOG_FORMAT"File Open for Reading TEIDRI Data :: START : \n", LOG_VALUE);

	bool old_teidri_found = false;
	uint8_t old_teidri = 0;
	uint8_t line_num = 0;
	while ((fgets(str_buf, BUF_READ_SIZE, teidri_fd)) != NULL ) {
		/* Read CP Node address */
		/* Format : node addr , TEIDRI ,\n*/
		token = strtok(str_buf, ",");
		if (token != NULL) {
			line_num++;
			if(line_num == FIRST_LINE){
				if(strncmp(token,TEID_NAME,strnlen(TEID_NAME, TEID_LEN)) == 0){
					token = strtok(NULL, ",");
					if (token != NULL) {
						old_teidri = atoi(token);
						if(old_teidri != teidri_val){
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" New TEIDRI value (%u) dose not match with previous "
									"TEIDRI value (%u). Cleaning records for old TEIDRI data",
									teidri_val, old_teidri, LOG_VALUE);
						}else{
							clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" New TEIDRI value (%u) is same as previous TEIDRI value (%u)\n",
									teidri_val, old_teidri, LOG_VALUE);
							old_teidri_found = true;
						}
					}else{
						/*If TEIDRI value is not present in file*/
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Previous TEIDRI value not found in file "
								"Cleaning records from file", LOG_VALUE);
					}
				}

				if(old_teidri_found == false){
					/*Close file opened in read mode*/
					if (fclose(teidri_fd) != 0) {
						RTE_LOG(NOTICE, DP, LOG_FORMAT"ERROR : %s\n",  LOG_VALUE, strerror(errno));
						return -1;
					}
					/*Open file to write*/
					if ((teidri_fd = fopen(filename, "w")) == NULL) {
						RTE_LOG(NOTICE, DP,  LOG_FORMAT"Error: %s \n", LOG_VALUE, strerror(errno));
						return -1;
					}
					/* Write into file TEIDRI value\n */
					if (fprintf(teidri_fd, "TEIDRI , %u ,\n", teidri_val) < 0) {
						RTE_LOG(NOTICE, DP,  LOG_FORMAT"Failed to write into "
								"file, Error : %s \n", LOG_VALUE, strerror(errno));
						return -1;
					}
					if (fclose(teidri_fd) != 0) {
						RTE_LOG(NOTICE, DP, LOG_FORMAT"ERROR : %s\n",  LOG_VALUE, strerror(errno));
						return -1;
					}
					create_teid_range_free_list(blocked_list_head, free_list_head, teidri_val, num_cp);
					return 0;
				}
			}
			if(line_num > FIRST_LINE){
				teidri_info *upf_info = NULL;
				upf_info = (teidri_info *)malloc(sizeof(teidri_info));
				if(upf_info == NULL){
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Failed to add node for cp ip : %u\n",
							LOG_VALUE, atoi(token));
					return -1;
				}
				upf_info->ip = atoi(token);
				upf_info->next = NULL;

				token = strtok(NULL, ",");
				if (token != NULL) {
					upf_info->teid_range = atoi(token);
					ret = add_teidri_info(blocked_list_head, upf_info);
					if(ret != 0){
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Failed to add node for cp ip : %u\n",
								LOG_VALUE, upf_info->ip);
						return -1;
					}
				} else {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"WARNING: TEIDRI value not found for record, skip this record\n",
							LOG_VALUE);
					free(upf_info);
					upf_info = NULL;
					continue;
				}
			}
		} else {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"WARNING: Data not found in record, check next record \n",
					LOG_VALUE);
			continue;
		}
		num_cp++;
	}

	RTE_LOG(NOTICE, DP, LOG_FORMAT"Number of CP : %d  \n",  LOG_VALUE, num_cp);

	if (fclose(teidri_fd) != 0) {
		RTE_LOG(NOTICE, DP, LOG_FORMAT"ERROR : %s\n",  LOG_VALUE, strerror(errno));
		return -1;
	}

	/* Adding nodes in free list */
	create_teid_range_free_list(blocked_list_head, free_list_head, teidri_val, num_cp);

	RTE_LOG(NOTICE, DP, LOG_FORMAT "File Close :: END :  \n", LOG_VALUE);
	return 0;
}

int
get_teidri_from_list(uint8_t *teid_range, uint32_t node_addr, teidri_info **head)
{
	teidri_info *upf_info = NULL;
	upf_info = get_teidri_info(head, node_addr);
	if(upf_info != NULL){
		*teid_range = upf_info->teid_range;
		return 1;
	}
	/* Node address not found into stored data */
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"NODE Address not found  \n", LOG_VALUE);
	return 0;
}

/* Function to write teid range and node address into file in csv format */
/* TODO : add one more paramete for file name in both read and write teidri data function */
int
add_teidri_node_entry(uint8_t teid_range, uint32_t node_addr, char *filename,
		teidri_info **add_list_head, teidri_info **remove_list_head)
{
	teidri_info *upf_info = NULL;
	int ret = 0;

	if (node_addr == 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"NODE Address is : %u  \n", LOG_VALUE,
				node_addr);
		return -1;
	}

	upf_info = get_teidri_info(add_list_head, node_addr);
	if(upf_info == NULL){
		upf_info = malloc(sizeof(teidri_info));
		if(upf_info == NULL){
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to add node for ip : %u\n",
					LOG_VALUE, node_addr);
			return -1;
		}
		/* copy into data structure */
		upf_info->ip = node_addr;
		upf_info->teid_range = teid_range;
		upf_info->next = NULL;

		ret = add_teidri_info(add_list_head, upf_info);
		if(ret != 0){
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to add node for cp ip : %u\n",
					LOG_VALUE, node_addr);
			return -1;
		}

		/* Remove node from list*/
		delete_entry_from_list_for_teid_range(remove_list_head, teid_range);
	}

	if(filename != NULL){
		/* Open file for write data in append mode */
		if ((teidri_fd = fopen(filename, "a")) == NULL) {
			RTE_LOG(NOTICE, DP, LOG_FORMAT"Failed to open file, "
				"Error : %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"File open : %s  successfully \n", LOG_VALUE, filename);

		/* Set fd at end of the file  */
		fseek(teidri_fd, 0L,SEEK_END);

		/* Write into file in cvs format FORMAT :
		 * node_addr in decimal, teid_range , node_address in ipv4 format\n
		 */
		if (fprintf(teidri_fd, "%u , %u , "IPV4_ADDR", \n", node_addr, teid_range,
					IPV4_ADDR_HOST_FORMAT(ntohl(node_addr))) < 0) {
			RTE_LOG(NOTICE, DP,  LOG_FORMAT"Failed to write into "
				"file, Error : %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"node addr : %u : teid range : %d \n", LOG_VALUE,
				upf_info->ip, upf_info->teid_range);

		if (fclose(teidri_fd) != 0) {
			RTE_LOG(NOTICE, DP, LOG_FORMAT"Failed to close file, "
				"Error: %s\n",  LOG_VALUE , strerror(errno));
			return -1;
		}

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"File close : %s successfully \n", LOG_VALUE, filename);
	}

	return 0;

}

/* Funtion to to delete all containt of file */
int
flush_inactive_teidri_data(char *filename, teidri_info **blocked_list_head, teidri_info **allocated_list_head,
		teidri_info **free_list_head, uint8_t teidri_val){

	teidri_info *temp = NULL;

	if(*blocked_list_head == NULL){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"No Inactive teidri records found \n",
				LOG_VALUE);
	}else{
		/* Remove data of inactive peers from blocked list,
		 * and add it to free list
		 */
		/* Traverse till end of free list*/
		temp = *free_list_head;
		if(temp != NULL){
			while(temp->next != NULL){
				temp = temp->next;
			}
			/* Append blocked list to free list*/
			temp->next = *blocked_list_head;
		}else{
			temp = *blocked_list_head;
		}

		/* Remove all contents from blocked list*/
		*blocked_list_head = NULL;
	}

	/* Add data for active peers in file */
	if ((teidri_fd = fopen(filename, "w")) == NULL ) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to open file [%s], Error : %s \n",
				LOG_VALUE, filename, strerror(errno));
		return -1;
	}

	/* Write into file TEIDRI value\n */
	if (fprintf(teidri_fd, "TEIDRI , %u ,\n", teidri_val) < 0) {
		RTE_LOG(NOTICE, DP,  LOG_FORMAT"Failed to write into "
				"file, Error : %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	temp = *allocated_list_head;
	while(temp != NULL){
		/* Write into file in cvs format FORMAT :
		 * node_addr in decimal, teid_range , node_address in ipv4 format\n
		 */
		if (fprintf(teidri_fd, "%u , %u , "IPV4_ADDR"\n", temp->ip, temp->teid_range,
		                     IPV4_ADDR_HOST_FORMAT(ntohl(temp->ip))) < 0) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to write into file for IP %d and "
				"teid_range %u , Error : %s \n", LOG_VALUE, temp->ip,
				temp->teid_range, strerror(errno));
			//return -1;
		}
		temp = temp->next;
	}

	if (fclose(teidri_fd) != 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to close file, Error : %s\n",  LOG_VALUE, strerror(errno));
		return -1;
	}

	return 0;
}

/* Function to delete teidri node addr entry from file */
int
delete_teidri_node_entry(char *filename, uint32_t node_addr, teidri_info **head, teidri_info **free_list_head,
		uint8_t teidri_val){

	teidri_info *upf_info = NULL;
	teidri_info *temp = NULL;
	int ret = 0;

	if (node_addr == 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"NODE Address: %u  \n", LOG_VALUE, node_addr);
		return -1;
	}

	temp = get_teidri_info(head, node_addr);
	if(temp == NULL){
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to find to be deleted for IP: %u\n", LOG_VALUE, node_addr);
		return -1;
	}
	upf_info = malloc(sizeof(teidri_info));
	if(upf_info == NULL){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to add node for IP: %u\n",
				LOG_VALUE, node_addr);
		return -1;
	}
	upf_info->ip = node_addr;
	upf_info->teid_range = temp->teid_range;
	upf_info->next = NULL;

	ret = add_teidri_info(free_list_head, upf_info);
	if(ret != 0){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to add node for CP IP: %u\n",
				LOG_VALUE, node_addr);
		return -1;
	}

	/* Delete node entry from allocated list */
	delete_entry_from_teidri_list_for_ip(node_addr, head);

	if ((teidri_fd = fopen(filename, "w")) == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Failed to open file, Error : %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	/* Write into file TEIDRI value\n */
	if (fprintf(teidri_fd, "TEIDRI , %u ,\n", teidri_val) < 0) {
		RTE_LOG(NOTICE, DP,  LOG_FORMAT"Failed to write into "
				"file, Error : %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	temp = *head;
	while (temp != NULL) {
		/* Write into file in cvs format FORMAT :
		 * node_addr in decimal, teid_range , node_address in ipv4 format\n
		 */
		if (fprintf(teidri_fd, "%u , %u , "IPV4_ADDR"\n", temp->ip, temp->teid_range,
		                     IPV4_ADDR_HOST_FORMAT(ntohl(temp->ip))) < 0) {
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to write into file for ip %u and teid_range %d, "
				"Error : %s \n", LOG_VALUE, temp->ip, temp->teid_range,
				strerror(errno));
		}
		temp = temp->next;
	}

	if (fclose(teidri_fd) != 0) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Failed to close file, Error : %s\n",  LOG_VALUE, strerror(errno));
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Node entry removed from "
		"list for node addr : %u \n", LOG_VALUE, node_addr);
	return 0;
}
