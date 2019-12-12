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

#ifndef PFCP_UP_LLIST_H
#define PFCP_UP_LLIST_H

#include "up_main.h"
#include "pfcp_messages.h"
#include "pfcp_up_struct.h"

/**
 * @brief  : Function to add a node in PDR Linked List.
 * @param  : head, linked list head pointer
 * @param  : sess_data, node to be added
 * @retrun : Returns linked list head pointer
 */
int8_t
insert_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *sess_data);

/**
 * @brief  : Function to get a node from session data Linked List.
 * @param  : head, linked list head pointer
 * @param  : sess_data, node to be added
 * @retrun : Returns linked list head pointer
 */
pfcp_session_datat_t *
get_sess_data_node(pfcp_session_datat_t *head, pfcp_session_datat_t *sess_data);

/**
 * @brief  : Function to get the next node from session data Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns linked list head pointer
 */
pfcp_session_datat_t *
get_sess_data_next_node(pfcp_session_datat_t *head);

/**
 * @brief  : Function to remove the last node from the session data Linked List.
 * @param  : head, linked list head pointer
 * @param  : node, node to be deleted
 * @retrun : Returns linked list head pointer
 */
pfcp_session_datat_t *remove_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *node);

/**
 * @brief  : Function to delete a node from the session data Linked List.
 * @param  : head, linked list head pointer
 * @return : Returns 0 in case of success , -1 otherwise.
 */
int8_t flush_sess_data_list(pfcp_session_datat_t *head);

/**
 * @brief  : Function to add a node in PDR Linked List.
 * @param  : head, linked list head pointer
 * @param  : pdr, pdr information
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t insert_pdr_node(pdr_info_t *head, pdr_info_t  *pdr);

/**
 * @brief  : Function to get a node from PDR Linked List.
 * @param  : head, linked list head pointer
 * @param  : precedence, precedence value
 * @retrun : Returns linked list head pointer
 */
pdr_info_t *get_pdr_node(pdr_info_t *head, uint32_t precedence);

/**
 * @brief  : Function to get the node from PDR Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns linked list head pointer
 */
pdr_info_t *
get_pdr_next_node(pdr_info_t *head);

/**
 * @brief  : Function to remove the node from the PDR Linked List.
 * @param  : head, linked list head pointer
 * @param  : node, node to be removed
 * @retrun : Returns linked list head pointer
 */
pdr_info_t *remove_pdr_node(pdr_info_t *head, pdr_info_t *node);

/**
 * @brief  : Function to delete a node from the PDR Linked List.
 * @param  : head, linked list head pointer
 * @return : Returns 0 in case of success , -1 otherwise.
 */
int8_t flush_pdr_list(pdr_info_t *head);

/**
 * @brief  : Function to add a node in QER Linked List.
 * @param  : head, linked list head pointer
 * @param  : qer, qer information
 * @return : Returns 0 in case of success , -1 otherwise.
 */
int8_t insert_qer_node(qer_info_t *head, qer_info_t *qer);

/**
 * @brief  : Function to get a node from QER Linked List.
 * @param  : head, linked list head pointer
 * @param  : qer, qer information
 * @retrun : Returns linked list head pointer
 */
qer_info_t *get_qer_node(qer_info_t *head, qer_info_t *qer);

/**
 * @brief  : Function to get the node from QER Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns linked list head pointer
 */
qer_info_t *
get_qer_next_node(qer_info_t *head);

/**
 * @brief  : Function to remove the node from the QER Linked List.
 * @param  : head, linked list head pointer
 * @param  : node, node to be removed
 * @retrun : Returns linked list head pointer
 */
qer_info_t *remove_qer_node(qer_info_t *head, qer_info_t *node);

/**
 * @brief  : Function to delete a node from the QER Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int8_t flush_qer_list(qer_info_t *head);

/**
 * @brief  : Function to add a node in URR Linked List.
 * @param  : head, linked list head pointer
 * @param  : urr, node to be added
 * @retrun : Returns 0 in case of success , -1 otherwise
 */
int8_t insert_urr_node(urr_info_t *head, urr_info_t *urr);

/**
 * @brief  : Function to get a node from URR Linked List.
 * @param  : head, linked list head pointer
 * @param  : urr, node to be added
 * @retrun : Returns linked list head pointer
 */
urr_info_t *get_urr_node(urr_info_t *head, urr_info_t *urr);

/**
 * @brief  : Function to get the node from URR Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns linked list head pointer
 */
urr_info_t *
get_urr_next_node(urr_info_t *head);

/**
 * @brief  : Function to remove the node from the URR Linked List.
 * @param  : head, linked list head pointer
 * @param  : node, node to be removed
 * @retrun : Returns linked list head pointer
 */
urr_info_t *remove_urr_node(urr_info_t *head, urr_info_t *node);

/**
 * @brief  : Function to delete a node from the URR Linked List.
 * @param  : head, linked list head pointer
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t flush_urr_list(urr_info_t *head);

/**
 * @brief  : Function to add a node in Predefined rules Linked List.
 * @param  : head, linked list head pointer
 * @return : Returns 0 in case of success , -1 otherwise
 */
int8_t insert_predef_rule_node(predef_rules_t *head, predef_rules_t *rules);

#endif /* PFCP_UP_LLIST_H */
