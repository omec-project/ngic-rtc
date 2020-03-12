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
#ifndef SEID_LLIST_H
#define SEID_LLIST_H

#if CP_BUILD
#include "csid_struct.h"
#include "cp.h"
#else

#include "up_main.h"
#endif
#include "clogger.h"

/**
 * @brief  : Function to add a node in sess_csid Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns
 *           head  in case of success
 *           NULL otherwise
 */
sess_csid *
add_sess_csid_data_node(sess_csid *head);

/**
 * @brief  : Function to add a node in sess_csid Linked List.
 * @param  : head, linked list head pointer
 * @param  : new_node, node to be added
 * @retrun : Returns
 *           0 in case of success
 *           -1 otherwise
 */
int8_t
insert_sess_csid_data_node(sess_csid *head, sess_csid *new_node);



/**
 * @brief  : Function to get a node in sess_csid Linked List.
 * @param  : head, linked list head pointer
 * @param  : seid, seid to find node
 * @retrun : Returns
 *           head  in case of success
 *           NULL otherwise
 */

sess_csid *
get_sess_csid_data_node(sess_csid *head, uint64_t seid);

/**
 * @brief  : Function to remove a node in sess_csid Linked List.
 * @param  : head, linked list head pointer
 * @param  : seid, side to find node and remove
 * @retrun : Returns
 *           head case of success
 *           NULL  otherwise
 */
sess_csid *
remove_sess_csid_data_node(sess_csid *head, uint64_t seid);

/**
 * @brief  : Function to flush  sess_csid Linked List.
 * @param  : head, linked list head pointer
 * @retrun : Returns
 *           0 in case of success
 *           -1 otherwise
 */
int8_t
flush_sess_csid_data_list(sess_csid *head);


#endif /* SEID_LLIST_H */
