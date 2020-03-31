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

/** Function to add a node in PDR Linked List. */
int8_t
insert_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *sess_data);

/** Function to get a node from session data Linked List. */
pfcp_session_datat_t *
get_sess_data_node(pfcp_session_datat_t *head, pfcp_session_datat_t *sess_data);

/* Function to get the next node from session data Linked List. */
pfcp_session_datat_t *
get_sess_data_next_node(pfcp_session_datat_t *head);

/** Function to remove the last node from the session data Linked List. */
pfcp_session_datat_t *remove_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *node);

/** Function to delete a node from the session data Linked List. */
int8_t flush_sess_data_list(pfcp_session_datat_t *head);

/** Function to add a node in PDR Linked List. */
int8_t insert_pdr_node(pdr_info_t *head, pdr_info_t  *pdr);

/** Function to get a node from PDR Linked List. */
pdr_info_t *get_pdr_node(pdr_info_t *head, uint32_t precedence);

/* Function to get the node from PDR Linked List. */
pdr_info_t *
get_pdr_next_node(pdr_info_t *head);

/** Function to remove the node from the PDR Linked List. */
pdr_info_t *remove_pdr_node(pdr_info_t *head, pdr_info_t *node);

/** Function to delete a node from the PDR Linked List. */
int8_t flush_pdr_list(pdr_info_t *head);

/** Function to add a node in QER Linked List. */
int8_t insert_qer_node(qer_info_t *head, qer_info_t *qer);

/** Function to get a node from QER Linked List. */
qer_info_t *get_qer_node(qer_info_t *head, qer_info_t *qer);

/* Function to get the node from QER Linked List. */
qer_info_t *
get_qer_next_node(qer_info_t *head);

/** Function to remove the node from the QER Linked List. */
qer_info_t *remove_qer_node(qer_info_t *head, qer_info_t *node);

/** Function to delete a node from the QER Linked List. */
int8_t flush_qer_list(qer_info_t *head);

/** Function to add a node in URR Linked List. */
int8_t insert_urr_node(urr_info_t *head, urr_info_t *urr);

/** Function to get a node from URR Linked List. */
urr_info_t *get_urr_node(urr_info_t *head, urr_info_t *urr);

/* Function to get the node from URR Linked List. */
urr_info_t *
get_urr_next_node(urr_info_t *head);

/** Function to remove the node from the URR Linked List. */
urr_info_t *remove_urr_node(urr_info_t *head, urr_info_t *node);

/** Function to delete a node from the URR Linked List. */
int8_t flush_urr_list(urr_info_t *head);

/** Function to add a node in Predefined rules Linked List. */
int8_t insert_predef_rule_node(predef_rules_t *head, predef_rules_t *rules);

#endif /* PFCP_UP_LLIST_H */
