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

#include "pfcp_up_llist.h"

/* Function to add a node in PDR Linked List. */
int8_t
insert_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *new_node)
{
	/* Allocate memory for new node */
	//pfcp_session_datat_t *new_node = rte_malloc_socket(NULL, sizeof(pfcp_session_datat_t),
	//		RTE_CACHE_LINE_SIZE, rte_socket_id());

	//if (new_node == NULL)
	//	return -1;

	///* Next pointing to NULL */
	//new_node = sess_data;
	new_node->next = NULL;

	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		pfcp_session_datat_t *tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

/* Function to get a node from session data Linked List. */
pfcp_session_datat_t *
get_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *sess_data)
{
	/* Pointing to head node */
	pfcp_session_datat_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Validate the expected node or not */
		/* VS: Need to put appropriate compare condition */
		if (current->ue_ip_addr == sess_data->ue_ip_addr)
			return current;

		/* Pointing to next node */
		current = current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to get the next node from session data Linked List. */
pfcp_session_datat_t *
get_sess_data_next_node(pfcp_session_datat_t *head)
{
	/* Pointing to head node */
	pfcp_session_datat_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Pointing to next node */
		return current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to remove the 1st node from the session data Linked List. */
static pfcp_session_datat_t *
remove_sess_data_first_node(pfcp_session_datat_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	/* Point to head node */
	pfcp_session_datat_t *current = head;
	/* Access the next node */
	head = head->next;
	/* Free next node address form current node*/
	current->next = NULL;

	/* Check this the last node in the linked list or not */
	if (current == head)
		head = NULL;

	/* Free the 1st node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the last node from the session data Linked List. */
static pfcp_session_datat_t *
remove_sess_data_last_node(pfcp_session_datat_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	pfcp_session_datat_t *current = head;
	pfcp_session_datat_t *last = NULL;

	/* Find the last node in the linked list */
	while(current->next != NULL) {
		last = current;
		current = current->next;
	}

	if (last != NULL)
		last->next = NULL;

	/* Check this the last node in the linked list */
	if (current == head)
		head = NULL;

	/* free the last node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the node from the session data Linked List. */
pfcp_session_datat_t *
remove_sess_data_node(pfcp_session_datat_t *head,
		pfcp_session_datat_t *node)
{
	/* Check linked list and node is not NULL */
	if ((node == NULL) || (head == NULL))
		return NULL;

	/* If the first node delete */
	if (node == head)
		return remove_sess_data_first_node(head);

	/* If the last node delete */
	if (node->next == NULL)
		return remove_sess_data_last_node(head);

	/* Middle node */
	pfcp_session_datat_t *current = head;
	while(current != NULL) {
		/* Find the node */
		if (current->next == node)
			break;

		/* Pointing to next node */
		current = current->next;
	}

	/* Remove the current node */
	if (current != NULL) {
		/* Stored next to next node address */
		pfcp_session_datat_t *tmp = current->next;
		/* point the current node next to next node */
		current->next = tmp->next;
		tmp->next = NULL;
		/* Free the next node */
		rte_free(tmp);
		tmp = NULL;
	}
	return head;
}

/* Function to delete a node from the session data Linked List. */
int8_t
flush_sess_data_list(pfcp_session_datat_t *head)
{
	pfcp_session_datat_t *current = NULL;
	pfcp_session_datat_t *tmp = NULL;

	/* Check linked list head pointer is not NULL */
	if (head != NULL) {
		/* Get the next node */
		tmp = head->next;
		head->next = NULL;

		while(tmp != NULL) {
			current = tmp->next;
			/* free the node */
			rte_free(tmp);
			tmp = current;
		}
	}

	return 0;
}


/* Function to add a node in PDR Linked List. */
int8_t
insert_pdr_node(pdr_info_t *head, pdr_info_t *new_node)
{
	/* Next pointing to NULL */
	new_node->next = NULL;

	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		 pdr_info_t *tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

/* Function to get a node from PDR Linked List. */
pdr_info_t *
get_pdr_node(pdr_info_t *head, uint32_t precedence)
{
	/* Pointing to head node */
	pdr_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Validate the expected node or not */
		if (current->prcdnc_val == precedence)
			return current;

		/* Pointing to next node */
		current = current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to get the node from PDR Linked List. */
pdr_info_t *
get_pdr_next_node(pdr_info_t *head)
{
	/* Pointing to head node */
	pdr_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Pointing to next node */
		return current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to remove the 1st node from the PDR Linked List. */
static pdr_info_t *
remove_pdr_first_node(pdr_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	/* Point to head node */
	pdr_info_t *current = head;

	/* Access the next node */
	head = head->next;

	/* Free next node address form current node*/
	current->next = NULL;

	/* Check this the last node in the linked list or not */
	if (current == head)
		head = NULL;

	/* Free the 1st node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the last node from the PDR Linked List. */
static pdr_info_t *
remove_pdr_last_node(pdr_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	pdr_info_t *current = head;
	pdr_info_t *last = NULL;

	/* Find the last node in the linked list */
	while(current->next != NULL) {
		last = current;
		current = current->next;
	}

	if (last != NULL)
		last->next = NULL;

	/* Check this the last node in the linked list */
	if (current == head)
		head = NULL;

	/* free the last node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the node from the PDR Linked List. */
pdr_info_t *
remove_pdr_node(pdr_info_t *head, pdr_info_t *node)
{
	/* Check linked list and node is not NULL */
	if ((node == NULL) || (head == NULL))
		return NULL;

	/* If the first node delete */
	if (node == head)
		return remove_pdr_first_node(head);

	/* If the last node delete */
	if (node->next == NULL)
		return remove_pdr_last_node(head);

	/* Middle node */
	pdr_info_t *current = head;
	while(current != NULL) {
		/* Find the node */
		if (current->next == node)
			break;

		/* Pointing to next node */
		current = current->next;
	}

	/* Remove the current node */
	if (current != NULL) {
		/* Stored next to next node address */
		pdr_info_t *tmp = current->next;

		/* point the current node next to next node */
		current->next = tmp->next;
		tmp->next = NULL;

		/* Free the next node */
		rte_free(tmp);
		tmp = NULL;
	}
	return head;
}

/* Function to delete a node from the PDR Linked List. */
int8_t
flush_pdr_list(pdr_info_t *head)
{
	pdr_info_t *current = NULL;
	pdr_info_t *tmp = NULL;

	/* Check linked list head pointer is not NULL */
	if (head != NULL) {
		/* Get the next node */
		tmp = head->next;
		head->next = NULL;

		while(tmp != NULL) {
			current = tmp->next;
			/* free the node */
			rte_free(tmp);
			tmp = current;
		}
	}

	return 0;
}

/* Function to add a node in QER Linked List. */
int8_t
insert_qer_node(qer_info_t *head, qer_info_t *new_node)
{
	/* Allocate memory for new node */
	//qer_info_t *new_node = rte_malloc_socket(NULL, sizeof(qer_info_t),
	//		RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Next pointing to NULL */
	//new_node = qer;
	new_node->next = NULL;

	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		 qer_info_t *tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

/* Function to get a node from QER Linked List. */
qer_info_t *
get_qer_node(qer_info_t *head, qer_info_t *qer)
{
	/* Pointing to head node */
	qer_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Validate the expected node or not */
		/* VS: Need to put appropriate compare condition */
		if (current->qer_corr_id_val == qer->qer_corr_id_val)
			return current;

		/* Pointing to next node */
		current = current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to get the node from QER Linked List. */
qer_info_t *
get_qer_next_node(qer_info_t *head)
{
	/* Pointing to head node */
	qer_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Pointing to next node */
		return current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to remove the 1st node from the QER Linked List. */
static qer_info_t *
remove_qer_first_node(qer_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	/* Point to head node */
	qer_info_t *current = head;

	/* Access the next node */
	head = head->next;

	/* Free next node address form current node*/
	current->next = NULL;

	/* Check this the last node in the linked list or not */
	if (current == head)
		head = NULL;

	/* Free the 1st node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the last node from the QER Linked List. */
static qer_info_t *
remove_qer_last_node(qer_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	qer_info_t *current = head;
	qer_info_t *last = NULL;

	/* Find the last node in the linked list */
	while(current->next != NULL) {
		last = current;
		current = current->next;
	}

	if (last != NULL)
		last->next = NULL;

	/* Check this the last node in the linked list */
	if (current == head)
		head = NULL;

	/* free the last node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the node from the QER Linked List. */
qer_info_t *
remove_qer_node(qer_info_t *head, qer_info_t *node)
{
	/* Check linked list and node is not NULL */
	if ((node == NULL) || (head == NULL))
		return NULL;

	/* If the first node delete */
	if (node == head)
		return remove_qer_first_node(head);

	/* If the last node delete */
	if (node->next == NULL)
		return remove_qer_last_node(head);

	/* Middle node */
	qer_info_t *current = head;
	while(current != NULL) {
		/* Find the node */
		if (current->next == node)
			break;

		/* Pointing to next node */
		current = current->next;
	}

	/* Remove the current node */
	if (current != NULL) {
		/* Stored next to next node address */
		qer_info_t *tmp = current->next;

		/* point the current node next to next node */
		current->next = tmp->next;
		tmp->next = NULL;

		/* Free the next node */
		rte_free(tmp);
		tmp = NULL;
	}
	return head;
}

/* Function to delete a node from the QER Linked List. */
int8_t
flush_qer_list(qer_info_t *head)
{
	qer_info_t *current = NULL;
	qer_info_t *tmp = NULL;

	/* Check linked list head pointer is not NULL */
	if (head != NULL) {
		/* Get the next node */
		tmp = head->next;
		head->next = NULL;

		while(tmp != NULL) {
			current = tmp->next;
			/* free the node */
			rte_free(tmp);
			tmp = current;
		}
	}

	return 0;
}

/* Function to add a node in URR Linked List. */
int8_t
insert_urr_node(urr_info_t *head, urr_info_t *new_node)
{
	/* Allocate memory for new node */
	//urr_info_t *new_node = rte_malloc_socket(NULL, sizeof(urr_info_t),
	//		RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Next pointing to NULL */
	//new_node = urr;
	new_node->next = NULL;

	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		urr_info_t *tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

/* Function to get a node from URR Linked List. */
urr_info_t *
get_urr_node(urr_info_t *head, urr_info_t *urr)
{
	/* Pointing to head node */
	urr_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Validate the expected node or not */
		/* VS: Need to put appropriate compare condition */
		if (current->urr_id == urr->urr_id)
			return current;

		/* Pointing to next node */
		current = current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to get the node from URR Linked List. */
urr_info_t *
get_urr_next_node(urr_info_t *head)
{
	/* Pointing to head node */
	urr_info_t *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Pointing to next node */
		return current->next;
	}
	/* Node is not present in linked list */
	return NULL;
}

/* Function to remove the 1st node from the URR Linked List. */
static urr_info_t *
remove_urr_first_node(urr_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	/* Point to head node */
	urr_info_t *current = head;

	/* Access the next node */
	head = head->next;

	/* Free next node address form current node*/
	current->next = NULL;

	/* Check this the last node in the linked list or not */
	if (current == head)
		head = NULL;

	/* Free the 1st node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the last node from the URR Linked List. */
static urr_info_t *
remove_urr_last_node(urr_info_t *head)
{
	/* Check linked list head pointer is not NULL */
	if(head == NULL)
		return NULL;

	urr_info_t *current = head;
	urr_info_t *last = NULL;

	/* Find the last node in the linked list */
	while(current->next != NULL) {
		last = current;
		current = current->next;
	}

	if (last != NULL)
		last->next = NULL;

	/* Check this the last node in the linked list */
	if (current == head)
		head = NULL;

	/* free the last node from linked list */
	rte_free(current);
	current = NULL;
	return head;
}

/* Function to remove the node from the URR Linked List. */
urr_info_t *
remove_urr_node(urr_info_t *head, urr_info_t *node)
{
	/* Check linked list and node is not NULL */
	if ((node == NULL) || (head == NULL))
		return NULL;

	/* If the first node delete */
	if (node == head)
		return remove_urr_first_node(head);

	/* If the last node delete */
	if (node->next == NULL)
		return remove_urr_last_node(head);

	/* Middle node */
	urr_info_t *current = head;
	while(current != NULL) {
		/* Find the node */
		if (current->next == node)
			break;

		/* Pointing to next node */
		current = current->next;
	}

	/* Remove the current node */
	if (current != NULL) {
		/* Stored next to next node address */
		urr_info_t *tmp = current->next;

		/* point the current node next to next node */
		current->next = tmp->next;
		tmp->next = NULL;

		/* Free the next node */
		rte_free(tmp);
		tmp = NULL;
	}
	return head;
}

/* Function to delete a node from the URR Linked List. */
int8_t
flush_urr_list(urr_info_t *head)
{
	urr_info_t *current = NULL;
	urr_info_t *tmp = NULL;

	/* Check linked list head pointer is not NULL */
	if (head != NULL) {
		/* Get the next node */
		tmp = head->next;
		head->next = NULL;

		while(tmp != NULL) {
			current = tmp->next;
			/* free the node */
			rte_free(tmp);
			tmp = current;
		}
	}

	return 0;
}

/* Function to add a node in Predefined rules Linked List. */
int8_t
insert_predef_rule_node(predef_rules_t *head, predef_rules_t *rules)
{
	/* Allocate memory for new node */
	predef_rules_t *new_node = rte_malloc_socket(NULL, sizeof(predef_rules_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());

	/* Next pointing to NULL */
	new_node = rules;
	new_node->next = NULL;

	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		predef_rules_t *tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

