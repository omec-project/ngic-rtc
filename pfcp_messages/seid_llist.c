/*Copyright (c) 2019 Sprint

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

#include "seid_llist.h"

sess_csid *
add_sess_csid_data_node(sess_csid *head) {

	sess_csid *new_node =NULL;

	/* Check linked list is empty or not */
	if(head == NULL )
		return NULL;

	/* Allocate memory for new node */
	new_node = rte_malloc_socket(NULL, sizeof(sess_csid),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(new_node == NULL ) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Failed to allocate memory for session data info\n", ERR_MSG);
		return NULL;
	}

	/* Add new node into linked list */
	if(insert_sess_csid_data_node(head, new_node) < 0){
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to add node entry in LL\n",
				ERR_MSG);
		return NULL;
	}

	return new_node;
}

/* Function  to add sess_csid node */
int8_t
insert_sess_csid_data_node(sess_csid *head, sess_csid *new_node)
{

	sess_csid *tmp =  NULL;

	if(new_node == NULL)
		return -1;

	new_node->next = NULL;
	/* Check linked list is empty or not */
	if (head == NULL) {
		head = new_node;
	} else {
		tmp = head;

		/* Traverse the linked list until tmp is the last node */
		while(tmp->next != NULL) {
			tmp = tmp->next;
		}
		tmp->next = new_node;
	}
	return 0;
}

/* Function to get sess_csid node data  */
sess_csid *
get_sess_csid_data_node(sess_csid *head, uint64_t seid)
{
	/* Pointing to head node */
	sess_csid *current = head;

	/* Check linked list is empty or not */
	while(current != NULL) {
		/* Validate the expected node or not */
		if (current->cp_seid == seid || current->up_seid == seid) {
			/* Node is not present in linked list */
			clLog(clSystemLog, eCLSeverityDebug, FORMAT"Match found for seid %"PRIu64" in LL\n",
						ERR_MSG, seid);
			return current;
		}

		/* Pointing to next node */
		current = current->next;
	}
	/* Node is not present in linked list */
	clLog(clSystemLog, eCLSeverityDebug, FORMAT"Match not found for seid %"PRIu64" in LL\n",
				ERR_MSG, seid);
	return NULL;
}

/**
 * @brief  : Function to remove firts node from likned list
 * @param  : head, link list pointer
 * @return : Returns list head on success , NULL otherwise
 */

static sess_csid *
remove_sess_csid_firts_node(sess_csid *head) {

	if(head == NULL)
		return NULL;

	sess_csid *current = head;

	/* Access the next node */
	head = current->next;

	/* Free next node address form current node  */
	current->next = NULL;

	/* Check this the last node in the linked list or not */
	if (current == head)
		head = NULL;

	/* Free the 1st node from linked list */
	if(current != NULL)
		rte_free(current);

	current = NULL;
	return head;
}

/* Function to remove last node from linked list */
//static sess_csid *
//remove_sess_csid_last_node(sess_csid *head) {
//
//	if(head == NULL)
//		return NULL;
//
//	sess_csid *current = head;
//	sess_csid *last = NULL;
//
//	/* Find the last node in the linked list */
//	while(current->next != NULL) {
//		last = current;
//		current = current->next;
//	}
//
//	if (last != NULL)
//		last->next = NULL;
//
//	/* Check this the last node in the linked list */
//	if (current == head)
//		head = NULL;
//
//	/* free the last node from linked list */
//	rte_free(current);
//	current = NULL;
//	return head;
//
//}

/* Function to remove node from linked list */
sess_csid *
remove_sess_csid_data_node(sess_csid *head, uint64_t seid)
{

	/* pointing to head node */
	sess_csid *current = head;
	sess_csid *previous = NULL;
	//sess_csid *tmp = NULL;

	if(head == NULL) {
		return NULL;
	}

	/* Check node and linked list empty or not */
	while(current != NULL) {

		/* Compare seid to remove requested node from link list */
		if(current->cp_seid == seid || current->up_seid == seid){

			/* If first node remove */
			if(current == head){
				return remove_sess_csid_firts_node(head);
			}
			/* B : need to think about last node remove */
			/* If the last node remove */
			if(current->next == NULL ){
				/* Check previous csid node is not empty */
				if(previous != NULL) {
					previous->next = NULL;
				}
				if(current != NULL)
					rte_free(current);
				current = NULL;
				return head;
				//return remove_sess_csid_last_node(head);
			}

			/* If middel node */
			previous->next = current->next;
			current->next = NULL;

			/* Free the next node */
			if(current != NULL)
			{
				rte_free(current);
				current = NULL;
			}

			return head;
		}

		previous = current;
		current = current->next;
	}


	/* If no node present in link list for given seid then return NULL */
	clLog(clSystemLog, eCLSeverityDebug, FORMAT"Failed to remove node, for seid : %"PRIu64"\n",
				ERR_MSG, seid);
	return NULL;

}


/* Function to delete a node from the session data Linked List. */
int8_t
flush_sess_csid_data_list(sess_csid *head)
{
	sess_csid *current = NULL;
	sess_csid *tmp = NULL;

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
