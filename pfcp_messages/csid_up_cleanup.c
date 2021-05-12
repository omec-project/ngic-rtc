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

#include "up_main.h"
#include "teid_upf.h"
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_sess.h"
#include "gw_adapter.h"
#include "seid_llist.h"
#include "pfcp_messages_encoder.h"

extern bool assoc_available;
extern int clSystemLog;
extern uint16_t dp_comm_port;

/**
 * @brief  : Cleanup csid using csid entry
 * @param  : peer_fqcsid
 * @param  : local_fqcsid
 * @param  : iface
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_csid_by_csid_entry(fqcsid_t *peer_fqcsid, fqcsid_t *local_fqcsid, uint8_t iface)
{

	for (uint8_t itr = 0; itr < peer_fqcsid->num_csid; itr++) {
		csid_t *local_csids = NULL;
		csid_key_t key_t = {0};

		key_t.local_csid = peer_fqcsid->local_csid[itr];
		key_t.node_addr = peer_fqcsid->node_addr;

		local_csids = get_peer_csid_entry(&key_t, iface, REMOVE_NODE);

		if (local_csids == NULL) {
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Failed to Get Local CSID entry:"
					" Peer Node addr : %u , CSID : %d \n",
					LOG_VALUE, key_t.node_addr, key_t.local_csid);
			continue;
		}

		for (uint8_t itr1 = 0; itr1 < local_fqcsid->num_csid; itr1++) {
			for (uint8_t itr2 = 0; itr2 < local_csids->num_csid; itr2++) {
				if (local_fqcsid->local_csid[itr1] == local_csids->local_csid[itr2]) {
					for(uint32_t pos = itr2; pos < (local_csids->num_csid - 1); pos++ ) {
						local_csids->local_csid[pos] = local_csids->local_csid[pos + 1];
					}
					local_csids->num_csid--;
				}
			}
		}

		if (!local_csids->num_csid) {
			if (del_peer_csid_entry(&key_t, iface)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
					" CSID entry: %s \n", LOG_VALUE, strerror(errno));
				return -1;
			}
		}
	}


	return 0;
}

static int8_t
get_peer_assoc_csids(fqcsid_t *peer_fqcsid, fqcsid_t *local_fqcsid)
{
	for(uint8_t itr = 0; itr < peer_fqcsid->num_csid; itr++) {
		uint8_t match = 0;
		for(uint8_t itr1 = 0; itr1 < local_fqcsid->num_csid; itr1++) {
			if (local_fqcsid->local_csid[itr1] == peer_fqcsid->local_csid[itr]){
				match = 1;
				break;
			}
		}

		if (!match) {
			local_fqcsid->local_csid[local_fqcsid->num_csid++] =
				peer_fqcsid->local_csid[itr];
		}
	}
	/* Node Addr */
	local_fqcsid->node_addr = peer_fqcsid->node_addr;

	return 0;
}

/**
 * @brief  : Cleanup session using csid entry
 * @param  : csids
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_sess_by_csid_entry(fqcsid_t *csids)
{
	uint8_t ret = 0;
	fqcsid_t mme_fqcsid = {0};
	fqcsid_t sgwc_fqcsid = {0};
	fqcsid_t pgwc_fqcsid = {0};
	fqcsid_t wb_fqcsid = {0};
	fqcsid_t eb_fqcsid = {0};

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *tmp_t = NULL;
		sess_csid *current = NULL;

		tmp_t = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp_t == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found, CSID: %u\n", LOG_VALUE, csids->local_csid[itr]);
			continue;
		}

		/* TODO: Temp handling the corner scenarios for temp allocated CSIDs */
		/* Check SEID is not ZERO */
		if ((tmp_t->up_seid == 0) && (tmp_t->next == 0)) {
			continue;
		}

		current = tmp_t;
		while(current != NULL) {
			sess_csid *tmp = NULL;
			pfcp_session_t *sess = NULL;
			/* Get the session information from session table based on UP_SESSION_ID*/
			sess = get_sess_info_entry(current->up_seid,
					SESS_DEL);

			if (sess == NULL) {
				tmp = current->next;
				current->next = NULL;

				/* free node  */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			/* MME FQ-CSID */
			if(sess->mme_fqcsid != NULL) {
				if (get_peer_assoc_csids(sess->mme_fqcsid, &mme_fqcsid) < 0) {
					/* TODO: ERR Handling */
				}
			}

			/* SGWC FQ-CSID */
			if (sess->sgw_fqcsid != NULL) {
				if (get_peer_assoc_csids(sess->sgw_fqcsid, &sgwc_fqcsid) < 0) {
					/* TODO: ERR Handling */
				}
			}

			/* PGWC FQ-CSID */
			if (sess->pgw_fqcsid != NULL) {
				if (get_peer_assoc_csids(sess->pgw_fqcsid, &pgwc_fqcsid) < 0) {
					/* TODO: ERR Handling */
				}
			}

			/* West Bound/eNB/SGWU FQ-CSID */
			if(sess->wb_peer_fqcsid != NULL) {
				if (get_peer_assoc_csids(sess->wb_peer_fqcsid, &wb_fqcsid) < 0) {
					/* TODO: ERR Handling */
				}
			}

			/* East Bound/PGWU FQ-CSID */
			if(sess->eb_peer_fqcsid != NULL) {
				if (get_peer_assoc_csids(sess->eb_peer_fqcsid, &eb_fqcsid) < 0) {
					/* TODO: ERR Handling */
				}
			}

			/* Cleanup Session dependant information such as PDR, QER and FAR */
			if (up_delete_session_entry(sess, NULL))
				continue;

			/* Cleanup the session */
			if (sess != NULL) {
				rte_free(sess);
			}
			sess = NULL;

			tmp = current->next;
			current->next = NULL;

			/* free node  */
			if(current != NULL) {
				rte_free(current);
			}
			current = NULL;
			current = tmp;
		}
		/* Update CSID Entry in table */
	    ret = rte_hash_add_key_data(seids_by_csid_hash,
				&csids->local_csid[itr], current);
		if (ret) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to update Session IDs entry for CSID = %u"
					"\n\tError= %s\n",
					LOG_VALUE, csids->local_csid[itr],
					rte_strerror(abs(ret)));
		}
	}

	/* Cleanup MME FQ-CSID */
	if (mme_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&mme_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
				"MME FQ-CSID entry while cleanup session by CSID entry, "
				"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
	}

	/* Cleanup SGWC FQ-CSID associte with peer CSID */
	if (sgwc_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&sgwc_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
				"SGW-C FQ-CSID entry while cleanup session by CSID entry, "
				"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
	}

	/* Cleanup PGWC FQ-CSID associte with peer CSID */
	if (pgwc_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&pgwc_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
				"PGW-C FQ-CSID entry while cleanup session by CSID entry, "
				"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
	}

	/* Cleanup West_Bound/eNB/SGWU FQ-CSID */
	if (wb_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&wb_fqcsid, csids, S1U_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
				"eNB/SGWU/WB FQ-CSID entry while cleanup session by CSID entry, "
				"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
	}

	/* Cleanup East_Bound/PGWU FQ-CSID */
	if (eb_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&eb_fqcsid, csids, SGI_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete "
				"PGW-U/EB FQ-CSID entry while cleanup session by CSID entry, "
				"Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}
	}
	return 0;
}

/**
 * @brief  : Cleanup peer node address entry for fqcsid IE address.
 * @param  : key, key of the hash.
 * @param  : iface, .
 * @return : In success return 0, otherwise -1.
 */
static int
cleanup_peer_node_addr_entry(peer_node_addr_key_t *key) {

	fqcsid_ie_node_addr_t *tmp;
	fqcsid_t *peer_csids = NULL;

	tmp = get_peer_node_addr_entry(key, REMOVE_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"Entry not found for Peer Node Addrres : %u\n",
				LOG_VALUE, key->peer_node_addr.ipv4_addr);
		return -1;
	}
	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(&tmp->fqcsid_node_addr, UPDATE_NODE);
	if (peer_csids == NULL) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(tmp->fqcsid_node_addr.ipv4_addr));
		del_peer_node_addr_entry(key);
		return 0;
	}
	/* Get the mapped Session */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		peer_csid_key_t key_t = {0};
		sess_csid *tmp = NULL;

		key_t.iface = SX_PORT_ID;
		key_t.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key_t.peer_node_addr,
				&peer_csids->node_addr, sizeof(node_address_t));

		tmp = get_sess_peer_csid_entry(&key_t, REMOVE_NODE);
		if (tmp == NULL) {
				del_peer_node_addr_entry(key);
				return 0;
		}
	}

	return 0;
}


/**
 * @brief  : Remove session from linked list entry
 * @param  : head,
 * @param  : seid,
 * @param  : key, peer csid hash key.
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int
remove_sess_entry(sess_csid *head, uint64_t seid, peer_csid_key_t *key) {

	int ret = 0;

	if (head == NULL) {
		/* Delete Local CSID entry */
		del_sess_peer_csid_entry(key);
	}

	/* Remove node from csid linked list */
	head = remove_sess_csid_data_node(head, seid);

	/* Update CSID Entry in table */
	ret = rte_hash_add_key_data(seid_by_peer_csid_hash,
			key, head);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to add Session IDs entry"
				" for CSID = %u \n", LOG_VALUE, key->peer_local_csid);
		return -1;
	}
	if (head == NULL) {
		/* Delete Local CSID entry */
		del_sess_peer_csid_entry(key);
	}
	return 0;
}

/**
 * @brief  : Cleanup session using csid entry
 * @param  : peer_csids,
 * @oaram  : iface,
 * @return : Returns 0 in case of success, -1 otherwise
 */
static int8_t
cleanup_sess_by_peer_csid_entry(fqcsid_t *peer_csids, uint8_t iface)
{
	/* TODO : add cl log  for ipv6 */
	uint8_t ret = 0;
	uint8_t num_csid = 0;
	node_address_t cp_ip = {0};
	peer_csid_key_t key = {0};
	fqcsid_t *csids = NULL;

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < peer_csids->num_csid; itr++) {
		sess_csid *tmp_t = NULL;
		sess_csid *current = NULL;

		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key.peer_node_addr,
			&peer_csids->node_addr, sizeof(node_address_t));

		tmp_t = get_sess_peer_csid_entry(&key, REMOVE_NODE);
		if (tmp_t == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found, CSID: %u\n", LOG_VALUE, peer_csids->local_csid[itr]);
			continue;
		}

		/* Check SEID is not ZERO */
		if ((tmp_t->up_seid == 0) && (tmp_t->next == 0)) {
			continue;
		}

		current = tmp_t;
		while(current != NULL) {
			sess_csid *tmp = NULL;
			pfcp_session_t *sess = NULL;
			/* Get the session information from session table based on UP_SESSION_ID*/
			sess = get_sess_info_entry(current->up_seid,
					SESS_DEL);

			if (sess == NULL) {
				tmp = current->next;
				current->next = NULL;

				/* free node  */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			sess_csid *head = NULL;
			/* Delete Session for peer CSID hash */
			if ((sess->mme_fqcsid != NULL) && (((sess->mme_fqcsid)->num_csid) &&
					(memcmp(&peer_csids->node_addr,
						&(sess->mme_fqcsid)->node_addr, sizeof(node_address_t))))) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from MME CSID Link List \n", LOG_VALUE);
				/* Remove the session link from MME CSID */
				key.iface = SX_PORT_ID;
				key.peer_local_csid = (sess->mme_fqcsid)->local_csid[num_csid];
				key.peer_node_addr = (sess->mme_fqcsid)->node_addr;

				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, sess->up_seid, &key);
			}

			if ((sess->pgw_fqcsid != NULL) && (((sess->pgw_fqcsid)->num_csid) &&
					(memcmp(&peer_csids->node_addr,
						 &(sess->pgw_fqcsid)->node_addr, sizeof(node_address_t))))) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"Removing Session from PGWC CSID Link List \n", LOG_VALUE);
				/* Remove the session link from UP CSID */
				key.iface = SX_PORT_ID;
				key.peer_local_csid = (sess->pgw_fqcsid)->local_csid[num_csid];
				key.peer_node_addr = (sess->pgw_fqcsid)->node_addr;
				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, sess->up_seid, &key);
			}

			if ((sess->sgw_fqcsid != NULL) && (((sess->sgw_fqcsid)->num_csid) &&
					(memcmp(&peer_csids->node_addr,
						&(sess->sgw_fqcsid)->node_addr, sizeof(node_address_t))))) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"Removing Session from SGWC CSID Link List \n", LOG_VALUE);
				/* Remove the session link from UP CSID */
				key.iface = SX_PORT_ID;
				key.peer_local_csid = (sess->sgw_fqcsid)->local_csid[num_csid];
				key.peer_node_addr = (sess->sgw_fqcsid)->node_addr;
				head = get_sess_peer_csid_entry(&key, REMOVE_NODE);
				remove_sess_entry(head, sess->up_seid, &key);
			}

			csids = sess->up_fqcsid;
			/* Get the session ID by csid */
			for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
				sess_csid *seids = NULL;

				seids = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
				if (seids == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Session "
							"ID by CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
					return -1;
				}

				seids = remove_sess_csid_data_node(seids, sess->up_seid);

				/* Update CSID Entry in table */
				ret = rte_hash_add_key_data(seids_by_csid_hash,
						&csids->local_csid[itr], seids);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
							"\n\tError= %s\n",
							LOG_VALUE, csids->local_csid[itr],
							rte_strerror(abs(ret)));
					return -1;
				}

				if (seids == NULL) {
					if (sess->sgw_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"SGWC/SAEGWC Node Addr:"IPV4_ADDR"\n",
							LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->sgw_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->sgw_fqcsid, csids,
									SX_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Failed to delete SGW CSID "
								"entry from hash , Error: %s \n",
								LOG_VALUE, strerror(errno));
							return -1;
						}
					}

					if (sess->pgw_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
								"PGWC Node Addr:"IPV4_ADDR"\n",
								LOG_VALUE,
								IPV4_ADDR_HOST_FORMAT((sess->pgw_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->pgw_fqcsid, csids,
									SX_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Error: %s \n", LOG_VALUE, strerror(errno));
							return -1;
						}
					}

					if (sess->up_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
								"UP Node Addr:"IPV4_ADDR"\n",
								LOG_VALUE,
								IPV4_ADDR_HOST_FORMAT((sess->up_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->up_fqcsid, csids,
									SGI_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Error: %s \n", LOG_VALUE, strerror(errno));
							return -1;
						}
					}

					if (sess->mme_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"MME Node Addr:"IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT((sess->mme_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->mme_fqcsid, csids,
									SX_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Failed to delete MME CSID "
								"entry from hash , Error: %s \n",
								LOG_VALUE, strerror(errno));
							return -1;
						}
					}

					if (sess->wb_peer_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"eNB/SGWU/West Bound Node Addr:"IPV4_ADDR"\n",
							LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->wb_peer_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->wb_peer_fqcsid, csids,
									S1U_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Error: %s \n", LOG_VALUE, strerror(errno));
							return -1;
						}
					}

					if (sess->eb_peer_fqcsid != NULL) {
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"PGWU/East Bound Node Addr:"IPV4_ADDR"\n",
							LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->eb_peer_fqcsid)->node_addr.ipv4_addr));
						if (del_csid_entry_hash(sess->eb_peer_fqcsid, csids,
									SGI_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
								"Error: %s \n", LOG_VALUE,
								strerror(errno));
							return -1;
						}
					}

					if (del_sess_csid_entry(csids->local_csid[itr])) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Failed to delete session by CSID "
							"entry , Error: %s \n", LOG_VALUE, strerror(errno));
						return -1;
					}
					/* Decrement the csid counters */
					csids->num_csid--;
				}
			}

			if (!(is_present(&cp_ip))) {
				memcpy(&cp_ip, &sess->cp_node_addr, sizeof(node_address_t));
			}

			/* Cleanup Session dependant information such as PDR, QER and FAR */
			if (up_delete_session_entry(sess, NULL))
				continue;

			/* Cleanup the session */
			if (sess != NULL) {
				rte_free(sess);
			}
			sess = NULL;

			tmp = current->next;
			current->next = NULL;

			/* free node  */
			if(current != NULL) {
				rte_free(current);
				current = NULL;
			}

			current = tmp;
		}
		/* Update CSID Entry in table */
	  	rte_hash_add_key_data(seid_by_peer_csid_hash, &key, current);
	}

	/* Delete Peer CSID entry */
	for (uint8_t itr = 0; itr < peer_csids->num_csid; ++itr) {
		key.iface = iface;
		key.peer_local_csid = peer_csids->local_csid[itr];
		memcpy(&key.peer_node_addr,
				&peer_csids->node_addr, sizeof(node_address_t));

		if (del_sess_peer_csid_entry(&key) < 0) {
			clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT"Error on "
				"Deleting peer CSID entry\n", LOG_VALUE);
		}
	}

	peer_node_addr_key_t key_t = {0};

	key_t.iface = SX_PORT_ID;
	memcpy(&key_t.peer_node_addr, &cp_ip, sizeof(node_address_t));

	cleanup_peer_node_addr_entry(&key_t);

	return 0;
}


/**
 * @brief  : Send pfcp sess. del. ser req. to peer node's
 * @param  : peer_csids, Conten list of peer csid.
 * @param  : iface,
 * @return : Returns 0 in case of success,
 */
static int8_t
send_pfcp_sess_del_set_req(fqcsid_t *csids, uint8_t iface)
{
	uint8_t match = 0;
	uint8_t num_node_addr = 0;
	node_address_t node_addrs[MAX_CSID] = {0};
	pfcp_sess_set_del_req_t del_set_req_t = {0};

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *tmp_t = NULL;
		sess_csid *current = NULL;

		tmp_t = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp_t == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Entry not found, CSID: %u\n",
					LOG_VALUE, csids->local_csid[itr]);
			continue;
		}

		/* Check SEID is not ZERO */
		if ((tmp_t->up_seid == 0) && (tmp_t->next == 0)) {
			continue;
		}

		current = tmp_t;
		while(current != NULL) {
			sess_csid *tmp = NULL;
			pfcp_session_t *sess = NULL;
			/* Get the session information from session table based on UP_SESSION_ID*/
			sess = get_sess_info_entry(current->up_seid, SESS_DEL);

			if (sess == NULL) {
				tmp = current->next;
				current->next = NULL;

				/* free node  */
				if(current != NULL) {
					rte_free(current);
					current = NULL;
				}
				current = tmp;
				continue;
			}

			if(sess->cp_ip.type == IPV6_TYPE){
				match = 0;
				for (uint8_t itr1 = 0; itr1 < num_node_addr; itr1++) {
					if (!memcmp(sess->cp_ip.ipv6.sin6_addr.s6_addr,
								node_addrs[itr1].ipv6_addr, IPV6_ADDR_LEN)) {
						match = 1;
						break;
					}
				}

				if (!match) {
					node_addrs[num_node_addr].ip_type = IPV6_TYPE;
					memcpy(node_addrs[num_node_addr++].ipv6_addr,
							sess->cp_ip.ipv6.sin6_addr.s6_addr, IPV6_ADDR_LEN);
				}
			} else if(sess->cp_ip.type == IPV4_TYPE) {
				match = 0;
				for (uint8_t itr1 = 0; itr1 < num_node_addr; itr1++) {
					if (sess->cp_ip.ipv4.sin_addr.s_addr == node_addrs[itr1].ipv4_addr) {
						match = 1;
						break;
					}
				}

				if (!match) {
					node_addrs[num_node_addr].ip_type = IPV4_TYPE;
					node_addrs[num_node_addr++].ipv4_addr = sess->cp_ip.ipv4.sin_addr.s_addr;
				}
			}
			/* Assign Next node address */
			tmp = current->next;
			current = tmp;
		}
	}

	fill_pfcp_sess_set_del_req_t(&del_set_req_t, csids, iface);

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;

	if (encoded) {
		for (uint8_t itr2 = 0; itr2 < num_node_addr; itr2++) {
			int bytes = 0;
			peer_address_t addr = {0};
			addr.type = node_addrs[itr2].ip_type;
			if (node_addrs[itr2].ip_type == IPV4_TYPE) {
				dest_addr_t.ipv4.sin_family = AF_INET;
				dest_addr_t.ipv4.sin_port = dp_comm_port;
				dest_addr_t.ipv4.sin_addr.s_addr = node_addrs[itr2].ipv4_addr;
				addr.ipv4.sin_addr.s_addr = node_addrs[itr2].ipv4_addr;

				if(my_sock.sock_fd <= 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IPv4:PFCP send is "
							"not possible due to incompatiable IP Type at "
							"Source and Destination\n", LOG_VALUE);
					continue;
				}
				bytes = sendto(my_sock.sock_fd, (uint8_t *) pfcp_msg, encoded, MSG_DONTWAIT,
						(struct sockaddr *) &dest_addr_t.ipv4, sizeof(struct sockaddr_in));

			} else if (node_addrs[itr2].ip_type == IPV6_TYPE) {
				dest_addr_t.ipv6.sin6_family = AF_INET6;
				dest_addr_t.ipv6.sin6_port = dp_comm_port;
				memcpy(dest_addr_t.ipv6.sin6_addr.s6_addr,
						node_addrs[itr2].ipv6_addr, IPV6_ADDR_LEN);
				memcpy(addr.ipv6.sin6_addr.s6_addr,
						node_addrs[itr2].ipv6_addr, IPV6_ADDR_LEN);

				if(my_sock.sock_fd_v6 <= 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"IPv6:PFCP send is "
							"not possible due to incompatiable IP Type at "
							"Source and Destination\n", LOG_VALUE);
					continue;
				}
				bytes = sendto(my_sock.sock_fd_v6, (uint8_t *) pfcp_msg, encoded, MSG_DONTWAIT,
						(struct sockaddr *) &dest_addr_t.ipv6, sizeof(struct sockaddr_in6));
			}

			if (bytes > 0) {
				update_cli_stats(&addr, header->message_type, SENT, SX);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"UP: Send the PFCP Session "
						"Set Deletion Request \n", LOG_VALUE);
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Send PFCP "
						"Session Set Deletion Request, Error: %s \n",
						LOG_VALUE, strerror(errno));
			}
		}
	}
	/* Reset the Number CP Address */
	num_node_addr = 0;
	return 0;
}

/* Cleanup Session information by local csid*/
int8_t
up_del_pfcp_peer_node_sess(node_address_t *node_addr, uint8_t iface)
{
	int ret = 0;
	fqcsid_t csids = {0};
	peer_node_addr_key_t key = {0};
	fqcsid_ie_node_addr_t *fqcsid_node_id = NULL;
	fqcsid_t *peer_csids = NULL;
	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT
			"UP Cleanup Internal data Structures For peer node \n", LOG_VALUE);

	if (iface == SX_PORT_ID) {
		if (app.teidri_val != 0) {
			/* TODO: TEID scenario handling for IPv6 */
			/* cleanup teidri entry for node*/
			ret =  delete_teidri_node_entry(TEIDRI_FILENAME, *node_addr, &upf_teidri_allocated_list,
					&upf_teidri_free_list, app.teidri_val);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete TEIDRI "
						"node entry, Error: %s \n", LOG_VALUE, strerror(errno));
			}

		} else {
			assoc_available = true;
		}
	}

	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(node_addr, UPDATE_NODE);
	if (peer_csids == NULL) {
		key.iface = iface;
		key.peer_node_addr = *node_addr;

		fqcsid_node_id = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (fqcsid_node_id == NULL) {
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv4 Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return 0;
		}

		peer_csids = get_peer_addr_csids_entry(&fqcsid_node_id->fqcsid_node_addr,
					UPDATE_NODE);
		if (peer_csids == NULL) {
			(node_addr->ip_type == IPV6_TYPE) ?
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv6 Addr:"IPv6_FMT"\n",
						LOG_VALUE, IPv6_PRINT(IPv6_CAST(node_addr->ipv6_addr))):
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Peer CSIDs are already cleanup, Node IPv4 Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return 0;
		}
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_csids->local_csid[itr];
		key.node_addr = peer_csids->node_addr;

		tmp = get_peer_csid_entry(&key, iface, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get peer "
				"CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		csids.node_addr = tmp->node_addr;
		(csids.node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Found Local CSIDs, Node IPv6 Addr:"IPv6_FMT", Num_CSID:%u\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(csids.node_addr.ipv6_addr)), csids.num_csid):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Found Local CSIDs, Node IPv4 Addr:"IPV4_ADDR", Num_CSID:%u\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(csids.node_addr.ipv4_addr), csids.num_csid);
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"CSIDs are already cleanup\n", LOG_VALUE);
		return 0;
	}

	if (iface != SX_PORT_ID) {
		send_pfcp_sess_del_set_req(&csids, iface);
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to cleanup session "
			"CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
		return 0;
	}

	ret = del_csid_entry_hash(peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete CSID "
			"hash, Error: %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	if (key.peer_node_addr.ip_type) {
		ret = del_peer_node_addr_entry(&key);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete CSID "
					"hash, Error: %s \n", LOG_VALUE, strerror(errno));
		}
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" UP Cleanup completed for peer "
		"node \n", LOG_VALUE);
	return 0;
}

int8_t
process_up_sess_set_del_req(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req)
{
	int ret = 0;
	fqcsid_t csids = {0};
	fqcsid_t peer_csids = {0};

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Set Deletion Request :: START \n", LOG_VALUE);
	/* MME FQ-CSID */
	if (pfcp_sess_set_del_req->mme_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->mme_fqcsid.number_of_csids) {
			for (uint8_t itr = 0; itr < pfcp_sess_set_del_req->mme_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->mme_fqcsid.pdn_conn_set_ident[itr];

				if (pfcp_sess_set_del_req->mme_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
					key.node_addr.ip_type = PDN_TYPE_IPV4;
					memcpy(&key.node_addr.ipv4_addr,
							&(pfcp_sess_set_del_req->mme_fqcsid.node_address), IPV4_SIZE);
				} else {
					key.node_addr.ip_type = PDN_TYPE_IPV6;
					memcpy(&key.node_addr.ipv6_addr,
						 &(pfcp_sess_set_del_req->mme_fqcsid.node_address), IPV6_ADDRESS_LEN);
				}

				tmp = get_peer_csid_entry(&key, SX_PORT_ID, REMOVE_NODE);
				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get peer "
						"MME CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
					continue;
				}

				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[peer_csids.num_csid++] =
						pfcp_sess_set_del_req->mme_fqcsid.pdn_conn_set_ident[itr];
				memcpy(&(peer_csids.node_addr), &(key.node_addr), sizeof(node_address_t));
			}
		}
	}

	/* SGW FQ-CSID */
	if (pfcp_sess_set_del_req->sgw_c_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids) {
			for (uint8_t itr = 0; itr < pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
				if (pfcp_sess_set_del_req->sgw_c_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
					key.node_addr.ip_type = PDN_TYPE_IPV4;
					memcpy(&key.node_addr.ipv4_addr,
							&(pfcp_sess_set_del_req->sgw_c_fqcsid.node_address), IPV4_SIZE);
				} else {
					key.node_addr.ip_type = PDN_TYPE_IPV6;
					memcpy(&key.node_addr.ipv6_addr,
						 &(pfcp_sess_set_del_req->sgw_c_fqcsid.node_address), IPV6_ADDRESS_LEN);
				}

				tmp = get_peer_csid_entry(&key, SX_PORT_ID, REMOVE_NODE);

				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get peer "
						"SGW-C CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
					continue;
				}
				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[peer_csids.num_csid++] =
						pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
				memcpy(&(peer_csids.node_addr), &(key.node_addr), sizeof(node_address_t));
			}
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_set_del_req->pgw_c_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->pgw_c_fqcsid.number_of_csids) {
			for (uint8_t itr = 0; itr < pfcp_sess_set_del_req->pgw_c_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
				if (pfcp_sess_set_del_req->pgw_c_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
					key.node_addr.ip_type = PDN_TYPE_IPV4;
					memcpy(&key.node_addr.ipv4_addr,
							&(pfcp_sess_set_del_req->pgw_c_fqcsid.node_address), IPV4_SIZE);
				} else {
					key.node_addr.ip_type = PDN_TYPE_IPV6;
					memcpy(&key.node_addr.ipv6_addr,
						 &(pfcp_sess_set_del_req->pgw_c_fqcsid.node_address), IPV6_ADDRESS_LEN);
				}

				tmp = get_peer_csid_entry(&key, SX_PORT_ID, REMOVE_NODE);
				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Failed to get peer "
						"PGW-C CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
					continue;
				}
				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[peer_csids.num_csid++] =
						pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
				memcpy(&(peer_csids.node_addr), &(key.node_addr), sizeof(node_address_t));
			}
		}
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Not found peer CSIDs \n", LOG_VALUE);
		return -1;
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_peer_csid_entry(&peer_csids, SX_PORT_ID);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to cleanup session "
			"CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	ret = del_csid_entry_hash(&peer_csids, &csids, SX_PORT_ID);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to delete CSID "
			"hash while Processing UP Session Set Delete Request, "
			"Error: %s \n", LOG_VALUE, strerror(errno));
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Set Deletion Request :: END \n", LOG_VALUE);
	return 0;
}

/**
 * @brief  : Delete session with peer CSID.
 * @param  : sess, session info.
 * @return : Returns 0 in case of success, cause value otherwise.
 */
static int
del_dp_session_csid_entry(pfcp_session_t *sess) {

	uint8_t num_csid = 0;
	sess_csid *tmp1 = NULL;
	peer_csid_key_t key = {0};

	if (sess->mme_fqcsid != NULL) {
		if ((sess->mme_fqcsid)->num_csid) {
			/* Remove the session link from MME CSID */
			key.iface = SX_PORT_ID;
			key.peer_local_csid = (sess->mme_fqcsid)->local_csid[num_csid];
			memcpy(&key.peer_node_addr,
					&(sess->mme_fqcsid)->node_addr, sizeof(node_address_t));

			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);
			remove_sess_entry(tmp1, sess->up_seid, &key);
		}
	}

	if (sess->sgw_fqcsid != NULL) {
		if ((sess->sgw_fqcsid)->num_csid) {
			/* Remove the session link from MME CSID */
			key.iface = SX_PORT_ID;
			key.peer_local_csid = (sess->sgw_fqcsid)->local_csid[num_csid];
			memcpy(&key.peer_node_addr,
					&(sess->sgw_fqcsid)->node_addr, sizeof(node_address_t));

			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);
			remove_sess_entry(tmp1, sess->up_seid, &key);
		}
	}

	if (sess->pgw_fqcsid != NULL) {
		if ((sess->pgw_fqcsid)->num_csid) {
			/* Remove the session link from MME CSID */
			key.iface = SX_PORT_ID;
			key.peer_local_csid = (sess->pgw_fqcsid)->local_csid[num_csid];
			memcpy(&key.peer_node_addr,
					&(sess->pgw_fqcsid)->node_addr, sizeof(node_address_t));

			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);
			remove_sess_entry(tmp1, sess->up_seid, &key);
		}
	}
	return 0;
}

int8_t
del_sess_by_csid_entry(pfcp_session_t *sess, fqcsid_t *csids, uint8_t iface)
{
	int ret = 0;
	uint16_t num_csid = csids->num_csid;
	peer_node_addr_key_t key = {0};

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < num_csid; itr++) {
		sess_csid *seids = NULL;

		seids = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (seids == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get Session "
				"ID by CSID entry, Error: %s \n", LOG_VALUE, strerror(errno));
			return -1;
		}

		seids = remove_sess_csid_data_node(seids, sess->up_seid);

		/* Update CSID Entry in table */
	    ret = rte_hash_add_key_data(seids_by_csid_hash,
				&csids->local_csid[itr], seids);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to add Session IDs entry for CSID = %u"
					"\n\tError= %s\n",
					LOG_VALUE, csids->local_csid[itr],
					rte_strerror(abs(ret)));
			return -1;
		}

		if (seids == NULL) {
			if (sess->sgw_fqcsid != NULL) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"SGWC/SAEGWC Node Addr:"IPV4_ADDR"\n",
						LOG_VALUE,
						IPV4_ADDR_HOST_FORMAT((sess->sgw_fqcsid)->node_addr.ipv4_addr));
				if (del_csid_entry_hash(sess->sgw_fqcsid, csids,
							SX_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
									"Failed to delete SGW CSID "
									"entry from hash , Error: %s \n", LOG_VALUE, strerror(errno));
					return -1;
				}
			}

			if (sess->pgw_fqcsid != NULL) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
						"PGWC Node Addr:"IPV4_ADDR"\n",
						LOG_VALUE,
						IPV4_ADDR_HOST_FORMAT((sess->pgw_fqcsid)->node_addr.ipv4_addr));
				if (del_csid_entry_hash(sess->pgw_fqcsid, csids,
						SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
							strerror(errno));
					return -1;
				}
			}

			/* TODO: VISHAL */
			if (sess->up_fqcsid != NULL) {
				((sess->up_fqcsid)->node_addr.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"UP Node IPv6 Addr:"IPv6_FMT"\n", LOG_VALUE,
							IPv6_PRINT(IPv6_CAST((sess->up_fqcsid)->node_addr.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"UP Node IPv4 Addr:"IPV4_ADDR"\n", LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->up_fqcsid)->node_addr.ipv4_addr));

				if (del_csid_entry_hash(sess->up_fqcsid, csids,
						SGI_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
							strerror(errno));
					return -1;
				}
			}

			if (sess->mme_fqcsid != NULL) {
				((sess->mme_fqcsid)->node_addr.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"MME Node IPv6 Addr:"IPv6_FMT"\n", LOG_VALUE,
							IPv6_PRINT(IPv6_CAST((sess->mme_fqcsid)->node_addr.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"MME Node IPv4 Addr:"IPV4_ADDR"\n", LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->mme_fqcsid)->node_addr.ipv4_addr));
				if (del_csid_entry_hash(sess->mme_fqcsid, csids,
						SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Failed to delete MME CSID "
							"entry from hash , Error: %s \n", LOG_VALUE, strerror(errno));
					return -1;
				}
			}

			if (sess->wb_peer_fqcsid != NULL) {
				((sess->wb_peer_fqcsid)->node_addr.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"eNB/SGWU/West Bound Node IPv6 Addr:"IPv6_FMT"\n", LOG_VALUE,
							IPv6_PRINT(IPv6_CAST((sess->wb_peer_fqcsid)->node_addr.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"eNB/SGWU/West Bound Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->wb_peer_fqcsid)->node_addr.ipv4_addr));
				if (del_csid_entry_hash(sess->wb_peer_fqcsid, csids,
						S1U_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
							strerror(errno));
					return -1;
				}
			}

			if (sess->eb_peer_fqcsid != NULL) {
				((sess->eb_peer_fqcsid)->node_addr.ip_type == IPV6_TYPE) ?
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"PGWU/East Bound Node IPv6 Addr:"IPv6_FMT"\n", LOG_VALUE,
							IPv6_PRINT(IPv6_CAST((sess->eb_peer_fqcsid)->node_addr.ipv6_addr))):
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
							"PGWU/East Bound Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE,
							IPV4_ADDR_HOST_FORMAT((sess->eb_peer_fqcsid)->node_addr.ipv4_addr));
				if (del_csid_entry_hash(sess->eb_peer_fqcsid, csids,
						SGI_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
							strerror(errno));
					return -1;
				}
			}

			if (del_sess_csid_entry(csids->local_csid[itr])) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Failed to delete session by CSID "
						"entry , Error: %s \n", LOG_VALUE, strerror(errno));
				return -1;
			}
			/* Decrement the csid counters */
			csids->num_csid--;

			key.iface = SX_PORT_ID;
			memcpy(&key.peer_node_addr,
					&sess->cp_node_addr, sizeof(node_address_t));

			if ((cleanup_peer_node_addr_entry(&key)) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Peer node address entry already deleted \n",
						LOG_VALUE);
			}
		}
	}

	del_dp_session_csid_entry(sess);

	return 0;
}

