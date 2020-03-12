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

#include "up_main.h"
#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_sess.h"
#include "clogger.h"
#include "gw_adapter.h"
#include "seid_llist.h"
#include "pfcp_messages_encoder.h"

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

		local_csids = get_peer_csid_entry(&key_t, SX_PORT_ID);

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
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
		}
	}


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
	fqcsid_t enb_fqcsid = {0};
	fqcsid_t mme_fqcsid = {0};
	fqcsid_t sgwc_fqcsid = {0};
	fqcsid_t sgwu_fqcsid = {0};
	fqcsid_t pgwc_fqcsid = {0};
	fqcsid_t pgwu_fqcsid = {0};

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *tmp = NULL;
		sess_csid *current = NULL;

		tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					FORMAT"Entry not found, CSID: %u\n", ERR_MSG, csids->local_csid[itr]);
			continue;
		}

		/* TODO: Temp handling the corner scenarios for temp allocated CSIDs */
		/* Check SEID is not ZERO */
		if ((tmp->up_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while(current != NULL) {
			pfcp_session_t *sess = NULL;
			/* Get the session information from session table based on UP_SESSION_ID*/
			sess = get_sess_info_entry(current->up_seid,
					SESS_DEL);

			if (sess == NULL) {
				tmp = current->next;
				current->next = NULL;

				/* free node  */
				if(current != NULL)
					rte_free(current);

				current = tmp;
				continue;
			}

			/* MME FQ-CSID */
			if(sess->mme_fqcsid != 0) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < (sess->mme_fqcsid)->num_csid; itr++) {
					for(uint8_t itr1 = 0; itr1 < mme_fqcsid.num_csid; itr1++) {
						if (mme_fqcsid.local_csid[itr1] == (sess->mme_fqcsid)->local_csid[itr])
							match = 1;
					}

					if (!match) {
						mme_fqcsid.local_csid[mme_fqcsid.num_csid++] =
							sess->mme_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				mme_fqcsid.node_addr = (sess->mme_fqcsid)->node_addr;
			}

			/* MME FQ-CSID */
			if((PGWU != app.spgw_cfg) && (sess->enb_fqcsid != 0)) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < (sess->enb_fqcsid)->num_csid; itr++) {
					for(uint8_t itr1 = 0; itr1 < enb_fqcsid.num_csid; itr1++) {
						if (enb_fqcsid.local_csid[itr1] == (sess->enb_fqcsid)->local_csid[itr])
							match = 1;
					}

					if (!match) {
						enb_fqcsid.local_csid[enb_fqcsid.num_csid++] =
							sess->enb_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				enb_fqcsid.node_addr = (sess->enb_fqcsid)->node_addr;
			}

			/* Cleanup Session dependant information such as PDR, QER and FAR */
			if (up_delete_session_entry(sess, NULL))
				continue;


			/* Cleanup Peer node CSID with are associated with the local CSID */
			/* SGWC FQ-CSID */
			if (sess->sgw_fqcsid != 0) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < sess->sgw_fqcsid->num_csid; itr++ ) {
					for(uint8_t itr1 = 0; itr1 < sgwc_fqcsid.num_csid; itr1++) {
						if(sgwc_fqcsid.local_csid[itr1] == sess->sgw_fqcsid->local_csid[itr])
							match = 1;
					}

					if(!match) {
						sgwc_fqcsid.local_csid[sgwc_fqcsid.num_csid++] =
							sess->sgw_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				sgwc_fqcsid.node_addr = sess->sgw_fqcsid->node_addr;
			}

			/* SGWU FQ-CSID */
			if ((PGWU == app.spgw_cfg) && (sess->sgwu_fqcsid != 0)) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < sess->sgwu_fqcsid->num_csid; itr++ ) {
					for(uint8_t itr1 = 0; itr1 < sgwu_fqcsid.num_csid; itr1++) {
						if(sgwu_fqcsid.local_csid[itr1] == sess->sgwu_fqcsid->local_csid[itr])
							match = 1;
					}

					if(!match) {
						sgwu_fqcsid.local_csid[sgwu_fqcsid.num_csid++] =
							sess->sgwu_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				sgwu_fqcsid.node_addr = sess->sgwu_fqcsid->node_addr;
			}

			/* PGWC FQ-CSID */
			if (sess->pgw_fqcsid != 0) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < sess->pgw_fqcsid->num_csid; itr++ ) {
					for(uint8_t itr1 = 0; itr1 < pgwc_fqcsid.num_csid; itr1++) {
						if(pgwc_fqcsid.local_csid[itr1] == sess->pgw_fqcsid->local_csid[itr])
							match = 1;
					}

					if(!match) {
						pgwc_fqcsid.local_csid[pgwc_fqcsid.num_csid++] =
							sess->pgw_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				pgwc_fqcsid.node_addr = sess->pgw_fqcsid->node_addr;
			}

			/* PGWU FQ-CSID */
			if ((SGWU == app.spgw_cfg) && (sess->pgwu_fqcsid != 0)) {
				uint8_t match = 0;
				for(uint8_t itr = 0; itr < sess->pgwu_fqcsid->num_csid; itr++ ) {
					for(uint8_t itr1 = 0; itr1 < pgwu_fqcsid.num_csid; itr1++) {
						if(pgwu_fqcsid.local_csid[itr1] == sess->pgwu_fqcsid->local_csid[itr])
							match = 1;
					}

					if(!match) {
						pgwu_fqcsid.local_csid[pgwu_fqcsid.num_csid++] =
							sess->pgwu_fqcsid->local_csid[itr];
						match = 0;
					}
				}
				/* Node Addr */
				pgwu_fqcsid.node_addr = sess->pgwu_fqcsid->node_addr;
			}

			/* Cleanup the session */
			rte_free(sess);
			sess = NULL;

			tmp = current->next;
			current->next = NULL;

			/* free node  */
			if(current != NULL)
				rte_free(current);

			current = tmp;
		}
	}

	/* Cleanup MME FQ-CSID */
	if (mme_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&mme_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}

	/* Cleanup eNB FQ-CSID */
	if ((PGWU != app.spgw_cfg) && (enb_fqcsid.num_csid != 0)) {
		if(cleanup_csid_by_csid_entry(&enb_fqcsid, csids, S1U_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}

	/* Cleanup SGWC FQ-CSID associte with peer CSID */
	if (sgwc_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&sgwc_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}

	/* Cleanup SGWU FQ-CSID associte with peer CSID */
	if ((PGWU == app.spgw_cfg) && (sgwu_fqcsid.num_csid != 0)) {
		if(cleanup_csid_by_csid_entry(&sgwu_fqcsid, csids, S1U_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}

	/* Cleanup PGWC FQ-CSID associte with peer CSID */
	if (pgwc_fqcsid.num_csid != 0) {
		if(cleanup_csid_by_csid_entry(&pgwc_fqcsid, csids, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}

	/* Cleanup PGWU FQ-CSID associte with peer CSID */
	if ((SGWU == app.spgw_cfg) && (pgwu_fqcsid.num_csid != 0)) {
		if(cleanup_csid_by_csid_entry(&pgwu_fqcsid, csids, SGI_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
			return -1;
		}
	}
	return 0;
}


/* Cleanup Session information by local csid*/
int8_t
up_del_pfcp_peer_node_sess(uint32_t node_addr, uint8_t iface)
{
	int ret = 0;
	pfcp_sess_set_del_req_t del_set_req_t = {0};
	fqcsid_t csids = {0};
	fqcsid_t *peer_csids = NULL;

	clLog(clSystemLog, eCLSeverityDebug,
			"UP Cleanup Internal data Structures For peer node \n");
	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(ntohl(node_addr),
			MOD);
	if (peer_csids == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
				ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
		return 0;
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_csids->local_csid[itr];
		key.node_addr = peer_csids->node_addr;

		tmp = get_peer_csid_entry(&key, iface);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		csids.node_addr = tmp->node_addr;
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Found Local CSIDs, Node_Addr:"IPV4_ADDR", Num_CSID:%u\n",
				ERR_MSG, IPV4_ADDR_HOST_FORMAT(csids.node_addr), csids.num_csid);
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"CSIDs are already cleanup\n", ERR_MSG);
		return 0;
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s\n", ERR_MSG);
		return 0;
	}

	ret = del_csid_entry_hash(peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	if (iface != SX_PORT_ID) {
		fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, iface);

		/* Send the Delete set Request to peer node */
		uint8_t pfcp_msg[1024]={0};
		int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);

		pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
		header->message_len = htons(encoded - 4);

		/* TODO: here we need SGWC or PGWC node address , ask vishal where we found node address for send req */
		if (sendto(my_sock.sock_fd,
			(char *)pfcp_msg,
			encoded,
			MSG_DONTWAIT,
			(struct sockaddr *)&dest_addr_t,
			sizeof(struct sockaddr_in)) < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "Error sending: %i\n",errno);
				return -1;
		}
		else {
			update_cli_stats(dest_addr_t.sin_addr.s_addr, header->message_type, SENT, SX);
		}
		clLog(clSystemLog, eCLSeverityDebug, "UP: Send the PFCP Session Set Deletion Request \n");
	}

	clLog(clSystemLog, eCLSeverityDebug, "UP Cleanup completed for peer node \n");
	return 0;
}

int8_t
process_up_sess_set_del_req(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req)
{
	int ret = 0;
	fqcsid_t csids = {0};
	fqcsid_t peer_csids = {0};

	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Set Deletion Request :: START \n");
	/* MME FQ-CSID */
	if (pfcp_sess_set_del_req->mme_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->mme_fqcsid.number_of_csids) {
			peer_csids.num_csid = pfcp_sess_set_del_req->mme_fqcsid.number_of_csids;
			for (uint8_t itr = 0; itr < pfcp_sess_set_del_req->mme_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->mme_fqcsid.pdn_conn_set_ident[itr];
				key.node_addr = pfcp_sess_set_del_req->mme_fqcsid.node_address;

				tmp = get_peer_csid_entry(&key, SX_PORT_ID);

				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[itr] =
						pfcp_sess_set_del_req->mme_fqcsid.pdn_conn_set_ident[itr];
			}
			peer_csids.node_addr = pfcp_sess_set_del_req->mme_fqcsid.node_address;
		}
	}

	/* SGW FQ-CSID */
	if (pfcp_sess_set_del_req->sgw_c_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids) {
			peer_csids.num_csid = pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids;
			for (uint8_t itr = 0; itr < pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
				key.node_addr = pfcp_sess_set_del_req->sgw_c_fqcsid.node_address;

				tmp = get_peer_csid_entry(&key, SX_PORT_ID);

				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[itr] =
						pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
			peer_csids.node_addr = pfcp_sess_set_del_req->sgw_c_fqcsid.node_address;
		}
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_set_del_req->pgw_c_fqcsid.header.len) {
		if (pfcp_sess_set_del_req->pgw_c_fqcsid.number_of_csids) {
			peer_csids.num_csid =  pfcp_sess_set_del_req->pgw_c_fqcsid.number_of_csids;
			for (uint8_t itr = 0; itr < peer_csids.num_csid; itr++) {
				/* Get linked local csid */
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
				key.node_addr = pfcp_sess_set_del_req->pgw_c_fqcsid.node_address;

				tmp = get_peer_csid_entry(&key, SX_PORT_ID);
				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				/* TODO: Hanlde Multiple CSID with single MME CSID */
				for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
				}

				peer_csids.local_csid[itr] =
						pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
			}
			peer_csids.node_addr = pfcp_sess_set_del_req->pgw_c_fqcsid.node_address;
		}
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				FORMAT"Not found peer CSIDs \n", ERR_MSG);
		return -1;
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	ret = del_csid_entry_hash(&peer_csids, &csids, SX_PORT_ID);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug, "PFCP Session Set Deletion Request :: END \n\n");
	return 0;
}

int8_t
del_sess_by_csid_entry(pfcp_session_t *sess, fqcsid_t *csids, uint8_t iface)
{
	int ret = 0;
	uint16_t num_csid = csids->num_csid;

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < num_csid; itr++) {
		sess_csid *seids = NULL;

		seids = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (seids == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
			return -1;
		}

		seids = remove_sess_csid_data_node(seids, sess->up_seid);

		/* Update CSID Entry in table */
	    ret = rte_hash_add_key_data(seids_by_csid_hash,
				&csids->local_csid[itr], seids);
		if (ret) {
			clLog(clSystemLog, eCLSeverityCritical,
					FORMAT"Failed to add Session IDs entry for CSID = %u"
					"\n\tError= %s\n",
					ERR_MSG, csids->local_csid[itr],
					rte_strerror(abs(ret)));
			return -1;
		}

		if (seids == NULL) {
			if (app.spgw_cfg != PGWU) {
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:SGWC/SAEGWC Node Addr:"IPV4_ADDR"\n",
						ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->sgw_fqcsid)->node_addr));
				if (del_csid_entry_hash(sess->sgw_fqcsid, csids,
							SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				if (app.spgw_cfg != SAEGWU) {
					clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:PGWC Node Addr:"IPV4_ADDR"\n",
							ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->pgw_fqcsid)->node_addr));
					if (del_csid_entry_hash(sess->pgw_fqcsid, csids,
							SX_PORT_ID)) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}
					if (sess->pgwu_fqcsid) {
						clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:PGWU Node Addr:"IPV4_ADDR"\n",
								ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->pgwu_fqcsid)->node_addr));
						if (del_csid_entry_hash(sess->pgwu_fqcsid, csids,
								SGI_PORT_ID)) {
							clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
							return -1;
						}
					}
				}

				if (sess->mme_fqcsid) {
					clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:MME Node Addr:"IPV4_ADDR"\n",
							ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->mme_fqcsid)->node_addr));
					if (del_csid_entry_hash(sess->mme_fqcsid, csids,
								SX_PORT_ID)) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}
				}

				if (sess->enb_fqcsid) {
					clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:eNB Node Addr:"IPV4_ADDR"\n",
							ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->enb_fqcsid)->node_addr));
					if (del_csid_entry_hash(sess->enb_fqcsid, csids,
							S1U_PORT_ID)) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}
				}
			} else {
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:PGWC Node Addr:"IPV4_ADDR"\n",
						ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->pgw_fqcsid)->node_addr));
				if (del_csid_entry_hash(sess->pgw_fqcsid, csids,
						SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:SGWC Node Addr:"IPV4_ADDR"\n",
						ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->sgw_fqcsid)->node_addr));
				if (del_csid_entry_hash(sess->sgw_fqcsid, csids,
						SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:MME Node Addr:"IPV4_ADDR"\n",
						ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->mme_fqcsid)->node_addr));
				if (del_csid_entry_hash(sess->mme_fqcsid, csids,
						SX_PORT_ID)) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}
				if (sess->sgwu_fqcsid) {
					clLog(clSystemLog, eCLSeverityDebug, FORMAT"PDSR:SGWU Node Addr:"IPV4_ADDR"\n",
							ERR_MSG, IPV4_ADDR_HOST_FORMAT((sess->sgwu_fqcsid)->node_addr));
					if (del_csid_entry_hash(sess->sgwu_fqcsid, csids,
							S1U_PORT_ID)) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}
				}
			}

			if (del_sess_csid_entry(csids->local_csid[itr])) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* Decrement the csid counters */
			csids->num_csid--;
		}

	}

	return 0;
}

//int8_t
//del_sess_by_csid_entry(fqcsid_t *peer_csids, fqcsid_t *csids, uint64_t sess_id, uint8_t iface)
//{
//	int ret = 0;
//
//	/* Get the session ID by csid */
//	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
//		sess_csid *seids = NULL;
//
//		seids = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
//		if (seids == NULL) {
//			ret = del_csid_entry_hash(peer_csids, csids, iface);
//			if (ret) {
//				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
//						strerror(errno));
//				return -1;
//			}
//			return 0;
//		}
//
//		seids = remove_sess_csid_data_node(seids, sess_id);
//
//		/* Update CSID Entry in table */
//	    ret = rte_hash_add_key_data(seids_by_csid_hash,
//				&csids->local_csid[itr], seids);
//		if (ret) {
//			clLog(clSystemLog, eCLSeverityCritical,
//					FORMAT"Failed to add Session IDs entry for CSID = %u"
//					"\n\tError= %s\n",
//					ERR_MSG, csids->local_csid[itr],
//					rte_strerror(abs(ret)));
//			return -1;
//		}
//
//		if (seids == NULL) {
//			ret = del_csid_entry_hash(peer_csids, csids, iface);
//			if (ret) {
//				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
//						strerror(errno));
//				return -1;
//			}
//
//			if (del_sess_csid_entry(csids->local_csid[itr])) {
//				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
//						strerror(errno));
//				//return -1;
//			}
//			/* Decrement the csid counters */
//			//csids->num_csid--;
//		}
//
//	}
//	return 0;
//}
/* Function */
//int
//process_pfcp_sess_set_del_rsp_t(pfcp_sess_set_del_rsp_t *del_set_rsp)
//{
//	if(del_set_rsp->cause.cause_value != REQUESTACCEPTED){
//		clLog(clSystemLog, eCLSeverityCritical, FORMAT"ERROR:Cause received Session Set deletion response is %d\n",
//				ERR_MSG, del_set_rsp->cause.cause_value);
//
//		/* TODO: Add handling to send association to next upf
//		 * for each buffered CSR */
//		return -1;
//	}
//	return 0;
//}

