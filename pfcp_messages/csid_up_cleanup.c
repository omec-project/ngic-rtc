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
#include "pfcp_messages_encoder.h"
#include "clogger.h"

static int8_t
cleanup_sess_by_csid_entry(fqcsid_t *csids)
{
	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *tmp = NULL;

		tmp = get_sess_csid_entry(csids->local_csid[itr]);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		for (uint16_t itr1 = 0; itr1 < tmp->seid_cnt; itr1++) {
			pfcp_session_t *sess = NULL;

			/* Get the session information from session table based on UP_SESSION_ID*/
			/* Check SEID is not ZERO */
			sess = get_sess_info_entry(tmp->up_seid[itr1],
					SESS_DEL);

			if (sess == NULL)
				continue;

			if (up_delete_session_entry(sess))
				continue;

			/* Cleanup the session */
			rte_free(sess);
			sess = NULL;

		}
	}
	return 0;
}

/* Cleanup Session information by local csid*/
int8_t
up_del_pfcp_peer_node_sess(uint32_t node_addr, uint8_t iface)
{
	int ret = 0;
	fqcsid_t csids = {0};
	fqcsid_t *peer_csids = NULL;

	clLog(clSystemLog, eCLSeverityDebug, "UP Cleanup Internal data Structures For peer node \n");
	/* Get peer CSID associated with node */
	peer_csids = get_peer_addr_csids_entry(ntohl(node_addr),
			MOD);

	if (peer_csids == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Get the mapped local CSID */
	csids.num_csid = peer_csids->num_csid;
	for (int8_t itr = 0; itr < peer_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		tmp = get_peer_csid_entry(&peer_csids->local_csid[itr],
				iface);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		csids.local_csid[itr] = tmp->local_csid;
		csids.node_addr = tmp->node_addr;
	}

	/* Cleanup Internal data structures */
	ret = cleanup_sess_by_csid_entry(&csids);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	ret = del_csid_entry_hash(peer_csids, &csids, iface);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
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
	/* SGW FQ-CSID */
	if (pfcp_sess_set_del_req->sgw_c_fqcsid.header.len) {
		csids.num_csid = pfcp_sess_set_del_req->sgw_c_fqcsid.number_of_csids;
		peer_csids.num_csid = csids.num_csid;
		for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(
					&pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr],
					SX_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			csids.local_csid[itr] = tmp->local_csid;
			peer_csids.local_csid[itr] =
					pfcp_sess_set_del_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
		}
		peer_csids.node_addr = pfcp_sess_set_del_req->sgw_c_fqcsid.node_address;
	}

	/* PGW FQ-CSID */
	if (pfcp_sess_set_del_req->pgw_c_fqcsid.header.len) {
		csids.num_csid = pfcp_sess_set_del_req->pgw_c_fqcsid.number_of_csids;
		peer_csids.num_csid = csids.num_csid;
		for (uint8_t itr = 0; itr < csids.num_csid; itr++) {
			/* Get linked local csid */
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(
					&pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr],
					SX_PORT_ID);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
			/* TODO: Hanlde Multiple CSID with single MME CSID */
			csids.local_csid[itr] = tmp->local_csid;
			peer_csids.local_csid[itr] =
					pfcp_sess_set_del_req->pgw_c_fqcsid.pdn_conn_set_ident[itr];
		}
		peer_csids.node_addr = pfcp_sess_set_del_req->pgw_c_fqcsid.node_address;
	}

	if (csids.num_csid == 0) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Not received any CSID from peer node \n", ERR_MSG);
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
del_sess_by_csid_entry(fqcsid_t *peer_csids, fqcsid_t *csids, uint64_t sess_id)
{
	int ret = 0;

	/* Get the session ID by csid */
	for (uint16_t itr = 0; itr < csids->num_csid; itr++) {
		sess_csid *seids = NULL;

		seids = get_sess_csid_entry(csids->local_csid[itr]);
		if (seids == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		/* VS: Delete sess id from csid table */
		for(uint32_t cnt = 0; cnt < seids->seid_cnt; cnt++) {
			if (sess_id == seids->up_seid[cnt]) {
				for(uint32_t pos = cnt; pos < (seids->seid_cnt - 1); pos++ )
					seids->up_seid[pos] = seids->up_seid[pos + 1];

				seids->seid_cnt--;
				clLog(clSystemLog, eCLSeverityDebug, "Session Deleted from csid table sid:%lu\n",
						sess_id);
			}
		}

		if (seids->seid_cnt == 0) {
			/* Need to think on it */
			ret = del_csid_entry_hash(peer_csids, csids, SX_PORT_ID);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}
		}

	}
	return 0;
}
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

