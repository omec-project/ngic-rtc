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

#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "clogger.h"
#include "gw_adapter.h"

#ifdef CP_BUILD
#include "cp.h"

extern pfcp_config_t pfcp_config;
extern int pfcp_fd;
extern struct sockaddr_in upf_pfcp_sockaddr;
#else
#include "up_main.h"
extern struct in_addr dp_comm_ip;
extern struct in_addr cp_comm_ip;
#endif /* CP_BUILD */

/* PFCP: Create and Fill the FQ-CSIDs */
void
set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids)
{
	fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;

	fq_csid->number_of_csids = csids->num_csid;

	fq_csid->node_address = csids->node_addr;

	for(uint8_t itr = 0; itr < fq_csid->number_of_csids; itr++) {
		fq_csid->pdn_conn_set_ident[itr] = csids->local_csid[itr];
	}

	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID, (2 * (fq_csid->number_of_csids)) + 5);

}

#ifdef CP_BUILD
void
set_gtpc_fqcsid_t(gtp_fqcsid_ie_t *fqcsid,
		enum ie_instance instance, fqcsid_t *csids)
{
	set_ie_header(&fqcsid->header, GTP_IE_FQCSID,
		instance, 0);

	fqcsid->node_id_type = 0;
	fqcsid->number_of_csids = csids->num_csid;
	fqcsid->node_address = csids->node_addr;

	for (uint8_t itr = 0; itr <fqcsid->number_of_csids; itr++) {
		fqcsid->pdn_csid[itr] = csids->local_csid[itr];
	}

	fqcsid->header.len = (2 * (fqcsid->number_of_csids) + 5);
	return;
}

int
fill_peer_node_info(pdn_connection *pdn,
				eps_bearer *bearer)
{
	int16_t local_csid = 0;
	csid_key peer_info = {0};

	/* MME FQ-CSID */
	if (((pdn->context)->mme_fqcsid)->num_csid) {
		peer_info.mme_ip = ((pdn->context)->mme_fqcsid)->node_addr;
	} else {
		/* IF MME not support partial failure */
		peer_info.mme_ip = (pdn->context)->s11_mme_gtpc_ipv4.s_addr;
	}

	/* SGW FQ-CSID */
	if (((pdn->context)->sgw_fqcsid)->num_csid) {
		peer_info.sgwc_ip = ((pdn->context)->sgw_fqcsid)->node_addr;
	} else {
		/* IF SGWC not support partial failure */
		if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
			peer_info.sgwc_ip = (pdn->context)->s11_sgw_gtpc_ipv4.s_addr;
		} else {
			peer_info.sgwc_ip = pdn->s5s8_sgw_gtpc_ipv4.s_addr;
		}
	}

	/* Fill the enodeb ID */
	peer_info.enodeb_id = ((pdn->context)->uli.ecgi2.eci >> 8);

	/* SGW and PGW peer node info */
	if (pfcp_config.cp_type == SGWC) {
		peer_info.pgwc_ip = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	} else if (pfcp_config.cp_type == PGWC) {
		peer_info.pgwc_ip = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	}

	/* SGWU and PGWU peer node info */
	if (pfcp_config.cp_type == SAEGWC) {
		peer_info.sgwu_ip = pdn->upf_ipv4.s_addr;
	} else if (pfcp_config.cp_type == SGWC) {
		peer_info.sgwu_ip = pdn->upf_ipv4.s_addr;
		peer_info.pgwu_ip = bearer->s5s8_pgw_gtpu_ipv4.s_addr;
	} else if (pfcp_config.cp_type == PGWC) {
		peer_info.sgwu_ip = bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		peer_info.pgwu_ip = pdn->upf_ipv4.s_addr;
	}

	/* Get local csid for set of peer node */
	local_csid = get_csid_entry(&peer_info);
	if (local_csid < 0) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Failed to assinged CSID..\n", ERR_MSG);
		return -1;
	}

	/* Update the local csid into the UE context */
	uint8_t match = 0;
	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
		for(uint8_t itr = 0; itr < ((pdn->context)->sgw_fqcsid)->num_csid; itr++) {
			if (((pdn->context)->sgw_fqcsid)->local_csid[itr] == local_csid)
				match = 1;
		}

		if (!match) {
			((pdn->context)->sgw_fqcsid)->local_csid[((pdn->context)->sgw_fqcsid)->num_csid++] =
				local_csid;
			match = 0;
		}
	} else {
		for(uint8_t itr = 0; itr < ((pdn->context)->pgw_fqcsid)->num_csid; itr++) {
			if (((pdn->context)->pgw_fqcsid)->local_csid[itr] == local_csid)
				match = 1;
		}

		if (!match) {
			((pdn->context)->pgw_fqcsid)->local_csid[((pdn->context)->pgw_fqcsid)->num_csid++] =
				local_csid;
			match = 0;
		}

	}

	/* Link local CSID with MME CSID */
	if (((pdn->context)->mme_fqcsid)->num_csid) {
		csid_t *tmp = NULL;
		tmp = get_peer_csid_entry(
				&((pdn->context)->mme_fqcsid)->local_csid[((pdn->context)->mme_fqcsid)->num_csid - 1],
				S11_SGW_PORT_ID);
		if (tmp == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}

		/* Link local csid with MME CSID */
		if (tmp->local_csid == 0) {
			tmp->local_csid = local_csid;
		} else if (tmp->local_csid != local_csid){
			/* TODO: handle condition like single MME CSID link with multiple local CSID  */
		}

		/* Update the Node Addr */
		if (pfcp_config.cp_type != PGWC)
			tmp->node_addr = ((pdn->context)->sgw_fqcsid)->node_addr;
		else
			tmp->node_addr = ((pdn->context)->pgw_fqcsid)->node_addr;
	}

	/* TODO: Need to think on it*/
	/* Adde entry of local CSID */
	//if (((pdn->context)->sgw_fqcsid)->num_csid) {
	//	csid_t *tmp1 = NULL;
	//	/* Need to think on it*/
	//	if ((pfcp_config.cp_type == SGWC) || (pfcp_config.cp_type == SAEGWC)) {
	//		tmp1 = get_peer_csid_entry(
	//				&((pdn->context)->sgw_fqcsid)->local_csid[((pdn->context)->sgw_fqcsid)->num_csid - 1],
	//				S11_SGW_PORT_ID);
	//	} else {
	//		tmp1 = get_peer_csid_entry(
	//				&((pdn->context)->pgw_fqcsid)->local_csid[((pdn->context)->pgw_fqcsid)->num_csid - 1],
	//				S5S8_PGWC_PORT_ID);
	//	}
	//	if (tmp1 == NULL) {
	//		clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
	//				strerror(errno));
	//		return -1;
	//	}

	//	/* Link local csid with MME CSID */
	//	if (tmp1->local_csid == 0) {
	//		/* Update csid by mme csid */
	//		tmp1->local_csid = local_csid;
	//	} else if (tmp1->local_csid != local_csid){
	//		/* TODO: handle condition like single MME CSID link with multiple local CSID  */
	//	}
	//}

	/* PGW Link local CSID with SGW CSID */
	if (((pdn->context)->sgw_fqcsid)->num_csid) {
		csid_t *tmp1 = NULL;
		if (pfcp_config.cp_type == PGWC) {
			tmp1 = get_peer_csid_entry(
					&((pdn->context)->sgw_fqcsid)->local_csid[((pdn->context)->sgw_fqcsid)->num_csid - 1],
					S5S8_PGWC_PORT_ID);

			if (tmp1 == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			/* Link local csid with SGW CSID */
			if (tmp1->local_csid == 0) {
				/* Update csid by mme csid */
				tmp1->local_csid = local_csid;
			} else if (tmp1->local_csid != local_csid){
				/* TODO: handle condition like single SGW CSID link with multiple local CSID  */
			}
			/* Update the node address */
			tmp1->node_addr = ((pdn->context)->pgw_fqcsid)->node_addr;
		}
	}

	return 0;
}


int
csrsp_fill_peer_node_info(create_sess_req_t *csr, pdn_connection *pdn,
				eps_bearer *bearer)
{
	RTE_SET_USED(csr);
	RTE_SET_USED(pdn);
	RTE_SET_USED(bearer);
	//csid_key peer_info = {0};
	//fq_csids *csids = NULL;

	///* SGW FQ-CSID */
	//if (csr->sgw_fqcsid.header.len) {
	//	for(int itr = 0; itr < csr->sgw_fqcsid.number_of_csids; itr++) {
	//		csids->sgwc_csid[itr] = csr->sgw_fqcsid.pdn_csid[itr];
	//	}
	//	peer_info.sgwc_ip = csr->sgw_fqcsid.node_address;
	//} else {
	//	/* IF SGW not support partial failure */
	//	peer_info.sgwc_ip = (pdn->context)->s11_sgw_gtpc_ipv4.s_addr;
	//}

	///* PGW FQ-CSID */
	//if (csr->pgw_fqcsid.header.len) {
	//	for(uint8_t itr = 0; itr < csr->pgw_fqcsid.number_of_csids; itr++) {
	//		csids->pgwc_csid[itr] = csr->pgw_fqcsid.pdn_csid[itr];
	//	}
	//	peer_info.pgwc_ip = csr->pgw_fqcsid.node_address;
	//} else {
	//	/* IF PGWC not support partial failure */
	//	peer_info.pgwc_ip = (pdn->context)->s11_sgw_gtpc_ipv4.s_addr;
	//}

	return 0;
}

/*
static void
fill_gtpc_sess_set_del_req()
{

}
*/
/* In partial failure support initiate the Request to cleanup peer node sessions based on FQ-CSID */
//int8_t
//gen_gtpc_sess_deletion_req()
//{
//
//
//	return 0;
//}

int8_t
update_peer_csid_link(fqcsid_t *fqcsid, fqcsid_t *fqcsid_t)
{
	/* Link local CSID with peer node CSID */
	if (fqcsid->num_csid) {
		for (uint8_t itr = 0; itr < fqcsid->num_csid; itr++) {
			csid_t *tmp = NULL;
			tmp = get_peer_csid_entry(
					&(fqcsid->local_csid[itr]),
					SX_PORT_ID);
			if (tmp == NULL) {
				clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			/* Link local csid with MME CSID */
			if (tmp->local_csid == 0) {
				tmp->local_csid = fqcsid_t->local_csid[itr];
			} else if (tmp->local_csid != fqcsid_t->local_csid[itr]){
				/* TODO: handle condition like single MME CSID link with multiple local CSID  */
			}
			/* Update the Node address */
			tmp->node_addr = fqcsid_t->node_addr;
		}
	}
	return 0;
}

int8_t
fill_fqcsid_sess_est_req(pfcp_sess_estab_req_t *pfcp_sess_est_req, ue_context *context)
{
	/* Spec don't have support to idetify */
	/* Set MME FQ-CSID */
	//if ((context->mme_fqcsid)->num_csid) {
	//	set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, context->mme_fqcsid);
	//}

	if (pfcp_config.cp_type != PGWC) {
		/* Set SGW FQ-CSID */
		if ((context->sgw_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, context->sgw_fqcsid);
			(pfcp_sess_est_req->sgw_c_fqcsid).node_address = pfcp_config.pfcp_ip.s_addr;
		}

	} else {
		/* Set PGW FQ-CSID */
		if ((context->pgw_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->pgw_c_fqcsid, context->pgw_fqcsid);
			(pfcp_sess_est_req->pgw_c_fqcsid).node_address = pfcp_config.pfcp_ip.s_addr;
		}
	}

	return 0;
}
#endif /* CP_BUID */


static uint16_t seq_t = 0;

void
fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids, uint8_t iface)
{
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, NO_SEID, ++seq_t);

	char pAddr[INET_ADDRSTRLEN];

#ifdef CP_BUILD
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
#else
	inet_ntop(AF_INET, &(dp_comm_ip.s_addr), pAddr, INET_ADDRSTRLEN);
#endif /* CP_BUILD */

	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	if (local_csids->num_csid) {
		/* Set the SGWC FQ-CSID */
		if ((iface == S11_SGW_PORT_ID) ||
				(iface == S5S8_SGWC_PORT_ID)) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, local_csids);
		}

		if (iface == S5S8_PGWC_PORT_ID) {
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);
		}
	}

	/* Set the MME FQ-CSID */
	//if (local_csids->num_csid) {
	//	set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, local_csids);

	//}

	/* Set the SGWU FQ-CSID */
	//if (local_csids->num_csid) {
	//	set_fq_csid_t(&pfcp_sess_set_del_req->sgw_u_fqcsid, local_csids);

	//}

	///* Set the PGWC FQ-CSID */
	//if (local_csids->num_csid) {
	//	set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);

	//}

	///* Set the PGWU FQ-CSID */
	//if (local_csids->num_csid) {
	//	set_fq_csid_t(&pfcp_sess_set_del_req->pgw_u_fqcsid, local_csids);

	//}
}

/* Cleanup Session information by local csid*/
int8_t
del_pfcp_peer_node_sess(uint32_t node_addr, uint8_t iface)
{
	pfcp_sess_set_del_req_t del_set_req_t = {0};
	fqcsid_t *local_csids = NULL;
	fqcsid_t csids = {0};

	/* Get local CSID associated with node */
	local_csids = get_peer_addr_csids_entry(node_addr,
			MOD);

	if (local_csids == NULL) {
		clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		return -1;
	}

	/* Get the mapped local CSID */
	csids.num_csid = local_csids->num_csid;
	for (int8_t itr = 0; itr < local_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		tmp = get_peer_csid_entry(&local_csids->local_csid[itr],
				iface);
		if (tmp == NULL) {
			clLog(apilogger, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			return -1;
		}
		csids.local_csid[itr] = tmp->local_csid;
		csids.node_addr = tmp->node_addr;
	}

	if (!csids.num_csid) {
		clLog(apilogger, eCLSeverityDebug, FORMAT"Csids are empty \n", ERR_MSG);
		return 0;
	}

#ifdef CP_BUILD
		csids.node_addr = pfcp_config.pfcp_ip.s_addr;
#endif /* CP_BUILD */

	fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, iface);

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef CP_BUILD
	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr) < 0 ) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error sending: %i\n",
				ERR_MSG, errno);
		return -1;
	}
#else
	if (sendto(my_sock.sock_fd,
		(char *)pfcp_msg,
		encoded,
		MSG_DONTWAIT,
		(struct sockaddr *)&dest_addr_t,
		sizeof(struct sockaddr_in)) < 0) {
		clLog(clSystemLog, eCLSeverityDebug, "Error sending: %i\n",errno);
			return -1;
	}
#endif /* CP_BUILD */
	return 0;
}

/* Fill PFCP SESSION SET SELETION RESPONSE */
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_del_resp,
			uint8_t cause_val, int offending_id)
{
	memset(pfcp_del_resp, 0, sizeof(pfcp_sess_set_del_rsp_t));

	set_pfcp_header(&pfcp_del_resp->header, PFCP_SESS_SET_DEL_RSP, 0);
#ifdef CP_BUILD
	set_node_id(&(pfcp_del_resp->node_id), pfcp_config.pfcp_ip.s_addr);
#else
	set_node_id(&(pfcp_del_resp->node_id), dp_comm_ip.s_addr);
#endif /* CP_BUILD */
	pfcp_set_ie_header(&pfcp_del_resp->cause.header, PFCP_IE_CAUSE,
			sizeof(pfcp_del_resp->cause.cause_value));
	pfcp_del_resp->cause.cause_value = cause_val;

	RTE_SET_USED(offending_id);
	//pfcp_set_ie_header(&pfcp_del_resp->offending_ie.header, PFCP_IE_OFFENDING_IE,
	//		sizeof(pfcp_del_resp->offending_ie.type_of_the_offending_ie));
	//pfcp_del_resp->offending_ie.type_of_the_offending_ie = (uint16_t)offending_id;
}

int8_t
del_csid_entry_hash(fqcsid_t *peer_csids,
				fqcsid_t *local_csids, uint8_t iface)
{
	if (peer_csids != NULL) {
		if (del_peer_addr_csids_entry(peer_csids->node_addr)) {
			clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
					strerror(errno));
			/* TODO ERROR HANDLING */
			return -1;
		}

		for (int itr = 0; itr < peer_csids->num_csid; itr++) {
			if (del_peer_csid_entry(&peer_csids->local_csid[itr], iface)) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				/* TODO ERROR HANDLING */
				return -1;
			}
		}
		/* Reset the seid counters */
		//peer_csids->num_csid = 0;
		//rte_free(peer_csids);
		//peer_csids = NULL;
	}

	if (local_csids != NULL) {
		for (int itr1 = 0; itr1 < local_csids->num_csid; itr1++) {
			if (del_sess_csid_entry(local_csids->local_csid[itr1])) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				/* TODO ERROR HANDLING */
				//return -1;
			}
		}

		//if (del_peer_addr_csids_entry(local_csids->node_addr)) {
		//	clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
		//			strerror(errno));
		//	/* TODO ERROR HANDLING */
		//	//return -1;
		//}
		/* Reset the seid counters */
		local_csids->num_csid = 0;
	}
	return 0;

}

