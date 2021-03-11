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

#include "pfcp_util.h"
#include "pfcp_enum.h"
#include "csid_struct.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "gw_adapter.h"
#include "pfcp_session.h"

extern int clSystemLog;
#ifdef CP_BUILD
#include "cp.h"
#include "cp_timer.h"
#include "seid_llist.h"
extern pfcp_config_t config;
extern int pfcp_fd;
extern int pfcp_fd_v6;
extern peer_addr_t upf_pfcp_sockaddr;
#else
#include "up_main.h"
#include "seid_llist.h"
extern struct in_addr dp_comm_ip;
extern struct in6_addr dp_comm_ipv6;
extern uint8_t dp_comm_ip_type;
extern struct in_addr cp_comm_ip;
extern struct app_params app;

int8_t
stored_recvd_peer_fqcsid(pfcp_fqcsid_ie_t *peer_fqcsid, fqcsid_t *local_fqcsid)
{
	fqcsid_t *tmp = NULL;
	node_address_t node_addr = {0};

	if (peer_fqcsid->fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
		node_addr.ip_type = IPV4_TYPE;
		memcpy(&node_addr.ipv4_addr,
				&peer_fqcsid->node_address, IPV4_SIZE);
	} else if (peer_fqcsid->fqcsid_node_id_type == IPV6_GLOBAL_UNICAST) {
		node_addr.ip_type = IPV6_TYPE;
		memcpy(&node_addr.ipv6_addr,
				&peer_fqcsid->node_address, IPV6_SIZE);
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Not supporting MCC and MNC as node address \n", LOG_VALUE);
		return -1;
	}

	/* Stored the Peer CSID by Peer Node address */
	tmp = get_peer_addr_csids_entry(&node_addr, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
				strerror(errno));
		return -1;
	}

	memcpy(&(tmp->node_addr), &(node_addr), sizeof(node_address_t));

	for(uint8_t itr = 0; itr < peer_fqcsid->number_of_csids; itr++) {
		uint8_t match = 0;
		for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			if (tmp->local_csid[itr1] == peer_fqcsid->pdn_conn_set_ident[itr]){
				match = 1;
				break;
			}
		}
		if (!match) {
			tmp->local_csid[tmp->num_csid++] =
				peer_fqcsid->pdn_conn_set_ident[itr];
		}
	}

	for(uint8_t itr1 = 0; itr1 < peer_fqcsid->number_of_csids; itr1++) {
			local_fqcsid->local_csid[local_fqcsid->num_csid++] =
				peer_fqcsid->pdn_conn_set_ident[itr1];
	}
	memcpy(&(local_fqcsid->node_addr), &(node_addr), sizeof(node_address_t));

	return 0;
}

int8_t
link_peer_csid_with_local_csid(fqcsid_t *peer_fqcsid,
		fqcsid_t *local_fqcsid, uint8_t iface)
{
	/* LINK Peer CSID with local CSID */
	if (peer_fqcsid->num_csid) {
		for (uint8_t itr = 0; itr < peer_fqcsid->num_csid; itr++) {
			csid_t *tmp1 = NULL;
			csid_key_t key = {0};
			key.local_csid = peer_fqcsid->local_csid[itr];
			memcpy(&key.node_addr,
					&peer_fqcsid->node_addr, sizeof(node_address_t));

			tmp1 = get_peer_csid_entry(&key, iface, ADD_NODE);
			if (tmp1 == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
						strerror(errno));
				return -1;
			}

			if (!tmp1->num_csid) {
				tmp1->local_csid[tmp1->num_csid++] =
					local_fqcsid->local_csid[local_fqcsid->num_csid - 1];
			} else {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp1->num_csid; itr1++) {
					if (tmp1->local_csid[itr1] ==
							local_fqcsid->local_csid[local_fqcsid->num_csid - 1]) {
						match = 1;
						break;
					}
				}
				if (!match) {
					tmp1->local_csid[tmp1->num_csid++] =
						local_fqcsid->local_csid[local_fqcsid->num_csid - 1];
				}
			}
			memcpy(&tmp1->node_addr,
					&local_fqcsid->node_addr, sizeof(node_address_t));
		}
	}
	return 0;
}

int
link_dp_sess_with_peer_csid(fqcsid_t *peer_csid, pfcp_session_t *sess, uint8_t iface)
{
	/* Add entry for cp session id with link local csid */
	sess_csid *tmp = NULL;
	uint8_t num_csid = 0;
	peer_csid_key_t key = {0};

	key.iface = iface;
	key.peer_local_csid = peer_csid->local_csid[num_csid];
	memcpy(&key.peer_node_addr,
			&peer_csid->node_addr, sizeof(node_address_t));

	tmp = get_sess_peer_csid_entry(&key, ADD_NODE);
	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get peer CSID "
				"entry, Error: %s \n", LOG_VALUE,strerror(errno));
		return -1;
	}

	/* Link local csid with session id */
	/* Check head node created ot not */
	if(tmp->up_seid != sess->up_seid && tmp->up_seid != 0) {
		sess_csid *new_node = NULL;
		/* Add new node into csid linked list */
		new_node = add_peer_csid_sess_data_node(tmp, &key);
		if(new_node == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to ADD new "
					"node into peer CSID linked list : %s\n", LOG_VALUE);
			return -1;
		} else {
			new_node->cp_seid = sess->cp_seid;
			new_node->up_seid = sess->up_seid;
		}

	} else {
		tmp->cp_seid = sess->cp_seid;
		tmp->up_seid = sess->up_seid;
		tmp->next = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Link Session "
				"[ CP seid : %u ] [ DP seid : %u ] with CSID : %u"
				" Linked List \n", LOG_VALUE, tmp->cp_seid,
				tmp->up_seid, peer_csid->local_csid[num_csid]);

	return 0;
}
#endif /* CP_BUILD */

/* PFCP: Create and Fill the FQ-CSIDs */
void
set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids)
{
	uint16_t len = 0;

	fq_csid->number_of_csids = csids->num_csid;

	if ((csids->node_addr.ip_type == PDN_TYPE_IPV4)
			|| (csids->node_addr.ip_type == IPV4_GLOBAL_UNICAST))  {
		fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;
		memcpy(fq_csid->node_address,
				&csids->node_addr.ipv4_addr, IPV4_SIZE);
		len += IPV4_SIZE;
	} else {
		fq_csid->fqcsid_node_id_type = IPV6_GLOBAL_UNICAST;
		memcpy(fq_csid->node_address,
				&csids->node_addr.ipv6_addr, IPV6_SIZE);
		len += IPV6_SIZE;
	}

	for(uint8_t itr = 0; itr < fq_csid->number_of_csids; itr++) {
		fq_csid->pdn_conn_set_ident[itr] = csids->local_csid[itr];
	}

	/* Adding 1 byte in the header for flags */
	len += PRESENT;

	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID, (2 * (fq_csid->number_of_csids)) + len);

}

#ifdef CP_BUILD
void
set_gtpc_fqcsid_t(gtp_fqcsid_ie_t *fqcsid,
		enum ie_instance instance, fqcsid_t *csids)
{
	/* Added 1 byte for Node_ID and Number of csids*/
	uint8_t len = 1;

	set_ie_header(&fqcsid->header, GTP_IE_FQCSID,
		instance, 0);

	fqcsid->number_of_csids = csids->num_csid;

	if((csids->node_addr.ip_type == IPV4_GLOBAL_UNICAST)
			|| (csids->node_addr.ip_type == PDN_TYPE_IPV4)) {
		fqcsid->node_id_type = IPV4_GLOBAL_UNICAST;
		memcpy(&(fqcsid->node_address),
				&(csids->node_addr.ipv4_addr), IPV4_SIZE);
		len += IPV4_SIZE;
	} else {
		fqcsid->node_id_type = IPV6_GLOBAL_UNICAST;
		memcpy(&(fqcsid->node_address),
				&(csids->node_addr.ipv6_addr), IPV6_SIZE);
		len += IPV6_SIZE;
	}

	for (uint8_t itr = 0; itr <fqcsid->number_of_csids; itr++) {
		fqcsid->pdn_csid[itr] = csids->local_csid[itr];
	}

	fqcsid->header.len = (2 * (fqcsid->number_of_csids) + len);
	return;
}

void
fill_node_addr_info(node_address_t *dst_info, node_address_t *src_info) {

	if ((src_info->ip_type == IPV4_GLOBAL_UNICAST)
			|| (src_info->ip_type == PDN_TYPE_IPV4)) {
		dst_info->ip_type = src_info->ip_type;
		dst_info->ipv4_addr = src_info->ipv4_addr;
	} else {
		dst_info->ip_type = src_info->ip_type;
		memcpy(&(dst_info->ipv6_addr),
				&(src_info->ipv6_addr), IPV6_ADDRESS_LEN);
	}
}

/* Linked the Peer CSID with local CSID */
int8_t
link_gtpc_peer_csids(fqcsid_t *peer_fqcsid, fqcsid_t *local_fqcsid,
		uint8_t iface)
{
	if (local_fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Local CSID is NULL, ERR:\n", LOG_VALUE);
		return -1;
	}

	for (uint8_t itr = 0; itr < peer_fqcsid->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = peer_fqcsid->local_csid[itr];
		fill_node_addr_info(&key.node_addr, &peer_fqcsid->node_addr);

		tmp = get_peer_csid_entry(&key, iface, ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get "
					"CSID entry to link with PEER FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
			return -1;
		}

		/* Link local csid with MME CSID */
		if (tmp->num_csid == 0) {
			tmp->local_csid[tmp->num_csid++] =
				local_fqcsid->local_csid[local_fqcsid->num_csid - 1];
			/* Update the Node Addr */
			fill_node_addr_info(&tmp->node_addr, &local_fqcsid->node_addr);
		} else {
			for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
				if (tmp->local_csid[itr1] ==
						local_fqcsid->local_csid[local_fqcsid->num_csid - 1]) {
					return 0;
				}
			}
			/* Link with peer CSID */
			tmp->local_csid[tmp->num_csid++] =
				local_fqcsid->local_csid[local_fqcsid->num_csid - 1];

			/* Update the Node Addr */
			fill_node_addr_info(&tmp->node_addr, &local_fqcsid->node_addr);
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer CSID Linked with Local CSID: %u\n", LOG_VALUE,
					local_fqcsid->local_csid[local_fqcsid->num_csid - 1]);
		}
	}

	return 0;
}

int
fill_peer_node_info(pdn_connection *pdn,
				eps_bearer *bearer)
{
	uint8_t num_csid = 0;
	int16_t local_csid = 0;
	csid_key peer_info = {0};

	/* MME FQ-CSID */
	if ((pdn->context)->cp_mode != PGWC) {
		if (((pdn->context)->mme_fqcsid)->num_csid) {
			num_csid = ((pdn->context)->mme_fqcsid)->num_csid;
			fill_node_addr_info(&peer_info.mme_ip,
					&((pdn->context)->mme_fqcsid)->node_addr[num_csid - 1]);
		} else {
			/* IF MME not support partial failure */
			fill_node_addr_info(&peer_info.mme_ip,
						&(pdn->context)->s11_mme_gtpc_ip);
		}
		(peer_info.mme_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node MME IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.mme_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node MME IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.mme_ip.ipv4_addr));
	}

	/* SGW FQ-CSID */
	if (((pdn->context)->sgw_fqcsid)->num_csid) {
		num_csid = ((pdn->context)->sgw_fqcsid)->num_csid;
		fill_node_addr_info(&peer_info.sgwc_ip,
				&((pdn->context)->sgw_fqcsid)->node_addr[num_csid - 1]);
	} else {
		/* IF SGWC not support partial failure */
		if (((pdn->context)->cp_mode == SGWC)
					|| ((pdn->context)->cp_mode == SAEGWC)) {
			fill_node_addr_info(&peer_info.sgwc_ip,
					&(pdn->context)->s11_sgw_gtpc_ip);
		} else {
			fill_node_addr_info(&peer_info.sgwc_ip,
					&pdn->s5s8_sgw_gtpc_ip);
		}
	}

	(peer_info.sgwc_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node SGWC/SAEGWC IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwc_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node SGWC/SAEGWC IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwc_ip.ipv4_addr));

	if ((pdn->context)->cp_mode != PGWC) {
		/* Fill the enodeb IP */
		if(pdn->context->indication_flag.s11tf){
			fill_node_addr_info(&peer_info.enodeb_ip,
					&bearer->s11u_mme_gtpu_ip);
		}else{
			fill_node_addr_info(&peer_info.enodeb_ip,
					&bearer->s1u_enb_gtpu_ip);
		}
		(peer_info.enodeb_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node enodeb IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.enodeb_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node enodeb IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.enodeb_ip.ipv4_addr));
	}

	/* SGW and PGW peer node info */
	fill_node_addr_info(&peer_info.pgwc_ip, &pdn->s5s8_pgw_gtpc_ip);
	(peer_info.pgwc_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node PGWC IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwc_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node PGWC IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwc_ip.ipv4_addr));

	/* SGWU and PGWU peer node info */
	if (((pdn->context)->cp_mode == SAEGWC) || ((pdn->context)->cp_mode == SGWC)) {
		fill_node_addr_info(&peer_info.sgwu_ip, &pdn->upf_ip);
		(peer_info.sgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwu_ip.ipv4_addr));
	} else if ((pdn->context)->cp_mode == PGWC) {
		/*TODO: Need to think on it*/
		fill_node_addr_info(&peer_info.pgwu_ip, &pdn->upf_ip);
		(peer_info.pgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwu_ip.ipv4_addr));
	}

	/* PGWU s5s8 node address */
	if (((pdn->context)->cp_mode == SGWC)
				&& (is_present(&bearer->s5s8_pgw_gtpu_ip))) {

		fill_node_addr_info(&peer_info.pgwu_ip,
					&bearer->s5s8_pgw_gtpu_ip);

		(peer_info.pgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwu_ip.ipv4_addr));
	} else if ((((pdn->context)->cp_mode == PGWC)
					&& (is_present(&bearer->s5s8_sgw_gtpu_ip)))) {
		/* SGWU s5s8 node address */
		fill_node_addr_info(&peer_info.sgwu_ip,
					&bearer->s5s8_sgw_gtpu_ip);

		(peer_info.sgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwu_ip.ipv4_addr));
	}

	/* Get local csid for set of peer node */
	local_csid = get_csid_entry(&peer_info);
	if (local_csid < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to assinged CSID..\n", LOG_VALUE);
		return -1;
	}

	/* Remove the dummy local CSIDs from the context */
	sess_fqcsid_t tmp_csid_t = {0};
	if ((pdn->context)->cp_mode != PGWC) {
		memcpy(&tmp_csid_t, (pdn->context)->sgw_fqcsid, sizeof(sess_fqcsid_t));
	} else {
		memcpy(&tmp_csid_t, (pdn->context)->pgw_fqcsid, sizeof(sess_fqcsid_t));
	}

	/* Validate the CSID present or not in exsiting CSID List */
	for (uint8_t inx = 0; inx < tmp_csid_t.num_csid; inx++) {
		if (tmp_csid_t.local_csid[inx] == local_csid) {
			return 0;
		}
	}

	/* Update the local csid into the UE context */
	if ((pdn->context)->cp_mode != PGWC) {
			num_csid  = ((pdn->context)->sgw_fqcsid)->num_csid;
		if ((pdn->context)->s11_mme_gtpc_ip.ip_type == PDN_TYPE_IPV4) {
			((pdn->context)->sgw_fqcsid)->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV4;
			((pdn->context)->sgw_fqcsid)->node_addr[num_csid].ipv4_addr =
					config.s11_ip.s_addr;
			pdn->sgw_csid.node_addr.ip_type = PDN_TYPE_IPV4;
			pdn->sgw_csid.node_addr.ipv4_addr =  config.s11_ip.s_addr;
		} else {
			((pdn->context)->sgw_fqcsid)->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV6;
			memcpy(
				&(((pdn->context)->sgw_fqcsid)->node_addr[num_csid].ipv6_addr),
					&(config.s11_ip_v6.s6_addr), IPV6_ADDRESS_LEN);

			pdn->sgw_csid.node_addr.ip_type = PDN_TYPE_IPV6;
			memcpy(&(pdn->sgw_csid.node_addr.ipv6_addr),
						&(config.s11_ip_v6.s6_addr), IPV6_ADDRESS_LEN);
		}

		((pdn->context)->sgw_fqcsid)->local_csid[num_csid] = local_csid;
		((pdn->context)->sgw_fqcsid)->num_csid++;
		pdn->flag_fqcsid_modified = TRUE;

		num_csid = 0;
		pdn->sgw_csid.local_csid[num_csid] = local_csid;
		pdn->sgw_csid.num_csid = PRESENT;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
					"SGW CSID is Modified ..\n", LOG_VALUE);
	} else {
		num_csid = ((pdn->context)->pgw_fqcsid)->num_csid;
		if (pdn->s5s8_sgw_gtpc_ip.ip_type == PDN_TYPE_IPV4) {
			((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ip_type =
				PDN_TYPE_IPV4;
			pdn->pgw_csid.node_addr.ip_type = PDN_TYPE_IPV4;

			if ((pdn->context)->cp_mode_flag == TRUE) {
				((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ipv4_addr =
					config.s11_ip.s_addr;

				pdn->pgw_csid.node_addr.ipv4_addr =  config.s11_ip.s_addr;
			} else {
				((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ipv4_addr =
					config.s5s8_ip.s_addr;

				pdn->pgw_csid.node_addr.ipv4_addr =  config.s5s8_ip.s_addr;
			}
		} else {
			((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ip_type =
					PDN_TYPE_IPV6;
			pdn->pgw_csid.node_addr.ip_type = PDN_TYPE_IPV6;

			if ((pdn->context)->cp_mode_flag == TRUE) {
				memcpy(
					&(((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ipv6_addr),
						&(config.s11_ip_v6.s6_addr), IPV6_ADDRESS_LEN);

				memcpy(&(pdn->pgw_csid.node_addr.ipv6_addr),
						&(config.s11_ip_v6.s6_addr), IPV6_ADDRESS_LEN);
			} else {
				memcpy(
					&(((pdn->context)->pgw_fqcsid)->node_addr[num_csid].ipv6_addr),
						&(config.s5s8_ip_v6.s6_addr), IPV6_ADDRESS_LEN);

				memcpy(&(pdn->pgw_csid.node_addr.ipv6_addr),
						&(config.s5s8_ip_v6.s6_addr), IPV6_ADDRESS_LEN);
			}
		}

		((pdn->context)->pgw_fqcsid)->local_csid[num_csid] = local_csid;
		((pdn->context)->pgw_fqcsid)->num_csid++;
		pdn->flag_fqcsid_modified = TRUE;

		num_csid = 0;
		pdn->pgw_csid.local_csid[num_csid] = local_csid;
		pdn->pgw_csid.num_csid = PRESENT;

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
				"PGW CSID is Modified ..\n", LOG_VALUE);
	}

	/* Link local CSID with MME CSID */
	if (pdn->mme_csid.num_csid) {
		if ((pdn->context)->cp_mode != PGWC) {
			if (link_gtpc_peer_csids(&pdn->mme_csid,
						&pdn->sgw_csid, S11_SGW_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with MME FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
		} else {
			if (link_gtpc_peer_csids(&pdn->mme_csid,
						&pdn->pgw_csid, S5S8_PGWC_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with MME FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
		}
	}

	/* PGW Link local CSID with SGW CSID */
	if ((pdn->context)->cp_mode == PGWC) {
		if (pdn->sgw_csid.num_csid) {
			if (link_gtpc_peer_csids(&pdn->sgw_csid,
						&pdn->pgw_csid, S5S8_PGWC_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with SGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
		}
	}

	/* SGW Link local CSID with PGW CSID */
	if ((pdn->context)->cp_mode != PGWC) {
		if (pdn->pgw_csid.num_csid) {
			if (link_gtpc_peer_csids(&pdn->pgw_csid,
						&pdn->sgw_csid, S5S8_SGWC_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to Link "
					"Local CSID entry to link with PGW FQCSID, Error : %s \n", LOG_VALUE,
					strerror(errno));
				return -1;
			}
		}
	}
	return 0;
}

int
delete_peer_node_info(pdn_connection *pdn,
				eps_bearer *bearer)
{
	int ret = 0;
	uint8_t num_csid = 0;
	csid_key peer_info = {0};

	/* MME FQ-CSID */
	if ((pdn->context)->cp_mode != PGWC) {
		if (((pdn->context)->mme_fqcsid)->num_csid) {
			num_csid = ((pdn->context)->mme_fqcsid)->num_csid;
			fill_node_addr_info(&peer_info.mme_ip,
					&((pdn->context)->mme_fqcsid)->node_addr[num_csid - 1]);
		} else {
			/* IF MME not support partial failure */
			fill_node_addr_info(&peer_info.mme_ip,
						&(pdn->context)->s11_mme_gtpc_ip);
		}
		(peer_info.mme_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node MME IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.mme_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node MME IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.mme_ip.ipv4_addr));
	}

	/* SGW FQ-CSID */
	if (((pdn->context)->sgw_fqcsid)->num_csid) {
		num_csid = ((pdn->context)->sgw_fqcsid)->num_csid;
		fill_node_addr_info(&peer_info.sgwc_ip,
				&((pdn->context)->sgw_fqcsid)->node_addr[num_csid - 1]);
	} else {
		/* IF SGWC not support partial failure */
		if (((pdn->context)->cp_mode == SGWC)
					|| ((pdn->context)->cp_mode == SAEGWC)) {
			fill_node_addr_info(&peer_info.sgwc_ip,
					&(pdn->context)->s11_sgw_gtpc_ip);
		} else {
			fill_node_addr_info(&peer_info.sgwc_ip,
					&pdn->s5s8_sgw_gtpc_ip);
		}
	}

	(peer_info.sgwc_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node SGWC/SAEGWC IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwc_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node SGWC/SAEGWC IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwc_ip.ipv4_addr));

	if ((pdn->context)->cp_mode != PGWC) {
		/* Fill the enodeb IP */
		if(pdn->context->indication_flag.s11tf){
			fill_node_addr_info(&peer_info.enodeb_ip,
					&bearer->s11u_mme_gtpu_ip);
		}else{
			fill_node_addr_info(&peer_info.enodeb_ip,
					&bearer->s1u_enb_gtpu_ip);
		}
		(peer_info.enodeb_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node enodeb IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.enodeb_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node enodeb IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.enodeb_ip.ipv4_addr));
	}

	/* SGW and PGW peer node info */
	fill_node_addr_info(&peer_info.pgwc_ip, &pdn->s5s8_pgw_gtpc_ip);
	(peer_info.pgwc_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node PGWC IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwc_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node PGWC IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwc_ip.ipv4_addr));

	/* SGWU and PGWU peer node info */
	if (((pdn->context)->cp_mode == SAEGWC) || ((pdn->context)->cp_mode == SGWC)) {
		fill_node_addr_info(&peer_info.sgwu_ip, &pdn->upf_ip);
		(peer_info.sgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwu_ip.ipv4_addr));
	} else if ((pdn->context)->cp_mode == PGWC) {
		/*TODO: Need to think on it*/
		fill_node_addr_info(&peer_info.pgwu_ip, &pdn->upf_ip);
		(peer_info.pgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwu_ip.ipv4_addr));
	}

	/* PGWU s5s8 node address */
	if (((pdn->context)->cp_mode == SGWC)
				&& (is_present(&bearer->s5s8_pgw_gtpu_ip))) {

		fill_node_addr_info(&peer_info.pgwu_ip,
					&bearer->s5s8_pgw_gtpu_ip);

		(peer_info.pgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.pgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node PGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.pgwu_ip.ipv4_addr));
	} else if ((((pdn->context)->cp_mode == PGWC)
					&& (is_present(&bearer->s5s8_sgw_gtpu_ip)))) {
		/* SGWU s5s8 node address */
		fill_node_addr_info(&peer_info.sgwu_ip,
					&bearer->s5s8_sgw_gtpu_ip);

		(peer_info.sgwu_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info.sgwu_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Peer Node SGWU/SAEGWU IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info.sgwu_ip.ipv4_addr));
	}

	/* Delete Permanent CSID of node */
	ret = del_csid_entry(&peer_info);

	/* Delete Temporary CSID of node */
	if ((pdn->context)->cp_mode != PGWC) {
		/*Set Enb ip to zero */
		memset(&peer_info.enodeb_ip, 0, sizeof(node_address_t));
		if ((pdn->context)->cp_mode == SGWC) {
			/*Set PGWU ip to zero */
			memset(&peer_info.pgwu_ip, 0, sizeof(node_address_t));
		}

		ret = del_csid_entry(&peer_info);
	}


	return ret;
}

void
fill_pdn_fqcsid_info(fqcsid_t *pdn_fqcsid, sess_fqcsid_t *cntx_fqcsid) {

	uint8_t num_csid = 0;

	pdn_fqcsid->local_csid[num_csid] =
		cntx_fqcsid->local_csid[cntx_fqcsid->num_csid -1];

	if (cntx_fqcsid->node_addr[cntx_fqcsid->num_csid -1].ip_type
			== PDN_TYPE_IPV4) {
		pdn_fqcsid->node_addr.ip_type = PDN_TYPE_IPV4;
		pdn_fqcsid->node_addr.ipv4_addr =
			cntx_fqcsid->node_addr[cntx_fqcsid->num_csid -1].ipv4_addr;
	} else {
		pdn_fqcsid->node_addr.ip_type = PDN_TYPE_IPV6;
		memcpy(pdn_fqcsid->node_addr.ipv6_addr,
				cntx_fqcsid->node_addr[cntx_fqcsid->num_csid -1].ipv6_addr,
				IPV6_ADDRESS_LEN);
	}

	pdn_fqcsid->num_csid = PRESENT;
}

int8_t
update_peer_csid_link(fqcsid_t *fqcsid, fqcsid_t *fqcsid_t)
{
	/* Link local CSID with peer node CSID */
	if (fqcsid->num_csid) {
		for (uint8_t itr = 0; itr < fqcsid->num_csid; itr++) {
			csid_t *tmp = NULL;
			csid_key_t key = {0};
			key.local_csid = fqcsid->local_csid[itr];
			memcpy(&(key.node_addr), &(fqcsid->node_addr), sizeof(node_address_t));

			tmp = get_peer_csid_entry(&key, SX_PORT_ID, ADD_NODE);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in "
					"updating peer CSID link: %s \n", LOG_VALUE, strerror(errno));
				return -1;
			}

			/* Link local csid with MME CSID */
			if (tmp->num_csid == 0) {
				tmp->local_csid[tmp->num_csid++] =
					fqcsid_t->local_csid[fqcsid_t->num_csid - 1];
			} else {
				uint8_t itr1 = 0;
				while (itr1 < tmp->num_csid) {
					if (tmp->local_csid[itr1] != fqcsid_t->local_csid[fqcsid_t->num_csid - 1]){
						/* Handle condition like single SGWU CSID link with multiple local CSID  */
						tmp->local_csid[tmp->num_csid++] = fqcsid_t->local_csid[fqcsid_t->num_csid - 1];
						itr1++;
					} else {
						break;
					}
				}
			}
			/* Update the Node address */
			memcpy(&(tmp->node_addr),
					&(fqcsid_t->node_addr), sizeof(node_address_t));
		}
	}
	return 0;
}

int8_t
fill_fqcsid_sess_mod_req(pfcp_sess_mod_req_t *pfcp_sess_mod_req, pdn_connection *pdn)
{
	/* Set SGW FQ-CSID */
	if (pdn->sgw_csid.num_csid) {

		set_fq_csid_t(&pfcp_sess_mod_req->sgw_c_fqcsid, &pdn->sgw_csid);

		/* set PGWC FQ-CSID */
		/* Note: In case of S1 handover pgw fqcsid is not generated,
		 * as new sgw doesn't know the pgw fqcsid
		 * so we don't want zero value to be set in
		 * fqcsid in pfcp mod request. That's why the
		 * below condition is checked*/

		if(pdn->context->update_sgw_fteid == FALSE)
			set_fq_csid_t(&pfcp_sess_mod_req->pgw_c_fqcsid, &pdn->pgw_csid);
	}

	return 0;
}

int8_t
fill_fqcsid_sess_est_req(pfcp_sess_estab_req_t *pfcp_sess_est_req, pdn_connection *pdn)
{

	fqcsid_t tmp_fqcsid = {0};
	if ((pdn->context)->cp_mode != PGWC) {
		/* Set SGW FQ-CSID */
		if (pdn->sgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, &pdn->sgw_csid);
		} else {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, &tmp_fqcsid);
		}
		/* Set MME FQ-CSID */
		if(pdn->mme_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, &pdn->mme_csid);
		}

	} else if ((pdn->context)->cp_mode == PGWC) {
		/* Set PGW FQ-CSID */
		if (pdn->pgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->pgw_c_fqcsid, &pdn->pgw_csid);
		} else {
			set_fq_csid_t(&pfcp_sess_est_req->pgw_c_fqcsid, &tmp_fqcsid);
		}

		/* Set SGW C FQ_CSID */
		if (pdn->sgw_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, &pdn->sgw_csid);
		} else {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, &tmp_fqcsid);
		}

		/* Set MME FQ-CSID */
		if(pdn->mme_csid.num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, &pdn->mme_csid);
		} else {
			set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, &tmp_fqcsid);
		}
	}

	return 0;
}

int
link_sess_with_peer_csid(fqcsid_t *peer_csid, pdn_connection *pdn, uint8_t iface) {

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp = NULL;
	uint8_t num_csid = 0;
	peer_csid_key_t key = {0};

	key.iface = iface;
	key.peer_local_csid = peer_csid->local_csid[num_csid];
	memcpy(&(key.peer_node_addr), &(peer_csid->node_addr), sizeof(node_address_t));

	tmp = get_sess_peer_csid_entry(&key, ADD_NODE);

	if (tmp == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get peer CSID "
				"entry, Error: %s \n", LOG_VALUE,strerror(errno));
		return GTPV2C_CAUSE_SYSTEM_FAILURE;
	}

	/* OPTIMIZE THE MEMORY: No Need to fill UP_SEID */
	/* Link local csid with session id */
	/* Check head node created ot not */
	if(tmp->cp_seid != pdn->seid && tmp->cp_seid != 0) {
		sess_csid *new_node = NULL;
		/* Add new node into csid linked list */
		new_node = add_peer_csid_sess_data_node(tmp, &key);
		if(new_node == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to ADD new "
					"node into peer CSID linked list : %s\n", LOG_VALUE);
			return GTPV2C_CAUSE_SYSTEM_FAILURE;
		} else {
			new_node->cp_seid = pdn->seid;
			new_node->up_seid = pdn->dp_seid;
		}

	} else {
		tmp->cp_seid = pdn->seid;
		tmp->up_seid = pdn->dp_seid;
		tmp->next = NULL;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Link Session "
				"[ CP seid : %u ] [ DP seid : %u ] with CSID : %u"
				" Peer Node addr Linked List \n", LOG_VALUE, tmp->cp_seid,
				tmp->up_seid, peer_csid->local_csid[num_csid]);

	return 0;
}

void
remove_csid_from_cntx(sess_fqcsid_t *cntx_fqcsid, fqcsid_t *csid_t) {

	for (uint8_t itr = 0; itr < (cntx_fqcsid)->num_csid; itr++) {

		if (((cntx_fqcsid)->local_csid[itr] == csid_t->local_csid[csid_t->num_csid -1])
				&& (COMPARE_IP_ADDRESS(cntx_fqcsid->node_addr[itr], csid_t->node_addr) == 0)) {

			for(uint8_t pos = itr; pos < ((cntx_fqcsid)->num_csid - 1); pos++ ) {

				(cntx_fqcsid)->local_csid[pos] =
					(cntx_fqcsid)->local_csid[pos + 1];

				if ((cntx_fqcsid)->node_addr[(pos + 1)].ip_type == PDN_TYPE_IPV4) {
					(cntx_fqcsid)->node_addr[pos].ipv4_addr =
						(cntx_fqcsid)->node_addr[(pos + 1)].ipv4_addr;
				} else  {
					memcpy(&((cntx_fqcsid)->node_addr[pos].ipv6_addr),
								&((cntx_fqcsid)->node_addr[(pos + 1)].ipv6_addr), IPV6_ADDRESS_LEN);
				}
			}
			(cntx_fqcsid)->num_csid--;
		}
	}
}
#endif /* CP_BUID */


static uint16_t seq_t = 0;
#ifdef CP_BUILD
void
cp_fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids)
{
	fqcsid_t tmp = {0};
	node_address_t node_value = {0};
	int ret = 0;

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, NO_SEID, ++seq_t, NO_CP_MODE_REQUIRED);

	/*filling of node id*/
#ifdef CP_BUILD

	ret = fill_ip_addr(config.pfcp_ip.s_addr,
					config.pfcp_ip_v6.s6_addr,
					&node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#else

	ret = fill_ip_addr(dp_comm_ip.s_addr,
					dp_comm_ipv6.s6_addr,
					&node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#endif /*CP_BUILD*/

	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	if (local_csids->instance == 0) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp);
			/* Set the UP FQ-CSID */
			set_fq_csid_t(&pfcp_sess_set_del_req->up_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, local_csids);
		}
	} else if (local_csids->instance == 1) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, local_csids);
		}
	} else if (local_csids->instance == 2) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);
		}
	}
}
#endif /* CP_BUILD */
void
fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids, uint8_t iface)
{
	fqcsid_t tmp_csids = {0};
	node_address_t node_value = {0};
	int ret = 0;
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, NO_SEID, ++seq_t, NO_CP_MODE_REQUIRED);

	/*filling of node id*/
#ifdef CP_BUILD

	ret = fill_ip_addr(config.pfcp_ip.s_addr,
					config.pfcp_ip_v6.s6_addr, &node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#else

	ret = fill_ip_addr(dp_comm_ip.s_addr,
					dp_comm_ipv6.s6_addr, &node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#endif /*CP_BUILD*/

	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	if (local_csids->num_csid) {
		/* Set the SGWC FQ-CSID */
#ifdef CP_BUILD
		if ((iface == S11_SGW_PORT_ID) ||
				(iface == S5S8_SGWC_PORT_ID)) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, local_csids);
		}

		if (iface == S5S8_PGWC_PORT_ID) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);
		}
#else
		set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp_csids);
		set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp_csids);
		set_fq_csid_t(&pfcp_sess_set_del_req->up_fqcsid, local_csids);
#endif /* DP_BUILD */
	}
}

#ifdef CP_BUILD

/**
 * @brief  : Match peer node address
 * @param  : num_node_addr, node addr count.
 * @param  : peer_node_addr,
 * @param  : peer_node_addrs,
 * @return : Returns 0 in case of match not found, 1 otherwise
 */
static int
match_node_addr(uint8_t num_node_addr, node_address_t *peer_node_addr,
				node_address_t *peer_node_addrs) {
	int match = 0;
	node_address_t ip_addr = {0}, ip_addrs = {0};

	memcpy(&ip_addr, peer_node_addr, sizeof(node_address_t));

	for (uint8_t itr = 0; itr < num_node_addr; itr++) {
		memcpy(&ip_addrs, &peer_node_addrs[itr], sizeof(node_address_t));
		if ((COMPARE_IP_ADDRESS(ip_addr, ip_addrs)) == 0) {
			match = 1;
			break;
		}
	}

	return match;
}

/**
 * @brief  : get upf node address
 * @param  : csids,
 * @param  :  upf_node_addrs,
 * @param  :  num_node_addr,
 * @return : Returns 0 in case of match not found, 1 otherwise
 */
static int8_t
get_upf_node_entry(fqcsid_t *csids, node_address_t *upf_node_addrs, uint8_t *num_node_addr)
{
	uint8_t ip_count = 0;
	int8_t ebi = 0;
	int8_t ebi_index = 0;
	int ret = 0;
	uint32_t teid_key = 0;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	sess_csid *tmp = NULL;
	sess_csid *current = NULL;
	for (uint8_t itr = 0; itr < csids->num_csid; itr++)
	{
		tmp = get_sess_csid_entry(csids->local_csid[itr], REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Failed to get CSID entry, CSID: %u\n", LOG_VALUE,
					csids->local_csid[itr]);
			continue;
		}
		/* Check SEID is not ZERO */
		if ((tmp->cp_seid == 0) && (tmp->next == 0)) {
			continue;
		}

		current = tmp;
		while (current != NULL ) {
			teid_key = UE_SESS_ID(current->cp_seid);
			ebi = UE_BEAR_ID(current->cp_seid);
			ebi_index = GET_EBI_INDEX(ebi);
			if (ebi_index == -1) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Invalid EBI ID\n", LOG_VALUE);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}

			ret = rte_hash_lookup_data(ue_context_by_fteid_hash,
					(const void *) &teid_key,
					(void **) &context);

			if (ret < 0 || context == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get UE context for teid : %u \n",
						LOG_VALUE, teid_key);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			pdn = context->pdns[ebi_index];
			if (pdn == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"ERROR : Failed to get PDN context for seid : %u \n",
						LOG_VALUE, current->cp_seid);
				/* Assign Next node address */
				tmp = current->next;
				current = tmp;
				continue;
			}
			if(is_present(&pdn->up_csid.node_addr)) {
				if ((match_node_addr(ip_count, &pdn->up_csid.node_addr,
								upf_node_addrs)) == 0)
				{
					fill_peer_info(&upf_node_addrs[ip_count++],
									&pdn->up_csid.node_addr);
				}
			}

			/* Assign Next node address */
			tmp = current->next;

			current = tmp;
		}
	}
	*num_node_addr = ip_count;
	return 0;
}
#endif /* CP_BUILD */

/* Cleanup Session information by local csid*/
int8_t
del_pfcp_peer_node_sess(node_address_t *node_addr, uint8_t iface)
{
	pfcp_sess_set_del_req_t del_set_req_t = {0};
	fqcsid_t *local_csids = NULL;
	fqcsid_ie_node_addr_t *tmp = NULL;
	fqcsid_t csids = {0};
	peer_node_addr_key_t key = {0};

#ifdef CP_BUILD
	delete_thrtle_timer(node_addr);
#endif

	/* Get local CSID associated with node */
	local_csids = get_peer_addr_csids_entry(node_addr, UPDATE_NODE);
	if (local_csids == NULL) {
		key.iface = iface;
		if (node_addr->ip_type == PDN_TYPE_IPV4) {
			key.peer_node_addr.ip_type = PDN_TYPE_IPV4;
			key.peer_node_addr.ipv4_addr = node_addr->ipv4_addr;
		} else {
			key.peer_node_addr.ip_type = PDN_TYPE_IPV6;
			memcpy(key.peer_node_addr.ipv6_addr,
					node_addr->ipv6_addr, IPV6_ADDRESS_LEN);
		}

		tmp = get_peer_node_addr_entry(&key, UPDATE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
				"entry while deleting session information: %s \n",
				LOG_VALUE, strerror(errno));
			clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(node_addr->ipv4_addr));
			return 0;
		}
	   /* Get local CSID associated with node */
	   local_csids = get_peer_addr_csids_entry(&tmp->fqcsid_node_addr, UPDATE_NODE);
	   if (local_csids == NULL)
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
				"entry while deleting session information: %s \n",
				LOG_VALUE, strerror(errno));
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < local_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = local_csids->local_csid[itr];
		memcpy(&key.node_addr, &local_csids->node_addr, sizeof(node_address_t));

		tmp = get_peer_csid_entry(&key, iface, REMOVE_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to get CSID "
				"while cleanup session information, Error : %s \n",
				LOG_VALUE, strerror(errno));
			return -1;
		}

		for (int8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
			csids.local_csid[csids.num_csid++] = tmp->local_csid[itr1];
		}

		csids.node_addr = tmp->node_addr;
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"CSIDs are already cleanup \n", LOG_VALUE);
		return 0;
	}

#ifdef CP_BUILD
		uint8_t num_upf_node_addr = 0;
		node_address_t upf_node_addrs[MAX_CSID] = {0};
		get_upf_node_entry(&csids, upf_node_addrs, &num_upf_node_addr);
#endif /* CP_BUILD */

	fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, iface);

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[PFCP_MSG_LEN]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);
#ifdef CP_BUILD
	for (uint8_t itr = 0; itr < num_upf_node_addr; itr++) {
		int ret = set_dest_address(upf_node_addrs[itr], &upf_pfcp_sockaddr);
		if (ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
				"IP address", LOG_VALUE);
		}

		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Send Pfcp Set Deletion Request to UP, Node Addr:"IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(upf_pfcp_sockaddr.ipv4.sin_addr.s_addr));

		if (pfcp_send(pfcp_fd, pfcp_fd_v6, pfcp_msg, encoded, upf_pfcp_sockaddr, SENT) < 0 ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending PFCP "
				"Set Session Deletion Request, Error : %i\n", LOG_VALUE, errno);
			return -1;
		}
	}
#else
	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	if (sendto(my_sock.sock_fd,
		(char *)pfcp_msg,
		encoded,
		MSG_DONTWAIT,
		(struct sockaddr *)&dest_addr_t.ipv4,
		sizeof(struct sockaddr_in)) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in sending PFCP "
			"Set Session Deletion Request, Error : %i\n", LOG_VALUE, errno);
			return -1;
	}
	else {
		peer_address_t address;
		address.ipv4.sin_addr.s_addr = dest_addr_t.ipv4.sin_addr.s_addr;
		address.type = IPV4_TYPE;
		update_cli_stats((peer_address_t *) &address, header->message_type, SENT, SX);
	}
#endif /* CP_BUILD */
	return 0;
}

/* Fill PFCP SESSION SET SELETION RESPONSE */
void
fill_pfcp_sess_set_del_resp(pfcp_sess_set_del_rsp_t *pfcp_del_resp,
			uint8_t cause_val, int offending_id)
{
	node_address_t node_value = {0};
	int ret = 0;
	memset(pfcp_del_resp, 0, sizeof(pfcp_sess_set_del_rsp_t));

	set_pfcp_header(&pfcp_del_resp->header, PFCP_SESS_SET_DEL_RSP, 0);

	/*filling of node id*/
#ifdef CP_BUILD

	ret = fill_ip_addr(config.pfcp_ip.s_addr,
					config.pfcp_ip_v6.s6_addr, &node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#else

	ret = fill_ip_addr(dp_comm_ip.s_addr,
					dp_comm_ipv6.s6_addr, &node_value);
	if (ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT "Error while assigning "
			"IP address", LOG_VALUE);
	}
#endif /*CP_BUILD*/

	set_node_id(&(pfcp_del_resp->node_id), node_value);
	pfcp_set_ie_header(&pfcp_del_resp->cause.header, PFCP_IE_CAUSE,
			sizeof(pfcp_del_resp->cause.cause_value));
	pfcp_del_resp->cause.cause_value = cause_val;

	RTE_SET_USED(offending_id);
}

int8_t
del_csid_entry_hash(fqcsid_t *peer_csids,
				fqcsid_t *local_csids, uint8_t iface)
{
	if (peer_csids != NULL) {
		for (int itr = 0; itr < peer_csids->num_csid; itr++) {
			csid_t *csids = NULL;
			csid_key_t key = {0};
			key.local_csid = peer_csids->local_csid[itr];
			memcpy(&key.node_addr,
					&peer_csids->node_addr, sizeof(node_address_t));

			csids = get_peer_csid_entry(&key, iface, REMOVE_NODE);
			if (csids == NULL)
				continue;

			for (uint8_t itr1 = 0; itr1 < local_csids->num_csid; itr1++) {
				for (uint8_t itr2 = 0; itr2 < csids->num_csid; itr2++) {
					if (csids->local_csid[itr2] == local_csids->local_csid[itr1]) {
						for(uint8_t pos = itr2; pos < (csids->num_csid - 1); pos++ ) {
							csids->local_csid[pos] = csids->local_csid[pos + 1];
						}
						csids->num_csid--;
					}
				}
			}

			if (csids->num_csid == 0)  {
				if (del_peer_csid_entry(&key, iface)) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in deleting "
						"peer CSID entry, Error : %i\n", LOG_VALUE, errno);
					/* TODO ERROR HANDLING */
					return -1;
				}

				fqcsid_t *tmp = NULL;
				tmp = get_peer_addr_csids_entry(&peer_csids->node_addr, UPDATE_NODE);
				if (tmp != NULL) {
					for (uint8_t itr3 = 0; itr3 < tmp->num_csid; itr3++) {
						if (tmp->local_csid[itr3] == peer_csids->local_csid[itr]) {
							for(uint8_t pos = itr3; pos < (tmp->num_csid - 1); pos++ ) {
								tmp->local_csid[pos] = tmp->local_csid[pos + 1];
							}
							tmp->num_csid--;
						}
					}

					if (!tmp->num_csid) {
						if (del_peer_addr_csids_entry(&peer_csids->node_addr)) {
							clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error in deleting "
								"peer CSID entry, Error : %i\n", LOG_VALUE, errno);
							/* TODO ERROR HANDLING */
							return -1;
						}
					}
				}
			}
		}
	}
	return 0;
}

#if defined(CP_BUILD) && defined(USE_CSID)
int
update_peer_node_csid(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp, pdn_connection *pdn)
{
	uint8_t num_csid = 0;
	node_address_t node_addr = {0};
	fqcsid_t up_old_csid = {0};
	ue_context *context = NULL;

	context = pdn->context;

	/* UP FQ-CSID */
	if (pfcp_sess_mod_rsp->up_fqcsid.header.len) {
		if (pfcp_sess_mod_rsp->up_fqcsid.number_of_csids) {
			uint8_t ret = 0;
			uint8_t match = 0;
			fqcsid_t *tmp = NULL;
			//fqcsid_t fqcsid = {0};
			uint16_t old_csid = 0;

			if (context->up_fqcsid != NULL) {
				memcpy(&up_old_csid, &pdn->up_csid, sizeof(fqcsid_t));
				old_csid = context->up_fqcsid->local_csid[context->up_fqcsid->num_csid - 1];
			} else {
				context->up_fqcsid = rte_zmalloc_socket(NULL, sizeof(sess_fqcsid_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
				if (context->up_fqcsid == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
							"Failed to allocate the memory for fqcsids entry\n", LOG_VALUE);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
			}

			if (pfcp_sess_mod_rsp->up_fqcsid.fqcsid_node_id_type ==  IPV4_GLOBAL_UNICAST) {
				node_addr.ip_type = PDN_TYPE_IPV4;
				memcpy(&node_addr.ipv4_addr,
						&pfcp_sess_mod_rsp->up_fqcsid.node_address, IPV4_SIZE);
			} else if (pfcp_sess_mod_rsp->up_fqcsid.fqcsid_node_id_type ==
						IPV6_GLOBAL_UNICAST) {
				node_addr.ip_type = PDN_TYPE_IPV6;
				memcpy(&node_addr.ipv6_addr,
						&pfcp_sess_mod_rsp->up_fqcsid.node_address, IPV6_SIZE);
			} else {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"te CSID entry\n", LOG_VALUE);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			/* Stored the UP CSID by UP Node address */
			tmp = get_peer_addr_csids_entry(&node_addr, ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
					"Failed to get peer csid entry while update CSID entry\n", LOG_VALUE);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}
			/* coping node address */
			memcpy(&tmp->node_addr, &node_addr, sizeof(node_address_t));

			/* TODO: Re-write the optimizes way */
			for(uint8_t itr = 0; itr < pfcp_sess_mod_rsp->up_fqcsid.number_of_csids; itr++) {
				match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] ==
								pfcp_sess_mod_rsp->up_fqcsid.pdn_conn_set_ident[itr]) {
						match = 1;
						break;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						pfcp_sess_mod_rsp->up_fqcsid.pdn_conn_set_ident[itr];
				}
			}

			/* Update the UP CSID in the context */
			if (context->up_fqcsid->num_csid) {
				match_and_add_pfcp_sess_fqcsid(&pfcp_sess_mod_rsp->up_fqcsid, context->up_fqcsid);
			} else {
				add_pfcp_sess_fqcsid(&pfcp_sess_mod_rsp->up_fqcsid, context->up_fqcsid);
			}
			//memcpy(&fqcsid.node_addr, &node_addr, sizeof(node_address_t));

			for (uint8_t itr2 = 0; itr2 < tmp->num_csid; itr2++) {
				if (tmp->local_csid[itr2] == old_csid) {
					for(uint8_t pos = itr2; pos < (tmp->num_csid - 1); pos++ ) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}

			/* Remove old up csid and node address */
			remove_csid_from_cntx(context->up_fqcsid, &up_old_csid);

			/* Delete old up csid link with local csid entry */
			if (up_old_csid.num_csid) {
				csid_key_t key = {0};
				key.local_csid = up_old_csid.local_csid[num_csid];
				memcpy(&key.node_addr, &up_old_csid.node_addr, sizeof(node_address_t));
				del_peer_csid_entry(&key, SX_PORT_ID);
			}

			fill_pdn_fqcsid_info(&pdn->up_csid, context->up_fqcsid);

			/* TODO: Add the handling if SGW or PGW not support Partial failure */
			/* Link peer node SGW or PGW csid with local csid */
			if (context->cp_mode != PGWC) {
				ret = update_peer_csid_link(&pdn->up_csid, &pdn->sgw_csid);
			} else {
				ret = update_peer_csid_link(&pdn->up_csid, &pdn->pgw_csid);
			}
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
						"Error: peer csid entry not found \n", LOG_VALUE);
				return GTPV2C_CAUSE_CONTEXT_NOT_FOUND;
			}

			if (link_sess_with_peer_csid(&pdn->up_csid, pdn, SX_PORT_ID)) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error : Failed to Link "
						"Session with MME CSID \n", LOG_VALUE);
				return -1;
			}

			/* Remove the session link from old CSID */
			sess_csid *tmp1 = NULL;
			peer_csid_key_t key = {0};

			key.iface = SX_PORT_ID;
			key.peer_local_csid = up_old_csid.local_csid[num_csid];
			memcpy(&key.peer_node_addr, &up_old_csid.node_addr, sizeof(node_address_t));

			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);

			if (tmp1 != NULL) {
				/* Remove node from csid linked list */
				tmp1 = remove_sess_csid_data_node(tmp1, pdn->seid);

				int8_t ret = 0;
				/* Update CSID Entry in table */
				ret = rte_hash_add_key_data(seid_by_peer_csid_hash, &key, tmp1);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add Session IDs entry"
							" for CSID = %u \n", LOG_VALUE,
							up_old_csid.local_csid[num_csid]);
					return GTPV2C_CAUSE_SYSTEM_FAILURE;
				}
				if (tmp1 == NULL) {
					/* Delete Local CSID entry */
					del_sess_peer_csid_entry(&key);
				}
			}
		}
	}

	return 0;
}
#endif /* CP_BUILD && USE_CSID */

int8_t
is_present(node_address_t *node) {

	if (node->ip_type == PDN_TYPE_IPV4) {
		if(node->ipv4_addr) {
			return 1;
		}
	} else if (node->ip_type == PDN_TYPE_IPV6) {
		if (node->ipv6_addr) {
			return 1;
		}
	}

	return 0;
}

void
fill_peer_info(node_address_t *dst_info, node_address_t *src_info) {

	if ((src_info->ip_type == IPV4_GLOBAL_UNICAST)
			|| (src_info->ip_type == PDN_TYPE_IPV4)) {
		dst_info->ip_type = PDN_TYPE_IPV4;
		dst_info->ipv4_addr = src_info->ipv4_addr;
	} else {
		dst_info->ip_type = PDN_TYPE_IPV6;
		memcpy(&dst_info->ipv6_addr,
				&src_info->ipv6_addr, IPV6_ADDRESS_LEN);
	}
}
