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

#include "up_acl.h"
#include "pfcp_enum.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_llist.h"
#include "pfcp_util.h"
#include "pfcp_association.h"
#include "li_interface.h"
#include "gw_adapter.h"
#include "seid_llist.h"
#include "pfcp_up_sess.h"
#include "../cp_dp_api/predef_rule_init.h"
#include "csid_struct.h"

#define OUT_HDR_DESC_VAL 1

extern uint16_t dp_comm_port;
extern struct in_addr dp_comm_ip;
extern struct in6_addr dp_comm_ipv6;
extern struct in_addr cp_comm_ip;
extern int clSystemLog;

#ifdef USE_CSID

/* TEMP fill the FQ-CSID form here */
/**
 * @brief  : Create and Fill the FQ-CSIDs
 * @param  : fq_csid
 * @param  : csids
 * @return : Returns nothing
 */
static void
est_set_fq_csid_t(pfcp_fqcsid_ie_t *fq_csid, fqcsid_t *csids)
{
	uint16_t len = 0;
	fq_csid->number_of_csids = csids->num_csid;

	if (csids->node_addr.ip_type == IPV4_TYPE) {
		fq_csid->fqcsid_node_id_type = IPV4_GLOBAL_UNICAST;
		memcpy(&(fq_csid->node_address),
				&(csids->node_addr.ipv4_addr), IPV4_SIZE);

		len += IPV4_SIZE;
	} else {
		fq_csid->fqcsid_node_id_type = IPV6_GLOBAL_UNICAST;
		memcpy(&(fq_csid->node_address),
				&(csids->node_addr.ipv6_addr), IPV6_ADDRESS_LEN);

		len += IPV6_ADDRESS_LEN;
	}

	for (uint8_t inx = 0; inx < csids->num_csid; inx++) {
		fq_csid->pdn_conn_set_ident[inx] = csids->local_csid[inx];
	}

	/* Adding 1 byte in header length for flags */
	len += PRESENT;
	pfcp_set_ie_header(&(fq_csid->header),
			PFCP_IE_FQCSID, (2 * (fq_csid->number_of_csids)) + len);

}

/**
 * @brief  : Fills fqcsid in pfcp session modification request
 * @param  : pfcp_sess_mod_rsp, request to be filled
 * @param  : sess, sess information
 * @return : Return 0 on success, -1 otherwise
 */
static int8_t
fill_fqcsid_sess_mod_rsp(pfcp_sess_mod_rsp_t *pfcp_sess_mod_rsp, pfcp_session_t *sess)
{
	/* Set SGW/PGW FQ-CSID */
	if (sess->up_fqcsid != NULL) {
		if ((sess->up_fqcsid)->num_csid) {
			est_set_fq_csid_t(&pfcp_sess_mod_rsp->up_fqcsid, sess->up_fqcsid);

			for (uint8_t inx = 0; inx < pfcp_sess_mod_rsp->up_fqcsid.number_of_csids; inx++) {
				if (pfcp_sess_mod_rsp->up_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
					uint32_t node_addr = 0;
					memcpy(&node_addr, pfcp_sess_mod_rsp->up_fqcsid.node_address, IPV4_SIZE);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Filled FQ-CSID in Sess MOD Resp, inx:%u,"
							"CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE, inx, pfcp_sess_mod_rsp->up_fqcsid.pdn_conn_set_ident[inx],
							IPV4_ADDR_HOST_FORMAT(node_addr));
				} else {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Filled FQ-CSID in Sess MOD Resp, inx:%u,"
							"CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, inx, pfcp_sess_mod_rsp->up_fqcsid.pdn_conn_set_ident[inx],
							IPv6_PRINT(IPv6_CAST(pfcp_sess_mod_rsp->up_fqcsid.node_address)));
				}
			}
		}
	}
	return 0;
}

int8_t
fill_fqcsid_sess_est_rsp(pfcp_sess_estab_rsp_t *pfcp_sess_est_rsp, pfcp_session_t *sess)
{
	/* Set SGW/PGW FQ-CSID */
	if (sess->up_fqcsid != NULL) {
		if ((sess->up_fqcsid)->num_csid) {
			est_set_fq_csid_t(&pfcp_sess_est_rsp->up_fqcsid, sess->up_fqcsid);

			for (uint8_t inx = 0; inx < pfcp_sess_est_rsp->up_fqcsid.number_of_csids; inx++) {
				uint32_t node_addr = 0;
				/* need to think about ip log */
				memcpy(&node_addr, pfcp_sess_est_rsp->up_fqcsid.node_address, IPV4_SIZE);
				(pfcp_sess_est_rsp->up_fqcsid.fqcsid_node_id_type == IPV6_GLOBAL_UNICAST) ?
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Filled FQ-CSID in Sess EST Resp, inx:%u,"
							"CSID:%u, Node IPv6 Addr:"IPv6_FMT"\n",
							LOG_VALUE, inx, pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[inx],
							IPv6_PRINT(IPv6_CAST((pfcp_sess_est_rsp->up_fqcsid.node_address)))):
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Filled FQ-CSID in Sess EST Resp, inx:%u,"
							"CSID:%u, Node IPv4 Addr:"IPV4_ADDR"\n",
							LOG_VALUE, inx, pfcp_sess_est_rsp->up_fqcsid.pdn_conn_set_ident[inx],
							IPV4_ADDR_HOST_FORMAT(node_addr));
			}
		}
	}
	return 0;
}

int
fill_peer_node_info_t(pfcp_session_t *sess, node_address_t *cp_node_addr)
{
	int16_t csid = 0;
	csid_key peer_info_t = {0};

	/* SGWC/PGWC/SAEGWC FQ-CSID */
	memcpy(&peer_info_t.cp_ip, cp_node_addr, sizeof(node_address_t));

	(peer_info_t.cp_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node CP IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info_t.cp_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"Peer Node CP IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info_t.cp_ip.ipv4_addr));

	/* Fill the enodeb/SGWU IP */
	{
		pfcp_session_datat_t *current = NULL;
		current = sess->sessions;
		while(current != NULL) {
			if (current->pdrs != NULL) {
				if ((current->pdrs)->pdi.src_intfc.interface_value == CORE) {
					memcpy(&peer_info_t.wb_peer_ip,
							&current->wb_peer_ip_addr, sizeof(node_address_t));

					(current->wb_peer_ip_addr.ip_type == IPV6_TYPE) ?
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"West Bound Peer Node IPv6 Address: "IPv6_FMT"\n",
								LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info_t.wb_peer_ip.ipv6_addr))):
						clLog(clSystemLog, eCLSeverityDebug,
								LOG_FORMAT"West Bound Peer Node IPv4 Address: "IPV4_ADDR"\n",
								LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info_t.wb_peer_ip.ipv4_addr));
					break;
				}
			}
			current = current->next;
		}
	}

	/* SGWU and PGWU peer node info */
	memcpy(&peer_info_t.up_ip,
			&(sess->up_fqcsid)->node_addr, sizeof(node_address_t));
	(peer_info_t.up_ip.ip_type == IPV6_TYPE) ?
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"User-Plane Node IPv6 Address: "IPv6_FMT"\n",
				LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info_t.up_ip.ipv6_addr))):
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"User-Plane Node IPv4 Address: "IPV4_ADDR"\n",
				LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info_t.up_ip.ipv4_addr));

	/* PGWU peer node Address */
	{
		pfcp_session_datat_t *current_t = NULL;
		current_t = sess->sessions;
		while(current_t != NULL) {
			if (current_t->pdrs != NULL) {
				if ((current_t->pdrs)->pdi.src_intfc.interface_value == ACCESS) {
					memcpy(&peer_info_t.eb_peer_ip,
							&current_t->eb_peer_ip_addr, sizeof(node_address_t));
					break;
				}
			}
			current_t = current_t->next;
		}
		(peer_info_t.eb_peer_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"East Bound Peer Node IPv6 Address: "IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info_t.eb_peer_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"East Bound Peer Node IPv4 Address: "IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info_t.eb_peer_ip.ipv4_addr));
	}


	/* Get local csid for set of peer node */
	csid = get_csid_entry(&peer_info_t);
	if (csid < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to assinged CSID..\n", LOG_VALUE);
		return -1;
	}

	/* Update the local csid into the UE context */
	uint8_t match = 0;
	for(uint8_t itr = 0; itr < (sess->up_fqcsid)->num_csid; itr++) {
		if ((sess->up_fqcsid)->local_csid[itr] == csid){
			match = 1;
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"CSID not generated, matched with exsiting CSID:%u\n",
					LOG_VALUE, csid);
			/* TODO: Validate it */
			/* Aleready Linked CSID */
			return itr;
		}
	}
	if (!match) {
		(sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid++] =
			csid;
		clLog(clSystemLog, eCLSeverityDebug,
				LOG_FORMAT"CSID Generated, Added in UP_FQCSID with CSID value:%u\n",
				LOG_VALUE, csid);
	}

	/* Link with eNB/SGWU node addr and local csid */
	if (is_present(&peer_info_t.wb_peer_ip)) {
		fqcsid_t *tmp = NULL;
		(peer_info_t.wb_peer_ip.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"West bound eNB/SGWU/WestBound Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST(peer_info_t.wb_peer_ip.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"West bound eNB/SGWU/WestBound Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_info_t.wb_peer_ip.ipv4_addr));

		/* Stored the SGW CSID by eNB/SGWU/West Bound Node address */
		tmp = get_peer_addr_csids_entry(&peer_info_t.wb_peer_ip,
				ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
					strerror(errno));
			return -1;
		}

		memcpy(&tmp->node_addr,
				&peer_info_t.wb_peer_ip, sizeof(node_address_t));

		if (!tmp->num_csid) {
				tmp->local_csid[tmp->num_csid++] = csid;
		} else {
			uint8_t match = 0;
			for (uint8_t itr = 0; itr < tmp->num_csid; itr++) {
				if (tmp->local_csid[itr] == csid){
					match = 1;
					break;
				}
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] = csid;
			}
		}

		if (sess->wb_peer_fqcsid == NULL) {
			sess->wb_peer_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (sess->wb_peer_fqcsid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for fqcsids entry\n",
						LOG_VALUE);
				return -1;
			}
		}

		/* Add the CSID in the Session List */
		(sess->wb_peer_fqcsid)->local_csid[(sess->wb_peer_fqcsid)->num_csid++] = csid;
		memcpy(&(sess->wb_peer_fqcsid)->node_addr,
				&peer_info_t.wb_peer_ip, sizeof(node_address_t));

		/* LINK West bound CSID with local CSID */
		if (link_peer_csid_with_local_csid(sess->wb_peer_fqcsid,
					sess->up_fqcsid, S1U_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed West Bound Peer CSID link with local CSID\n",
					LOG_VALUE);
			return -1;
		}

		((sess->wb_peer_fqcsid)->node_addr.ip_type == IPV6_TYPE) ?
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Fill Sess West Bound Peer Node IPv6 Addr:"IPv6_FMT"\n",
					LOG_VALUE, IPv6_PRINT(IPv6_CAST((sess->wb_peer_fqcsid)->node_addr.ipv6_addr))):
			clLog(clSystemLog, eCLSeverityDebug,
					LOG_FORMAT"Fill Sess West Bound Peer Node IPv4 Addr:"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT((sess->wb_peer_fqcsid)->node_addr.ipv4_addr));
	}

	/* Link with PGWU/East Bound node addr and local csid */
	if (is_present(&peer_info_t.eb_peer_ip)) {
		fqcsid_t *tmp = NULL;
		/* Stored the SGW CSID by PGW/East Bound Node address */
		tmp = get_peer_addr_csids_entry(&peer_info_t.eb_peer_ip, ADD_NODE);
		if (tmp == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
					strerror(errno));
			return -1;
		}
		memcpy(&tmp->node_addr,
				&peer_info_t.eb_peer_ip, sizeof(node_address_t));
		if (!tmp->num_csid) {
				tmp->local_csid[tmp->num_csid++] = csid;
		} else {
			uint8_t match = 0;
			for(uint8_t itr = 0; itr < tmp->num_csid; itr++) {
				if (tmp->local_csid[itr] == csid){
					match = 1;
					break;
				}
			}
			if (!match) {
				tmp->local_csid[tmp->num_csid++] = csid;
			}
		}

		if (sess->eb_peer_fqcsid == NULL) {
			sess->eb_peer_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (sess->eb_peer_fqcsid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to allocate the memory for fqcsids entry\n",
						LOG_VALUE);
				return -1;
			}
		}
		(sess->eb_peer_fqcsid)->local_csid[(sess->eb_peer_fqcsid)->num_csid++] = csid;
		memcpy(&(sess->eb_peer_fqcsid)->node_addr,
					&peer_info_t.eb_peer_ip, sizeof(node_address_t));

		/* LINK East bound CSID with local CSID */
		if (link_peer_csid_with_local_csid(sess->eb_peer_fqcsid,
					sess->up_fqcsid, SGI_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed East Bound Peer CSID link with local CSID\n",
					LOG_VALUE);
			return -1;
		}
	}

	/* LINK MME CSID with local CSID */
	if (sess->mme_fqcsid) {
		/* LINK MME CSID with local CSID */
		if (link_peer_csid_with_local_csid(sess->mme_fqcsid,
					sess->up_fqcsid, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed MME Peer CSID link with local CSID\n",
					LOG_VALUE);
			return -1;
		}
	}

	/* LINK SGW CSID with local CSID */
	if (sess->sgw_fqcsid) {
		/* LINK SGWC CSID with local CSID */
		if (link_peer_csid_with_local_csid(sess->sgw_fqcsid,
					sess->up_fqcsid, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed SGWC Peer CSID link with local CSID\n",
					LOG_VALUE);
			return -1;
		}
	}

	/* LINK PGW CSID with local CSID */
	if (sess->pgw_fqcsid) {
		/* LINK PGWC CSID with local CSID */
		if (link_peer_csid_with_local_csid(sess->pgw_fqcsid,
					sess->up_fqcsid, SX_PORT_ID) < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed PGWC Peer CSID link with local CSID\n",
					LOG_VALUE);
			return -1;
		}
	}
	return 0;
}
#endif /* USE_CSID */

/**
 * @brief  : Get cp node address
 * @param  : cp_node_addr, holds cp ip.
 * @param  : cp_fseid, Strucutre for hold cp fseid data
 * @return : Returns void
 */
static void
get_cp_node_addr(node_address_t *cp_node_addr, pfcp_fseid_ie_t *cp_fseid) {

	if (cp_fseid->v4) {
		cp_node_addr->ip_type = PDN_TYPE_IPV4;
		cp_node_addr->ipv4_addr = cp_fseid->ipv4_address;
	}
	if (cp_fseid->v6) {
		cp_node_addr->ip_type = PDN_TYPE_IPV6;
		memcpy(&cp_node_addr->ipv6_addr,
				&cp_fseid->ipv6_address, IPV6_ADDRESS_LEN);
	}
}

/**
 * @brief  : Process sdf filters
 * @param  : sdf_fltr_t , holds sdf filter data
 * @param  : sdf_fltr , update this strucutre using sdf filter data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_sdf_filters(pfcp_sdf_filter_ie_t *sdf_fltr_t, sdf_filter_t *sdf_fltr)
{
	if (sdf_fltr_t->fd) {
		/* len of flow description */
		sdf_fltr->len_of_flow_desc = sdf_fltr_t->len_of_flow_desc;

		sdf_fltr->fd = sdf_fltr_t->fd;
		/* flow description */
		memcpy(&sdf_fltr->flow_desc, sdf_fltr_t->flow_desc,
				sdf_fltr->len_of_flow_desc);
	}

	if (sdf_fltr_t->bid) {
		/* TODO:*/
	}

	if (sdf_fltr_t->fl) {
		/* TODO:*/
	}

	return 0;
}

/**
 * @brief  : Process ueip information
 * @param  : ue_addr, holds ue ip information
 * @param  : ue_addr_t, update this structure with ue ip info
 * @param  : ue_ip, copy ue ip address to this variable
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_ueip_info(pfcp_ue_ip_address_ie_t *ue_addr, ue_ip_addr_t *ue_addr_t,
				pfcp_session_datat_t *session)
{
	/* Check ipv4 address */
	if (ue_addr->v4) {
		/* UE IP Address */
		session->ipv4  = PRESENT;
		ue_addr_t->v4 = PRESENT;
		ue_addr_t->ipv4_address = ue_addr->ipv4_address;
		session->ue_ip_addr = ue_addr_t->ipv4_address;
	}

	/* Check the IPv6 Flag */
	if (ue_addr->v6) {
		/* TODO: IPv6 not Supported */
		session->ipv6 = PRESENT;
		ue_addr_t->v6 = PRESENT;
		ue_addr_t->ipv6_pfx_dlgtn_bits = ue_addr->ipv6_pfx_dlgtn_bits;
		memcpy(ue_addr_t->ipv6_address, ue_addr->ipv6_address, IPV6_ADDRESS_LEN);
		memcpy(session->ue_ipv6_addr, ue_addr->ipv6_address, IPV6_ADDRESS_LEN);
	}
	return 0;
}

/**
 * @brief  : Process pdi local teid info
 * @param  : lo_tied, hold information about local teid
 * @param  : f_teid, update this structure using local teid info
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdi_local_teid_info(pfcp_fteid_ie_t *lo_teid, fteid_ie_t *f_teid)
{
	/* Check the IPv4 Flag */
	if (lo_teid->v4) {
		/* TEID */
		f_teid->teid = lo_teid->teid;
		/* Local Interface IPv4 address */
		f_teid->ipv4_address = lo_teid->ipv4_address;
	}

	/* Check the IPv6 Flag */
	if (lo_teid->v6) {
		/* TEID */
		f_teid->teid = lo_teid->teid;
		/* Local Interface IPv6 address */
		memcpy(f_teid->ipv6_address, lo_teid->ipv6_address, IPV6_ADDRESS_LEN);
		// return -1;
	}

	/* Check the chid Flag */
	if (lo_teid->chid) {
		/* TODO: Not Supported */
		return -1;
	}

	/* Check the CHOOSE Flag */
	if (lo_teid->ch) {
		/* TODO: Not supported */
		return -1;
	}

	return 0;
}

static uint8_t
get_rule_ip_type(char *rule){

	char *s, *sp, *in[CB_FLD_NUM], tmp[MAX_LEN] = {0};
	static const char *dlm = " \t\n";
	strncpy(tmp, rule, MAX_LEN);
	s = tmp;
	in[0] = strtok_r(s, dlm, &sp);

	if(strstr(in[0], ":") != NULL)
		return RULE_IPV6;

	return RULE_IPV4;

}


/**
 * @brief  : Process pdi info
 * @param  : pdi_ie_t, holds pdi information
 * @param  : pdi, structure to be updated
 * @param  : session, session information
 * @param  : prcdnc_val , precondition value
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_pdr_pdi_info(pfcp_pdi_ie_t *pdi_ie_t, pdi_t *pdi,
			pfcp_session_datat_t **session, uint32_t prcdnc_val)
{
	/* M: Source Interface */
	if (pdi_ie_t->src_intfc.header.len) {
		pdi->src_intfc.interface_value = pdi_ie_t->src_intfc.interface_value;
	}

	/* Local F-TEID */
	if (pdi_ie_t->local_fteid.header.len) {
		if (process_pdi_local_teid_info(&pdi_ie_t->local_fteid,
					&pdi->local_fteid)) {
			return -1;
		}
	}

	/* Network Instance */
	if (pdi_ie_t->ntwk_inst.header.len) {
		memcpy(pdi->ntwk_inst.ntwk_inst, pdi_ie_t->ntwk_inst.ntwk_inst,
				sizeof(ntwk_inst_t));
	}

	/* UE IP Address */
	if (pdi_ie_t->ue_ip_address.header.len) {
		if (process_pdi_ueip_info(&pdi_ie_t->ue_ip_address, &pdi->ue_addr,
						*session)) {
			return -1;
		}
	}

	/* SDF Filters */
	if (pdi_ie_t->sdf_filter_count > 0) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Number of SDF Rule Rcv:%u\n",
			LOG_VALUE, pdi_ie_t->sdf_filter_count);

		for (int itr = 0; itr < pdi_ie_t->sdf_filter_count; itr++) {
			if (pdi_ie_t->sdf_filter[itr].header.len) {
				/* Add SDF rule entry in the ACL TABLE */
				struct sdf_pkt_filter pkt_filter = {0};
				pkt_filter.precedence = prcdnc_val;


				if (process_pdi_sdf_filters(&pdi_ie_t->sdf_filter[itr],
							&pdi->sdf_filter[pdi->sdf_filter_cnt++])) {
					return -1;
				}

				/* Reset the rule string */
				memset(pkt_filter.u.rule_str, 0, MAX_LEN);

				/* flow description */
				if (pdi_ie_t->sdf_filter[itr].fd) {
					memcpy(&pkt_filter.u.rule_str, &pdi_ie_t->sdf_filter[itr].flow_desc,
							pdi_ie_t->sdf_filter[itr].len_of_flow_desc);

					pkt_filter.rule_ip_type = get_rule_ip_type(pkt_filter.u.rule_str);
					if (!pdi_ie_t->src_intfc.interface_value) {
						/* swap the src and dst address for UL traffic.*/
						swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
					}

					(*session)->acl_table_indx[(*session)->acl_table_count] =
													get_acl_table_indx(&pkt_filter, SESS_CREATE);
					if ((*session)->acl_table_indx[(*session)->acl_table_count] <= 0) {
						/* TODO: ERROR Handling */
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ACL table creation failed\n", LOG_VALUE);
					}else{
						(*session)->acl_table_count++;
					}
				}
			}
		}
#ifdef DEFAULT_ACL_RULE_ADD
		uint8_t dir = 0;
		if (pdi_ie_t->src_intfc.interface_value) {
			dir = DOWNLINK;
		} else {
			dir = UPLINK;
		}

		if (up_sdf_default_entry_add((*session)->acl_table_indx[(*session)->acl_table_count],
																			prcdnc_val, dir)) {
			/* TODO: ERROR Handling */
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add default rule \n", LOG_VALUE);
		}
		pdi->sdf_filter_cnt++;
#endif /* DEFAULT_ACL_RULE_ADD */
	}
	return 0;
}

/**
 * @brief  : Process create urr info
 * @param  : urr, hold create urr info
 * @param  : urr_t, structure to be updated
 * @param  : cp_seid, cp session id
 * @param  : up_seid, up session id
 * @param  : cp_ip, peer node address
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_urr_info(pfcp_create_urr_ie_t *urr, urr_info_t *urr_t, uint64_t cp_seid,
		uint64_t up_seid, peer_addr_t cp_ip)
{
	peerEntry *timer_entry = NULL;
	urr_t  = get_urr_info_entry(urr->urr_id.urr_id_value, cp_ip);
	if(urr_t == NULL){
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" URR not found for "
			"URR_ID:%u while creating URR info\n",
			LOG_VALUE, urr->urr_id.urr_id_value);
		return -1;
	}

	/* Vol threshold for Usage report Gen */
	if(urr->vol_thresh.header.len){
		if(urr->vol_thresh.ulvol)
			urr_t->vol_thes_uplnk = urr->vol_thresh.uplink_volume;
		if(urr->vol_thresh.dlvol)
			urr_t->vol_thes_dwnlnk = urr->vol_thresh.downlink_volume;
	}

	/* Time threshold for Usage report Gen */
	if(urr->time_threshold.header.len){
		urr_t->time_thes = urr->time_threshold.time_threshold;
	}

	/* Measurement Method
	 * Now only Supporting
	 * 1) Time threshold base
	 * 2) Volume threshold base
	 * 3) Both  */
	if(urr->meas_mthd.volum && urr->meas_mthd.durat)
		urr_t->meas_method = VOL_TIME_BASED;
	else if(urr->meas_mthd.durat)
		urr_t->meas_method = TIME_BASED;
	else if(urr->meas_mthd.volum)
		urr_t->meas_method = VOL_BASED;
	else {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT" Measurement Method Not "
			"supported for URR ID %u\n", LOG_VALUE, urr->urr_id.urr_id_value);
		return -1;
	}

	if(urr->rptng_triggers.volth && urr->rptng_triggers.timth)
		urr_t->rept_trigg = VOL_TIME_BASED;
	else if(urr->rptng_triggers.timth)
		urr_t->rept_trigg = TIME_BASED;
	else if(urr->rptng_triggers.volth)
		urr_t->rept_trigg = VOL_BASED;
	else {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT" Trigger Type  Not supported for URR ID %u\n",
			LOG_VALUE, urr->urr_id.urr_id_value);
		return -1;
	}

	/* Defaulte setting to 0 as it is start of Usage report Generation */
	urr_t->uplnk_data = 0;
	urr_t->dwnlnk_data = 0;
	urr_t->start_time = current_ntp_timestamp();
	urr_t->end_time = 0;
	urr_t->first_pkt_time = 0;
	urr_t->last_pkt_time = 0;

	clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT" URR created with urr id %u\n",
			LOG_VALUE, urr_t->urr_id);

	if((urr_t->rept_trigg == TIME_BASED) || (urr_t->rept_trigg == VOL_TIME_BASED)) {
		timer_entry = fill_timer_entry_usage_report(&dest_addr_t.ipv4, urr_t, cp_seid, up_seid);
		if(!(add_timer_entry_usage_report(timer_entry, urr_t->time_thes, timer_callback))) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Faild to add timer "
				"entry while creating URR info\n", LOG_VALUE);
		}

		if (starttimer(&timer_entry->pt) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Periodic Timer "
			"failed to start while creating URR info\n", LOG_VALUE);
		}
	}


	return 0;
}

/**
 * @brief  : Process create bar info
 * @param  : bar, hold create bar info
 * @param  : bar_t, structure to be updated
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_bar_info(pfcp_create_bar_ie_t *bar, bar_info_t *bar_t)
{
	/* M: BAR ID */
	/* Downlink Data Notification Delay */
	/* Suggested Buffering Packet Count */

	/* TODO: Implement Handling */
	return 0;
}

/**
 * @brief  : Process create qer info
 * @param  : qer, hold create qer info
 * @param  : quer_t, structure to be updated
 * @param  : session, session information
 * @param  : cp_ip, peer node address
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_qer_info(pfcp_create_qer_ie_t *qer, qer_info_t **quer_t,
		pfcp_session_datat_t **session, peer_addr_t cp_ip)
{
	qer_info_t *qer_t = NULL;
	/* M: QER ID */
	if (qer->qer_id.header.len) {
		/* Get allocated memory location */
		qer_t = get_qer_info_entry(qer->qer_id.qer_id_value, quer_t, cp_ip);
		if (qer_t == NULL)
			return -1;
	}

	/* M: Gate Status */
	if (qer->gate_status.header.len) {
		/* Uplink Action Allow/Drop */
		qer_t->gate_status.ul_gate = qer->gate_status.ul_gate;
		/* Downlink Action Allow/Drop */
		qer_t->gate_status.dl_gate = qer->gate_status.dl_gate;
	}

	/* QER Correlation ID */
	if (qer->qer_corr_id.header.len) {
		qer_t->qer_corr_id_val = qer->qer_corr_id.qer_corr_id_val;
	}

	/* MBR: Maximum Bitrate */
	if (qer->maximum_bitrate.header.len) {
		/* Maximum Bitrare allow on Uplink */
		qer_t->max_bitrate.ul_mbr = qer->maximum_bitrate.ul_mbr;
		/* Maximum Bitrare allow on Downlink */
		qer_t->max_bitrate.dl_mbr = qer->maximum_bitrate.dl_mbr;
	}

	/* GBR: Guaranteed Bitrate */
	if (qer->guaranteed_bitrate.header.len) {
		/* Guaranteed Bitrare allow on Uplink */
		qer_t->guaranteed_bitrate.ul_gbr = qer->guaranteed_bitrate.ul_gbr;
		/* Guaranteed Bitrare allow on Downlink */
		qer_t->guaranteed_bitrate.dl_gbr = qer->guaranteed_bitrate.dl_gbr;
	}

	/* Packet Rate */
	if (qer->packet_rate.header.len) {
		/* Check Uplink Packet Rate Flag */
		if (qer->packet_rate.ulpr) {
			/* Maximum Uplink Packet Rate */
			qer_t->packet_rate.max_uplnk_pckt_rate =
				qer->packet_rate.max_uplnk_pckt_rate;
			/* Uplink Time Unit */
			qer_t->packet_rate.uplnk_time_unit =
				qer->packet_rate.uplnk_time_unit;
		}
		/* Check Downlink Packet Rate Flag */
		if (qer->packet_rate.dlpr) {
			/* Maximum Downlink Packet Rate */
			qer_t->packet_rate.max_dnlnk_pckt_rate =
				qer->packet_rate.max_dnlnk_pckt_rate;
			/* Downlink Time Unit */
			qer_t->packet_rate.dnlnk_time_unit =
				qer->packet_rate.dnlnk_time_unit;
		}
	}

	/* Downlink Flow Level Marking */
	if (qer->dl_flow_lvl_marking.header.len) {
		/* Check ToS/Traffic Class Flag */
		if (qer->dl_flow_lvl_marking.ttc) {
			qer_t->dl_flow_lvl_marking.ttc =
				qer->dl_flow_lvl_marking.ttc;
			/* ToS/Traffic Class */
			memcpy(&(qer_t->dl_flow_lvl_marking.tostraffic_cls),
				&(qer->dl_flow_lvl_marking.tostraffic_cls), sizeof(qer_t->dl_flow_lvl_marking.tostraffic_cls));
		}

		/* Check Service Class Indicator Flag */
		if (qer->dl_flow_lvl_marking.sci) {
			qer_t->dl_flow_lvl_marking.sci =
				qer->dl_flow_lvl_marking.sci;
			/* Service Class Indicator */
			memcpy(&(qer_t->dl_flow_lvl_marking.svc_cls_indctr),
				&(qer->dl_flow_lvl_marking.svc_cls_indctr) ,sizeof(qer->dl_flow_lvl_marking.svc_cls_indctr));
		}
	}

	/* QOS Flow Ident */
	if (qer->qos_flow_ident.header.len) {
		qer_t->qos_flow_ident.qfi_value = qer->qos_flow_ident.qfi_value;
	}

	/* RQI: Reflective QoS */
	if (qer->reflective_qos.header.len) {
		qer_t->reflective_qos.rqi = qer->reflective_qos.rqi;
	}

	/* Paging policy */
	if (qer->paging_plcy_indctr.header.len) {
		qer_t->paging_plcy_indctr.ppi_value = qer->paging_plcy_indctr.ppi_value;
	}

	/* Averaging Window */
	if (qer->avgng_wnd.header.len) {
		qer_t->avgng_wnd.avgng_wnd = qer->avgng_wnd.avgng_wnd;
	}

	/* Pointer to Sessions */
	qer_t->session = *session;

	return 0;
}

/**
 * @brief  : update far apply action
 * @param  : far, hold create far apply action info
 * @param  : far_t, structure to be updated
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
far_apply_action(pfcp_apply_action_ie_t *far, apply_action *far_t)
{
	/* M: Apply Action */
	if (far->header.len) {
		/* Duplicate the packets */
		far_t->dupl = far->dupl;
		/* Buffer the packets */
		far_t->buff = far->buff;
		/* Forward the packets */
		far_t->forw = far->forw;
		/* Drop the packets */
		far_t->drop = far->drop;
		/* Notify the CP function about arrival of a
		 * first downlink packet being buffered */
		far_t->nocp = far->nocp;
	}
	return 0;
}

/**
 * @brief  : Process create far info
 * @param  : far, hold create far info
 * @param  : session, session information
 * @param  : up_seid , session id
 * @param  : sess,pfcp_session_t infomation
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_far_info(pfcp_create_far_ie_t *far,
		pfcp_session_datat_t **session, uint64_t up_seid,
		pfcp_session_t *sess)
{
	node_address_t peer_addr = {0};
	far_info_t *far_t = NULL;

	/* M: FAR ID */
	if (far->far_id.header.len) {
		/* Get allocated memory location */
		far_t = get_far_info_entry(far->far_id.far_id_value, sess->cp_ip);

		if (far_t == NULL)
			return -1;
	}

	/* M: Apply Action */
	if (far->apply_action.header.len) {
		if (far_apply_action(&far->apply_action, &far_t->actions)) {
			/* TODO: Error Handling */
		}
	}

	/* Forwarding Parameters */
	if (far->frwdng_parms.header.len) {
		/* M: Destination Interface */
		if (far->frwdng_parms.dst_intfc.header.len) {
			/* Destination Interface */
			far_t->frwdng_parms.dst_intfc.interface_value =
				far->frwdng_parms.dst_intfc.interface_value;
		}

		/* Outer Header Creation */
		if (far->frwdng_parms.outer_hdr_creation.header.len) {

			/* TODO: Add the handling for dual stack connectivity scenario */
			if (far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4) {
				far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc = GTPU_UDP_IPv4;
					/* Linked Outer header Creation with Session */
				if (far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4 ==
						OUT_HDR_DESC_VAL) {
					(*session)->hdr_crt = GTPU_UDP_IPv4;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Outer Header Desciprition(GTPU_UDP_IPv4) : %u\n",
							LOG_VALUE,
							far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);
				}
			} else if (far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6) {
				far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc = GTPU_UDP_IPv6;
					/* Linked Outer header Creation with Session */
				if (far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6 ==
						OUT_HDR_DESC_VAL) {
					(*session)->hdr_crt = GTPU_UDP_IPv6;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Outer Header Desciprition(GTPU_UDP_IPv6) : %u\n",
							LOG_VALUE,
							far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);
				}
			} else {
				/* Linked Outer header Creation with Session */
				(*session)->hdr_crt = NOT_SET_OUT_HDR_RVL_CRT;
			}

			/* TEID */
			far_t->frwdng_parms.outer_hdr_creation.teid =
				far->frwdng_parms.outer_hdr_creation.teid;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR Teid : %u\n",
				LOG_VALUE, far_t->frwdng_parms.outer_hdr_creation.teid);

			/* Customer-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.ctag =
				far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.ctag;

			/* Service-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.stag =
				far->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.stag;

			/* Port Number */
			far_t->frwdng_parms.outer_hdr_creation.port_number =
				far->frwdng_parms.outer_hdr_creation.port_number;

			/* Flush the exsting peer node entry from connection table */
			if ((far_t->frwdng_parms.outer_hdr_creation.ipv4_address != 0)
					&& (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0)) {
				memset(&peer_addr, 0, sizeof(node_address_t));
				peer_addr.ip_type = IPV4_TYPE;
				peer_addr.ipv4_addr = far_t->frwdng_parms.outer_hdr_creation.ipv4_address;
				dp_flush_session(peer_addr, sess->up_seid);
			}

			/* Flush the exsting peer node entry from connection table */
			if (memcmp(far_t->frwdng_parms.outer_hdr_creation.ipv6_address,
						far->frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN)) {
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV6_TYPE;
					memcpy(peer_addr.ipv6_addr,
							far_t->frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);
				dp_flush_session(peer_addr, sess->up_seid);
			}

			if(far->frwdng_parms.outer_hdr_creation.ipv4_address != 0){
				/* IPv4 Address */
				far_t->frwdng_parms.outer_hdr_creation.ip_type = IPV4_TYPE;
				far_t->frwdng_parms.outer_hdr_creation.ipv4_address =
					far->frwdng_parms.outer_hdr_creation.ipv4_address;
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR dst Ipv4 Address :"
					IPV4_ADDR"\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT(far_t->frwdng_parms.outer_hdr_creation.ipv4_address));
			} else if(far->frwdng_parms.outer_hdr_creation.ipv6_address != NULL){
				far_t->frwdng_parms.outer_hdr_creation.ip_type = IPV6_TYPE;
				memcpy(far_t->frwdng_parms.outer_hdr_creation.ipv6_address,
						far->frwdng_parms.outer_hdr_creation.ipv6_address,
						IPV6_ADDRESS_LEN);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR dst Ipv6 Address :"
					IPv6_FMT"\n", LOG_VALUE,
					IPv6_PRINT(*(struct in6_addr *)far_t->frwdng_parms.outer_hdr_creation.ipv6_address));

			}
		} else {
			/* Linked Outer header Creation with Session */
			(*session)->hdr_crt = NOT_SET_OUT_HDR_RVL_CRT;
		}

		uint8_t tmp_ipv6[IPV6_ADDR_LEN] = {0};
		if (far->frwdng_parms.dst_intfc.interface_value == ACCESS ) {
			/* Add eNB peer node information in connection table */
			if ((far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) ||
				(memcmp(&far->frwdng_parms.outer_hdr_creation.ipv6_address,
					&tmp_ipv6, IPV6_ADDR_LEN))) {
				if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
					/* Fill the peer node entry and add the entry into connection table */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV4_TYPE;
					peer_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;

					if ((add_node_conn_entry(peer_addr, up_seid, S1U_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT":Failed to add connection entry for eNB\n",
								LOG_VALUE);
					}
#endif /* USE_REST */
					(*session)->wb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV4;
					(*session)->wb_peer_ip_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"MBR: West Bound Peer IPv4 Node Addr:"IPV4_ADDR"\n",
							LOG_VALUE, IPV4_ADDR_HOST_FORMAT((*session)->wb_peer_ip_addr.ipv4_addr));

				} else {
					(*session)->wb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV6;
					memcpy((*session)->wb_peer_ip_addr.ipv6_addr,
							far->frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"MBR: West Bound Peer IPv6 Node Addr:"IPv6_FMT"\n",
							LOG_VALUE,
							IPv6_PRINT(*(struct in6_addr *)(*session)->wb_peer_ip_addr.ipv6_addr));
#ifdef USE_REST
					/* Fill the peer node entry and add the entry into connection table */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV6_TYPE;
					memcpy(peer_addr.ipv6_addr,
							far->frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDRESS_LEN);

					if ((add_node_conn_entry(peer_addr, up_seid, S1U_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT":Failed to add connection entry for eNB\n",
								LOG_VALUE);
					}
#endif /* USE_REST */
				}

				/* Update the Session state */
				if (far->frwdng_parms.outer_hdr_creation.teid != 0) {
					(*session)->sess_state = CONNECTED;
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session State Change : "
								"IN_PROGRESS --> CONNECTED\n", LOG_VALUE);
				}
			}
		} else {
			/* Add S5S8 peer node information in connection table */
			if ((far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) ||
				(memcmp(&far->frwdng_parms.outer_hdr_creation.ipv6_address,
					&tmp_ipv6, IPV6_ADDR_LEN))) {
				if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
#ifdef USE_REST
					/* Fill the peer node entry and add the entry into connection table */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV4_TYPE;
					peer_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;

					if ((add_node_conn_entry(peer_addr, up_seid, SGI_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT":Failed to add connection entry for S5S8\n",
							LOG_VALUE);
					}
#endif /* USE_REST */
					(*session)->eb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV4;
					(*session)->eb_peer_ip_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"MBR: West Bound Peer IPv4 Node Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT((*session)->eb_peer_ip_addr.ipv4_addr));

				} else {
					/* TODO:PATH MANG: Add the entry for IPv6 Address */
					(*session)->eb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV6;
					memcpy((*session)->eb_peer_ip_addr.ipv6_addr,
							far->frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"MBR: West Bound Peer IPv6 Node Addr:"IPv6_FMT"\n",
							LOG_VALUE, IPv6_PRINT(*(struct in6_addr *)(*session)->eb_peer_ip_addr.ipv6_addr));
#ifdef USE_REST
					/* Fill the peer node entry and add the entry into connection table */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV6_TYPE;
					memcpy(peer_addr.ipv6_addr,
							far->frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDRESS_LEN);

					if ((add_node_conn_entry(peer_addr, up_seid, SGI_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT":Failed to add connection entry for S5S8\n",
								LOG_VALUE);
					}
#endif /* USE_REST */
				}


				/* Update the Session state */
				if (far->frwdng_parms.outer_hdr_creation.teid != 0) {
					(*session)->sess_state = CONNECTED;
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session State Change : "
								"IN_PROGRESS --> CONNECTED\n", LOG_VALUE);
				}
			}
		}
	} else {
		/* Linked Outer header Creation with Session */
		(*session)->hdr_crt = NOT_SET_OUT_HDR_RVL_CRT;
	}

	/* Buffering Action Rule Identifier */
	if (far->bar_id.header.len) {

		far_t->bar_id_value = far->bar_id.bar_id_value;
	}

	/* Duplicating Parameters */
	if (far->dupng_parms_count) {
		/* Fill Duplicating Parameters For User Level Packet Copying */
		fill_li_duplicating_params(far, far_t, sess);
	}

	/* Pointer to Session */
	far_t->session = *session;
	return 0;
}

/**
 * @brief  : Process update pdr info
 * @param  : pdr, hold pdr info
 * @param  : sess , pfcp session info
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_update_pdr_info(pfcp_update_pdr_ie_t *pdr, pfcp_session_t *sess)
{
	int ret = 0;
	pfcp_session_datat_t *session = NULL;
	pdr_info_t *pdr_t = NULL;
	struct sdf_pkt_filter pkt_filter = {0};

	if (pdr->pdi.local_fteid.teid) {
		session = get_sess_by_teid_entry(pdr->pdi.local_fteid.teid,
										&sess->sessions, SESS_MODIFY);
		if (session == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to create "
				"the session for TEID:%u", LOG_VALUE, pdr->pdi.local_fteid.teid);
			return -1;
		}
	} else if (pdr->pdi.ue_ip_address.header.len){

		ue_ip_t ue_ip = {0};

		if (pdr->pdi.ue_ip_address.v4) {
			ue_ip.ue_ipv4 = pdr->pdi.ue_ip_address.ipv4_address;
			session = get_sess_by_ueip_entry(ue_ip,	&sess->sessions, SESS_MODIFY);
			if (session == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to create the session for UE_IPv4:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(pdr->pdi.ue_ip_address.ipv4_address));
				return -1;
			}
		}

		if (pdr->pdi.ue_ip_address.v6) {
			memcpy(ue_ip.ue_ipv6, pdr->pdi.ue_ip_address.ipv6_address, IPV6_ADDRESS_LEN);
			char ipv6[IPV6_STR_LEN];
			inet_ntop(AF_INET6, ue_ip.ue_ipv6, ipv6, IPV6_STR_LEN);

			if (pdr->pdi.ue_ip_address.v4) {
				int ret = 0;
				/* Session Entry not present. Add new session entry */
				ret = rte_hash_add_key_data(sess_by_ueip_hash,
						&ue_ip, session);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add entry for UE IPv4: "IPV4_ADDR" or IPv6 Addr: %s"
							", Error: %s\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip.ue_ipv4), ue_ip.ue_ipv6,
							rte_strerror(abs(ret)));

					return -1;
				}
			} else {
				session = get_sess_by_ueip_entry(ue_ip,	&sess->sessions, SESS_MODIFY);
				if (session == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to create the session for IPv6 Addr: %s\n",
							LOG_VALUE, ipv6);
					return -1;
				}
			}
		}

	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" TIED and UE_IP_addr "
			"both are NULL \n", LOG_VALUE);
		return -1;
	}

	/* M: PDR ID */
	if (pdr->pdr_id.header.len) {
		rule_key hash_key = {0};

		hash_key.cp_ip_addr.type = sess->cp_ip.type;
		if(sess->cp_ip.type == PDN_TYPE_IPV4){
			hash_key.cp_ip_addr.ip.ipv4_addr = sess->cp_ip.ipv4.sin_addr.s_addr;
		}else{
			memcpy(hash_key.cp_ip_addr.ip.ipv6_addr, sess->cp_ip.ipv6.sin6_addr.s6_addr, IPV6_ADDRESS_LEN);
		}
		hash_key.id = (uint32_t)pdr->pdr_id.rule_id;

		ret = rte_hash_lookup_data(pdr_by_id_hash,
				&hash_key, (void **)&pdr_t);

		if ( ret < 0) {
			return -1;
		}
		if(pdr_t->rule_id != pdr->pdr_id.rule_id)
			return -1;
	}

	if ((pdr->pdi).sdf_filter_count) {
		/*First remove older sdf context from acl rules*/
		for(int itr = 0; itr < pdr_t->pdi.sdf_filter_cnt; itr++){

			pkt_filter.precedence = pdr_t->prcdnc_val;
			/* Reset the rule string */
			memset(pkt_filter.u.rule_str, 0, MAX_LEN);

			/* flow description */
			if (pdr_t->pdi.sdf_filter[itr].fd) {
				memcpy(&pkt_filter.u.rule_str, &pdr_t->pdi.sdf_filter[itr].flow_desc,
						pdr_t->pdi.sdf_filter[itr].len_of_flow_desc);
				pkt_filter.rule_ip_type = get_rule_ip_type(pkt_filter.u.rule_str);
				if (!pdr_t->pdi.src_intfc.interface_value) {
					/* swap the src and dst address for UL traffic.*/
					swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
				}
				int flag = 0;
				int32_t indx = get_acl_table_indx(&pkt_filter, SESS_MODIFY);
				if(indx > 0){
					for(uint16_t itr = 0; itr < session->acl_table_count; itr++){
						if(session->acl_table_indx[itr] == indx){
							flag = 1;
						}
						if(flag && itr != session->acl_table_count - 1)
							session->acl_table_indx[itr] = session->acl_table_indx[itr+1];
					}
				}

				if(flag){
					session->acl_table_indx[session->acl_table_count] = 0;
					session->acl_table_count--;
				}
			}
		}
	}

	if (pdr->precedence.header.len) {
		pdr_t->prcdnc_val = pdr->precedence.prcdnc_val;
	}

	/* M: Packet Detection Information */
	if (pdr->pdi.header.len) {
		if (process_pdr_pdi_info(&pdr->pdi, &pdr_t->pdi, &session,
				pdr_t->prcdnc_val)) {
			/* TODO:Error handling  */
		}
	}

	/* C: Outer Header Removal */
	if (pdr->outer_hdr_removal.header.len) {
		/* Fill the outer header header description */
		pdr_t->outer_hdr_removal.outer_hdr_removal_desc =
			pdr->outer_hdr_removal.outer_hdr_removal_desc;
		/* Linked into Session Obj */
		session->hdr_rvl = pdr->outer_hdr_removal.outer_hdr_removal_desc;
	}
	return 0;
}

static int
fill_sdf_rule_by_rule_name(uint8_t *rule_name, pdi_t *pdi,
		pfcp_session_datat_t **session)
{
	int ret = 0;
	pcc_rule_name rule = {0};
	struct pcc_rules *pcc = NULL;

	if (rule_name == NULL)
		return -1;

	/* Fill/Copy the Rule Name */
	memcpy(&rule.rname, (void *)rule_name, strnlen(((char *)rule_name),MAX_RULE_LEN));

	pcc = get_predef_pcc_rule_entry(&rule, GET_RULE);
	if (pcc == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Failed to GET PCC Rule in the pcc table"
				" for Rule_Name: %s\n", LOG_VALUE, rule.rname);
		return -1;
	}else {
		pdi->sdf_filter_cnt = pcc->sdf_idx_cnt;
		for (uint8_t idx = 0; idx < pcc->sdf_idx_cnt; idx++) {
			void *sdf_rule = NULL;
			struct pkt_filter *sdf = NULL;
			ret = get_predef_rule_entry(pcc->sdf_idx[idx],
						SDF_HASH, GET_RULE, &sdf_rule);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to GET SDF Rule from the internal table"
						"for SDF_Indx: %u\n", LOG_VALUE, pcc->sdf_idx[idx]);
				continue;
			} else {
				/* Fill the QER info */
				sdf = (struct pkt_filter *)sdf_rule;
				if (sdf != NULL) {
					/* Add SDF rule entry in the ACL TABLE */
					struct sdf_pkt_filter pkt_filter = {0};
					pkt_filter.precedence = pcc->precedence;

					/* len of flow description */
					pdi->sdf_filter[idx].len_of_flow_desc = sizeof(sdf->u.rule_str);

					/* flow description */
					memcpy(&pdi->sdf_filter[idx].flow_desc, &(sdf->u).rule_str,
							pdi->sdf_filter[idx].len_of_flow_desc);

					/* Reset the rule string */
					memset(pkt_filter.u.rule_str, 0, MAX_LEN);

					/* Fill the flow description*/
					memcpy(&pkt_filter.u.rule_str, &pdi->sdf_filter[idx].flow_desc,
							pdi->sdf_filter[idx].len_of_flow_desc);
					pkt_filter.rule_ip_type = get_rule_ip_type(pkt_filter.u.rule_str);

					if (!pdi->src_intfc.interface_value) {
						/* swap the src and dst address for UL traffic.*/
						swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
					}

					(*session)->acl_table_indx[(*session)->acl_table_count] =
													get_acl_table_indx(&pkt_filter, SESS_CREATE);
					if ((*session)->acl_table_indx[(*session)->acl_table_count] <= 0) {
						/* TODO: ERROR Handling */
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"ACL table creation failed\n", LOG_VALUE);
						continue;
					}else{
						(*session)->acl_table_count++;
					}
					(*session)->predef_rule = TRUE;

				} /* TODO: ERROR Handling */
			}
		}
	}
	return 0;
}

/**
 * @brief  : Process create pdr info
 * @param  : pdr, hold create pdr info
 * @param  : session, pfcp session data related info
 * @param  : sess, pfcp_session_t
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_create_pdr_info(pfcp_create_pdr_ie_t *pdr, pfcp_session_datat_t **session,
			pfcp_session_t *sess)
{
	pdr_info_t *pdr_t = NULL;

	/* M: PDR ID */
	if (pdr->pdr_id.header.len) {
		pdr_t = get_pdr_info_entry(pdr->pdr_id.rule_id,
				&(*session)->pdrs, SESS_CREATE, sess->cp_ip);
		if (pdr_t == NULL)
			return -1;

		pdr_t->rule_id = pdr->pdr_id.rule_id;
	}

	/* M: Precedance */
	if (pdr->precedence.header.len) {
		pdr_t->prcdnc_val = pdr->precedence.prcdnc_val;
	}

	/* M: Packet Detection Information */
	if (pdr->pdi.header.len) {
		if (process_pdr_pdi_info(&pdr->pdi, &pdr_t->pdi, session,
				pdr_t->prcdnc_val)) {
			return -1;
		}
	}

	/* C: Outer Header Removal */
	if (pdr->outer_hdr_removal.header.len) {
		/* Fill the outer header header description */
		pdr_t->outer_hdr_removal.outer_hdr_removal_desc =
			pdr->outer_hdr_removal.outer_hdr_removal_desc;
		/* Linked into Session Obj */
		(*session)->hdr_rvl = pdr->outer_hdr_removal.outer_hdr_removal_desc;
	} else {
		/* Linked into Session Obj */
		(*session)->hdr_rvl = NOT_SET_OUT_HDR_RVL_CRT;
	}

	/* Forwarding Action Rule (FAR ID) Identifer */
	if (pdr->far_id.header.len) {
		/* Add FAR ID entry in the hash table */
		if (add_far_info_entry(pdr->far_id.far_id_value, &pdr_t->far, sess->cp_ip)) {
			return -1;
		}
		(pdr_t->far)->far_id_value = pdr->far_id.far_id_value;
		(pdr_t->far)->pdr_count++;
	}

	/* QoS Enforcement Rule (QER ID) Identifiers */
	if (pdr->qer_id_count > 0) {
		pdr_t->qer_count = pdr->qer_id_count;
		for (int itr = 0; itr < pdr_t->qer_count; itr++) {
			/* Add QER ID entry in the hash table */
			if (add_qer_info_entry(pdr->qer_id[itr].qer_id_value, &pdr_t->quer, sess->cp_ip)) {
			     return -1;
			}
			(pdr_t->quer[itr]).qer_id = pdr->qer_id[itr].qer_id_value;
		}
	}

	/* Usage Reporting Rule (URR ID) Identifiers */
	if (pdr->urr_id_count > 0) {
		pdr_t->urr_count = pdr->urr_id_count;
		for (int itr = 0; itr < pdr_t->urr_count; itr++) {
			/* Add URR ID entry in the hash table */
			if (add_urr_info_entry(pdr->urr_id[itr].urr_id_value, &pdr_t->urr, sess->cp_ip)) {
				return -1;
			}
			(pdr_t->urr[itr]).urr_id = pdr->urr_id[itr].urr_id_value;
			(pdr_t->urr[itr]).pdr_count++;
		}
	}

	/* Predefine Rules */
	if (pdr->actvt_predef_rules_count) {
		pdr_t->predef_rules_count = pdr->actvt_predef_rules_count;
		clLog(clSystemLog, eCLSeverityDebug, "Number of Predef Rule Rcv:%u\n",
				pdr_t->predef_rules_count);

		for (int itr = 0; itr < pdr_t->predef_rules_count; itr++) {
			/* Add predefine rule entry in the table */
			memcpy(&pdr_t->predef_rules[itr], &pdr->actvt_predef_rules[itr],
					pdr->actvt_predef_rules[itr].header.len);

			/* Based on the rule name fill/generate the QER */
			qer_info_t *qer = NULL;
			qer = add_rule_info_qer_hash(pdr->actvt_predef_rules[itr].predef_rules_nm);
			if (qer != NULL) {
				/* Pointer to Sessions */
				qer->session = *session;

				qer->next = NULL;
				/* Linked the QER with PDR */
				if (pdr_t->quer == NULL) {
					pdr_t->quer = qer;
				} else {
					qer_info_t *tmp = NULL;
					tmp = pdr_t->quer;

					while (tmp->next != NULL) {
						tmp = tmp->next;
					}
					tmp->next = qer;
				}
				pdr_t->qer_count++;
			}
			/* TODO: Add Error handling */

			/* Based on the rule name fill the SDF Information */
			fill_sdf_rule_by_rule_name(pdr->actvt_predef_rules[itr].predef_rules_nm,
					&pdr_t->pdi, session);
		}
	}

	clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"Entry Add PDR_ID:%u, precedence:%u, ACL_TABLE_INDX:%u\n",
			LOG_VALUE, pdr->pdr_id.rule_id, pdr->precedence.prcdnc_val,
			(*session)->acl_table_indx[(*session)->acl_table_count - 1]);

	/* pointer to the session */
	pdr_t->session = sess;
	return 0;
}

/**
 * @brief  : Decode imsi value to 64 bit uint
 * @param  : buf, incoming data
 * @param  : len, length
 * @param  : imsi, buffer to store decoded data
 * @return : Returns 0 in case of success , -1 otherwise
 */
static void
decode_imsi_to_u64(uint8_t *buf, int len, uint64_t *imsi)
{
	char hex[16] = {0};
	bool flag = false;

	for(uint32_t i = 0; i < len; i++) {
		if (i == len -1 && (((buf[i] & 0xF0)>>4) == 0x0F)) {
			sprintf(hex + i*2 , "%02x", (buf[i] & 0x0F)<<4);
			flag = true;
		} else
			sprintf(hex + i*2 , "%02x",(((buf[i] & 0x0F)<<4) | ((buf[i] & 0xF0)>>4)));
	}
	sscanf(hex, "%lu", imsi);

	if (flag)
		*imsi /= 10;
	return;
}

static pfcp_session_datat_t *
get_pfcp_session_data(pfcp_create_pdr_ie_t *create_pdr, pfcp_session_t *sess)
{
	pfcp_session_datat_t *session = NULL;
	if (create_pdr->pdi.local_fteid.teid) {
		session = get_sess_by_teid_entry(create_pdr->pdi.local_fteid.teid,
				&sess->sessions, SESS_CREATE);
		if (session == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to create the session for TEID:%u", LOG_VALUE,
					create_pdr->pdi.local_fteid.teid);
			return NULL;
		}
	} else if (create_pdr->pdi.ue_ip_address.header.len) {

		ue_ip_t ue_ip = {0};

		if (create_pdr->pdi.ue_ip_address.v4) {
			ue_ip.ue_ipv4 = create_pdr->pdi.ue_ip_address.ipv4_address;
			session = get_sess_by_ueip_entry(ue_ip, &sess->sessions, SESS_CREATE);
			if (session == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to create the session for UE_IPv4:"IPV4_ADDR"", LOG_VALUE,
						IPV4_ADDR_HOST_FORMAT(create_pdr->pdi.ue_ip_address.ipv4_address));
				return NULL;
			}
		}

		if (create_pdr->pdi.ue_ip_address.v6) {
			memset(&ue_ip, 0, sizeof(ue_ip_t));
			memcpy(ue_ip.ue_ipv6, create_pdr->pdi.ue_ip_address.ipv6_address, IPV6_ADDRESS_LEN);

			char ipv6[IPV6_STR_LEN];
			inet_ntop(AF_INET6, ue_ip.ue_ipv6, ipv6, IPV6_STR_LEN);

			if (create_pdr->pdi.ue_ip_address.v4) {
				int ret = 0;
				/* Session Entry not present. Add new session entry */
				ret = rte_hash_add_key_data(sess_by_ueip_hash,
						&ue_ip, session);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add entry for UE IPv4: "IPV4_ADDR" or IPv6 Addr: %s"
							", Error: %s\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip.ue_ipv4), ipv6,
							rte_strerror(abs(ret)));

					return NULL;
				}
			} else {
				session = get_sess_by_ueip_entry(ue_ip, &sess->sessions, SESS_CREATE);
				if (session == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to create the session for IPv6 Addr: %s", LOG_VALUE,
							ipv6);
					return NULL;
				}
			}
		}
	} else {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"TIED and UE_IP_addr both are NULL \n", LOG_VALUE);
		return NULL;
	}

	return session;
}

int8_t
process_up_session_estab_req(pfcp_sess_estab_req_t *sess_req,
				                   pfcp_sess_estab_rsp_t *sess_rsp, peer_addr_t *peer_addr)
{
	node_address_t cp_node_addr = {0};
	pfcp_session_t *sess = NULL;

	if (sess_req == NULL)
		return -1;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"PFCP Session Establishment Request :: START \n", LOG_VALUE);
	/* Check Session ID is present or not in header */
	if (sess_req->header.s) {
		/* Check SEID is not ZERO */
		if (sess_req->header.seid_seqno.has_seid.seid != 0) {
			sess = get_sess_info_entry(sess_req->header.seid_seqno.has_seid.seid,
					SESS_CREATE);
		} else {
			/* Generate the Session ID for UP */
			sess = get_sess_info_entry(
					gen_up_sess_id(sess_req->cp_fseid.seid),
					SESS_CREATE);
		}
	} else {
		/* Generate the Session ID for UP */
		sess = get_sess_info_entry(gen_up_sess_id(0),
				SESS_CREATE);
	}

	if (sess == NULL)
		return -1;

	if(sess_req->user_id.header.len){
		uint64_t imsi;
		decode_imsi_to_u64(sess_req->user_id.imsi, sess_req->user_id.length_of_imsi, &imsi);
		sess->imsi = imsi;
	}

	/* Get the CP Session Id  */
	get_cp_node_addr(&cp_node_addr, &sess_req->cp_fseid);

	memcpy(&sess->cp_node_addr,
			&cp_node_addr, sizeof(node_address_t));

	sess->cp_seid = sess_req->cp_fseid.seid;

	if(sess_req->node_id.node_id_type == NODE_ID_TYPE_TYPE_IPV4ADDRESS) {
		sess->cp_ip.ipv4.sin_family = AF_INET;
		sess->cp_ip.ipv4.sin_port = peer_addr->ipv4.sin_port;
		sess->cp_ip.ipv4.sin_addr.s_addr = sess_req->node_id.node_id_value_ipv4_address;
		sess->cp_ip.type = PDN_TYPE_IPV4;
	} else if (sess_req->node_id.node_id_type == NODE_ID_TYPE_TYPE_IPV6ADDRESS) {
		sess->cp_ip.ipv6.sin6_family = AF_INET6;
		sess->cp_ip.ipv6.sin6_port = peer_addr->ipv6.sin6_port;
		memcpy(sess->cp_ip.ipv6.sin6_addr.s6_addr, sess_req->node_id.node_id_value_ipv6_address, IPV6_ADDRESS_LEN);
		sess->cp_ip.type = PDN_TYPE_IPV6;
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
				"Invalid Node ID interface type is received\n",
				LOG_VALUE);
		return -1;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			LOG_VALUE, sess->cp_seid, sess->up_seid);

	/* TODO: Export this function to make it generic across the establishment and modify request */
	/* Fill the info from PDR */
	for (int itr = 0; itr < sess_req->create_pdr_count; itr++) {
		pfcp_session_datat_t *session = NULL;

		/* Get the Session Object per PDR */
		session = get_pfcp_session_data(&sess_req->create_pdr[itr], sess);
		if (session == NULL)
			continue;

		/* Update the Session state */
		session->sess_state = IN_PROGRESS;

		/* Process the Create PDR info */
		if (process_create_pdr_info(&sess_req->create_pdr[itr],
					&session, sess)) {
			return -1;
		}

		for (int itr1 = 0; itr1 < sess_req->create_far_count; itr1++) {
			if (sess_req->create_pdr[itr].far_id.far_id_value ==
					sess_req->create_far[itr1].far_id.far_id_value) {
				/* Process the Create FAR info */
				if (process_create_far_info(&sess_req->create_far[itr1],
						&session, sess->up_seid, sess)) {
					return -1;

				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr2 = 0; itr2 < sess_req->create_pdr[itr].qer_id_count; itr2++) {
			for (int itr3 = 0; itr3 < sess_req->create_qer_count; itr3++) {
				if (sess_req->create_pdr[itr].qer_id[itr2].qer_id_value ==
						sess_req->create_qer[itr3].qer_id.qer_id_value) {

					if (process_create_qer_info(&sess_req->create_qer[itr3],
								&(session->pdrs[itr]).quer, &session, sess->cp_ip)) {
						return -1;
					}
				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr3 = 0; itr3 < sess_req->create_pdr[itr].urr_id_count; itr3++) {
			for (int itr4 = 0; itr4 < sess_req->create_urr_count; itr4++) {
				if (sess_req->create_pdr[itr].urr_id[itr3].urr_id_value ==
						sess_req->create_urr[itr4].urr_id.urr_id_value) {

					urr_info_t urr = {0};
					/* Process the Create URR info */
					if (process_create_urr_info(&sess_req->create_urr[itr4],
								&urr, sess->cp_seid, sess->up_seid, sess->cp_ip)) {
						return -1;
					}
				}
			}
		}

		/* Maintain the teids in session level  */
		if (sess_req->create_pdr[itr].pdi.local_fteid.teid) {
			sess->teids[sess->ber_cnt] = sess_req->create_pdr[itr].pdi.local_fteid.teid;
			sess->ber_cnt++;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Checking Teid value:0x%x, counter:%u\n",
				LOG_VALUE, sess->teids[(sess->ber_cnt - 1)], (sess->ber_cnt - 1));
		}
	}


	sess->bar.bar_id = sess_req->create_bar.bar_id.bar_id_value;
	sess->bar.dl_buf_suggstd_pckts_cnt.pckt_cnt_val = DL_PKTS_RING_SIZE;

#ifdef USE_CSID
	/* SGWC/SAEGWC FQ-CSID */
	sess->sgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (sess->sgw_fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to allocate the "
			"memory for SGW FQ-CSID entry\n", LOG_VALUE);
		return -1;
	}

	/* MME FQ-CSID */
	if (sess_req->mme_fqcsid.header.len) {
		if (sess_req->mme_fqcsid.number_of_csids) {
			sess->mme_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
					RTE_CACHE_LINE_SIZE, rte_socket_id());
			if (sess->mme_fqcsid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for MME FQ-CSID entry\n",
					LOG_VALUE);
				return -1;
			}

			/* Stored the MME CSID by MME Node address */
			if (stored_recvd_peer_fqcsid(&sess_req->mme_fqcsid, sess->mme_fqcsid) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to Store MME CSID \n", LOG_VALUE);
				return -1;
			}
			/* Link session with Peer CSID */
			link_dp_sess_with_peer_csid(sess->mme_fqcsid, sess, SX_PORT_ID);
		}
	}

	/* SGW FQ-CSID */
	if (sess_req->sgw_c_fqcsid.header.len) {
		node_address_t sgw_node_addr = {0};

		if (sess_req->sgw_c_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
			sgw_node_addr.ip_type = IPV4_TYPE;
			memcpy(&sgw_node_addr.ipv4_addr,
					&sess_req->sgw_c_fqcsid.node_address, IPV4_SIZE);
		} else {
			sgw_node_addr.ip_type = IPV6_TYPE;
			memcpy(&sgw_node_addr.ipv6_addr,
					&sess_req->sgw_c_fqcsid.node_address, IPV6_SIZE);
		}
		if (sess_req->sgw_c_fqcsid.number_of_csids) {
			if (sess_req->pgw_c_fqcsid.header.len == 0) {
				if (add_peer_addr_entry_for_fqcsid_ie_node_addr(
							&cp_node_addr, &(sess_req->sgw_c_fqcsid),
							SX_PORT_ID) < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to Store SGWC Address\n", LOG_VALUE);
					return -1;
				}
			}
			/* Stored the SGW CSID by SGW Node address */
			if (stored_recvd_peer_fqcsid(&sess_req->sgw_c_fqcsid, sess->sgw_fqcsid) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to Store SGWC CSID \n", LOG_VALUE);
				return -1;
			}

			/* Link session with Peer CSID */
			link_dp_sess_with_peer_csid(sess->sgw_fqcsid, sess, SX_PORT_ID);

		} else if (sess_req->sgw_c_fqcsid.node_address) {
			fqcsid_t *tmp = NULL;
			tmp = get_peer_addr_csids_entry(&sgw_node_addr, ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
					"CSID entry by SGW-C FQ-CSID while Processing UP Session "
					"Establishment Request, Error : %s \n",
					LOG_VALUE, strerror(errno));
				return -1;
			}
			memcpy(&(tmp->node_addr),
					&(sgw_node_addr), sizeof(node_address_t));
			memcpy(&(sess->sgw_fqcsid)->node_addr,
					&tmp->node_addr, sizeof(node_address_t));
		}
	}

	/* PGW FQ-CSID */
	if (sess_req->pgw_c_fqcsid.header.len) {
		/* PGWC FQ-CSID */
		sess->pgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (sess->pgw_fqcsid == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to allocate the memory for fqcsids entry\n",
					LOG_VALUE);
			return -1;
		}
		node_address_t pgw_node_addr = {0};

		if (sess_req->pgw_c_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
			pgw_node_addr.ip_type = IPV4_TYPE;
			memcpy(&pgw_node_addr.ipv4_addr,
					&sess_req->pgw_c_fqcsid.node_address, IPV4_SIZE);
		} else {
			pgw_node_addr.ip_type = IPV6_TYPE;
			memcpy(&pgw_node_addr.ipv6_addr,
					&sess_req->pgw_c_fqcsid.node_address, IPV6_SIZE);
		}

		if (sess_req->pgw_c_fqcsid.number_of_csids) {
			int ret = add_peer_addr_entry_for_fqcsid_ie_node_addr(
						&cp_node_addr, &sess_req->pgw_c_fqcsid,
						SX_PORT_ID);
			if (ret < 0)
				return ret;

			/* Stored the PGWC CSID by PGW Node address */
			if (stored_recvd_peer_fqcsid(&sess_req->pgw_c_fqcsid, sess->pgw_fqcsid) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to Store PGWC CSID \n", LOG_VALUE);
				return -1;
			}

			/* Link session with Peer CSID */
			link_dp_sess_with_peer_csid(sess->pgw_fqcsid, sess, SX_PORT_ID);

		} else if (sess_req->pgw_c_fqcsid.node_address) {
			fqcsid_t *tmp = NULL;
			tmp = get_peer_addr_csids_entry(&pgw_node_addr, ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
					"CSID entry by PGW-C FQ-CSID while Processing UP Session "
					"Establishment Request, Error : %s \n",
					LOG_VALUE, strerror(errno));
				return -1;
			}

			memcpy(&tmp->node_addr, &pgw_node_addr, sizeof(node_address_t));
			memcpy(&(sess->pgw_fqcsid)->node_addr,
					&pgw_node_addr, sizeof(node_address_t));
		}
	}

	/* Allocate the memory User-Plane CSID */
	sess->up_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (sess->up_fqcsid == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to allocate the memory for SGW-U FQ-CSID entry\n",
				LOG_VALUE);
		return -1;
	}

	if ((sess->cp_node_addr).ip_type == IPV4_TYPE) {
		/* Add the User-plane Node Address */
		(sess->up_fqcsid)->node_addr.ip_type = IPV4_TYPE;
		(sess->up_fqcsid)->node_addr.ipv4_addr = dp_comm_ip.s_addr;
	} else {
		/* Add the User-plane Node Address */
		(sess->up_fqcsid)->node_addr.ip_type = IPV6_TYPE;
		memcpy(&(sess->up_fqcsid)->node_addr.ipv6_addr,
				&dp_comm_ipv6.s6_addr, IPV6_ADDRESS_LEN);
	}

	int indx = 0;
	/* Add the entry for peer nodes */
	indx = fill_peer_node_info_t(sess, &cp_node_addr);
	if (indx < 0) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
				LOG_VALUE, strerror(errno));
		return -1;
	}

	/* Add entry for cp session id with link local csid */
	sess_csid *tmp1 = NULL;
	tmp1 = get_sess_csid_entry(
			(sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1], ADD_NODE);
	if (tmp1 == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
				"PGW-U CSID entry while Processing UP Session "
				"Establishment Request, CSID:%u, Error : %s \n",
				LOG_VALUE, (sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1],
				strerror(errno));
		return -1;
	}

	/* Link local csid with session id */
	/* Check head node created ot not */
	if(tmp1->up_seid != sess->up_seid && tmp1->up_seid != 0) {
		sess_csid *new_node = NULL;
		/* Add new node into csid linked list */
		new_node = add_sess_csid_data_node(tmp1);
		if(new_node == NULL ) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to ADD new node into CSID"
				"linked list : %s\n", LOG_VALUE);
			return -1;
		} else {
			new_node->cp_seid = sess->cp_seid;
			new_node->up_seid = sess->up_seid;
			new_node->next = NULL;
		}
	} else {
		tmp1->cp_seid = sess->cp_seid;
		tmp1->up_seid = sess->up_seid;
	}

	/* Fill the fqcsid into the session est response */
	if (fill_fqcsid_sess_est_rsp(sess_rsp, sess)) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Failed to fill FQ-CSID in Sess EST Resp ERROR: %s\n",
				LOG_VALUE,
				strerror(errno));
		return -1;
	}
#endif /* USE_CSID */

	/* Update the UP session id in the response */
	sess_rsp->up_fseid.seid = sess->up_seid;
	sess_req->header.seid_seqno.has_seid.seid = sess->up_seid;

	/* Update the CP seid in the response packet */
	sess_rsp->header.seid_seqno.has_seid.seid = sess->cp_seid;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Establishment Request :: END \n", LOG_VALUE);
	return 0;
}


/**
 * @brief  : Process update far info
 * @param  : far, hold create far info
 * @param  : up_seid, session id
 * @param  : sess, pfcp_session
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int8_t
process_update_far_info(pfcp_update_far_ie_t *far, uint64_t up_seid,
							pfcp_session_t *sess)
{
	node_address_t peer_addr = {0};
	far_info_t *far_t = NULL;

	/* M: FAR ID */
	if (far->far_id.header.len) {
		/* Get allocated memory location */
		far_t = get_far_info_entry(far->far_id.far_id_value, sess->cp_ip);
	}

	/* Check far entry found or not */
	if (far_t == NULL)
		return -1;

	/* M: Apply Action */
	if (far->apply_action.header.len) {
		/* Stop lawful interception request */
		if ((NOT_PRESENT == far->apply_action.dupl) &&
				(PRESENT == far_t->actions.dupl)) {

			far_t->dup_parms_cnt = 0;
			far_t->li_config_cnt = 0;
			sess->li_sx_config_cnt = 0;

			memset(far_t->li_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_config_t));
			memset(sess->li_sx_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_sx_config_t));
		}

		if (far_apply_action(&far->apply_action, &far_t->actions)) {
			/* TODO: Error Handling */
		}
	}

	/* Update Forwarding Parameters */
	if (far->upd_frwdng_parms.header.len) {
		/* pfcpsmreq_flags: */
		if (far->upd_frwdng_parms.pfcpsmreq_flags.header.len) {

			/* TODO: Add support for IPv6 */
			/* X2 Handover: Send the endmarker packet to old eNB*/
			if (far->upd_frwdng_parms.pfcpsmreq_flags.sndem) {
				if (sess_modify_with_endmarker(far_t)) {
					/* TODO: ERROR Handling */
				}
			}
		}

		/* M: Destination Interface */
		if (far->upd_frwdng_parms.dst_intfc.header.len) {
			/* Destination Interface */
			far_t->frwdng_parms.dst_intfc.interface_value =
				far->upd_frwdng_parms.dst_intfc.interface_value;
		}

		/* Outer Header Creation */
		if (far->upd_frwdng_parms.outer_hdr_creation.header.len) {
			if (far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4) {

				far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc = GTPU_UDP_IPv4;
				/* TODO: Need to validate this logic*/
				/* Linked Outer header Creation with Session */
				if (far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv4 ==
						OUT_HDR_DESC_VAL) {
					(far_t->session)->hdr_crt = GTPU_UDP_IPv4;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Outer Header Desciprition(GTPU_UDP_IPv4) : %u\n",
							LOG_VALUE,
							far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);
				}
			} else if (far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6) {
				far_t->frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc = GTPU_UDP_IPv6;
					/* Linked Outer header Creation with Session */
				if (far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.gtpu_udp_ipv6 ==
						OUT_HDR_DESC_VAL) {
					(far_t->session)->hdr_crt = GTPU_UDP_IPv6;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Outer Header Desciprition(GTPU_UDP_IPv6) : %u\n",
							LOG_VALUE,
							far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc);
				}
			}

			/* TEID */
			far_t->frwdng_parms.outer_hdr_creation.teid =
				far->upd_frwdng_parms.outer_hdr_creation.teid;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR Teid : %u\n",
					LOG_VALUE, far->upd_frwdng_parms.outer_hdr_creation.teid);

			/* Customer-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.ctag =
				far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.ctag;

			/* Service-VLAN Tag */
			far_t->frwdng_parms.outer_hdr_creation.stag =
				far->upd_frwdng_parms.outer_hdr_creation.outer_hdr_creation_desc.stag;

			/* Port Number */
			far_t->frwdng_parms.outer_hdr_creation.port_number =
				far->upd_frwdng_parms.outer_hdr_creation.port_number;

			/* Flush the exsting peer node entry from connection table */
			if ((far_t->frwdng_parms.outer_hdr_creation.ipv4_address != 0)
					&& (far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0)) {
				memset(&peer_addr, 0, sizeof(node_address_t));
				peer_addr.ip_type = IPV4_TYPE;
				peer_addr.ipv4_addr = far_t->frwdng_parms.outer_hdr_creation.ipv4_address;
				dp_flush_session(peer_addr, up_seid);
			}

			/* Flush the exsting peer node entry from connection table */
			if (memcmp(far_t->frwdng_parms.outer_hdr_creation.ipv6_address,
						far->upd_frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN)) {
				memset(&peer_addr, 0, sizeof(node_address_t));
				peer_addr.ip_type = IPV6_TYPE;
				memcpy(peer_addr.ipv6_addr,
						far_t->frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN);
				dp_flush_session(peer_addr, up_seid);
			}

			if(far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
				/* IPv4 Address */
				far_t->frwdng_parms.outer_hdr_creation.ip_type = IPV4_TYPE;
				far_t->frwdng_parms.outer_hdr_creation.ipv4_address =
					far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;

				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR Dst Ipv4 Address :"
					IPV4_ADDR"\n", LOG_VALUE,
					IPV4_ADDR_HOST_FORMAT(far_t->frwdng_parms.outer_hdr_creation.ipv4_address));
			} else if(far->upd_frwdng_parms.outer_hdr_creation.ipv6_address != NULL) {

				far_t->frwdng_parms.outer_hdr_creation.ip_type = IPV6_TYPE;
				memcpy(far_t->frwdng_parms.outer_hdr_creation.ipv6_address,
						far->upd_frwdng_parms.outer_hdr_creation.ipv6_address,
						IPV6_ADDRESS_LEN);
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"FAR Dst Ipv6 Address :"
					IPv6_FMT"\n", LOG_VALUE,
					IPv6_PRINT(IPv6_CAST(far_t->frwdng_parms.outer_hdr_creation.ipv6_address)));

			}
		}

		uint8_t tmp_ipv6[IPV6_ADDR_LEN] = {0};
		if (far->upd_frwdng_parms.dst_intfc.interface_value == ACCESS ) {
			/* Add eNB peer node information in connection table */
			if ((far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0) ||
				((memcmp(&far->upd_frwdng_parms.outer_hdr_creation.ipv6_address,
					&tmp_ipv6, IPV6_ADDR_LEN)))) {
				if (far->upd_frwdng_parms.outer_hdr_creation.ipv4_address) {
#ifdef USE_REST
					/* Add the peer node connection entry */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV4_TYPE;
					peer_addr.ipv4_addr = far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;
					if ((add_node_conn_entry(peer_addr, up_seid, S1U_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT":Failed to add connection entry for eNB\n",
							LOG_VALUE);
					}
#endif /* USE_REST */

					far_t->session->wb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV4;
					far_t->session->wb_peer_ip_addr.ipv4_addr = far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"MBR: West Bound Peer IPv4 Node Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT((far_t->session)->wb_peer_ip_addr.ipv4_addr));

				} else {
					/* TODO:PATH: Add the connection entry */
					far_t->session->wb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV6;
					memcpy(far_t->session->wb_peer_ip_addr.ipv6_addr,
							far->upd_frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"MBR: West Bound Peer IPv6 Node Addr:"IPv6_FMT"\n",
						LOG_VALUE,
						IPv6_PRINT(IPv6_CAST(far_t->session)->wb_peer_ip_addr.ipv6_addr));
#ifdef USE_REST
					/* Add the peer node connection entry */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV6_TYPE;
					memcpy(peer_addr.ipv6_addr,
							far->upd_frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN);
					if ((add_node_conn_entry(peer_addr, up_seid, S1U_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT":Failed to add connection entry for eNB\n",
							LOG_VALUE);
					}
#endif /* USE_REST */
				}

				/* Update the Session state */
				if (!far->upd_frwdng_parms.outer_hdr_creation.teid) {
					if ((far_t->session)->sess_state == CONNECTED) {
						(far_t->session)->sess_state = IDLE;
						clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session State Change : "
							"CONNECTED --> IDLE\n", LOG_VALUE);
					}
				} else {
					switch((far_t->session)->sess_state) {
					case IDLE:
						{
							(far_t->session)->sess_state = CONNECTED;
							clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "Session State Change : "
										"IDLE --> CONNECTED\n", LOG_VALUE);
						}
						break;
					case IN_PROGRESS:
						{
								/* TODO: DDN Support for IPv6 */
						/** Resolved queued pkts by dl core and enqueue pkts into notification ring */
							struct rte_mbuf *buf_pkt =
								rte_ctrlmbuf_alloc(notify_msg_pool);
							if (buf_pkt == NULL) {
								clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT
										"Failed to Allocate a new mbuf from mempool \n", LOG_VALUE);
							}
							if (buf_pkt != NULL) {
								uint32_t *key =
									rte_pktmbuf_mtod(buf_pkt, uint32_t *);


								if ((far_t->session)->pdrs) {
									if ((far_t->session)->pdrs->pdi.local_fteid.teid) {
										*key = (far_t->session)->pdrs->pdi.local_fteid.teid;
									} else if ((far_t->session)->pdrs->pdi.ue_addr.ipv4_address) {
										*key = (far_t->session)->pdrs->pdi.ue_addr.ipv4_address;
									}
								} else {
									clLog(clSystemLog, eCLSeverityDebug,
											LOG_FORMAT"ERROR: PDRs value is NULL\n", LOG_VALUE);
									break;
								}
								rte_ring_enqueue(notify_ring,
										buf_pkt);


								(far_t->session)->sess_state = CONNECTED;
								clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session State Change : "
										"IN_PROGRESS --> CONNECTED\n", LOG_VALUE);
							}
						}
						break;
					default:
						clLog(clSystemLog, eCLSeverityDebug,LOG_FORMAT "No state change\n", LOG_VALUE);
					}
				}
			}
		} else {
			/* Add S5S8 peer node information in connection table */
			if ((far->upd_frwdng_parms.outer_hdr_creation.ipv4_address != 0) ||
				((memcmp(&far->upd_frwdng_parms.outer_hdr_creation.ipv6_address,
					&tmp_ipv6, IPV6_ADDR_LEN)))) {
				if (far->upd_frwdng_parms.outer_hdr_creation.ipv4_address) {
#ifdef USE_REST
					/* Add the peer node connection entry */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV4_TYPE;
					peer_addr.ipv4_addr = far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;
					if ((add_node_conn_entry(peer_addr, up_seid, SGI_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT":Failed to add connection entry for S5S8\n",
							LOG_VALUE);
					}
#endif /* USE_REST */
					far_t->session->eb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV4;
					far_t->session->eb_peer_ip_addr.ipv4_addr =
							far->upd_frwdng_parms.outer_hdr_creation.ipv4_address;
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"MBR: West Bound Peer IPv4 Node Addr:"IPV4_ADDR"\n",
						LOG_VALUE, IPV4_ADDR_HOST_FORMAT(far_t->session->eb_peer_ip_addr.ipv4_addr));
				} else {
					/* TODO:PATH MANG: Add the entry for IPv6 Address */
					far_t->session->eb_peer_ip_addr.ip_type |=  PDN_TYPE_IPV6;
					memcpy(far_t->session->eb_peer_ip_addr.ipv6_addr,
							far->upd_frwdng_parms.outer_hdr_creation.ipv6_address,
							IPV6_ADDRESS_LEN);

					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"MBR: West Bound Peer IPv6 Node Addr:"IPv6_FMT"\n",
						LOG_VALUE,
						IPv6_PRINT(IPv6_CAST(far_t->session->eb_peer_ip_addr.ipv6_addr)));
#ifdef USE_REST
					/* Add the peer node connection entry */
					memset(&peer_addr, 0, sizeof(node_address_t));
					peer_addr.ip_type = IPV6_TYPE;
					memcpy(peer_addr.ipv6_addr,
							far->upd_frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN);

					if ((add_node_conn_entry(peer_addr, up_seid, SGI_PORT_ID)) < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT":Failed to add connection entry for S5S8\n",
							LOG_VALUE);
					}
#endif /* USE_REST */
				}

				/* Update the Session state */
				if (far->upd_frwdng_parms.outer_hdr_creation.teid != 0) {
					(far_t->session)->sess_state = CONNECTED;
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Session State Change to : "
								"CONNECTED\n", LOG_VALUE);
				}
			}
		}
	}

	/* Buffering Action Rule Identifier */
	if (far->bar_id.header.len) {
		/* TODO: Implement Handling */
	}

	/* Duplicating Parameters */
	if (far->upd_dupng_parms_count > 0) {
		fill_li_update_duplicating_param(far, far_t, sess);
	}

	return 0;
}

int8_t
fill_sess_mod_usage_report(pfcp_usage_rpt_sess_mod_rsp_ie_t *usage_report,
								urr_info_t *urr)
{

	int8_t size = 0;
	int ret = 0;
	struct timeval epoc_start_time;
	struct timeval epoc_end_time;
	peerEntry *data = NULL;
	uint32_t end_time = 0;

	size += set_urr_id(&usage_report->urr_id, urr->urr_id);

	pfcp_set_ie_header(&(usage_report->urseqn.header), PFCP_IE_URSEQN,
						(sizeof(pfcp_urseqn_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_urseqn_ie_t);
	usage_report->urseqn.urseqn = urr->urr_seq_num++;

	pfcp_set_ie_header(&(usage_report->usage_rpt_trig.header), PFCP_IE_USAGE_RPT_TRIG,
						(sizeof(pfcp_usage_rpt_trig_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_usage_rpt_trig_ie_t);

	usage_report->usage_rpt_trig.termr = 1;



	if(urr->meas_method == VOL_TIME_BASED ||
			urr->meas_method == VOL_BASED){
		size += set_volume_measurment(&usage_report->vol_meas);
		usage_report->vol_meas.uplink_volume = urr->uplnk_data;
		usage_report->vol_meas.downlink_volume = urr->dwnlnk_data;
		usage_report->vol_meas.total_volume = urr->dwnlnk_data + urr->uplnk_data;
	}

	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		end_time = current_ntp_timestamp();
		size += set_duration_measurment(&usage_report->dur_meas);
		ntp_to_unix_time(&urr->start_time, &epoc_start_time);
		ntp_to_unix_time(&end_time, &epoc_end_time);
		usage_report->dur_meas.duration_value = epoc_end_time.tv_sec - epoc_start_time.tv_sec;
	}
	size += set_start_time(&usage_report->start_time);
	size += set_end_time(&usage_report->end_time);
	size += set_first_pkt_time(&usage_report->time_of_frst_pckt);
	size += set_last_pkt_time(&usage_report->time_of_lst_pckt);

	usage_report->start_time.start_time = urr->start_time;
	usage_report->end_time.end_time = current_ntp_timestamp();
	usage_report->time_of_frst_pckt.time_of_frst_pckt = urr->first_pkt_time;
	usage_report->time_of_lst_pckt.time_of_lst_pckt = urr->last_pkt_time;

	urr->start_time = current_ntp_timestamp();
	urr->first_pkt_time = 0;
	urr->last_pkt_time = 0;

	pfcp_set_ie_header(&usage_report->header, IE_USAGE_RPT_SESS_MOD_RSP, size);
	/*remove from hash*/
	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		ret = rte_hash_lookup_data(timer_by_id_hash,
				&urr->urr_id, (void **)&data);
		if (ret >=  0) {
			if(data->pt.ti_id != 0) {
				stoptimer(&data->pt.ti_id);
				deinittimer(&data->pt.ti_id);

				/* URR Entry is present. Delete Session Entry */
				ret = rte_hash_del_key(timer_by_id_hash, &urr->urr_id);

				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry "
						"not found for URR_ID:%u\n", LOG_VALUE, urr->urr_id);
					return -1;
				}

				if (data != NULL) {
					rte_free(data);
					data = NULL;
				}
			}
		}
	}
	return size;
}

int8_t
process_remove_pdr_sess(pfcp_remove_pdr_ie_t *remove_pdr, uint64_t up_seid,
								pfcp_sess_mod_rsp_t *sess_mod_rsp, peer_addr_t cp_ip)
{
	int ret = 0;
	uint8_t uiFlag = 0;
	pfcp_session_t *sess = NULL;
	node_address_t peer_addr = {0};
	struct sdf_pkt_filter pkt_filter = {0};

	/* Get the session information from session table based on UP_SESSION_ID*/
	sess = get_sess_info_entry(up_seid, SESS_MODIFY);

	if (sess == NULL)
		return -1;

	/* Flush the Session data info from the hash tables based on teid*/
	pfcp_session_datat_t *session = sess->sessions;
	/* Cleanup the session data form hash table and delete the node from linked list */
	while (NULL != session) {
		/* Cleanup PDRs info from the linked list */
		pdr_info_t *pdr = session->pdrs;
		while (NULL != pdr) {
			if (remove_pdr->pdr_id.rule_id == pdr->rule_id) {
				pdr = get_pdr_info_entry(
					remove_pdr->pdr_id.rule_id, NULL,SESS_MODIFY, cp_ip);
				if (pdr == NULL)
					return -1;
				for(int itr = 0; itr < pdr->urr_count; itr++){
					fill_sess_mod_usage_report(&sess_mod_rsp->usage_report[sess_mod_rsp->usage_report_count++],
																									&pdr->urr[itr]);

				}
				//Remove Entry from ACL Table
				for(int itr = 0; itr < pdr->pdi.sdf_filter_cnt; itr++){

					pkt_filter.precedence = pdr->prcdnc_val;
					/* Reset the rule string */
					memset(pkt_filter.u.rule_str, 0, MAX_LEN);

					/* flow description */
					if (pdr->pdi.sdf_filter[itr].fd) {
						memcpy(&pkt_filter.u.rule_str, &pdr->pdi.sdf_filter[itr].flow_desc,
										pdr->pdi.sdf_filter[itr].len_of_flow_desc);
						pkt_filter.rule_ip_type = get_rule_ip_type(pkt_filter.u.rule_str);

						if (!pdr->pdi.src_intfc.interface_value) {
							/* swap the src and dst address for UL traffic.*/
							swap_src_dst_ip(&pkt_filter.u.rule_str[0]);
						}

						int flag = 0;
						int32_t indx = get_acl_table_indx(&pkt_filter, SESS_DEL);
						for(uint16_t itr = 0; itr < session->acl_table_count; itr++){
							if(session->acl_table_indx[itr] == indx){
								flag = 1;
							}
							if(flag && itr != session->acl_table_count - 1)
								session->acl_table_indx[itr] = session->acl_table_indx[itr+1];
						}

						if(flag == 1 && indx > 0){
							if (remove_rule_entry_acl(indx,	&pkt_filter)) {
								/* TODO: ERROR handling */
							}else{
								session->acl_table_indx[session->acl_table_count] = 0;
								session->acl_table_count--;
							}
						}
					}
				}


				far_info_t *far = pdr->far;
				/* Cleanup the FAR information */
				if (far != NULL) {
					if(far->pdr_count > 1){
						far->pdr_count--;
					}else{
#ifdef USE_REST
						memset(&peer_addr, 0, sizeof(node_address_t));
						peer_addr.ip_type = far->frwdng_parms.outer_hdr_creation.ip_type;

						if (far->frwdng_parms.outer_hdr_creation.ip_type == IPV4_TYPE) {
							if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
								peer_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;
								dp_flush_session(peer_addr, sess->up_seid);
							}
						} else if (far->frwdng_parms.outer_hdr_creation.ip_type == IPV6_TYPE) {
							if (far->frwdng_parms.outer_hdr_creation.ipv6_address != NULL) {
								memcpy(peer_addr.ipv6_addr,
										far->frwdng_parms.outer_hdr_creation.ipv6_address, IPV6_ADDR_LEN);
								dp_flush_session(peer_addr, sess->up_seid);
							}
						}
#endif /* USE_REST */

						/* Flush the far info from the hash table */
						ret = del_far_info_entry(far->far_id_value, cp_ip);
						if (ret) {
							clLog(clSystemLog, eCLSeverityDebug,
								"DP:"LOG_FORMAT"Entry not found for FAR_ID:%u...\n",
								LOG_VALUE, far->far_id_value);
							return -1;
						}
					}
				}

				/* Cleanup QERs info from the linked list */
				qer_info_t *qer = pdr->quer;
				while (qer != NULL) {
					/* Get QER ID */
					uint32_t qer_id = qer->qer_id;

					/* Delete the QER info node from the linked list */
					pdr->quer = remove_qer_node(pdr->quer, qer);
					qer = pdr->quer;

					/* Flush the QER info from the hash table */
					ret = del_qer_info_entry(qer_id, cp_ip);
					if ( ret < 0) {
						clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Entry not found for QER_ID:%u...\n",
									LOG_VALUE, qer_id);
						return -1;
					}
				}

				/* Cleanup URRs info from the linked list */
				urr_info_t *urr = pdr->urr;
				while (urr != NULL) {
					if(urr->pdr_count > 1){
						urr->pdr_count--;
						urr = urr->next;
					}else{
						/* Get URR ID */
						uint32_t urr_id = urr->urr_id;

						/* Delete the URR info node from the linked list */
						pdr->urr = remove_urr_node(pdr->urr, urr);
						urr = pdr->urr;

						/* Flush the URR info from the hash table */
						if (del_urr_info_entry(urr_id, cp_ip)) {
							/* TODO : ERROR Handling */
						}
					}
				}

				if (pdr->pdi.local_fteid.teid && pdr->next == NULL) {
					if (del_sess_by_teid_entry(pdr->pdi.local_fteid.teid)) {
						/* TODO : ERROR Handling */
					}else{
						for (int itr1 = 0; itr1 < sess->ber_cnt; itr1++) {
							if (pdr->pdi.local_fteid.teid == sess->teids[itr1]) {
								sess->teids[itr1] = 0;
							}
						}

					}
				}

				/* Cleanup PDRs info from the linked list */
				/* Get PDR ID */
				uint32_t pdr_id = pdr->rule_id;

				/* Delete the PDR info node from the linked list */
				session->pdrs = remove_pdr_node(session->pdrs, pdr);

				/* Flush the PDR info from the hash table */
				ret = del_pdr_info_entry(pdr_id, cp_ip);
				if (ret) {
					clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Entry not found for PDR_ID:%u...\n",
								LOG_VALUE, pdr_id);
					return -1;
				}

				uiFlag = 1;
				pdr = session->pdrs;
				continue;
			}

			pdr = pdr->next;
		}

		if ((1 == uiFlag) && (NULL == session->pdrs)) {
			/* Delete the Session data info node from the linked list */
			sess->sessions = remove_sess_data_node(sess->sessions, session);
			if (sess->sessions != NULL) {
				session = sess->sessions;
			}
			uiFlag = 0;
		} else {
			session = session->next;
		}
	}

	return 0;
}

int8_t
process_up_session_modification_req(pfcp_sess_mod_req_t *sess_mod_req,
					pfcp_sess_mod_rsp_t *sess_mod_rsp)
{
	node_address_t cp_node_addr = {0};
	pfcp_session_t *sess = NULL;
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"PFCP Session Modification Request :: START \n", LOG_VALUE);
	/* Get the session information from session table based on UP_SESSION_ID*/
	if (sess_mod_req->header.s) {
		/* Check SEID is not ZERO */
		sess = get_sess_info_entry(sess_mod_req->header.seid_seqno.has_seid.seid,
				SESS_MODIFY);
	}

	if (sess == NULL)
		return -1;

	/* pfcpsmreq_flags: Dropped the bufferd packets  */
	if (sess_mod_req->pfcpsmreq_flags.drobu) {
		/* Free the downlink data rings */
		//rte_free();

		struct rte_ring *ring = NULL;
		struct pfcp_session_datat_t *si = NULL;

		si = sess->sessions;

		while (si != NULL) {

			/* Delete dl ring which created by default if present */
			ring = si->dl_ring;
			if (ring) {
				if (rte_ring_dequeue(dl_ring_container, (void **)&ring) ==
						ENOENT) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Can't put ring back, so free it\n", LOG_VALUE);
					rte_ring_free(ring);
				}

				rte_ring_free(si->dl_ring);
				si->dl_ring = NULL;
			}

			si = si->next;
		}
	}

	/* Scenario CP Changes it's SEID */
	get_cp_node_addr(&cp_node_addr, &sess_mod_req->cp_fseid);

	if (sess->cp_seid != sess_mod_req->cp_fseid.seid) {
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"CP Session IP Changed CP_Old_Seid: %lu, CP_New_Seid:%lu\n",
			LOG_VALUE, sess->cp_seid, sess_mod_req->cp_fseid.seid);
		sess->cp_seid = sess_mod_req->cp_fseid.seid;
	}

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			LOG_VALUE, sess->cp_seid, sess->up_seid);

	/* TODO: Export this function to make it generic across the establishment and modify request */
	/* Fill the info from PDR */
	for (int itr = 0; itr < sess_mod_req->create_pdr_count; itr++) {
		pfcp_session_datat_t *session = NULL;

		/* Get the Session Object per PDR */
		session = get_pfcp_session_data(&sess_mod_req->create_pdr[itr], sess);
		if (session == NULL)
			continue;

		/*  Update the Session state */
		session->sess_state = IN_PROGRESS;

		/* Process the Create PDR info */
		if (process_create_pdr_info(&sess_mod_req->create_pdr[itr],
					&session, sess)) {
			return -1;
		}

		/* TODO: Remove the loops */
		for (int itr1 = 0; itr1 < sess_mod_req->create_far_count; itr1++) {
			if (sess_mod_req->create_pdr[itr].far_id.far_id_value ==
					sess_mod_req->create_far[itr1].far_id.far_id_value) {
				/* Process the Create FAR info */
				if (process_create_far_info(&sess_mod_req->create_far[itr1],
						&session, sess->up_seid, sess)) {
					return -1;

				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr2 = 0; itr2 < sess_mod_req->create_pdr[itr].qer_id_count; itr2++) {
			for (int itr3 = 0; itr3 < sess_mod_req->create_qer_count; itr3++) {
				if (sess_mod_req->create_pdr[itr].qer_id[itr2].qer_id_value ==
						sess_mod_req->create_qer[itr3].qer_id.qer_id_value) {

					if (process_create_qer_info(&sess_mod_req->create_qer[itr3],
								&(session->pdrs[itr]).quer, &session, sess->cp_ip)) {
						return -1;
					}
				}
			}
		}

		/* TODO: Remove the loops */
		for (int itr3 = 0; itr3 < sess_mod_req->create_pdr[itr].urr_id_count; itr3++) {
			for (int itr4 = 0; itr4 < sess_mod_req->create_urr_count; itr4++) {
				if (sess_mod_req->create_pdr[itr].urr_id[itr3].urr_id_value ==
						sess_mod_req->create_urr[itr4].urr_id.urr_id_value) {

					urr_info_t urr = {0};
					/* Process the Create URR info */
					if (process_create_urr_info(&sess_mod_req->create_urr[itr4],
								&urr, sess->cp_seid, sess->up_seid, sess->cp_ip)) {
						return -1;
					}
				}
			}
		}

		/* Maintain the teids in session level  */
		if (sess_mod_req->create_pdr[itr].pdi.local_fteid.teid) {
			sess->teids[sess->ber_cnt] = sess_mod_req->create_pdr[itr].pdi.local_fteid.teid;
			sess->ber_cnt++;
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Checking Teid value:%u, counter:%u\n",
				LOG_VALUE, sess->teids[sess->ber_cnt - 1], sess->ber_cnt - 1);
		}

		/*  Update the Session state */
		session->sess_state = CONNECTED;
	}


	/* Process the Update FAR information */
	for (int itr = 0; itr < sess_mod_req->update_far_count; itr++) {
		if (process_update_far_info(&sess_mod_req->update_far[itr],
					sess->up_seid, sess)) {
			/* TODO: Error Handling */
			return -1;
		}
	}

	for(int itr = 0; itr < sess_mod_req->update_pdr_count; itr++ ){
		/* Process the Update PDR info */
		if(process_update_pdr_info(&sess_mod_req->update_pdr[itr], sess)){
				/* TODO: Error Handling */
		}
	}

	/* Process the Remove PDR information */
	for (int itr = 0; itr < sess_mod_req->remove_pdr_count; itr++) {
		if (process_remove_pdr_sess(&sess_mod_req->remove_pdr[itr], sess->up_seid,
																	sess_mod_rsp, sess->cp_ip)) {
			/* TODO: Error Handling */
			return -1;
		}
	}

#ifdef USE_CSID
	fqcsid_t *tmp = NULL;
	uint16_t tmp_csid = 0;
	uint16_t old_csid = 0;
	node_address_t old_node_addr = {0};
	node_address_t node_addr = {0};

	/* SGW FQ-CSID */
	if (sess_mod_req->sgw_c_fqcsid.header.len) {
		if (sess_mod_req->sgw_c_fqcsid.number_of_csids) {
			/* Get the List of the Old CSID */
			old_csid = (sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid - 1];
			memcpy(&old_node_addr,
					&(sess->sgw_fqcsid)->node_addr, sizeof(node_address_t));

			if (sess_mod_req->sgw_c_fqcsid.fqcsid_node_id_type == IPV4_GLOBAL_UNICAST) {
				node_addr.ip_type = IPV4_TYPE;
				memcpy(&node_addr.ipv4_addr,
						sess_mod_req->sgw_c_fqcsid.node_address, IPV4_SIZE);
			} else {
				node_addr.ip_type = IPV6_TYPE;
				memcpy(&node_addr.ipv6_addr,
						&sess_mod_req->sgw_c_fqcsid.node_address, IPV6_SIZE);
			}

			/* Stored the SGW CSID by SGW Node address */
			tmp = get_peer_addr_csids_entry(&node_addr, ADD_NODE);
			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
					"CSID entry by SGW-C while Processing UP Session "
					"Modification Request, Error : %s \n",
					LOG_VALUE, strerror(errno));
				return -1;
			}
			if (!(is_present(&tmp->node_addr))) {
				memcpy(&tmp->node_addr, &node_addr, sizeof(node_address_t));
			}

			for(uint8_t itr = 0; itr < sess_mod_req->sgw_c_fqcsid.number_of_csids; itr++) {
				uint8_t match = 0;
				for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
					if (tmp->local_csid[itr1] == sess_mod_req->sgw_c_fqcsid.pdn_conn_set_ident[itr]){
						match = 1;
						break;
					}
				}
				if (!match) {
					tmp->local_csid[tmp->num_csid++] =
						sess_mod_req->sgw_c_fqcsid.pdn_conn_set_ident[itr];
				}
			}
			/* Remove old CSID */
			for (uint8_t itr = 0; itr < tmp->num_csid; itr++) {
				if (tmp->local_csid[itr] == old_csid) {
					for (uint8_t pos = itr; pos  < tmp->num_csid; pos++) {
						tmp->local_csid[pos] = tmp->local_csid[pos + 1];
					}
					tmp->num_csid--;
				}
			}
			/* Remove the temp associated CSID Link with local CSID*/
			csid_t *sgw_csid = NULL;
			csid_key_t key_t = {0};
			key_t.local_csid = old_csid;
			memcpy(&key_t.node_addr,
					&old_node_addr, sizeof(node_address_t));

			sgw_csid = get_peer_csid_entry(&key_t, SX_PORT_ID, REMOVE_NODE);
			if (sgw_csid == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
					"CSID entry by SGW-C while Processing UP Session "
					"Modification Request, Error : %s \n",
					LOG_VALUE, strerror(errno));
			} else {
				for (uint8_t itr = 0; itr < (sess->sgw_fqcsid)->num_csid; itr++) {
					if ((sess->sgw_fqcsid)->local_csid[itr] == old_csid) {
						for (uint8_t pos = itr; pos < ((sess->sgw_fqcsid)->num_csid - 1); pos++) {
							(sess->sgw_fqcsid)->local_csid[pos] = (sess->sgw_fqcsid)->local_csid[pos + 1];
						}
						(sess->sgw_fqcsid)->num_csid--;
					}
				}
			}

			for(uint8_t itr1 = 0; itr1 < sess_mod_req->sgw_c_fqcsid.number_of_csids; itr1++) {
				(sess->sgw_fqcsid)->local_csid[(sess->sgw_fqcsid)->num_csid++] =
					sess_mod_req->sgw_c_fqcsid.pdn_conn_set_ident[itr1];
			}
			memcpy(&((sess->sgw_fqcsid)->node_addr),
					&(node_addr), sizeof(node_address_t));

			/* TODO: Need to think about this, this portion only has to hit in PGWU */
			/* LINK SGW CSID with local CSID */
			if (link_peer_csid_with_local_csid(sess->sgw_fqcsid,
						sess->up_fqcsid, SX_PORT_ID) < 0) {
				return -1;
			}

			link_dp_sess_with_peer_csid(sess->sgw_fqcsid, sess, SX_PORT_ID);

			/* Remove the session link from old CSID */
			sess_csid *tmp1 = NULL;
			peer_csid_key_t key = {0};

			key.iface = SX_PORT_ID;
			key.peer_local_csid = old_csid;
			memcpy(&key.peer_node_addr,
					&old_node_addr, sizeof(node_address_t));

			tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);

			if (tmp1 != NULL) {
				/* Remove node from csid linked list */
				tmp1 = remove_sess_csid_data_node(tmp1, sess->up_seid);

				int8_t ret = 0;
				/* Update CSID Entry in table */
				ret = rte_hash_add_key_data(seid_by_peer_csid_hash, &key, tmp1);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to add Session IDs entry"
							" for CSID = %u \n", LOG_VALUE, old_csid);
					return -1;
				}
				if (tmp1 == NULL) {
					/* Delete Local CSID entry */
					del_sess_peer_csid_entry(&key);
				}
			}
		}
	}

	/* PGW FQ-CSID */
	if (sess_mod_req->pgw_c_fqcsid.header.len) {
		if (sess_mod_req->pgw_c_fqcsid.number_of_csids) {

			if (sess->pgw_fqcsid == NULL) {
				/* PGWC FQ-CSID */
				sess->pgw_fqcsid = rte_zmalloc_socket(NULL, sizeof(fqcsid_t),
						RTE_CACHE_LINE_SIZE, rte_socket_id());
				if (sess->pgw_fqcsid == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to allocate the memory for fqcsids entry\n",
							LOG_VALUE);
					return -1;
				}
			} else {
				old_csid = (sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid - 1];
				memcpy(&old_node_addr,
						&(sess->pgw_fqcsid)->node_addr, sizeof(node_address_t));
			}

			/* Stored the PGWC CSID by PGW Node address */
			if (stored_recvd_peer_fqcsid(&sess_mod_req->pgw_c_fqcsid, sess->pgw_fqcsid) < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to Store PGWC CSID \n", LOG_VALUE);
				return -1;
			}

			/* LINK SGW CSID with local CSID */
			if (link_peer_csid_with_local_csid(sess->pgw_fqcsid,
						sess->up_fqcsid, SX_PORT_ID) < 0) {
				return -1;
			}

			link_dp_sess_with_peer_csid(sess->pgw_fqcsid, sess, SX_PORT_ID);

			if (old_csid != (sess->pgw_fqcsid)->local_csid[(sess->pgw_fqcsid)->num_csid -1]) {
				/* Remove the session link from old CSID */
				sess_csid *tmp1 = NULL;
				peer_csid_key_t key = {0};

				key.iface = SX_PORT_ID;
				key.peer_local_csid = old_csid;
				memcpy(&key.peer_node_addr,
						&old_node_addr, sizeof(node_address_t));

				tmp1 = get_sess_peer_csid_entry(&key, REMOVE_NODE);

				if (tmp1 != NULL) {
					/* Remove node from csid linked list */
					tmp1 = remove_sess_csid_data_node(tmp1, sess->up_seid);

					int8_t ret = 0;
					/* Update CSID Entry in table */
					ret = rte_hash_add_key_data(seid_by_peer_csid_hash, &key, tmp1);
					if (ret) {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to add Session IDs entry"
								" for CSID = %u \n", LOG_VALUE, old_csid);
						return -1;
					}
					if (tmp1 == NULL) {
						/* Delete Local CSID entry */
						del_sess_peer_csid_entry(&key);
					}
				}
			}
		}
	}

	/* TODO:VISHAL Need to think in PGWU case */
	if (sess_mod_req->sgw_c_fqcsid.number_of_csids) {
		tmp_csid = (sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1];

		int indx = 0;
		/* Add the entry for peer nodes */
		indx = fill_peer_node_info_t(sess, &cp_node_addr);
		if (indx < 0) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Failed to fill peer node info and assignment of the CSID Error: %s\n",
					LOG_VALUE,
					strerror(errno));
			return -1;
		}
		/* TODO: Based on the index value, add the condition */

		/* Remove temp associated old CSIDs*/
		if (tmp_csid != (sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1]) {
			for (uint8_t itr = 0; itr < (sess->up_fqcsid)->num_csid; itr++) {
				if (tmp_csid == (sess->up_fqcsid)->local_csid[itr]) {
					for(uint32_t pos = itr; pos < ((sess->up_fqcsid)->num_csid - 1); pos++ ) {
						(sess->up_fqcsid)->local_csid[pos] = (sess->up_fqcsid)->local_csid[pos + 1];
					}
					(sess->up_fqcsid)->num_csid--;
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Remove temp allocated local CSID:%u, Num_Local_CSID:%u\n",
							LOG_VALUE, tmp_csid, (sess->up_fqcsid)->num_csid);
				}
			}

			/* Remove the current session link from tmp csid */
			sess_csid *tmp_t = NULL;
			tmp_t = get_sess_csid_entry(tmp_csid, REMOVE_NODE);
			if (tmp_t != NULL) {
				int ret = 0;
				sess_csid *seid_tmp = NULL;
				seid_tmp = remove_sess_csid_data_node(tmp_t, sess->up_seid);

				/* Update CSID Entry in table */
				ret = rte_hash_add_key_data(seids_by_csid_hash,
						&tmp_csid, seid_tmp);
				if (ret) {
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"Failed to Update Session IDs entry for CSID = %u"
							"\n\tError= %s\n",
							LOG_VALUE, tmp_csid,
							rte_strerror(abs(ret)));
				}
			}
		}

		/* Add entry for cp session id with link local csid */
		sess_csid *tmp1 = NULL;
		tmp1 = get_sess_csid_entry(
				(sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1], ADD_NODE);
		if (tmp1 == NULL) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed to get "
					"CSID entry by PGW-U while Processing UP Session "
					"Modification Request, Error : %s \n",
					LOG_VALUE, strerror(errno));
			return -1;
		}

		/* Link local csid with session id */
		/* Check head node created ot not */
		if(tmp1->up_seid != sess->up_seid && tmp1->up_seid != 0) {
			sess_csid *new_node = NULL;
			/* Add new node into csid linked list */
			new_node = add_sess_csid_data_node(tmp1);
			if(new_node == NULL ) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to ADD new node into CSID"
					"linked list : %s\n",__func__);
				return -1;
			} else {
				new_node->cp_seid = sess->cp_seid;
				new_node->up_seid = sess->up_seid;
			}
		} else {
			tmp1->cp_seid = sess->cp_seid;
			tmp1->up_seid = sess->up_seid;
		}

		if (tmp_csid != (sess->up_fqcsid)->local_csid[(sess->up_fqcsid)->num_csid - 1]) {
			/* Fill the fqcsid into the session est request */
			if (fill_fqcsid_sess_mod_rsp(sess_mod_rsp, sess)) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to fill FQ-CSID in Sess EST Resp ERROR: %s\n",
						LOG_VALUE,
						strerror(errno));
				return -1;
			}
		}
	}
#endif /* USE_CSID */
	/* Update the CP seid in the response packet */
	sess_mod_rsp->header.seid_seqno.has_seid.seid = sess->cp_seid;

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"PFCP Session Modification Request :: END \n", LOG_VALUE);
	return 0;
}

int8_t
fill_sess_rep_req_usage_report(pfcp_usage_rpt_sess_rpt_req_ie_t *usage_report,
					urr_info_t *urr, uint32_t trig)
{

	int8_t size = 0;
	struct timeval epoc_start_time;
	struct timeval epoc_end_time;
	uint32_t end_time = 0;

	size += set_urr_id(&usage_report->urr_id, urr->urr_id);

	pfcp_set_ie_header(&(usage_report->urseqn.header), PFCP_IE_URSEQN,
						(sizeof(pfcp_urseqn_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_urseqn_ie_t);
	usage_report->urseqn.urseqn = urr->urr_seq_num++;

	pfcp_set_ie_header(&(usage_report->usage_rpt_trig.header), PFCP_IE_USAGE_RPT_TRIG,
						(sizeof(pfcp_usage_rpt_trig_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_usage_rpt_trig_ie_t);

	if(trig == VOL_BASED)
		usage_report->usage_rpt_trig.volth = 1;
	else if(trig == TIME_BASED)
		usage_report->usage_rpt_trig.timth = 1;



	if(urr->meas_method == VOL_TIME_BASED ||
			urr->meas_method == VOL_BASED){
		size += set_volume_measurment(&usage_report->vol_meas);
		usage_report->vol_meas.uplink_volume = urr->uplnk_data;
		usage_report->vol_meas.downlink_volume = urr->dwnlnk_data;
		usage_report->vol_meas.total_volume = urr->dwnlnk_data + urr->uplnk_data;
	}

	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		end_time = current_ntp_timestamp();
		size += set_duration_measurment(&usage_report->dur_meas);
		ntp_to_unix_time(&urr->start_time, &epoc_start_time);
		ntp_to_unix_time(&end_time, &epoc_end_time);
		usage_report->dur_meas.duration_value = epoc_end_time.tv_sec - epoc_start_time.tv_sec;

	}

	size += set_start_time(&usage_report->start_time);
	size += set_end_time(&usage_report->end_time);
	size += set_first_pkt_time(&usage_report->time_of_frst_pckt);
	size += set_last_pkt_time(&usage_report->time_of_lst_pckt);

	usage_report->start_time.start_time = urr->start_time;
	usage_report->end_time.end_time = current_ntp_timestamp();
	usage_report->time_of_frst_pckt.time_of_frst_pckt = urr->first_pkt_time;
	usage_report->time_of_lst_pckt.time_of_lst_pckt = urr->last_pkt_time;

	urr->start_time = current_ntp_timestamp();
	urr->first_pkt_time = 0;
	urr->last_pkt_time = 0;

	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		urr->uplnk_data = 0;
		urr->dwnlnk_data = 0;
	}
	pfcp_set_ie_header(&usage_report->header, IE_USAGE_RPT_SESS_RPT_REQ, size);
	return size;
}

int8_t
fill_sess_del_usage_report(pfcp_usage_rpt_sess_del_rsp_ie_t *usage_report,
				urr_info_t *urr)
{

	int8_t size = 0;
	peerEntry *data = NULL;
	int ret = 0;
	struct timeval epoc_start_time;
	struct timeval epoc_end_time;
	uint32_t end_time = 0;

	size += set_urr_id(&usage_report->urr_id, urr->urr_id);

	pfcp_set_ie_header(&(usage_report->urseqn.header), PFCP_IE_URSEQN,
						(sizeof(pfcp_urseqn_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_urseqn_ie_t);
	usage_report->urseqn.urseqn = urr->urr_seq_num++;

	pfcp_set_ie_header(&(usage_report->usage_rpt_trig.header), PFCP_IE_USAGE_RPT_TRIG,
						(sizeof(pfcp_usage_rpt_trig_ie_t) - sizeof(pfcp_ie_header_t)));
	size += sizeof(pfcp_usage_rpt_trig_ie_t);

	usage_report->usage_rpt_trig.termr = 1;



	if(urr->meas_method == VOL_TIME_BASED ||
			urr->meas_method == VOL_BASED){
		size += set_volume_measurment(&usage_report->vol_meas);
		usage_report->vol_meas.uplink_volume = urr->uplnk_data;
		usage_report->vol_meas.downlink_volume = urr->dwnlnk_data;
		usage_report->vol_meas.total_volume = urr->dwnlnk_data + urr->uplnk_data;
	}

	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		end_time = current_ntp_timestamp();
		size += set_duration_measurment(&usage_report->dur_meas);
		ntp_to_unix_time(&urr->start_time, &epoc_start_time);
		ntp_to_unix_time(&end_time, &epoc_end_time);
		usage_report->dur_meas.duration_value = epoc_end_time.tv_sec - epoc_start_time.tv_sec;
	}

	size += set_start_time(&usage_report->start_time);
	size += set_end_time(&usage_report->end_time);
	size += set_first_pkt_time(&usage_report->time_of_frst_pckt);
	size += set_last_pkt_time(&usage_report->time_of_lst_pckt);

	usage_report->start_time.start_time = urr->start_time;
	usage_report->end_time.end_time = current_ntp_timestamp();
	usage_report->time_of_frst_pckt.time_of_frst_pckt = urr->first_pkt_time;
	usage_report->time_of_lst_pckt.time_of_lst_pckt = urr->last_pkt_time;

	urr->start_time = current_ntp_timestamp();
	urr->first_pkt_time = 0;
	urr->last_pkt_time = 0;

	pfcp_set_ie_header(&usage_report->header, IE_USAGE_RPT_SESS_DEL_RSP, size);

	if(urr->meas_method == TIME_BASED || urr->meas_method == VOL_TIME_BASED) {
		ret = rte_hash_lookup_data(timer_by_id_hash,
				&urr->urr_id, (void **)&data);

		if (ret >= 0) {
			if(data->pt.ti_id != 0) {
				stoptimer(&data->pt.ti_id);
				deinittimer(&data->pt.ti_id);

				/* URR Entry is present. Delete timer Entry */
				ret = rte_hash_del_key(timer_by_id_hash, &urr->urr_id);

				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Timer Entry "
						"not found for URR_ID:%u\n", LOG_VALUE, urr->urr_id);
					return -1;
				}

				if (data != NULL) {
					rte_free(data);
					data = NULL;
				}
			}
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"No timer entery found for URR %u\n", LOG_VALUE, urr->urr_id);
		}
	}
	return size;
}

int8_t
up_delete_session_entry(pfcp_session_t *sess, pfcp_sess_del_rsp_t *sess_del_rsp)
{
	int ret = 0;
	int8_t inx = 0;
	node_address_t peer_addr = {0};
	ue_ip_t ue_ip[MAX_BEARERS] = {0};

	int cnt = 0;
	uint32_t ue_ip_addr = 0;
	uint8_t ue_ipv6_addr[IPV6_ADDRESS_LEN] = {0};
	pfcp_usage_rpt_sess_del_rsp_ie_t usage_report[MAX_LIST_SIZE]= {0};

	(sess->cp_ip.type == IPV6_TYPE)?
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" CP_Sess_ID: %lu, UP_Sess_ID:%lu, CP_IPv6:"IPv6_FMT"\n",
				LOG_VALUE, sess->cp_seid, sess->up_seid,
				IPv6_PRINT(IPv6_CAST(sess->cp_ip.ipv6.sin6_addr.s6_addr))):
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" CP_Sess_ID: %lu, UP_Sess_ID:%lu, CP_IPv4:"IPV4_ADDR"\n",
				LOG_VALUE, sess->cp_seid, sess->up_seid,
				IPV4_ADDR_HOST_FORMAT(sess->cp_ip.ipv4.sin_addr.s_addr));

	/* Flush the Session data info from the hash tables based on teid*/
	pfcp_session_datat_t *session = sess->sessions;

	/* Cleanup the session data form hash table and delete the node from linked list */
	while (session != NULL) {
			if (session->dl_ring != NULL) {
			struct rte_ring *ring = session->dl_ring;

			session->dl_ring = NULL;
			/* This is going to be nasty. We could potentially have a race
			 * condition if modify bearer occurs directly before a delete
			 * session, causing scan_notify_ring_func to work on the same
			 * ring as this function. For our current tests, we *should* be
			 * okay. For now.
			 */

			int i = 0;
			int ret = 0;
			int count = 0;
			struct rte_mbuf *m[MAX_BURST_SZ];

			do {

		 /* Adding handling for support dpdk-18.02 and dpdk-16.11.04 */
#if (RTE_VER_YEAR >= 16) && (RTE_VER_MONTH >= 11)
				ret = rte_ring_sc_dequeue_burst(ring,
				        (void **)m, MAX_BURST_SZ);
#elif (RTE_VER_YEAR >= 18) && (RTE_VER_MONTH >= 02)
				unsigned int *ring_entry = NULL;

				/* Adding handling for support dpdk-18.02 */
				ret = rte_ring_sc_dequeue_burst(ring,
				        (void **)m, MAX_BURST_SZ, ring_entry);
#endif

				for (i = 0; i < ret; ++i) {
					if (m[i] != NULL)
						rte_pktmbuf_free(m[i]);
				}
				count += ret;
			} while (ret);

			if (rte_ring_enqueue(dl_ring_container, ring) ==
			        ENOBUFS) {
			    clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Can't put ring back, so free it - "
		            "dropped %d pkts\n", LOG_VALUE, count);
			    rte_ring_free(ring);
			}
		}

		/* Cleanup PDRs info from the linked list */
		pdr_info_t *pdr = session->pdrs;

		if (ue_ip_addr == 0 && *ue_ipv6_addr == 0) {
			if (session->ipv4) {
				ue_ip_addr = session->ue_ip_addr;
			}
			if (session->ipv6) {
				memcpy(ue_ipv6_addr, session->ue_ipv6_addr, IPV6_ADDRESS_LEN);
			}
		}

		if (ue_ip_addr == 0 && *ue_ipv6_addr == 0) {
			if(session->next != NULL) {
				if (session->next->ipv4) {
					ue_ip_addr = session->next->ue_ip_addr;
				}
				if (session->next->ipv6) {
					memcpy(ue_ipv6_addr, session->next->ue_ipv6_addr, IPV6_ADDRESS_LEN);
				}
			}
		}

		while (pdr != NULL) {
			for(int itr = 0; itr < pdr->urr_count; itr++){
				if(sess_del_rsp != NULL){
					fill_sess_del_usage_report(&sess_del_rsp->usage_report[sess_del_rsp->usage_report_count++],
							&pdr->urr[itr]);
				} else {
					fill_sess_del_usage_report(&usage_report[cnt], &pdr->urr[itr]);
					store_cdr_for_restoration(&usage_report[cnt], sess->up_seid, 0,
																	0, ue_ip_addr, ue_ipv6_addr);
					cnt++;
				}
			}
			far_info_t *far = pdr->far;
			/* Cleanup the FAR information */
			if (far != NULL) {
#ifdef USE_REST
				memset(&peer_addr, 0, sizeof(node_address_t));
				peer_addr.ip_type = far->frwdng_parms.outer_hdr_creation.ip_type;
				if (far->frwdng_parms.outer_hdr_creation.ip_type == IPV6_TYPE) {
					if (far->frwdng_parms.outer_hdr_creation.ipv6_address != NULL) {
						memcpy(peer_addr.ipv6_addr,
								far->frwdng_parms.outer_hdr_creation.ipv6_address,
								IPV6_ADDR_LEN);
						dp_flush_session(peer_addr, sess->up_seid);
					}
				} else if (far->frwdng_parms.outer_hdr_creation.ip_type == IPV4_TYPE) {
					if (far->frwdng_parms.outer_hdr_creation.ipv4_address != 0) {
						peer_addr.ipv4_addr = far->frwdng_parms.outer_hdr_creation.ipv4_address;
						dp_flush_session(peer_addr, sess->up_seid);
					}
				}
#endif /* USE_REST */
				/* Flush the far info from the hash table */
				ret = del_far_info_entry(far->far_id_value, sess->cp_ip);
				if (ret) {
					clLog(clSystemLog, eCLSeverityCritical, "DP:"LOG_FORMAT"Entry not found for FAR_ID:%u...\n",
								LOG_VALUE, far->far_id_value);
					return -1;
				}
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":FAR_ID:%u\n",
					LOG_VALUE, far->far_id_value);
			}

			/* Cleanup QERs info from the linked list */
			if (!pdr->predef_rules_count) {
				qer_info_t *qer = pdr->quer;
				while (qer != NULL) {
					/* Get QER ID */
					uint32_t qer_id = qer->qer_id;

					/* Delete the QER info node from the linked list */
					pdr->quer = remove_qer_node(pdr->quer, qer);
					qer = pdr->quer;

					/* Flush the QER info from the hash table */
					ret = del_qer_info_entry(qer_id, sess->cp_ip);
					if ( ret < 0) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for QER_ID:%u...\n",
								LOG_VALUE, qer_id);
						return -1;
					}
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": QER_ID:%u\n",
					LOG_VALUE, qer_id);
				}
			}


			/* Cleanup URRs info from the linked list */
			urr_info_t *urr = pdr->urr;
			while (urr != NULL) {
				uint32_t urr_id = urr->urr_id;

				/* Delete the URR info node from the linked list */
				pdr->urr = remove_urr_node(pdr->urr, urr);
				urr = pdr->urr;

				/* Flush the URR info from the hash table */
				if (del_urr_info_entry(urr_id, sess->cp_ip)) {
					/* TODO : ERROR Handling */
				}
			}

			/* Cleanup PDRs info from the linked list */
			/* Get PDR ID */
			uint32_t pdr_id = pdr->rule_id;

			/* Delete the PDR info node from the linked list */
			session->pdrs = remove_pdr_node(session->pdrs, pdr);
			pdr = session->pdrs;

			/* Flush the PDR info from the hash table */
			ret = del_pdr_info_entry(pdr_id, sess->cp_ip);
			if (ret) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for PDR_ID:%u...\n",
					LOG_VALUE, pdr_id);
				return -1;
			}
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT":PDR_ID:%u\n", LOG_VALUE, pdr_id);
		}

		if ((session->ipv4 != 0) || (session->ipv6 != 0)){
			ue_ip[inx].ue_ipv4 = session->ue_ip_addr;
			memcpy(ue_ip[inx].ue_ipv6, session->ue_ipv6_addr, IPV6_ADDRESS_LEN);
			inx++;
		}

		/* Delete the Session data info node from the linked list */
		sess->sessions = remove_sess_data_node(sess->sessions, session);
		if (sess->sessions == NULL)
			break;

		session = sess->sessions;
	}

	/* Flush the Session data info from the hash tables based on ue_ip */
	for (int itr = 0; itr < inx; itr++) {
		ue_ip_t ue_addr = {0};
		if (ue_ip[inx].ue_ipv4) {
			ue_addr.ue_ipv4 = ue_ip[inx].ue_ipv4;
			if (del_sess_by_ueip_entry(ue_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for UE_IPv4 :"
						""IPV4_ADDR"\n", LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip[itr].ue_ipv4));
				return -1;
			}
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": UE_IPv4 :"IPV4_ADDR"\n",
					LOG_VALUE, IPV4_ADDR_HOST_FORMAT(ue_ip[itr].ue_ipv4));
		}

		if (ue_ip[inx].ue_ipv6) {
			memset(&ue_addr, 0, sizeof(ue_ip_t));
			memcpy(ue_addr.ue_ipv6, ue_ip[itr].ue_ipv6, IPV6_ADDRESS_LEN);

			char ipv6[IPV6_STR_LEN];
			inet_ntop(AF_INET6, ue_ip[itr].ue_ipv6, ipv6, IPV6_STR_LEN);
			if (del_sess_by_ueip_entry(ue_addr) < 0) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Entry not found for"
					" IPv6 Addr: %s\n", LOG_VALUE, ipv6);
				return -1;
			}
			clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": IPv6 Addr: %s\n",
					LOG_VALUE, ipv6);
		}
	}

	for (int itr1 = 0; itr1 < sess->ber_cnt; itr1++) {
		if(sess->teids[itr1] == 0)
			continue;
		else if (del_sess_by_teid_entry(sess->teids[itr1])) {
			/* TODO : ERROR Handling */
		}
		clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Checking Teid value: 0x%x, counter:%u, Max Counter:%u\n",
			LOG_VALUE, sess->teids[itr1], itr1, sess->ber_cnt);
		sess->teids[itr1] = 0;
	}

	/* Session Entry is present. Delete Session Entry */
	ret = del_sess_info_entry(sess->up_seid);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Entry not found for UP_SESS_ID:%lu...\n",
			LOG_VALUE, sess->up_seid);
		return -1;
	}

	/*CLI:decrement active session count*/
	update_sys_stat(number_of_active_session, DECREMENT);

	return 0;
}

int8_t
process_up_session_deletion_req(pfcp_sess_del_req_t *sess_del_req,
				    pfcp_sess_del_rsp_t *sess_del_rsp)
{
	pfcp_session_t *sess = NULL;
	memset(sess_del_rsp, 0, sizeof(pfcp_sess_del_rsp_t));

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Deletion Request :: START \n", LOG_VALUE);
	/* Get the session information from session table based on UP_SESSION_ID*/
	if (sess_del_req->header.s) {
		/* Check SEID is not ZERO */
		sess = get_sess_info_entry(sess_del_req->header.seid_seqno.has_seid.seid,
				SESS_DEL);
	}

	if (sess == NULL)
		return -1;

	if (up_delete_session_entry(sess, sess_del_rsp))
		return -1;

	/* Update the CP seid in the response packet */
	sess_del_rsp->header.seid_seqno.has_seid.seid = sess->cp_seid;

#ifdef USE_CSID
	if (del_sess_by_csid_entry(sess, sess->up_fqcsid, SX_PORT_ID)) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Error: %s \n", LOG_VALUE,
				strerror(errno));
		return -1;
	}
#endif /* USE_CSID */

	/* Cleanup the session */
	rte_free(sess);
	sess = NULL;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"PFCP Session Deletion Request :: END \n", LOG_VALUE);
	return 0;
}


bool inittimer(peerEntry *md, int ptms, gstimercallback cb)
{
	return gst_timer_init(&md->pt, ttInterval, cb, ptms, md);
}

peerEntry *
fill_timer_entry_usage_report(struct sockaddr_in *peer_addr, urr_info_t *urr, uint64_t cp_seid, uint64_t up_seid)
{
	peerEntry *timer_entry = NULL;
	int ret = 0;

	timer_entry = rte_zmalloc_socket(NULL, sizeof(peerEntry),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failure to allocate timer entry :"
				"%s\n", LOG_VALUE, rte_strerror(rte_errno));
		return NULL;
	}



	timer_entry->dstIP = peer_addr->sin_addr.s_addr;
	timer_entry->cp_seid = cp_seid;
	timer_entry->up_seid = up_seid;
	timer_entry->urr = urr;
	ret = rte_hash_add_key_data(timer_by_id_hash,
			&urr->urr_id, timer_entry);
	if (ret) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add timer entry for URR_ID = %u"
			"\n\tError= %s\n", LOG_VALUE, urr->urr_id, rte_strerror(abs(ret)));

		return NULL;
	}

	return(timer_entry);
}

bool
add_timer_entry_usage_report(peerEntry *conn_data, uint32_t timeout_ms,
		gstimercallback cb)
{

	if (!inittimer(conn_data, timeout_ms*1000, cb))
	{
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT " =>%s - initialization of %s failed erro no %d\n",
			LOG_VALUE, getPrintableTime(), conn_data->name, errno);
		return false;
	}

	return true;
}


void
timer_callback(gstimerinfo_t *ti, const void *data_t )
{

	peerEntry *data =  (peerEntry *) data_t;
	int ret = 0;

	if(data->urr->meas_method == TIME_BASED ||
			data->urr->meas_method == VOL_TIME_BASED) {
		if(send_usage_report_req(data->urr, data->cp_seid, data->up_seid, TIME_BASED) != 0 ){

			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to Send Usage "
				"Report Request \n", LOG_VALUE);
		}

	} else {
		ret = rte_hash_lookup_data(timer_by_id_hash,
				&data->urr->urr_id, (void **)&data);

		if (ret >=0 ) {

			if(data->pt.ti_id != 0) {
				stoptimer(&data->pt.ti_id);
				deinittimer(&data->pt.ti_id);
				ret = rte_hash_del_key(timer_by_id_hash, &data->urr->urr_id);

				if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"Timer Entry not "
						"found for URR_ID:%u\n", LOG_VALUE, data->urr->urr_id);
					return;
				}

				if (data != NULL) {
					rte_free(data);
					data = NULL;
				}
			}
		}
	}
}

int
fill_li_duplicating_params(pfcp_create_far_ie_t *far, far_info_t *far_t, pfcp_session_t *sess) {

	far_t->dup_parms_cnt = 0;
	far_t->li_config_cnt = 0;
	sess->li_sx_config_cnt = 0;

	memset(far_t->li_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_config_t));
	memset(sess->li_sx_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_sx_config_t));

	for (uint8_t itr = 0; itr < far->dupng_parms_count; ++itr) {

		uint8_t policy_ident = 0;
		for (uint8_t iCnt = 0; iCnt < far->dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident_len;
				++iCnt) {

			policy_ident = far->dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident[iCnt];

			switch(iCnt) {
			case FRWDING_PLCY_SX:
				sess->li_sx_config[itr].sx = policy_ident;
				break;

			case FRWDING_PLCY_WEST_DIRECTION:
				far_t->li_config[itr].west_direction = policy_ident;
				break;

			case FRWDING_PLCY_WEST_CONTENT:
				far_t->li_config[itr].west_content = policy_ident;
				break;

			case FRWDING_PLCY_EAST_DIRECTION:
				far_t->li_config[itr].east_direction = policy_ident;
				break;

			case FRWDING_PLCY_EAST_CONTENT:
				far_t->li_config[itr].east_content = policy_ident;
				break;

			case FRWDING_PLCY_FORWARD:
				sess->li_sx_config[itr].forward = policy_ident;
				far_t->li_config[itr].forward = policy_ident;
				break;

			case FRWDING_PLCY_ID:
				memcpy(&sess->li_sx_config[itr].id,
					&far->dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident[iCnt],
					sizeof(uint64_t));
				far_t->li_config[itr].id = sess->li_sx_config[itr].id;
				break;

			default:
				break;
			}
		}
	}

	far_t->dup_parms_cnt = far->dupng_parms_count;
	far_t->li_config_cnt = far->dupng_parms_count;
	sess->li_sx_config_cnt = far->dupng_parms_count;

	return 0;
}

int
fill_li_update_duplicating_param(pfcp_update_far_ie_t *far, far_info_t *far_t, pfcp_session_t *sess) {

	far_t->dup_parms_cnt = 0;
	far_t->li_config_cnt = 0;
	sess->li_sx_config_cnt = 0;

	memset(far_t->li_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_config_t));
	memset(sess->li_sx_config, 0, MAX_LI_ENTRIES_PER_UE * sizeof(li_sx_config_t));

	for (int itr = 0; itr < far->upd_dupng_parms_count; itr++) {

		uint8_t policy_ident = 0;
		for (uint8_t iCnt = 0; iCnt < far->upd_dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident_len;
				++iCnt) {

			policy_ident = far->upd_dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident[iCnt];

			switch(iCnt) {

			case FRWDING_PLCY_SX:
				sess->li_sx_config[itr].sx = policy_ident;
				break;

			case FRWDING_PLCY_WEST_DIRECTION:
				far_t->li_config[itr].west_direction = policy_ident;
				break;

			case FRWDING_PLCY_WEST_CONTENT:
				far_t->li_config[itr].west_content = policy_ident;
				break;

			case FRWDING_PLCY_EAST_DIRECTION:
				far_t->li_config[itr].east_direction = policy_ident;
				break;

			case FRWDING_PLCY_EAST_CONTENT:
				far_t->li_config[itr].east_content = policy_ident;
				break;

			case FRWDING_PLCY_FORWARD:
				sess->li_sx_config[itr].forward = policy_ident;
				far_t->li_config[itr].forward = policy_ident;
				break;

			case FRWDING_PLCY_ID:
				memcpy(&sess->li_sx_config[itr].id,
					&far->upd_dupng_parms[itr].frwdng_plcy.frwdng_plcy_ident[iCnt],
					sizeof(uint64_t));
				far_t->li_config[itr].id = sess->li_sx_config[itr].id;
				break;

			default:
				break;
			}
		}
	}

	far_t->dup_parms_cnt = far->upd_dupng_parms_count;
	far_t->li_config_cnt = far->upd_dupng_parms_count;
	sess->li_sx_config_cnt = far->upd_dupng_parms_count;

	return 0;
}

int32_t
process_event_li(pfcp_session_t *sess, uint8_t *buf_rx, int buf_rx_size,
	uint8_t *buf_tx, int buf_tx_size, peer_addr_t *peer_addr) {

	int ret = 0;
	int pkt_length = 0;
	uint8_t *pkt = NULL;

	if (NULL == sess) {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Sess"
			" entry Not found ", LOG_VALUE);
		return -1;
	}

	for (uint8_t cnt = 0; cnt < sess->li_sx_config_cnt; cnt++) {

		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Li "
			"configuration sx(%u)", LOG_VALUE, sess->li_sx_config[cnt].sx);

		if (NOT_PRESENT == sess->li_sx_config[cnt].sx) {

			continue;
		}

		/* For incoming message */
		if ((NULL != buf_rx) && (buf_rx_size > 0)) {

			pkt_length = buf_rx_size;
			pkt = rte_malloc(NULL, (pkt_length + sizeof(li_header_t)), 0);
			if (NULL == pkt) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failed"
					" to allocate memory for li packet", LOG_VALUE);

				return -1;
			}

			memcpy(pkt, buf_rx, pkt_length);

			create_li_header(pkt, &pkt_length, EVENT_BASED,
				sess->li_sx_config[cnt].id, sess->imsi,
				fill_ip_info(peer_addr->type,
						peer_addr->ipv4.sin_addr.s_addr,
						peer_addr->ipv6.sin6_addr.s6_addr),
				fill_ip_info(peer_addr->type,
						dp_comm_ip.s_addr,
						dp_comm_ipv6.s6_addr),
				((peer_addr->type == IPTYPE_IPV4_LI) ?
						ntohs(peer_addr->ipv4.sin_port) :
						ntohs(peer_addr->ipv6.sin6_port)),
				dp_comm_port,
				sess->li_sx_config[cnt].forward);

			ret = send_li_data_pkt(ddf2_fd, pkt, pkt_length);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Failed"
					" to send PFCP event on TCP sock"
					" with error %d\n", LOG_VALUE, ret);
				return -1;
			}

			rte_free(pkt);
			pkt = NULL;
		}

		/* For outgoing message */
		if ((NULL != buf_tx) && (buf_tx_size > 0)) {

			pkt_length = buf_tx_size;
			pkt = rte_malloc(NULL, (pkt_length + sizeof(li_header_t)), 0);
			if (NULL == pkt) {
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed"
					" to allocate memory for li packet", LOG_VALUE);

				return -1;
			}

			memcpy(pkt, buf_tx, pkt_length);

			create_li_header(pkt, &pkt_length, EVENT_BASED,
				sess->li_sx_config[cnt].id, sess->imsi,
				fill_ip_info(peer_addr->type,
						dp_comm_ip.s_addr,
						dp_comm_ipv6.s6_addr),
				fill_ip_info(peer_addr->type,
						peer_addr->ipv4.sin_addr.s_addr,
						peer_addr->ipv6.sin6_addr.s6_addr),
				dp_comm_port,
				((peer_addr->type == IPTYPE_IPV4_LI) ?
						ntohs(peer_addr->ipv4.sin_port) :
						ntohs(peer_addr->ipv6.sin6_port)),
				sess->li_sx_config[cnt].forward);

			ret = send_li_data_pkt(ddf2_fd, pkt, pkt_length);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT" Failed"
						" to send PFCP event on TCP sock"
						" with error %d\n", LOG_VALUE, ret);
				return -1;
			}

			rte_free(pkt);
			pkt = NULL;
		}
	}

	return 0;
}

void
check_cause_id_pfd_mgmt(pfcp_pfd_contents_ie_t *pfd_content, uint8_t **cause_id, int **offend_id)
{

	if((pfd_content->cp) && (pfd_content->len_of_cstm_pfd_cntnt)){
		**cause_id = REQUESTACCEPTED;
	} else {

		**cause_id = MANDATORYIEMISSING;
		**offend_id= PFCP_IE_PFD_CONTENTS;
	}
}

struct pcc_rules* get_pcc_rule(uint32_t ip)
{
	rules_struct *rule = NULL;
	rule = get_map_rule_entry(ip, GET_RULE);
	if (rule != NULL) {
		rules_struct *current = NULL;
		current = rule;

		while (current != NULL) {

			/* Retrive the PCC rule based on the rule name */
			struct pcc_rules *pcc = NULL;
			pcc = get_predef_pcc_rule_entry(&current->rule_name, GET_RULE);
			if (pcc == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to get PCC Rule from the pcc table"
						" for Rule_Name: %s\n", LOG_VALUE, current->rule_name.rname);
				/* Assign Next node address */
				rule = current->next;
				/* Get the next node */
				current = rule;
				continue;
			}else {
				return pcc;
			}

		}
	}
	clLog(clSystemLog, eCLSeverityCritical,
			LOG_FORMAT"Error: Failed to Get PCC Rule from centralized map table\n",
			LOG_VALUE);
	return NULL;

}

void
process_rule_msg(pfcp_pfd_contents_ie_t *pfd_content, uint64_t msg_type,
		uint32_t cp_ip, uint16_t idx)
{
	int ret = 0;
	switch(msg_type) {
		case MSG_PCC_TBL_ADD: {
			struct pcc_rules *pcc = NULL;
			pcc_rule_name key = {0};
			memset(key.rname, '\0', sizeof(key.rname));
			pcc = (struct pcc_rules *)(pfd_content->cstm_pfd_cntnt + idx);
			if (pcc == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to extract PCC Rule\n", LOG_VALUE);
				return;
			}

			memcpy(key.rname, pcc->rule_name, sizeof(pcc->rule_name));

			struct pcc_rules *pcc_temp = get_predef_pcc_rule_entry(&key, ADD_RULE);
			if (pcc_temp != NULL) {
				memcpy(pcc_temp, pcc, sizeof(struct pcc_rules));

				/* Add the rule name in centralized map table */
				rules_struct *rules = NULL;
				rules = get_map_rule_entry(cp_ip, ADD_RULE);
				if (rules == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Error: Failed to ADD/GET PCC Rule from centralized map table\n",
							LOG_VALUE);
					return;
				} else {
					rules_struct *new_node = NULL;
					/* Calculate the memory size to allocate */
					uint16_t size = sizeof(rules_struct);

					/* allocate memory for rule entry*/
					new_node = rte_zmalloc("Rules_Infos", size, RTE_CACHE_LINE_SIZE);
					if (new_node == NULL) {
					    clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Failed to allocate memory for rule entry.\n",
								LOG_VALUE);
					    return;
					}

					/* Set/Stored the rule name in the centralized location */
					memcpy(new_node->rule_name.rname, &key.rname,
							sizeof(key.rname));

					/* Insert the node into the LL */
					if (insert_rule_name_node(rules, new_node) < 0) {
						clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Failed to add node entry in LL\n",
								LOG_VALUE);
						return;
					}
					clLog(clSystemLog, eCLSeverityDebug,
							LOG_FORMAT"PCC Rule add/inserted in the internal table and map,"
							"Rule_Name: %s, Node_Count:%u\n", LOG_VALUE, key.rname, rules->rule_cnt);
				}
			} else {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to add pcc rules for rule_name =%s\n",
						LOG_VALUE, key.rname);
			}
			print_pcc_val(pcc);
			break;
		}
		case MSG_SDF_ADD:{
			/* TypeCast the payload into SDF Rule */
			struct pkt_filter *sdf_filter = (struct pkt_filter *)(pfd_content->cstm_pfd_cntnt + idx);
			if (sdf_filter == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to extract SDF Rule\n", LOG_VALUE);
				return;
			}
			ret = get_predef_rule_entry(sdf_filter->rule_id,
					SDF_HASH, ADD_RULE, (void **)&sdf_filter);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Add SDF Rule from the internal table"
						"for SDF_Indx: %u\n", LOG_VALUE, sdf_filter->rule_id);
			}
			print_sdf_val(sdf_filter);
			break;
		}
		case MSG_ADC_TBL_ADD:{
			struct adc_rules *adc_rule_entry = (struct adc_rules *)(pfd_content->cstm_pfd_cntnt + idx);
			if (adc_rule_entry == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to extract ADC Rule\n", LOG_VALUE);
				return;
			}
			ret = get_predef_rule_entry(adc_rule_entry->rule_id,
					ADC_HASH, ADD_RULE, (void **)&adc_rule_entry);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to add ADC Rule from the internal table"
						"for ADC_Indx: %u\n", LOG_VALUE, adc_rule_entry->rule_id);
			}
			print_adc_val(adc_rule_entry);
			break;
		}

		case MSG_MTR_ADD: {
			struct mtr_entry *mtr_rule = (struct mtr_entry *)(pfd_content->cstm_pfd_cntnt + idx);
			if (mtr_rule == NULL) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Failed to extract Mtr Rule\n", LOG_VALUE);
				return;
			}
			ret = get_predef_rule_entry(mtr_rule->mtr_profile_index,
					MTR_HASH, ADD_RULE, (void **)&mtr_rule);
			if (ret < 0) {
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to Add MTR Rule from the internal table"
						"for Mtr_Indx: %u\n", LOG_VALUE, mtr_rule->mtr_profile_index);
			}
			print_mtr_val(mtr_rule);
			break;
		}
		case MSG_PCC_TBL_DEL:
		case MSG_SDF_DEL:
		case MSG_ADC_TBL_DEL:
		case MSG_MTR_DEL:
		case MSG_SESS_DEL:{
			ret = del_map_rule_entry(cp_ip);
			if(ret < 0){
				clLog(clSystemLog, eCLSeverityCritical,
						LOG_FORMAT"Error: Failed to delete rules\n",
						LOG_VALUE);
			}
			break;
		}
		case MSG_SESS_MOD:
			break;

		case MSG_DDN_ACK:
			break;

		case MSG_EXP_CDR:
			break;

		default:
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Error: no appropirate message passed\n",
					LOG_VALUE);
			break;
	}
}

void
process_up_pfd_mgmt_request(pfcp_pfd_mgmt_req_t *pfcp_pfd_mgmt_req,
		uint8_t *cause_id, int *offend_id, uint32_t cp_ip)
{
	uint16_t idx = 0;
	uint8_t app_id_itr = 0;
	uint8_t pfd_context_itr = 0;
	uint8_t pfd_context_count = 0;
	uint8_t pfd_content_itr = 0;
	uint8_t pfd_content_count = 0;
	pfcp_pfd_contents_ie_t *pfd_content = NULL;

	for (app_id_itr = 0; app_id_itr < pfcp_pfd_mgmt_req->app_ids_pfds_count;
			app_id_itr++) {
		pfd_context_count =
			pfcp_pfd_mgmt_req->app_ids_pfds[app_id_itr].pfd_context_count;
		for (pfd_context_itr = 0; pfd_context_itr < pfd_context_count;
				pfd_context_itr++) {
			pfd_content_count =
				pfcp_pfd_mgmt_req->app_ids_pfds[app_id_itr].pfd_context[pfd_context_itr].pfd_contents_count;

			for (pfd_content_itr = 0; pfd_content_itr < pfd_content_count; pfd_content_itr++) {
				pfd_content =
					&(pfcp_pfd_mgmt_req->app_ids_pfds[app_id_itr].pfd_context[pfd_context_itr].pfd_contents[pfd_content_itr]);

				if(pfd_content->header.len){
					check_cause_id_pfd_mgmt(pfd_content, &cause_id, &offend_id);

					if(*cause_id == REQUESTACCEPTED){
						long mtype= 0 ;
						mtype = get_rule_type(pfd_content, &idx);
						process_rule_msg(pfd_content, mtype, cp_ip, idx);

					}else {
						clLog(clSystemLog, eCLSeverityCritical,
								LOG_FORMAT"Error: cause id is not accepted\n",
								LOG_VALUE);
						return;
					}
				}
			}
		}
	}

	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Successfully pfd management request processed\n",
			LOG_VALUE);
	return;
}

int8_t
process_up_session_report_resp(pfcp_sess_rpt_rsp_t *sess_rep_resp)
{
	pfcp_session_t *sess = NULL;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT
			"PFCP Session Report Response :: START \n", LOG_VALUE);

	/* Get the session information from session table based on UP_SESSION_ID */
	if (sess_rep_resp->header.s) {
		/* Check SEID is not ZERO */
		sess = get_sess_info_entry(sess_rep_resp->header.seid_seqno.has_seid.seid,
				SESS_MODIFY);
	}

	if (sess == NULL)
		return -1;

	/* pfcpsrrsp_flags: Dropped the bufferd packets  */
	if (sess_rep_resp->sxsrrsp_flags.drobu) {
		/* Free the downlink data rings */
		//rte_free();

	}

	if (sess->bar.dl_buf_suggstd_pckts_cnt.pckt_cnt_val !=
			sess_rep_resp->update_bar.dl_buf_suggstd_pckt_cnt.pckt_cnt_val) {

		struct rte_ring *ring = NULL;
		struct rte_ring *new_ring = NULL;
		struct pfcp_session_datat_t *si = NULL;

		si = sess->sessions;

		while (si != NULL) {

			/* Delete dl ring which created by default if present */
			ring = si->dl_ring;
			if (ring) {

				unsigned int *ring_entry = NULL;
				unsigned int count = rte_ring_count(ring);
				struct rte_mbuf pkts[count];
				new_ring = allocate_ring(
						sess_rep_resp->update_bar.dl_buf_suggstd_pckt_cnt.pckt_cnt_val);

				if (new_ring == NULL) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Not enough memory "
							"to allocate new ring\n", LOG_VALUE);
					return 0;
				}
				if(rte_ring_sc_dequeue_burst(ring, (void **)&pkts,
							count, ring_entry) == -ENOENT) {

					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Can't put ring back, so free it\n",
							LOG_VALUE);
					rte_ring_free(ring);
				}
				if(rte_ring_enqueue_burst(new_ring, (void **)&pkts,
							count, ring_entry) == -ENOBUFS) {

					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Can't put ring back, so free it\n", LOG_VALUE);
					rte_ring_free(new_ring);
				}
				rte_ring_free(ring);
				si->dl_ring = new_ring;
			}

			si = si->next;
		}
	}

	sess->bar.bar_id = sess_rep_resp->update_bar.bar_id.bar_id_value;
	sess->bar.dl_buf_suggstd_pckts_cnt.pckt_cnt_val =
		sess_rep_resp->update_bar.dl_buf_suggstd_pckt_cnt.pckt_cnt_val;

	clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT": CP_Sess_ID: %lu, UP_Sess_ID:%lu\n",
			LOG_VALUE, sess->cp_seid, sess->up_seid);

	return 0;
}
