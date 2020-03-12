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
extern struct app_params app;
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
	if (pfcp_config.cp_type != PGWC) {
		if (((pdn->context)->mme_fqcsid)->num_csid) {
			peer_info.mme_ip = ((pdn->context)->mme_fqcsid)->node_addr;
		} else {
			/* IF MME not support partial failure */
			peer_info.mme_ip = (pdn->context)->s11_mme_gtpc_ipv4.s_addr;
		}
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer Node MME IP Address: "IPV4_ADDR"\n",
				ERR_MSG,
				IPV4_ADDR_HOST_FORMAT(peer_info.mme_ip));
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

	clLog(clSystemLog, eCLSeverityDebug,
			FORMAT"Peer Node SGWC/SAEGWC IP Address: "IPV4_ADDR"\n",
			ERR_MSG,
			IPV4_ADDR_HOST_FORMAT(peer_info.sgwc_ip));

	if (pfcp_config.cp_type != PGWC) {
		/* Fill the enodeb IP */
		peer_info.enodeb_ip = bearer->s1u_enb_gtpu_ipv4.s_addr;
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer Node enodeb IP Address: "IPV4_ADDR"\n",
				ERR_MSG,
				IPV4_ADDR_HOST_FORMAT(peer_info.enodeb_ip));
	}

	/* SGW and PGW peer node info */
	peer_info.pgwc_ip = pdn->s5s8_pgw_gtpc_ipv4.s_addr;
	clLog(clSystemLog, eCLSeverityDebug,
			FORMAT"Peer Node PGWC IP Address: "IPV4_ADDR"\n",
			ERR_MSG,
			IPV4_ADDR_HOST_FORMAT(peer_info.pgwc_ip));

	/* SGWU and PGWU peer node info */
	if ((pfcp_config.cp_type == SAEGWC) || (pfcp_config.cp_type == SGWC)) {
		peer_info.sgwu_ip = pdn->upf_ipv4.s_addr;
		//peer_info.pgwu_ip = bearer->s5s8_pgw_gtpu_ipv4.s_addr;
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer Node SGWU/SAEGWU IP Address: "IPV4_ADDR"\n",
				ERR_MSG,
				IPV4_ADDR_HOST_FORMAT(peer_info.sgwu_ip));
	} else if (pfcp_config.cp_type == PGWC) {
		/*TODO: Need to think on it*/
		//peer_info.sgwu_ip = bearer->s5s8_sgw_gtpu_ipv4.s_addr;
		peer_info.pgwu_ip = pdn->upf_ipv4.s_addr;
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer Node PGWU IP Address: "IPV4_ADDR"\n",
				ERR_MSG,
				IPV4_ADDR_HOST_FORMAT(peer_info.pgwu_ip));
	}

	/* Get local csid for set of peer node */
	local_csid = get_csid_entry(&peer_info);
	if (local_csid < 0) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Failed to assinged CSID..\n", ERR_MSG);
		return -1;
	}

	/* Remove the dummy local CSIDs from the context */
	if (pfcp_config.cp_type != PGWC) {
		if (((pdn->context)->sgw_fqcsid)->local_csid[((pdn->context)->sgw_fqcsid)->num_csid - 1] != local_csid) {
			//memset((pdn->context)->sgw_fqcsid, 0, sizeof(fqcsid_t));
			((pdn->context)->sgw_fqcsid)->num_csid = 0;
		}
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
	if ((pdn->context)->mme_fqcsid != NULL) {
		if (((pdn->context)->mme_fqcsid)->num_csid) {
			for (uint8_t itr = 0; itr < ((pdn->context)->mme_fqcsid)->num_csid; itr++) {
				csid_t *tmp = NULL;
				csid_key_t key = {0};
				key.local_csid = ((pdn->context)->mme_fqcsid)->local_csid[itr];
				key.node_addr = ((pdn->context)->mme_fqcsid)->node_addr;

				if (pfcp_config.cp_type != PGWC)
					tmp = get_peer_csid_entry(&key, S11_SGW_PORT_ID);
				else
					tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);

				if (tmp == NULL) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					return -1;
				}

				/* Link local csid with MME CSID */
				if (tmp->num_csid == 0) {
					tmp->local_csid[tmp->num_csid++] = local_csid;
				} else {
					uint8_t match = 0;
					for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
							if (tmp->local_csid[itr1] == local_csid)
								match = 1;
					}

					if (!match) {
						tmp->local_csid[tmp->num_csid++] = local_csid;
					}
				}

				/* Update the Node Addr */
				if (pfcp_config.cp_type != PGWC)
					tmp->node_addr = ((pdn->context)->sgw_fqcsid)->node_addr;
				else
					tmp->node_addr = ((pdn->context)->pgw_fqcsid)->node_addr;
			}
		}
	}

	/* PGW Link local CSID with SGW CSID */
	if (pfcp_config.cp_type == PGWC) {
		if ((pdn->context)->sgw_fqcsid != NULL) {
			if (((pdn->context)->sgw_fqcsid)->num_csid) {
				for (uint8_t itr = 0; itr < ((pdn->context)->sgw_fqcsid)->num_csid; itr++) {
					csid_t *tmp = NULL;
					csid_key_t key = {0};
					key.local_csid = ((pdn->context)->sgw_fqcsid)->local_csid[itr];
					key.node_addr = ((pdn->context)->sgw_fqcsid)->node_addr;

					tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);
					if (tmp == NULL) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}

					/* Link local csid with SGW CSID */
					if (tmp->num_csid == 0) {
						/* Update csid by mme csid */
						tmp->local_csid[tmp->num_csid++] = local_csid;
					} else {
						uint8_t match = 0;
						for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
								if (tmp->local_csid[itr1] == local_csid)
									match = 1;
						}

						if (!match) {
							tmp->local_csid[tmp->num_csid++] = local_csid;
						}
					}
					/* Update the node address */
					tmp->node_addr = ((pdn->context)->sgw_fqcsid)->node_addr;
				}
			}
		}
	}

	/* SGW Link local CSID with PGW CSID */
	if (pfcp_config.cp_type != PGWC) {
		if ((pdn->context)->pgw_fqcsid != NULL) {
			if (((pdn->context)->pgw_fqcsid)->num_csid) {
				for (uint8_t itr = 0; itr < ((pdn->context)->pgw_fqcsid)->num_csid; itr++) {
					csid_t *tmp = NULL;
					csid_key_t key = {0};
					key.local_csid = ((pdn->context)->pgw_fqcsid)->local_csid[itr];
					key.node_addr = ((pdn->context)->pgw_fqcsid)->node_addr;

					tmp = get_peer_csid_entry(&key, S5S8_PGWC_PORT_ID);
					if (tmp == NULL) {
						clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
								strerror(errno));
						return -1;
					}

					/* Link local csid with SGW CSID */
					if (tmp->num_csid == 0) {
						/* Update csid by mme csid */
						tmp->local_csid[tmp->num_csid++] = local_csid;
					} else {
						uint8_t match = 0;
						for (uint8_t itr1 = 0; itr1 < tmp->num_csid; itr1++) {
								if (tmp->local_csid[itr1] == local_csid)
									match = 1;
						}

						if (!match) {
							tmp->local_csid[tmp->num_csid++] = local_csid;
						}
					}
					/* Update the node address */
					tmp->node_addr = ((pdn->context)->pgw_fqcsid)->node_addr;
				}
			}
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
			csid_key_t key = {0};
			key.local_csid = fqcsid->local_csid[itr];
			key.node_addr = fqcsid->node_addr;

			tmp = get_peer_csid_entry(&key, SX_PORT_ID);

			if (tmp == NULL) {
				clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
						strerror(errno));
				return -1;
			}

			/* Link local csid with MME CSID */
			if (tmp->num_csid == 0) {
				tmp->local_csid[tmp->num_csid++] = fqcsid_t->local_csid[fqcsid_t->num_csid - 1];
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
			tmp->node_addr = fqcsid_t->node_addr;
		}
	}
	return 0;
}

int8_t
fill_fqcsid_sess_mod_req(pfcp_sess_mod_req_t *pfcp_sess_mod_req, ue_context *context)
{
	/* Set SGW FQ-CSID */
	if (context->sgw_fqcsid != NULL) {
		if ((context->sgw_fqcsid)->num_csid) {
			fqcsid_t tmp_fqcsid = {0};

			set_fq_csid_t(&pfcp_sess_mod_req->sgw_c_fqcsid, context->sgw_fqcsid);
			if (pfcp_config.cp_type != PGWC) {
				(pfcp_sess_mod_req->sgw_c_fqcsid).node_address = ntohl(pfcp_config.pfcp_ip.s_addr);
			}

			/* set PGWC FQ-CSID explicitlly zero */
			set_fq_csid_t(&pfcp_sess_mod_req->pgw_c_fqcsid, &tmp_fqcsid);
			/* set MME FQ-CSID explicitlly zero */
			set_fq_csid_t(&pfcp_sess_mod_req->mme_fqcsid, &tmp_fqcsid);
		}
	}

	return 0;
}

int8_t
fill_fqcsid_sess_est_req(pfcp_sess_estab_req_t *pfcp_sess_est_req, ue_context *context)
{

	if (pfcp_config.cp_type != PGWC) {
		/* Set SGW FQ-CSID */
		if ((context->sgw_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, context->sgw_fqcsid);
			(pfcp_sess_est_req->sgw_c_fqcsid).node_address = ntohl(pfcp_config.pfcp_ip.s_addr);
		}
		/* Set MME FQ-CSID */
		if((context->mme_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, context->mme_fqcsid);
		}

		/* set PGWC FQ-CSID */
		/* set PGWC FQ-CSID expliciatlly zero */
		if (pfcp_config.cp_type != SAEGWC) {
			fqcsid_t tmp_fqcsid = {0};
			set_fq_csid_t(&pfcp_sess_est_req->pgw_c_fqcsid, &tmp_fqcsid);
		}
	} else {
		/* Set PGW FQ-CSID */
		if ((context->pgw_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->pgw_c_fqcsid, context->pgw_fqcsid);
			(pfcp_sess_est_req->pgw_c_fqcsid).node_address = ntohl(pfcp_config.pfcp_ip.s_addr);
		}
		/* Set SGW C FQ_CSID */
		if ((context->sgw_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->sgw_c_fqcsid, context->sgw_fqcsid);
		}
		/* Set MME FQ-CSID */
		if((context->mme_fqcsid)->num_csid) {
			set_fq_csid_t(&pfcp_sess_est_req->mme_fqcsid, context->mme_fqcsid);
		}
	}

	return 0;
}
#endif /* CP_BUID */


static uint16_t seq_t = 0;
#ifdef CP_BUILD
void
cp_fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids)
{
	fqcsid_t tmp = {0};
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, NO_SEID, ++seq_t);

	char pAddr[INET_ADDRSTRLEN] = {0};

#ifdef CP_BUILD
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
#else
	inet_ntop(AF_INET, &(dp_comm_ip.s_addr), pAddr, INET_ADDRSTRLEN);
#endif /* CP_BUILD */

	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	if (local_csids->instance == 0) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, local_csids);
		}
	} else if (local_csids->instance == 1) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp);

		}
	} else if (local_csids->instance == 2) {
		if (local_csids->num_csid) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp);
		}
	}

	if (pfcp_config.cp_type != PGWC) {
		set_fq_csid_t(&pfcp_sess_set_del_req->sgw_u_fqcsid, &tmp);
	} else {
		set_fq_csid_t(&pfcp_sess_set_del_req->pgw_u_fqcsid, &tmp);
	}

}
#endif /* CP_BUILD */
void
fill_pfcp_sess_set_del_req_t(pfcp_sess_set_del_req_t *pfcp_sess_set_del_req,
		fqcsid_t *local_csids, uint8_t iface)
{
	fqcsid_t tmp_csids = {0};
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_set_del_req->header),
			PFCP_SESSION_SET_DELETION_REQUEST, NO_SEID, ++seq_t);

	char pAddr[INET_ADDRSTRLEN] = {0};

#ifdef CP_BUILD
	inet_ntop(AF_INET, &(pfcp_config.pfcp_ip), pAddr, INET_ADDRSTRLEN);
#else
	inet_ntop(AF_INET, &(dp_comm_ip.s_addr), pAddr, INET_ADDRSTRLEN);
#endif /* CP_BUILD */

	unsigned long node_value = inet_addr(pAddr);
	set_node_id(&(pfcp_sess_set_del_req->node_id), node_value);

	if (local_csids->num_csid) {
		/* Set the SGWC FQ-CSID */
#ifdef CP_BUILD
		if ((iface == S11_SGW_PORT_ID) ||
				(iface == S5S8_SGWC_PORT_ID)) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_u_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp_csids);
		}

		if (iface == S5S8_PGWC_PORT_ID) {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_u_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp_csids);
		}
#else
		if(app.spgw_cfg == PGWU){
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_u_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp_csids);
			/* Set Node Addr */
			pfcp_sess_set_del_req->pgw_u_fqcsid.node_address = ntohl(dp_comm_ip.s_addr);
		} else {
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->pgw_c_fqcsid, &tmp_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->sgw_u_fqcsid, local_csids);
			set_fq_csid_t(&pfcp_sess_set_del_req->mme_fqcsid, &tmp_csids);
			/* Set Node Addr */
			pfcp_sess_set_del_req->sgw_u_fqcsid.node_address = ntohl(dp_comm_ip.s_addr);
		}
#endif /* DP_BUILD */
	}
}

/* Cleanup Session information by local csid*/
int8_t
del_pfcp_peer_node_sess(uint32_t node_addr, uint8_t iface)
{
	pfcp_sess_set_del_req_t del_set_req_t = {0};
	fqcsid_t *local_csids = NULL;
	fqcsid_t csids = {0};

	/* Get local CSID associated with node */
	local_csids = get_peer_addr_csids_entry(node_addr, MOD);
	if (local_csids == NULL) {
		clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
				strerror(errno));
		clLog(clSystemLog, eCLSeverityDebug,
				FORMAT"Peer CSIDs are already cleanup, Node_Addr:"IPV4_ADDR"\n",
				ERR_MSG, IPV4_ADDR_HOST_FORMAT(node_addr));
		return 0;
	}

	/* Get the mapped local CSID */
	for (int8_t itr = 0; itr < local_csids->num_csid; itr++) {
		csid_t *tmp = NULL;
		csid_key_t key = {0};
		key.local_csid = local_csids->local_csid[itr];
		key.node_addr = local_csids->node_addr;

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
	}

	if (!csids.num_csid) {
		clLog(clSystemLog, eCLSeverityDebug, FORMAT"CSIDs are already cleanup \n", ERR_MSG);
		return 0;
	}

#ifdef CP_BUILD
		csids.node_addr = ntohl(pfcp_config.pfcp_ip.s_addr);
#endif /* CP_BUILD */

	fill_pfcp_sess_set_del_req_t(&del_set_req_t, &csids, iface);

	/* Send the Delete set Request to peer node */
	uint8_t pfcp_msg[1024]={0};
	int encoded = encode_pfcp_sess_set_del_req_t(&del_set_req_t, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

#ifdef CP_BUILD
	if (pfcp_send(pfcp_fd, pfcp_msg, encoded, &upf_pfcp_sockaddr, SENT) < 0 ) {
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
	else {
		update_cli_stats(dest_addr_t.sin_addr.s_addr, header->message_type, SENT, SX);
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
		for (int itr = 0; itr < peer_csids->num_csid; itr++) {
			csid_t *csids = NULL;
			csid_key_t key = {0};
			key.local_csid = peer_csids->local_csid[itr];
			key.node_addr = peer_csids->node_addr;

			csids = get_peer_csid_entry(&key, iface);
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

			if (!csids->num_csid) {
				if (del_peer_csid_entry(&key, iface)) {
					clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
							strerror(errno));
					/* TODO ERROR HANDLING */
					return -1;
				}

				fqcsid_t *tmp = NULL;
				tmp = get_peer_addr_csids_entry(peer_csids->node_addr, MOD);
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
						if (del_peer_addr_csids_entry(peer_csids->node_addr)) {
							clLog(clSystemLog, eCLSeverityCritical, FORMAT"Error: %s \n", ERR_MSG,
									strerror(errno));
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

