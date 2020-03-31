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

#include <rte_errno.h>

#include "up_main.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"

/**
 * @brief Allocates ring for buffering downlink packets
 * Allocate downlink packet buffer ring from a set of
 * rings from the ring container.
 *
 * @param void
 *
 * @return
 *  - rte_ring Allocated ring
 *  - NULL on failure
 */

static struct
rte_ring *allocate_ring(void)
{
	struct rte_ring *dl_ring = NULL;
	unsigned dl_core = rte_lcore_id();
	int i;
	char name[32];

	if ((DL_RING_CONTAINER_SIZE > num_dl_rings) &&
		(rte_ring_count(dl_ring_container)
				< DL_RINGS_THRESHOLD)) {
		for (i = 0; i < DL_RINGS_THRESHOLD; ++i) {
			snprintf(name, sizeof(name), "dl_pkt_ring_%"PRIu32"_%u",
					num_dl_rings,
					dl_core);
			struct rte_ring *tmp =
				rte_ring_create(name, DL_PKTS_RING_SIZE,
						rte_socket_id(),
						RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (tmp) {
				int ret = rte_ring_enqueue(
					dl_ring_container, tmp);

				if (ret == ENOBUFS) {
					RTE_LOG_DP(DEBUG, DP,
						"Cannot hold more dl rings\n");
					rte_ring_free(tmp);
					break;
				}
				num_dl_rings++;
			} else {
				RTE_LOG_DP(ERR, DP, "Couldnt create %s for DL "
						"pkts - %s\n", name,
						rte_strerror(rte_errno));
				if (rte_errno == EEXIST)
					num_dl_rings++;
			}
		}
	}
	rte_ring_dequeue(dl_ring_container, (void **)&dl_ring);

	return dl_ring;
}

/* Process ddn ack received by data-plane from control-plane */
int
dp_ddn_ack(struct dp_id dp_id,
		struct downlink_data_notification_ack_t *dl_ddn)
{
	/* TBD: Downlink data notification Ack handling need to be implement. */

	/** Currently ack attribute dl_buff_cnt and dl_buff_duration is not handled.
	 *  default behaviour is ddn will be issued for the 1st packet for which the
	 *  session is IDEL and it will issued after ring is full. */

	RTE_LOG_DP(INFO, DP, "DDN ACK processed..\n");

	return 0;
}

static void
set_dndl_data_srv_if_ie(pfcp_dnlnk_data_svc_info_ie_t *dl)
{

	pfcp_set_ie_header(&(dl->header), PFCP_IE_DNLNK_DATA_SVC_INFO, 3);

	dl->ppi = 0;
	dl->qfi = 0;
	dl->qfii = 0;
	dl->paging_plcy_indctn_val = 0;
	dl->dnlnk_data_svc_info_spare = 0;
	dl->dnlnk_data_svc_info_spare2 = 0;
	dl->dnlnk_data_svc_info_spare3 = 0;
}
static void
set_dldr_ie(pfcp_dnlnk_data_rpt_ie_t *dl)
{
	dl->pdr_id_count = 1;
	//pfcp_set_ie_header(&(dl->header), IE_DNLNK_DATA_RPT, 13);
	pfcp_set_ie_header(&(dl->header), IE_DNLNK_DATA_RPT, 6);
			/*((sizeof(pfcp_dnlnk_data_rpt_ie_t) - ((MAX_LIST_SIZE - dl->pdr_id_count) * sizeof(dl->pdr_id) - 5))));*/

	set_pdr_id(dl->pdr_id);
	//set_dndl_data_srv_if_ie(&dl->dnlnk_data_svc_info);

}

static void
set_sess_report_type(pfcp_report_type_ie_t *rt)
{
	pfcp_set_ie_header(&(rt->header), PFCP_IE_REPORT_TYPE, UINT8_SIZE);
	rt->rpt_type_spare = 0;
	rt->upir  = 0;
	rt->erir  = 0;
	rt->usar  = 0;
	rt->dldr  = 1;
}

static void
fill_pfcp_sess_rep_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req,
			ddn_t **ddn)
{
	static uint32_t seq = 1;

	memset(pfcp_sess_rep_req, 0, sizeof(pfcp_sess_rpt_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_REPORT_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_req->header),
		PFCP_SESSION_REPORT_REQUEST, HAS_SEID, seq);

	pfcp_sess_rep_req->header.seid_seqno.has_seid.seid = (*ddn)->cp_seid;

	set_sess_report_type(&pfcp_sess_rep_req->report_type);

	/* TODO Need to Implement handling of other IE's when Rules implementation is done  */
	if (pfcp_sess_rep_req->report_type.dldr == 1) {
		set_dldr_ie(&pfcp_sess_rep_req->dnlnk_data_rpt);
		pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[0].rule_id = (*ddn)->pdr_id;
	}

	pfcp_sess_rep_req->header.message_len = pfcp_sess_rep_req->report_type.header.len +
		pfcp_sess_rep_req->dnlnk_data_rpt.header.len + 8;

	RTE_LOG_DP(DEBUG, DP, "VS: Sending DDN Request to control-plane for CP_Seid:%lu, PDR_ID:%u\n",
			(*ddn)->cp_seid, (*ddn)->pdr_id);
}

uint8_t
process_pfcp_session_report_req(struct sockaddr_in *peer_addr,
			ddn_t *ddn)
{
	int encoded = 0;
	uint8_t pfcp_msg[250] = {0};

	pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};

	fill_pfcp_sess_rep_req(&pfcp_sess_rep_req, &ddn);

	encoded = encode_pfcp_sess_rpt_req_t(&pfcp_sess_rep_req, pfcp_msg);

	pfcp_header_t *header = (pfcp_header_t *) pfcp_msg;
	header->message_len = htons(encoded - 4);

	if ( pfcp_send(my_sock.sock_fd, pfcp_msg, encoded, peer_addr) < 0 ) {
	                RTE_LOG_DP(DEBUG, DP, "Error sending: %i\n",errno);
	                return -1;
	}

	return 0;
}

/**
 * @brief Data-plane send ddn request to control-plane to activate the bearer.
 *
 * @param session info
 *
 * @return
 *  - 0 SUCESSS
 *  - -1 on failure
 */
static int
send_ddn_request(pdr_info_t *pdr)
{
	ddn_t *ddn = malloc(sizeof(ddn_t));

	ddn->pdr_id = pdr->rule_id;
	memcpy(&ddn->cp_seid, &(pdr->session)->cp_seid, sizeof(uint64_t));
	memcpy(&ddn->up_seid, &(pdr->session)->up_seid, sizeof(uint64_t));

	/* VS: Process and initiate the DDN Request */
	if (process_pfcp_session_report_req(&dest_addr_t, ddn) < 0 ) {
		perror("msgsnd");
		return -1;
	}

	/* Free allocated memory */
	free(ddn);
	++epc_app.dl_params[SGI_PORT_ID].ddn;
	return 0;

}

void
enqueue_dl_pkts(pdr_info_t **pdrs, pfcp_session_datat_t **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask)
{
	int i = 0, rc = 0;
	pdr_info_t *pdr = NULL;
	struct rte_ring *ring = NULL;
	struct pfcp_session_datat_t *si = NULL;

	while (pkts_queue_mask) {
		i = __builtin_ffsll(pkts_queue_mask) - 1;
		RESET_BIT(pkts_queue_mask, i);

		si = sess_info[i];
		pdr = pdrs[i];

		/* Check the action */
		if ((pdr->far)->actions.drop) {
			RTE_LOG_DP(INFO, DP, "Action : DROP :"
					"Dropping pkts for this session:%lu\n",
					(pdr->session)->up_seid);
			rte_pktmbuf_free(pkts[i]);
			continue;
		}

		ring = si->dl_ring;
		if (!ring) {
			ring = allocate_ring();
			if (ring == NULL) {
				RTE_LOG_DP(INFO, DP, "Not enough memory, can't "
						"buffer this session:%lu\n",
						(pdr->session)->up_seid);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}

			si->dl_ring = ring;
			if (si->sess_state == IDLE) {
				if ((pdr->far)->actions.nocp) {
					rc = send_ddn_request(pdr);

					if(rc < 0) {
						RTE_LOG_DP(ERR, DP, "failed to send ddn req  "
								"for this session:%lu\n",
								(pdr->session)->up_seid);

					}

					si->sess_state = IN_PROGRESS;
				}
			}
		}


		if (((pdr->far)->actions.nocp) || ((pdr->far)->actions.buff)) {
			if (rte_ring_enqueue(ring, (void *)pkts[i]) == -ENOBUFS) {
				rte_pktmbuf_free(pkts[i]);
				rte_ring_free(si->dl_ring);
				si->dl_ring = NULL;
				si->sess_state = IDLE;

				RTE_LOG_DP(ERR, DP, "%s::Can't queue pkt- ring full..."
						" Dropping pkt\n", __func__);
			} else {
				RTE_LOG_DP(DEBUG, DP, "ACTIONS : %s :"
						"Buffering the pkts\n",
						(((pdr->far)->actions.nocp != 0) &&
						((pdr->far)->actions.nocp != 0)) ? "Notify to CP, Buffer," :
						(pdr->far)->actions.nocp != 0 ? "Notify to CP" :
						(pdr->far)->actions.nocp != 0 ? "Buffer" :"UNKNOWN");
			}
		}
	}
}
