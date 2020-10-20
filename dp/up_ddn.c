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

#include <rte_errno.h>

#include "gtpu.h"
#include "up_main.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "gw_adapter.h"
#include "interface.h"
#include "pfcp_messages_encoder.h"

extern int clSystemLog;

struct
rte_ring *allocate_ring(unsigned int dl_ring_size)
{
	char name[32];
	struct rte_ring *dl_ring = NULL;
	unsigned dl_core = rte_lcore_id();

	if ((DL_RING_CONTAINER_SIZE > num_dl_rings) &&
			(rte_ring_count(dl_ring_container) < DL_RING_CONTAINER_SIZE)) {

		snprintf(name, sizeof(name), "dl_pkt_ring_%"PRIu32"_%u",
				num_dl_rings, dl_core);

		struct rte_ring *tmp =
			rte_ring_create(name, rte_align32pow2(dl_ring_size),
					rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
		if (tmp) {
			int ret = rte_ring_enqueue(dl_ring_container, tmp);
			if (ret == ENOBUFS) {
				clLog(clSystemLog, eCLSeverityDebug,
						LOG_FORMAT"Cannot hold more dl rings\n", LOG_VALUE);
				rte_ring_free(tmp);
				return NULL;
			}

			dl_ring = tmp;
			num_dl_rings++;
		} else {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Couldnt create %s for DL PKTS %s\n",
					LOG_VALUE, name, rte_strerror(rte_errno));
			if (rte_errno == EEXIST)
				num_dl_rings++;
		}
	}

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

	clLog(clSystemLog, eCLSeverityInfo,
		LOG_FORMAT"DDN ACK processed\n", LOG_VALUE);

	return 0;
}

/**
 * @brief  : Set values in downlink data service info ie
 * @param  : dl, structure to be filled
 * @return : Returns nothing
 */
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

/**
 * @brief  : Set values in downlink data report ie
 * @param  : dl, structure to be filled
 * @return : Returns nothing
 */
static void
set_dldr_ie(pfcp_dnlnk_data_rpt_ie_t *dl)
{
	dl->pdr_id_count = 1;
	pfcp_set_ie_header(&(dl->header), IE_DNLNK_DATA_RPT, 6);
	set_pdr_id(dl->pdr_id, 0);

}


/**
 * @brief  : Fill pfcp session report request
 * @param  : pfcp_sess_rep_req, structure ti be filled
 * @param  : ddn, ddn information
 * @return : Returns nothing
 */
static void
fill_pfcp_sess_rep_req(pfcp_sess_rpt_req_t *pfcp_sess_rep_req,
			ddn_t **ddn)
{
	static uint32_t seq = 1;

	memset(pfcp_sess_rep_req, 0, sizeof(pfcp_sess_rpt_req_t));

	seq = get_pfcp_sequence_number(PFCP_SESSION_REPORT_REQUEST, seq);
	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_req->header),
		PFCP_SESSION_REPORT_REQUEST, HAS_SEID, seq, NO_CP_MODE_REQUIRED);

	pfcp_sess_rep_req->header.seid_seqno.has_seid.seid = (*ddn)->cp_seid;

	set_sess_report_type(&pfcp_sess_rep_req->report_type);

	/* Need to Implement handling of other IE's when Rules implementation is done  */
	if (pfcp_sess_rep_req->report_type.dldr == 1) {
		set_dldr_ie(&pfcp_sess_rep_req->dnlnk_data_rpt);
		pfcp_sess_rep_req->dnlnk_data_rpt.pdr_id[0].rule_id = (*ddn)->pdr_id;
	}

	pfcp_sess_rep_req->header.message_len = pfcp_sess_rep_req->report_type.header.len +
		pfcp_sess_rep_req->dnlnk_data_rpt.header.len + 8;

	clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"VS:- Sending DDN Request to Control Plane for CP Seid: %lu, PDR_ID:%u\n",
		LOG_VALUE, (*ddn)->cp_seid, (*ddn)->pdr_id);
}

uint8_t
process_pfcp_session_report_req(peer_addr_t peer_addr, ddn_t *ddn)
{
	int encoded = 0;
	uint8_t pfcp_msg[250] = {0};

	pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};

	fill_pfcp_sess_rep_req(&pfcp_sess_rep_req, &ddn);

	encoded = encode_pfcp_sess_rpt_req_t(&pfcp_sess_rep_req, pfcp_msg);

	if ( pfcp_send(my_sock.sock_fd, my_sock.sock_fd_v6, pfcp_msg, encoded, peer_addr, SENT) < 0 ) {
		clLog(clSystemLog, eCLSeverityDebug,
		LOG_FORMAT"Error in Sending PFCP SESSION REPORT REQ %i\n",
		LOG_VALUE, errno);
		return -1;
	}
	clLog(clSystemLog, eCLSeverityDebug,
			LOG_FORMAT"Sends Report Request message to CP:"IPV4_ADDR" for trigger DDN\n",
			LOG_VALUE, IPV4_ADDR_HOST_FORMAT(peer_addr.ipv4.sin_addr.s_addr));

	return 0;
}

/**
 * @brief  : Data-plane send ddn request to control-plane to activate the bearer.
 * @param  : pdr, pdr information
 * @return : Returns 0 in case of success , -1 otherwise
 */
static int
send_ddn_request(pdr_info_t *pdr)
{
	ddn_t *ddn = malloc(sizeof(ddn_t));

	ddn->pdr_id = pdr->rule_id;
	memcpy(&ddn->cp_seid, &(pdr->session)->cp_seid, sizeof(uint64_t));
	memcpy(&ddn->up_seid, &(pdr->session)->up_seid, sizeof(uint64_t));

	/* VS: Process and initiate the DDN Request */
	if (process_pfcp_session_report_req((pdr->session)->cp_ip, ddn) < 0 ) {
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

		if (pdr == NULL) {
			clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"DROPPED Packet, PDR is NULL\n", LOG_VALUE);
			rte_pktmbuf_free(pkts[i]);
			continue;
		}

		/* Check the action */
		if ((pdr->far)->actions.drop) {
			clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"Action : DROP :"
					"Dropping pkts for this Session:%lu\n", LOG_VALUE,
					(pdr->session)->up_seid);
			rte_pktmbuf_free(pkts[i]);
			continue;
		}

		/* Decarding the END MARKER for the IDEL Session */
		struct ether_hdr *ether = NULL;
		struct gtpu_hdr *gtpu_hdr = NULL;

		/* Get the ether header info */
		ether = (struct ether_hdr *)rte_pktmbuf_mtod(pkts[i], uint8_t *);
		/* Handle the IPv4 packets */
		if (ether && (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv4))) {
			gtpu_hdr = get_mtogtpu(pkts[i]);
			if (gtpu_hdr && (gtpu_hdr->msgtype == GTP_GEMR)) {
				clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"IPv4 Session State : IDLE"
						"Dropping pkts the endmarker pkts for this Session:%lu\n", LOG_VALUE,
						(pdr->session)->up_seid);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}
		} else if (ether && (ether->ether_type == rte_cpu_to_be_16(ETHER_TYPE_IPv6))) {
			gtpu_hdr = get_mtogtpu_v6(pkts[i]);
			if (gtpu_hdr && (gtpu_hdr->msgtype == GTP_GEMR)) {
				clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"IPv6 Session State : IDLE"
						"Dropping pkts the endmarker pkts for this Session:%lu\n", LOG_VALUE,
						(pdr->session)->up_seid);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}
		}

		ring = si->dl_ring;
		if ((!ring) /* && ((pdr->far)->actions.buff) */) {
			ring = allocate_ring((pdr->session)->bar.dl_buf_suggstd_pckts_cnt.pckt_cnt_val);
			if (ring == NULL) {
				clLog(clSystemLog, eCLSeverityInfo, LOG_FORMAT"Not enough memory, can't "
					"buffer this Session: %lu\n", LOG_VALUE,
					(pdr->session)->up_seid);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}

			si->dl_ring = ring;
			if (si->sess_state == IDLE) {
				if ((pdr->far)->actions.nocp) {
					rc = send_ddn_request(pdr);

					if(rc < 0) {
						clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to send ddn req for session: %lu\n",
							LOG_VALUE, (pdr->session)->up_seid);

					}

					si->sess_state = IN_PROGRESS;
				}
			}
		}


		if (((pdr->far)->actions.nocp) || ((pdr->far)->actions.buff) || ((pdr->far)->actions.forw)) {

			if (rte_ring_enqueue(ring, (void *)pkts[i]) == -ENOBUFS) {

				rte_pktmbuf_free(pkts[i]);
				rte_ring_free(si->dl_ring);
				si->dl_ring = NULL;
				si->sess_state = IDLE;

				clLog(clSystemLog, eCLSeverityCritical,
					LOG_FORMAT"Can't queue pkt ring full"
					" So Dropping pkt\n", LOG_VALUE);

				/* Send PFCP Session Report Response */
				rc = send_ddn_request(pdr);
				if(rc < 0) {
					clLog(clSystemLog, eCLSeverityCritical,
							LOG_FORMAT"Failed to send ddn req for session: %lu\n",
							LOG_VALUE, (pdr->session)->up_seid);

				}

			} else {
				clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"ACTIONS : %s :"
						"Buffering the PKTS\n", LOG_VALUE,
						(((pdr->far)->actions.nocp != 0) &&
						((pdr->far)->actions.nocp != 0)) ? "Notify to CP, Buffer," :
						(pdr->far)->actions.nocp != 0 ? "Notify to CP" :
						(pdr->far)->actions.nocp != 0 ? "Buffer" :"UNKNOWN");
			}
		}
	}
}
