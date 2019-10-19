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

/**
 * pkt_handler.c: Main processing for uplink and downlink packets.
 * Also process any notification coming from interface core for
 * messages from CP for modifications to an active session.
 * This is done by the worker core in the pipeline.
 */

#include <unistd.h>
#include <locale.h>

#include "up_acl.h"
#include "up_main.h"
#include "pfcp_up_llist.h"
#include "pfcp_up_struct.h"

#ifdef EXTENDED_CDR
uint64_t s1u_non_gtp_pkts_mask;
#endif

#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_east;
extern pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */

int
notification_handler(struct rte_mbuf **pkts,
	uint32_t n)
{
	uint16_t tx_cnt = 0;
	unsigned int *ring_entry = NULL;
	struct rte_ring *ring = NULL;
	struct rte_mbuf *buf_pkt = NULL;
	pfcp_session_datat_t *data = NULL;
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_info[MAX_BURST_SZ] = {NULL};
	uint64_t pkts_mask = 0, pkts_queue_mask = 0;
	uint32_t *key = NULL;
	unsigned int ret = 32, num = 32, i;

	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	RTE_LOG_DP(DEBUG, DP, "Notification handler resolved the buffer packets\n");

	for (i = 0; i < n; ++i) {
		buf_pkt = pkts[i];
		key = rte_pktmbuf_mtod(buf_pkt, uint32_t *);

		/* TODO: Add the handling of the session */
		if (app.spgw_cfg == SGWU) {
			data = get_sess_by_teid_entry(*key, NULL, SESS_MODIFY);
			if (data == NULL) {
				RTE_LOG_DP(DEBUG, DP, FORMAT"Session entry not found for TEID:%u\n",
									ERR_MSG, *key);
				continue;
			}
		} else {
			data = get_sess_by_ueip_entry(*key, NULL, SESS_MODIFY);
			if (data == NULL) {
				RTE_LOG_DP(DEBUG, DP, FORMAT"Session entry not found for UE_IP:"IPV4_ADDR"\n",
									ERR_MSG, IPV4_ADDR_HOST_FORMAT(*key));
				continue;
			}
		}

		rte_ctrlmbuf_free(buf_pkt);
		ring = data->dl_ring;
		if (data->sess_state != CONNECTED) {
			RTE_LOG_DP(DEBUG, DP, FORMAT"Update the State to CONNECTED\n",
					ERR_MSG);
			data->sess_state = CONNECTED;
		}

		if (!ring) {
			RTE_LOG_DP(DEBUG, DP, FORMAT"No DL Ring is found..!!!\n",
					ERR_MSG);
			continue; /* No dl ring*/
		}

		/* de-queue this ring and send the downlink pkts*/
		while (ret) {
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)pkts, num, ring_entry);
			pkts_mask = (1 << ret) - 1;

			for (i = 0; i < ret; ++i)
				sess_info[i] = data;

			for (i = 0; i < ret; ++i)
				pdr[i] = sess_info[i]->pdrs;

			if(app.spgw_cfg == SAEGWU) {
				RTE_LOG_DP(DEBUG, DP, FORMAT"SAEGWU: Encap the GTPU Pkts...\n", 
						ERR_MSG);
				/* Encap GTPU header*/
				gtpu_encap(&pdr[0], &sess_info[0], (struct rte_mbuf **)pkts, ret,
					&pkts_mask, &pkts_queue_mask);
			} else {
				/* Get downlink session info */
				dl_get_sess_info((struct rte_mbuf **)pkts, ret, &pkts_mask,
						&sess_data[0],
						&pkts_queue_mask);
			}

			if (pkts_queue_mask != 0)
			    RTE_LOG_DP(ERR, DP, "Something is wrong!!, the "
			            "session still doesnt hv "
			            "enb teid\n");

			if(app.spgw_cfg == SGWU){
				RTE_LOG_DP(DEBUG, DP, "Update the Next Hop eNB ipv4 frame info\n");
				/* Update nexthop L3 header*/
				update_enb_info(pkts, num, &pkts_mask, &sess_data[0], &pdr[0]);
			}

			/* Update nexthop L2 header*/
			update_nexthop_info((struct rte_mbuf **)pkts, num, &pkts_mask,
					app.s1u_port, &pdr[0]);


			uint32_t pkt_indx = 0;

#ifdef STATS
			RTE_LOG_DP(DEBUG, DP, "Resolved the Buffer packets Pkts:%u\n", ret);
			epc_app.dl_params[SGI_PORT_ID].pkts_in += ret;
			epc_app.dl_params[SGI_PORT_ID].ddn_buf_pkts -= ret;
#endif /* STATS */
			while (ret) {
				uint16_t pkt_cnt = PKT_BURST_SZ;

				if (ret < PKT_BURST_SZ)
					pkt_cnt = ret;

				tx_cnt = rte_eth_tx_burst(S1U_PORT_ID,
						0, &pkts[pkt_indx], pkt_cnt);
				ret -= tx_cnt;
				pkt_indx += tx_cnt;
			}
		}

		if (rte_ring_enqueue(dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "Can't put ring back, so free it\n");
			rte_ring_free(ring);
		}
	}

	return 0;
}

static void
fill_pdr_info(uint32_t n, pfcp_session_datat_t **sess_data,
				pdr_info_t **pdr, uint64_t *pkts_queue_mask)
{
	uint32_t itr = 0;

	for (itr = 0; itr < n; itr++) {
		if (ISSET_BIT(*pkts_queue_mask, itr)) {
			/* Fill the PDR info form the session data */
			pdr[itr] = sess_data[itr]->pdrs;
		}
	}

	return;
}

static void
get_pdr_info(pfcp_session_datat_t **sess_data, pdr_info_t **pdr,
		uint32_t **precedence, uint32_t n, uint64_t *pkts_mask,
		uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;

	for (j = 0; j < n; j++) {
		if (ISSET_BIT(*pkts_mask, j)) {
			pdr[j] = get_pdr_node(sess_data[j]->pdrs, *precedence[j]);

			/* Need to check this condition */
			if (pdr[j] == NULL) {
				RESET_BIT(*pkts_mask, j);
				//RESET_BIT(*pkts_queue_mask, j);
				RTE_LOG_DP(DEBUG, DP, FORMAT": PDR LKUP Linked List :FAIL!! Precedence "
					":%u\n", ERR_MSG,
					*precedence[j]);
			} else {
				RTE_LOG_DP(DEBUG, DP, "PDR LKUP: PDR_ID:%u, FAR_ID:%u\n",
					pdr[j]->rule_id, (pdr[j]->far)->far_id_value);
			}
		}

		//} else {
		//	RESET_BIT(*pkts_queue_mask, j);
		//}
	}

	return;
}

static void
acl_sdf_lookup(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
			pfcp_session_datat_t **sess_data,
			uint32_t **prcdnc)
{
	uint32_t j = 0;

	for (j = 0; j < n; j++) {
		if (ISSET_BIT(*pkts_mask, j)) {
			if (!sess_data[j]->acl_table_indx) {
				RESET_BIT(*pkts_mask, j);
				RTE_LOG_DP(ERR, DP, "Not Found any ACL_Table or SDF Rule for the UL\n");
				continue;
			}

			prcdnc[j] = sdf_lookup(pkts, j,
				sess_data[j]->acl_table_indx);
			RTE_LOG_DP(DEBUG, DP, "ACL SDF LKUP TABLE Index:%u, prcdnc:%u\n",
						sess_data[j]->acl_table_indx, *prcdnc[j]);
		}
	}
	return;
}

void
filter_ul_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, uint64_t *pkts_mask, pdr_info_t **pdr)
{
	uint64_t pkts_queue_mask = 0;
	uint32_t *precedence[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	ul_sess_info_get(pkts, n, pkts_mask, &sess_data[0]);

	acl_sdf_lookup(pkts, n, pkts_mask, &sess_data[0], &precedence[0]);

	get_pdr_info(&sess_data[0], &pdr[0], &precedence[0], n, pkts_mask,
			&pkts_queue_mask);

	/* QER Gating */
	qer_gating(&pdr[0], n, pkts_mask, &pkts_queue_mask, UPLINK);

	return;
}

int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
	uint32_t next_port = 0; //GCC_Security flag
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);


	switch(app.spgw_cfg) {
		case SAEGWU: {
			/* Decap GTPU and update meta data*/
			gtpu_decap(pkts, n, &pkts_mask);

			/*Apply sdf filters on uplink traffic*/
			filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask, &pdr[0]);

			/*Set next hop directly to SGi*/
			next_port = app.sgi_port;

			break;
		}

		case SGWU: {
			ul_sess_info_get(pkts, n, &pkts_mask, &sess_data[0]);

			/* Set next hop IP to S5/S8 PGW port*/
			next_port = app.s5s8_sgwu_port;

			/* Update nexthop L3 header*/
			update_nexts5s8_info(pkts, n, &pkts_mask, &sess_data[0], &pdr[0]);

			break;
		}

		default:
			break;
	}

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &pdr[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */


	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

int
sgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n, int wk_index)
{
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	uint64_t pkts_queue_mask = 0;

	pkts_mask = (~0LLU) >> (64 - n);

	/* Get downlink session info */
	dl_get_sess_info(pkts, n, &pkts_mask, &sess_data[0],
			&pkts_queue_mask);

	/* En-queue DL pkts */
	if (pkts_queue_mask) {
		/* Fill the PDR info for session data */
		fill_pdr_info(n, &sess_data[0], &pdr[0], &pkts_queue_mask);
		rte_pipeline_ah_packet_hijack(p, pkts_queue_mask);
		enqueue_dl_pkts(&pdr[0], &sess_data[0], pkts, pkts_queue_mask);
	}

	/* Update nexthop L3 header*/
	update_enb_info(pkts, n, &pkts_mask, &sess_data[0], &pdr[0]);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.s1u_port, &pdr[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}


int
pgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	gtpu_decap(pkts, n, &pkts_mask);

	/*Apply sdf filters on uplink traffic*/
	filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask, &pdr[0]);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.sgi_port, &pdr[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

static uint64_t
filter_dl_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index,  pfcp_session_datat_t **sess_data, pdr_info_t **pdr)
{
	uint32_t *precedence[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask = (~0LLU) >> (64 - n);
	uint64_t pkts_queue_mask = 0;

	dl_sess_info_get(pkts, n, &pkts_mask, &sess_data[0], &pkts_queue_mask);

	acl_sdf_lookup(pkts, n, &pkts_mask, &sess_data[0], &precedence[0]);

	get_pdr_info(&sess_data[0], &pdr[0], &precedence[0], n, &pkts_mask,
			&pkts_queue_mask);

	/* QER Gating */
	qer_gating(&pdr[0], n, &pkts_mask, &pkts_queue_mask, DOWNLINK);

#ifdef HYPERSCAN_DPI
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, &pkts_mask);
#endif /* HYPERSCAN_DPI */

	return pkts_mask;
}

/**
 * Process Downlink traffic: sdf and adc filter, metering, charging and encap gtpu.
 * Update adc hash if dns reply is found with ip addresses.
 */
int
sgi_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{

	uint32_t next_port = 0; //GCC_Security flag
	uint64_t pkts_mask = 0;
	uint64_t pkts_queue_mask = 0;
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	pfcp_session_datat_t *sess_data[MAX_BURST_SZ] = {NULL};

	pkts_mask = (~0LLU) >> (64 - n);

	/**
	 * TODO : filter_dl_traffic and gtpu_encap can be called irrespective
	 *      of app configuration.
	 *      Do we need enqueue_dl_pkts and hijack ?
	 */
	switch(app.spgw_cfg) {
		case SAEGWU:
			/* Filter Downlink traffic. Apply sdf*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, &sess_data[0], &pdr[0]);

			/* Encap GTPU header*/
			gtpu_encap(&pdr[0], &sess_data[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Next port is S1U for SPGW*/
			next_port = app.s1u_port;

			/* En-queue DL pkts */
			if (pkts_queue_mask) {
				rte_pipeline_ah_packet_hijack(p, pkts_queue_mask);
				enqueue_dl_pkts(&pdr[0], &sess_data[0], pkts, pkts_queue_mask);
			}
			break;

		case PGWU:
			/*Filter downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, &sess_data[0], &pdr[0]);

			/* Encap for S5/S8*/
			gtpu_encap(&pdr[0], &sess_data[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Set next port to S5/S8*/
			next_port = app.s5s8_pgwu_port;
			break;

		default:
			break;
	}

	update_nexthop_info(pkts, n, &pkts_mask, next_port, &pdr[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
	return 0;
}
