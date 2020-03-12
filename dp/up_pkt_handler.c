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
#include "clogger.h"
#include "pfcp_set_ie.h"
#include "pfcp_up_sess.h"
#include "pfcp_set_ie.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_util.h"
#include "../cp_dp_api/tcp_client.h"


#ifdef EXTENDED_CDR
uint64_t s1u_non_gtp_pkts_mask;
#endif

#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_east;
extern pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */


extern udp_sock_t my_sock;
extern struct rte_ring *li_dl_ring;
extern struct rte_ring *li_ul_ring;


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

	clLog(clSystemLog, eCLSeverityDebug, "Notification handler resolving the buffer packets, count:%u\n", n);

	for (i = 0; i < n; ++i) {
		buf_pkt = pkts[i];
		key = rte_pktmbuf_mtod(buf_pkt, uint32_t *);

		/* TODO: Add the handling of the session */
		if (app.spgw_cfg == SGWU) {
			data = get_sess_by_teid_entry(*key, NULL, SESS_MODIFY);
			if (data == NULL) {
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"Session entry not found for TEID:%u\n",
									ERR_MSG, *key);
				continue;
			}
		} else {
			data = get_sess_by_ueip_entry(*key, NULL, SESS_MODIFY);
			if (data == NULL) {
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"Session entry not found for UE_IP:"IPV4_ADDR"\n",
									ERR_MSG, IPV4_ADDR_HOST_FORMAT(*key));
				continue;
			}
		}

		rte_ctrlmbuf_free(buf_pkt);
		ring = data->dl_ring;
		if (data->sess_state != CONNECTED) {
			clLog(clSystemLog, eCLSeverityDebug, FORMAT"Update the State to CONNECTED\n",
					ERR_MSG);
			data->sess_state = CONNECTED;
		}

		if (!ring) {
			clLog(clSystemLog, eCLSeverityDebug, FORMAT"No DL Ring is found..!!!\n",
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
				clLog(clSystemLog, eCLSeverityDebug, FORMAT"SAEGWU: Encap the GTPU Pkts...\n",
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
			    clLog(clSystemLog, eCLSeverityCritical, "Something is wrong!!, the "
			            "session still doesnt hv "
			            "enb teid\n");

			if(app.spgw_cfg == SGWU){
				clLog(clSystemLog, eCLSeverityDebug, "Update the Next Hop eNB ipv4 frame info\n");
				/* Update nexthop L3 header*/
				update_enb_info(pkts, num, &pkts_mask, &sess_data[0], &pdr[0]);
			}

			/* Update nexthop L2 header*/
			update_nexthop_info((struct rte_mbuf **)pkts, num, &pkts_mask,
					app.s1u_port, &pdr[0]);


			uint32_t pkt_indx = 0;

#ifdef STATS
			clLog(clSystemLog, eCLSeverityDebug, "Resolved the Buffer packets Pkts:%u\n", ret);
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
			clLog(clSystemLog, eCLSeverityCritical, "Can't put ring back, so free it\n");
			rte_ring_free(ring);
		}
	}

	return 0;
}

int send_usage_report_req(urr_info_t *urr, uint64_t cp_seid, uint32_t trig){

	pfcp_sess_rpt_req_t pfcp_sess_rep_req = {0};
	static uint32_t seq = 1;
	int encoded = 0;
	uint8_t pfcp_msg[1024]= {0};
	memset(pfcp_msg, 0, sizeof(pfcp_msg));

	seq = get_pfcp_sequence_number(PFCP_SESSION_REPORT_REQUEST, seq);

	set_pfcp_seid_header((pfcp_header_t *) &(pfcp_sess_rep_req.header),
		PFCP_SESSION_REPORT_REQUEST, HAS_SEID, seq);

	pfcp_sess_rep_req.header.seid_seqno.has_seid.seid = cp_seid;

	set_sess_report_type(&pfcp_sess_rep_req.report_type);
	pfcp_sess_rep_req.report_type.dldr = 0;
	pfcp_sess_rep_req.report_type.usar = 1;

	fill_sess_rep_req_usage_report(&pfcp_sess_rep_req.usage_report[pfcp_sess_rep_req.usage_report_count++],
																								urr, trig);

	encoded = encode_pfcp_sess_rpt_req_t(&pfcp_sess_rep_req, pfcp_msg);
	pfcp_header_t *pfcp_hdr = (pfcp_header_t *) pfcp_msg;
	pfcp_hdr->message_len = htons(encoded - 4);

	clLog(clSystemLog, eCLSeverityDebug, "sending PFCP_SESSION_REPORT_REQUEST [%d] from dp\n",pfcp_hdr->message_type);
	clLog(clSystemLog, eCLSeverityDebug, "length[%d]\n",htons(pfcp_hdr->message_len));

	if (encoded != 0) {
		if(pfcp_send(my_sock.sock_fd,
					(char *)pfcp_msg,
							 encoded,
	 					&dest_addr_t,
								SENT) < 0) {
			clLog(clSystemLog, eCLSeverityDebug, "Error sending: %i\n",errno);
		}
	}

	pfcp_session_t *sess = NULL;
	sess = get_sess_info_entry(cp_seid, SESS_MODIFY);

	if(sess == NULL) {
               clLog(clSystemLog, eCLSeverityCritical, "Failed to Retrieve Session Info %d::%s\n\n", __LINE__, __func__ );
    }

    process_event_li(sess, NULL, 0, pfcp_msg, encoded,
                     dest_addr_t.sin_addr.s_addr, dest_addr_t.sin_port);
	return 0;
}

/**
 * @brief  : Update the Usage Report structre as per data recived
 * @param  : pkts, pkts recived
 * @param  : n, no of pkts recived
 * @param  : pkts_mask, packet  mask
 * @param  : pdr, structure for pdr info for pkts
 * @return : Returns 0 for succes and -1 failure
 */
static
int update_usage(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
										pdr_info_t **pdr, uint16_t flow){
	for(int i = 0; i < n; i++){
		if (ISSET_BIT(*pkts_mask, i)) {
			if(pdr[i]->urr_count){
				if(flow == DOWNLINK){
					if(!pdr[i]->urr->first_pkt_time)
						pdr[i]->urr->first_pkt_time = current_ntp_timestamp();
					pdr[i]->urr->last_pkt_time = current_ntp_timestamp();
					pdr[i]->urr->dwnlnk_data += rte_pktmbuf_data_len(pkts[i]);
					if((pdr[i]->urr->rept_trigg == VOL_TIME_BASED || pdr[i]->urr->rept_trigg == VOL_BASED) &&
												(pdr[i]->urr->dwnlnk_data >= pdr[i]->urr->vol_thes_dwnlnk)){
						clLog(clSystemLog, eCLSeverityDebug, "downlink Volume threshol reached\n");
						send_usage_report_req(pdr[i]->urr, pdr[i]->session->cp_seid,
																			VOL_BASED);
						pdr[i]->urr->dwnlnk_data = 0;
					}
				}else if(flow == UPLINK){
					pdr[i]->urr->uplnk_data += rte_pktmbuf_data_len(pkts[i]);
					if(!pdr[i]->urr->first_pkt_time)
						pdr[i]->urr->first_pkt_time = current_ntp_timestamp();
					pdr[i]->urr->last_pkt_time = current_ntp_timestamp();
					if((pdr[i]->urr->rept_trigg == VOL_TIME_BASED || pdr[i]->urr->rept_trigg == VOL_BASED) &&
							(pdr[i]->urr->uplnk_data >= pdr[i]->urr->vol_thes_uplnk)){
						clLog(clSystemLog, eCLSeverityDebug, "uplink Volume threshol reached\n");
						send_usage_report_req(pdr[i]->urr, pdr[i]->session->cp_seid,
																			VOL_BASED);
						pdr[i]->urr->uplnk_data = 0;
					}
				}
			}
		}
	}
	return 0;
}
/**
 * @Brief  : Function to enqueue pkts for LI if required
 * @param  : n, no of packets
 * @param  : pkts, mbuf packets
 * @param  : pkts_mask, packet mask
 * @param  : PDR, pointer to pdr session info
 * @param  : flow, direction of packet flow
 * @return : Returns nothing
 */
static void
enqueue_li_pkts(uint32_t n, struct rte_mbuf **pkts,
			 		pdr_info_t **pdr, uint16_t flow){

	uint32_t i;
	for(i =0; i < n; i++){
		if(pkts[i] != NULL && pdr[i] != NULL &&
			pdr[i]->far->dup_parms_cnt > 0){

			li_data_t *li_data;
			li_data = rte_malloc(NULL, sizeof(li_data_t), 0);

			li_data->size = rte_pktmbuf_data_len(pkts[i]);

			uint8_t *tmp_pkt =  rte_pktmbuf_mtod(pkts[i], uint8_t *);
			li_data->pkts = rte_malloc(NULL, li_data->size, 0);
			memcpy(li_data->pkts, tmp_pkt, li_data->size);

			li_data->far = pdr[i]->far;

			if(flow == DOWNLINK){
				if (rte_ring_enqueue(li_dl_ring, (void *)li_data) == -ENOBUFS) {
					clLog(clSystemLog, eCLSeverityCritical, "%s::Can't queue DL LI pkt- ring full..."
																							, __func__);
				}
			}else{
				if (rte_ring_enqueue(li_ul_ring, (void *)li_data) == -ENOBUFS) {
					clLog(clSystemLog, eCLSeverityCritical, "%s::Can't queue UL LI pkt- ring full..."
																						, __func__);
				}
			}
			rte_free(pkts[i]);
		}
	}
}

/**
 * @brief  : Fill pdr details
 * @param  : n, no of pdrs
 * @param  : sess_data, session information
 * @param  : pdr, structure to ne filled
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
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

/**
 * @brief  : Get pdr details
 * @param  : sess_data, session information
 * @param  : pdr, structure to ne filled
 * @param  : precedence, variable to precedence value
 * @param  : n, no of pdrs
 * @param  : pkts_mask, packet mask
 * @param  : pkts_queue_mask, packet queue mask
 * @return : Returns nothing
 */
static void
get_pdr_info(pfcp_session_datat_t **sess_data, pdr_info_t **pdr,
		uint32_t **precedence, uint32_t n, uint64_t *pkts_mask,
		uint64_t *pkts_queue_mask)
{
	uint32_t j = 0;

	for (j = 0; j < n; j++) {
		if (ISSET_BIT(*pkts_mask, j) && precedence[j] != NULL) {
			pdr[j] = get_pdr_node(sess_data[j]->pdrs, *precedence[j]);

			/* Need to check this condition */
			if (pdr[j] == NULL) {
				RESET_BIT(*pkts_mask, j);
				//RESET_BIT(*pkts_queue_mask, j);
				clLog(clSystemLog, eCLSeverityDebug, FORMAT": PDR LKUP Linked List :FAIL!! Precedence "
					":%u\n", ERR_MSG,
					*precedence[j]);
			} else {
				clLog(clSystemLog, eCLSeverityDebug, "PDR LKUP: PDR_ID:%u, FAR_ID:%u\n",
					pdr[j]->rule_id, (pdr[j]->far)->far_id_value);
			}
		} else {
			RESET_BIT(*pkts_mask, j);
		}
	}

	return;
}

/**
 * @brief  : Acl table lookup for sdf rule
 * @param  : pkts, mbuf packets
 * @param  : n, no of packets
 * @param  : pkts_mask, packet mask
 * @param  : sess_data, session information
 * @param  : prcdnc, precedence value
 * @return : Returns nothing
 */
static void
acl_sdf_lookup(struct rte_mbuf **pkts, uint32_t n, uint64_t *pkts_mask,
			pfcp_session_datat_t **sess_data,
			uint32_t **prcdnc)
{
	uint32_t j = 0;
	uint32_t tmp_prcdnc;


	for (j = 0; j < n; j++) {
		if (ISSET_BIT(*pkts_mask, j)) {
			if (!sess_data[j]->acl_table_indx) {
				RESET_BIT(*pkts_mask, j);
				clLog(clSystemLog, eCLSeverityCritical, "Not Found any ACL_Table or SDF Rule for the UL\n");
				continue;
			}
			tmp_prcdnc = 0;
			int index = 0;
			for(uint16_t itr = 0; itr < sess_data[j]->acl_table_count; itr++){
				if(sess_data[j]->acl_table_indx[itr] != 0){
					 prcdnc[j] = sdf_lookup(pkts, j,
											sess_data[j]->acl_table_indx[itr]);
				}
				if(tmp_prcdnc == 0 || (*prcdnc[j] != 0 && *prcdnc[j] < tmp_prcdnc)){
					tmp_prcdnc = *prcdnc[j];
					index = itr;
				}else{
					*prcdnc[j] = tmp_prcdnc;
				}
			}
			if(prcdnc[j] != NULL)
				clLog(clSystemLog, eCLSeverityDebug, "ACL SDF LKUP TABLE Index:%u, prcdnc:%u\n",
													sess_data[j]->acl_table_indx[index], *prcdnc[j]);
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
	struct rte_mbuf *tmp_pkts[n];

	/* DUPLICATING PKTS for LI */
	for(uint8_t itr = 0; itr < n; itr++){
		tmp_pkts[itr] = rte_malloc(NULL, sizeof(struct rte_mbuf), 0);
		if (tmp_pkts[itr] == NULL)
			rte_panic("Out of memory\n");
		rte_memcpy(tmp_pkts[itr], pkts[itr], sizeof(struct rte_mbuf));
	}

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


			update_usage(tmp_pkts, n, &pkts_mask, pdr, UPLINK);

			enqueue_li_pkts(n, tmp_pkts, pdr, UPLINK);

			break;
		}

		case SGWU: {

			ul_sess_info_get(pkts, n, &pkts_mask, &sess_data[0]);

			/* Set next hop IP to S5/S8 PGW port*/
			next_port = app.s5s8_sgwu_port;
			/* Update nexthop L3 header*/
			update_nexts5s8_info(pkts, n, &pkts_mask, &sess_data[0], &pdr[0]);

			update_usage(pkts, n, &pkts_mask, pdr, UPLINK);

			enqueue_li_pkts(n, tmp_pkts, pdr, UPLINK);


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
	struct rte_mbuf *tmp_pkts[n];

	/* DUPLICATING PKTS for LI */
     for(uint8_t itr = 0; itr < n; itr++){
		tmp_pkts[itr] = rte_malloc(NULL, sizeof(struct rte_mbuf), 0);
		if (tmp_pkts[itr] == NULL)
			rte_panic("Out of memory\n");
		rte_memcpy(tmp_pkts[itr], pkts[itr], sizeof(struct rte_mbuf));
	}

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

	enqueue_li_pkts(n, tmp_pkts, pdr, DOWNLINK);
#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	update_usage(pkts, n, &pkts_mask, pdr, DOWNLINK);
	return 0;
}


int
pgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	pdr_info_t *pdr[MAX_BURST_SZ] = {NULL};
	struct rte_mbuf *tmp_pkts[n];

	/* DUPLICATING PKTS for LI */
     for(uint8_t itr = 0; itr < n; itr++){
		tmp_pkts[itr] = rte_malloc(NULL, sizeof(struct rte_mbuf), 0);
		if (tmp_pkts[itr] == NULL)
			rte_panic("Out of memory\n");
		rte_memcpy(tmp_pkts[itr], pkts[itr], sizeof(struct rte_mbuf));
	}

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	gtpu_decap(pkts, n, &pkts_mask);

	/*Apply sdf filters on uplink traffic*/
	filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask, &pdr[0]);

	update_usage(tmp_pkts, n, &pkts_mask, pdr, UPLINK);

	enqueue_li_pkts(n, tmp_pkts, pdr, UPLINK);
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.sgi_port, &pdr[0]);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

/**
 * @brief  : Filter downlink traffic
 * @param  : p, rte pipeline data
 * @param  : pkts, mbuf packets
 * @param  : n, no of packets
 * @param  : wk_index
 * @param  : sess_data, session information
 * @param  : pdr, structure to store pdr info
 * @return : Returns packet mask value
 */
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
	struct rte_mbuf *tmp_pkts[n];


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
			update_usage(pkts, n, &pkts_mask, pdr, DOWNLINK);

			break;

		case PGWU:

			/*Filter downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, &sess_data[0], &pdr[0]);

			/* Encap for S5/S8*/
			gtpu_encap(&pdr[0], &sess_data[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Set next port to S5/S8*/
			next_port = app.s5s8_pgwu_port;
			update_usage(pkts, n, &pkts_mask, pdr, DOWNLINK);

			break;

		default:
			break;
	}

	update_nexthop_info(pkts, n, &pkts_mask, next_port, &pdr[0]);

	/* DUPLICATING PKTS for LI */
	for(uint8_t itr = 0; itr < n; itr++){
		tmp_pkts[itr] = rte_malloc(NULL, sizeof(struct rte_mbuf), 0);
		if (tmp_pkts[itr] == NULL)
			rte_panic("Out of memory\n");
		rte_memcpy(tmp_pkts[itr], pkts[itr], sizeof(struct rte_mbuf));
	}

	enqueue_li_pkts(n ,tmp_pkts, pdr, DOWNLINK);

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */

	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
	return 0;
}
