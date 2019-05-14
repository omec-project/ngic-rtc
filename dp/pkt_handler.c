/*
 * Copyright (c) 2017 Intel Corporation
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

#include "main.h"
#include "acl_dp.h"
#include "interface.h"

#ifdef EXTENDED_CDR
uint64_t s1u_non_gtp_pkts_mask;
#endif

#ifdef PCAP_GEN
extern pcap_dumper_t *pcap_dumper_east;
extern pcap_dumper_t *pcap_dumper_west;
#endif /* PCAP_GEN */

#ifndef NGCORE_SHRINK
#ifdef TIMER_STATS
extern uint8_t print_ul_perf_stats;
extern uint8_t print_dl_perf_stats;
#ifdef AUTO_ANALYSIS
extern struct dl_performance_stats dl_perf_stats;
extern struct ul_performance_stats ul_perf_stats;
extern int dl_ignore_cnt;
extern int ul_ignore_cnt;
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
#endif

#ifdef DP_DDN
#ifdef NGCORE_SHRINK

int
notification_handler(struct rte_mbuf **pkts,
	uint32_t n)
#else
int
notification_handler(struct rte_pipeline *p,
	struct rte_mbuf **pkts,
	uint32_t n,
	void *arg)

#endif /* NGCORE_SHRINK */
{
	uint16_t tx_cnt;
	struct rte_mbuf *buf_pkt = NULL;
	struct rte_ring *ring;
	struct dp_session_info *data;
	struct dp_session_info *sess_info[MAX_BURST_SZ];
	unsigned int *ring_entry = NULL;
	uint64_t pkt_mask = 0, pkts_queue_mask = 0;
	uint64_t *sess = NULL;
	unsigned int ret = 32, num = 32, i;

#ifndef NGCORE_SHRINK

	int wk_index = (uintptr_t)arg;
	struct epc_worker_params *wk_params = &epc_app.worker[wk_index];

#endif /* NGCORE_SHRINK */

	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ];

	for (i = 0; i < n; ++i) {
		buf_pkt = pkts[i];
		sess = rte_pktmbuf_mtod(buf_pkt, uint64_t *);
		data = get_session_data(*sess, 1);

		if (data == NULL)
			continue;

		rte_ctrlmbuf_free(buf_pkt);
		ring = data->dl_ring;
		if (data->sess_state != CONNECTED)
			data->sess_state = CONNECTED;

		if (!ring)
			continue; /* No dl ring*/
		/* de-queue this ring and send the downlink pkts*/
		while (ret) {
			ret = rte_ring_sc_dequeue_burst(ring,
					(void **)pkts, num, ring_entry);
			pkt_mask = (1 << ret) - 1;
			for (i = 0; i < ret; ++i)
				sess_info[i] = data;
			gtpu_encap(&sess_info[0], (struct rte_mbuf **)pkts, ret,
					&pkt_mask, &pkts_queue_mask);
			if (pkts_queue_mask != 0)
				RTE_LOG_DP(ERR, DP, "Something is wrong!!, the "
						"session still doesnt hv "
						"enb teid\n");
			update_nexthop_info((struct rte_mbuf **)pkts, num,
					&pkt_mask, app.s1u_port, &sdf_info[0]);

#ifndef NGCORE_SHRINK
			for (i = 0; i < ret; ++i)
				rte_pipeline_port_out_packet_insert(
					epc_app.worker[wk_index].pipeline,
					app.s1u_port, pkts[i]);
#else
			uint32_t pkt_indx = 0;

#ifdef STATS
			epc_app.dl_params[SGI_PORT_ID].pkts_in += ret;
			epc_app.dl_params[SGI_PORT_ID].ddn -= ret;
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
#endif /* NGCORE_SHRINK */

		}

#ifdef NGCORE_SHRINK

		if (rte_ring_enqueue(dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "Can't put ring back, so free it\n");
			rte_ring_free(ring);
		}
#else
		if (rte_ring_enqueue(wk_params->dl_ring_container, ring) ==
				ENOBUFS) {
			RTE_LOG_DP(ERR, DP, "Can't put ring back, so free it\n");
			rte_ring_free(ring);
		}
#endif /* NGCORE_SHRINK */
	}

	return 0;
}
#endif /* DP_DDN*/

void
filter_ul_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, uint64_t *pkts_mask)
{
	uint32_t *sdf_rule_id = NULL;
	struct pcc_id_precedence sdf_info[MAX_BURST_SZ];
	struct pcc_id_precedence adc_info[MAX_BURST_SZ];
	void *adc_ue_info[MAX_BURST_SZ] = {NULL};
	struct dp_sdf_per_bearer_info *sdf_bearer_info[MAX_BURST_SZ] = {NULL};
	uint32_t *adc_rule_a = NULL;
	uint32_t adc_rule_b[MAX_BURST_SZ];
	uint32_t pcc_rule_id[MAX_BURST_SZ];
#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
	/* increment burst counter for every pkt busrt received */
	++ul_perf_stats.no_of_bursts;
	/* Total no. of pkts recvd = cumm_pkt_cnt */
	ul_perf_stats.cumm_pkt_cnt += n;
#endif /* AUTO_ANALYSIS */
	_timer_t _init_time = 0;
	TIMER_GET_CURRENT_TP(_init_time);
	sdf_rule_id = sdf_lookup(pkts, n);
#ifndef AUTO_ANALYSIS
	ul_stat_info.sdf_acl_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[0] = sdf_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[0], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info[0]);

#ifndef AUTO_ANALYSIS
	ul_stat_info.sdf_pcc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[1] = pcc_entry_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[1], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */
	TIMER_GET_CURRENT_TP(_init_time);
	/* ADC table lookup*/
	adc_rule_a = adc_ul_lookup(pkts, n);
#ifndef AUTO_ANALYSIS
	ul_stat_info.adc_acl_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[2] = adc_ul_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[2], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], UL_FLOW);
#ifndef AUTO_ANALYSIS
	ul_stat_info.adc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[3] = adc_hash_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[3], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);
#ifndef AUTO_ANALYSIS
	ul_stat_info.update_adc_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[4] = update_adc_rid */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[4], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	/* get ADC UE info struct*/
	adc_ue_info_get(pkts, n, adc_rule_a, &adc_ue_info[0], UL_FLOW);
#ifndef AUTO_ANALYSIS
	ul_stat_info.ue_info_lkup_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[5] = adc_ue_info_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[5], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info[0]);
#ifndef AUTO_ANALYSIS
	ul_stat_info.adc_pcc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[6] = pcc_entry_lookup */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[6], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	pcc_gating(&sdf_info[0], &adc_info[0], n, pkts_mask, &pcc_rule_id[0]);

#ifndef AUTO_ANALYSIS
	ul_stat_info.pcc_gating_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[7] = pcc_gating */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[7], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	ul_sess_info_get(pkts, n, pkts_mask, &sdf_bearer_info[0]);
#ifndef AUTO_ANALYSIS
	ul_stat_info.ul_sess_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[8] = ul_sess_hash */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[8], _init_time, n, 0);
#endif /* AUTO_ANALYSIS */

  /*update_sdf_cdr(&adc_ue_info[0], &sdf_bearer_info[0], pkts, n,
  		&adc_pkts_mask, pkts_mask, UL_FLOW);*/
	update_pcc_cdr(&sdf_bearer_info[0], pkts, n, pkts_mask,
			&pcc_rule_id[0], UL_FLOW);
#else
	sdf_rule_id = sdf_lookup(pkts, n);

	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info[0]);

	/* ADC table lookup*/
	adc_rule_a = adc_ul_lookup(pkts, n);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], UL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	/* get ADC UE info struct*/
	adc_ue_info_get(pkts, n, adc_rule_a, &adc_ue_info[0], UL_FLOW);

	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info[0]);

	pcc_gating(&sdf_info[0], &adc_info[0], n, pkts_mask, &pcc_rule_id[0]);

	ul_sess_info_get(pkts, n, pkts_mask, &sdf_bearer_info[0]);

  /*update_sdf_cdr(&adc_ue_info[0], &sdf_bearer_info[0], pkts, n,
  		&adc_pkts_mask, pkts_mask, UL_FLOW);*/
	update_pcc_cdr(&sdf_bearer_info[0], pkts, n, pkts_mask,
			&pcc_rule_id[0], UL_FLOW);
#endif
#ifdef EXTENDED_CDR
	update_extended_cdr(pkts, n, pkts_mask, &s1u_non_gtp_pkts_mask, &pcc_rule_id[0],
			UL_FLOW);
#endif /* EXTENDED_CDR */

	return;
}

int
s1u_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index)
{
#ifdef TIMER_STATS
	/* enable printing UL perf stats */
	print_ul_perf_stats = 1;
	_timer_t _s1u_init_time = 0;
	TIMER_GET_CURRENT_TP(_s1u_init_time);
#endif /* TIMER_STATS */
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ] = {NULL};
	uint32_t next_port = 0; //GCC_Security flag

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);
#ifdef EXTENDED_CDR
	s1u_non_gtp_pkts_mask = (~0LLU) >> (64 - n);
#endif

	switch(app.spgw_cfg) {
		case SAEGWU: {
#ifdef TIMER_STATS
			_timer_t _init_time = 0;
			TIMER_GET_CURRENT_TP(_init_time);
#endif /*TIMER_STATS */
			/* Decap GTPU and update meta data*/
			gtpu_decap(pkts, n, &pkts_mask);
#ifdef TIMER_STATS
#ifndef AUTO_ANALYSIS
			ul_stat_info.gtp_decap_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
			/* calculate min time, max time, min_burst_sz, max_burst_sz
			 * ul_perf_stats.op_time[9] = gtpu_decap */
			SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[9], _init_time, n, 0);
#endif /* AUTO_ANAYSIS */
#endif /*TIMER_STATS */
#ifdef EXTENDED_CDR
			s1u_non_gtp_pkts_mask = pkts_mask;
#endif

			/*Apply adc, sdf, pcc filters on uplink traffic*/
			filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask);

			/*Set next hop directly to SGi*/
			next_port = app.sgi_port;
			break;
		}

		case SGWU: {
			ul_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0]);

			/* Set next hop IP to S5/S8 PGW port*/
			next_port = app.s5s8_sgwu_port;
			update_nexts5s8_info(pkts, n, &pkts_mask, &sdf_info[0]);
			break;
		}

		default:
			break;
	}
#ifdef TIMER_STATS
	_timer_t _init_time = 0;
	TIMER_GET_CURRENT_TP(_init_time);
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);
#ifndef AUTO_ANALYSIS
	ul_stat_info.retrive_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * ul_perf_stats.op_time[10] = arp_hash */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[10], _init_time, n, 0);
	/* Decrement ul_ignore cnt by 1 */
	++ul_ignore_cnt;
#endif /* AUTO_ANALYSIS */
#else
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);
#endif /* TIMER_STATS */

#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */


	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
#ifdef TIMER_STATS
#ifndef AUTO_ANALYSIS
	ul_stat_info.s1u_handler_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[11] = s1u_time */
	SET_PERF_MAX_MIN_TIME(ul_perf_stats.op_time[11], _s1u_init_time, n, 0);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
	return 0;
}

int
sgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ] = {NULL};
	struct dp_session_info *si[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	/* Get downlink session info */
	dl_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0], &si[0]);

	update_enb_info(pkts, n, &pkts_mask, &sdf_info[0]);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.s1u_port, &sdf_info[0]);

#ifdef PCAP_GEN
	//dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

int
pgw_s5_s8_pkt_handler(struct rte_pipeline *p, struct rte_mbuf **pkts,
		uint32_t n,	int wk_index)
{
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ] = {NULL};

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	gtpu_decap(pkts, n, &pkts_mask);

	/*Apply adc, sdf, pcc filters on uplink traffic*/
	filter_ul_traffic(p, pkts, n, wk_index, &pkts_mask);

	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, app.sgi_port, &sdf_info[0]);

#ifdef PCAP_GEN
	//dump_pcap(pkts, n, pcap_dumper_west);
#endif /* PCAP_GEN */
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);

	return 0;
}

static uint64_t
filter_dl_traffic(struct rte_pipeline *p, struct rte_mbuf **pkts, uint32_t n,
		int wk_index, struct dp_sdf_per_bearer_info *sdf_info[],
		struct dp_session_info *si[])
{
	uint32_t *sdf_rule_id = NULL;
	struct pcc_id_precedence sdf_info_dl[MAX_BURST_SZ];
	struct pcc_id_precedence adc_info_dl[MAX_BURST_SZ];

	uint64_t pkts_mask = (~0LLU) >> (64 - n);

#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
	/* increment burst counter for every pkt busrt received */
	++dl_perf_stats.no_of_bursts;
	/* Total no. of pkts recvd = cumm_pkt_cnt */
	dl_perf_stats.cumm_pkt_cnt += n;
#endif /* AUTO_ANALYSIS */
	_timer_t _init_time = 0;

	TIMER_GET_CURRENT_TP(_init_time);
	sdf_rule_id = sdf_lookup(pkts, n);
#ifndef AUTO_ANALYSIS
	dl_stat_info.sdf_acl_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[0] = sdf_acl */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[0], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info_dl[0]);
#ifndef AUTO_ANALYSIS
	dl_stat_info.sdf_pcc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[1] = sdf_pcc_hash */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[1], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	uint32_t *adc_rule_a = NULL;
	uint32_t adc_rule_b[MAX_BURST_SZ];
	uint32_t pcc_rule_id[MAX_BURST_SZ];

	/* ADC table lookup*/
	TIMER_GET_CURRENT_TP(_init_time);
	adc_rule_a = adc_dl_lookup(pkts, n);
#ifndef AUTO_ANALYSIS
	dl_stat_info.adc_acl_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[2] = adc_acl */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[2], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	/* Identify the DNS rule and update the meta*/
	update_dns_meta(pkts, n, adc_rule_a);
#ifndef AUTO_ANALYSIS
	dl_stat_info.update_dns_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[7] = update_dns */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[7], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	/* ADC Hash table lookup*/
	TIMER_GET_CURRENT_TP(_init_time);
	adc_hash_lookup(pkts, n, &adc_rule_b[0], DL_FLOW);
#ifndef AUTO_ANALYSIS
	dl_stat_info.adc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[3] = adc_hash */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[3], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);
#ifndef AUTO_ANALYSIS
	dl_stat_info.update_adc_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[8] = update_adc_rid */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[8], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info_dl[0]);
#ifndef AUTO_ANALYSIS
	dl_stat_info.adc_pcc_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[4] = adc_pcc_hash */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[4], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	pcc_gating(&sdf_info_dl[0], &adc_info_dl[0], n, &pkts_mask,
			&pcc_rule_id[0]);
#ifndef AUTO_ANALYSIS
	dl_stat_info.pcc_gating_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[9] = pcc_gate */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[9], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */

	TIMER_GET_CURRENT_TP(_init_time);
	dl_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0], &si[0]);
#ifndef AUTO_ANALYSIS
	dl_stat_info.dl_sess_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[5] = dl_sess_hash */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[5], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */
#else
	sdf_rule_id = sdf_lookup(pkts, n);

	filter_pcc_entry_lookup(FILTER_SDF, sdf_rule_id, n, &sdf_info_dl[0]);

	uint32_t *adc_rule_a = NULL;
	uint32_t adc_rule_b[MAX_BURST_SZ];
	uint32_t pcc_rule_id[MAX_BURST_SZ];

	/* ADC table lookup*/
	adc_rule_a = adc_dl_lookup(pkts, n);

	/* Identify the DNS rule and update the meta*/
	update_dns_meta(pkts, n, adc_rule_a);

	/* ADC Hash table lookup*/
	adc_hash_lookup(pkts, n, &adc_rule_b[0], DL_FLOW);

	/* if adc rule is found in adc domain name table (from hash lookup),
	 * overwrite the result from filter table.	*/
	update_adc_rid_from_domain_lookup(adc_rule_a, &adc_rule_b[0], n);

	filter_pcc_entry_lookup(FILTER_ADC, adc_rule_a, n, &adc_info_dl[0]);

	pcc_gating(&sdf_info_dl[0], &adc_info_dl[0], n, &pkts_mask,
			&pcc_rule_id[0]);

	dl_sess_info_get(pkts, n, &pkts_mask, &sdf_info[0], &si[0]);

#endif /* TIMER_STATS */
	/*update_sdf_cdr(&adc_ue_info[0], &sdf_info[0], pkts, n,
			&adc_pkts_mask, &pkts_mask, DL_FLOW);*/

	update_pcc_cdr(&sdf_info[0], pkts, n, &pkts_mask,
			&pcc_rule_id[0], DL_FLOW);

#ifdef EXTENDED_CDR
	uint64_t tmp = (~0LLU) >> (64 - n);
	update_extended_cdr(pkts, n, &pkts_mask, &tmp, &pcc_rule_id[0], DL_FLOW);
#endif /* EXTENDED_CDR */

#ifdef HYPERSCAN_DPI
#ifdef TIMER_STATS
	TIMER_GET_CURRENT_TP(_init_time);
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, pkts_mask);
#ifndef AUTO_ANALYSIS
	dl_stat_info.clone_dns_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[10] = clone_dns */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[10], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */
#else
	/* Send cloned dns pkts to dns handler*/
	clone_dns_pkts(pkts, n, pkts_mask);
#endif /* STATS_TIMER */

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
#ifdef TIMER_STATS
#ifdef AUTO_ANALYSIS
	/* enable printing DL perf stats */
	print_dl_perf_stats = 1;
	_timer_t _sgi_init_time = 0;
	TIMER_GET_CURRENT_TP(_sgi_init_time);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
	struct dp_sdf_per_bearer_info *sdf_info[MAX_BURST_SZ] = {NULL};
	struct dp_session_info *si[MAX_BURST_SZ] = {NULL};
	uint64_t pkts_queue_mask = 0;
	uint32_t next_port = 0; //GCC_Security flag

	uint64_t pkts_mask;
	pkts_mask = (~0LLU) >> (64 - n);

	/**
	 * TODO : filter_dl_traffic and gtpu_encap can be called irrespective
	 *      of app configuration.
	 *      Do we need enqueue_dl_pkts and hijack ?
	 */
	switch(app.spgw_cfg) {
		case SAEGWU:
			/* Filter Downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, sdf_info, si);

#ifdef TIMER_STATS
			_timer_t _init_time = 0;
			TIMER_GET_CURRENT_TP(_init_time);
#endif /* TIMER_STATS */
			/* Encap GTPU header*/
			gtpu_encap(&si[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Next port is S1U for SPGW*/
			next_port = app.s1u_port;

			/* En-queue DL pkts */
			if (pkts_queue_mask) {
				rte_pipeline_ah_packet_hijack(p, pkts_queue_mask);
#ifdef NGCORE_SHRINK
#ifdef DP_DDN
				enqueue_dl_pkts(&sdf_info[0], pkts, pkts_queue_mask);
#endif	/* DP_DDN */
#else
				enqueue_dl_pkts(&sdf_info[0], pkts, pkts_queue_mask, wk_index);

#endif /* NGCORE_SHRINK */
			}
#ifdef TIMER_STATS
#ifndef AUTO_ANALYSIS
			dl_stat_info.gtp_encap_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
			/* calculate min time, max time, min_burst_sz, max_burst_sz
			 * dl_perf_stats.op_time[11] = gtp_encap */
			SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[11], _init_time, n, 1);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */
			break;

		case PGWU:
			/*Filter downlink traffic. Apply adc, sdf, pcc*/
			pkts_mask = filter_dl_traffic(p, pkts, n, wk_index, sdf_info, si);

			/* Encap for S5/S8*/
			gtpu_encap(&si[0], pkts, n, &pkts_mask, &pkts_queue_mask);

			/*Set next port to S5/S8*/
			next_port = app.s5s8_pgwu_port;
			break;

		default:
			break;
	}

#ifdef TIMER_STATS
	_timer_t _init_time = 0;
	TIMER_GET_CURRENT_TP(_init_time);
	/* Update nexthop L2 header*/
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);
#ifndef AUTO_ANALYSIS
	dl_stat_info.retrive_hash_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[6] = arp_hash */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[6], _init_time, n, 1);
	/* Decrement ignore cnt by 1 */
	++dl_ignore_cnt;
#endif /* AUTO_ANALYSIS */
#else
	update_nexthop_info(pkts, n, &pkts_mask, next_port, &sdf_info[0]);
#endif /* TIMER_STATS*/
#ifdef PCAP_GEN
	dump_pcap(pkts, n, pcap_dumper_east);
#endif /* PCAP_GEN */
	/* Intimate the packets to be dropped*/
	rte_pipeline_ah_packet_drop(p, ~pkts_mask);
#ifdef TIMER_STATS
#ifndef AUTO_ANALYSIS
	dl_stat_info.sgi_handler_delta = TIMER_GET_ELAPSED_NS(_init_time);
#else
	/* calculate min time, max time, min_burst_sz, max_burst_sz
	 * dl_perf_stats.op_time[12] = sgi_time */
	SET_PERF_MAX_MIN_TIME(dl_perf_stats.op_time[12], _sgi_init_time, n, 1);
#endif /* AUTO_ANALYSIS */
#endif /* TIMER_STATS */

	return 0;
}
