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

#include "main.h"
#include <rte_errno.h>
/**
 * @brief Allocates ring for buffering downlink packets
 * Allocate downlink packet buffer ring from a set of
 * rings from the ring container per worker core.
 *
 * @param wk_params
 * Worker params from which to allocate the ring.
 *
 * @return
 *  - rte_ring Allocated ring
 *  - NULL on failure
 */

/* ASR- NGCORE_SHRINK Notification handler temporarily defined out */
#ifndef NGCORE_SHRINK
static struct
rte_ring *allocate_ring(struct epc_worker_params *wk_params)
{
	struct rte_ring *dl_ring = NULL;
	unsigned worker_core = rte_lcore_id();
	int i;
	char name[32];

	if ((DL_RING_CONTAINER_SIZE > wk_params->num_dl_rings) &&
		(rte_ring_count(wk_params->dl_ring_container)
				< DL_RINGS_THRESHOLD)) {
		for (i = 0; i < DL_RINGS_THRESHOLD; ++i) {
			snprintf(name, sizeof(name), "dl_pkt_ring_%"PRIu32"_%u",
					wk_params->num_dl_rings,
					worker_core);
			struct rte_ring *tmp =
				rte_ring_create(name, DL_PKTS_RING_SIZE,
						rte_socket_id(),
						RING_F_SP_ENQ | RING_F_SC_DEQ);
			if (tmp) {
				int ret = rte_ring_enqueue(
					wk_params->dl_ring_container, tmp);

				if (ret == ENOBUFS) {
					RTE_LOG_DP(DEBUG, DP,
						"Cannot hold more dl rings\n");
					rte_ring_free(tmp);
					break;
				}
				wk_params->num_dl_rings++;
			} else {
				RTE_LOG_DP(ERR, DP, "Couldnt create %s for DL "
						"pkts - %s\n", name,
						rte_strerror(rte_errno));
				if (rte_errno == EEXIST)
					wk_params->num_dl_rings++;
			}
		}
	}
	rte_ring_dequeue(wk_params->dl_ring_container, (void **)&dl_ring);

	return dl_ring;
}

void
enqueue_dl_pkts(struct dp_sdf_per_bearer_info **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask,
		int wk_index)
{
	struct rte_ring *ring;
	struct dp_session_info *si;
	int i;

	while (pkts_queue_mask) {
		i = __builtin_ffsll(pkts_queue_mask) - 1;
		RESET_BIT(pkts_queue_mask, i);

		si = ((struct dp_sdf_per_bearer_info *)
				sess_info[i])->bear_sess_info;

		ring = si->dl_ring;
		if (!ring) {
			ring = allocate_ring(&epc_app.worker[wk_index]);
			if (ring == NULL) {
				RTE_LOG_DP(INFO, DP, "Not enough memory, can't "
						"buffer this session:%lu\n",
						si->sess_id);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}
			si->dl_ring = ring;
			if (si->sess_state == IDLE) {
#ifdef SDN_ODL_BUILD
				zmq_ddn(si->sess_id, si->client_id);
#else
				struct msgbuf msg_payload = {
					.mtype = MSG_DDN,
					.dp_id.id = DPN_ID,
					.msg_union.sess_entry.sess_id = si->sess_id };

				if (comm_node[COMM_SOCKET].send(&msg_payload,
						sizeof(struct msgbuf)) < 0) {
						perror("msgsnd");
				}
#endif
				si->sess_state = IN_PROGRESS;
			}
		}
		rte_ring_enqueue(ring, (void *)pkts[i]);
	}
}
#endif	/* NGCORE_SHRINK */

