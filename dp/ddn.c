/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include "main.h"
#include <rte_errno.h>

#ifdef DP_DDN

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
send_ddn_request(struct dp_session_info *si) 
{

#ifdef SDN_ODL_BUILD
				zmq_ddn(si->sess_id, si->client_id);
#else
#ifdef ZMQ_COMM
				struct resp_msgbuf msg_payload = {
					.mtype = MSG_DDN,
					.op_id = 0,
					.sess_id = si->sess_id,
					.dp_id.id = DPN_ID };

				if (comm_node[COMM_ZMQ].send(&msg_payload,
						sizeof(struct resp_msgbuf)) < 0) {
						perror("msgsnd");
						return -1;
				}

#else
				struct msgbuf msg_payload = {
					.mtype = MSG_DDN,
					.dp_id.id = DPN_ID,
					.msg_union.sess_entry.sess_id = si->sess_id };

				if (comm_node[COMM_SOCKET].send(&msg_payload,
						sizeof(struct msgbuf)) < 0) {
						perror("msgsnd");
						return -1;
				}
#endif  /* ZMQ_COMM */
#endif  /* SDN_ODL_BUILD */
			return 0;

}

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

void
enqueue_dl_pkts(struct dp_sdf_per_bearer_info **sess_info,
		struct rte_mbuf **pkts, uint64_t pkts_queue_mask)
{
	struct rte_ring *ring;
	struct dp_session_info *si;
	int i;
	int rc;

	while (pkts_queue_mask) {
		i = __builtin_ffsll(pkts_queue_mask) - 1;
		RESET_BIT(pkts_queue_mask, i);

		si = ((struct dp_sdf_per_bearer_info *)
				sess_info[i])->bear_sess_info;

		ring = si->dl_ring;
		if (!ring) {
			ring = allocate_ring();
			if (ring == NULL) {
				RTE_LOG_DP(INFO, DP, "Not enough memory, can't "
						"buffer this session:%lu\n",
						si->sess_id);
				rte_pktmbuf_free(pkts[i]);
				continue;
			}

			si->dl_ring = ring;
			if (si->sess_state == IDLE) {
				rc = send_ddn_request(si);
				
				if(rc < 0) {
					RTE_LOG_DP(ERR, DP, "failed to send ddn req  "
							"for this session:%lu\n",
							si->sess_id);

				}
					
				si->sess_state = IN_PROGRESS;
			}
		}

		if (rte_ring_enqueue(ring, (void *)pkts[i]) == -ENOBUFS) {
			rte_pktmbuf_free(pkts[i]);
			rte_ring_free(si->dl_ring);
			si->dl_ring = NULL;
			si->sess_state = IDLE;

			RTE_LOG_DP(ERR, DP, "%s::Can't queue pkt- ring full..."
					" Dropping pkt\n", __func__);
		}

	}
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

#endif	/* DP_DDN */

