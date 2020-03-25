/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2017 Intel Corporation
 */

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_common.h>
#include <rte_acl.h>

#include "cp.h"

#include "gtpv2c_set_ie.h"
#include "gtpv2c.h"

extern struct rte_hash *resp_op_id_hash;
extern struct response_info resp_t;
extern socklen_t s11_mme_sockaddr_len;
extern socklen_t s5s8_pgwc_sockaddr_len;
uint64_t op_id = 0;

/**
 * @brief Adds the current op_id to the hash table used to account for NB
 * Messages
 */
void
add_resp_op_id_hash(void)
{
	int ret;

	switch (resp_t.msg_type) {
		case GTP_CREATE_SESSION_REQ:
		case GTP_MODIFY_BEARER_REQ:
		case GTP_DELETE_SESSION_REQ: 
		case GTP_RELEASE_ACCESS_BEARERS_REQ: {
			struct response_info *tmp = rte_zmalloc("test",
					sizeof(struct response_info),
					RTE_CACHE_LINE_SIZE);

			if (NULL == tmp)
				rte_panic("%s: Failure to allocate create session buffer: "
						"%s (%s:%d)\n", __func__, rte_strerror(rte_errno),
						__FILE__,
						__LINE__);

			memcpy(tmp, &resp_t, sizeof(struct response_info));

			ret = rte_hash_add_key_data(resp_op_id_hash, (void *)&op_id,
					(void *)tmp);
			if (ret) {
				fprintf(stderr, "%s: rte_hash_add_key_data failed for "
						" op_id %"PRIu64": %s (%u)\n", __func__,
						op_id, rte_strerror(abs(ret)), ret);
			}
			break;
		} /* Req handling case */

		default:
			/*Adding entry for received entry for unknown request for now.
			 * For future reference*/
			ret = rte_hash_add_key_data(resp_op_id_hash, (void *)&op_id, NULL);
			if (ret) {
				fprintf(stderr, "%s: rte_hash_add_key_data failed for "
						" op_id %"PRIu64": %s (%u)\n", __func__,
						op_id, rte_strerror(abs(ret)), ret);
			}
			break;
	} /* switch case */

	RTE_LOG_DP(DEBUG, CP, "Added op_id; %"PRIu64"\n", op_id);

	++op_id;

}

/**
 * @brief Deletes the op_id from the hash table used to account for NB
 * Messages
 * @param resp_op_id
 * op_id received in process_resp_msg message to indicate message
 * was received and processed by the DPN
 */
void
del_resp_op_id(uint64_t resp_op_id)
{
	int ret = 0;
	struct response_info *tmp = NULL;

	RTE_LOG_DP(DEBUG, CP, "Deleting op_id; %"PRIu64"\n", resp_op_id);

	ret = rte_hash_lookup_data(resp_op_id_hash, (void *)&resp_op_id,
			(void **)&tmp);
	if (ret < 0) {
		fprintf(stderr, "%s: rte_hash_lookup_data failed for "
				"op_id %"PRIu64": %s (%u)\n", __func__,
				resp_op_id, rte_strerror(abs(ret)), ret);
		return;
	}

#ifdef SYNC_STATS
		update_stats_entry(resp_op_id, RESPONSE);
#endif /* SYNC_STATS */

#ifndef SIMU_CP
	uint16_t payload_length;

	switch (tmp->msg_type) {
		case GTP_CREATE_SESSION_REQ: {
			switch(spgw_cfg){
				case SGWC:
				case SPGWC: {
					set_create_session_response(&(tmp->gtpv2c_tx_t),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq,
							&(tmp->context_t), &(tmp->pdn_t),
							&(tmp->bearer_t), &(tmp->pco));

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
					break;
					}

				case PGWC: {
					set_pgwc_s5s8_create_session_response(&(tmp->gtpv2c_tx_t),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq, &(tmp->pdn_t),
							&(tmp->bearer_t));

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s5s8_pgwc_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s5s8_sgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
					break;
					}
				default:
					break;
			}/* Case cp type*/

			break;

		}/* Case Create session req*/

		case GTP_MODIFY_BEARER_REQ: {
			set_modify_bearer_response(&(tmp->gtpv2c_tx_t),
					tmp->gtpv2c_tx_t.teid_u.has_teid.seq,
					&(tmp->context_t), &(tmp->bearer_t));

			payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
				+ sizeof(tmp->gtpv2c_tx_t.gtpc);

			gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
					payload_length,
					(struct sockaddr *) &s11_mme_sockaddr,
					s11_mme_sockaddr_len);
			break;
		} /* Case modify session req */

		case GTP_DELETE_SESSION_REQ: {
			switch(spgw_cfg){
				case SGWC:
				case SPGWC:
					set_gtpv2c_teid_header(&(tmp->gtpv2c_tx_t),
							GTP_DELETE_SESSION_RSP,
							htonl(tmp->context_t.s11_mme_gtpc_teid),
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq);

					set_cause_accepted_ie(&(tmp->gtpv2c_tx_t),
							IE_INSTANCE_ZERO);

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s11_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s11_mme_sockaddr,
							s11_mme_sockaddr_len);
					break;

				case PGWC:
					set_gtpv2c_teid_header(&(tmp->gtpv2c_tx_t),
							GTP_DELETE_SESSION_RSP,
							tmp->s5s8_sgw_gtpc_del_teid_ptr,
							tmp->gtpv2c_tx_t.teid_u.has_teid.seq);

					set_cause_accepted_ie(&(tmp->gtpv2c_tx_t),
							IE_INSTANCE_ZERO);

					payload_length = ntohs(tmp->gtpv2c_tx_t.gtpc.length)
						+ sizeof(tmp->gtpv2c_tx_t.gtpc);

					gtpv2c_send(s5s8_pgwc_fd, (uint8_t*)&(tmp->gtpv2c_tx_t),
							payload_length,
							(struct sockaddr *) &s5s8_sgwc_sockaddr,
							s5s8_pgwc_sockaddr_len);
					break;

				default:
					break;
			}/* case cp type*/
			break;

		}/*case delete session req */

		default:
			break;
	}/* case msg_type */

#endif /* SIMU_CP */

	ret = rte_hash_del_key(resp_op_id_hash, (void *)&resp_op_id);

	if (ret < 0) {
		fprintf(stderr, "%s:rte_hash_del_key failed for op_id %"PRIu64
				": %s (%u)\n", __func__,
				resp_op_id,
				rte_strerror(abs(ret)), ret);
	}

	if (NULL != tmp) {
		/* free the memory */
		rte_free(tmp);
	}
}
