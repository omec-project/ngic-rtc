#include "gtpv2c.h"
#include "pfcp_util.h"
#include "sm_struct.h"
#include "rte_common.h"
#include "cp_timer.h"
#include "gtpv2c_error_rsp.h"
#include "clogger.h"

#define DIAMETER_PCC_RULE_EVENT (5142)

extern int s11_fd;
extern int s5s8_fd;
extern int pfcp_fd;


/**
 * @brief  : Retrives session entry
 * @param  : sess_id, session id
 * @param  : resp, structure to be filled with retrived entry
 * @return : Returns 0 in case of success , -1 otherwise
 */
static uint8_t
get_ses_entry(uint64_t sess_id, struct resp_info **resp)
{
        int ret = 0;
        ret = rte_hash_lookup_data(sm_hash,
                                &sess_id, (void **)resp);

        if ( ret < 0) {
                return -1;
        }

        return 0;

}

bool
add_timer_entry(peerData *conn_data, uint32_t timeout_ms,
		gstimercallback cb)
{

	if (!init_timer(conn_data, timeout_ms, cb))
	{
		clLog(clSystemLog, eCLSeverityCritical,"%s:%s:%u =>%s - initialization of %s failed erro no %d\n",
				__FILE__, __func__, __LINE__,
				getPrintableTime(), conn_data->name, errno);
		return false;
	}

	return true;
}

void
timer_callback(gstimerinfo_t *ti, const void *data_t )
{
	int ret = 0;
	int64_t seid = 0;
	msg_info msg;
	ue_context *context = NULL;
	pdn_connection *pdn = NULL;
	struct resp_info *resp = NULL;

	RTE_SET_USED(ti);

#pragma GCC diagnostic push  /* require GCC 4.6 */
#pragma GCC diagnostic ignored "-Wcast-qual"
	peerData *data =  (peerData *) data_t;
#pragma GCC diagnostic pop   /* require GCC 4.6 */


	if (data->itr_cnt >= data->itr - 1) {
	        ret = get_ue_context(data->teid, &context);
		if ( ret < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, data->teid);
			return;
		}
		if(context != NULL && context->eps_bearers[data->ebi_index] != NULL
			&& context->eps_bearers[data->ebi_index]->pdn != NULL ) {
			pdn = context->eps_bearers[data->ebi_index]->pdn;
			seid = pdn->seid;
			if (get_ses_entry(seid, &resp) != 0){
				/* Assuming that session is not established or resp entry is not created */
				upf_context_t *upf_context = NULL;
				context_key *key = NULL;

				ret = rte_hash_lookup_data(upf_context_by_ip_hash,
					(const void*) &(context->eps_bearers[data->ebi_index]->pdn->upf_ipv4.s_addr),
					(void **) &(upf_context));

				if (upf_context != NULL &&  ret >= 0) {
					/*msg.msg_type = GTP_CREATE_SESSION_REQ;
					msg.gtpc_msg.csr = upf_context->csr;
					cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
						spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);*/
				       for(uint8_t idx = 0; idx < upf_context->csr_cnt; idx++) {
						msg.msg_type = GTP_CREATE_SESSION_REQ;
						key = (context_key *) upf_context->pending_csr_teid[idx];
						msg.gtpc_msg.csr.sender_fteid_ctl_plane.teid_gre_key = key->sender_teid;
						msg.gtpc_msg.csr.header.teid.has_teid.seq = key->sequence;
						msg.gtpc_msg.csr.bearer_contexts_to_be_created.eps_bearer_id.ebi_ebi =
										key->ebi_index + 5;
						msg.gtpc_msg.csr.header.teid.has_teid.teid = key->teid;
						cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
        		                                spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
					}
				}
			} else {
			if (GTP_MODIFY_BEARER_REQ == resp->msg_type) {
				msg.gtpc_msg.mbr = resp->gtpc_msg.mbr;
				msg.msg_type = resp->msg_type;
				mbr_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
					spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			} else if (GTP_CREATE_SESSION_REQ == resp->msg_type) {
				msg.gtpc_msg.csr = resp->gtpc_msg.csr;
				msg.msg_type = resp->msg_type;
				cs_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
					spgw_cfg != PGWC ? S11_IFACE : S5S8_IFACE);
			} else if (GTP_DELETE_SESSION_REQ == resp->msg_type) {
				msg.gtpc_msg.dsr = resp->gtpc_msg.dsr;
				msg.msg_type = resp->msg_type;
				ds_error_response(&msg, GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING,
					spgw_cfg != PGWC ? S11_IFACE :S5S8_IFACE);
			} else if ((pfcp_config.cp_type == PGWC ||  pfcp_config.cp_type ==  SAEGWC )
				 && (resp->msg_type == GX_RAR_MSG || resp->state == CREATE_BER_REQ_SNT_STATE)) {
#ifdef GX_BUILD
				gen_reauth_error_response(pdn, DIAMETER_PCC_RULE_EVENT);
#endif
				pdn->state = IDEL_STATE;
			} else {
				/* Need to handle for other request */
			}
			}
		}
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			rte_free(data);
		}
		return;
	}

	/* timer retry handler */
	switch(data->portId) {
		case GX_IFACE:
			break;
		case S11_IFACE:
			timer_retry_send(s11_fd, data);
			break;
		case S5S8_IFACE:
			timer_retry_send(s5s8_fd, data);
			break;
		case PFCP_IFACE:
			timer_retry_send(pfcp_fd, data);
			break;
		default:
			break;
	}
	data->itr_cnt++;
	return;
}

peerData *
fill_timer_entry_data(enum source_interface iface, struct sockaddr_in *peer_addr,
		uint8_t *buf, uint16_t buf_len, uint8_t itr, uint32_t teid,  uint8_t ebi_index)
{
	peerData *timer_entry = NULL;

	timer_entry = rte_zmalloc_socket(NULL, sizeof(upf_context_t),
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(timer_entry == NULL )
	{
		clLog(clSystemLog, eCLSeverityCritical, "Failure to allocate timer entry :"
				"%s (%s:%d)\n",
				rte_strerror(rte_errno),
				__FILE__, __LINE__);
		return NULL;
	}
	memset(timer_entry, 0, sizeof(peerData));

	timer_entry->portId = (uint8_t)iface;
	timer_entry->dstIP = peer_addr->sin_addr.s_addr;
	timer_entry->dstPort = peer_addr->sin_port;
	timer_entry->itr = itr;
	timer_entry->teid = teid;
	timer_entry->ebi_index = ebi_index;
	timer_entry->buf_len = buf_len;
	memcpy(&timer_entry->buf,(uint8_t *)buf, buf_len);

	return(timer_entry);
}

void
delete_pfcp_if_timer_entry(uint32_t teid, uint8_t ebi_index)
{
	int ret = 0;
        peerData *data = NULL;
        ue_context *context = NULL;

	ret = get_ue_context(teid, &context);
        if ( ret < 0) {
                clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
                return;
        }
	if(context != NULL && context->eps_bearers[ebi_index] != NULL
		&& context->eps_bearers[ebi_index]->pdn != NULL ) {
		data = context->eps_bearers[ebi_index]->pdn->timer_entry;
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			rte_free(data);
		}
	}
        return;
}

void
delete_gtpv2c_if_timer_entry(uint32_t teid)
{
	int ret = 0;
        peerData *data = NULL;
       	eps_bearer *bearer = NULL;

        ret = get_bearer_by_teid(teid, &bearer);

        if ( ret < 0) {
                clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
                return;
        }
	if(bearer != NULL && bearer->pdn != NULL &&
		bearer->pdn->timer_entry != NULL ) {
        	data = bearer->pdn->timer_entry;
        	if(data->pt.ti_id != 0) {
                	stoptimer(&data->pt.ti_id);
                	deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			rte_free(data);
		}
	}
        return;
}

void
delete_timer_entry(uint32_t teid)
{
	int ret = 0;
	peerData *data = NULL;
       	eps_bearer *bearer = NULL;

        ret = get_bearer_by_teid(teid, &bearer);
	if ( ret < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
		return;
	}

	if(bearer != NULL && bearer->pdn != NULL &&
		bearer->pdn->timer_entry != NULL ) {
		data = bearer->pdn->timer_entry;
		if(data->pt.ti_id != 0) {
			stoptimer(&data->pt.ti_id);
			deinittimer(&data->pt.ti_id);
			/* free peer data when timer is de int */
			rte_free(data);
		}
	}
	return;
}

void
add_pfcp_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
        uint8_t *buf, uint16_t buf_len, uint8_t ebi_index)
{
        int ret = 0;
        peerData *timer_entry = NULL;
        ue_context *context = NULL;

        ret = get_ue_context(teid, &context);
        if ( ret < 0) {
                clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
                return;
        }
        /* fill and add timer entry */
        timer_entry = fill_timer_entry_data(PFCP_IFACE, peer_addr,
                        buf, buf_len, pfcp_config.request_tries, teid, ebi_index);

        if(!(add_timer_entry(timer_entry, pfcp_config.request_timeout, timer_callback))) {
                clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%u Faild to add timer entry...\n",
                                __FILE__, __func__, __LINE__);
        }
	if(context != NULL && context->eps_bearers[ebi_index] != NULL
		&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
       		context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;

		if (starttimer(&timer_entry->pt) < 0) {
			clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%u Periodic Timer failed to start...\n",
				__FILE__, __func__, __LINE__);
		}
	}
}

void
add_gtpv2c_if_timer_entry(uint32_t teid, struct sockaddr_in *peer_addr,
	uint8_t *buf, uint16_t buf_len, uint8_t ebi_index, enum source_interface iface)
{
	int ret = 0;
	peerData *timer_entry = NULL;
	eps_bearer *bearer = NULL;
	ue_context *context = NULL;

	/* fill and add timer entry */
	timer_entry = fill_timer_entry_data(iface, peer_addr,
			buf, buf_len, pfcp_config.request_tries, teid, ebi_index);

	if(!(add_timer_entry(timer_entry, pfcp_config.request_timeout, timer_callback))) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%u Faild to add timer entry...\n",
				__FILE__, __func__, __LINE__);
	}

	if(SGWC == pfcp_config.cp_type) {
			/* if we get s5s8 fteid we will retrive bearer , if we get sgw s11 fteid we will retrive ue contex */
		ret = get_bearer_by_teid(teid, &bearer);
		if ( ret < 0) {
			/*The teid might be of S11*/
			ret = get_ue_context(teid, &context);
			if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
					return;
			}

			if(context != NULL && context->eps_bearers[ebi_index] != NULL
				&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
					context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;
			} else {
				return;
			}
		}else {
			bearer->pdn->timer_entry = timer_entry;
		}
	} else {
		ret = get_ue_context(teid, &context);
			if ( ret < 0) {
					clLog(clSystemLog, eCLSeverityCritical, "%s:Entry not found for teid:%x...\n", __func__, teid);
					return;
			}

		if(context != NULL && context->eps_bearers[ebi_index] != NULL
			&&  context->eps_bearers[ebi_index]->pdn != NULL ) {
					context->eps_bearers[ebi_index]->pdn->timer_entry = timer_entry;
		} else {
			return;
		}
	}
	if (starttimer(&timer_entry->pt) < 0) {
		clLog(clSystemLog, eCLSeverityCritical, "%s:%s:%u Periodic Timer failed to start...\n",
				__FILE__, __func__, __LINE__);
	}
}
