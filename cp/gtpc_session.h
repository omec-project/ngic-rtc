#include "cp.h"
#include "main.h"
#include "pfcp.h"
#include "cp_stats.h"
#include "pfcp_util.h"
#include "pfcp_set_ie.h"
#include "pfcp_session.h"
#include "pfcp_messages.h"
#include "pfcp_association.h"
#include "pfcp_messages_encoder.h"
#include "pfcp_messages_decoder.h"
#include "pfcp_enum.h"

#ifdef CP_BUILD
#include "ue.h"
#include "gtp_messages.h"
#include "gtpv2c_set_ie.h"
#include "cp_config.h"
#include "ipc_api.h"
#endif /* CP_BUILD */

#ifndef GTPC_SESSION_H
#define GTPC_SESSION_H

struct gw_info {
	uint8_t eps_bearer_id;
	uint32_t s5s8_sgw_gtpc_teid;
	uint32_t s5s8_pgw_gtpc_ipv4;
	uint64_t seid;
};

#ifdef CP_BUILD
int
delete_context(del_sess_req_t *ds_req,
		ue_context **_context, uint32_t *s5s8_pgw_gtpc_teid,
		uint32_t *s5s8_pgw_gtpc_ipv4);

int
fill_cs_request(create_sess_req_t *cs_req, struct ue_context_t *context,
		uint8_t ebi_index);

int
process_sgwc_s5s8_create_sess_rsp(create_sess_rsp_t *cs_rsp);

void
fill_pgwc_create_session_response(create_sess_rsp_t *cs_resp,
		uint32_t sequence, struct ue_context_t *context, uint8_t ebi_index);
void
fill_ds_request(del_sess_req_t *ds_req, struct ue_context_t *context,
		 uint8_t ebi_index);
void
fill_pgwc_ds_sess_rsp(del_sess_rsp_t *ds_resp, uint32_t sequence, uint32_t has_teid);

int
process_pgwc_s5s8_delete_session_request(del_sess_req_t *ds_req);

int
process_sgwc_s5s8_delete_session_response(del_sess_rsp_t *dsr, uint8_t *gtpv2c_tx);

/**
 * Handles the processing at sgwc after receiving response for delete
 * session request messages from pgwc
 *
 * @param gtpv2c_rx
 *   gtpv2c message buffer containing delete session request message
 * @param proc
 *   procedure
 * @return
 *   \- 0 if successful
 *   \- > 0 if error occurs during packet filter parsing corresponds to 3gpp
 *   specified cause error value
 *   \- < 0 for all other errors
 */
int
process_sgwc_s5s8_delete_session_request(del_sess_rsp_t *ds_resp);

int
delete_sgwc_context(uint32_t gtpv2c_teid, ue_context **_context, uint64_t *seid);
int
process_pgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp);

int
process_sgwc_create_bearer_rsp(create_bearer_rsp_t *cb_rsp);

#endif /*CP_BUILD*/
#endif
