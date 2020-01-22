#ifndef _GTPV2C_ERROR_RSP_H_
#define _GTPV2C_ERROR_RSP_H_

#include "ue.h"
#include "gtpv2c.h"
#include "sm_struct.h"
#include "gtpv2c_ie.h"
#include "pfcp_util.h"
#include "pfcp_session.h"
#include "gtpv2c_set_ie.h"
#include "pfcp_messages_encoder.h"


typedef struct err_rsp_info_t
{
	uint32_t sender_teid;
	uint32_t teid;
	uint32_t seq;
	uint8_t ebi_index;
	uint8_t offending;
}err_rsp_info;

void clean_up_while_error(uint8_t ebi, uint32_t teid, uint64_t *imsi_val, uint16_t imsi_len, uint32_t seq );

void cs_error_response(msg_info *msg, uint8_t cause_value, int iface);

void mbr_error_response(msg_info *msg, uint8_t cause_value, int iface);

void ds_error_response(msg_info *msg, uint8_t cause_value, int iface);

void get_error_rsp_info(msg_info *msg, err_rsp_info *err_rsp_info, uint8_t index);

void get_info_filled(msg_info *msg, err_rsp_info *t2 , uint8_t index);
#ifdef GX_BUILD
void send_ccr_t_req(msg_info *msg, uint8_t ebi, uint32_t teid);
#endif /* GX_BUILD */
void send_version_not_supported(int iface, uint32_t seq);
#endif
