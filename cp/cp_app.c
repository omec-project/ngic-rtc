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
#include <stdlib.h>
#include <math.h>
#include "cp_config.h"
#include "cp_app.h"
#include "ipc_api.h"
#include "sm_arr.h"
#include "pfcp.h"
#include "pfcp_association.h"
#include "sm_pcnd.h"
#include "ue.h"
#include "gw_adapter.h"
#include "gtpv2c_error_rsp.h"

static uint32_t cc_request_number = 0;
extern pfcp_config_t config;
extern int clSystemLog;
/*Socket used by CP to listen for GxApp client connection */
int g_cp_sock_read = 0;
int g_cp_sock_read_v6 = 0;

/*Socket used by CP to write CCR and RAA*/
int gx_app_sock = 0;
int gx_app_sock_v6 = 0;

/*Socket used by CP to read CCR and RAA*/
int gx_app_sock_read = 0;
int gx_app_sock_read_v6 = 0;
int ret ;

void
fill_rat_type_ie( int32_t *ccr_rat_type, uint8_t csr_rat_type )
{
	if ( csr_rat_type == EUTRAN_ ) {
		*ccr_rat_type = GX_EUTRAN;
	}else if ( csr_rat_type == UTRAN ){
		*ccr_rat_type = GX_UTRAN;
	}else if ( csr_rat_type == GERAN ){
		*ccr_rat_type = GX_GERAN;
	}else if ( csr_rat_type == WLAN ){
		*ccr_rat_type = GX_WLAN;
	}else if ( csr_rat_type == VIRTUAL ){
		*ccr_rat_type = GX_VIRTUAL;
	}else if ( csr_rat_type == GAN ){
		*ccr_rat_type = GX_GAN;
	}else if ( csr_rat_type == HSPA_EVOLUTION ){
		*ccr_rat_type = GX_HSPA_EVOLUTION;
	}
}

/**
 * @brief  : Fill qos information
 * @param  : ccr_qos_info, structure to be filled
 * @param  : bearer, bearer information
 * @param  : apn_ambr, ambr details
 * @return : Returns nothing
 */
static void
fill_qos_info( GxQosInformation *ccr_qos_info,
		eps_bearer *bearer, ambr_ie *apn_ambr)
{

	/* VS: Fill the bearer identifier value */
	ccr_qos_info->presence.bearer_identifier = PRESENT ;
	ccr_qos_info->bearer_identifier.len =
		(1 + (uint32_t)log10(bearer->eps_bearer_id));
	if (ccr_qos_info->bearer_identifier.len >= 255) {
		clLog(clSystemLog, eCLSeverityCritical,
				LOG_FORMAT"Error: Insufficient memory to copy bearer identifier\n", LOG_VALUE);
		return;
	} else {
		strncpy((char *)ccr_qos_info->bearer_identifier.val,
				(char *)&bearer->eps_bearer_id,
				ccr_qos_info->bearer_identifier.len);
	}

	ccr_qos_info->presence.apn_aggregate_max_bitrate_ul = PRESENT;
	ccr_qos_info->presence.apn_aggregate_max_bitrate_dl = PRESENT;
	ccr_qos_info->apn_aggregate_max_bitrate_ul =
		apn_ambr->ambr_uplink;
	ccr_qos_info->apn_aggregate_max_bitrate_dl =
		apn_ambr->ambr_downlink;

	ccr_qos_info->presence.max_requested_bandwidth_ul = PRESENT;
	ccr_qos_info->presence.max_requested_bandwidth_dl = PRESENT;
	ccr_qos_info->max_requested_bandwidth_ul =
		bearer->qos.ul_mbr;
	ccr_qos_info->max_requested_bandwidth_dl =
		bearer->qos.dl_mbr;

	ccr_qos_info->presence.guaranteed_bitrate_ul = PRESENT;
	ccr_qos_info->presence.guaranteed_bitrate_dl = PRESENT;
	ccr_qos_info->guaranteed_bitrate_ul =
		bearer->qos.ul_gbr;
	ccr_qos_info->guaranteed_bitrate_dl =
		bearer->qos.dl_gbr;
}

/**
 * @brief  : fill default eps bearer qos
 * @param  : ccr_default_eps_bearer_qos, structure to be filled
 * @param  : bearer, bearer data
 * @return : Returns Nothing
 */
static void
fill_default_eps_bearer_qos( GxDefaultEpsBearerQos *ccr_default_eps_bearer_qos,
		eps_bearer *bearer)
{
	if(( QCI_1 <= (bearer->qos.qci)  && (bearer->qos.qci) <= QCI_9 ) ||
			QCI_65 == (bearer->qos.qci) ||
			QCI_66 == (bearer->qos.qci) ||
			QCI_69 == (bearer->qos.qci) ||
			QCI_70 == (bearer->qos.qci))
	{
		ccr_default_eps_bearer_qos->presence.qos_class_identifier = PRESENT;
		ccr_default_eps_bearer_qos->qos_class_identifier = bearer->qos.qci;
	} else {
		/* TODO :Revisit to handler other values of Qci e.g 0 */
	}

	ccr_default_eps_bearer_qos->presence.allocation_retention_priority = PRESENT;

	ccr_default_eps_bearer_qos->allocation_retention_priority.presence.priority_level = PRESENT;
	ccr_default_eps_bearer_qos->allocation_retention_priority.priority_level =
		bearer->qos.arp.priority_level;

	ccr_default_eps_bearer_qos->allocation_retention_priority.presence.pre_emption_capability = PRESENT;
	ccr_default_eps_bearer_qos->allocation_retention_priority.pre_emption_capability =
		bearer->qos.arp.preemption_capability;
	ccr_default_eps_bearer_qos->allocation_retention_priority.presence.pre_emption_vulnerability = PRESENT;
	ccr_default_eps_bearer_qos->allocation_retention_priority.pre_emption_vulnerability =
		bearer->qos.arp.preemption_vulnerability;
}

/**
 * @brief  : convert binary value to string
 *           Binary value is stored in 8 bytes, each nibble representing each char.
 *           char binary stroes each char in 1 byte.
 * @param  : [in] b_val : Binary val
 * @param  : [out] s_val : Converted string val
 * @return : void
 */
void
bin_to_str(unsigned char *b_val, char *s_val, int b_len, int s_len)
{
	if(NULL == b_val || NULL == s_val) return;

	memset(s_val, 0, s_len);

	/* Byte 'AB' in b_val, is converted to two bytes 'A', 'B' in s_val*/
	s_val[0] = '0' + (b_val[0] & 0x0F);
	s_val[1] = '0' + ((b_val[0]>>4) & 0x0F);

	for(int i=1; i < b_len; ++i) {
		s_val[(i*2)] = '0' + (b_val[i] & 0x0F);
		s_val[(i*2) + 1] = '0' + ((b_val[i]>>4) & 0x0F);
	}
	s_val[(b_len*2)-1] = '\0';
}

void
encode_imsi_to_bin(uint64_t imsi, int imsi_len, uint8_t *bin_imsi){
	uint8_t buf[32] = {0};
	snprintf((char*)buf,32, "%" PRIu64, imsi);
	for (int i=0; i < imsi_len; i++)
		bin_imsi[i] = ((buf[i*2 + 1] & 0xF) << 4) | ((buf[i*2] & 0xF));
	uint8_t odd = strnlen((const char *)buf,32)%2;
	if (odd)
		bin_imsi[imsi_len -1] = (0xF << 4) | ((buf[(imsi_len-1)*2] & 0xF));

	return;
}

void
fill_subscription_id( GxSubscriptionIdList *subs_id, uint64_t imsi, uint64_t msisdn )
{
	subs_id->count = 0;

	if( imsi != 0 ) {
		subs_id->list = rte_malloc_socket(NULL,	sizeof( GxSubscriptionId),
									RTE_CACHE_LINE_SIZE, rte_socket_id());
		if(subs_id->list == NULL){
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Memory allocation fails\n",
					LOG_VALUE);
		}

		subs_id->list[subs_id->count].presence.subscription_id_type = PRESENT;
		subs_id->list[subs_id->count].presence.subscription_id_data = PRESENT;
		subs_id->list[subs_id->count].subscription_id_type = END_USER_IMSI;
		subs_id->list[subs_id->count].subscription_id_data.len = STR_IMSI_LEN -1 ;
		uint8_t bin_imsi[32] = {0};
		encode_imsi_to_bin(imsi, BINARY_IMSI_LEN , bin_imsi);
		uint64_t temp_imsi = 0;
		memcpy(&temp_imsi, bin_imsi, BINARY_IMSI_LEN);
		bin_to_str((unsigned char*) (&temp_imsi),
				(char *)(subs_id->list[subs_id->count].subscription_id_data.val),
				BINARY_IMSI_LEN, STR_IMSI_LEN);

		subs_id->count++;
	} else if( msisdn != 0 ) {

		subs_id->list = rte_malloc_socket(NULL,	sizeof( GxSubscriptionId),
									RTE_CACHE_LINE_SIZE, rte_socket_id());
		if(subs_id->list == NULL){
			clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Memory allocation fails\n",
					LOG_VALUE);
		}

		subs_id->list[subs_id->count].presence.subscription_id_type = PRESENT;
		subs_id->list[subs_id->count].presence.subscription_id_data = PRESENT;
		subs_id->list[subs_id->count].subscription_id_type = END_USER_E164;
		subs_id->list[subs_id->count].subscription_id_data.len = STR_MSISDN_LEN;
		bin_to_str((unsigned char*) (&msisdn),
				(char *)(subs_id->list[subs_id->count].subscription_id_data.val),
				BINARY_MSISDN_LEN, STR_MSISDN_LEN);
		subs_id->count++;
	}
}

void
fill_user_equipment_info( GxUserEquipmentInfo *ccr_user_eq_info, uint64_t csr_imei )
{
	ccr_user_eq_info->presence.user_equipment_info_type = PRESENT;
	ccr_user_eq_info->presence.user_equipment_info_value = PRESENT;
	ccr_user_eq_info->user_equipment_info_type = IMEISV ;
	ccr_user_eq_info->user_equipment_info_value.len = sizeof(uint64_t);
	memcpy( ccr_user_eq_info->user_equipment_info_value.val,  &(csr_imei),
			ccr_user_eq_info->user_equipment_info_value.len);
}
void
fill_3gpp_ue_timezone( Gx3gppMsTimezoneOctetString *ccr_tgpp_ms_timezone,
		gtp_ue_time_zone_ie_t csr_ue_timezone )
{
	ccr_tgpp_ms_timezone->len = csr_ue_timezone.header.len;
	memcpy( ccr_tgpp_ms_timezone->val, &(csr_ue_timezone.time_zone), ccr_tgpp_ms_timezone->len);
}

void
fill_presence_rprtng_area_info(GxPresenceReportingAreaInformationList *pra_info,
											presence_reproting_area_info_t *ue_pra_info){

	pra_info->count = 0;
	pra_info->list = rte_malloc_socket(NULL, sizeof( GxPresenceReportingAreaInformation),
									RTE_CACHE_LINE_SIZE, rte_socket_id());
	if(pra_info->list == NULL){
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Memory allocation fails\n",
				LOG_VALUE);
		return;
	}
	memset(pra_info->list, 0, sizeof(GxPresenceReportingAreaInformation));
	pra_info->list[pra_info->count].presence.presence_reporting_area_identifier = 1;
	pra_info->list[pra_info->count].presence.presence_reporting_area_status = 1;
	if(ue_pra_info->ipra){
		pra_info->list[pra_info->count].presence_reporting_area_status = PRA_IN_AREA;
	} else if(ue_pra_info->opra){
		pra_info->list[pra_info->count].presence_reporting_area_status = PRA_OUT_AREA;
	} else {
		pra_info->list[pra_info->count].presence_reporting_area_status = PRA_INACTIVE;
	}

	pra_info->list[pra_info->count].presence_reporting_area_identifier.len = 3*sizeof(uint8_t);
	memcpy(pra_info->list[pra_info->count].presence_reporting_area_identifier.val,
			&ue_pra_info->pra_identifier,
			pra_info->list[pra_info->count].presence_reporting_area_identifier.len);
	pra_info->count++;
	return;
}

/* Fill the Credit Crontrol Request to send PCRF */
int
fill_ccr_request(GxCCR *ccr, ue_context *context,
					int ebi_index, char *sess_id, uint8_t flow_flag)
{
	char apn[MAX_APN_LEN] = {0};

	eps_bearer *bearer = NULL;
	pdn_connection *pdn = NULL;

	if (ebi_index > 0) {
		bearer = context->eps_bearers[ebi_index];
	} else {
		clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Invalid EBI ID \n", LOG_VALUE);
		return -1;
	}

	pdn = GET_PDN(context, ebi_index);
	if ( pdn == NULL) {
		clLog(clSystemLog, eCLSeverityCritical,LOG_FORMAT"Failed to get pdn"
			" for ebi_index: %d\n",
			LOG_VALUE, ebi_index);
		return -1;
	}

	/* Assign the Session ID in the request */
	if (sess_id != NULL) {
		ccr->presence.session_id = PRESENT;
		ccr->session_id.len = strnlen(sess_id, MAX_LEN);
		memcpy(ccr->session_id.val, sess_id, ccr->session_id.len);
	}

	/* RFC 4006 section 8.2 */
	/* ============================================== */
	/*  Cc Request Type      |    Cc Request number   */
	/* ============================================== */
	/*   Initial Request     --     0                 */
	/*   Event   Request     --     0                 */
	/*   Update  Request_1   --     1                 */
	/*   Update  Request_2   --     2                 */
	/*   Update  Request_n   --     n                 */
	/*   Termination Request --     n + 1             */

	/* VS: Handle the Multiple Msg type request */
	if (ccr->presence.cc_request_type == PRESENT) {
		switch(ccr->cc_request_type) {
			case INITIAL_REQUEST: {
				ccr->presence.cc_request_number = PRESENT;
				/* Make this number generic */
				ccr->cc_request_number = 0 ;

				/* TODO: Need to Check condition handling */
				ccr->presence.ip_can_type = PRESENT;
				ccr->ip_can_type = TGPP_GPRS;

				break;
			}
			case UPDATE_REQUEST:
				ccr->presence.cc_request_number = PRESENT;
				ccr->cc_request_number = ++cc_request_number ;
				break;

			case TERMINATION_REQUEST:
				ccr->presence.cc_request_number = PRESENT;
				/* Make this number generic */
				ccr->cc_request_number =  ++cc_request_number ;

				/* TODO: Need to Check condition handling */
				ccr->presence.ip_can_type = PRESENT;
				ccr->ip_can_type = TGPP_GPRS;
				break;

			default:
				clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT"Unknown "
				"Message type request %s \n", LOG_VALUE, strerror(errno));
				return -1;
		}
	}

	/* TODO: Need to Discuss to make following AVP's generic or
	 * to be based on MSG TYPE OR condition basis */

	/* Fill the APN Vaule */
	if ((pdn->apn_in_use)->apn_name_length != 0) {
		ccr->presence.called_station_id = PRESENT;

		get_apn_name((pdn->apn_in_use)->apn_name_label, apn);

		ccr->called_station_id.len = strnlen(apn, MAX_APN_LEN);
		memcpy(ccr->called_station_id.val, apn, ccr->called_station_id.len);

	}

	/* Fill the RAT type in CCR */
	if( context->rat_type.len != 0 ){
		ccr->presence.rat_type = PRESENT;
		fill_rat_type_ie(&ccr->rat_type, context->rat_type.rat_type);
	}

	/* Set the bearer eps qos values received in CSR */
	ccr->presence.default_eps_bearer_qos = PRESENT;
	fill_default_eps_bearer_qos( &(ccr->default_eps_bearer_qos),
			bearer);

	/* Set the bearer apn ambr and Uplink/Downlink MBR/GBR values received in CSR */
	if (flow_flag != 1) {
		ccr->presence.qos_information = PRESENT;
		fill_qos_info(&(ccr->qos_information), bearer, &pdn->apn_ambr);
	}

	/* Need to Handle IMSI and MSISDN */
	if( context->imsi != 0 || context->msisdn != 0 )
	{
		ccr->presence.subscription_id = PRESENT;
		fill_subscription_id( &ccr->subscription_id, context->imsi, context->msisdn );
	}

	/* TODO Need to check later on */
	if(context->mei != 0)
	{
		ccr->presence.user_equipment_info = PRESENT;
		fill_user_equipment_info( &(ccr->user_equipment_info), context->mei );
	}

	if(context->pra_flag &&
		(context->event_trigger &
			1UL << CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA_REPORT)){
		ccr->presence.presence_reporting_area_information = PRESENT;
		fill_presence_rprtng_area_info(&(ccr->presence_reporting_area_information),
														&context->pre_rptng_area_info);
		context->pra_flag = 0;
	}

	return 0;
}

void
process_create_bearer_resp_and_send_raa( int sock )
{
	char *send_buf =  NULL;
	uint32_t buflen ;

	gx_msg *resp = malloc(sizeof(gx_msg));
	memset(resp, 0, sizeof(gx_msg));

	/* Filling Header value of RAA */
	resp->msg_type = GX_RAA_MSG ;

	/* Cal the length of buffer needed */
	buflen = gx_raa_calc_length (&resp->data.cp_raa);
	resp->msg_len = buflen + GX_HEADER_LEN;

	send_buf = malloc(resp->msg_len);
	memset(send_buf, 0, resp->msg_len);

	/* encoding the raa header value to buffer */
	memcpy( send_buf, &resp->msg_type, sizeof(resp->msg_type));
	memcpy( send_buf + sizeof(resp->msg_type),
							&resp->msg_len,
						sizeof(resp->msg_len));

	if ( gx_raa_pack(&(resp->data.cp_raa),
		(unsigned char *)(send_buf + GX_HEADER_LEN),
		buflen ) == 0 ){
		clLog(clSystemLog, eCLSeverityDebug, LOG_FORMAT"RAA Packing failure on sock [%d] \n", LOG_VALUE, sock);
	}

	if (resp != NULL) {
		free(resp);
		resp = NULL;
	}
	free(send_buf);

}

int
msg_handler_gx( void )
{
	int bytes_rx = 0;
	int ret = 0;
	msg_info msg = {0};
	gx_msg *gxmsg = NULL;
	char recv_buf[BUFFSIZE] = {0};
	uint16_t msg_len = 0;

	bytes_rx = recv_from_ipc_channel(gx_app_sock_read, recv_buf);
	if(bytes_rx <= 0 ){
			close_ipc_channel(gx_app_sock_read);
			/* Greacefull Exit */
			exit(0);
	}

	while(bytes_rx > 0) {
		gxmsg = (gx_msg *)(recv_buf + msg_len);

		if ((ret = gx_pcnd_check(gxmsg, &msg)) != 0) {
			clLog(clSystemLog, eCLSeverityCritical, LOG_FORMAT" Failure in gx "
				"precondion check\n",LOG_VALUE);
			if(msg.msg_type == GX_CCA_MSG)
					gx_cca_error_response(ret, &msg);
			if(msg.msg_type == GX_RAR_MSG)
					gen_reauth_error_resp_for_wrong_seid_rcvd(&msg, gxmsg, ret);
			if(bytes_rx == gxmsg->msg_len)
				return -1;
		}else{

			if ((msg.proc < END_PROC) && (msg.state < END_STATE) && (msg.event < END_EVNT)) {
				if (SGWC == msg.cp_mode) {
				    ret = (*state_machine_sgwc[msg.proc][msg.state][msg.event])(&msg, gxmsg);
				} else if (PGWC == msg.cp_mode) {
				    ret = (*state_machine_pgwc[msg.proc][msg.state][msg.event])(&msg, gxmsg);
				} else if (SAEGWC == msg.cp_mode) {
				    ret = (*state_machine_saegwc[msg.proc][msg.state][msg.event])(&msg, gxmsg);
				} else {
					if(bytes_rx == gxmsg->msg_len)
						return -1;
				}

				if (ret) {
					if(bytes_rx == gxmsg->msg_len)
						return -1;
				}
			} else {
				if(bytes_rx == gxmsg->msg_len)
					return -1;
			}
		}
		msg_len = gxmsg->msg_len;
		bytes_rx = bytes_rx - msg_len;
	}

	return 0;
}

void
start_cp_app(void )
{
	struct sockaddr_un cp_app_sockaddr_read = {0};
	struct sockaddr_un gx_app_sockaddr_read = {0};

	/* Socket Creation */
	g_cp_sock_read = create_ipc_channel();
	if (g_cp_sock_read < 0) {
		/*Gracefully exit*/
		exit(0);
	}

	/* Bind the socket*/
	bind_ipc_channel(g_cp_sock_read, cp_app_sockaddr_read, SERVER_PATH);

	/* Mark the socket fd for listen */
	listen_ipc_channel(g_cp_sock_read);

	/* Accept incomming connection request receive on socket */
	gx_app_sock_read  = accept_from_ipc_channel( g_cp_sock_read, gx_app_sockaddr_read);
	if (g_cp_sock_read < 0) {
		/*Gracefully exit*/
		exit(0);
	}
	/* Remove this sleep to resolved the delay issue in between CSR and CCR */
	/* sleep(5); */

	int ret = -1;
	while (ret) {
		struct sockaddr_un app_sockaddr = {0};
		gx_app_sock = create_ipc_channel();
		ret = connect_to_ipc_channel(gx_app_sock, app_sockaddr, CLIENT_PATH );
		if (ret < 0) {
			printf("Trying to connect to GxApp...\n");
		}
		sleep(1);
	}

	printf("Succesfully connected to GxApp...!!!\n");

}


