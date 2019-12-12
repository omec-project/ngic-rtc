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

#include <stdint.h>

#include "gx.h"
#include "cp_app.h"
#include "ipc_api.h"

extern int g_gx_client_sock;

int
add_fd_msg(union avp_value *val, struct dict_object * obj,
		struct msg **msg_buf);

/*
*
*       Fun:    gx_send_ccr
*
*       Desc:
*
*       Ret:
*
*       Notes:  None
*
*       File:   gx_ccr.c
*
*/
int gx_send_ccr(void *data)
{

	int rval = FD_REASON_OK;
	struct msg *msg = NULL;
	char *current =  NULL;;
	struct avp *avp_ptr = NULL;;
	union avp_value val;
	int32_t offset;

	GxCCR gx_ccr = {0};

	gx_ccr_unpack((unsigned char *)data, &gx_ccr );

	/* construct the Diameter CCR  message */

	FDCHECK_MSG_NEW_APPL( gxDict.cmdCCR, gxDict.appGX, msg, rval, goto err);

	if( gx_ccr.presence.session_id )
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_session_id, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.session_id.val, gx_ccr.session_id.len, rval,goto err );

	FDCHECK_MSG_ADD_ORIGIN( msg, rval, goto err );

	//FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_host, msg, MSG_BRW_LAST_CHILD,
	//		"dstest3.test3gpp.net", strlen("dstest3.test3gpp.net"), rval, goto   err );

	FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_destination_realm, msg, MSG_BRW_LAST_CHILD,
			fd_g_config->cnf_diamrlm, fd_g_config->cnf_diamrlm_len, rval, goto err );

	FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_auth_application_id, msg, MSG_BRW_LAST_CHILD,
			gxDict.appGX, sizeof(gxDict.appGX), rval, goto err );

	if( gx_ccr.presence.cc_request_number )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_cc_request_number, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.cc_request_number, rval, goto err );

	if( gx_ccr.presence.cc_request_type )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_cc_request_type, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.cc_request_type, rval, goto err );

	if( gx_ccr.presence.credit_management_status )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_credit_management_status, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.credit_management_status, rval, goto err );

	if( gx_ccr.presence.origin_state_id )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_origin_state_id, msg, MSG_BRW_LAST_CHILD,
				fd_g_config->cnf_orstateid, rval, goto err );

	if( gx_ccr.presence.network_request_support )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_network_request_support, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.network_request_support, rval, goto err );

	if( gx_ccr.presence.packet_filter_operation )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_packet_filter_operation, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.packet_filter_operation, rval, goto err );

	if( gx_ccr.presence.bearer_operation )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_bearer_operation, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.bearer_operation, rval, goto err );

	if( gx_ccr.presence.dynamic_address_flag )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_dynamic_address_flag, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.dynamic_address_flag, rval, goto err );

	if( gx_ccr.presence.dynamic_address_flag_extension )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_dynamic_address_flag_extension, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.dynamic_address_flag_extension, rval, goto err );

	if( gx_ccr.presence.pdn_connection_charging_id )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_pdn_connection_charging_id, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.pdn_connection_charging_id, rval, goto err );

	if( gx_ccr.presence.ip_can_type )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_ip_can_type, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.ip_can_type, rval, goto err );

	if( gx_ccr.presence.an_trusted )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_an_trusted, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.an_trusted, rval, goto err );

	if( gx_ccr.presence.rat_type )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_rat_type, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.rat_type, rval, goto err );

	if( gx_ccr.presence.termination_cause )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_termination_cause, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.termination_cause, rval, goto err );

	if( gx_ccr.presence.qos_negotiation )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_qos_negotiation, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.qos_negotiation, rval, goto err );

	if( gx_ccr.presence.qos_upgrade )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_qos_upgrade, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.qos_upgrade, rval, goto err );

	if( gx_ccr.presence.an_gw_status )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_an_gw_status, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.an_gw_status, rval, goto err );

	if( gx_ccr.presence.rai )
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_rai, msg, MSG_BRW_LAST_CHILD, gx_ccr.rai.val,
				gx_ccr.rai.len, rval, goto err );

	if( gx_ccr.presence.bearer_usage )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_bearer_usage, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.bearer_usage, rval, goto err );

	if( gx_ccr.presence.online )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_online, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.online, rval, goto err );

	if( gx_ccr.presence.offline )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_offline, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.offline, rval, goto err );

	if( gx_ccr.presence.nbifom_support )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_nbifom_support, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.nbifom_support, rval, goto err );

	if( gx_ccr.presence.nbifom_mode )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_nbifom_mode, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.nbifom_mode, rval, goto err );

	if( gx_ccr.presence.default_access )
		FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_default_access, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.default_access, rval, goto err );

	if( gx_ccr.presence.origination_time_stamp )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_origination_time_stamp, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.origination_time_stamp, rval, goto err );

	if( gx_ccr.presence.maximum_wait_time )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_maximum_wait_time, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.maximum_wait_time, rval, goto err );

	if( gx_ccr.presence.access_availability_change_reason )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_access_availability_change_reason, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.access_availability_change_reason, rval, goto err );

	if( gx_ccr.presence.user_location_info_time )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_user_location_info_time, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.user_location_info_time, rval, goto err );

	if( gx_ccr.presence.udp_source_port )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_udp_source_port, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.udp_source_port, rval, goto err );

	if( gx_ccr.presence.tcp_source_port )
		FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_tcp_source_port, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.tcp_source_port, rval, goto err );

	if( gx_ccr.presence.access_network_charging_address)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_access_network_charging_address, msg, MSG_BRW_LAST_CHILD,
				gx_ccr.access_network_charging_address.address,
				strlen(gx_ccr.access_network_charging_address.address), rval, goto err );

	if( gx_ccr.presence.bearer_identifier)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_bearer_identifier, msg, MSG_BRW_LAST_CHILD, gx_ccr.bearer_identifier.val,
				gx_ccr.bearer_identifier.len, rval, goto err );

	if( gx_ccr.presence.tgpp_charging_characteristics)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_3gpp_charging_characteristics, msg,
				MSG_BRW_LAST_CHILD, gx_ccr.tgpp_charging_characteristics.val,
				gx_ccr.tgpp_charging_characteristics.len, rval, goto err );

	if( gx_ccr.presence.called_station_id)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_called_station_id, msg, MSG_BRW_LAST_CHILD, gx_ccr.called_station_id.val,
				gx_ccr.called_station_id.len, rval, goto err );

	if( gx_ccr.presence.pdn_connection_id)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_pdn_connection_id, msg, MSG_BRW_LAST_CHILD, gx_ccr.pdn_connection_id.val,
				gx_ccr.pdn_connection_id.len, rval, goto err );

	if( gx_ccr.presence.framed_ip_address)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_framed_ip_address, msg, MSG_BRW_LAST_CHILD, gx_ccr.framed_ip_address.val,
				gx_ccr.framed_ip_address.len, rval, goto err );

	if( gx_ccr.presence.framed_ipv6_prefix)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_framed_ipv6_prefix, msg, MSG_BRW_LAST_CHILD, gx_ccr.framed_ipv6_prefix.val,
				gx_ccr.framed_ipv6_prefix.len, rval, goto err );

	if( gx_ccr.presence.tgpp_rat_type)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_3gpp_rat_type, msg, MSG_BRW_LAST_CHILD, gx_ccr.tgpp_rat_type.val,
				gx_ccr.tgpp_rat_type.len, rval, goto err );

	if( gx_ccr.presence.twan_identifier)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_twan_identifier, msg, MSG_BRW_LAST_CHILD, gx_ccr.twan_identifier.val,
				gx_ccr.twan_identifier.len, rval, goto err );

	if( gx_ccr.presence.tgpp_ms_timezone)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_3gpp_ms_timezone, msg, MSG_BRW_LAST_CHILD, gx_ccr.tgpp_ms_timezone.val,
				gx_ccr.tgpp_ms_timezone.len, rval, goto err );

	if( gx_ccr.presence.tgpp_user_location_info)
		FDCHECK_MSG_ADD_AVP_OSTR( gxDict.avp_3gpp_user_location_info, msg,
				MSG_BRW_LAST_CHILD, gx_ccr.tgpp_user_location_info.val,
				gx_ccr.tgpp_user_location_info.len, rval, goto err );

	if(gx_ccr.presence.fixed_user_location_info ){

		if(gx_ccr.fixed_user_location_info.presence.ssid){
			val.os.len = gx_ccr.fixed_user_location_info.ssid.len;
			val.os.data = gx_ccr.fixed_user_location_info.ssid.val;
			add_fd_msg(&val, gxDict.avp_ssid, (struct msg**)&avp_ptr);
		}

		if(gx_ccr.fixed_user_location_info.presence.bssid){
			val.os.len = gx_ccr.fixed_user_location_info.bssid.len;
			val.os.data = gx_ccr.fixed_user_location_info.bssid.val;
			add_fd_msg(&val, gxDict.avp_bssid, (struct msg**)&avp_ptr);
		}

		if(gx_ccr.fixed_user_location_info.presence.logical_access_id){
			val.os.len = gx_ccr.fixed_user_location_info.logical_access_id.len;
			val.os.data = gx_ccr.fixed_user_location_info.logical_access_id.val;
			add_fd_msg(&val, gxDict.avp_logical_access_id, (struct msg**)&avp_ptr);
		}

		if(gx_ccr.fixed_user_location_info.presence.physical_access_id){
			val.os.len = gx_ccr.fixed_user_location_info.physical_access_id.len;
			val.os.data = gx_ccr.fixed_user_location_info.physical_access_id.val;
			add_fd_msg(&val, gxDict.avp_physical_access_id, (struct msg**)&avp_ptr);
		}
	}

		if( gx_ccr.presence.user_csg_information ){

			if( gx_ccr.user_csg_information.presence.csg_id ){
				val.u32 =  gx_ccr.user_csg_information.csg_id;
				add_fd_msg(&val, gxDict.avp_csg_id, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.user_csg_information.presence.csg_access_mode ){
				val.i32 =  gx_ccr.user_csg_information.csg_access_mode;
				add_fd_msg(&val, gxDict.avp_csg_access_mode, (struct msg**)&avp_ptr);
			}
			if( gx_ccr.user_csg_information.presence.csg_membership_indication ){
				val.i32 =  gx_ccr.user_csg_information.csg_membership_indication;
				add_fd_msg(&val, gxDict.avp_csg_membership_indication, (struct msg**)&avp_ptr);
			}
		}

	if(gx_ccr.presence.oc_supported_features &&
			gx_ccr.oc_supported_features.presence.oc_feature_vector ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_oc_supported_features,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		val.u64 = gx_ccr.oc_supported_features.oc_feature_vector;
		add_fd_msg(&val, gxDict.avp_oc_feature_vector, (struct msg**)&avp_ptr);
	}

	if( gx_ccr.presence.tdf_information){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_tdf_information, 0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		if( gx_ccr.tdf_information.presence.tdf_destination_realm ){
			val.os.len = gx_ccr.tdf_information.tdf_destination_realm.len;
			val.os.data = gx_ccr.tdf_information.tdf_destination_realm.val;
			add_fd_msg(&val, gxDict.avp_tdf_destination_realm, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.tdf_information.presence.tdf_destination_host ){
			val.os.len = gx_ccr.tdf_information.tdf_destination_host.len;
			val.os.data = gx_ccr.tdf_information.tdf_destination_host.val;
			add_fd_msg(&val, gxDict.avp_tdf_destination_host, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.tdf_information.presence.tdf_ip_address){
			/* need to fill address on the basis of type*/
			val.os.data = gx_ccr.tdf_information.tdf_ip_address.address;
			add_fd_msg(&val, gxDict.avp_tdf_ip_address, (struct msg**)&avp_ptr);
		}
	}

	if( gx_ccr.presence.user_equipment_info){
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_user_equipment_info,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		if( gx_ccr.user_equipment_info.presence.user_equipment_info_type){
			val.i32 = gx_ccr.user_equipment_info.user_equipment_info_type;
			add_fd_msg(&val, gxDict.avp_user_equipment_info_type, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.user_equipment_info.presence.user_equipment_info_value){
			val.os.len = gx_ccr.user_equipment_info.user_equipment_info_value.len;
			val.os.data = gx_ccr.user_equipment_info.user_equipment_info_value.val;
			add_fd_msg(&val, gxDict.avp_user_equipment_info_value, (struct msg**)&avp_ptr);
		}
	}

	/* Adding Subscription Id list params */
	if( gx_ccr.presence.subscription_id ){
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_subscription_id,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i=0; i < gx_ccr.subscription_id.count; i++){

			if( gx_ccr.subscription_id.list[i].presence.subscription_id_type ){
				val.i32 = gx_ccr.subscription_id.list[i].subscription_id_type;
				add_fd_msg(&val, gxDict.avp_subscription_id_type, (struct msg**)&avp_ptr);
			}
			if( gx_ccr.subscription_id.list[i].presence.subscription_id_data ){
				val.os.len = gx_ccr.subscription_id.list[i].subscription_id_data.len;
				val.os.data = gx_ccr.subscription_id.list[i].subscription_id_data.val;
				add_fd_msg(&val, gxDict.avp_subscription_id_data, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding Supported feature list params */
	if( gx_ccr.presence.supported_features ){
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_supported_features,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for(int i=0; i < gx_ccr.supported_features.count; i++){

			if( gx_ccr.supported_features.list[i].presence.vendor_id ){
				val.u32 = gx_ccr.supported_features.list[i].vendor_id;
				add_fd_msg(&val, gxDict.avp_vendor_id, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.supported_features.list[i].presence.feature_list_id ){
				val.u32 = gx_ccr.supported_features.list[i].feature_list_id;
				add_fd_msg(&val, gxDict.avp_feature_list_id, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.supported_features.list[i].presence.feature_list ){
				val.u32 = gx_ccr.supported_features.list[i].feature_list;
				add_fd_msg(&val, gxDict.avp_feature_list, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding avp_packet_filter_information list params */
	if( gx_ccr.presence.packet_filter_information ){
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_packet_filter_information, 0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for(int i=0; i < gx_ccr.packet_filter_information.count; i++){

			if( gx_ccr.packet_filter_information.list[i].presence.packet_filter_identifier ){
				val.os.len = gx_ccr.packet_filter_information.list[i].packet_filter_identifier.len;
				val.os.data = gx_ccr.packet_filter_information.list[i].packet_filter_identifier.val;
				add_fd_msg(&val, gxDict.avp_packet_filter_identifier, (struct msg**)&avp_ptr);
			}
			if( gx_ccr.packet_filter_information.list[i].presence.precedence ){
				val.u32 = gx_ccr.packet_filter_information.list[i].precedence;
				add_fd_msg(&val, gxDict.avp_precedence, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.packet_filter_information.list[i].presence.packet_filter_content ){
				val.os.len = gx_ccr.packet_filter_information.list[i].packet_filter_content.len;
				val.os.data = gx_ccr.packet_filter_information.list[i].packet_filter_content.val;
				add_fd_msg(&val, gxDict.avp_packet_filter_content, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.packet_filter_information.list[i].presence.tos_traffic_class){
				val.os.len = gx_ccr.packet_filter_information.list[i].tos_traffic_class.len;
				val.os.data = gx_ccr.packet_filter_information.list[i].tos_traffic_class.val;
				add_fd_msg(&val, gxDict.avp_tos_traffic_class, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.packet_filter_information.list[i].presence.security_parameter_index ){
				val.os.len = gx_ccr.packet_filter_information.list[i].security_parameter_index.len;
				val.os.data = gx_ccr.packet_filter_information.list[i].security_parameter_index.val;
				add_fd_msg(&val, gxDict.avp_security_parameter_index, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.packet_filter_information.list[i].presence.flow_label ){
				val.os.len = gx_ccr.packet_filter_information.list[i].flow_label.len;
				val.os.data = gx_ccr.packet_filter_information.list[i].flow_label.val;
				add_fd_msg(&val, gxDict.avp_flow_label, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.packet_filter_information.list[i].presence.flow_direction ){
				val.i32 = gx_ccr.packet_filter_information.list[i].flow_direction;
				add_fd_msg(&val, gxDict.avp_flow_direction, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding Qos info */
	if( gx_ccr.presence.qos_information ){
		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_qos_information, 0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		if( gx_ccr.qos_information.presence.qos_class_identifier ){
			val.i32 = gx_ccr.qos_information.qos_class_identifier;
			add_fd_msg(&val,gxDict.avp_qos_class_identifier ,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.max_requested_bandwidth_ul ){
			val.u32 = gx_ccr.qos_information.max_requested_bandwidth_ul;
			add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.max_requested_bandwidth_dl ){
			val.u32 = gx_ccr.qos_information.max_requested_bandwidth_dl;
			add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_max_requested_bw_ul ){
			val.u32 = gx_ccr.qos_information.extended_max_requested_bw_ul;
			add_fd_msg(&val,gxDict.avp_extended_max_requested_bw_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_max_requested_bw_dl ){
			val.u32 = gx_ccr.qos_information.extended_max_requested_bw_dl;
			add_fd_msg(&val,gxDict.avp_extended_max_requested_bw_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.guaranteed_bitrate_ul ){
			val.u32 = gx_ccr.qos_information.guaranteed_bitrate_ul;
			add_fd_msg(&val,gxDict.avp_guaranteed_bitrate_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.guaranteed_bitrate_dl ){
			val.u32 = gx_ccr.qos_information.guaranteed_bitrate_dl;
			add_fd_msg(&val,gxDict.avp_guaranteed_bitrate_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_gbr_ul ){
			val.u32 = gx_ccr.qos_information.extended_gbr_ul;
			add_fd_msg(&val,gxDict.avp_extended_gbr_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_gbr_dl ){
			val.u32 = gx_ccr.qos_information.extended_gbr_dl;
			add_fd_msg(&val,gxDict.avp_extended_gbr_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.bearer_identifier ){
			val.os.len = gx_ccr.qos_information.bearer_identifier.len;
			val.os.data = gx_ccr.qos_information.bearer_identifier.val;
			add_fd_msg(&val, gxDict.avp_bearer_identifier, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.allocation_retention_priority.presence.priority_level ){
			val.u32 = gx_ccr.qos_information.allocation_retention_priority.priority_level;
			add_fd_msg(&val,gxDict.avp_priority_level,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.allocation_retention_priority.presence.pre_emption_capability ){
			val.i32 = gx_ccr.qos_information.allocation_retention_priority.pre_emption_capability;
			add_fd_msg(&val,gxDict.avp_pre_emption_capability,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.allocation_retention_priority.presence.pre_emption_vulnerability ){
			val.i32 = gx_ccr.qos_information.allocation_retention_priority.pre_emption_vulnerability;
			add_fd_msg(&val,gxDict.avp_pre_emption_vulnerability,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.apn_aggregate_max_bitrate_ul ){
			val.u32 = gx_ccr.qos_information.apn_aggregate_max_bitrate_ul;
			add_fd_msg(&val,gxDict.avp_apn_aggregate_max_bitrate_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.apn_aggregate_max_bitrate_dl ){
			val.u32 = gx_ccr.qos_information.apn_aggregate_max_bitrate_dl;
			add_fd_msg(&val,gxDict.avp_apn_aggregate_max_bitrate_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_apn_ambr_ul){
			val.u32 = gx_ccr.qos_information.extended_apn_ambr_ul;
			add_fd_msg(&val,gxDict.avp_extended_apn_ambr_ul,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.extended_apn_ambr_dl){
			val.u32 = gx_ccr.qos_information.extended_apn_ambr_dl;
			add_fd_msg(&val,gxDict.avp_extended_apn_ambr_dl,(struct msg**)&avp_ptr);
		}

		if( gx_ccr.qos_information.presence.conditional_apn_aggregate_max_bitrate ){
			for(int i=0; i < gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.count; i++){

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.list[i].
						presence.apn_aggregate_max_bitrate_ul ){
					val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].apn_aggregate_max_bitrate_ul;
					add_fd_msg(&val,gxDict.avp_apn_aggregate_max_bitrate_ul,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].presence.apn_aggregate_max_bitrate_dl ){
					val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].apn_aggregate_max_bitrate_dl;
					add_fd_msg(&val,gxDict.avp_apn_aggregate_max_bitrate_dl,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.list[i].
						presence.extended_apn_ambr_ul ){
					val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].extended_apn_ambr_ul;
					add_fd_msg(&val,gxDict.avp_extended_apn_ambr_ul,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.list[i].
						presence.extended_apn_ambr_dl ){
					val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].extended_apn_ambr_dl;
					add_fd_msg(&val,gxDict.avp_extended_apn_ambr_dl,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].presence.ip_can_type ){

					for(int k = 0; k < gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
							list[i].ip_can_type.count; k++){
						val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
							list[i].ip_can_type.list[k];
						add_fd_msg(&val,gxDict.avp_ip_can_type,(struct msg**)&avp_ptr);
					}
				}

				if( gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
						list[i].presence.rat_type ){
					for(int k = 0; k < gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.
							list[i].rat_type.count; k++){
						val.u32 = gx_ccr.qos_information.conditional_apn_aggregate_max_bitrate.list[i].rat_type.list[k];
						add_fd_msg(&val,gxDict.avp_rat_type,(struct msg**)&avp_ptr);
					}
				}
			}
		}
	}

	/* Adding an gw address params */
	if( gx_ccr.presence.an_gw_address ){

		for(int r=0; r < gx_ccr.an_gw_address.count; r++){
			val.os.len = (gx_ccr.an_gw_address.count) * sizeof(FdAddress) ;
			val.os.data = gx_ccr.an_gw_address.list[r].address;
			/*TODO : Need to fill an_gw_address on the basis of type */
			add_fd_msg(&val,gxDict.avp_an_gw_address,(struct msg**)&avp_ptr);
		}
	}

	/* Adding ran_nas_release_cause  params*/
	if( gx_ccr.presence.ran_nas_release_cause ){

		for(int i=0; i < gx_ccr.ran_nas_release_cause.count; i++){
			val.os.len = gx_ccr.ran_nas_release_cause.list[i].len;
			val.os.data = gx_ccr.ran_nas_release_cause.list[i].val;
			add_fd_msg(&val, gxDict.avp_ran_nas_release_cause, (struct msg**)&avp_ptr);
		}
	}

	/* Adding packet filter info  params */
	if( gx_ccr.presence.tft_packet_filter_information ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_tft_packet_filter_information ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for(int i=0; i < gx_ccr.tft_packet_filter_information.count; i++){

			if( gx_ccr.tft_packet_filter_information.list[i].presence.precedence ){
				val.u32 = gx_ccr.tft_packet_filter_information.list[i].precedence;
				add_fd_msg(&val, gxDict.avp_precedence, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.tft_packet_filter_information.list[i].presence.tft_filter ){
				val.os.len = gx_ccr.tft_packet_filter_information.list[i].tft_filter.len;
				val.os.data = gx_ccr.tft_packet_filter_information.list[i].tft_filter.val;
				add_fd_msg(&val, gxDict.avp_tft_filter, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.tft_packet_filter_information.list[i].presence.tos_traffic_class){
				val.os.len = gx_ccr.tft_packet_filter_information.list[i].tos_traffic_class.len;
				val.os.data = gx_ccr.tft_packet_filter_information.list[i].tos_traffic_class.val;
				add_fd_msg(&val, gxDict.avp_tos_traffic_class, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.tft_packet_filter_information.list[i].presence.security_parameter_index ){
				val.os.len = gx_ccr.tft_packet_filter_information.list[i].security_parameter_index.len;
				val.os.data = gx_ccr.tft_packet_filter_information.list[i].security_parameter_index.val;
				add_fd_msg(&val, gxDict.avp_security_parameter_index, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.tft_packet_filter_information.list[i].presence.flow_label ){
				val.os.len = gx_ccr.tft_packet_filter_information.list[i].flow_label.len;
				val.os.data = gx_ccr.tft_packet_filter_information.list[i].flow_label.val;
				add_fd_msg(&val, gxDict.avp_flow_label, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.tft_packet_filter_information.list[i].presence.flow_direction ){
				val.i32 = gx_ccr.tft_packet_filter_information.list[i].flow_direction;
				add_fd_msg(&val, gxDict.avp_flow_direction, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding charging rule report  params */
	if( gx_ccr.presence.charging_rule_report ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_charging_rule_report ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for(int i = 0; i < gx_ccr.charging_rule_report.count; i++){

			if( gx_ccr.charging_rule_report.list[i].presence.charging_rule_name ){

				for(int k = 0; k < gx_ccr.charging_rule_report.list[i].charging_rule_name.count; k++){
					val.os.len = gx_ccr.charging_rule_report.list[i].
						charging_rule_name.list[k].len ;
					val.os.data = gx_ccr.charging_rule_report.list[i].
						charging_rule_name.list[k].val;
					add_fd_msg(&val,gxDict.avp_charging_rule_name,(struct msg**)&avp_ptr);
				}
			}

			if(  gx_ccr.charging_rule_report.list[i].presence.charging_rule_base_name ){

				for(int k = 0; k < gx_ccr.charging_rule_report.list[i].
						charging_rule_base_name.count; k++){
					val.os.len =  gx_ccr.charging_rule_report.list[i].
						charging_rule_base_name.list[k].len ;
					val.os.data = gx_ccr.charging_rule_report.list[i].
						charging_rule_base_name.list[k].val;
					add_fd_msg(&val,gxDict.avp_charging_rule_base_name,(struct msg**)&avp_ptr);
				}
			}

			if( gx_ccr.charging_rule_report.list[i].presence.bearer_identifier ){
				val.os.len = gx_ccr.charging_rule_report.list[i].
					bearer_identifier.len;
				val.os.data = gx_ccr.charging_rule_report.list[i].bearer_identifier.val;
				add_fd_msg(&val, gxDict.avp_bearer_identifier, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.charging_rule_report.list[i].presence.pcc_rule_status ){
				val.i32 = gx_ccr.charging_rule_report.list[i].pcc_rule_status;
				add_fd_msg(&val, gxDict.avp_pcc_rule_status, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.charging_rule_report.list[i].presence.rule_failure_code ){
				val.i32 = gx_ccr.charging_rule_report.list[i].rule_failure_code;
				add_fd_msg(&val, gxDict.avp_rule_failure_code, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.charging_rule_report.list[i].presence.final_unit_indication){

				if( gx_ccr.charging_rule_report.list[i].final_unit_indication.
						presence.final_unit_action){
					val.i32 = gx_ccr.charging_rule_report.list[i].
						final_unit_indication.final_unit_action;
					add_fd_msg(&val, gxDict.avp_final_unit_action, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.charging_rule_report.list[i].final_unit_indication.
						presence.restriction_filter_rule ){

					for(int k = 0; k < gx_ccr.charging_rule_report.list[i].final_unit_indication.
							restriction_filter_rule.count; k++){

						val.os.len = gx_ccr.charging_rule_report.list[i].final_unit_indication.
							restriction_filter_rule.list[k].len ;
						val.os.data = gx_ccr.charging_rule_report.list[i].final_unit_indication.
							restriction_filter_rule.list[k].val;
						add_fd_msg(&val,gxDict.avp_restriction_filter_rule, (struct msg**)&avp_ptr);
					}
				}

				if( gx_ccr.charging_rule_report.list[i].final_unit_indication.presence.filter_id ){

					for(int k = 0; k < gx_ccr.charging_rule_report.list[i].
							final_unit_indication.filter_id.count; k++ ){
						val.os.len = gx_ccr.charging_rule_report.list[i].
							final_unit_indication.filter_id.list[k].len ;
						val.os.data = gx_ccr.charging_rule_report.list[i].
							final_unit_indication.filter_id.list[k].val;
						add_fd_msg(&val,gxDict.avp_filter_id, (struct msg**)&avp_ptr);
					}
				}

				if( gx_ccr.charging_rule_report.list[i].final_unit_indication.presence.redirect_server ){

					if( gx_ccr.charging_rule_report.list[i].final_unit_indication.
							redirect_server.presence.redirect_address_type){
						val.i32 = gx_ccr.charging_rule_report.list[i].final_unit_indication.
							redirect_server.redirect_address_type;
						add_fd_msg(&val, gxDict.avp_redirect_address_type, (struct msg**)&avp_ptr);
					}

					if(gx_ccr.charging_rule_report.list[i].final_unit_indication.
							redirect_server.presence.redirect_server_address ){
						val.os.len = gx_ccr.charging_rule_report.list[i].
							final_unit_indication.redirect_server.redirect_server_address.len;
						val.os.data = gx_ccr.charging_rule_report.list[i].
							final_unit_indication.redirect_server.redirect_server_address.val;
						add_fd_msg(&val, gxDict.avp_redirect_server_address, (struct msg**)&avp_ptr);
					}
				}
			}

			if( gx_ccr.charging_rule_report.list[i].presence.ran_nas_release_cause){

				for(int k = 0; k < gx_ccr.charging_rule_report.list[i].ran_nas_release_cause.count; k++){

					val.os.len = gx_ccr.charging_rule_report.list[i].ran_nas_release_cause.list[k].len;
					val.os.data = gx_ccr.charging_rule_report.list[i].ran_nas_release_cause.list[k].val;
					add_fd_msg(&val,gxDict.avp_ran_nas_release_cause, (struct msg**)&avp_ptr);
				}
			}

			if( gx_ccr.charging_rule_report.list[i].presence.content_version){

				for(int k = 0; k < gx_ccr.charging_rule_report.list[i].content_version.count; k++ ){
					val.u64 = gx_ccr.charging_rule_report.list[i].content_version.list[k] ;
					add_fd_msg(&val,gxDict.avp_content_version, (struct msg**)&avp_ptr);
				}
			}
		}
	}

	/* Adding application detection info  params */
	if( gx_ccr.presence.application_detection_information ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_application_detection_information ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.application_detection_information.count; i++){

			if( gx_ccr.application_detection_information.list[i].presence.
					tdf_application_identifier){
				val.os.len = gx_ccr.application_detection_information.list[i].
					tdf_application_identifier.len;
				val.os.data = gx_ccr.application_detection_information.list[i].
					tdf_application_identifier.val;
				add_fd_msg(&val,gxDict.avp_tdf_application_identifier, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.application_detection_information.list[i].presence.
					tdf_application_instance_identifier ){
				val.os.len = gx_ccr.application_detection_information.list[i].
					tdf_application_instance_identifier.len;
				val.os.data = gx_ccr.application_detection_information.list[i].
					tdf_application_instance_identifier.val;
				add_fd_msg(&val,gxDict.avp_tdf_application_instance_identifier, (struct msg**)&avp_ptr);
			}
			if( gx_ccr.application_detection_information.list[i].presence.flow_information ){

				for( int j = 0; j < gx_ccr.application_detection_information.list[i].
						flow_information.count; j++){

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.flow_description ){
						val.os.len = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].flow_description.len;
						val.os.data = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].flow_description.val;
						add_fd_msg(&val,gxDict.avp_flow_description, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.packet_filter_identifier){
						val.os.len = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].packet_filter_identifier.len;
						val.os.data = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].packet_filter_identifier.val;
						add_fd_msg(&val,gxDict.avp_packet_filter_identifier, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.packet_filter_usage ){
						val.i32 = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].packet_filter_usage;
						add_fd_msg(&val, gxDict.avp_packet_filter_usage, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.tos_traffic_class ){
						val.os.len = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].tos_traffic_class.len;
						val.os.data = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].tos_traffic_class.val;
						add_fd_msg(&val,gxDict.avp_tos_traffic_class, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.security_parameter_index){
						val.os.len = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].security_parameter_index.len;
						val.os.data = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].security_parameter_index.val;
						add_fd_msg(&val,gxDict.avp_security_parameter_index, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.flow_label ){
						val.os.len = gx_ccr.application_detection_information.list[i].flow_information.
							list[j].flow_label.len;
						val.os.data = gx_ccr.application_detection_information.list[i].flow_information.
							list[j].flow_label.val;
						add_fd_msg(&val,gxDict.avp_flow_label, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.flow_direction){
						val.i32 = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].flow_direction;
						add_fd_msg(&val, gxDict.avp_flow_direction, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.application_detection_information.list[i].flow_information.
							list[j].presence.routing_rule_identifier){
						val.os.len = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].routing_rule_identifier.len;
						val.os.data = gx_ccr.application_detection_information.list[i].
							flow_information.list[j].routing_rule_identifier.val;
						add_fd_msg(&val,gxDict.avp_routing_rule_identifier, (struct msg**)&avp_ptr);
					}
				}
			}
		}
	}

	/* Adding trigger list info  params */
	if( gx_ccr.presence.event_trigger ){

		for( int k = 0 ; k < gx_ccr.event_trigger.count; k++ ){
			val.u32 = gx_ccr.event_trigger.list[k];
			add_fd_msg(&val,gxDict.avp_event_trigger, (struct msg**)&avp_ptr);
		}
	}

	/* Adding event report ind params */
	if( gx_ccr.presence.event_report_indication ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_event_report_indication ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		if( gx_ccr.event_report_indication.presence.an_trusted ){
			val.i32 =  gx_ccr.event_report_indication.an_trusted;
			add_fd_msg(&val, gxDict.avp_an_trusted, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.event_trigger ){
			for(int j = 0; j < gx_ccr.event_report_indication.event_trigger.count ; j++){
				val.u32 = gx_ccr.event_report_indication.event_trigger.list[j];
				add_fd_msg(&val,gxDict.avp_event_trigger, (struct msg**)&avp_ptr);
			}
		}

		if( gx_ccr.event_report_indication.presence.user_csg_information ){

			if( gx_ccr.event_report_indication.user_csg_information.presence.csg_id ){
				val.u32 =  gx_ccr.event_report_indication.user_csg_information.csg_id;
				add_fd_msg(&val, gxDict.avp_csg_id, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.user_csg_information.presence.csg_access_mode ){
				val.i32 =  gx_ccr.event_report_indication.user_csg_information.csg_access_mode;
				add_fd_msg(&val, gxDict.avp_csg_access_mode, (struct msg**)&avp_ptr);
			}
			if( gx_ccr.event_report_indication.user_csg_information.presence.csg_membership_indication ){
				val.i32 =  gx_ccr.event_report_indication.user_csg_information.csg_membership_indication;
				add_fd_msg(&val, gxDict.avp_csg_membership_indication, (struct msg**)&avp_ptr);
			}
		}


		if( gx_ccr.event_report_indication.presence.ip_can_type ){
			val.i32 =  gx_ccr.event_report_indication.ip_can_type;
			add_fd_msg(&val, gxDict.avp_ip_can_type, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.an_gw_address ){

			for(int r = 0; r < gx_ccr.event_report_indication.an_gw_address.count; r++){
				val.os.len = (gx_ccr.event_report_indication.an_gw_address.count) * sizeof(FdAddress) ;
				val.os.data = gx_ccr.event_report_indication.an_gw_address.list[r].address;
				/*TODO : Need to fill an_gw_address on the basis of type and length */
				add_fd_msg(&val,gxDict.avp_an_gw_address,(struct msg**)&avp_ptr);
			}
		}

		if( gx_ccr.event_report_indication.presence.tgpp_sgsn_address){
			val.os.len = (gx_ccr.event_report_indication.tgpp_sgsn_address.len);
			val.os.data = gx_ccr.event_report_indication.tgpp_sgsn_address.val;
			add_fd_msg(&val,gxDict.avp_3gpp_sgsn_address, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.tgpp_sgsn_ipv6_address){
			val.os.len = (gx_ccr.event_report_indication.tgpp_sgsn_ipv6_address.len);
			val.os.data = gx_ccr.event_report_indication.tgpp_sgsn_ipv6_address.val;
			add_fd_msg(&val,gxDict.avp_3gpp_sgsn_ipv6_address, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.tgpp_sgsn_mcc_mnc){
			val.os.len = (gx_ccr.event_report_indication.tgpp_sgsn_mcc_mnc.len);
			val.os.data = gx_ccr.event_report_indication.tgpp_sgsn_mcc_mnc.val;
			add_fd_msg(&val,gxDict.avp_3gpp_sgsn_mcc_mnc, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.framed_ip_address){
			val.os.len = (gx_ccr.event_report_indication.framed_ip_address.len);
			val.os.data = gx_ccr.event_report_indication.framed_ip_address.val;
			add_fd_msg(&val,gxDict.avp_framed_ip_address, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.rat_type){
			val.i32 =  gx_ccr.event_report_indication.rat_type;
			add_fd_msg(&val, gxDict.avp_rat_type, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.rai){
			val.os.len = (gx_ccr.event_report_indication.rai.len);
			val.os.data = gx_ccr.event_report_indication.rai.val;
			add_fd_msg(&val,gxDict.avp_rai, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.tgpp_user_location_info){
			val.os.len = (gx_ccr.event_report_indication.tgpp_user_location_info.len);
			val.os.data = gx_ccr.event_report_indication.tgpp_user_location_info.val;
			add_fd_msg(&val,gxDict.avp_3gpp_user_location_info, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.rai){
			val.os.len = (gx_ccr.event_report_indication.rai.len);
			val.os.data = gx_ccr.event_report_indication.rai.val;
			add_fd_msg(&val,gxDict.avp_rai, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.trace_data){

			if( gx_ccr.event_report_indication.trace_data.presence.trace_reference){
				val.os.len = (gx_ccr.event_report_indication.trace_data.trace_reference.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_reference.val;
				add_fd_msg(&val,gxDict.avp_trace_reference, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_depth){
				val.i32 =  gx_ccr.event_report_indication.trace_data.trace_depth;
				add_fd_msg(&val, gxDict.avp_trace_depth, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_ne_type_list){
				val.os.len = (gx_ccr.event_report_indication.trace_data.trace_ne_type_list.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_ne_type_list.val;
				add_fd_msg(&val,gxDict.avp_trace_ne_type_list, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_ne_type_list){
				val.os.len = (gx_ccr.event_report_indication.trace_data.trace_ne_type_list.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_ne_type_list.val;
				add_fd_msg(&val,gxDict.avp_trace_ne_type_list, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_interface_list){
				val.os.len = (gx_ccr.event_report_indication.trace_data.trace_interface_list.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_interface_list.val;
				add_fd_msg(&val,gxDict.avp_trace_interface_list, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_event_list){
				val.os.len = (gx_ccr.event_report_indication.trace_data.trace_event_list.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_event_list.val;
				add_fd_msg(&val,gxDict.avp_trace_event_list, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.omc_id){
				val.os.len = (gx_ccr.event_report_indication.trace_data.omc_id.len);
				val.os.data = gx_ccr.event_report_indication.trace_data.omc_id.val;
				add_fd_msg(&val,gxDict.avp_omc_id, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.event_report_indication.trace_data.presence.trace_collection_entity){
				/*TODO :need to addres on the basis of type in Fdaddress  */
				val.os.len = strlen(gx_ccr.event_report_indication.trace_data.trace_collection_entity.address);
				val.os.data = gx_ccr.event_report_indication.trace_data.trace_collection_entity.address;
				add_fd_msg(&val,gxDict.avp_trace_collection_entity, (struct msg**)&avp_ptr);

			}

			if( gx_ccr.event_report_indication.trace_data.presence.mdt_configuration){

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.job_type){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.job_type;
					add_fd_msg(&val, gxDict.avp_job_type, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.area_scope){

					if( gx_ccr.event_report_indication.trace_data.mdt_configuration.
							area_scope.presence.cell_global_identity ){

						for(int k = 0; k < gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.cell_global_identity.count; k++ ){
							val.os.len = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.cell_global_identity.list[k].len;
							val.os.data = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.cell_global_identity.list[k].val;
							add_fd_msg(&val,gxDict.avp_cell_global_identity, (struct msg**)&avp_ptr);
						}

					}
					if( gx_ccr.event_report_indication.trace_data.mdt_configuration.
							area_scope.presence.e_utran_cell_global_identity){

						for(int k = 0; k < gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.e_utran_cell_global_identity.count; k++ ){
							val.os.len = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.e_utran_cell_global_identity.list[k].len;
							val.os.data = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.e_utran_cell_global_identity.list[k].val;
							add_fd_msg(&val,gxDict.avp_e_utran_cell_global_identity, (struct msg**)&avp_ptr);
						}
					}
					if( gx_ccr.event_report_indication.trace_data.mdt_configuration.
							area_scope.presence.routing_area_identity){

						for(int k = 0; k < gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.routing_area_identity.count; k++ ){
							val.os.len = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.routing_area_identity.list[k].len;
							val.os.data = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.routing_area_identity.list[k].val;
							add_fd_msg(&val,gxDict.avp_routing_area_identity, (struct msg**)&avp_ptr);
						}
					}

					if( gx_ccr.event_report_indication.trace_data.mdt_configuration.
							area_scope.presence.tracking_area_identity){

						for(int k = 0; k < gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.tracking_area_identity.count; k++ ){
							val.os.len = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.tracking_area_identity.list[k].len;
							val.os.data = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.tracking_area_identity.list[k].val;
							add_fd_msg(&val,gxDict.avp_tracking_area_identity, (struct msg**)&avp_ptr);
						}
					}

					if( gx_ccr.event_report_indication.trace_data.mdt_configuration.
							area_scope.presence.location_area_identity){

						for( int k = 0; k < gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.location_area_identity.count; k++ ){
							val.os.len = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.location_area_identity.list[k].len;
							val.os.data = gx_ccr.event_report_indication.trace_data.
								mdt_configuration.area_scope.location_area_identity.list[k].val;
							add_fd_msg(&val,gxDict.avp_location_area_identity, (struct msg**)&avp_ptr);
						}
					}
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.list_of_measurements){
					val.u32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.list_of_measurements;
					add_fd_msg(&val, gxDict.avp_list_of_measurements, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.reporting_trigger){
					val.u32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.reporting_trigger;
					add_fd_msg(&val, gxDict.avp_reporting_trigger, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.report_interval){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.report_interval;
					add_fd_msg(&val, gxDict.avp_report_interval, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.report_amount){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.report_amount;
					add_fd_msg(&val, gxDict.avp_report_amount, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.event_threshold_rsrp){
					val.u32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.event_threshold_rsrp;
					add_fd_msg(&val, gxDict.avp_event_threshold_rsrp, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.event_threshold_rsrq){
					val.u32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.event_threshold_rsrq;
					add_fd_msg(&val, gxDict.avp_event_threshold_rsrq, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.logging_interval){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.logging_interval;
					add_fd_msg(&val, gxDict.avp_logging_interval, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.logging_duration){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.logging_duration;
					add_fd_msg(&val, gxDict.avp_logging_duration, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.measurement_period_lte){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.measurement_period_lte;
					add_fd_msg(&val, gxDict.avp_measurement_period_lte, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.measurement_period_umts){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.measurement_period_umts;
					add_fd_msg(&val, gxDict.avp_measurement_period_umts, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.collection_period_rrm_lte){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.collection_period_rrm_lte;
					add_fd_msg(&val, gxDict.avp_collection_period_rrm_lte, (struct msg**)&avp_ptr);
				}
				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.collection_period_rrm_umts){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.collection_period_rrm_umts;
					add_fd_msg(&val, gxDict.avp_collection_period_rrm_umts, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.positioning_method){
					val.os.len = (gx_ccr.event_report_indication.trace_data.mdt_configuration.positioning_method.len);
					val.os.data = gx_ccr.event_report_indication.trace_data.mdt_configuration.positioning_method.val;
					add_fd_msg(&val,gxDict.avp_positioning_method, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.measurement_quantity){
					val.os.len =gx_ccr.event_report_indication.trace_data.mdt_configuration.measurement_quantity.len;
					val.os.data = gx_ccr.event_report_indication.trace_data.mdt_configuration.measurement_quantity.val;
					add_fd_msg(&val,gxDict.avp_measurement_quantity, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.event_threshold_event_1f){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.event_threshold_event_1f;
					add_fd_msg(&val, gxDict.avp_event_threshold_event_1f, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.event_threshold_event_1i){
					val.i32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.event_threshold_event_1i;
					add_fd_msg(&val, gxDict.avp_event_threshold_event_1i, (struct msg**)&avp_ptr);
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.mdt_allowed_plmn_id){

					for( int k = 0; k < gx_ccr.event_report_indication.trace_data.
							mdt_configuration.mdt_allowed_plmn_id.count; k++){
						val.os.len = gx_ccr.event_report_indication.trace_data.
							mdt_configuration.mdt_allowed_plmn_id.list[k].len;
						val.os.data =  gx_ccr.event_report_indication.trace_data.
							mdt_configuration.mdt_allowed_plmn_id.list[k].val;
						add_fd_msg(&val,gxDict.avp_mdt_allowed_plmn_id, (struct msg**)&avp_ptr);
					}
				}

				if( gx_ccr.event_report_indication.trace_data.mdt_configuration.presence.mbsfn_area){

					for(int k = 0; k < gx_ccr.event_report_indication.
							trace_data.mdt_configuration.mbsfn_area.count; k++){

						if( gx_ccr.event_report_indication.trace_data.mdt_configuration.mbsfn_area.
								list[k].presence.mbsfn_area_id){
							val.u32 = gx_ccr.event_report_indication.trace_data.mdt_configuration.mbsfn_area.
								list[k].mbsfn_area_id;
							add_fd_msg(&val,gxDict.avp_mbsfn_area_id, (struct msg**)&avp_ptr);
						}

						if(  gx_ccr.event_report_indication.trace_data.mdt_configuration.mbsfn_area.
								list[k].presence.carrier_frequency ){
							val.u32 =  gx_ccr.event_report_indication.trace_data.mdt_configuration.
								mbsfn_area.list[k].carrier_frequency;
							add_fd_msg(&val,gxDict.avp_carrier_frequency, (struct msg**)&avp_ptr);
						}
					}
				}
			}
		}

		if( gx_ccr.event_report_indication.presence.trace_reference ){
			val.os.len = ( gx_ccr.event_report_indication.trace_reference.len );
			val.os.data = gx_ccr.event_report_indication.trace_reference.val;
			add_fd_msg(&val,gxDict.avp_trace_reference, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.tgpp2_bsid ){
			val.os.len = ( gx_ccr.event_report_indication.tgpp2_bsid.len );
			val.os.data = gx_ccr.event_report_indication.tgpp2_bsid.val;
			add_fd_msg( &val, gxDict.avp_3gpp2_bsid, (struct msg**)&avp_ptr );
		}
		if( gx_ccr.event_report_indication.presence.tgpp_ms_timezone){
			val.os.len = (gx_ccr.event_report_indication.tgpp_ms_timezone.len);
			val.os.data = gx_ccr.event_report_indication.tgpp_ms_timezone.val;
			add_fd_msg(&val,gxDict.avp_3gpp_ms_timezone, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.routing_ip_address){
			/*TODO :Need to fill according to type*/
			val.os.len = strlen( gx_ccr.event_report_indication.routing_ip_address.address);
			val.os.data = gx_ccr.event_report_indication.routing_ip_address.address;
			add_fd_msg(&val,gxDict.avp_routing_ip_address, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.ue_local_ip_address){
			/*TODO :Need to fill according to type*/
			val.os.len = strlen( gx_ccr.event_report_indication.ue_local_ip_address.address);
			val.os.data = gx_ccr.event_report_indication.ue_local_ip_address.address;
			add_fd_msg(&val,gxDict.avp_ue_local_ip_address, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.henb_local_ip_address){
			/*TODO :Need to fill according to type*/
			val.os.len = strlen( gx_ccr.event_report_indication.henb_local_ip_address.address);
			val.os.data = gx_ccr.event_report_indication.henb_local_ip_address.address;
			add_fd_msg(&val,gxDict.avp_henb_local_ip_address, (struct msg**)&avp_ptr);
		}
		if( gx_ccr.event_report_indication.presence.udp_source_port){
			val.u32 =  gx_ccr.event_report_indication.udp_source_port;
			add_fd_msg(&val, gxDict.avp_udp_source_port, (struct msg**)&avp_ptr);
		}

		if( gx_ccr.event_report_indication.presence.presence_reporting_area_information){

			if ( gx_ccr.event_report_indication.presence_reporting_area_information.
					presence.presence_reporting_area_identifier){

				val.os.len = (gx_ccr.event_report_indication.
						presence_reporting_area_information.presence_reporting_area_identifier.len);
				val.os.data = gx_ccr.event_report_indication.
					presence_reporting_area_information.presence_reporting_area_identifier.val;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_identifier, (struct msg**)&avp_ptr);
			}

			if ( gx_ccr.event_report_indication.presence_reporting_area_information.
					presence.presence_reporting_area_status){
				val.u32 = gx_ccr.event_report_indication.
					presence_reporting_area_information.presence_reporting_area_status;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_status, (struct msg**)&avp_ptr);
			}

			if ( gx_ccr.event_report_indication.presence_reporting_area_information.
					presence.presence_reporting_area_elements_list){
				val.os.len = (gx_ccr.event_report_indication.
						presence_reporting_area_information.presence_reporting_area_elements_list.len);
				val.os.data = gx_ccr.event_report_indication.
					presence_reporting_area_information.presence_reporting_area_elements_list.val;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_elements_list, (struct msg**)&avp_ptr);
			}

			if ( gx_ccr.event_report_indication.presence_reporting_area_information.
					presence.presence_reporting_area_node){
				val.u32 = gx_ccr.event_report_indication.
					presence_reporting_area_information.presence_reporting_area_node;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_node, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding access networrk charging identifier params */
	if( gx_ccr.presence.access_network_charging_identifier_gx ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_access_network_charging_identifier_gx ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.access_network_charging_identifier_gx.count; i++){

			if( gx_ccr.access_network_charging_identifier_gx.list[i].presence.
					access_network_charging_identifier_value){
				val.os.len = gx_ccr.access_network_charging_identifier_gx.list[i].
					access_network_charging_identifier_value.len;
				val.os.data = gx_ccr.access_network_charging_identifier_gx.list[i].
					access_network_charging_identifier_value.val;
				add_fd_msg(&val,gxDict.avp_access_network_charging_identifier_value, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.access_network_charging_identifier_gx.list[i].presence.
					charging_rule_base_name){

				for(int k = 0; k < gx_ccr.access_network_charging_identifier_gx.
						list[i].charging_rule_name.count; k++){

					val.os.len = gx_ccr.access_network_charging_identifier_gx.list[i].
						charging_rule_base_name.list[k].len ;
					val.os.data = gx_ccr.access_network_charging_identifier_gx.list[i].
						charging_rule_base_name.list[k].val;
					add_fd_msg(&val,gxDict.avp_charging_rule_base_name,(struct msg**)&avp_ptr);
				}
			}

			if( gx_ccr.access_network_charging_identifier_gx.list[i].presence.
					charging_rule_name){

				for( int k = 0; k < gx_ccr.access_network_charging_identifier_gx.
						list[i].charging_rule_name.count; k++){
					val.os.len =  gx_ccr.access_network_charging_identifier_gx.list[i].
						charging_rule_name.list[k].len ;
					val.os.data = gx_ccr.access_network_charging_identifier_gx.list[i].
						charging_rule_name.list[k].val;
					add_fd_msg(&val,gxDict.avp_charging_rule_name,(struct msg**)&avp_ptr);
				}
			}

			if( gx_ccr.access_network_charging_identifier_gx.list[i].
					presence.ip_can_session_charging_scope ){
				val.i32 = gx_ccr.access_network_charging_identifier_gx.
					list[i].ip_can_session_charging_scope;
				add_fd_msg(&val,gxDict.avp_ip_can_session_charging_scope, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding coa infor params */
	if( gx_ccr.presence.coa_information ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_coa_information ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.coa_information.count; i++){

			if( gx_ccr.coa_information.list[i].presence.tunnel_information){

				if ( gx_ccr.coa_information.list[i].tunnel_information.presence.tunnel_header_length ){
					val.i32 = gx_ccr.coa_information.list[i].tunnel_information.tunnel_header_length;
					add_fd_msg(&val,gxDict.avp_tunnel_header_length, (struct msg**)&avp_ptr);
				}

				if ( gx_ccr.coa_information.list[i].tunnel_information.presence.
						tunnel_header_filter){

					for (int k = 0; k < gx_ccr.coa_information.list[i].
							tunnel_information.tunnel_header_filter.count; k++){
						val.os.len =  gx_ccr.coa_information.list[i].
							tunnel_information.tunnel_header_filter.list[k].len ;
						val.os.data = gx_ccr.coa_information.list[i].
							tunnel_information.tunnel_header_filter.list[k].val ;
						add_fd_msg(&val,gxDict.avp_tunnel_header_filter,(struct msg**)&avp_ptr);
					}
				}
			}

			if( gx_ccr.coa_information.list[i].presence.coa_ip_address ){
				/*TODO address need to fill on the basis of type */
				val.os.len = strlen(gx_ccr.coa_information.list[i].coa_ip_address.address);
				val.os.data = gx_ccr.coa_information.list[i].coa_ip_address.address;
				add_fd_msg(&val,gxDict.avp_coa_ip_address, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding usage monitoring infor params */
	if( gx_ccr.presence.usage_monitoring_information ){

		CHECK_FCT_DO( fd_msg_avp_new( gxDict.avp_usage_monitoring_information, 0, &avp_ptr ), return -1 );
		CHECK_FCT_DO( fd_msg_avp_add( msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1 );

		for( int i = 0; i < gx_ccr.usage_monitoring_information.count; i++){

			if( gx_ccr.usage_monitoring_information.list[i].presence.monitoring_key ){
				val.os.len = gx_ccr.usage_monitoring_information.list[i].monitoring_key.len;
				val.os.data = gx_ccr.usage_monitoring_information.list[i].monitoring_key.val;
				add_fd_msg(&val,gxDict.avp_monitoring_key, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.usage_monitoring_information.list[i].presence.granted_service_unit ){

				for( int j = 0; j < gx_ccr.usage_monitoring_information.
						list[i].granted_service_unit.count; j++ ){

					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.tariff_time_change ){
						val.u32 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].tariff_time_change;
						add_fd_msg(&val,gxDict.avp_tariff_time_change, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_time ){
						val.u32 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].cc_time;
						add_fd_msg(&val,gxDict.avp_cc_time, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_money ){

						if( gx_ccr.usage_monitoring_information.list[i].
								granted_service_unit.list[j].cc_money.presence.unit_value){

							if( gx_ccr.usage_monitoring_information.list[i].
									granted_service_unit.list[j].cc_money.
									unit_value.presence.value_digits ){

								val.u32 = gx_ccr.usage_monitoring_information.list[i].
									granted_service_unit.list[j].cc_money.unit_value.value_digits;
								add_fd_msg(&val,gxDict.avp_value_digits, (struct msg**)&avp_ptr);
							}

							if( gx_ccr.usage_monitoring_information.list[i].
									granted_service_unit.list[j].cc_money.
									unit_value.presence.exponent ){

								val.u32 = gx_ccr.usage_monitoring_information.list[i].
									granted_service_unit.list[j].cc_money.unit_value.exponent;
								add_fd_msg(&val,gxDict.avp_exponent, (struct msg**)&avp_ptr);
							}
						}

						if( gx_ccr.usage_monitoring_information.list[i].
								granted_service_unit.list[j].cc_money.
								presence.currency_code ){

							val.u32 = gx_ccr.usage_monitoring_information.list[i].
								granted_service_unit.list[j].cc_money.currency_code;
							add_fd_msg(&val,gxDict.avp_currency_code, (struct msg**)&avp_ptr);
						}

					}
					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_total_octets ){

						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].cc_total_octets;
						add_fd_msg(&val,gxDict.avp_cc_total_octets, (struct msg**)&avp_ptr);
					}

					if(  gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_input_octets){

						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].cc_input_octets;
						add_fd_msg(&val,gxDict.avp_cc_input_octets, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_output_octets ){

						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].cc_output_octets;
						add_fd_msg(&val,gxDict.avp_cc_output_octets, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].presence.cc_service_specific_units){

						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							granted_service_unit.list[j].cc_service_specific_units;
						add_fd_msg(&val,gxDict.avp_cc_service_specific_units, (struct msg**)&avp_ptr);
					}
				}
			}

			if( gx_ccr.usage_monitoring_information.list[i].presence.used_service_unit ){

				for( int k = 0; k < gx_ccr.usage_monitoring_information.list[i].
						used_service_unit.count; k++ ){

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.reporting_reason){
						val.i32 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].reporting_reason;
						add_fd_msg(&val,gxDict.avp_reporting_reason, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.tariff_change_usage ){

						val.i32 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].tariff_change_usage;
						add_fd_msg(&val,gxDict.avp_tariff_change_usage, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_time ){

						val.u32 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].cc_time;
						add_fd_msg(&val,gxDict.avp_cc_time, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_money ){

						if( gx_ccr.usage_monitoring_information.list[i].
								used_service_unit.list[k].cc_money.presence.unit_value ){

							if( gx_ccr.usage_monitoring_information.list[i].
									used_service_unit.list[k].cc_money.unit_value.
									presence.value_digits ){

								val.u32 = gx_ccr.usage_monitoring_information.list[i].
									used_service_unit.list[k].cc_money.unit_value.value_digits;
								add_fd_msg(&val,gxDict.avp_value_digits, (struct msg**)&avp_ptr);
							}

							if( gx_ccr.usage_monitoring_information.list[i].
									used_service_unit.list[k].cc_money.unit_value.presence.exponent ){

								val.u32 = gx_ccr.usage_monitoring_information.list[i].
									used_service_unit.list[k].cc_money.unit_value.exponent;
								add_fd_msg(&val,gxDict.avp_exponent, (struct msg**)&avp_ptr);
							}
						}

						if( gx_ccr.usage_monitoring_information.list[i].
								used_service_unit.list[k].cc_money.presence.currency_code ){
							val.u32 = gx_ccr.usage_monitoring_information.list[i].
								used_service_unit.list[k].cc_money.currency_code;
							add_fd_msg(&val,gxDict.avp_currency_code, (struct msg**)&avp_ptr);
						}
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_total_octets ){
						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].cc_total_octets;
						add_fd_msg(&val,gxDict.avp_cc_total_octets, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_input_octets ){
						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].cc_input_octets;
						add_fd_msg(&val,gxDict.avp_cc_input_octets, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_output_octets ){
						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].cc_output_octets;
						add_fd_msg(&val,gxDict.avp_cc_output_octets, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.cc_service_specific_units ){
						val.u64 = gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].cc_service_specific_units;
						add_fd_msg(&val,gxDict.avp_cc_service_specific_units, (struct msg**)&avp_ptr);
					}

					if( gx_ccr.usage_monitoring_information.list[i].
							used_service_unit.list[k].presence.event_charging_timestamp ){

						for( int itr = 0; itr < gx_ccr.usage_monitoring_information.list[i].
								used_service_unit.list[k].event_charging_timestamp.count; itr++ ){
							val.u64 = gx_ccr.usage_monitoring_information.list[i].
								used_service_unit.list[k].event_charging_timestamp.list[itr];
							add_fd_msg(&val,gxDict.avp_event_charging_timestamp, (struct msg**)&avp_ptr);
						}
					}
				}
			}

			if( gx_ccr.usage_monitoring_information.list[i].presence.quota_consumption_time ){
				val.u32 = gx_ccr.usage_monitoring_information.list[i].quota_consumption_time;
				add_fd_msg(&val,gxDict.avp_quota_consumption_time, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.usage_monitoring_information.list[i].presence.usage_monitoring_level ){
				val.i32 = gx_ccr.usage_monitoring_information.list[i].usage_monitoring_level;
				add_fd_msg(&val,gxDict.avp_usage_monitoring_level, (struct msg**)&avp_ptr);
			}

			if( gx_ccr.usage_monitoring_information.list[i].presence.usage_monitoring_report ){
				val.i32 = gx_ccr.usage_monitoring_information.list[i].usage_monitoring_report;
				add_fd_msg(&val,gxDict.avp_usage_monitoring_report, (struct msg**)&avp_ptr);

			}
			if( gx_ccr.usage_monitoring_information.list[i].presence.usage_monitoring_support ){
				val.i32 = gx_ccr.usage_monitoring_information.list[i].usage_monitoring_support;
				add_fd_msg(&val,gxDict.avp_usage_monitoring_support, (struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding routing rule install params */
	if( gx_ccr.presence.routing_rule_install){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_routing_rule_install ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		if( gx_ccr.routing_rule_install.presence.routing_rule_definition ){

			for( int i = 0; i < gx_ccr.routing_rule_install.routing_rule_definition.count; i++){


				if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
						presence.routing_rule_identifier){

					val.os.len = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
						routing_rule_identifier.len;
					val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
						routing_rule_identifier.val;
					add_fd_msg(&val,gxDict.avp_routing_rule_identifier ,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.routing_rule_install.routing_rule_definition.list[i]
						.presence.routing_filter){

					for( int j = 0; j < gx_ccr.routing_rule_install.routing_rule_definition.
							list[i].routing_filter.count; j++){

						if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].presence.flow_description ){
							val.os.len = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].flow_description.len;
							val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].flow_description.val;
							add_fd_msg(&val,gxDict.avp_flow_description ,(struct msg**)&avp_ptr);
						}

						if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].presence.flow_direction ){
							val.i32 = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].flow_direction;
							add_fd_msg(&val,gxDict.avp_flow_direction ,(struct msg**)&avp_ptr);
						}
						if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].presence.tos_traffic_class ){
							val.os.len = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].tos_traffic_class.len;
							val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].tos_traffic_class.val;
							add_fd_msg(&val,gxDict.avp_tos_traffic_class,(struct msg**)&avp_ptr);
						}
						if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].presence.security_parameter_index ){
							val.os.len = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].security_parameter_index.len;
							val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].security_parameter_index.val;
							add_fd_msg(&val,gxDict.avp_security_parameter_index,(struct msg**)&avp_ptr);
						}
						if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].presence.flow_label){
							val.os.len = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].flow_label.len;
							val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.list[i].
								routing_filter.list[j].flow_label.val;
							add_fd_msg(&val,gxDict.avp_flow_label,(struct msg**)&avp_ptr);
						}
					}
				}

				if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].presence.precedence ){
					val.u32 = gx_ccr.routing_rule_install.routing_rule_definition.list[i].precedence;
					add_fd_msg(&val,gxDict.avp_precedence ,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].presence.routing_ip_address ){
					/*TODO address need to fill on the basis of type */
					val.os.len = strlen( gx_ccr.routing_rule_install.routing_rule_definition.
							list[i].routing_ip_address.address);
					val.os.data = gx_ccr.routing_rule_install.routing_rule_definition.
						list[i].routing_ip_address.address;
					add_fd_msg(&val,gxDict.avp_routing_ip_address ,(struct msg**)&avp_ptr);
				}

				if( gx_ccr.routing_rule_install.routing_rule_definition.list[i].presence.ip_can_type){
					val.i32 = gx_ccr.routing_rule_install.routing_rule_definition.list[i].ip_can_type;
					add_fd_msg(&val,gxDict.avp_ip_can_type ,(struct msg**)&avp_ptr);
				}
			}
		}
	}

	/* Adding routing rule remove params */
	if( gx_ccr.presence.routing_rule_remove ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_routing_rule_remove ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.routing_rule_remove.routing_rule_identifier.count; i++){
			val.os.len = gx_ccr.routing_rule_remove.routing_rule_identifier.list[i].len;
			val.os.data = gx_ccr.routing_rule_remove.routing_rule_identifier.list[i].val;
			add_fd_msg(&val,gxDict.avp_routing_rule_identifier,(struct msg**)&avp_ptr);
		}
	}

	/* Adding presence_reporting_area_information  params */
	if( gx_ccr.presence.presence_reporting_area_information ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_presence_reporting_area_information ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.presence_reporting_area_information.count; i++){

			if( gx_ccr.presence_reporting_area_information.list[i].presence.
					presence_reporting_area_identifier ){
				val.os.len = gx_ccr.presence_reporting_area_information.
					list[i].presence_reporting_area_identifier.len;
				val.os.data = gx_ccr.presence_reporting_area_information.list[i].
					presence_reporting_area_identifier.val;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_identifier,(struct msg**)&avp_ptr);
			}

			if( gx_ccr.presence_reporting_area_information.list[i].presence.
					presence_reporting_area_status ){
				val.u32 = gx_ccr.presence_reporting_area_information.list[i].
					presence_reporting_area_status;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_status,(struct msg**)&avp_ptr);
			}

			if( gx_ccr.presence_reporting_area_information.list[i].presence.
					presence_reporting_area_elements_list ){
				val.os.len = gx_ccr.presence_reporting_area_information.list[i].
					presence_reporting_area_elements_list.len;
				val.os.data = gx_ccr.presence_reporting_area_information.list[i].
					presence_reporting_area_elements_list.val;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_elements_list,(struct msg**)&avp_ptr);
			}

			if( gx_ccr.presence_reporting_area_information.list[i].presence.
					presence_reporting_area_node ){
				val.u32 = gx_ccr.presence_reporting_area_information.list[i].
					presence_reporting_area_node;
				add_fd_msg(&val,gxDict.avp_presence_reporting_area_node,(struct msg**)&avp_ptr);
			}

		}
	}

	/* Adding proxy info params */
	if( gx_ccr.presence.proxy_info ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_proxy_info ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for( int i = 0; i < gx_ccr.proxy_info.count; i++){

			if(  gx_ccr.proxy_info.list[i].presence.proxy_host ){
				val.os.len = gx_ccr.proxy_info.list[i].proxy_host.len;
				val.os.data = gx_ccr.proxy_info.list[i].proxy_host.val;
				add_fd_msg(&val,gxDict.avp_proxy_host,(struct msg**)&avp_ptr);
			}

			if( gx_ccr.proxy_info.list[i].presence.proxy_state ){
				val.os.len = gx_ccr.proxy_info.list[i].proxy_state.len;
				val.os.data = gx_ccr.proxy_info.list[i].proxy_state.val;
				add_fd_msg(&val,gxDict.avp_proxy_state,(struct msg**)&avp_ptr);
			}
		}
	}

	/* Adding proxy info params */
	if( gx_ccr.presence.route_record ){

		CHECK_FCT_DO(fd_msg_avp_new(gxDict.avp_route_record ,0, &avp_ptr), return -1);
		CHECK_FCT_DO(fd_msg_avp_add(msg, MSG_BRW_LAST_CHILD, avp_ptr), return -1);

		for(int i = 0; i < gx_ccr.route_record.count; i++){
			val.os.len = gx_ccr.route_record.list[i].len;
			val.os.data = gx_ccr.route_record.list[i].val;
			add_fd_msg(&val,gxDict.avp_route_record ,(struct msg**)&avp_ptr);
		}
	}

	/* Adding Default EPS  Bearer Qos params */
	if( gx_ccr.presence.default_eps_bearer_qos ) {

		struct avp *default_eps_bearer_qos = NULL;
		FDCHECK_MSG_ADD_AVP_GROUPED_2( gxDict.avp_default_eps_bearer_qos, msg, MSG_BRW_LAST_CHILD,
			 default_eps_bearer_qos, rval, goto err );

		if ( gx_ccr.default_eps_bearer_qos.presence.qos_class_identifier )
			FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_qos_class_identifier, default_eps_bearer_qos,
				MSG_BRW_LAST_CHILD, gx_ccr.default_eps_bearer_qos.qos_class_identifier, rval, goto err );

		if( gx_ccr.default_eps_bearer_qos.presence.allocation_retention_priority ) {

			struct avp *allocation_retention_priority = NULL;
			FDCHECK_MSG_ADD_AVP_GROUPED_2( gxDict.avp_allocation_retention_priority,
				 default_eps_bearer_qos, MSG_BRW_LAST_CHILD, allocation_retention_priority, rval, goto err );

			if( gx_ccr.default_eps_bearer_qos.allocation_retention_priority.presence.pre_emption_capability ){

				FDCHECK_MSG_ADD_AVP_U32( gxDict.avp_priority_level, allocation_retention_priority,
						MSG_BRW_LAST_CHILD, gx_ccr.default_eps_bearer_qos.allocation_retention_priority.priority_level,
						rval, goto err );
			}

			if( gx_ccr.default_eps_bearer_qos.allocation_retention_priority.presence.pre_emption_capability ){

				FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_pre_emption_capability, allocation_retention_priority,
					MSG_BRW_LAST_CHILD, gx_ccr.default_eps_bearer_qos.allocation_retention_priority.pre_emption_capability,
						rval, goto err );
			}

			if( gx_ccr.default_eps_bearer_qos.allocation_retention_priority.presence.pre_emption_vulnerability ){

				FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_pre_emption_vulnerability, allocation_retention_priority,
					MSG_BRW_LAST_CHILD, gx_ccr.default_eps_bearer_qos.allocation_retention_priority.pre_emption_vulnerability,
						rval, goto err );
			}
		}
	}

	if(gx_ccr.presence.default_qos_information){

		if(gx_ccr.default_qos_information.presence.qos_class_identifier){
			val.i32 = gx_ccr.default_qos_information.qos_class_identifier;
			add_fd_msg(&val,gxDict.avp_qos_class_identifier,(struct msg**)&avp_ptr);
		}

		if(gx_ccr.default_qos_information.presence.max_requested_bandwidth_ul){
			val.u32 = gx_ccr.default_qos_information.max_requested_bandwidth_ul;
			add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_ul,(struct msg**)&avp_ptr);
		}
		if(gx_ccr.default_qos_information.presence.max_requested_bandwidth_dl){
			val.u32 = gx_ccr.default_qos_information.max_requested_bandwidth_dl;
			add_fd_msg(&val,gxDict.avp_max_requested_bandwidth_dl,(struct msg**)&avp_ptr);
		}
		if(gx_ccr.default_qos_information.presence.default_qos_name){
			val.os.len = gx_ccr.default_qos_information.default_qos_name.len;
			val.os.data = gx_ccr.default_qos_information.default_qos_name.val;
			add_fd_msg(&val,gxDict.avp_default_qos_name,(struct msg**)&avp_ptr);
		}
	}


   //TODO - FILL IN HERE
#ifdef GX_DEBUG
   FD_DUMP_MESSAGE(msg);
#endif

   /* send the message */
   FDCHECK_MSG_SEND( msg, NULL, NULL, rval, goto err );
   goto fini;

err:
   /* free the message since an error occurred */
   FDCHECK_MSG_FREE(msg);

fini:

   return rval;
}

/*
*
*       Fun:    gx_ccr_cb
*
*       Desc:   CMDNAME call back
*
*       Ret:    0
*
*       File:   gx_ccr.c
*
    The Credit-Control-Request (CCR) command, indicated by
    the Command-Code field set to 272 and the 'R'
    bit set in the Command Flags field, is sent to/from MME or SGSN.
*
    Credit-Control-Request ::= <Diameter Header: 272, REQ, PXY, 16777238>
          < Session-Id >
          [ DRMP ]
          { Auth-Application-Id }
          { Origin-Host }
          { Origin-Realm }
          { Destination-Realm }
          { CC-Request-Type }
          { CC-Request-Number }
          [ Credit-Management-Status ]
          [ Destination-Host ]
          [ Origin-State-Id ]
      *   [ Subscription-Id ]
          [ OC-Supported-Features ]
      *   [ Supported-Features ]
          [ TDF-Information ]
          [ Network-Request-Support ]
      *   [ Packet-Filter-Information ]
          [ Packet-Filter-Operation ]
          [ Bearer-Identifier ]
          [ Bearer-Operation ]
          [ Dynamic-Address-Flag ]
          [ Dynamic-Address-Flag-Extension ]
          [ PDN-Connection-Charging-ID ]
          [ Framed-IP-Address ]
          [ Framed-IPv6-Prefix ]
          [ IP-CAN-Type ]
          [ 3GPP-RAT-Type ]
          [ AN-Trusted ]
          [ RAT-Type ]
          [ Termination-Cause ]
          [ User-Equipment-Info ]
          [ QoS-Information ]
          [ QoS-Negotiation ]
          [ QoS-Upgrade ]
          [ Default-EPS-Bearer-QoS ]
          [ Default-QoS-Information ]
      * 2 [ AN-GW-Address ]
          [ AN-GW-Status ]
          [ 3GPP-SGSN-MCC-MNC ]
          [ 3GPP-SGSN-Address ]
          [ 3GPP-SGSN-Ipv6-Address ]
          [ 3GPP-GGSN-Address ]
          [ 3GPP-GGSN-Ipv6-Address ]
          [ 3GPP-Selection-Mode ]
          [ RAI ]
          [ 3GPP-User-Location-Info ]
          [ Fixed-User-Location-Info ]
          [ User-Location-Info-Time ]
          [ User-CSG-Information ]
          [ TWAN-Identifier ]
          [ 3GPP-MS-TimeZone ]
      *   [ RAN-NAS-Release-Cause ]
          [ 3GPP-Charging-Characteristics ]
          [ Called-Station-Id ]
          [ PDN-Connection-ID ]
          [ Bearer-Usage ]
          [ Online ]
          [ Offline ]
      *   [ TFT-Packet-Filter-Information ]
      *   [ Charging-Rule-Report ]
      *   [ Application-Detection-Information ]
      *   [ Event-Trigger ]
          [ Event-Report-Indication ]
          [ Access-Network-Charging-Address ]
      *   [ Access-Network-Charging-Identifier-Gx ]
      *   [ CoA-Information ]
      *   [ Usage-Monitoring-Information ]
          [ NBIFOM-Support ]
          [ NBIFOM-Mode ]
          [ Default-Access ]
          [ Origination-Time-Stamp ]
          [ Maximum-Wait-Time ]
          [ Access-Availability-Change-Reason ]
          [ Routing-Rule-Install ]
          [ Routing-Rule-Remove ]
          [ HeNB-Local-IP-Address ]
          [ UE-Local-IP-Address ]
          [ UDP-Source-Port ]
          [ TCP-Source-Port ]
      *   [ Presence-Reporting-Area-Information ]
          [ Logical-Access-Id ]
          [ Physical-Access-Id ]
      *   [ Proxy-Info ]
      *   [ Route-Record ]
          [ 3GPP-PS-Data-Off-Status ]
      *   [ AVP ]

*/
int gx_ccr_cb
(
   struct msg ** msg,
   struct avp * pavp,
   struct session * sess,
   void * data,
   enum disp_action * act
)
{
   int ret = FD_REASON_OK;
   struct msg *rqst = *msg;
   struct msg *ans = rqst;
   GxCCR *ccr = NULL;

   *msg = NULL;

#if 1
FD_DUMP_MESSAGE(rqst);
#endif

   /* allocate the ccr message */
   ccr = (GxCCR*)malloc(sizeof(*ccr));

   memset((void*)ccr, 0, sizeof(*ccr));

   ret = gx_ccr_parse(rqst, ccr);
   if (ret != FD_REASON_OK)
      goto err;

   /*
    *  TODO - Add request processing code
    */
   FDCHECK_MSG_NEW_ANSWER_FROM_REQ( fd_g_config->cnf_dict, ans, ret, goto err );
   FDCHECK_MSG_ADD_ORIGIN( ans, ret, goto err );
   FDCHECK_MSG_ADD_AVP_S32( gxDict.avp_result_code, ans, MSG_BRW_LAST_CHILD, 2001, ret, goto err );

   FDCHECK_MSG_SEND( ans, NULL, NULL, ret, goto err );

   goto fini1;

err:
   printf("Error (%d) while processing CCR\n", ret);
   free(ccr);
   goto fini2;

fini1:

fini2:
   gx_ccr_free(ccr);
   return ret;
}
