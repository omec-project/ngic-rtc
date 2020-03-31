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

#ifndef  __GX_DEF_H__
#define  __GX_DEF_H__

#define GX_TDF_DESTINATION_HOST_LEN                          255
#define GX_PACKET_FILTER_CONTENT_LEN                         255
#define GX_PHYSICAL_ACCESS_ID_LEN                            255
#define GX_3GPP_RAT_TYPE_LEN                                 255
#define GX_TRACKING_AREA_IDENTITY_LEN                        255
#define GX_OMC_ID_LEN                                        255
#define GX_RAI_LEN                                           255
#define GX_SECONDARY_EVENT_CHARGING_FUNCTION_NAME_LEN        255
#define GX_ORIGIN_HOST_LEN                                   255
#define GX_SERVICE_CONTEXT_ID_LEN                            255
#define GX_LOGICAL_ACCESS_ID_LEN                             255
#define GX_3GPP_SGSN_MCC_MNC_LEN                             255
#define GX_TUNNEL_HEADER_FILTER_LEN                          255
#define GX_ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE_LEN      255
#define GX_SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN   255
#define GX_DESTINATION_HOST_LEN                              255
#define GX_3GPP_SELECTION_MODE_LEN                           255
#define GX_LOCATION_AREA_IDENTITY_LEN                        255
#define GX_TDF_APPLICATION_IDENTIFIER_LEN                    255
#define GX_FRAMED_IPV6_PREFIX_LEN                            255
#define GX_3GPP_CHARGING_CHARACTERISTICS_LEN                 255
#define GX_MDT_ALLOWED_PLMN_ID_LEN                           255
#define GX_ORIGIN_REALM_LEN                                  255
#define GX_TWAN_IDENTIFIER_LEN                               255
#define GX_FLOW_LABEL_LEN                                    255
#define GX_3GPP_GGSN_IPV6_ADDRESS_LEN                        255
#define GX_RESTRICTION_FILTER_RULE_LEN                       255
#define GX_3GPP_SGSN_ADDRESS_LEN                             255
#define GX_TDF_DESTINATION_REALM_LEN                         255
#define GX_SUBSCRIPTION_ID_DATA_LEN                          255
#define GX_REDIRECT_SERVER_ADDRESS_LEN                       255
#define GX_3GPP_SGSN_IPV6_ADDRESS_LEN                        255
#define GX_3GPP2_BSID_LEN                                    255
#define GX_CHARGING_RULE_BASE_NAME_LEN                       255
#define GX_USER_EQUIPMENT_INFO_VALUE_LEN                     255
#define GX_ROUTE_RECORD_LEN                                  255
#define GX_PRESENCE_REPORTING_AREA_IDENTIFIER_LEN            255
#define GX_FILTER_ID_LEN                                     255
#define GX_SSID_LEN                                          255
#define GX_FLOW_DESCRIPTION_LEN                              255
#define GX_POSITIONING_METHOD_LEN                            255
#define GX_SOURCEID_LEN                                      255
#define GX_BEARER_IDENTIFIER_LEN                             255
#define GX_SPONSOR_IDENTITY_LEN                              255
#define GX_DEFAULT_QOS_NAME_LEN                              255
#define GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_UL_LEN         255
#define GX_ERROR_REPORTING_HOST_LEN                          255
#define GX_CELL_GLOBAL_IDENTITY_LEN                          255
#define GX_APPLICATION_SERVICE_PROVIDER_IDENTITY_LEN         255
#define GX_TRACE_NE_TYPE_LIST_LEN                            255
#define GX_REDIRECT_HOST_LEN                                 255
#define GX_RAN_NAS_RELEASE_CAUSE_LEN                         255
#define GX_TRACE_EVENT_LIST_LEN                              255
#define GX_3GPP_USER_LOCATION_INFO_LEN                       255
#define GX_SECURITY_PARAMETER_INDEX_LEN                      255
#define GX_TRACE_INTERFACE_LIST_LEN                          255
#define GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_DL_LEN         255
#define GX_3GPP_GGSN_ADDRESS_LEN                             255
#define GX_E_UTRAN_CELL_GLOBAL_IDENTITY_LEN                  255
#define GX_CALLED_STATION_ID_LEN                             255
#define GX_FRAMED_IP_ADDRESS_LEN                             255
#define GX_PACKET_FILTER_IDENTIFIER_LEN                      255
#define GX_TDF_APPLICATION_INSTANCE_IDENTIFIER_LEN           255
#define GX_PROXY_HOST_LEN                                    255
#define GX_PDN_CONNECTION_ID_LEN                             255
#define GX_PRESENCE_REPORTING_AREA_ELEMENTS_LIST_LEN         255
#define GX_MONITORING_KEY_LEN                                255
#define GX_3GPP_MS_TIMEZONE_LEN                              255
#define GX_CHARGING_RULE_NAME_LEN                            255
#define GX_ERROR_MESSAGE_LEN                                 255
#define GX_ROUTING_AREA_IDENTITY_LEN                         255
#define GX_TFT_FILTER_LEN                                    255
#define GX_TRACE_REFERENCE_LEN                               255
#define GX_MEASUREMENT_QUANTITY_LEN                          255
#define GX_PROXY_STATE_LEN                                   255
#define GX_AF_CHARGING_IDENTIFIER_LEN                        255
#define GX_ROUTING_RULE_IDENTIFIER_LEN                       255
#define GX_DESTINATION_REALM_LEN                             255
#define GX_SESSION_ID_LEN                                    255
#define GX_TOS_TRAFFIC_CLASS_LEN                             255
#define GX_BSSID_LEN                                         255
#define GX_PRIMARY_EVENT_CHARGING_FUNCTION_NAME_LEN          255
#define GX_PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN     255

#define DISABLED 1
#define ENABLED 0

#define NOT_PRESENT 0
#define PRESENT 1

#define DEFAULT_BEARER_ID 5

/*rfc4006  8.3*/
enum cc_request_type_value{
  INITIAL_REQUEST = 1,
  UPDATE_REQUEST,
  TERMINATION_REQUEST,
  EVENT_REQUEST,
};

enum network_request_support_value{
	NETWORK_REQUEST_NOT_SUPPORTED = 0,
	NETWORK_REQUEST_SUPPORTED,
};

enum ip_can_type_value{
	TGPP_GPRS = 0,
	DOCSIS,
	XDSL,
	WIMAX,
	TGPP2,
	TGPP_EPS,
	NON_3GPP_EPS,
	FBA,
};

enum metering_method_value{
	DURATION = 0,
	VOLUME,
	DURATION_VOLUME,
	EVENT,
};

enum mute_notif_value{
	MUTE_REQUIRED = 0,
};

enum online_value{
	DISABLE_ONLINE = 0,
	ENABLE_ONLINE,
};

enum offline_value{
	DISABLE_OFFLINE = 0,
	ENABLE_OFFLINE,
};

enum packet_filter_usage_value{
	SEND_TO_UE = 0,
};

enum packet_filter_operation_value{
	DELETION = 0,
	ADDITION,
	MDIFICAITON,
};

enum pre_emption_capability_value{
	PRE_EMPTION_CAPABILITY_ENABLED = 0,
	PRE_EMPTION_CAPABILITY_DISABLED,
};

enum pre_emption_vulnerability_value{
	PRE_EMPTION_VULNERABILITY_ENABLED = 0,
	PRE_EMPTION_VULNERABILITY_DISABLED,
};

enum pcc_rule_status_value{
	ACTIVE = 0,
	INACTIVE,
	TEMPORARILY_INACTIVE,
};

enum ps_to_cs_session_conitnuity_value{
	VIDEO_PS2CS_CONT_CANDIDATE = 0,
};

enum qos_class_identifier_value{
	QCI_1 = 1,
	QCI_2,
	QCI_3,
	QCI_4,
	QCI_5,
	QCI_6,
	QCI_7,
	QCI_8,
	QCI_9,
	QCI_65 = 65,
	QCI_66,
	QCI_69 = 69,
	QCI_70,
};

enum qos_negotiation_value{
	NO_QOS_NEGOTIATION = 0,
	QOS_NEGOTIATION_SUPPORTED,
};

enum qos_upgrade_value{
	QOS_UPGRADE_NOT_SUPPORTED = 0,
	QOS_UPGRADE_SUPPORTED,
};

enum rat_type_value{
	GX_WLAN = 0,
	GX_VIRTUAL,
	GX_UTRAN = 1000,
	GX_GERAN,
	GX_GAN,
	GX_HSPA_EVOLUTION,
	GX_EUTRAN,
	GX_CDMA2000_1X = 2000,
	GX_HRPD,
	GX_UMB,
	GX_EHRPD,
};

enum redirect_support_value{
	REDIRECTION_DISABLED = 0,
	REDIRECTION_ENABLED ,
};

enum repoting_level_value{
	SERVICE_IDENTIFIER_LEVEL = 0,
	RATING_GROUP_LEVEL,
	SPONSORED_CONNECTIVITY_LEVEL,
};

enum resource_alloc_notif_value{
	ENABLE_NOTIFICATION = 0,
};

enum an_gw_status_value{
	AN_GW_FAILED = 0,
};

enum bearer_control_mode_value{
	UE_ONLY = 0,
	RESERVED,
	UE_NW,
};

enum bearer_operation_value{
	TERMINATION = 0,
	ESTABLISHMENT,
	MODIFICATION,
};

enum bearer_usage_value{
	GENERAL = 0,
	IMS_SIGNALLING,
};

enum charging_correl_ind_value{
	CHARGING_IDENTIFIER_REQUIRED = 0,
};

enum csg_info_reporting_value{
	CHANGE_CSG_CELL = 0,
	CHANGE_CSG_SUBSCRIBED_HYBRID_CELL,
	CHANGE_CSG_UNSUBSCRIBED_HYBRID_CELL,
};

enum event_trigger_value{
	SGSN_CHANGE = 0,
	QOS_CHANGE,
	RAT_CHANGE,
	TFT_CHANGE,
	PLMN_CHANGE,
	LOSS_OF_BEARER,
	RECOVERY_OF_BEARER,
	IP_CAN_CHANGE,
	QOS_CHANGE_EXCEEDING_AUTHORIZATION = 11,
	RAI_CHANGE,
	USER_LOCATION_CHANGE,
	NO_EVENT_TRIGGERS,
	OUT_OF_CREDIT,
	REALLOCATION_OF_CREDIT,
	REVALIDATION_TIMEOUT,
	UE_IP_ADDRESS_ALLOCATE = 18,
	UE_IP_ADDRESS_RELEASE,
	DEFAULT_EPS_BEARER_QOS_CHANGE,
	AN_GW_CHANGE,
	SUCCESSFUL_RESOURCE_ALLOCATION,
	RESOURCE_MODIFICATION_REQUEST,
	PGW_TRACE_CONTROL,
	UE_TIME_ZONE_CHANGE,
	TAI_CHANGE,
	ECGI_CHANGE,
	CHARGING_CORRELATION_EXCHANGE,
	APN_AMBR_MODIFICATION_FAILURE = 29,
	USER_CSG_INFORMATION_CHANGE,
	USAGE_REPORT = 33,
	DEFAULT_EPS_BEARER_QOS_MODIFICATION_FAILURE = 34,
	USER_CSG_HYBRID_SUBSCRIBED_INFORMATION_CHANGE,
	USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE,
	ROUTING_RULE_CHANGE,
	APPLICATION_START = 39,
	APPLICATION_STOP,
	CS_TO_PS_HANDOVER = 42,
	UE_LOCAL_IP_ADDRESS_CHANGE,
	HENB_LOCAL_IP_ADDRESS_CHANGE,
	ACCESS_NETWORK_INFO_REPORT,
	CREDIT_MANAGEMENT_SESSION_FAILURE,
	DEFAULT_QOS_CHANGE,
	CHANGE_OF_UE_PRESENCE_IN_PRESENCE_REPORTING_AREA_REPORT,
};

enum flow_direction_value{
	GX_UNSPECIFIED = 0,
	GX_DOWNLINK,
	GX_UPLINK,
	GX_BIDIRECTIONAL,
};

enum rule_failure_code{
	UNKNOWN_RULE_NAME = 1,
	RATING_GROUP_ERROR,
	SERVICE_IDENTIFIER_ERROR,
	GW_PCEF_MALFUNCTION,
	RESOURCES_LIMITATION,
	MAX_NR_BEARERS_REACHED,
	UNKNOWN_BEARER_ID,
	MISSING_BEARER_ID,
	MISSING_FLOW_INFORMATION,
	RESOURCE_ALLOCATION_FAILURE,
	UNSUCCESSFUL_QOS_VALIDATION,
	INCORRECT_FLOW_INFORMATION,
	PS_TO_CS_HANDOVER,
	TDF_APPLICATION_IDENTIFIER_ERROR,
	NO_BEARER_BOUND = 15,
	FILTER_RESTRICTIONS,
	AN_GW_RULE_FAILED,
	MISSING_REDIRECT_SERVER_ADDRESS,
	CM_END_USER_SERVICE_DENIED,
	CM_CREDIT_CONTROL_NOT_APPLICABLE,
	CM_AUTHORIZATION_REJECTED,
	CM_USER_UNKNOWN,
	CM_RATING_FAILED = 23,
};

enum session_release_cause_value{
	UNSPECIFIED_REASON = 0,
	UE_SUBSCRIPTION_REASON,
	INSUFFICIENT_SERVER_RESOURCES,
	IP_CAN_SESSION_TERMINATION,
	UE_IP_ADDRESS_SESS_RELEASE,
};

enum usage_monitoring_level_value{
	SESSION_LEVEL = 0,
	PCC_RULE_LEVEL,
	ADC_RULE_LEVEL,
};

enum usage_monitoring_report_value{
	USAGE_MONITORING_REPORT_REQUIRED = 0,
};

enum usage_monitoring_support_value{
	USAGE_MONITORING_DISABLED = 0 ,
};

enum user_equipment_info_type{
	IMEISV = 0,
};

enum subscription_id_type{
	END_USER_E164 = 0,
	END_USER_IMSI,
	END_USER_SIP_URI,
	END_USER_NAI,
	END_USER_PRIVATE,
};
#endif /* __GX_DEF_H__ */
