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

#ifndef __GX_STRUCT_H__
#define __GX_STRUCT_H__

#include "gx_def.h"
#include "stdint.h"
#include "fd.h"

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************************/
/***** OctetString Structures                                             *****/
/******************************************************************************/

typedef struct gxMeasurementQuantityOctetString {
    uint32_t len;
    uint8_t val[GX_MEASUREMENT_QUANTITY_LEN + 1];
} GxMeasurementQuantityOctetString;

typedef struct gxMdtAllowedPlmnIdOctetString {
    uint32_t len;
    uint8_t val[GX_MDT_ALLOWED_PLMN_ID_LEN + 1];
} GxMdtAllowedPlmnIdOctetString;

typedef struct gxOriginRealmOctetString {
    uint32_t len;
    uint8_t val[GX_ORIGIN_REALM_LEN + 1];
} GxOriginRealmOctetString;

typedef struct gx3gppSelectionModeOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_SELECTION_MODE_LEN + 1];
} Gx3gppSelectionModeOctetString;

typedef struct gxRoutingRuleIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_ROUTING_RULE_IDENTIFIER_LEN + 1];
} GxRoutingRuleIdentifierOctetString;

typedef struct gxTosTrafficClassOctetString {
    uint32_t len;
    uint8_t val[GX_TOS_TRAFFIC_CLASS_LEN + 1];
} GxTosTrafficClassOctetString;

typedef struct gxRanNasReleaseCauseOctetString {
    uint32_t len;
    uint8_t val[GX_RAN_NAS_RELEASE_CAUSE_LEN + 1];
} GxRanNasReleaseCauseOctetString;

typedef struct gxPrimaryChargingCollectionFunctionNameOctetString {
    uint32_t len;
    uint8_t val[GX_PRIMARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN + 1];
} GxPrimaryChargingCollectionFunctionNameOctetString;

typedef struct gxTraceInterfaceListOctetString {
    uint32_t len;
    uint8_t val[GX_TRACE_INTERFACE_LIST_LEN + 1];
} GxTraceInterfaceListOctetString;

typedef struct gxTraceEventListOctetString {
    uint32_t len;
    uint8_t val[GX_TRACE_EVENT_LIST_LEN + 1];
} GxTraceEventListOctetString;

typedef struct gx3gppChargingCharacteristicsOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_CHARGING_CHARACTERISTICS_LEN + 1];
} Gx3gppChargingCharacteristicsOctetString;

typedef struct gxTdfApplicationInstanceIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_TDF_APPLICATION_INSTANCE_IDENTIFIER_LEN + 1];
} GxTdfApplicationInstanceIdentifierOctetString;

typedef struct gxCellGlobalIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_CELL_GLOBAL_IDENTITY_LEN + 1];
} GxCellGlobalIdentityOctetString;

typedef struct gxPresenceReportingAreaIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_PRESENCE_REPORTING_AREA_IDENTIFIER_LEN + 1];
} GxPresenceReportingAreaIdentifierOctetString;

typedef struct gxDefaultQosNameOctetString {
    uint32_t len;
    uint8_t val[GX_DEFAULT_QOS_NAME_LEN + 1];
} GxDefaultQosNameOctetString;

typedef struct gxBearerIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_BEARER_IDENTIFIER_LEN + 1];
} GxBearerIdentifierOctetString;

typedef struct gx3gppGgsnIpv6AddressOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_GGSN_IPV6_ADDRESS_LEN + 1];
} Gx3gppGgsnIpv6AddressOctetString;

typedef struct gx3gpp2BsidOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP2_BSID_LEN + 1];
} Gx3gpp2BsidOctetString;

typedef struct gxOriginHostOctetString {
    uint32_t len;
    uint8_t val[GX_ORIGIN_HOST_LEN + 1];
} GxOriginHostOctetString;

typedef struct gxServiceContextIdOctetString {
    uint32_t len;
    uint8_t val[GX_SERVICE_CONTEXT_ID_LEN + 1];
} GxServiceContextIdOctetString;

typedef struct gxPacketFilterIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_PACKET_FILTER_IDENTIFIER_LEN + 1];
} GxPacketFilterIdentifierOctetString;

typedef struct gxPhysicalAccessIdOctetString {
    uint32_t len;
    uint8_t val[GX_PHYSICAL_ACCESS_ID_LEN + 1];
} GxPhysicalAccessIdOctetString;

typedef struct gxTunnelHeaderFilterOctetString {
    uint32_t len;
    uint8_t val[GX_TUNNEL_HEADER_FILTER_LEN + 1];
} GxTunnelHeaderFilterOctetString;

typedef struct gxTraceNeTypeListOctetString {
    uint32_t len;
    uint8_t val[GX_TRACE_NE_TYPE_LIST_LEN + 1];
} GxTraceNeTypeListOctetString;

typedef struct gxSecondaryEventChargingFunctionNameOctetString {
    uint32_t len;
    uint8_t val[GX_SECONDARY_EVENT_CHARGING_FUNCTION_NAME_LEN + 1];
} GxSecondaryEventChargingFunctionNameOctetString;

typedef struct gxAccessNetworkChargingIdentifierValueOctetString {
    uint32_t len;
    uint8_t val[GX_ACCESS_NETWORK_CHARGING_IDENTIFIER_VALUE_LEN + 1];
} GxAccessNetworkChargingIdentifierValueOctetString;

typedef struct gxSourceidOctetString {
    uint32_t len;
    uint8_t val[GX_SOURCEID_LEN + 1];
} GxSourceidOctetString;

typedef struct gxChargingRuleNameOctetString {
    uint32_t len;
    uint8_t val[GX_CHARGING_RULE_NAME_LEN + 1];
} GxChargingRuleNameOctetString;

typedef struct gxErrorMessageOctetString {
    uint32_t len;
    uint8_t val[GX_ERROR_MESSAGE_LEN + 1];
} GxErrorMessageOctetString;

typedef struct gxSubscriptionIdDataOctetString {
    uint32_t len;
    uint8_t val[GX_SUBSCRIPTION_ID_DATA_LEN + 1];
} GxSubscriptionIdDataOctetString;

typedef struct gx3gppSgsnMccMncOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_SGSN_MCC_MNC_LEN + 1];
} Gx3gppSgsnMccMncOctetString;

typedef struct gxRaiOctetString {
    uint32_t len;
    uint8_t val[GX_RAI_LEN + 1];
} GxRaiOctetString;

typedef struct gxUserEquipmentInfoValueOctetString {
    uint32_t len;
    uint8_t val[GX_USER_EQUIPMENT_INFO_VALUE_LEN + 1];
} GxUserEquipmentInfoValueOctetString;

typedef struct gxFlowDescriptionOctetString {
    uint32_t len;
    uint8_t val[GX_FLOW_DESCRIPTION_LEN + 1];
} GxFlowDescriptionOctetString;

typedef struct gxTdfDestinationRealmOctetString {
    uint32_t len;
    uint8_t val[GX_TDF_DESTINATION_REALM_LEN + 1];
} GxTdfDestinationRealmOctetString;

typedef struct gxFilterIdOctetString {
    uint32_t len;
    uint8_t val[GX_FILTER_ID_LEN + 1];
} GxFilterIdOctetString;

typedef struct gx3gppRatTypeOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_RAT_TYPE_LEN + 1];
} Gx3gppRatTypeOctetString;

typedef struct gxPdnConnectionIdOctetString {
    uint32_t len;
    uint8_t val[GX_PDN_CONNECTION_ID_LEN + 1];
} GxPdnConnectionIdOctetString;

typedef struct gxChargingRuleBaseNameOctetString {
    uint32_t len;
    uint8_t val[GX_CHARGING_RULE_BASE_NAME_LEN + 1];
} GxChargingRuleBaseNameOctetString;

typedef struct gxFramedIpAddressOctetString {
    uint32_t len;
    uint8_t val[GX_FRAMED_IP_ADDRESS_LEN + 1];
} GxFramedIpAddressOctetString;

typedef struct gxLogicalAccessIdOctetString {
    uint32_t len;
    uint8_t val[GX_LOGICAL_ACCESS_ID_LEN + 1];
} GxLogicalAccessIdOctetString;

typedef struct gxFramedIpv6PrefixOctetString {
    uint32_t len;
    uint8_t val[GX_FRAMED_IPV6_PREFIX_LEN + 1];
} GxFramedIpv6PrefixOctetString;

typedef struct gxEUtranCellGlobalIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_E_UTRAN_CELL_GLOBAL_IDENTITY_LEN + 1];
} GxEUtranCellGlobalIdentityOctetString;

typedef struct gxLocationAreaIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_LOCATION_AREA_IDENTITY_LEN + 1];
} GxLocationAreaIdentityOctetString;

typedef struct gxSecurityParameterIndexOctetString {
    uint32_t len;
    uint8_t val[GX_SECURITY_PARAMETER_INDEX_LEN + 1];
} GxSecurityParameterIndexOctetString;

typedef struct gxTdfDestinationHostOctetString {
    uint32_t len;
    uint8_t val[GX_TDF_DESTINATION_HOST_LEN + 1];
} GxTdfDestinationHostOctetString;

typedef struct gxRoutingAreaIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_ROUTING_AREA_IDENTITY_LEN + 1];
} GxRoutingAreaIdentityOctetString;

typedef struct gxTrackingAreaIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_TRACKING_AREA_IDENTITY_LEN + 1];
} GxTrackingAreaIdentityOctetString;

typedef struct gx3gppMsTimezoneOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_MS_TIMEZONE_LEN + 1];
} Gx3gppMsTimezoneOctetString;

typedef struct gxPresenceReportingAreaElementsListOctetString {
    uint32_t len;
    uint8_t val[GX_PRESENCE_REPORTING_AREA_ELEMENTS_LIST_LEN + 1];
} GxPresenceReportingAreaElementsListOctetString;

typedef struct gxTwanIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_TWAN_IDENTIFIER_LEN + 1];
} GxTwanIdentifierOctetString;

typedef struct gxSessionIdOctetString {
    uint32_t len;
    uint8_t val[GX_SESSION_ID_LEN + 1];
} GxSessionIdOctetString;

typedef struct gx3gppUserLocationInfoOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_USER_LOCATION_INFO_LEN + 1];
} Gx3gppUserLocationInfoOctetString;

typedef struct gxRestrictionFilterRuleOctetString {
    uint32_t len;
    uint8_t val[GX_RESTRICTION_FILTER_RULE_LEN + 1];
} GxRestrictionFilterRuleOctetString;

typedef struct gxSecondaryChargingCollectionFunctionNameOctetString {
    uint32_t len;
    uint8_t val[GX_SECONDARY_CHARGING_COLLECTION_FUNCTION_NAME_LEN + 1];
} GxSecondaryChargingCollectionFunctionNameOctetString;

typedef struct gxApplicationServiceProviderIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_APPLICATION_SERVICE_PROVIDER_IDENTITY_LEN + 1];
} GxApplicationServiceProviderIdentityOctetString;

typedef struct gxTftFilterOctetString {
    uint32_t len;
    uint8_t val[GX_TFT_FILTER_LEN + 1];
} GxTftFilterOctetString;

typedef struct gxTrafficSteeringPolicyIdentifierDlOctetString {
    uint32_t len;
    uint8_t val[GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_DL_LEN + 1];
} GxTrafficSteeringPolicyIdentifierDlOctetString;

typedef struct gxPrimaryEventChargingFunctionNameOctetString {
    uint32_t len;
    uint8_t val[GX_PRIMARY_EVENT_CHARGING_FUNCTION_NAME_LEN + 1];
} GxPrimaryEventChargingFunctionNameOctetString;

typedef struct gxTraceReferenceOctetString {
    uint32_t len;
    uint8_t val[GX_TRACE_REFERENCE_LEN + 1];
} GxTraceReferenceOctetString;

typedef struct gxOmcIdOctetString {
    uint32_t len;
    uint8_t val[GX_OMC_ID_LEN + 1];
} GxOmcIdOctetString;

typedef struct gxSsidOctetString {
    uint32_t len;
    uint8_t val[GX_SSID_LEN + 1];
} GxSsidOctetString;

typedef struct gxBssidOctetString {
    uint32_t len;
    uint8_t val[GX_BSSID_LEN + 1];
} GxBssidOctetString;

typedef struct gxProxyHostOctetString {
    uint32_t len;
    uint8_t val[GX_PROXY_HOST_LEN + 1];
} GxProxyHostOctetString;

typedef struct gxDestinationRealmOctetString {
    uint32_t len;
    uint8_t val[GX_DESTINATION_REALM_LEN + 1];
} GxDestinationRealmOctetString;

typedef struct gxPacketFilterContentOctetString {
    uint32_t len;
    uint8_t val[GX_PACKET_FILTER_CONTENT_LEN + 1];
} GxPacketFilterContentOctetString;

typedef struct gxSponsorIdentityOctetString {
    uint32_t len;
    uint8_t val[GX_SPONSOR_IDENTITY_LEN + 1];
} GxSponsorIdentityOctetString;

typedef struct gx3gppGgsnAddressOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_GGSN_ADDRESS_LEN + 1];
} Gx3gppGgsnAddressOctetString;

typedef struct gxDestinationHostOctetString {
    uint32_t len;
    uint8_t val[GX_DESTINATION_HOST_LEN + 1];
} GxDestinationHostOctetString;

typedef struct gxProxyStateOctetString {
    uint32_t len;
    uint8_t val[GX_PROXY_STATE_LEN + 1];
} GxProxyStateOctetString;

typedef struct gxRedirectServerAddressOctetString {
    uint32_t len;
    uint8_t val[GX_REDIRECT_SERVER_ADDRESS_LEN + 1];
} GxRedirectServerAddressOctetString;

typedef struct gxRedirectHostOctetString {
    uint32_t len;
    uint8_t val[GX_REDIRECT_HOST_LEN + 1];
} GxRedirectHostOctetString;

typedef struct gxTdfApplicationIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_TDF_APPLICATION_IDENTIFIER_LEN + 1];
} GxTdfApplicationIdentifierOctetString;

typedef struct gxFlowLabelOctetString {
    uint32_t len;
    uint8_t val[GX_FLOW_LABEL_LEN + 1];
} GxFlowLabelOctetString;

typedef struct gxCalledStationIdOctetString {
    uint32_t len;
    uint8_t val[GX_CALLED_STATION_ID_LEN + 1];
} GxCalledStationIdOctetString;

typedef struct gxAfChargingIdentifierOctetString {
    uint32_t len;
    uint8_t val[GX_AF_CHARGING_IDENTIFIER_LEN + 1];
} GxAfChargingIdentifierOctetString;

typedef struct gx3gppSgsnAddressOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_SGSN_ADDRESS_LEN + 1];
} Gx3gppSgsnAddressOctetString;

typedef struct gxTrafficSteeringPolicyIdentifierUlOctetString {
    uint32_t len;
    uint8_t val[GX_TRAFFIC_STEERING_POLICY_IDENTIFIER_UL_LEN + 1];
} GxTrafficSteeringPolicyIdentifierUlOctetString;

typedef struct gxPositioningMethodOctetString {
    uint32_t len;
    uint8_t val[GX_POSITIONING_METHOD_LEN + 1];
} GxPositioningMethodOctetString;

typedef struct gxMonitoringKeyOctetString {
    uint32_t len;
    uint8_t val[GX_MONITORING_KEY_LEN + 1];
} GxMonitoringKeyOctetString;

typedef struct gxRouteRecordOctetString {
    uint32_t len;
    uint8_t val[GX_ROUTE_RECORD_LEN + 1];
} GxRouteRecordOctetString;

typedef struct gxErrorReportingHostOctetString {
    uint32_t len;
    uint8_t val[GX_ERROR_REPORTING_HOST_LEN + 1];
} GxErrorReportingHostOctetString;

typedef struct gx3gppSgsnIpv6AddressOctetString {
    uint32_t len;
    uint8_t val[GX_3GPP_SGSN_IPV6_ADDRESS_LEN + 1];
} Gx3gppSgsnIpv6AddressOctetString;

/******************************************************************************/
/***** Presence Structures                                                *****/
/******************************************************************************/

typedef struct gxExperimentalResultPresence {
    unsigned int vendor_id                : 1;
    unsigned int experimental_result_code : 1;
} GxExperimentalResultPresence;

typedef struct gxPraRemovePresence {
    unsigned int presence_reporting_area_identifier : 1;
} GxPraRemovePresence;

typedef struct gxQosInformationPresence {
    unsigned int qos_class_identifier                  : 1;
    unsigned int max_requested_bandwidth_ul            : 1;
    unsigned int max_requested_bandwidth_dl            : 1;
    unsigned int extended_max_requested_bw_ul          : 1;
    unsigned int extended_max_requested_bw_dl          : 1;
    unsigned int guaranteed_bitrate_ul                 : 1;
    unsigned int guaranteed_bitrate_dl                 : 1;
    unsigned int extended_gbr_ul                       : 1;
    unsigned int extended_gbr_dl                       : 1;
    unsigned int bearer_identifier                     : 1;
    unsigned int allocation_retention_priority         : 1;
    unsigned int apn_aggregate_max_bitrate_ul          : 1;
    unsigned int apn_aggregate_max_bitrate_dl          : 1;
    unsigned int extended_apn_ambr_ul                  : 1;
    unsigned int extended_apn_ambr_dl                  : 1;
    unsigned int conditional_apn_aggregate_max_bitrate : 1;
} GxQosInformationPresence;

typedef struct gxConditionalPolicyInformationPresence {
    unsigned int execution_time                        : 1;
    unsigned int default_eps_bearer_qos                : 1;
    unsigned int apn_aggregate_max_bitrate_ul          : 1;
    unsigned int apn_aggregate_max_bitrate_dl          : 1;
    unsigned int extended_apn_ambr_ul                  : 1;
    unsigned int extended_apn_ambr_dl                  : 1;
    unsigned int conditional_apn_aggregate_max_bitrate : 1;
} GxConditionalPolicyInformationPresence;

typedef struct gxPraInstallPresence {
    unsigned int presence_reporting_area_information : 1;
} GxPraInstallPresence;

typedef struct gxAreaScopePresence {
    unsigned int cell_global_identity         : 1;
    unsigned int e_utran_cell_global_identity : 1;
    unsigned int routing_area_identity        : 1;
    unsigned int location_area_identity       : 1;
    unsigned int tracking_area_identity       : 1;
} GxAreaScopePresence;

typedef struct gxFlowInformationPresence {
    unsigned int flow_description         : 1;
    unsigned int packet_filter_identifier : 1;
    unsigned int packet_filter_usage      : 1;
    unsigned int tos_traffic_class        : 1;
    unsigned int security_parameter_index : 1;
    unsigned int flow_label               : 1;
    unsigned int flow_direction           : 1;
    unsigned int routing_rule_identifier  : 1;
} GxFlowInformationPresence;

typedef struct gxTunnelInformationPresence {
    unsigned int tunnel_header_length : 1;
    unsigned int tunnel_header_filter : 1;
} GxTunnelInformationPresence;

typedef struct gxTftPacketFilterInformationPresence {
    unsigned int precedence               : 1;
    unsigned int tft_filter               : 1;
    unsigned int tos_traffic_class        : 1;
    unsigned int security_parameter_index : 1;
    unsigned int flow_label               : 1;
    unsigned int flow_direction           : 1;
} GxTftPacketFilterInformationPresence;

typedef struct gxMbsfnAreaPresence {
    unsigned int mbsfn_area_id     : 1;
    unsigned int carrier_frequency : 1;
} GxMbsfnAreaPresence;

typedef struct gxEventReportIndicationPresence {
    unsigned int an_trusted                          : 1;
    unsigned int event_trigger                       : 1;
    unsigned int user_csg_information                : 1;
    unsigned int ip_can_type                         : 1;
    unsigned int an_gw_address                       : 1;
    unsigned int tgpp_sgsn_address                   : 1;
    unsigned int tgpp_sgsn_ipv6_address              : 1;
    unsigned int tgpp_sgsn_mcc_mnc                   : 1;
    unsigned int framed_ip_address                   : 1;
    unsigned int rat_type                            : 1;
    unsigned int rai                                 : 1;
    unsigned int tgpp_user_location_info             : 1;
    unsigned int trace_data                          : 1;
    unsigned int trace_reference                     : 1;
    unsigned int tgpp2_bsid                          : 1;
    unsigned int tgpp_ms_timezone                    : 1;
    unsigned int routing_ip_address                  : 1;
    unsigned int ue_local_ip_address                 : 1;
    unsigned int henb_local_ip_address               : 1;
    unsigned int udp_source_port                     : 1;
    unsigned int presence_reporting_area_information : 1;
} GxEventReportIndicationPresence;

typedef struct gxTdfInformationPresence {
    unsigned int tdf_destination_realm : 1;
    unsigned int tdf_destination_host  : 1;
    unsigned int tdf_ip_address        : 1;
} GxTdfInformationPresence;

typedef struct gxProxyInfoPresence {
    unsigned int proxy_host  : 1;
    unsigned int proxy_state : 1;
} GxProxyInfoPresence;

typedef struct gxUsedServiceUnitPresence {
    unsigned int reporting_reason          : 1;
    unsigned int tariff_change_usage       : 1;
    unsigned int cc_time                   : 1;
    unsigned int cc_money                  : 1;
    unsigned int cc_total_octets           : 1;
    unsigned int cc_input_octets           : 1;
    unsigned int cc_output_octets          : 1;
    unsigned int cc_service_specific_units : 1;
    unsigned int event_charging_timestamp  : 1;
} GxUsedServiceUnitPresence;

typedef struct gxChargingRuleInstallPresence {
    unsigned int charging_rule_definition         : 1;
    unsigned int charging_rule_name               : 1;
    unsigned int charging_rule_base_name          : 1;
    unsigned int bearer_identifier                : 1;
    unsigned int monitoring_flags                 : 1;
    unsigned int rule_activation_time             : 1;
    unsigned int rule_deactivation_time           : 1;
    unsigned int resource_allocation_notification : 1;
    unsigned int charging_correlation_indicator   : 1;
    unsigned int ip_can_type                      : 1;
} GxChargingRuleInstallPresence;

typedef struct gxChargingRuleDefinitionPresence {
    unsigned int charging_rule_name                    : 1;
    unsigned int service_identifier                    : 1;
    unsigned int rating_group                          : 1;
    unsigned int flow_information                      : 1;
    unsigned int default_bearer_indication             : 1;
    unsigned int tdf_application_identifier            : 1;
    unsigned int flow_status                           : 1;
    unsigned int qos_information                       : 1;
    unsigned int ps_to_cs_session_continuity           : 1;
    unsigned int reporting_level                       : 1;
    unsigned int online                                : 1;
    unsigned int offline                               : 1;
    unsigned int max_plr_dl                            : 1;
    unsigned int max_plr_ul                            : 1;
    unsigned int metering_method                       : 1;
    unsigned int precedence                            : 1;
    unsigned int af_charging_identifier                : 1;
    unsigned int flows                                 : 1;
    unsigned int monitoring_key                        : 1;
    unsigned int redirect_information                  : 1;
    unsigned int mute_notification                     : 1;
    unsigned int af_signalling_protocol                : 1;
    unsigned int sponsor_identity                      : 1;
    unsigned int application_service_provider_identity : 1;
    unsigned int required_access_info                  : 1;
    unsigned int sharing_key_dl                        : 1;
    unsigned int sharing_key_ul                        : 1;
    unsigned int traffic_steering_policy_identifier_dl : 1;
    unsigned int traffic_steering_policy_identifier_ul : 1;
    unsigned int content_version                       : 1;
} GxChargingRuleDefinitionPresence;

typedef struct gxFinalUnitIndicationPresence {
    unsigned int final_unit_action       : 1;
    unsigned int restriction_filter_rule : 1;
    unsigned int filter_id               : 1;
    unsigned int redirect_server         : 1;
} GxFinalUnitIndicationPresence;

typedef struct gxUnitValuePresence {
    unsigned int value_digits : 1;
    unsigned int exponent     : 1;
} GxUnitValuePresence;

typedef struct gxPresenceReportingAreaInformationPresence {
    unsigned int presence_reporting_area_identifier    : 1;
    unsigned int presence_reporting_area_status        : 1;
    unsigned int presence_reporting_area_elements_list : 1;
    unsigned int presence_reporting_area_node          : 1;
} GxPresenceReportingAreaInformationPresence;

typedef struct gxConditionalApnAggregateMaxBitratePresence {
    unsigned int apn_aggregate_max_bitrate_ul : 1;
    unsigned int apn_aggregate_max_bitrate_dl : 1;
    unsigned int extended_apn_ambr_ul         : 1;
    unsigned int extended_apn_ambr_dl         : 1;
    unsigned int ip_can_type                  : 1;
    unsigned int rat_type                     : 1;
} GxConditionalApnAggregateMaxBitratePresence;

typedef struct gxAccessNetworkChargingIdentifierGxPresence {
    unsigned int access_network_charging_identifier_value : 1;
    unsigned int charging_rule_base_name                  : 1;
    unsigned int charging_rule_name                       : 1;
    unsigned int ip_can_session_charging_scope            : 1;
} GxAccessNetworkChargingIdentifierGxPresence;

typedef struct gxOcOlrPresence {
    unsigned int oc_sequence_number      : 1;
    unsigned int oc_report_type          : 1;
    unsigned int oc_reduction_percentage : 1;
    unsigned int oc_validity_duration    : 1;
} GxOcOlrPresence;

typedef struct gxRoutingRuleInstallPresence {
    unsigned int routing_rule_definition : 1;
} GxRoutingRuleInstallPresence;

typedef struct gxTraceDataPresence {
    unsigned int trace_reference         : 1;
    unsigned int trace_depth             : 1;
    unsigned int trace_ne_type_list      : 1;
    unsigned int trace_interface_list    : 1;
    unsigned int trace_event_list        : 1;
    unsigned int omc_id                  : 1;
    unsigned int trace_collection_entity : 1;
    unsigned int mdt_configuration       : 1;
} GxTraceDataPresence;

typedef struct gxRoutingRuleDefinitionPresence {
    unsigned int routing_rule_identifier : 1;
    unsigned int routing_filter          : 1;
    unsigned int precedence              : 1;
    unsigned int routing_ip_address      : 1;
    unsigned int ip_can_type             : 1;
} GxRoutingRuleDefinitionPresence;

typedef struct gxMdtConfigurationPresence {
    unsigned int job_type                   : 1;
    unsigned int area_scope                 : 1;
    unsigned int list_of_measurements       : 1;
    unsigned int reporting_trigger          : 1;
    unsigned int report_interval            : 1;
    unsigned int report_amount              : 1;
    unsigned int event_threshold_rsrp       : 1;
    unsigned int event_threshold_rsrq       : 1;
    unsigned int logging_interval           : 1;
    unsigned int logging_duration           : 1;
    unsigned int measurement_period_lte     : 1;
    unsigned int measurement_period_umts    : 1;
    unsigned int collection_period_rrm_lte  : 1;
    unsigned int collection_period_rrm_umts : 1;
    unsigned int positioning_method         : 1;
    unsigned int measurement_quantity       : 1;
    unsigned int event_threshold_event_1f   : 1;
    unsigned int event_threshold_event_1i   : 1;
    unsigned int mdt_allowed_plmn_id        : 1;
    unsigned int mbsfn_area                 : 1;
} GxMdtConfigurationPresence;

typedef struct gxChargingRuleRemovePresence {
    unsigned int charging_rule_name            : 1;
    unsigned int charging_rule_base_name       : 1;
    unsigned int required_access_info          : 1;
    unsigned int resource_release_notification : 1;
} GxChargingRuleRemovePresence;

typedef struct gxAllocationRetentionPriorityPresence {
    unsigned int priority_level            : 1;
    unsigned int pre_emption_capability    : 1;
    unsigned int pre_emption_vulnerability : 1;
} GxAllocationRetentionPriorityPresence;

typedef struct gxDefaultEpsBearerQosPresence {
    unsigned int qos_class_identifier          : 1;
    unsigned int allocation_retention_priority : 1;
} GxDefaultEpsBearerQosPresence;

typedef struct gxRoutingRuleReportPresence {
    unsigned int routing_rule_identifier   : 1;
    unsigned int pcc_rule_status           : 1;
    unsigned int routing_rule_failure_code : 1;
} GxRoutingRuleReportPresence;

typedef struct gxUserEquipmentInfoPresence {
    unsigned int user_equipment_info_type  : 1;
    unsigned int user_equipment_info_value : 1;
} GxUserEquipmentInfoPresence;

typedef struct gxSupportedFeaturesPresence {
    unsigned int vendor_id       : 1;
    unsigned int feature_list_id : 1;
    unsigned int feature_list    : 1;
} GxSupportedFeaturesPresence;

typedef struct gxFixedUserLocationInfoPresence {
    unsigned int ssid               : 1;
    unsigned int bssid              : 1;
    unsigned int logical_access_id  : 1;
    unsigned int physical_access_id : 1;
} GxFixedUserLocationInfoPresence;

typedef struct gxDefaultQosInformationPresence {
    unsigned int qos_class_identifier       : 1;
    unsigned int max_requested_bandwidth_ul : 1;
    unsigned int max_requested_bandwidth_dl : 1;
    unsigned int default_qos_name           : 1;
} GxDefaultQosInformationPresence;

typedef struct gxLoadPresence {
    unsigned int load_type  : 1;
    unsigned int load_value : 1;
    unsigned int sourceid   : 1;
} GxLoadPresence;

typedef struct gxRedirectServerPresence {
    unsigned int redirect_address_type   : 1;
    unsigned int redirect_server_address : 1;
} GxRedirectServerPresence;

typedef struct gxOcSupportedFeaturesPresence {
    unsigned int oc_feature_vector : 1;
} GxOcSupportedFeaturesPresence;

typedef struct gxPacketFilterInformationPresence {
    unsigned int packet_filter_identifier : 1;
    unsigned int precedence               : 1;
    unsigned int packet_filter_content    : 1;
    unsigned int tos_traffic_class        : 1;
    unsigned int security_parameter_index : 1;
    unsigned int flow_label               : 1;
    unsigned int flow_direction           : 1;
} GxPacketFilterInformationPresence;

typedef struct gxSubscriptionIdPresence {
    unsigned int subscription_id_type : 1;
    unsigned int subscription_id_data : 1;
} GxSubscriptionIdPresence;

typedef struct gxChargingInformationPresence {
    unsigned int primary_event_charging_function_name        : 1;
    unsigned int secondary_event_charging_function_name      : 1;
    unsigned int primary_charging_collection_function_name   : 1;
    unsigned int secondary_charging_collection_function_name : 1;
} GxChargingInformationPresence;

typedef struct gxUsageMonitoringInformationPresence {
    unsigned int monitoring_key           : 1;
    unsigned int granted_service_unit     : 1;
    unsigned int used_service_unit        : 1;
    unsigned int quota_consumption_time   : 1;
    unsigned int usage_monitoring_level   : 1;
    unsigned int usage_monitoring_report  : 1;
    unsigned int usage_monitoring_support : 1;
} GxUsageMonitoringInformationPresence;

typedef struct gxChargingRuleReportPresence {
    unsigned int charging_rule_name      : 1;
    unsigned int charging_rule_base_name : 1;
    unsigned int bearer_identifier       : 1;
    unsigned int pcc_rule_status         : 1;
    unsigned int rule_failure_code       : 1;
    unsigned int final_unit_indication   : 1;
    unsigned int ran_nas_release_cause   : 1;
    unsigned int content_version         : 1;
} GxChargingRuleReportPresence;

typedef struct gxRedirectInformationPresence {
    unsigned int redirect_support        : 1;
    unsigned int redirect_address_type   : 1;
    unsigned int redirect_server_address : 1;
} GxRedirectInformationPresence;

typedef struct gxFailedAvpPresence {
} GxFailedAvpPresence;

typedef struct gxRoutingRuleRemovePresence {
    unsigned int routing_rule_identifier : 1;
} GxRoutingRuleRemovePresence;

typedef struct gxRoutingFilterPresence {
    unsigned int flow_description         : 1;
    unsigned int flow_direction           : 1;
    unsigned int tos_traffic_class        : 1;
    unsigned int security_parameter_index : 1;
    unsigned int flow_label               : 1;
} GxRoutingFilterPresence;

typedef struct gxCoaInformationPresence {
    unsigned int tunnel_information : 1;
    unsigned int coa_ip_address     : 1;
} GxCoaInformationPresence;

typedef struct gxGrantedServiceUnitPresence {
    unsigned int tariff_time_change        : 1;
    unsigned int cc_time                   : 1;
    unsigned int cc_money                  : 1;
    unsigned int cc_total_octets           : 1;
    unsigned int cc_input_octets           : 1;
    unsigned int cc_output_octets          : 1;
    unsigned int cc_service_specific_units : 1;
} GxGrantedServiceUnitPresence;

typedef struct gxCcMoneyPresence {
    unsigned int unit_value    : 1;
    unsigned int currency_code : 1;
} GxCcMoneyPresence;

typedef struct gxApplicationDetectionInformationPresence {
    unsigned int tdf_application_identifier          : 1;
    unsigned int tdf_application_instance_identifier : 1;
    unsigned int flow_information                    : 1;
} GxApplicationDetectionInformationPresence;

typedef struct gxFlowsPresence {
    unsigned int media_component_number : 1;
    unsigned int flow_number            : 1;
    unsigned int content_version        : 1;
    unsigned int final_unit_action      : 1;
    unsigned int media_component_status : 1;
} GxFlowsPresence;

typedef struct gxUserCsgInformationPresence {
    unsigned int csg_id                    : 1;
    unsigned int csg_access_mode           : 1;
    unsigned int csg_membership_indication : 1;
} GxUserCsgInformationPresence;

typedef struct gxRarPresence {
    unsigned int session_id                     : 1;
    unsigned int drmp                           : 1;
    unsigned int auth_application_id            : 1;
    unsigned int origin_host                    : 1;
    unsigned int origin_realm                   : 1;
    unsigned int destination_realm              : 1;
    unsigned int destination_host               : 1;
    unsigned int re_auth_request_type           : 1;
    unsigned int session_release_cause          : 1;
    unsigned int origin_state_id                : 1;
    unsigned int oc_supported_features          : 1;
    unsigned int event_trigger                  : 1;
    unsigned int event_report_indication        : 1;
    unsigned int charging_rule_remove           : 1;
    unsigned int charging_rule_install          : 1;
    unsigned int default_eps_bearer_qos         : 1;
    unsigned int qos_information                : 1;
    unsigned int default_qos_information        : 1;
    unsigned int revalidation_time              : 1;
    unsigned int usage_monitoring_information   : 1;
    unsigned int pcscf_restoration_indication   : 1;
    unsigned int conditional_policy_information : 1;
    unsigned int removal_of_access              : 1;
    unsigned int ip_can_type                    : 1;
    unsigned int pra_install                    : 1;
    unsigned int pra_remove                     : 1;
    unsigned int csg_information_reporting      : 1;
    unsigned int proxy_info                     : 1;
    unsigned int route_record                   : 1;
} GxRarPresence;

typedef struct gxRaaPresence {
    unsigned int session_id              : 1;
    unsigned int drmp                    : 1;
    unsigned int origin_host             : 1;
    unsigned int origin_realm            : 1;
    unsigned int result_code             : 1;
    unsigned int experimental_result     : 1;
    unsigned int origin_state_id         : 1;
    unsigned int oc_supported_features   : 1;
    unsigned int oc_olr                  : 1;
    unsigned int ip_can_type             : 1;
    unsigned int rat_type                : 1;
    unsigned int an_trusted              : 1;
    unsigned int an_gw_address           : 1;
    unsigned int tgpp_sgsn_mcc_mnc       : 1;
    unsigned int tgpp_sgsn_address       : 1;
    unsigned int tgpp_sgsn_ipv6_address  : 1;
    unsigned int rai                     : 1;
    unsigned int tgpp_user_location_info : 1;
    unsigned int user_location_info_time : 1;
    unsigned int netloc_access_support   : 1;
    unsigned int user_csg_information    : 1;
    unsigned int tgpp_ms_timezone        : 1;
    unsigned int default_qos_information : 1;
    unsigned int charging_rule_report    : 1;
    unsigned int error_message           : 1;
    unsigned int error_reporting_host    : 1;
    unsigned int failed_avp              : 1;
    unsigned int proxy_info              : 1;
} GxRaaPresence;

typedef struct gxCcaPresence {
    unsigned int session_id                          : 1;
    unsigned int drmp                                : 1;
    unsigned int auth_application_id                 : 1;
    unsigned int origin_host                         : 1;
    unsigned int origin_realm                        : 1;
    unsigned int result_code                         : 1;
    unsigned int experimental_result                 : 1;
    unsigned int cc_request_type                     : 1;
    unsigned int cc_request_number                   : 1;
    unsigned int oc_supported_features               : 1;
    unsigned int oc_olr                              : 1;
    unsigned int supported_features                  : 1;
    unsigned int bearer_control_mode                 : 1;
    unsigned int event_trigger                       : 1;
    unsigned int event_report_indication             : 1;
    unsigned int origin_state_id                     : 1;
    unsigned int redirect_host                       : 1;
    unsigned int redirect_host_usage                 : 1;
    unsigned int redirect_max_cache_time             : 1;
    unsigned int charging_rule_remove                : 1;
    unsigned int charging_rule_install               : 1;
    unsigned int charging_information                : 1;
    unsigned int online                              : 1;
    unsigned int offline                             : 1;
    unsigned int qos_information                     : 1;
    unsigned int revalidation_time                   : 1;
    unsigned int default_eps_bearer_qos              : 1;
    unsigned int default_qos_information             : 1;
    unsigned int bearer_usage                        : 1;
    unsigned int usage_monitoring_information        : 1;
    unsigned int csg_information_reporting           : 1;
    unsigned int user_csg_information                : 1;
    unsigned int pra_install                         : 1;
    unsigned int pra_remove                          : 1;
    unsigned int presence_reporting_area_information : 1;
    unsigned int session_release_cause               : 1;
    unsigned int nbifom_support                      : 1;
    unsigned int nbifom_mode                         : 1;
    unsigned int default_access                      : 1;
    unsigned int ran_rule_support                    : 1;
    unsigned int routing_rule_report                 : 1;
    unsigned int conditional_policy_information      : 1;
    unsigned int removal_of_access                   : 1;
    unsigned int ip_can_type                         : 1;
    unsigned int error_message                       : 1;
    unsigned int error_reporting_host                : 1;
    unsigned int failed_avp                          : 1;
    unsigned int proxy_info                          : 1;
    unsigned int route_record                        : 1;
    unsigned int load                                : 1;
} GxCcaPresence;

typedef struct gxCcrPresence {
    unsigned int session_id                            : 1;
    unsigned int drmp                                  : 1;
    unsigned int auth_application_id                   : 1;
    unsigned int origin_host                           : 1;
    unsigned int origin_realm                          : 1;
    unsigned int destination_realm                     : 1;
    unsigned int service_context_id                    : 1;
    unsigned int cc_request_type                       : 1;
    unsigned int cc_request_number                     : 1;
    unsigned int credit_management_status              : 1;
    unsigned int destination_host                      : 1;
    unsigned int origin_state_id                       : 1;
    unsigned int subscription_id                       : 1;
    unsigned int oc_supported_features                 : 1;
    unsigned int supported_features                    : 1;
    unsigned int tdf_information                       : 1;
    unsigned int network_request_support               : 1;
    unsigned int packet_filter_information             : 1;
    unsigned int packet_filter_operation               : 1;
    unsigned int bearer_identifier                     : 1;
    unsigned int bearer_operation                      : 1;
    unsigned int dynamic_address_flag                  : 1;
    unsigned int dynamic_address_flag_extension        : 1;
    unsigned int pdn_connection_charging_id            : 1;
    unsigned int framed_ip_address                     : 1;
    unsigned int framed_ipv6_prefix                    : 1;
    unsigned int ip_can_type                           : 1;
    unsigned int tgpp_rat_type                         : 1;
    unsigned int an_trusted                            : 1;
    unsigned int rat_type                              : 1;
    unsigned int termination_cause                     : 1;
    unsigned int user_equipment_info                   : 1;
    unsigned int qos_information                       : 1;
    unsigned int qos_negotiation                       : 1;
    unsigned int qos_upgrade                           : 1;
    unsigned int default_eps_bearer_qos                : 1;
    unsigned int default_qos_information               : 1;
    unsigned int an_gw_address                         : 1;
    unsigned int an_gw_status                          : 1;
    unsigned int tgpp_sgsn_mcc_mnc                     : 1;
    unsigned int tgpp_sgsn_address                     : 1;
    unsigned int tgpp_sgsn_ipv6_address                : 1;
    unsigned int tgpp_ggsn_address                     : 1;
    unsigned int tgpp_ggsn_ipv6_address                : 1;
    unsigned int tgpp_selection_mode                   : 1;
    unsigned int rai                                   : 1;
    unsigned int tgpp_user_location_info               : 1;
    unsigned int fixed_user_location_info              : 1;
    unsigned int user_location_info_time               : 1;
    unsigned int user_csg_information                  : 1;
    unsigned int twan_identifier                       : 1;
    unsigned int tgpp_ms_timezone                      : 1;
    unsigned int ran_nas_release_cause                 : 1;
    unsigned int tgpp_charging_characteristics         : 1;
    unsigned int called_station_id                     : 1;
    unsigned int pdn_connection_id                     : 1;
    unsigned int bearer_usage                          : 1;
    unsigned int online                                : 1;
    unsigned int offline                               : 1;
    unsigned int tft_packet_filter_information         : 1;
    unsigned int charging_rule_report                  : 1;
    unsigned int application_detection_information     : 1;
    unsigned int event_trigger                         : 1;
    unsigned int event_report_indication               : 1;
    unsigned int access_network_charging_address       : 1;
    unsigned int access_network_charging_identifier_gx : 1;
    unsigned int coa_information                       : 1;
    unsigned int usage_monitoring_information          : 1;
    unsigned int nbifom_support                        : 1;
    unsigned int nbifom_mode                           : 1;
    unsigned int default_access                        : 1;
    unsigned int origination_time_stamp                : 1;
    unsigned int maximum_wait_time                     : 1;
    unsigned int access_availability_change_reason     : 1;
    unsigned int routing_rule_install                  : 1;
    unsigned int routing_rule_remove                   : 1;
    unsigned int henb_local_ip_address                 : 1;
    unsigned int ue_local_ip_address                   : 1;
    unsigned int udp_source_port                       : 1;
    unsigned int tcp_source_port                       : 1;
    unsigned int presence_reporting_area_information   : 1;
    unsigned int logical_access_id                     : 1;
    unsigned int physical_access_id                    : 1;
    unsigned int proxy_info                            : 1;
    unsigned int route_record                          : 1;
    unsigned int tgpp_ps_data_off_status               : 1;
} GxCcrPresence;

/******************************************************************************/
/***** Grouped AVP Structures                                             *****/
/******************************************************************************/

typedef struct gxRouteRecordList {
    int32_t count;
    GxRouteRecordOctetString *list;
} GxRouteRecordList;

typedef struct gxProxyInfo {
    GxProxyInfoPresence presence;
    GxProxyHostOctetString proxy_host;
    GxProxyStateOctetString proxy_state;
} GxProxyInfo;

typedef struct gxProxyInfoList {
    int32_t count;
    GxProxyInfo *list;
} GxProxyInfoList;

typedef struct gxPresenceReportingAreaInformation {
    GxPresenceReportingAreaInformationPresence presence;
    GxPresenceReportingAreaIdentifierOctetString presence_reporting_area_identifier;
    uint32_t presence_reporting_area_status;
    GxPresenceReportingAreaElementsListOctetString presence_reporting_area_elements_list;
    uint32_t presence_reporting_area_node;
} GxPresenceReportingAreaInformation;

typedef struct gxPresenceReportingAreaInformationList {
    int32_t count;
    GxPresenceReportingAreaInformation *list;
} GxPresenceReportingAreaInformationList;

typedef struct gxRoutingRuleIdentifierList {
    int32_t count;
    GxRoutingRuleIdentifierOctetString *list;
} GxRoutingRuleIdentifierList;

typedef struct gxRoutingRuleRemove {
    GxRoutingRuleRemovePresence presence;
    GxRoutingRuleIdentifierList routing_rule_identifier;
} GxRoutingRuleRemove;

typedef struct gxRoutingFilter {
    GxRoutingFilterPresence presence;
    GxFlowDescriptionOctetString flow_description;
    int32_t flow_direction;
    GxTosTrafficClassOctetString tos_traffic_class;
    GxSecurityParameterIndexOctetString security_parameter_index;
    GxFlowLabelOctetString flow_label;
} GxRoutingFilter;

typedef struct gxRoutingFilterList {
    int32_t count;
    GxRoutingFilter *list;
} GxRoutingFilterList;

typedef struct gxRoutingRuleDefinition {
    GxRoutingRuleDefinitionPresence presence;
    GxRoutingRuleIdentifierOctetString routing_rule_identifier;
    GxRoutingFilterList routing_filter;
    uint32_t precedence;
    FdAddress routing_ip_address;
    int32_t ip_can_type;
} GxRoutingRuleDefinition;

typedef struct gxRoutingRuleDefinitionList {
    int32_t count;
    GxRoutingRuleDefinition *list;
} GxRoutingRuleDefinitionList;

typedef struct gxRoutingRuleInstall {
    GxRoutingRuleInstallPresence presence;
    GxRoutingRuleDefinitionList routing_rule_definition;
} GxRoutingRuleInstall;

typedef struct gxEventChargingTimestampList {
    int32_t count;
    FdTime *list;
} GxEventChargingTimestampList;

typedef struct gxUnitValue {
    GxUnitValuePresence presence;
    int64_t value_digits;
    int32_t exponent;
} GxUnitValue;

typedef struct gxCcMoney {
    GxCcMoneyPresence presence;
    GxUnitValue unit_value;
    uint32_t currency_code;
} GxCcMoney;

typedef struct gxUsedServiceUnit {
    GxUsedServiceUnitPresence presence;
    int32_t reporting_reason;
    int32_t tariff_change_usage;
    uint32_t cc_time;
    GxCcMoney cc_money;
    uint64_t cc_total_octets;
    uint64_t cc_input_octets;
    uint64_t cc_output_octets;
    uint64_t cc_service_specific_units;
    GxEventChargingTimestampList event_charging_timestamp;
} GxUsedServiceUnit;

typedef struct gxUsedServiceUnitList {
    int32_t count;
    GxUsedServiceUnit *list;
} GxUsedServiceUnitList;

typedef struct gxGrantedServiceUnit {
    GxGrantedServiceUnitPresence presence;
    FdTime tariff_time_change;
    uint32_t cc_time;
    GxCcMoney cc_money;
    uint64_t cc_total_octets;
    uint64_t cc_input_octets;
    uint64_t cc_output_octets;
    uint64_t cc_service_specific_units;
} GxGrantedServiceUnit;

typedef struct gxGrantedServiceUnitList {
    int32_t count;
    GxGrantedServiceUnit *list;
} GxGrantedServiceUnitList;

typedef struct gxUsageMonitoringInformation {
    GxUsageMonitoringInformationPresence presence;
    GxMonitoringKeyOctetString monitoring_key;
    GxGrantedServiceUnitList granted_service_unit;
    GxUsedServiceUnitList used_service_unit;
    uint32_t quota_consumption_time;
    int32_t usage_monitoring_level;
    int32_t usage_monitoring_report;
    int32_t usage_monitoring_support;
} GxUsageMonitoringInformation;

typedef struct gxUsageMonitoringInformationList {
    int32_t count;
    GxUsageMonitoringInformation *list;
} GxUsageMonitoringInformationList;

typedef struct gxTunnelHeaderFilterList {
    int32_t count;
    GxTunnelHeaderFilterOctetString *list;
} GxTunnelHeaderFilterList;

typedef struct gxTunnelInformation {
    GxTunnelInformationPresence presence;
    uint32_t tunnel_header_length;
    GxTunnelHeaderFilterList tunnel_header_filter;
} GxTunnelInformation;

typedef struct gxCoaInformation {
    GxCoaInformationPresence presence;
    GxTunnelInformation tunnel_information;
    FdAddress coa_ip_address;
} GxCoaInformation;

typedef struct gxCoaInformationList {
    int32_t count;
    GxCoaInformation *list;
} GxCoaInformationList;

typedef struct gxChargingRuleNameList {
    int32_t count;
    GxChargingRuleNameOctetString *list;
} GxChargingRuleNameList;

typedef struct gxChargingRuleBaseNameList {
    int32_t count;
    GxChargingRuleBaseNameOctetString *list;
} GxChargingRuleBaseNameList;

typedef struct gxAccessNetworkChargingIdentifierGx {
    GxAccessNetworkChargingIdentifierGxPresence presence;
    GxAccessNetworkChargingIdentifierValueOctetString access_network_charging_identifier_value;
    GxChargingRuleBaseNameList charging_rule_base_name;
    GxChargingRuleNameList charging_rule_name;
    int32_t ip_can_session_charging_scope;
} GxAccessNetworkChargingIdentifierGx;

typedef struct gxAccessNetworkChargingIdentifierGxList {
    int32_t count;
    GxAccessNetworkChargingIdentifierGx *list;
} GxAccessNetworkChargingIdentifierGxList;

typedef struct gxMbsfnArea {
    GxMbsfnAreaPresence presence;
    uint32_t mbsfn_area_id;
    uint32_t carrier_frequency;
} GxMbsfnArea;

typedef struct gxMbsfnAreaList {
    int32_t count;
    GxMbsfnArea *list;
} GxMbsfnAreaList;

typedef struct gxMdtAllowedPlmnIdList {
    int32_t count;
    GxMdtAllowedPlmnIdOctetString *list;
} GxMdtAllowedPlmnIdList;

typedef struct gxTrackingAreaIdentityList {
    int32_t count;
    GxTrackingAreaIdentityOctetString *list;
} GxTrackingAreaIdentityList;

typedef struct gxLocationAreaIdentityList {
    int32_t count;
    GxLocationAreaIdentityOctetString *list;
} GxLocationAreaIdentityList;

typedef struct gxRoutingAreaIdentityList {
    int32_t count;
    GxRoutingAreaIdentityOctetString *list;
} GxRoutingAreaIdentityList;

typedef struct gxEUtranCellGlobalIdentityList {
    int32_t count;
    GxEUtranCellGlobalIdentityOctetString *list;
} GxEUtranCellGlobalIdentityList;

typedef struct gxCellGlobalIdentityList {
    int32_t count;
    GxCellGlobalIdentityOctetString *list;
} GxCellGlobalIdentityList;

typedef struct gxAreaScope {
    GxAreaScopePresence presence;
    GxCellGlobalIdentityList cell_global_identity;
    GxEUtranCellGlobalIdentityList e_utran_cell_global_identity;
    GxRoutingAreaIdentityList routing_area_identity;
    GxLocationAreaIdentityList location_area_identity;
    GxTrackingAreaIdentityList tracking_area_identity;
} GxAreaScope;

typedef struct gxMdtConfiguration {
    GxMdtConfigurationPresence presence;
    int32_t job_type;
    GxAreaScope area_scope;
    uint32_t list_of_measurements;
    uint32_t reporting_trigger;
    int32_t report_interval;
    int32_t report_amount;
    uint32_t event_threshold_rsrp;
    uint32_t event_threshold_rsrq;
    int32_t logging_interval;
    int32_t logging_duration;
    int32_t measurement_period_lte;
    int32_t measurement_period_umts;
    int32_t collection_period_rrm_lte;
    int32_t collection_period_rrm_umts;
    GxPositioningMethodOctetString positioning_method;
    GxMeasurementQuantityOctetString measurement_quantity;
    int32_t event_threshold_event_1f;
    int32_t event_threshold_event_1i;
    GxMdtAllowedPlmnIdList mdt_allowed_plmn_id;
    GxMbsfnAreaList mbsfn_area;
} GxMdtConfiguration;

typedef struct gxTraceData {
    GxTraceDataPresence presence;
    GxTraceReferenceOctetString trace_reference;
    int32_t trace_depth;
    GxTraceNeTypeListOctetString trace_ne_type_list;
    GxTraceInterfaceListOctetString trace_interface_list;
    GxTraceEventListOctetString trace_event_list;
    GxOmcIdOctetString omc_id;
    FdAddress trace_collection_entity;
    GxMdtConfiguration mdt_configuration;
} GxTraceData;

typedef struct gxAnGwAddressList {
    int32_t count;
    FdAddress *list;
} GxAnGwAddressList;

typedef struct gxUserCsgInformation {
    GxUserCsgInformationPresence presence;
    uint32_t csg_id;
    int32_t csg_access_mode;
    int32_t csg_membership_indication;
} GxUserCsgInformation;

typedef struct gxEventTriggerList {
    int32_t count;
    int32_t *list;
} GxEventTriggerList;

typedef struct gxEventReportIndication {
    GxEventReportIndicationPresence presence;
    int32_t an_trusted;
    GxEventTriggerList event_trigger;
    GxUserCsgInformation user_csg_information;
    int32_t ip_can_type;
    GxAnGwAddressList an_gw_address;
    Gx3gppSgsnAddressOctetString tgpp_sgsn_address;
    Gx3gppSgsnIpv6AddressOctetString tgpp_sgsn_ipv6_address;
    Gx3gppSgsnMccMncOctetString tgpp_sgsn_mcc_mnc;
    GxFramedIpAddressOctetString framed_ip_address;
    int32_t rat_type;
    GxRaiOctetString rai;
    Gx3gppUserLocationInfoOctetString tgpp_user_location_info;
    GxTraceData trace_data;
    GxTraceReferenceOctetString trace_reference;
    Gx3gpp2BsidOctetString tgpp2_bsid;
    Gx3gppMsTimezoneOctetString tgpp_ms_timezone;
    FdAddress routing_ip_address;
    FdAddress ue_local_ip_address;
    FdAddress henb_local_ip_address;
    uint32_t udp_source_port;
    GxPresenceReportingAreaInformation presence_reporting_area_information;
} GxEventReportIndication;

typedef struct gxFlowInformation {
    GxFlowInformationPresence presence;
    GxFlowDescriptionOctetString flow_description;
    GxPacketFilterIdentifierOctetString packet_filter_identifier;
    int32_t packet_filter_usage;
    GxTosTrafficClassOctetString tos_traffic_class;
    GxSecurityParameterIndexOctetString security_parameter_index;
    GxFlowLabelOctetString flow_label;
    int32_t flow_direction;
    GxRoutingRuleIdentifierOctetString routing_rule_identifier;
} GxFlowInformation;

typedef struct gxFlowInformationList {
    int32_t count;
    GxFlowInformation *list;
} GxFlowInformationList;

typedef struct gxApplicationDetectionInformation {
    GxApplicationDetectionInformationPresence presence;
    GxTdfApplicationIdentifierOctetString tdf_application_identifier;
    GxTdfApplicationInstanceIdentifierOctetString tdf_application_instance_identifier;
    GxFlowInformationList flow_information;
} GxApplicationDetectionInformation;

typedef struct gxApplicationDetectionInformationList {
    int32_t count;
    GxApplicationDetectionInformation *list;
} GxApplicationDetectionInformationList;

typedef struct gxContentVersionList {
    int32_t count;
    uint64_t *list;
} GxContentVersionList;

typedef struct gxRanNasReleaseCauseList {
    int32_t count;
    GxRanNasReleaseCauseOctetString *list;
} GxRanNasReleaseCauseList;

typedef struct gxRedirectServer {
    GxRedirectServerPresence presence;
    int32_t redirect_address_type;
    GxRedirectServerAddressOctetString redirect_server_address;
} GxRedirectServer;

typedef struct gxFilterIdList {
    int32_t count;
    GxFilterIdOctetString *list;
} GxFilterIdList;

typedef struct gxRestrictionFilterRuleList {
    int32_t count;
    GxRestrictionFilterRuleOctetString *list;
} GxRestrictionFilterRuleList;

typedef struct gxFinalUnitIndication {
    GxFinalUnitIndicationPresence presence;
    int32_t final_unit_action;
    GxRestrictionFilterRuleList restriction_filter_rule;
    GxFilterIdList filter_id;
    GxRedirectServer redirect_server;
} GxFinalUnitIndication;

typedef struct gxChargingRuleReport {
    GxChargingRuleReportPresence presence;
    GxChargingRuleNameList charging_rule_name;
    GxChargingRuleBaseNameList charging_rule_base_name;
    GxBearerIdentifierOctetString bearer_identifier;
    int32_t pcc_rule_status;
    int32_t rule_failure_code;
    GxFinalUnitIndication final_unit_indication;
    GxRanNasReleaseCauseList ran_nas_release_cause;
    GxContentVersionList content_version;
} GxChargingRuleReport;

typedef struct gxChargingRuleReportList {
    int32_t count;
    GxChargingRuleReport *list;
} GxChargingRuleReportList;

typedef struct gxTftPacketFilterInformation {
    GxTftPacketFilterInformationPresence presence;
    uint32_t precedence;
    GxTftFilterOctetString tft_filter;
    GxTosTrafficClassOctetString tos_traffic_class;
    GxSecurityParameterIndexOctetString security_parameter_index;
    GxFlowLabelOctetString flow_label;
    int32_t flow_direction;
} GxTftPacketFilterInformation;

typedef struct gxTftPacketFilterInformationList {
    int32_t count;
    GxTftPacketFilterInformation *list;
} GxTftPacketFilterInformationList;

typedef struct gxFixedUserLocationInfo {
    GxFixedUserLocationInfoPresence presence;
    GxSsidOctetString ssid;
    GxBssidOctetString bssid;
    GxLogicalAccessIdOctetString logical_access_id;
    GxPhysicalAccessIdOctetString physical_access_id;
} GxFixedUserLocationInfo;

typedef struct gxDefaultQosInformation {
    GxDefaultQosInformationPresence presence;
    int32_t qos_class_identifier;
    uint32_t max_requested_bandwidth_ul;
    uint32_t max_requested_bandwidth_dl;
    GxDefaultQosNameOctetString default_qos_name;
} GxDefaultQosInformation;

typedef struct gxAllocationRetentionPriority {
    GxAllocationRetentionPriorityPresence presence;
    uint32_t priority_level;
    int32_t pre_emption_capability;
    int32_t pre_emption_vulnerability;
} GxAllocationRetentionPriority;

typedef struct gxDefaultEpsBearerQos {
    GxDefaultEpsBearerQosPresence presence;
    int32_t qos_class_identifier;
    GxAllocationRetentionPriority allocation_retention_priority;
} GxDefaultEpsBearerQos;

typedef struct gxRatTypeList {
    int32_t count;
    int32_t *list;
} GxRatTypeList;

typedef struct gxIpCanTypeList {
    int32_t count;
    int32_t *list;
} GxIpCanTypeList;

typedef struct gxConditionalApnAggregateMaxBitrate {
    GxConditionalApnAggregateMaxBitratePresence presence;
    uint32_t apn_aggregate_max_bitrate_ul;
    uint32_t apn_aggregate_max_bitrate_dl;
    uint32_t extended_apn_ambr_ul;
    uint32_t extended_apn_ambr_dl;
    GxIpCanTypeList ip_can_type;
    GxRatTypeList rat_type;
} GxConditionalApnAggregateMaxBitrate;

typedef struct gxConditionalApnAggregateMaxBitrateList {
    int32_t count;
    GxConditionalApnAggregateMaxBitrate *list;
} GxConditionalApnAggregateMaxBitrateList;

typedef struct gxQosInformation {
    GxQosInformationPresence presence;
    int32_t qos_class_identifier;
    uint32_t max_requested_bandwidth_ul;
    uint32_t max_requested_bandwidth_dl;
    uint32_t extended_max_requested_bw_ul;
    uint32_t extended_max_requested_bw_dl;
    uint32_t guaranteed_bitrate_ul;
    uint32_t guaranteed_bitrate_dl;
    uint32_t extended_gbr_ul;
    uint32_t extended_gbr_dl;
    GxBearerIdentifierOctetString bearer_identifier;
    GxAllocationRetentionPriority allocation_retention_priority;
    uint32_t apn_aggregate_max_bitrate_ul;
    uint32_t apn_aggregate_max_bitrate_dl;
    uint32_t extended_apn_ambr_ul;
    uint32_t extended_apn_ambr_dl;
    GxConditionalApnAggregateMaxBitrateList conditional_apn_aggregate_max_bitrate;
} GxQosInformation;

typedef struct gxUserEquipmentInfo {
    GxUserEquipmentInfoPresence presence;
    int32_t user_equipment_info_type;
    GxUserEquipmentInfoValueOctetString user_equipment_info_value;
} GxUserEquipmentInfo;

typedef struct gxPacketFilterInformation {
    GxPacketFilterInformationPresence presence;
    GxPacketFilterIdentifierOctetString packet_filter_identifier;
    uint32_t precedence;
    GxPacketFilterContentOctetString packet_filter_content;
    GxTosTrafficClassOctetString tos_traffic_class;
    GxSecurityParameterIndexOctetString security_parameter_index;
    GxFlowLabelOctetString flow_label;
    int32_t flow_direction;
} GxPacketFilterInformation;

typedef struct gxPacketFilterInformationList {
    int32_t count;
    GxPacketFilterInformation *list;
} GxPacketFilterInformationList;

typedef struct gxTdfInformation {
    GxTdfInformationPresence presence;
    GxTdfDestinationRealmOctetString tdf_destination_realm;
    GxTdfDestinationHostOctetString tdf_destination_host;
    FdAddress tdf_ip_address;
} GxTdfInformation;

typedef struct gxSupportedFeatures {
    GxSupportedFeaturesPresence presence;
    uint32_t vendor_id;
    uint32_t feature_list_id;
    uint32_t feature_list;
} GxSupportedFeatures;

typedef struct gxSupportedFeaturesList {
    int32_t count;
    GxSupportedFeatures *list;
} GxSupportedFeaturesList;

typedef struct gxOcSupportedFeatures {
    GxOcSupportedFeaturesPresence presence;
    uint64_t oc_feature_vector;
} GxOcSupportedFeatures;

typedef struct gxSubscriptionId {
    GxSubscriptionIdPresence presence;
    int32_t subscription_id_type;
    GxSubscriptionIdDataOctetString subscription_id_data;
} GxSubscriptionId;

typedef struct gxSubscriptionIdList {
    int32_t count;
    GxSubscriptionId *list;
} GxSubscriptionIdList;

typedef struct gxCCR {
    GxCcrPresence presence;
    GxSessionIdOctetString session_id;
    int32_t drmp;
    uint32_t auth_application_id;
    GxOriginHostOctetString origin_host;
    GxOriginRealmOctetString origin_realm;
    GxDestinationRealmOctetString destination_realm;
    GxServiceContextIdOctetString service_context_id;
    int32_t cc_request_type;
    uint32_t cc_request_number;
    uint32_t credit_management_status;
    GxDestinationHostOctetString destination_host;
    uint32_t origin_state_id;
    GxSubscriptionIdList subscription_id;
    GxOcSupportedFeatures oc_supported_features;
    GxSupportedFeaturesList supported_features;
    GxTdfInformation tdf_information;
    int32_t network_request_support;
    GxPacketFilterInformationList packet_filter_information;
    int32_t packet_filter_operation;
    GxBearerIdentifierOctetString bearer_identifier;
    int32_t bearer_operation;
    int32_t dynamic_address_flag;
    int32_t dynamic_address_flag_extension;
    uint32_t pdn_connection_charging_id;
    GxFramedIpAddressOctetString framed_ip_address;
    GxFramedIpv6PrefixOctetString framed_ipv6_prefix;
    int32_t ip_can_type;
    Gx3gppRatTypeOctetString tgpp_rat_type;
    int32_t an_trusted;
    int32_t rat_type;
    int32_t termination_cause;
    GxUserEquipmentInfo user_equipment_info;
    GxQosInformation qos_information;
    int32_t qos_negotiation;
    int32_t qos_upgrade;
    GxDefaultEpsBearerQos default_eps_bearer_qos;
    GxDefaultQosInformation default_qos_information;
    GxAnGwAddressList an_gw_address;
    int32_t an_gw_status;
    Gx3gppSgsnMccMncOctetString tgpp_sgsn_mcc_mnc;
    Gx3gppSgsnAddressOctetString tgpp_sgsn_address;
    Gx3gppSgsnIpv6AddressOctetString tgpp_sgsn_ipv6_address;
    Gx3gppGgsnAddressOctetString tgpp_ggsn_address;
    Gx3gppGgsnIpv6AddressOctetString tgpp_ggsn_ipv6_address;
    Gx3gppSelectionModeOctetString tgpp_selection_mode;
    GxRaiOctetString rai;
    Gx3gppUserLocationInfoOctetString tgpp_user_location_info;
    GxFixedUserLocationInfo fixed_user_location_info;
    FdTime user_location_info_time;
    GxUserCsgInformation user_csg_information;
    GxTwanIdentifierOctetString twan_identifier;
    Gx3gppMsTimezoneOctetString tgpp_ms_timezone;
    GxRanNasReleaseCauseList ran_nas_release_cause;
    Gx3gppChargingCharacteristicsOctetString tgpp_charging_characteristics;
    GxCalledStationIdOctetString called_station_id;
    GxPdnConnectionIdOctetString pdn_connection_id;
    int32_t bearer_usage;
    int32_t online;
    int32_t offline;
    GxTftPacketFilterInformationList tft_packet_filter_information;
    GxChargingRuleReportList charging_rule_report;
    GxApplicationDetectionInformationList application_detection_information;
    GxEventTriggerList event_trigger;
    GxEventReportIndication event_report_indication;
    FdAddress access_network_charging_address;
    GxAccessNetworkChargingIdentifierGxList access_network_charging_identifier_gx;
    GxCoaInformationList coa_information;
    GxUsageMonitoringInformationList usage_monitoring_information;
    int32_t nbifom_support;
    int32_t nbifom_mode;
    int32_t default_access;
    uint64_t origination_time_stamp;
    uint32_t maximum_wait_time;
    uint32_t access_availability_change_reason;
    GxRoutingRuleInstall routing_rule_install;
    GxRoutingRuleRemove routing_rule_remove;
    FdAddress henb_local_ip_address;
    FdAddress ue_local_ip_address;
    uint32_t udp_source_port;
    uint32_t tcp_source_port;
    GxPresenceReportingAreaInformationList presence_reporting_area_information;
    GxLogicalAccessIdOctetString logical_access_id;
    GxPhysicalAccessIdOctetString physical_access_id;
    GxProxyInfoList proxy_info;
    GxRouteRecordList route_record;
    int32_t tgpp_ps_data_off_status;
} GxCCR;

typedef struct gxLoad {
    GxLoadPresence presence;
    int32_t load_type;
    uint64_t load_value;
    GxSourceidOctetString sourceid;
} GxLoad;

typedef struct gxLoadList {
    int32_t count;
    GxLoad *list;
} GxLoadList;

typedef struct gxFailedAvp {
    GxFailedAvpPresence presence;
} GxFailedAvp;

typedef struct gxConditionalPolicyInformation {
    GxConditionalPolicyInformationPresence presence;
    FdTime execution_time;
    GxDefaultEpsBearerQos default_eps_bearer_qos;
    uint32_t apn_aggregate_max_bitrate_ul;
    uint32_t apn_aggregate_max_bitrate_dl;
    uint32_t extended_apn_ambr_ul;
    uint32_t extended_apn_ambr_dl;
    GxConditionalApnAggregateMaxBitrateList conditional_apn_aggregate_max_bitrate;
} GxConditionalPolicyInformation;

typedef struct gxConditionalPolicyInformationList {
    int32_t count;
    GxConditionalPolicyInformation *list;
} GxConditionalPolicyInformationList;

typedef struct gxRoutingRuleReport {
    GxRoutingRuleReportPresence presence;
    GxRoutingRuleIdentifierList routing_rule_identifier;
    int32_t pcc_rule_status;
    uint32_t routing_rule_failure_code;
} GxRoutingRuleReport;

typedef struct gxRoutingRuleReportList {
    int32_t count;
    GxRoutingRuleReport *list;
} GxRoutingRuleReportList;

typedef struct gxPresenceReportingAreaIdentifierList {
    int32_t count;
    GxPresenceReportingAreaIdentifierOctetString *list;
} GxPresenceReportingAreaIdentifierList;

typedef struct gxPraRemove {
    GxPraRemovePresence presence;
    GxPresenceReportingAreaIdentifierList presence_reporting_area_identifier;
} GxPraRemove;

typedef struct gxPraInstall {
    GxPraInstallPresence presence;
    GxPresenceReportingAreaInformationList presence_reporting_area_information;
} GxPraInstall;

typedef struct gxCsgInformationReportingList {
    int32_t count;
    int32_t *list;
} GxCsgInformationReportingList;

typedef struct gxQosInformationList {
    int32_t count;
    GxQosInformation *list;
} GxQosInformationList;

typedef struct gxChargingInformation {
    GxChargingInformationPresence presence;
    GxPrimaryEventChargingFunctionNameOctetString primary_event_charging_function_name;
    GxSecondaryEventChargingFunctionNameOctetString secondary_event_charging_function_name;
    GxPrimaryChargingCollectionFunctionNameOctetString primary_charging_collection_function_name;
    GxSecondaryChargingCollectionFunctionNameOctetString secondary_charging_collection_function_name;
} GxChargingInformation;

typedef struct gxRequiredAccessInfoList {
    int32_t count;
    int32_t *list;
} GxRequiredAccessInfoList;

typedef struct gxRedirectInformation {
    GxRedirectInformationPresence presence;
    int32_t redirect_support;
    int32_t redirect_address_type;
    GxRedirectServerAddressOctetString redirect_server_address;
} GxRedirectInformation;

typedef struct gxFlowNumberList {
    int32_t count;
    uint32_t *list;
} GxFlowNumberList;

typedef struct gxFlows {
    GxFlowsPresence presence;
    uint32_t media_component_number;
    GxFlowNumberList flow_number;
    GxContentVersionList content_version;
    int32_t final_unit_action;
    uint32_t media_component_status;
} GxFlows;

typedef struct gxFlowsList {
    int32_t count;
    GxFlows *list;
} GxFlowsList;

typedef struct gxChargingRuleDefinition {
    GxChargingRuleDefinitionPresence presence;
    GxChargingRuleNameOctetString charging_rule_name;
    uint32_t service_identifier;
    uint32_t rating_group;
    GxFlowInformationList flow_information;
    int32_t default_bearer_indication;
    GxTdfApplicationIdentifierOctetString tdf_application_identifier;
    int32_t flow_status;
    GxQosInformation qos_information;
    int32_t ps_to_cs_session_continuity;
    int32_t reporting_level;
    int32_t online;
    int32_t offline;
    float max_plr_dl;
    float max_plr_ul;
    int32_t metering_method;
    uint32_t precedence;
    GxAfChargingIdentifierOctetString af_charging_identifier;
    GxFlowsList flows;
    GxMonitoringKeyOctetString monitoring_key;
    GxRedirectInformation redirect_information;
    int32_t mute_notification;
    int32_t af_signalling_protocol;
    GxSponsorIdentityOctetString sponsor_identity;
    GxApplicationServiceProviderIdentityOctetString application_service_provider_identity;
    GxRequiredAccessInfoList required_access_info;
    uint32_t sharing_key_dl;
    uint32_t sharing_key_ul;
    GxTrafficSteeringPolicyIdentifierDlOctetString traffic_steering_policy_identifier_dl;
    GxTrafficSteeringPolicyIdentifierUlOctetString traffic_steering_policy_identifier_ul;
    uint64_t content_version;
} GxChargingRuleDefinition;

typedef struct gxChargingRuleDefinitionList {
    int32_t count;
    GxChargingRuleDefinition *list;
} GxChargingRuleDefinitionList;

typedef struct gxChargingRuleInstall {
    GxChargingRuleInstallPresence presence;
    GxChargingRuleDefinitionList charging_rule_definition;
    GxChargingRuleNameList charging_rule_name;
    GxChargingRuleBaseNameList charging_rule_base_name;
    GxBearerIdentifierOctetString bearer_identifier;
    uint32_t monitoring_flags;
    FdTime rule_activation_time;
    FdTime rule_deactivation_time;
    int32_t resource_allocation_notification;
    int32_t charging_correlation_indicator;
    int32_t ip_can_type;
} GxChargingRuleInstall;

typedef struct gxChargingRuleInstallList {
    int32_t count;
    GxChargingRuleInstall *list;
} GxChargingRuleInstallList;

typedef struct gxChargingRuleRemove {
    GxChargingRuleRemovePresence presence;
    GxChargingRuleNameList charging_rule_name;
    GxChargingRuleBaseNameList charging_rule_base_name;
    GxRequiredAccessInfoList required_access_info;
    int32_t resource_release_notification;
} GxChargingRuleRemove;

typedef struct gxChargingRuleRemoveList {
    int32_t count;
    GxChargingRuleRemove *list;
} GxChargingRuleRemoveList;

typedef struct gxRedirectHostList {
    int32_t count;
    GxRedirectHostOctetString *list;
} GxRedirectHostList;

typedef struct gxOcOlr {
    GxOcOlrPresence presence;
    uint64_t oc_sequence_number;
    int32_t oc_report_type;
    uint32_t oc_reduction_percentage;
    uint32_t oc_validity_duration;
} GxOcOlr;

typedef struct gxExperimentalResult {
    GxExperimentalResultPresence presence;
    uint32_t vendor_id;
    uint32_t experimental_result_code;
} GxExperimentalResult;

typedef struct gxCCA {
    GxCcaPresence presence;
    GxSessionIdOctetString session_id;
    int32_t drmp;
    uint32_t auth_application_id;
    GxOriginHostOctetString origin_host;
    GxOriginRealmOctetString origin_realm;
    uint32_t result_code;
    GxExperimentalResult experimental_result;
    int32_t cc_request_type;
    uint32_t cc_request_number;
    GxOcSupportedFeatures oc_supported_features;
    GxOcOlr oc_olr;
    GxSupportedFeaturesList supported_features;
    int32_t bearer_control_mode;
    GxEventTriggerList event_trigger;
    GxEventReportIndication event_report_indication;
    uint32_t origin_state_id;
    GxRedirectHostList redirect_host;
    int32_t redirect_host_usage;
    uint32_t redirect_max_cache_time;
    GxChargingRuleRemoveList charging_rule_remove;
    GxChargingRuleInstallList charging_rule_install;
    GxChargingInformation charging_information;
    int32_t online;
    int32_t offline;
    GxQosInformationList qos_information;
    FdTime revalidation_time;
    GxDefaultEpsBearerQos default_eps_bearer_qos;
    GxDefaultQosInformation default_qos_information;
    int32_t bearer_usage;
    GxUsageMonitoringInformationList usage_monitoring_information;
    GxCsgInformationReportingList csg_information_reporting;
    GxUserCsgInformation user_csg_information;
    GxPraInstall pra_install;
    GxPraRemove pra_remove;
    GxPresenceReportingAreaInformation presence_reporting_area_information;
    int32_t session_release_cause;
    int32_t nbifom_support;
    int32_t nbifom_mode;
    int32_t default_access;
    uint32_t ran_rule_support;
    GxRoutingRuleReportList routing_rule_report;
    GxConditionalPolicyInformationList conditional_policy_information;
    int32_t removal_of_access;
    int32_t ip_can_type;
    GxErrorMessageOctetString error_message;
    GxErrorReportingHostOctetString error_reporting_host;
    GxFailedAvp failed_avp;
    GxProxyInfoList proxy_info;
    GxRouteRecordList route_record;
    GxLoadList load;
} GxCCA;

typedef struct gxRAA {
    GxRaaPresence presence;
    GxSessionIdOctetString session_id;
    int32_t drmp;
    GxOriginHostOctetString origin_host;
    GxOriginRealmOctetString origin_realm;
    uint32_t result_code;
    GxExperimentalResult experimental_result;
    uint32_t origin_state_id;
    GxOcSupportedFeatures oc_supported_features;
    GxOcOlr oc_olr;
    int32_t ip_can_type;
    int32_t rat_type;
    int32_t an_trusted;
    GxAnGwAddressList an_gw_address;
    Gx3gppSgsnMccMncOctetString tgpp_sgsn_mcc_mnc;
    Gx3gppSgsnAddressOctetString tgpp_sgsn_address;
    Gx3gppSgsnIpv6AddressOctetString tgpp_sgsn_ipv6_address;
    GxRaiOctetString rai;
    Gx3gppUserLocationInfoOctetString tgpp_user_location_info;
    FdTime user_location_info_time;
    uint32_t netloc_access_support;
    GxUserCsgInformation user_csg_information;
    Gx3gppMsTimezoneOctetString tgpp_ms_timezone;
    GxDefaultQosInformation default_qos_information;
    GxChargingRuleReportList charging_rule_report;
    GxErrorMessageOctetString error_message;
    GxErrorReportingHostOctetString error_reporting_host;
    GxFailedAvp failed_avp;
    GxProxyInfoList proxy_info;
} GxRAA;

typedef struct gxRAR {
    GxRarPresence presence;
    GxSessionIdOctetString session_id;
    int32_t drmp;
    uint32_t auth_application_id;
    GxOriginHostOctetString origin_host;
    GxOriginRealmOctetString origin_realm;
    GxDestinationRealmOctetString destination_realm;
    GxDestinationHostOctetString destination_host;
    int32_t re_auth_request_type;
    int32_t session_release_cause;
    uint32_t origin_state_id;
    GxOcSupportedFeatures oc_supported_features;
    GxEventTriggerList event_trigger;
    GxEventReportIndication event_report_indication;
    GxChargingRuleRemoveList charging_rule_remove;
    GxChargingRuleInstallList charging_rule_install;
    GxDefaultEpsBearerQos default_eps_bearer_qos;
    GxQosInformationList qos_information;
    GxDefaultQosInformation default_qos_information;
    FdTime revalidation_time;
    GxUsageMonitoringInformationList usage_monitoring_information;
    uint32_t pcscf_restoration_indication;
    GxConditionalPolicyInformationList conditional_policy_information;
    int32_t removal_of_access;
    int32_t ip_can_type;
    GxPraInstall pra_install;
    GxPraRemove pra_remove;
    GxCsgInformationReportingList csg_information_reporting;
    GxProxyInfoList proxy_info;
    GxRouteRecordList route_record;
} GxRAR;

#ifdef __cplusplus
}
#endif

#endif /* __GX_STRUCT_H__ */
